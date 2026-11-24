#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A14 records.

The producer reads the tracked records that establish the real role fills and
builds three documents:

  * ``ROLES.json``       -- every real role assignment the records establish;
  * ``AUTHORISATION.json`` -- the six actions attempted against those records,
                              each with the recorded outcome and the counterfactual
                              role assessment that names the separation that fails;
  * ``CONTROLS.json``    -- one control per refusal code, built in memory from
                              synthetic identities labelled ``control-only``.

Every value is derived from a literal in this file or from the bytes of a named
input record.  Two runs are byte-identical, and the committed files match a
fresh run; the test suite enforces both.

Usage:
    python3 evidence/a14/build_evidence.py [--out DIR] [--source-commit SHA]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import authorisation as auth  # noqa: E402

BASE_COMMIT = "4e9262bf34e937439ec92bc832b5a569b27267b8"
BASE_COMMIT_SHORT = "4e9262bf3"
ITEM = "A14"
AS_OF = "2026-11-24"
AT = "2026-11-24"

T8 = "evidence/etp-t8/ASSIGNMENTS.json"
T8_ROLES = "evidence/etp-t8/ROLES.json"
A12 = "evidence/a12/TRUST-ROOTS.json"
A10 = "evidence/a10/ENVELOPES.json"
B85C_ADJUDICATION = "evidence/b85c-adjudication.json"
B85C_RELEASE = "evidence/SAFE-COMPATIBLE-openssh-b85c.json"
TOOL_PATH = "forensics/tools/authorisation.py"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def source_identity() -> dict[str, Any]:
    inputs = [T8, T8_ROLES, A12, A10, B85C_ADJUDICATION, B85C_RELEASE]
    return {
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_COMMIT_SHORT,
        "branch": "staging",
        "recordedAt": AS_OF,
        "tool": {"path": TOOL_PATH, "sha256": sha256_file(REPO_ROOT / TOOL_PATH)},
        "inputs": [
            {"path": path, "sha256": sha256_file(REPO_ROOT / path)}
            for path in inputs
        ],
    }


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# ROLES.json -- the real assignments
# ---------------------------------------------------------------------------
def build_roles(identity: dict[str, Any]) -> dict[str, Any]:
    assignments = [
        {
            "identity": "P-CAMPAIGN",
            "identityRecordedAt": f"{T8}#parties.P-CAMPAIGN",
            "party": "P-PROJECT-UNDECLARED",
            "declaredIdentity": False,
            "role": "producer",
            "scope": ["*"],
            "grantedAt": "2026-11-23",
            "grantedBy": {
                "identity": None,
                "role": None,
                "recorded": False,
                "note": "no grantor identity, role, account or signing key is recorded",
            },
            "revokedAt": None,
            "expiresAt": None,
            "external": False,
            "evidence": (
                f"{T8}#summary (author 50/50, evidence_producer 50/50, "
                "proof_producer 15/50, instrument_author 15/50; every fill at party "
                "P-CAMPAIGN with identity null and declared false)"
            ),
        },
        {
            "identity": "P-CAMPAIGN",
            "identityRecordedAt": f"{T8}#parties.P-CAMPAIGN",
            "party": "P-PROJECT-UNDECLARED",
            "declaredIdentity": False,
            "role": "adjudicator",
            "scope": ["*"],
            "grantedAt": "2026-11-23",
            "grantedBy": {
                "identity": None,
                "role": None,
                "recorded": False,
                "note": "no grantor identity, role, account or signing key is recorded",
            },
            "revokedAt": None,
            "expiresAt": None,
            "external": False,
            "evidence": (
                f"{T8}#summary (adjudicator 50/50, same_party_adjudicator 50; every "
                "fill at party P-CAMPAIGN with identity null and declared false)"
            ),
        },
        {
            "identity": "P-CAMPAIGN",
            "identityRecordedAt": f"{T8}#parties.P-CAMPAIGN",
            "party": "P-PROJECT-UNDECLARED",
            "declaredIdentity": False,
            "role": "external_reproducer",
            "scope": ["claim:openssh-b85c"],
            "grantedAt": "2026-11-23",
            "grantedBy": {
                "identity": None,
                "role": None,
                "recorded": False,
                "note": "no grantor identity, role, account or signing key is recorded",
            },
            "revokedAt": None,
            "expiresAt": None,
            "external": False,
            "evidence": (
                f"{T8}#A-ADJ-B85C/filled.independent_reproducer (party P-CAMPAIGN, "
                "identity null, declared false; the record itself states the "
                "reproduction ran in this repository's environment on project "
                "artefacts, so it is not an external reproduction)"
            ),
        },
        {
            "identity": "P-PRINCIPAL",
            "identityRecordedAt": f"{T8}#parties.P-PRINCIPAL",
            "party": "P-PROJECT-UNDECLARED",
            "declaredIdentity": False,
            "role": "release_authority",
            "scope": ["release:openssh-b85c"],
            "grantedAt": "2026-11-23",
            "grantedBy": {
                "identity": None,
                "role": None,
                "recorded": False,
                "note": "no grantor identity, role, account or signing key is recorded",
            },
            "revokedAt": None,
            "expiresAt": None,
            "external": False,
            "evidence": (
                f"{T8}#A-REL-OPENSSH-B85C/filled.release_authority (party "
                "P-PRINCIPAL, identity null, declared false; T8 states its "
                "distinctness from P-CAMPAIGN is not established)"
            ),
        },
        {
            "identity": "P-CAMPAIGN",
            "identityRecordedAt": f"{T8}#parties.P-CAMPAIGN",
            "party": "P-PROJECT-UNDECLARED",
            "declaredIdentity": False,
            "role": "revocation_authority",
            "scope": ["release:openssh-b85c"],
            "grantedAt": "2026-11-23",
            "grantedBy": {
                "identity": None,
                "role": None,
                "recorded": False,
                "note": "no grantor identity, role, account or signing key is recorded",
            },
            "revokedAt": None,
            "expiresAt": None,
            "external": False,
            "evidence": (
                f"{T8}#A-REL-OPENSSH-B85C/filled.revocation_authority (party "
                "P-CAMPAIGN, identity null, declared false)"
            ),
        },
    ]
    parties = {
        "P-CAMPAIGN": {
            "identity": "P-CAMPAIGN",
            "party": "P-PROJECT-UNDECLARED",
            "declared": False,
            "trustDomain": "project",
            "record": f"{T8}#parties.P-CAMPAIGN",
            "note": (
                "no identity string, account, organisation or signing key is "
                "declared in any artefact; the record does not invent one"
            ),
        },
        "P-PRINCIPAL": {
            "identity": "P-PRINCIPAL",
            "party": "P-PROJECT-UNDECLARED",
            "declared": False,
            "trustDomain": "undeclared",
            "record": f"{T8}#parties.P-PRINCIPAL",
            "note": (
                "named only as 'decision-maker (campaign principal)'; its "
                "distinctness from P-CAMPAIGN is not established, so both are "
                "conservatively classified as one party"
            ),
        },
    }
    real_state = {
        "maintainer": "none",
        "instrumentReviewer": "none",
        "externalReproducer": "none",
        "releaseAuthority": "none",
        "declaredIdentities": 0,
        "externalTrustDomains": 0,
        "samePartyAdjudications": 50,
        "samePartyAssignments": 49,
        "notEstablishedAssignments": 1,
        "assignments": len(assignments),
        "onlySigningRoot": {
            "keyid": "test-only:hmac-sha256:8e10a5a15d233d54",
            "source": f"{A12}#roots[0]",
            "algorithm": "hmac-sha256",
            "symmetric": True,
            "trustDomain": "same-party",
            "external": False,
            "purpose": (
                "signs the A9 statements in the A10 envelopes; it is not a "
                "role-authorisation signature and establishes no identity"
            ),
        },
    }
    role_coverage = [
        {
            "role": "maintainer",
            "assignments": 0,
            "state": "none",
            "reason": "no tracked record assigns a maintainer identity or party",
        },
        {
            "role": "producer",
            "assignments": 1,
            "state": "same-party only",
            "reason": "the only fill is the undeclared party P-CAMPAIGN",
        },
        {
            "role": "instrument_reviewer",
            "assignments": 0,
            "state": "none",
            "reason": (
                "T8's 'reviewer' fill is the independent-adjudication reviewer "
                "for RV-B85C-1, not an instrument reviewer; no instrument-review "
                "assignment exists"
            ),
        },
        {
            "role": "adjudicator",
            "assignments": 1,
            "state": "same-party only",
            "reason": "50/50 adjudications are filled at the undeclared party P-CAMPAIGN",
        },
        {
            "role": "external_reproducer",
            "assignments": 1,
            "state": "same-party only",
            "reason": (
                "the only fill is party P-CAMPAIGN in this repository's "
                "environment; A12 records 0 external trust domains"
            ),
        },
        {
            "role": "release_authority",
            "assignments": 1,
            "state": "same-party only",
            "reason": (
                "the only fill is P-PRINCIPAL, whose distinctness from "
                "P-CAMPAIGN is not established; no declared release authority exists"
            ),
        },
        {
            "role": "revocation_authority",
            "assignments": 1,
            "state": "same-party only",
            "reason": "the only fill is the undeclared party P-CAMPAIGN",
        },
    ]
    return {
        "schema": "openssl-rs/a14/roles/1",
        "item": ITEM,
        "sourceIdentity": identity,
        "roleVocabulary": list(auth.ROLES),
        "parties": parties,
        "assignments": assignments,
        "roleCoverage": role_coverage,
        "realState": real_state,
        "notes": [
            "A role label is not a party: P-CAMPAIGN and P-PRINCIPAL are both "
            "undeclared and their distinctness is not established, so both map "
            "to party P-PROJECT-UNDECLARED.",
            "No assignment records a grantor, an account, an organisation or a "
            "signing key. The field is recorded as null rather than invented.",
            "The three roles with no assignment are recorded explicitly as "
            "none; an absent role is a refusal, not an omission.",
        ],
    }


# ---------------------------------------------------------------------------
# AUTHORISATION.json -- the six real actions
# ---------------------------------------------------------------------------
def signature(identity: str, role: str, scope: str, verified: bool) -> dict[str, Any]:
    if verified:
        basis = (
            "counterfactual: the recorded role fill is taken as if a verified "
            "signature existed; this is not a real signature and authorises nothing"
        )
    else:
        basis = (
            "none: no authorisation signature exists. The only recorded signing "
            "root is test-only:hmac-sha256:8e10a5a15d233d54 (A10/A12), which signs "
            "A9 statements, not role authorisations."
        )
    return {
        "identity": identity,
        "role": role,
        "scope": [scope],
        "verified": verified,
        "verificationBasis": basis,
    }


REAL_ACTIONS: dict[str, dict[str, Any]] = {
    "release": {
        "scope": "release:openssh-b85c",
        "record": B85C_RELEASE,
        "reason": (
            "the release record fills release_authority at P-PRINCIPAL, "
            "adjudicator at P-CAMPAIGN, and names no external reproducer"
        ),
        "signers": [
            ("P-PRINCIPAL", "release_authority"),
            ("P-CAMPAIGN", "adjudicator"),
        ],
    },
    "claim-promotion": {
        "scope": "claim:openssh-b85c",
        "record": B85C_ADJUDICATION,
        "reason": (
            "the b85c adjudication asserts an independent promotion and is filled "
            "by the same undeclared party as the evidence it judges"
        ),
        "signers": [("P-CAMPAIGN", "adjudicator")],
    },
    "consumer-graduation": {
        "scope": "claim:openssh-b85c",
        "record": B85C_RELEASE,
        "reason": (
            "the graduation record fills adjudicator at P-CAMPAIGN and records the "
            "independent reproducer as ABSENT"
        ),
        "signers": [("P-CAMPAIGN", "adjudicator")],
    },
    "instrument-qualification": {
        "scope": "instrument:etp3",
        "record": "evidence/etp3/instruments.json",
        "reason": (
            "no instrument reviewer is assigned; the instrument author is the same "
            "undeclared party as every other role"
        ),
        "signers": [
            ("P-CAMPAIGN", "producer"),
            ("P-CAMPAIGN", "instrument_reviewer"),
        ],
    },
    "evidence-correction": {
        "scope": "evidence:a14",
        "record": "evidence/etp-t8/ASSIGNMENTS.json",
        "reason": "no maintainer is assigned; the evidence producer is P-CAMPAIGN",
        "signers": [
            ("P-CAMPAIGN", "producer"),
            ("P-CAMPAIGN", "maintainer"),
        ],
    },
    "revocation": {
        "scope": "release:openssh-b85c",
        "record": B85C_RELEASE,
        "reason": (
            "the release record fills revocation_authority at P-CAMPAIGN, the same "
            "party that produced the evidence"
        ),
        "signers": [("P-CAMPAIGN", "revocation_authority")],
    },
}


def build_authorisation(
    identity: dict[str, Any], assignments: list[dict[str, Any]]
) -> dict[str, Any]:
    actions: dict[str, Any] = {}
    recorded_authorised = 0
    face_value_authorised = 0
    refused = 0
    not_run = 0
    for action, spec in REAL_ACTIONS.items():
        scope = spec["scope"]
        context = {
            "scope": [scope],
            "evidenceProducer": "P-CAMPAIGN",
            "roleIdentities": {"producer": "P-CAMPAIGN"},
        }
        recorded_signatures = [
            signature(who, role, scope, False) for who, role in spec["signers"]
        ]
        face_value_signatures = [
            signature(who, role, scope, True) for who, role in spec["signers"]
        ]
        recorded = auth.authorise(
            action, recorded_signatures, assignments, at=AT, context=context
        )
        recorded["signatures"] = recorded_signatures
        face_value = auth.authorise(
            action, face_value_signatures, assignments, at=AT, context=context
        )
        face_value["label"] = "COUNTERFACTUAL_ROLE_ASSESSMENT"
        face_value["signatures"] = face_value_signatures
        separation = auth.separation_failures(
            action, assignments, at=AT, context=context
        )
        if recorded["outcome"] == "AUTHORISED":
            recorded_authorised += 1
        if face_value["outcome"] == "AUTHORISED":
            face_value_authorised += 1
        if recorded["outcome"] == "REFUSED":
            refused += 1
        if recorded["outcome"] == "NOT_RUN":
            not_run += 1
        actions[action] = {
            "scope": [scope],
            "record": spec["record"],
            "reason": spec["reason"],
            "context": context,
            "recorded": recorded,
            "faceValue": face_value,
            "separationFailed": separation,
        }
    return {
        "schema": "openssl-rs/a14/authorisation/1",
        "item": ITEM,
        "sourceIdentity": identity,
        "policy": {
            name: auth.explain(name) for name in REAL_ACTIONS
        },
        "actions": actions,
        "aggregate": {
            "actions": len(actions),
            "authorised": 0,
            "recordedAuthorised": recorded_authorised,
            "faceValueAuthorised": face_value_authorised,
            "refused": refused,
            "notRun": not_run,
            "note": (
                "0 actions are authorised by the real records. Every recorded "
                "attempt is refused first at an unverified signature; taking the "
                "recorded role fills at face value, every action is still refused "
                "because every identity is the same undeclared party, required "
                "roles are unassigned, or the required separation fails."
            ),
        },
    }


# ---------------------------------------------------------------------------
# CONTROLS.json -- one control per refusal code
# ---------------------------------------------------------------------------
def control_assignment(
    identity: str,
    role: str,
    party: str | None = None,
    scope: str = "*",
    granted_at: str = "2026-01-01",
    expires_at: str | None = None,
    revoked_at: str | None = None,
) -> dict[str, Any]:
    return {
        "identity": identity,
        "party": party or f"P-{identity}",
        "role": role,
        "scope": [scope],
        "grantedAt": granted_at,
        "grantedBy": {
            "identity": None,
            "role": None,
            "recorded": False,
            "note": "control-only fixture",
        },
        "revokedAt": revoked_at,
        "expiresAt": expires_at,
        "evidence": f"control-only:{identity}/{role}",
    }


def control_signature(
    identity: str, role: str, scope: str = "*", verified: bool = True
) -> dict[str, Any]:
    return {
        "identity": identity,
        "role": role,
        "scope": [scope],
        "verified": verified,
    }


def _control(
    name: str,
    code: str,
    action: str,
    assignments: list[dict[str, Any]],
    signatures: list[dict[str, Any]] | None,
    expected_outcome: str,
    expected_codes: list[str],
    *,
    at: str = AT,
    context: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    forbidden_codes: list[str] | None = None,
) -> dict[str, Any]:
    result = auth.authorise(
        action, signatures, assignments, policy=policy, at=at, context=context
    )
    observed = result["codes"]
    passed = result["outcome"] == expected_outcome and all(
        item in observed for item in expected_codes
    ) and all(item not in observed for item in (forbidden_codes or []))
    return {
        "name": name,
        "code": code,
        "kind": "refusal" if code else "positive",
        "label": "control-only",
        "action": action,
        "at": at,
        "context": context or {},
        "assignments": assignments,
        "signatures": signatures,
        "expected": {"outcome": expected_outcome, "codes": expected_codes,
                     "forbiddenCodes": forbidden_codes or []},
        "observed": result,
        "pass": passed,
    }


def build_controls(identity: dict[str, Any]) -> dict[str, Any]:
    base = [
        control_assignment("control-only-alice", "adjudicator", "P-CONTROL-ALICE"),
        control_assignment("control-only-bob", "release_authority", "P-CONTROL-BOB"),
        control_assignment("control-only-producer", "producer", "P-CONTROL-PRODUCER"),
    ]
    claim_context = {"scope": ["claim:control"], "evidenceProducer": "control-only-producer",
                     "roleIdentities": {"producer": "control-only-producer"}}
    release_context = {"scope": ["release:control"], "evidenceProducer": "control-only-producer",
                       "roleIdentities": {"producer": "control-only-producer"}}

    controls = [
        _control(
            "role-unknown", "RA_REFUSED_ROLE_UNKNOWN", "claim-promotion", base,
            [control_signature("control-only-alice", "root")],
            "REFUSED", ["RA_REFUSED_ROLE_UNKNOWN"], context=claim_context,
        ),
        _control(
            "role-not-assigned", "RA_REFUSED_ROLE_NOT_ASSIGNED", "claim-promotion", base,
            [control_signature("control-only-producer", "adjudicator")],
            "REFUSED", ["RA_REFUSED_ROLE_NOT_ASSIGNED"], context=claim_context,
        ),
        _control(
            "wrong-role", "RA_REFUSED_WRONG_ROLE", "release", base,
            [control_signature("control-only-producer", "producer")],
            "REFUSED", ["RA_REFUSED_WRONG_ROLE"], context=release_context,
        ),
        _control(
            "self-authorisation", "RA_REFUSED_SELF_AUTHORISATION", "claim-promotion",
            base + [
                control_assignment("control-only-producer", "adjudicator",
                                   "P-CONTROL-PRODUCER"),
            ],
            [control_signature("control-only-producer", "adjudicator")],
            "REFUSED", ["RA_REFUSED_SELF_AUTHORISATION"],
            context={
                "scope": ["claim:control"],
                "evidenceProducer": "control-only-producer",
                "roleIdentities": {"producer": "control-only-producer"},
            },
        ),
        _control(
            "separation", "RA_REFUSED_SEPARATION", "instrument-qualification",
            base + [
                control_assignment("control-only-producer", "instrument_reviewer",
                                   "P-CONTROL-PRODUCER"),
            ],
            [control_signature("control-only-producer", "instrument_reviewer")],
            "REFUSED", ["RA_REFUSED_SEPARATION"],
            context={
                "scope": ["instrument:control"],
                "roleIdentities": {"producer": "control-only-producer"},
            },
        ),
        _control(
            "identity-unrecorded", "RA_REFUSED_IDENTITY_UNRECORDED", "claim-promotion", base,
            [control_signature("control-only-mallory", "adjudicator")],
            "REFUSED", ["RA_REFUSED_IDENTITY_UNRECORDED"], context=claim_context,
        ),
        _control(
            "signature-unverified", "RA_REFUSED_SIGNATURE_UNVERIFIED", "claim-promotion", base,
            [control_signature("control-only-alice", "root", verified=False)],
            "REFUSED", ["RA_REFUSED_SIGNATURE_UNVERIFIED"], context=claim_context,
            forbidden_codes=["RA_REFUSED_ROLE_UNKNOWN"],
        ),
        _control(
            "scope-exceeded", "RA_REFUSED_SCOPE_EXCEEDED", "claim-promotion", base,
            [control_signature("control-only-alice", "adjudicator", "claim:other")],
            "REFUSED", ["RA_REFUSED_SCOPE_EXCEEDED"], context=claim_context,
        ),
        _control(
            "expired", "RA_REFUSED_EXPIRED", "claim-promotion", [
                control_assignment("control-only-alice", "adjudicator",
                                   "P-CONTROL-ALICE", expires_at="2026-01-01"),
            ],
            [control_signature("control-only-alice", "adjudicator")],
            "REFUSED", ["RA_REFUSED_EXPIRED"], at="2026-06-01", context=claim_context,
        ),
        _control(
            "revoked", "RA_REFUSED_REVOKED", "claim-promotion", [
                control_assignment("control-only-alice", "adjudicator",
                                   "P-CONTROL-ALICE", revoked_at="2026-02-01"),
            ],
            [control_signature("control-only-alice", "adjudicator")],
            "REFUSED", ["RA_REFUSED_REVOKED"], at="2026-06-01", context=claim_context,
        ),
        _control(
            "insufficient-signers", "RA_REFUSED_INSUFFICIENT_SIGNERS", "release", base,
            [control_signature("control-only-bob", "release_authority")],
            "REFUSED", ["RA_REFUSED_INSUFFICIENT_SIGNERS"], context=release_context,
        ),
        _control(
            "duplicate-signer", "RA_REFUSED_DUPLICATE_SIGNER", "release",
            base + [
                control_assignment("control-only-alice", "release_authority",
                                   "P-CONTROL-ALICE"),
            ],
            [
                control_signature("control-only-alice", "release_authority"),
                control_signature("control-only-alice", "adjudicator"),
            ],
            "REFUSED", ["RA_REFUSED_DUPLICATE_SIGNER"], context=release_context,
        ),
        _control(
            "action-unknown", "RA_REFUSED_ACTION_UNKNOWN", "launch", base,
            [control_signature("control-only-alice", "adjudicator")],
            "REFUSED", ["RA_REFUSED_ACTION_UNKNOWN"],
        ),
    ]

    # The positive control: distinct synthetic parties, the right roles and the
    # required separation reach AUTHORISED.  It establishes the decision
    # procedure, not a real authorised action.
    positive_assignments = [
        control_assignment("control-only-release", "release_authority", "P-CONTROL-RELEASE"),
        control_assignment("control-only-adjudicator", "adjudicator", "P-CONTROL-ADJUDICATOR"),
        control_assignment("control-only-author", "producer", "P-CONTROL-AUTHOR"),
    ]
    positive = _control(
        "positive-distinct-roles", "", "release", positive_assignments,
        [
            control_signature("control-only-release", "release_authority", "release:control"),
            control_signature("control-only-adjudicator", "adjudicator", "release:control"),
        ],
        "AUTHORISED", [], context=release_context,
    )
    positive["establishes"] = (
        "the decision procedure can return AUTHORISED when distinct synthetic "
        "identities hold the required roles and satisfy the separation; it is not "
        "a real authorised action"
    )

    # NOT_RUN is an outcome, not a refusal: a policy that declares the action
    # not run, and an action that was not attempted, both reach it.
    not_run_policy = {
        "release": dict(auth.ACTIONS["release"], status="NOT_RUN",
                        notRunReason="control-only: the action was not attempted"),
    }
    not_run = _control(
        "not-run", "", "release", positive_assignments, None,
        "NOT_RUN", [], policy=not_run_policy, context=release_context,
    )
    not_run["kind"] = "not-run"
    not_run["establishes"] = "NOT_RUN is reported as an outcome and is not a pass"

    # An alias pair is one signer party, never two.
    alias = _control(
        "alias-is-one-signer", "", "release", [
            control_assignment("control-only-alias-a", "release_authority", "P-CONTROL-ONE"),
            control_assignment("control-only-alias-b", "adjudicator", "P-CONTROL-ONE"),
            control_assignment("control-only-author", "producer", "P-CONTROL-AUTHOR"),
        ],
        [
            control_signature("control-only-alias-a", "release_authority", "release:control"),
            control_signature("control-only-alias-b", "adjudicator", "release:control"),
        ],
        "REFUSED", ["RA_REFUSED_INSUFFICIENT_SIGNERS", "RA_REFUSED_SEPARATION"],
        context=release_context,
    )
    alias["kind"] = "count"
    alias["establishes"] = (
        "two identity tokens of one party are one signer and one side of a "
        "separation, not two"
    )

    refused_controls = [item for item in controls if item["kind"] == "refusal"]
    codes = sorted({item["code"] for item in refused_controls})
    missing = sorted(set(auth.REFUSAL_CODES) - set(codes))
    return {
        "schema": "openssl-rs/a14/controls/1",
        "item": ITEM,
        "sourceIdentity": identity,
        "label": "control-only",
        "controls": controls + [positive, not_run, alias],
        "counts": {
            "controls": len(controls),
            "refusalCodes": len(auth.REFUSAL_CODES),
            "codesExercised": len(codes),
            "positiveControls": 1,
            "notRunControls": 1,
            "countControls": 1,
        },
        "missingCodes": missing,
    }


def build(source_commit: str | None = None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity = source_identity()
    if source_commit:
        identity["baseCommit"] = source_commit
        identity["baseCommitShort"] = source_commit[:9]
    roles = build_roles(identity)
    authorisation = build_authorisation(identity, roles["assignments"])
    controls = build_controls(identity)
    if controls["missingCodes"]:
        raise SystemExit(
            f"a14: controls do not exercise every refusal code: {controls['missingCodes']}"
        )
    for control in controls["controls"]:
        if not control["pass"]:
            raise SystemExit(
                f"a14: control {control['name']} failed: expected "
                f"{control['expected']}, observed {control['observed']['outcome']}/"
                f"{control['observed']['codes']}"
            )
    if authorisation["aggregate"]["authorised"] != 0:
        raise SystemExit("a14: a real action was authorised; the record may not claim 0")
    return roles, authorisation, controls


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(REPO_ROOT / "evidence/a14"))
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args(argv)

    roles, authorisation, controls = build(args.source_commit)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "ROLES.json", roles)
    write_json(out / "AUTHORISATION.json", authorisation)
    write_json(out / "CONTROLS.json", controls)
    print(
        f"a14: assignments={len(roles['assignments'])} "
        f"roles={len(roles['roleVocabulary'])} "
        f"actions={authorisation['aggregate']['actions']} "
        f"authorised={authorisation['aggregate']['authorised']} "
        f"refused={authorisation['aggregate']['refused']} "
        f"codes={controls['counts']['codesExercised']} "
        f"controls={len(controls['controls'])} "
        f"commit={roles['sourceIdentity']['baseCommitShort']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
