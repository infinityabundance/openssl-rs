#!/usr/bin/env python3
"""Deterministic producer of the A23 records.

The specification is a declaration, not a transcription of the code: it is
written here, hashed into ``SPEC.json``, and the reference evaluator in
``forensics/tools/verifier_formalisation.py`` is implemented from it.  The
producer then runs the exhaustive differential, the invariants and the controls,
and writes four records:

    python3 evidence/a23/build_evidence.py [--out DIR]

The default output directory is this file's directory.  ``--out`` exists so the
gate can compare two runs.  No timestamp is written anywhere, every array is
built in a deterministic order, and two runs over the same tree reproduce the
same bytes.

The producer exits 0 only when every record agrees; a disagreement is preserved
in the record and the process exits 1 with ``VF_REFUSED_DISAGREEMENT``.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

HERE = Path(__file__).resolve().parent
BASE_COMMIT = "7c2b5f25fe55e6302b942ed124f4fbec5aff8888"
TOOL = "forensics/tools/verifier_formalisation.py"
DOCUMENT = "docs/VERIFIER-FORMALISATION.md"

SCHEMA_SPEC = "openssl-rs/a23/verifier-formalisation-spec/1"
SCHEMA_DIFFERENTIAL = "openssl-rs/a23/differential/1"
SCHEMA_PROPERTIES = "openssl-rs/a23/properties/1"
SCHEMA_CONTROLS = "openssl-rs/a23/controls/1"


def specification() -> dict[str, Any]:
    """The rules, written before the reference and independent of the module."""
    return {
        "schema": SCHEMA_SPEC,
        "subject": (
            "the decision rules of the release verifier: the obligation conjunction, "
            "the distinct-trust-domain threshold and correction-chain admission"
        ),
        "states": ["MET", "UNMET", "UNKNOWN", "NOT_APPLICABLE"],
        "decisions": ["ADMIT", "DENY"],
        "rules": [
            {
                "id": "VF-R1",
                "name": "obligation-state-vocabulary",
                "level": "L1",
                "statement": (
                    "An obligation's recorded state is exactly one of MET, UNMET, "
                    "UNKNOWN or NOT_APPLICABLE. No other state is admissible, and a "
                    "state vector containing one is unspecified rather than decided."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 2.1"],
                "reference": "reference_decide",
                "enforcedBy": [
                    "VF_REFUSED_UNSPECIFIED_RULE",
                    "test_reference_rejects_an_unspecified_state",
                ],
            },
            {
                "id": "VF-R2",
                "name": "conjunction",
                "level": "L1",
                "statement": (
                    "The decision is ADMIT if and only if the required set is non-empty "
                    "and every required obligation's state is MET; otherwise it is DENY. "
                    "There is no score, weight, count of passing obligations, threshold "
                    "or aggregation key that contributes to the decision."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 2.1"],
                "reference": "reference_decide",
                "enforcedBy": [
                    "VF_REFUSED_DISAGREEMENT",
                    "test_decision_differential_small_domain",
                    "test_decision_differential_real_policy",
                ],
            },
            {
                "id": "VF-R3",
                "name": "unknown-is-a-refusal",
                "level": "L1",
                "statement": (
                    "An obligation whose state is UNKNOWN makes the decision DENY whether "
                    "or not the obligation is required. UNKNOWN is never read as MET and "
                    "never as NOT_APPLICABLE: an obligation nobody could evaluate is a "
                    "machinery defect in either case."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 2.1"],
                "reference": "reference_decide",
                "enforcedBy": [
                    "test_property_unknown_never_admits",
                    "wrong-reference-unknown-as-met",
                ],
            },
            {
                "id": "VF-R4",
                "name": "required-inapplicable-denies",
                "level": "L1",
                "statement": (
                    "NOT_APPLICABLE on a required obligation is not a pass: only MET "
                    "satisfies a required obligation, so a required obligation that is "
                    "inapplicable denies. NOT_APPLICABLE on a non-required obligation "
                    "does not decide."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 2.1"],
                "reference": "reference_decide",
                "enforcedBy": [
                    "test_property_required_inapplicable_denies",
                    "wrong-reference-not-applicable-as-met",
                ],
            },
            {
                "id": "VF-R5",
                "name": "no-required-obligation-denies",
                "level": "L1",
                "statement": (
                    "A state vector with no required obligation admits nothing. Denial by "
                    "default: an empty required set is not an all-met proof."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 2.2"],
                "reference": "reference_decide",
                "enforcedBy": ["test_decision_differential_small_domain"],
            },
            {
                "id": "VF-R6",
                "name": "canonical-order-independence",
                "level": "L1",
                "statement": (
                    "The decision is a pure function of the obligation state vector and "
                    "the policy's required set. Permuting the state vector and its required "
                    "flags together changes no decision; canonical (ascending-id) order is "
                    "for recording, not for deciding."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 2.3"],
                "reference": "reference_decide",
                "enforcedBy": ["test_property_canonical_order_independence"],
            },
            {
                "id": "VF-R7",
                "name": "determinism",
                "level": "L1",
                "statement": (
                    "Two evaluations of the same state vector and required set return the "
                    "same decision. No clock, random source or ambient state enters."
                ),
                "groundedIn": ["docs/POLICY-ENGINE.md section 3"],
                "reference": "reference_decide",
                "enforcedBy": ["test_property_determinism"],
            },
            {
                "id": "VF-R8",
                "name": "threshold-distinct-domains",
                "level": "L2",
                "statement": (
                    "A k-of-n threshold is MET if and only if the number of distinct "
                    "established trust domains among verified, role-valid, fresh, "
                    "non-candidate approvals is at least k. An approval's domain label is "
                    "a lookup key only: two labels whose domain records share an "
                    "establishment record (path, sha256) are one domain. A duplicate "
                    "approval on one domain counts once, and one identity contributes at "
                    "most one domain."
                ),
                "groundedIn": ["docs/TRUST-THRESHOLDS.md"],
                "reference": "reference_threshold_count",
                "enforcedBy": [
                    "test_threshold_differential",
                    "wrong-threshold-ignores-aliases",
                ],
            },
            {
                "id": "VF-R9",
                "name": "correction-chain-binding",
                "level": "L2",
                "statement": (
                    "An event is admissible if and only if every binding rule holds: its "
                    "predecessor id names a stored event, the recorded predecessor digest "
                    "is that event's canonical digest, each predecessor has at most one "
                    "successor, no chain revisits an event, a subject has at most one root "
                    "assertion, a correction names a predecessor about the same subject, "
                    "and a correction's old value is the predecessor's accepted value. The "
                    "original is never modified."
                ),
                "groundedIn": ["docs/CORRECTIONS.md section 3", "docs/CORRECTIONS.md section 4"],
                "reference": "reference_chain_admissible",
                "enforcedBy": [
                    "test_correction_differential",
                    "wrong-chain-ignores-digest",
                ],
            },
        ],
        "decision": {
            "satisfies": "MET",
            "admit": "ADMIT",
            "deny": "DENY",
            "unknown": "UNKNOWN",
            "minimumRequired": 1,
            "forbiddenContributions": ["score", "weight", "threshold", "count", "rank"],
            "statement": (
                "DENY if any obligation is UNKNOWN; else DENY if no obligation is "
                "required; else ADMIT iff every required obligation is MET; else DENY."
            ),
        },
        "threshold": {
            "counts": "distinct established trust domains",
            "requires": ["verified", "role-valid", "fresh", "non-candidate"],
            "collapseBy": "establishment record (path, sha256)",
            "duplicateApproval": "counts once",
            "identityContribution": "one domain",
            "requiredRoles": ["release_authority", "adjudicator"],
            "artefactDigest": "a" * 64,
            "moment": "2026-11-15",
            "catalogueSize": 12,
            "maxApprovals": 4,
            "inventories": ["three-distinct", "one-aliased"],
        },
        "correction": {
            "rules": [
                {"id": "VF-C1", "statement": "a correction's predecessor id names an event in the chain", "refusal": "CR_REFUSED_PREDECESSOR_MISMATCH"},
                {"id": "VF-C2", "statement": "the recorded predecessor digest is the predecessor's canonical digest", "refusal": "CR_REFUSED_PREDECESSOR_MISMATCH"},
                {"id": "VF-C3", "statement": "each event has at most one successor", "refusal": "CR_REFUSED_FORK"},
                {"id": "VF-C4", "statement": "no chain revisits an event and no predecessor points forward", "refusal": "CR_REFUSED_CYCLE"},
                {"id": "VF-C5", "statement": "a correction's predecessor is about the same subject", "refusal": "CR_REFUSED_SUBJECT_CHANGED"},
                {"id": "VF-C6", "statement": "a subject has at most one root assertion", "refusal": "CR_REFUSED_ASSERTION_EXISTS"},
                {"id": "VF-C7", "statement": "a correction's old value is the predecessor's accepted value", "refusal": "CR_REFUSED_ORIGINAL_MISMATCH"},
                {"id": "VF-C8", "statement": "an assertion does not supersede an event", "refusal": "CR_REFUSED_EVENT_INVALID"},
            ],
            "rootKinds": ["assert"],
            "successorLimit": 1,
            "cycle": "forbidden",
            "original": "preserved",
        },
        "domains": {
            "decision-small": 585,
            "decision-policy": 65536,
            "threshold": 9100,
            "correction": 386,
        },
        "limits": [
            "The enumeration is finite. Only decision-policy (4**8 = 65,536) is the whole "
            "state space of its function; decision-small, threshold and correction are "
            "declared finite domains and cannot prove the rule for inputs outside them.",
            "The enumeration covers decision functions over abstract states and declared "
            "models, not the whole tool: record reading, predicates, applicability, pins, "
            "signatures, roles and history witnesses are outside it.",
            "The reference shares an author with the implementation, so agreement is a "
            "shared reading, not independent verification (Earned Trust Article 5).",
            "No machine-checked theorem exists: no TLA+, Coq, Lean or Kani proof, and no "
            "correspondence between this model and a compiled binary (Article 7).",
        ],
    }


def write_json(path: Path, value: Any) -> bytes:
    body = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(body)
    return body


def _capture(action: Any) -> str:
    import verifier_formalisation as vf

    try:
        action()
    except vf.Refusal as refusal:
        return refusal.code
    return vf.CODE_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the A23 records deterministically")
    parser.add_argument("--out", default=str(HERE), help="output directory")
    arguments = parser.parse_args(argv)
    out = Path(arguments.out)
    out.mkdir(parents=True, exist_ok=True)

    spec = specification()
    import verifier_formalisation as vf

    spec["digest"] = vf.spec_digest(spec)
    write_json(out / "SPEC.json", spec)

    # The module caches a specification by path; a producer run after an edit must
    # read the bytes it has just written.
    vf._SPEC_CACHE.pop(REPO / "evidence/a23/SPEC.json", None)
    vf._SPEC_CACHE.pop(out / "SPEC.json", None)

    differential = vf.run_differential()
    differential["schema"] = SCHEMA_DIFFERENTIAL
    differential["baseCommit"] = BASE_COMMIT
    differential["tool"] = {
        "path": TOOL,
        "sha256": hashlib.sha256((REPO / TOOL).read_bytes()).hexdigest(),
    }
    differential["document"] = DOCUMENT
    differential_code = _capture(
        lambda: vf.assert_agreement(
            {
                "disagreements": [
                    item for domain in differential["domains"] for item in domain["disagreements"]
                ]
            },
            domain="the declared domains",
        )
    )
    differential["code"] = differential_code

    properties_record = vf.run_properties()
    properties_record["schema"] = SCHEMA_PROPERTIES
    properties_record["baseCommit"] = BASE_COMMIT
    properties_code = _capture(lambda: vf.assert_properties(properties_record))
    properties_record["code"] = properties_code

    control_rows = vf.controls()
    controls_record = {
        "schema": SCHEMA_CONTROLS,
        "baseCommit": BASE_COMMIT,
        "controls": control_rows,
        "codesCovered": sorted({row["expectedCode"] for row in control_rows}),
        "coversEveryCode": sorted({row["expectedCode"] for row in control_rows})
        == sorted(vf.REFUSAL_CODES),
        "code": _capture(lambda: vf.assert_controls(control_rows)),
    }

    write_json(out / "DIFFERENTIAL.json", differential)
    write_json(out / "PROPERTIES.json", properties_record)
    write_json(out / "CONTROLS.json", controls_record)

    overall = "VF_OK"
    for code in (differential_code, properties_code, controls_record["code"]):
        if code != "VF_OK":
            overall = code
            break
    print(
        f"a23: base={BASE_COMMIT[:9]} rules={len(spec['rules'])} "
        f"domains={len(differential['domains'])} compared={differential['compared']} "
        f"disagreements={differential['disagreements']} "
        f"properties={len(properties_record['properties'])} "
        f"allHold={str(properties_record['allHold']).lower()} "
        f"controls={len(control_rows)} codesCovered={len(controls_record['codesCovered'])} "
        f"codes={overall}"
    )
    return 0 if overall == "VF_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
