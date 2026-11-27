#!/usr/bin/env python3
"""Append the PFP-3 EXPERIMENT arm to ARMS.json (idempotent).

The campaign does not commit, so the arm's `source_commit` is the staging HEAD
and its build profile records that the artefact was built from the uncommitted
working tree identified by the src fingerprint. Measurement and constant-time
audit are null; the open obligations name exactly what is missing.
"""

import json
from pathlib import Path

REPO = Path("/work")
PATH = REPO / "evidence/performance-frontier/admission/ARMS.json"
DSO = "04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4"
DIFF = "evidence/performance-frontier/campaigns/PFP-3/dso-differential/differential-dso-bound.json"

arm = {
    "arm_id": "PFP-3",
    "assurance": {"safe_compatible": False, "semantic_assurance": False},
    "candidate": {
        "artefact": {
            "label": "distribution-shaped libcrypto.so.3 from the PFP-3 working tree on staging HEAD b0ada60eb",
            "sha256": DSO,
        },
        "build_profile": (
            "release, x86_64-unknown-linux-gnu, rustc 1.98.1; uncommitted working tree "
            "(src/ec/mult.rs and src/ec/p256.rs modified, src/ec/p256/fixed_base.rs added), "
            "src fingerprint ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a; "
            "two independent clean builds reproduce the DSO and the static archive byte for byte"
        ),
        "source_commit": "b0ada60ebd72432daaef68d8ee6d7cd5245f7895",
    },
    "constant_time_audit": None,
    "description": (
        "fixed-base P-256 multiplication: a 16-entry comb table derived at first use from the "
        "tracked EC_CURVE_DATA generator, masked full-scan constant-time selection, and exact-group "
        "admission with refusal tests; DSO-bound differential of 4,096 k*G and 4,096 k*P plus ECDSA "
        "cross-verification at 04611380"
    ),
    "differential_courts": {
        "candidate_sha256": DSO,
        "note": (
            "4,096 k*G and 4,096 k*P serialised points compared with the authority, 0 mismatches; "
            "256+256 ECDSA cross-verifications accepted with one agreed public key; 8/8 identity rows "
            "ok. In-crate 4,096-case fixed-versus-variable differential also 0 mismatches."
        ),
        "reference": {
            "path": DIFF,
            "present": True,
            "sha256": "a014588b7dc6cc0d8646c407ea104a5d766f1e139eb012c65f252a1e8dce116a",
        },
        "result": "PASS",
    },
    "measurement": None,
    "queue_item": "PFP-3",
    "reuse": None,
    "shortcuts": [],
    "status": "EXPERIMENT",
    "timing_obligations": {
        "attempted_discharge": [],
        "none_open_because": None,
        "open": [
            {
                "description": "No preregistered 15-repetition timing at 04611380: the identity guard requires a clean committed source and this campaign may not commit, so no latency, trend or speedup is claimed.",
                "discharged": False,
                "id": "PFP3-TIMING",
            },
            {
                "description": "No DSO-level ctgrind at 04611380; there is no engine-origin context count for the fixed-base code.",
                "discharged": False,
                "id": "PFP3-CTGRIND",
            },
            {
                "description": "No binary branch audit at 04611380; no jcc/setcc/cmov classification exists, so no constant-time claim is made.",
                "discharged": False,
                "id": "PFP3-BINARY-BRANCH-AUDIT",
            },
            {
                "description": "The candidate is built from an uncommitted working tree; it is reproducible from the recorded src fingerprint, not from a commit.",
                "discharged": False,
                "id": "PFP3-DIRTY-CANDIDATE",
            },
            {
                "description": "Three audit targets are named but not checked at the artefact: the scalar-metadata admission branch, if-conversion of the masked select to a conditional branch, and the fixed-size write-back.",
                "discharged": False,
                "id": "PFP3-AUDIT-TARGETS",
            },
            {
                "description": "T23/T24/T29 timing residuals are unchanged by PFP-3.",
                "discharged": False,
                "id": "PFP3-T23-T24-T29",
            },
            {
                "description": "No DSO-level mutation control proves the fixed-base arm (rather than a ladder fallback) produced the 4,096 k*G results; the in-crate probe confirms the arm in the test build only.",
                "discharged": False,
                "id": "PFP3-DSO-MUTATION-CONTROL",
            },
        ],
    },
}

doc = json.loads(PATH.read_text(encoding="utf-8"))
doc["arms"] = [a for a in doc["arms"] if a.get("arm_id") != "PFP-3"]
doc["arms"].append(arm)
PATH.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", PATH, "arms:", [a["arm_id"] for a in doc["arms"]])
