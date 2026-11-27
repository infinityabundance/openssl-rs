#!/usr/bin/env python3
"""Rewrite the PFP-3 EXPERIMENT arm in ARMS.json (idempotent).

The campaign now runs from the clean commit 289f11187 and every deferred
conjunct exists at DSO 04611380.  The arm stays EXPERIMENT, not CANDIDATE: the
constant-time audit found a secret-derived conditional transfer in the
fixed-base admission (`je` at ossl_ec_wNAF_mul+0x1938, the ct_ge(k, n) early
exit), and the campaign rule makes that a STOP.  The measurement, the passing
differential, the mutation control and the audit are all recorded at the same
digest; the STOP is the one thing the arm cannot declare away.
"""

import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
PATH = REPO / "evidence/performance-frontier/admission/ARMS.json"
DSO = "04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4"
COMMIT = "289f111877ce7aa9a9a76d25bf76357f57ed6582"
DIFF = "evidence/performance-frontier/campaigns/PFP-3/dso-differential/differential-dso-bound.json"
AUDIT_MD = "evidence/performance-frontier/campaigns/PFP-3/audit/AUDIT.md"
AUDIT_RAW = "evidence/performance-frontier/campaigns/PFP-3/audit/raw/audit-pfp3.md"
CARRIERS = "evidence/performance-frontier/campaigns/PFP-3/audit/raw/carriers.json"
CT_MD = "evidence/performance-frontier/campaigns/PFP-3/ctgrind/pfp3-2026-11-27/CTGRIND.md"
MUT_JSON = "evidence/performance-frontier/campaigns/PFP-3/mutation/raw/mutation-record.json"
MUT_MD = "evidence/performance-frontier/campaigns/PFP-3/mutation/MUTATION.md"
RESULTS = "evidence/performance-frontier/campaigns/PFP-3/timing-04611380/results.json"
ECDH = "evidence/performance-frontier/campaigns/PFP-3/timing-04611380/raw/ecdh-timing.json"

arm = {
    "arm_id": "PFP-3",
    "assurance": {"safe_compatible": False, "semantic_assurance": False},
    "candidate": {
        "artefact": {
            "label": "distribution-shaped libcrypto.so.3 from clean staging commit 289f11187 (PFP-3)",
            "sha256": DSO,
        },
        "build_profile": (
            "release, x86_64-unknown-linux-gnu, rustc 1.98.1; clean committed tree "
            "289f111877ce7aa9a9a76d25bf76357f57ed6582 (src tree 11a5d18f); src fingerprint "
            "ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a; a fresh-target "
            "rebuild reproduces the DSO and archive 6c2133c0 byte for byte"
        ),
        "source_commit": COMMIT,
    },
    "constant_time_audit": {
        "kind": "CTGRIND_PLUS_BRANCH_AUDIT",
        "candidate_sha256": DSO,
        "harness_kind": (
            "pfp3_dso_ct.c: the PFP-21 DSO harness with one added population "
            "(mul-g-fixed, EC_POINT_mul(k,NULL,NULL)); taint verification, "
            "LOADED/MAPS/FOREIGN identity proof and the attribution classifier unchanged"
        ),
        "harness_sha256": "5840dbd51e76cce9eefb611067ce2aaf6ac15d71486ae0e76832ed5da5d5faa3",
        "branch_audit_harness_sha256": "5d54f3a1995263032fbdd23f9ccd533b50fa53b283199b2e1f43a3002cd1dfd4",
        "branch_audit": {"path": AUDIT_RAW, "present": True,
                         "sha256": "7b8b0b5e5b421ee57c600b23418023228b0de93349fb28c47f8ceb90dcf3c6bc"},
        "branch_audit_carriers": {"path": CARRIERS, "present": True,
                                  "sha256": "e266c3fc75bcb6e04e6cc9d6381567eddcc083a58a84c8d9803b774e8dc5982d"},
        "ctgrind": {
            "engine_on_path": 0,
            "engine_origins": 0,
            "secret_derived_conditional_transfers": 1,
            "finding": (
                "je at ossl_ec_wNAF_mul+0x1938 (file vaddr 0x242138), condition the "
                "ct_ge(k, ORDER_MODULUS) admission result: a secret-dependent early exit. "
                "try_fixed_base_mul is inlined into the ec::mult driver, so the frame is "
                "named ossl_ec_wNAF_mul and the classifier's engine-on-path is 0."
            ),
            "populations": {
                "mul_g_fixed": {"errors": [1, 1, 1], "contexts": [1, 1, 1]},
                "mul_g": {"errors": [3621, 3606, 3670], "contexts": [200, 197, 233]},
                "sign": {"errors": [123, 123, 123], "contexts": [120, 120, 120]},
                "control": {"errors": [0], "contexts": [0]},
            },
            "sensitivity_control": {
                "artefact": "83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f",
                "engine_on_path_per_repetition": 4,
                "limit": "predates the comb; establishes that the harness sees engine code on the same call shape, not that it reaches the new carrier",
            },
        },
        "branch_audit_carriers_classification": {
            "rcb_add": {"jcc": 0, "cmov": 0, "setcc": 40,
                        "class": "branch-free; setcc are carry/borrow masks, not transfers"},
            "table_mul": {"jcc": 2, "cmov": 0, "setcc": 2, "class": "public loop counters"},
            "to_affine": {"jcc": 2, "cmov": 0, "setcc": 0, "class": "loop + public exponent bit"},
            "build_table": {"jcc": 1, "cmov": 0, "setcc": 0, "class": "public table loop"},
            "advance": {"jcc": 1, "cmov": 0, "setcc": 0, "class": "public doubling loop"},
            "ossl_ec_wNAF_mul": {"jcc": 186, "cmov": 33, "setcc": 5, "div": 4,
                                 "class": "general wNAF (pre-existing) + inlined fixed-base admission; secret-derived jcc at +0x1938"},
        },
        "mutation_control": {
            "control_b_sha256": "e4b2cb6e204443e1d696ceb8241b439100e9f0317a3de879400812db7cb3ac73",
            "difference": "admits final true -> false (fallback ladder)",
            "differential_mul_g_mismatches": {"a": 0, "b": 0, "count": 4096},
            "mul_g_ir_ratio": 2.049747139511887,
            "mul_g_wall_ratio": 1.95944639380138,
            "record": {"path": MUT_JSON, "present": True,
                       "sha256": "d56c5db1630989d86c92c16ec3c88b03060dec400edfc8c0e962c8568615b6b1"},
        },
        "result": (
            "STOP: one secret-derived conditional transfer in the fixed-base admission; "
            "shared inventory 31/31 exit 0; six carriers exact-symbol resolved; the jcc "
            "is reproduced by ctgrind and by the branch audit"
        ),
        "reference": {"path": AUDIT_MD, "present": True,
                      "sha256": "af371f4d1a0f190c8c3b657b8bae5317d5cd445abfe422bfe39cf7cec71a9d94"},
    },
    "description": (
        "fixed-base P-256 multiplication: a 16-entry comb table derived at first use from the "
        "tracked EC_CURVE_DATA generator, masked full-scan constant-time selection, and exact-group "
        "admission with refusal tests; DSO-bound differential of 4,096 k*G and 4,096 k*P plus ECDSA "
        "cross-verification at 04611380; the fixed-base admission carries a secret-derived conditional "
        "transfer (ct_ge(k, n) early exit), which is a STOP for the constant-time conjunct"
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
    "measurement": {
        "candidate_sha256": DSO,
        "classification": "SCOPED_OBSERVATION",
        "identity": {
            "instrument": (
                "cross-library single-operation latency, 15 paired processes pinned to one CPU, "
                "median of paired ratios with a 20,000-resample percentile bootstrap (ecdsa256); "
                "the ecdh row uses the PFP-29 per-path instrument with the same conventions"
            ),
            "population": "40d1537b1a86851a17c49636cd5620704c4836bf6153074fd964f1c3a4fe691e",
            "source": "289f111877ce7aa9a9a76d25bf76357f57ed6582, the clean committed PFP-3 source; the DSO was rebuilt from it",
            "target": "x86_64-unknown-linux-gnu release",
            "tool": "courts/phase18/timing/bench_api.c, analyse_bench_api.py; timing-04611380/run_timing.sh; pfp29_paths.c for ecdh",
        },
        "population": {
            "digest": "40d1537b1a86851a17c49636cd5620704c4836bf6153074fd964f1c3a4fe691e",
            "frozen_at": "c9a0fdd58429ef13ca9b25ddccbc84a832787277",
            "frozen_before_execution": True,
        },
        "record": {"path": RESULTS, "present": True,
                   "sha256": "81da64153ad33e4c9b47d9e29cc77d617f359d5ec5b29dc7880aa35bb038a0e5"},
        "ecdsa256": {"candidate_us": 135.695, "authority_us": 12.730,
                     "ratio": 10.64, "ci95": [10.61, 10.67]},
        "ecdh": {"candidate_us": 222.658, "authority_us": 32.805,
                 "ratio": 6.79, "ci95": [4.69, 6.90],
                 "record": {"path": ECDH, "present": True,
                            "sha256": "e3ec3f97d261c5d9926807cc816ab4b0ff9d8478d847e9163fef6d8483e3d9b6"}},
    },
    "queue_item": "PFP-3",
    "reuse": None,
    "shortcuts": [],
    "status": "EXPERIMENT",
    "timing_obligations": {
        "attempted_discharge": [],
        "none_open_because": None,
        "open": [
            {
                "description": (
                    "The fixed-base admission branches on the secret-derived ct_ge(k, n) result "
                    "(je at ossl_ec_wNAF_mul+0x1938). Remove it, or establish without branching on a "
                    "secret-derived value that the predicate is independent of the secret for the "
                    "admitted population. This is a src/ change and is not made here."
                ),
                "discharged": False,
                "id": "PFP3-CT-BRANCH",
            },
            {
                "description": (
                    "The PFP-34 coverage mapping still lists the ladder targets for the ecdsa-sign "
                    "paths; at this candidate those paths route to the fixed-base comb, so the "
                    "coverage-to-path join is stale and must be extended to the fixed-base carriers "
                    "before the release gate can speak about this candidate."
                ),
                "discharged": False,
                "id": "PFP3-P34-COVERAGE",
            },
            {
                "description": "T23/T24/T29 timing residuals are unchanged by PFP-3.",
                "discharged": False,
                "id": "PFP3-T23-T24-T29",
            },
        ],
    },
}

doc = json.loads(PATH.read_text(encoding="utf-8"))
doc["arms"] = [a for a in doc["arms"] if a.get("arm_id") != "PFP-3"]
doc["arms"].append(arm)
PATH.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", PATH, "arms:", [a["arm_id"] for a in doc["arms"]])
