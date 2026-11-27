#!/usr/bin/env python3
"""Rewrite the PFP-3 arm in ARMS.json after the branch-free admission.

Before: the arm was an EXPERIMENT at DSO 04611380 because the fixed-base
admission carried a secret-derived conditional transfer (`je` at
ossl_ec_wNAF_mul+0x1938, the ct_ge(k, n) early exit).

After: the admission folds the in-range mask into the scalar the comb consumes,
so the decision is exact and arithmetic.  At DSO ecbefb7d the same ctgrind
harness reports 0 contexts on mul-g-fixed, the pre-PFP-20 sensitivity control
still fires, and the branch audit has no admission-mask jcc.  The measurement,
the differential court and the constant-time audit are all at ecbefb7d, so the
arm is a CANDIDATE.  Every cited digest below is computed from the file itself.
"""

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
PATH = REPO / "evidence/performance-frontier/admission/ARMS.json"
DSO = "ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053"
COMMIT = "f8d5c4b33cf751a0dd805fa7cf0d730915e1d073"
SRC_FP = "52219f14f2402ffcb2b1ce5abcc843c168b79fb4798b9db66e50b5683c3b0aee"
ARCHIVE = "14f76179c517213a35c3c1d69e3dccb722e228f7e12a81efceecb15bdac12bf6"
POPULATION = "40d1537b1a86851a17c49636cd5620704c4836bf6153074fd964f1c3a4fe691e"
HARNESS_SRC = "ea18ec93bb961328d6c268b4fc1307e0489c01ea62f0a1c33ba962fafa85771d"
HARNESS_BIN = "c89d64d892b941e8d148b9662e2adc6781e054adb8bda637914c95820d5fb732"

CT = "evidence/performance-frontier/campaigns/PFP-3/ctgrind/pfp3-2026-11-27-postfix"
AUD = "evidence/performance-frontier/campaigns/PFP-3/audit-postfix"
DIFF = "evidence/performance-frontier/campaigns/PFP-3/dso-differential-postfix"
TIME = "evidence/performance-frontier/campaigns/PFP-3/timing-ecbefb7d"
PFP = "evidence/performance-frontier/campaigns/PFP-3"


def sha(rel: str) -> str:
    return hashlib.sha256((REPO / rel).read_bytes()).hexdigest()


def ref(rel: str) -> dict:
    return {"path": rel, "present": True, "sha256": sha(rel)}


arm = {
    "arm_id": "PFP-3",
    "assurance": {"safe_compatible": False, "semantic_assurance": False},
    "candidate": {
        "artefact": {
            "label": "distribution-shaped libcrypto.so.3 from staging f8d5c4b33 + uncommitted branch-free fixed-base admission (PFP-3 post-fix)",
            "sha256": DSO,
        },
        "build_profile": (
            "release, x86_64-unknown-linux-gnu, rustc 1.98.1; staging "
            f"{COMMIT} with an uncommitted src/ec/p256/fixed_base.rs branch-free "
            f"admission (source fingerprint {SRC_FP}, 887 files; "
            "build_relevant_clean=false, recorded in the timing identity); two "
            f"fresh-target builds reproduce the DSO and archive {ARCHIVE} byte for byte"
        ),
        "source_commit": COMMIT,
    },
    "constant_time_audit": {
        "kind": "CTGRIND_PLUS_BRANCH_AUDIT",
        "candidate_sha256": DSO,
        "harness_kind": (
            "pfp3_dso_ct.c: the PFP-21 DSO harness with all eight populations, "
            "the limb-value taint, LOADED/MAPS/FOREIGN identity proof, negative "
            "control and attribution classifier unchanged; only the candidate "
            "digest/path changed"
        ),
        "harness_sha256": HARNESS_BIN,
        "harness_source_sha256": HARNESS_SRC,
        "branch_audit_harness_sha256": "5d54f3a1995263032fbdd23f9ccd533b50fa53b283199b2e1f43a3002cd1dfd4",
        "branch_audit": ref(f"{AUD}/raw/audit-pfp3.md"),
        "branch_audit_carriers": ref(f"{AUD}/raw/carriers.json"),
        "ctgrind": {
            "engine_on_path": 0,
            "engine_origins": 0,
            "secret_derived_conditional_transfers": 0,
            "finding": (
                "none. The pre-fix je at ossl_ec_wNAF_mul+0x1938 (the "
                "ct_ge(k, n) admission early exit) is gone: the in-range mask is "
                "folded into the scalar the comb consumes. mul-g-fixed is 0/0/0 "
                "errors/contexts (was 1/1/1); the pre-PFP-20 sensitivity control "
                "still reports 4 engine-on-path per repetition."
            ),
            "populations": {
                "mul_g_fixed": {"errors": [0, 0, 0], "contexts": [0, 0, 0]},
                "mul_g": {
                    "errors": [3645, 3631, 3606],
                    "contexts": [225, 209, 196],
                },
                "mul_p": {
                    "errors": [3596, 3606, 3670],
                    "contexts": [186, 197, 236],
                },
                "mul_g_bytes": {
                    "errors": [3661, 3636, 3607],
                    "contexts": [228, 216, 197],
                },
                "sign": {"errors": [122, 122, 122], "contexts": [119, 119, 119]},
                "sign_ex": {"errors": [24, 24, 24], "contexts": [24, 24, 24]},
                "sign_ex_k": {
                    "errors": [33042, 33007, 32978],
                    "contexts": [460, 442, 427],
                },
                "control": {"errors": [0], "contexts": [0]},
            },
            "sensitivity_control": {
                "artefact": "83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f",
                "engine_on_path_per_repetition": 4,
                "limit": "predates the comb; establishes that the harness sees engine code on the same call shape, not that it reaches the new carrier",
            },
        },
        "branch_audit_carriers_classification": {
            "rcb_add": {
                "jcc": 0,
                "cmov": 0,
                "setcc": 40,
                "class": "branch-free; setcc are carry/borrow masks, not transfers",
            },
            "table_mul": {
                "jcc": 2,
                "cmov": 0,
                "setcc": 2,
                "class": "public loop counters",
            },
            "to_affine": {
                "jcc": 2,
                "cmov": 0,
                "setcc": 0,
                "class": "loop + public exponent bit",
            },
            "build_table": {
                "jcc": 1,
                "cmov": 0,
                "setcc": 0,
                "class": "public table loop",
            },
            "advance": {
                "jcc": 1,
                "cmov": 0,
                "setcc": 0,
                "class": "public doubling loop",
            },
            "ossl_ec_wNAF_mul": {
                "jcc": 183,
                "cmov": 34,
                "setcc": 5,
                "div": 4,
                "class": "general wNAF (pre-existing); no secret-derived jcc; the admission-mask jcc (test $0x1,%cl) is absent (pre-fix 186 jcc)",
            },
        },
        "mutation_control": {
            "control_b_sha256": "e4b2cb6e204443e1d696ceb8241b439100e9f0317a3de879400812db7cb3ac73",
            "difference": "admits final true -> false (fallback ladder)",
            "differential_mul_g_mismatches": {"a": 0, "b": 0, "count": 4096},
            "mul_g_ir_ratio": 2.049747139511887,
            "mul_g_wall_ratio": 1.95944639380138,
            "record": {
                "path": f"{PFP}/mutation/raw/mutation-record.json",
                "present": True,
                "sha256": sha(f"{PFP}/mutation/raw/mutation-record.json"),
            },
            "digest_scope": "control built from the pre-fix candidate at 04611380; not re-run at ecbefb7d. It establishes that the comb (not a ladder fallback) is load-bearing, not a post-fix timing claim.",
        },
        "result": (
            "PASS: zero secret-derived conditional transfers on mul-g-fixed; "
            "shared inventory 31/31 exit 0; six carriers resolved; wNAF jcc "
            "186 -> 183 and no test $0x1,%cl admission-mask jcc; ctgrind "
            "independently reports 0 contexts and the pre-PFP-20 sensitivity "
            "control still fires"
        ),
        "reference": ref(f"{AUD}/AUDIT.md"),
    },
    "description": (
        "fixed-base P-256 multiplication: a 16-entry comb table derived at first use "
        "from the tracked EC_CURVE_DATA generator, masked full-scan constant-time "
        "selection, and exact-group admission with refusal tests; the scalar range "
        "admission is now branch-free (the in-range mask is folded into the scalar the "
        "comb consumes, so an out-of-range value is replaced by k-n before "
        "multiplication) at DSO ecbefb7d; DSO-bound differential of 4,096 k*G and "
        "4,096 k*P plus ECDSA cross-verification; ctgrind 0 contexts on mul-g-fixed "
        "and no admission-mask branch in the audit"
    ),
    "differential_courts": {
        "candidate_sha256": DSO,
        "note": (
            "4,096 k*G and 4,096 k*P serialised points compared with the authority, "
            "0 mismatches (candidate streams equal the authority a9e1068d… and "
            "bcb22a91…); 256+256 ECDSA cross-verifications accepted with one agreed "
            "public key; 8/8 identity rows ok. In-crate 4,096-case "
            "fixed-versus-variable differential also 0 mismatches, and the new "
            "out-of-range test checks k = n, n+1, n+2, 2^256-1 against the ladder."
        ),
        "reference": ref(f"{DIFF}/differential-dso-bound.json"),
        "result": "PASS",
    },
    "measurement": {
        "candidate_sha256": DSO,
        "classification": "SCOPED_OBSERVATION",
        "identity": {
            "instrument": (
                "cross-library single-operation latency, 15 paired processes pinned "
                "to one CPU, median of paired ratios with a 20,000-resample "
                "percentile bootstrap (ecdsa256); the ecdh row uses the PFP-29 "
                "per-path instrument with the same conventions"
            ),
            "population": POPULATION,
            "source": (
                f"{COMMIT} with the uncommitted branch-free fixed-base admission "
                "(build_relevant_clean=false); the DSO was rebuilt from it and two "
                "fresh builds reproduce ecbefb7d"
            ),
            "target": "x86_64-unknown-linux-gnu release",
            "tool": "courts/phase18/timing/bench_api.c, analyse_bench_api.py; timing-ecbefb7d/run_timing.sh; pfp29_paths.c for ecdh",
        },
        "population": {
            "digest": POPULATION,
            "frozen_at": "c9a0fdd58429ef13ca9b25ddccbc84a832787277",
            "frozen_before_execution": True,
        },
        "record": ref(f"{TIME}/results.json"),
        "ecdsa256": {
            "candidate_us": 134.485,
            "authority_us": 12.721,
            "ratio": 10.58,
            "ci95": [10.55, 10.62],
        },
        "ecdh": {
            "candidate_us": 224.290,
            "authority_us": 33.165,
            "ratio": 6.72,
            "ci95": [6.67, 6.83],
            "record": ref(f"{TIME}/raw/ecdh-timing.json"),
        },
    },
    "queue_item": "PFP-3",
    "reuse": None,
    "shortcuts": [],
    "status": "CANDIDATE",
    "timing_obligations": {
        "attempted_discharge": [],
        "none_open_because": None,
        "open": [
            {
                "description": (
                    "The PFP-34 coverage mapping still lists the ladder targets for "
                    "the ecdsa-sign paths; at this candidate those paths route to the "
                    "fixed-base comb, so the coverage-to-path join is stale and must be "
                    "extended to the fixed-base carriers before the release gate can "
                    "speak about this candidate."
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
if "author" in doc and isinstance(doc["author"], dict):
    doc["author"]["identity"] = (
        "openssl-rs performance programme (staging session, 2026-11-27)"
    )
PATH.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", PATH, "arms:", [a["arm_id"] for a in doc["arms"]])
print("PFP-3 status:", arm["status"], "DSO:", DSO)
