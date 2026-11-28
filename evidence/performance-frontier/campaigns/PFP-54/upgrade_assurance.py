#!/usr/bin/env python3
"""PFP-54: add the ARTEFACT_AUDITED dimension to the carriers the audit covered.

PFP-49 says the assurance classes are *dimensions, not a ladder*.  The register's
`claims` layer cites the historical SOURCE_REVIEWED entries by evidence index, so
replacing them in place makes those claims stale (KV_ASSURANCE_CLASS_ABSENT) --
the schema working, not a defect to relax.  This script therefore adds one
ARTEFACT_AUDITED entry per covered carrier at the new artefact and leaves the
historical SOURCE_REVIEWED entries and their claims intact.

Only kernels whose carriers are among the 31 targets the branch audit actually
covered are touched.  p256-fixed-comb (not in the inventory), the SOURCE_TAINT_
TESTED bn-cias-* kernels, and the UNASSESSED kernels (bn-mont-sqr, p256-field-
arch, rsa-crt) are left exactly as they were.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[4]
REGISTER = ROOT / "forensics/performance/KERNELS.json"
RECORD = ROOT / "evidence/performance-frontier/campaigns/PFP-34/audit-record.json"

DSO = "a535454753d8857e4c385689ea431b5a47a9686322e6f52b203971188a49359f"
DBG = "cd64dd590a597116f8475f6db0c81cc94602d74d540d4b45b4b1bae1a0b7ed9b"
BUILD_ID = "83eccb95e79216e5b53b46389df55fda6f9a9dee"
DSO_PATH = "evidence/performance-frontier/campaigns/PFP-54/raw/artefacts/libcrypto.so.3"
AUDIT_PATH = "evidence/performance-frontier/campaigns/PFP-54/raw/audit-a5354547.md"
TOOL = "courts/phase18/timing/binary_branch_audit.py"

TARGET = ("x86_64-unknown-linux-gnu release, court openssl-rs-court:1, "
          "rustc 1.98.1 (48a229cea)")
PROFILE = ("release, x86_64-unknown-linux-gnu, rustc 1.98.1 (48a229cea 2026-09-01); "
           "CARGO_PROFILE_RELEASE_DEBUG=1; objcopy --only-keep-debug/--strip-debug/"
           "--add-gnu-debuglink; build-id " + BUILD_ID)
SOURCE = ("staging f536fd63913073bab76f839d41e89617da4fa74c, tree "
          "4fef3b02666120f261bc00c43e2e6e04c50cd013; one release compilation; "
          "detached DWARF companion sha256 " + DBG)

COVERED = {
    "bn-mont-sos": ["mont_mul_sos_into", "mont_mul_fallible"],
    "bn-window-ladder": ["run_mont_ladder", "mod_exp_core_consttime_from_parts",
                         "mod_inverse_consttime"],
    "p256-field-mont": ["p256::mont_reduce_into", "p256::wide_mul_x86"],
    "p256-order-inverse": ["mod_inverse_consttime"],
    "dh-width-policy": ["ossl_dh_compute_key", "run_mont_ladder",
                        "mont_mul_sos_into", "mont_mul_fallible"],
}


def main() -> int:
    document = json.loads(REGISTER.read_text())
    record = json.loads(RECORD.read_text())
    tool_sha = hashlib.sha256((ROOT / TOOL).read_bytes()).hexdigest()

    document["campaigns"]["PFP-54"] = {
        "artefact": {
            "binding": "ARTEFACT",
            "sha256": DSO,
            "target": TARGET,
            "profile": PROFILE,
            "source": SOURCE,
        }
    }

    assumptions = [
        ("the shipped DSO is debug-stripped; the DWARF it was audited through is "
         "the detached companion artefacts/libcrypto.so.3.debug, bound by build-id "
         + BUILD_ID),
        ("only key::decap carries a mechanised secret-dependence contract; for every "
         "other target the audit prints branch provenance and instruction counts, not "
         "taint, so this class records what the audit observed and does not assert "
         "constant time"),
        ("the audit covers the 31-target inventory; optimised, duplicated or partially "
         "inlined functions outside it, and any artefact other than the DSO digest "
         "named here, are not covered"),
    ]
    instrument = (f"{TOOL} sha256 {tool_sha}; GNU objdump/readelf 2.40; detached "
                  f"DWARF companion sha256 {DBG}")

    def counts(target: str) -> str:
        o = record["targets"][target]["observed"]
        return f"{target} {o['jcc']} jcc / {o['cmov']} cmov / {o['setcc']} setcc"

    kernels = {k["id"]: k for k in document["kernels"]}
    added = []
    for kernel_id, carriers in COVERED.items():
        kernel = kernels[kernel_id]
        prior = [a.get("class") for a in kernel["assurance"]]
        detail = "; ".join(counts(t) for t in carriers)
        evidence = {
            "campaign": "PFP-54",
            "artefact_sha256": DSO,
            "target": TARGET,
            "profile": PROFILE,
            "binding": "ARTEFACT",
            "differential": None,
            "audit": {
                "kind": "BINARY_BRANCH_AUDIT",
                "result": (f"detached-DWARF binary branch audit at DSO {DSO[:12]} "
                           f"resolved 31/31 targets; {detail}; 0 secret-derived jcc; "
                           "0 secret-derived address"),
                "verdict": "PASS",
                "digest": DSO,
                "binding": "ARTEFACT",
            },
            "ctgrind": None,
        }
        kernel["evidence"].append(evidence)
        index = len(kernel["evidence"]) - 1
        kernel["assurance"].append({
            "class": "ARTEFACT_AUDITED",
            "scope": (
                "PFP-54 f536fd639130 / DSO a535454753d88: the branch audit resolves "
                "31/31 targets and covers " + ", ".join(carriers) + f" ({detail}). "
                "One secret-derived setcc (key::decap, consumed arithmetically) and "
                "zero secret-derived conditional transfers or memory addresses were "
                "observed. A binary branch audit is not a constant-time proof; the "
                f"historical {prior} entries remain as the evidence they record."),
            "evidence": index,
            "subject": {
                "source": SOURCE,
                "artefact": {"path": DSO_PATH, "sha256": DSO},
            },
            "assumptions": list(assumptions),
            "result": "PASS",
            "instrument": instrument,
            "evidence_path": AUDIT_PATH,
        })
        added.append(f"{kernel_id} (prior {prior})")

    REGISTER.write_text(json.dumps(document, indent=1) + "\n")
    print("added ARTEFACT_AUDITED to:", "; ".join(added))
    print("register sha256:", hashlib.sha256(REGISTER.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
