#!/usr/bin/env python3
"""One-shot edit of evidence/etp/claims.json for the ETP-T15 reconciliation.

Run from the repository root. Idempotency is not claimed; the pre-change bytes
are preserved at evidence/etp-t15/history/claims.before-reconciliation.json.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLAIMS = ROOT / "evidence/etp/claims.json"
HISTORY_CLAIMS = ROOT / "evidence/etp-t15/history/claims.before-reconciliation.json"
RECONCILIATION = ROOT / "evidence/etp-t15/RECONCILIATION.json"
HISTORY_CLAIMS_REL = "evidence/etp-t15/history/claims.before-reconciliation.json"
HISTORY_CLAIMS_SHA = "65d8105b744c80ae01e76af8bf3370c478ab116c7fc9b0f16f63eea5d5c579de"
SUPERSEDING = "evidence/etp-t15/RECONCILIATION.json"
SUPERSEDING_SHA = hashlib.sha256(RECONCILIATION.read_bytes()).hexdigest()


def reconciliation(claim: dict, classification: str, statement: str) -> dict:
    parties = claim["contradiction"]["parties"]
    return {
        "resolution_owner": "ETP-T15",
        "classification": classification,
        "original_verdict": "CONTRADICTED",
        "original_parties": parties,
        "historical_record": {
            "path": HISTORY_CLAIMS_REL,
            "sha256": HISTORY_CLAIMS_SHA,
        },
        "superseding_record": {
            "path": SUPERSEDING,
            "sha256": SUPERSEDING_SHA,
        },
        "statement": statement,
    }


def discharge(claim: dict, obligation_id: str, settled_by: str) -> None:
    for obligation in claim["obligations"]:
        if obligation["id"] == obligation_id:
            obligation["state"] = "DISCHARGED"
            obligation["settled_by"] = settled_by
            return
    raise SystemExit(f"{claim['id']}: no obligation {obligation_id}")


STATEMENTS = {
    "ETP0-CLM-004": (
        "The seal prose is the wrong side of the contradiction: the tracked registry "
        "records all_pass false, four pass and one fail, and the obligation ledger "
        "records implemented 4 with one open. The tracked measurement stands and the "
        "prose is superseded by the erratum."
    ),
    "ETP0-CLM-005": (
        "The probe source and the machine threshold agree at 150 percent; the prose's "
        "110 percent, 50 percent floor and the registry claim field's 50 percent are "
        "the wrong side. The measurement stands; the descriptive field is recorded as "
        "a record defect, not a measurement defect."
    ),
    "ETP0-CLM-030": (
        "The record no longer asserts SAFE_COMPATIBLE. Its cited receipts, freeze and "
        "adjudication record that safe_compatible is not established, and five of seven "
        "mechanisms plus all four cross-cutting obligations remain unresolved. The "
        "principal decision to proceed is recorded as RISK_ACCEPTED with the accepted "
        "obligations named and the dissent preserved."
    ),
    "ETP0-CLM-032": (
        "The ledger self-contradiction is repaired to one value: 0/33 section 7 "
        "SAFE_COMPATIBLE families and one risk-accepted family (openssh). The previous "
        "1/33 reading and its note are preserved in the ledger history block and in "
        "evidence/etp-t15/history/."
    ),
}

BASIS = {
    "ETP0-CLM-004": (
        "SUPERSEDED by ETP-T15: the tracked registry at S records all_pass false, four "
        "pass and one fail (HOSTILE-BOUNDARY-REGISTER), and the obligation ledger "
        "records implemented 4 with one open. The seal prose is the wrong side; the "
        "tracked measurement stands. The claim is retained as the record of the "
        "contradiction and is superseded by docs/PHASE-18-HARDENING-SEAL-ERRATUM.md "
        "and evidence/etp-t15/RECONCILIATION.json."
    ),
    "ETP0-CLM-005": (
        "SUPERSEDED by ETP-T15: courts/phase18/ct_primitives_probe.c defines SEP_PCT "
        "150 and artifacts/phase18/COURTS.json records threshold_percent 150; the seal "
        "prose is internally inconsistent and the registry's own claim field still says "
        "50 percent. The measurement is self-consistent; the prose and the descriptive "
        "field are the defect. Superseded by docs/PHASE-18-HARDENING-SEAL-ERRATUM.md "
        "and evidence/etp-t15/RECONCILIATION.json."
    ),
    "ETP0-CLM-030": (
        "RISK_ACCEPTED by ETP-T15: the record no longer asserts SAFE_COMPATIBLE. Its "
        "own cited closure receipts record verdict.safe_compatible=false, the freeze "
        "records safe_compatible=false and L7 not_graduated, and the adjudication "
        "records NOT ESTABLISHED; five of seven mechanisms and all four cross-cutting "
        "obligations remain unresolved. SAFE_COMPATIBLE remains NOT_ESTABLISHED and the "
        "record is a principal decision to proceed with the accepted obligations named."
    ),
    "ETP0-CLM-032": (
        "SUPERSEDED by ETP-T15: the ledger now records consumers.safe_compatible = 0 "
        "(section 7) and consumers.risk_accepted = 1 for openssh, with the previous "
        "1/33 value and note preserved in its history block and in "
        "evidence/etp-t15/history/. PROGRESS.md and STATUS-2026-10-20.md agree."
    ),
}

SETTLED = {
    "ETP0-CLM-004": [
        ("OBL-GAP-001", "ETP-T15: docs/PHASE-18-HARDENING-SEAL-ERRATUM.md records the tracked registry values; the seal prose is the wrong side."),
        ("OBL-GAP-002", "ETP-T15: docs/PHASE-18-HARDENING-SEAL-ERRATUM.md records the tracked obligation counts; the seal prose is the wrong side."),
        ("OBL-GAP-030", "ETP-T15: the erratum binds the seal values to their date and marks them historical; the tracked registry is the current record."),
        ("OBL-T15-RESOLUTION", "evidence/etp-t15/RECONCILIATION.json"),
    ],
    "ETP0-CLM-005": [
        ("OBL-GAP-003", "ETP-T15: the probe source and threshold_percent (150) are the measurement; the prose and the registry's claim field are the defect."),
        ("OBL-T15-RESOLUTION", "evidence/etp-t15/RECONCILIATION.json"),
    ],
    "ETP0-CLM-030": [
        ("OBL-GAP-004", "ETP-T15: the SAFE_COMPATIBLE label is withdrawn by reclassifying the record as RISK_ACCEPTED; the dissent is retained."),
        ("OBL-T15-RESOLUTION", "evidence/etp-t15/RECONCILIATION.json"),
    ],
    "ETP0-CLM-032": [
        ("OBL-GAP-005", "ETP-T15: CAMPAIGN-STATUS.json now records 0/33 section 7 and 1 risk-accepted family; the previous 1/33 is preserved in its history block."),
        ("OBL-GAP-006", "ETP-T15: CAMPAIGN-STATUS.json, PROGRESS.md and STATUS-2026-10-20.md now agree."),
        ("OBL-T15-RESOLUTION", "evidence/etp-t15/RECONCILIATION.json"),
    ],
}

CLASSIFICATION = {
    "ETP0-CLM-004": "SUPERSEDED",
    "ETP0-CLM-005": "SUPERSEDED",
    "ETP0-CLM-030": "RISK_ACCEPTED",
    "ETP0-CLM-032": "SUPERSEDED",
}


def main() -> int:
    document = json.loads(HISTORY_CLAIMS.read_text(encoding="utf-8"))
    by_id = {claim["id"]: claim for claim in document["claims"]}
    for ident, state in CLASSIFICATION.items():
        claim = by_id[ident]
        claim["verdict"] = {"state": state, "basis": BASIS[ident]}
        claim["reconciliation"] = reconciliation(
            claim, state, STATEMENTS[ident]
        )
        del claim["contradiction"]
        for obligation_id, settled_by in SETTLED[ident]:
            discharge(claim, obligation_id, settled_by)
        if ident == "ETP0-CLM-032":
            claim["interpretation"] = (
                "At S the campaign ledger recorded more than one value for the cohort "
                "SAFE_COMPATIBLE counter; the operational meaning was that the counter "
                "was not a single established fact. After the ETP-T15 reconciliation "
                "the ledger records one section 7 counter (0/33) and one risk-accepted "
                "family (openssh), and the S disagreement is preserved in history."
            )
            claim["quantification"]["measure"]["value"] = (
                "0/33 section 7 SAFE_COMPATIBLE families; 1 risk-accepted family "
                "(openssh); the S reading was 1/33 and 0/33"
            )
    CLAIMS.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
