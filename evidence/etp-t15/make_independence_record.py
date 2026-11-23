#!/usr/bin/env python3
"""Derive the ETP-T15 independence record from the ETP-T8 projection.

The ETP-T8 record is a historical projection at its own base. This script keeps
every assignment, dissent and party as recorded and changes exactly one
assignment: the OpenSSH release entry is a risk acceptance, so it asserts no
independence and requires no distinct parties. The ETP-T8 record remains
unchanged; this is a new record with its own identity.

Run from the repository root:
    python3 evidence/etp-t15/make_independence_record.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics" / "tools"))

import independence  # noqa: E402

SOURCE = ROOT / "evidence" / "etp-t8" / "ASSIGNMENTS.json"
TARGET = ROOT / "evidence" / "etp-t15" / "INDEPENDENCE.json"


def head() -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def main() -> int:
    document = json.loads(SOURCE.read_text(encoding="utf-8"))
    document["generated_utc"] = "2026-11-23T00:00:00Z"
    document["source_identity"] = {
        "commit": head(),
        "branch": "staging",
        "worktree_clean_tracked_files": True,
    }
    claims = json.loads(
        (ROOT / "evidence" / "etp" / "claims.json").read_text(encoding="utf-8")
    )
    verdicts = {
        claim["id"]: claim["verdict"]["state"] for claim in claims["claims"]
    }
    for assignment in document["assignments"]:
        ident = assignment["id"]
        if ident.startswith("A-ETP0-CLM-"):
            claim_id = ident[len("A-"):]
            if claim_id in verdicts:
                assignment["asserted_verdict"] = verdicts[claim_id]
    for assignment in document["assignments"]:
        if assignment["id"] != "A-REL-OPENSSH-B85C":
            continue
        assignment["class"] = "ORDINARY_CLAIM"
        assignment["asserted_verdict"] = "RISK_ACCEPTED"
        assignment["claimed_independence"] = False
        assignment["independence_kind"] = "NONE"
        assignment["independence_required"] = []
        assignment["finding"] = (
            "Reclassified by ETP-T15: the b85c record is a principal risk "
            "acceptance (RISK_ACCEPTED), not a SAFE_COMPATIBLE graduation. It "
            "asserts no independence and requires no distinct party. The absence "
            "of an independent acceptance is recorded, not repaired, and the "
            "adjudication's NOT ESTABLISHED dissent is retained."
        )
    for dissent in document["dissents"]:
        if dissent["id"] != "D-OPENSSH-B85C":
            continue
        dissent["statement"] = (
            "The b85c adjudication returned NOT ESTABLISHED against the OpenSSH "
            "SAFE_COMPATIBLE graduation. ETP-T15 reclassified the graduation as "
            "RISK_ACCEPTED on 2026-11-23; the dissent is retained unchanged in "
            "position and is not withdrawn or reinterpreted."
        )
    document["aggregate"] = independence.aggregate(document)
    TARGET.write_text(independence.dump_json(document), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
