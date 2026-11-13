#!/usr/bin/env python3
"""B75 — re-adjudicate both frozen OpenSSH queues and verify sshd's binding.

This is the b67-g1 probe method: it imports the shipping instrument's own
loaders and adjudicator and runs them over the obligations recorded in the
frozen closure receipts.  It does not rebuild, and it does not re-analyse a
binary.

It is evidence about the evidence ledger.  A fresh closure run is still
required to carry the result in a closure receipt.

Exit 0 iff both queues are entirely DISCHARGED and the sshd per-artefact
ledger binding passes every check.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO / "forensics/tools"))
import consumer_closure as cc  # noqa: E402
import rebind_consumer_artifact as rb  # noqa: E402

CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
BOUNDARY_DIR = CAMPAIGN / "atlas-refresh"

CASES = [
    ("ssh", "evidence/closure-ssh-b74.json", {"DISCHARGED": 321, "BLOCKED": 2}),
    ("sshd", "evidence/closure-sshd-b73-r2.json", {"DISCHARGED": 320, "BLOCKED": 3}),
]


def adjudicate_all(receipt_path, mechanisms, plane, by_file):
    receipt = json.loads((REPO / receipt_path).read_text())
    rows = [
        cc.adjudicate(
            json.loads(json.dumps(o)),
            mechanisms,
            by_file.get(o["file"], []),
            plane,
            repo=REPO,
            allow_worktree_span=True,
            enforce_conflicts=True,
        )
        for o in receipt["obligations"]
    ]
    return receipt, rows


def main() -> int:
    status = json.loads((CAMPAIGN / "CAMPAIGN-STATUS.json").read_text())
    state = json.loads((CAMPAIGN / "state.json").read_text())
    mechanisms = cc.load_obligation_mechanisms(state)
    plane = cc.discharge_plane(status, BOUNDARY_DIR)
    by_file, _by_id = cc.load_boundaries(BOUNDARY_DIR)

    failures = []
    results = {}
    for family, receipt_path, before in CASES:
        receipt, rows = adjudicate_all(receipt_path, mechanisms, plane, by_file)
        counts = {}
        for row in rows:
            counts[row.get("status")] = counts.get(row.get("status"), 0) + 1
        results[family] = {"receipt": receipt_path, "before": before,
                           "after": counts, "obligations": len(rows)}
        print(f"{family}: before={before} after={counts} n={len(rows)}")
        if counts != {"DISCHARGED": 323}:
            failures.append(f"{family} queue did not resolve to 323/0: {counts}")
        if family == "sshd":
            ledger = json.loads((REPO / "evidence/sshd-artifact-ledger.json").read_text())
            freeze = json.loads((REPO / "court/freeze-b73/FREEZE-b73.json").read_text())
            try:
                checks = rb.verify(receipt, ledger, freeze)
            except rb.Refusal as exc:
                failures.append(f"sshd artifact binding refused: {exc}")
                checks = None
            results["sshd"]["artifact_binding"] = checks
            print("sshd artifact binding:", checks)

    if failures:
        for failure in failures:
            print("FAIL:", failure)
        return 1
    print("OK: both queues 323 DISCHARGED; sshd artefact binding verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
