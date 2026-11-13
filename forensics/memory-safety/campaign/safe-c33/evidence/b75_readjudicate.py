#!/usr/bin/env python3
"""B75 — re-adjudicate the frozen b74 OpenSSH obligation queue.

This is the b67-g1 probe method: it imports the shipping instrument's own
loaders and adjudicator and runs them over the obligations recorded in
``evidence/closure-ssh-b74.json``.  It does not rebuild, and it does not
re-analyse a binary.

It is evidence about the evidence ledger.  A fresh closure run is still
required to carry the result in a closure receipt.

Exit 0 iff every obligation is DISCHARGED and both OCSP conflicts are
superseded.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

CAMPAIGN = REPO / "forensics/memory-safety/campaign/safe-c33"
BOUNDARY_DIR = CAMPAIGN / "atlas-refresh"


def main() -> int:
    status = json.loads((CAMPAIGN / "CAMPAIGN-STATUS.json").read_text())
    state = json.loads((CAMPAIGN / "state.json").read_text())
    mechanisms = cc.load_obligation_mechanisms(state)
    plane = cc.discharge_plane(status, BOUNDARY_DIR)
    by_file, _by_id = cc.load_boundaries(BOUNDARY_DIR)
    receipt = json.loads((REPO / "evidence/closure-ssh-b74.json").read_text())

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

    counts = {}
    for o in rows:
        counts[o.get("status")] = counts.get(o.get("status"), 0) + 1
    print("counts:", counts)
    failures = [o for o in rows if o.get("status") != "DISCHARGED"]

    ocsp = [o for o in rows if o.get("item") in ("i2r_ocsp_crlid", "i2r_ocsp_serviceloc")]
    print("ocsp:", [(o.get("item"), o.get("status")) for o in ocsp])
    for o in ocsp:
        for c in o.get("disposition_conflicts", []):
            print("  conflict", c["boundary"], c["keyword"], "superseded=", c["superseded"])
            if not c["superseded"]:
                failures.append(o)

    for o in failures:
        print("FAIL:", o["id"], o.get("status"), (o.get("status_reason") or "")[:200])
    return 0 if not failures and len(rows) == 323 else 1


if __name__ == "__main__":
    raise SystemExit(main())
