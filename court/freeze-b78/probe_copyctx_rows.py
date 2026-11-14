#!/usr/bin/env python3
"""Re-adjudicate the seven b78 `copyctx` rows with the repaired binding.

This is the Blocker-1 acceptance probe.  It loads the *same* boundary receipts,
discharge plane, mechanism state and census the closure uses, and runs the real
`adjudicate()` on the seven carried-forward rows from the b78 closure.  No
binary graph is involved, so it is fast and reads only committed evidence.
"""
import collections
import json
import sys
from pathlib import Path

ROOT = Path("/work")
sys.path.insert(0, "/work/forensics/tools")
import consumer_closure as cc  # noqa: E402

ATLAS = "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
CENSUS = "court/freeze-b78/census-b78.json"
STATE = "forensics/memory-safety/campaign/safe-c33/state.json"
STATUS = "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"


def main():
    repo = ROOT
    inventory = json.loads((repo / CENSUS).read_text())
    state_doc = json.loads((repo / STATE).read_text())
    status_doc = json.loads((repo / STATUS).read_text())
    mechanisms = {m["id"]: dict(m, state_source="state.json")
                  for m in state_doc.get("mechanisms") or []}
    for rec in status_doc.get("mechanism_discharges") or []:
        if rec.get("state") != "SAFETY_DISCHARGED":
            continue
        mid = str(rec.get("id") or "").split("-")[0]
        if mid in mechanisms:
            mechanisms[mid] = dict(mechanisms[mid], state="SAFETY_DISCHARGED")
    by_file, _by_id = cc.load_boundaries(repo / ATLAS)
    plane = cc.discharge_plane(status_doc, repo / ATLAS)
    census = cc._census_operation_index(inventory.get("contracts") or {})
    head = cc.span_source_commit(inventory, repo)
    cc._EVIDENCE_ENV["repo"] = str(repo)
    cc._EVIDENCE_ENV["install"] = str(repo / "artifacts/phase2/install")
    cc._EVIDENCE_ENV["source_commit"] = head
    print("span source commit", head)

    rows = []
    for fam in ("ssh", "sshd"):
        closure = json.loads((repo / f"evidence/closure-{fam}-b78.json").read_text())
        for ob in closure["obligations"]:
            if ob.get("item") == "copyctx" and ob.get("status") == "BLOCKED":
                rows.append((fam, ob))
    print(f"{len(rows)} blocked copyctx row(s)")
    for fam, ob in rows:
        rec = dict(ob)
        rec.pop("scoped_discharge_attempts", None)
        rec.pop("span_discharge_rejections", None)
        rec.pop("stale_discharge_rejections", None)
        rec.pop("documentation_note", None)
        rec.pop("migration", None)
        rec["status"] = None
        rec["discharge_receipt"] = None
        rec["status_reason"] = None
        rec.pop("discharge_boundary_id", None)
        rec.pop("span_discharge", None)
        out = cc.adjudicate(rec, mechanisms,
                            by_file.get(rec["file"], []), plane,
                            repo=repo, census_ops=census)
        mig = out.get("migration") or {}
        anc = mig.get("ancestor") or {}
        print(f"  {rec['file']}:{rec['line']} {rec['item']} -> {out['status']} "
              f"boundary={out.get('discharge_boundary_id')} "
              f"binding={mig.get('rule') if mig else '-'} "
              f"ancestor={anc.get('receipt', '').split('/')[-1]}:"
              f"{anc.get('line')}@{str(anc.get('head'))[:10]}")
        if out["status"] != "DISCHARGED":
            print("      reason:", (out.get("status_reason") or "")[:220])


if __name__ == "__main__":
    main()
