"""Recompute every boundary span of the two site receipts at b78 and at the
b76 review head, and report drift.  Non-cohort boundaries keep their earlier
disposition only if their span hash did not move.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
B76 = "0238c6e4adbc7ed85a42be68b6fb965e139bd93e"
B78 = "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac"
B77 = "ada7df257e157964f3baade5ec40b66e9a9cbf35"

migration = json.loads((ATLAS / "span-hash-migration.json").read_text())
mig = {(s["receipt"], s["boundary_id"]): s for s in migration["sites"]}

out = {}
for name in ("openssh-v1i-sites.json", "openssh-v1l-sites.json"):
    doc = json.loads((ATLAS / name).read_text())
    receipt = doc["receipt"]
    rows = []
    for b in doc["boundaries"]:
        rec = {"id": b["id"], "file": b["file"], "kind": b["kind"],
               "operation": b.get("operation"),
               "recorded_line": b.get("line"),
               "disposition": b.get("disposition")}
        key = (receipt, b["id"])
        m = mig.get(key)
        rec["migration_sha256"] = (m or {}).get("span_sha256")
        rec["migration_candidate"] = (m or {}).get("migration_candidate")
        for tag, head in (("b76", B76), ("b77", B77), ("b78", B78)):
            try:
                s = cc.resolve_operation_span(ROOT, b["file"], b["operation"],
                                              b["operation"].split("::")[-1],
                                              source_commit=head)
                rec[tag] = {"sha256": s["sha256"], "start": s["start_line"],
                            "end": s["end_line"], "def": s["def_line"],
                            "qual": s["qualified_identity"]}
            except cc.SpanResolutionError as exc:
                rec[tag] = {"error": exc.classification,
                            "detail": exc.detail[:160]}
        a, c = rec.get("b76", {}), rec.get("b78", {})
        rec["drift_since_b76"] = ("unresolved" if "error" in a or "error" in c
                                 else "same" if a.get("sha256") == c.get("sha256")
                                 else "changed")
        mm = rec["migration_sha256"]
        rec["migration_matches_b78"] = (mm is None or mm == c.get("sha256"))
        rows.append(rec)
    out[receipt] = rows

Path(__file__).resolve().parent.joinpath("receipt-spans-b78.json").write_text(
    json.dumps({"heads": {"b76": B76, "b77": B77, "b78": B78},
                "receipts": out}, indent=1) + "\n")

import collections
for receipt, rows in out.items():
    print(receipt, len(rows), dict(collections.Counter(
        r["drift_since_b76"] for r in rows)))
    print("  migration mismatch:",
          [r["id"] for r in rows if not r["migration_matches_b78"]])
    for r in rows:
        if r["drift_since_b76"] != "same":
            print("  DRIFT", r["id"], r["file"], r["operation"],
                  r["drift_since_b76"], r.get("b78", {}).get("error"))
    print("  disposition-not-discharge:",
          [r["id"] for r in rows
           if not cc.boundary_disposition_is_discharge(r["disposition"])])
