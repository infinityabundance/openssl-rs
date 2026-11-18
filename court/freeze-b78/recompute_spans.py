"""Recompute every cohort span hash with the closure tool's own span rule.

Heads:
  B76 = 0238c6e4  (the b76 v1i/v1l review batches' source_head)
  B77 = ada7df257 (the b77 repair review's source_head)
  B78 = bb7d5206a (this candidate)

For every review row the recorded boundary supplies the operation qualifier and
the review row supplies the item.  Nothing is resolved by recorded line.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
HEADS = {
    "b76": "0238c6e4adbc7ed85a42be68b6fb965e139bd93e",
    "b77": "ada7df257e157964f3baade5ec40b66e9a9cbf35",
    "b78": "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac",
}

v1i = json.loads((ATLAS / "openssh-v1i-sites.json").read_text())
v1l = json.loads((ATLAS / "openssh-v1l-sites.json").read_text())
ops = {}
for doc in (v1i, v1l):
    for b in doc["boundaries"]:
        ops[b["id"]] = b

repair = {r["boundary"]: r for r in json.loads(
    (ATLAS / "b77-review-v1i-repaired.json").read_text())["repaired_sites"]}

rows = []
for name in ("b76-review-v1i-batch1.json", "b76-review-v1i-batch2.json",
             "b76-review-v1i-batch3.json", "b76-review-v1l.json"):
    doc = json.loads((ATLAS / name).read_text())
    for o in doc["obligations"]:
        rows.append({
            "review": name.replace(".json", ""),
            "review_head": doc["candidate_identity"]["source_head"],
            "boundary": o["boundary"],
            "file": o["file"],
            "kind": o.get("kind", "UNSAFE_FN_DEF"),
            "item": o["item"],
            "reviewed_line": o["line"],
            "reviewed_verdict": o["verdict"],
            "reviewed_reason": o.get("verdict_reason"),
        })


def span(head, file, operation, item):
    return cc.resolve_operation_span(ROOT, file, operation, item,
                                     source_commit=head)


out = []
for r in rows:
    b = ops.get(r["boundary"])
    rec = {"boundary": r["boundary"], "file": r["file"], "kind": r["kind"],
           "item": r["item"], "review": r["review"],
           "review_head": r["review_head"],
           "reviewed_line": r["reviewed_line"],
           "reviewed_verdict": r["reviewed_verdict"],
           "reviewed_reason": r["reviewed_reason"],
           "boundary_operation": (b or {}).get("operation"),
           "boundary_recorded_line": (b or {}).get("line"),
           "boundary_disposition": (b or {}).get("disposition")}
    if b is None:
        rec["error"] = "boundary-not-found"
        out.append(rec)
        continue
    for tag, head in HEADS.items():
        try:
            s = span(head, r["file"], b["operation"], r["item"])
            rec[tag] = {"sha256": s["sha256"], "start": s["start_line"],
                        "end": s["end_line"], "def": s["def_line"],
                        "qual": s["qualified_identity"],
                        "resolution": s["resolution"],
                        "source": s["source"]["source"]}
        except cc.SpanResolutionError as exc:
            rec[tag] = {"error": exc.classification, "detail": exc.detail[:200]}
    out.append(rec)

# identity: compare the hash at the head the earlier review accepted against b78
for rec in out:
    if "error" in rec:
        rec["identity"] = "unresolved"
        continue
    old_tag = "b77" if rec["boundary"] in repair else "b76"
    old, new = rec.get(old_tag, {}), rec.get("b78", {})
    if "error" in old or "error" in new:
        rec["identity"] = "unresolved"
    elif old.get("sha256") == new.get("sha256"):
        rec["identity"] = f"identical-to-{old_tag}"
        rec["hash"] = old.get("sha256")
    else:
        rec["identity"] = f"changed-since-{old_tag}"

doc = {
    "schema": "openssl-rs/safe-c33/atlas-refresh/b78-span-recompute/v1",
    "heads": HEADS,
    "tool": {"path": "forensics/tools/consumer_closure.py",
             "sha256": cc.sha256_file(ROOT / "forensics/tools/consumer_closure.py"),
             "span_rule": cc.SPAN_NORMALISATION,
             "claim_scope": cc.SPAN_CLAIM_SCOPE},
    "rows": out,
}
Path(__file__).resolve().parent.joinpath("span-recompute-b78.json").write_text(
    json.dumps(doc, indent=1) + "\n")

import collections
print("rows", len(out))
print("identity", dict(collections.Counter(r["identity"] for r in out)))
print("reviewed verdict", dict(collections.Counter(r["reviewed_verdict"] for r in out)))
for r in out:
    if r["identity"] != r.get("identity"):
        pass
for r in out:
    old_tag = "b77" if r["boundary"] in repair else "b76"
    if r["identity"].startswith("changed") or r["identity"] == "unresolved":
        print("CHANGED", r["boundary"], r["file"], r["item"],
              "review=", r["reviewed_verdict"], r["identity"],
              "old=", r.get(old_tag, {}).get("sha256", "")[:12],
              "new=", r.get("b78", {}).get("sha256", "")[:12],
              "err=", r.get("b78", {}).get("error"))
