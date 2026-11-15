#!/usr/bin/env python3
"""Re-bind the sixteen stale site rows at the review-3 candidate.

Uses the closure tool's own span resolver (resolve_operation_span) at two
commits: the commit whose bytes the recorded span_sha256 belongs to, and the
review candidate 08cb1148b.  Nothing is written to the receipts here.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/home/user/openssl-rs")
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

CAND = "08cb1148b40aa4cebc727e7c0b988505d3094ff0"
AR = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"

ROWS = []


def add(source_receipt, rid, file, operation, recorded, old_commit, extra=None):
    ROWS.append(dict(source_receipt=source_receipt, id=rid, file=file,
                     operation=operation, recorded=recorded,
                     old_commit=old_commit, extra=extra or {}))


sites = json.load(open(AR / "openssh-v1i-sites.json"))
byid = {b["id"]: b for b in sites["boundaries"]}
for rid in ["OSSH-V1I-049", "OSSH-V1I-050", "OSSH-V1I-051", "OSSH-V1I-052",
            "OSSH-V1I-053", "OSSH-V1I-054", "OSSH-V1I-059", "OSSH-V1I-060",
            "OSSH-V1I-061", "OSSH-V1I-063", "OSSH-V1I-064", "OSSH-V1I-065",
            "OSSH-V1I-067", "OSSH-V1I-069"]:
    b = byid[rid]
    add("openssh-v1i-sites.json", rid, b["file"], b["operation"],
        b["span_sha256"], "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac",
        {"span_start_line": b.get("span_start_line"),
         "span_end_line": b.get("span_end_line"),
         "line_current": b.get("line_current")})

b69 = json.load(open(AR / "boundary-sweep-B69.json"))
r1 = [b for b in b69["boundaries"] if b["id"] == "RAND-CTX-001"][0]
add("boundary-sweep-B69.json", "RAND-CTX-001", r1["file"], r1["operation"],
    r1["span_sha256"], b69["candidate"]["source_head"],
    {"span_start_line": r1.get("span_start_line"),
     "span_end_line": r1.get("span_end_line"),
     "line_current": r1.get("line_current")})

sc = json.load(open(AR / "sslconf-exclusivity-2026-11-10-sites.json"))
r2 = [b for b in sc["boundaries"] if b["id"] == "ssl_conf.rs:616"][0]
add("sslconf-exclusivity-2026-11-10-sites.json", "ssl_conf.rs:616",
    r2["file"], r2["operation"], r2["span_sha256"], sc["candidate"],
    {"span_start_line": r2.get("span_start_line"),
     "span_end_line": r2.get("span_end_line"),
     "line_current": r2.get("line_current")})


def span(commit, file, operation, item):
    try:
        return cc.resolve_operation_span(ROOT, file, operation, item,
                                         source_commit=commit)
    except cc.SpanResolutionError as exc:
        return {"error": exc.classification, "detail": exc.detail}


out = []
for r in ROWS:
    item = r["operation"].split("::")[-1]
    old = span(r["old_commit"], r["file"], r["operation"], item)
    new = span(CAND, r["file"], r["operation"], item)
    rec = dict(r)
    rec["old_span"] = old
    rec["new_span"] = new
    # span text for the classification diff
    old_text = cc._git_blob_text(ROOT, r["old_commit"], r["file"])[0]
    new_text = cc._git_blob_text(ROOT, CAND, r["file"])[0]
    if "error" not in old and "error" not in new:
        ol = old_text.splitlines()[old["start_line"] - 1:old["end_line"]]
        nl = new_text.splitlines()[new["start_line"] - 1:new["end_line"]]
        rec["old_lines"] = ol
        rec["new_lines"] = nl
    out.append(rec)
    om = "OK" if "error" not in old and old["sha256"] == r["recorded"] else "DIFF"
    nm = "OK" if "error" not in new else "ERR"
    print(f'{r["id"]:20s} {r["operation"]:26s} old {om} '
          f'{(old.get("sha256") or old.get("error",""))[:12]} '
          f'{old.get("start_line")}-{old.get("end_line")} -> new {nm} '
          f'{(new.get("sha256") or new.get("error",""))[:12]} '
          f'{new.get("start_line")}-{new.get("end_line")}')

json.dump(out, open(ROOT / "court/freeze-b79/review3/spans.json", "w"),
          indent=1, sort_keys=True)
print("wrote court/freeze-b79/review3/spans.json rows=", len(out))
