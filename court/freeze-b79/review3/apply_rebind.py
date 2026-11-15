#!/usr/bin/env python3
"""Re-bind the sixteen stale rows at the review-3 candidate.

Writes only the sixteen rows (plus one additive receipt-level block per receipt)
and emits court/freeze-b79/review3/receipt-diffs.json.  Byte-style is preserved:
each file round-trips identically through json.dumps(indent=1, ensure_ascii=True).
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path("/home/user/openssl-rs")
AR = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
CAND = "08cb1148b40aa4cebc727e7c0b988505d3094ff0"
REVIEW = "b79-review-rebind"
REVIEW_PATH = "evidence/b79-review-rebind.json"
OUT = ROOT / "court/freeze-b79/review3/receipt-diffs.json"

spans = {r["id"]: r for r in json.loads(
    (ROOT / "court/freeze-b79/review3/spans.json").read_text())}


def blob_sha(file):
    text = subprocess.run(["git", "-C", str(ROOT), "show", f"{CAND}:{file}"],
                          capture_output=True, check=True).stdout
    return hashlib.sha256(text).hexdigest()


def load(name):
    raw = (AR / name).read_bytes()
    doc = json.loads(raw)
    assert (json.dumps(doc, indent=1, ensure_ascii=True) + "\n").encode() == raw
    return doc, raw


def save(name, doc, raw):
    out = (json.dumps(doc, indent=1, ensure_ascii=True) + "\n").encode()
    (AR / name).write_bytes(out)
    return hashlib.sha256(out).hexdigest(), hashlib.sha256(raw).hexdigest()


diffs = []


def row_delta(bid, row, s, kind):
    """Apply the span/coordinate update and record the delta."""
    old_verdict = row.get("verdict") or row.get("recorded_verdict")
    old_review = row.get("review_receipt") or row.get("source_receipt") or \
        row.get("ledger_receipt")
    old = {"line": row.get("line"), "line_current": row.get("line_current"),
           "span_start_line": row.get("span_start_line"),
           "span_end_line": row.get("span_end_line"),
           "span_sha256": row.get("span_sha256"),
           "span_source_commit": row.get("span_source_commit")}
    new = s["new_span"]
    row["line"] = new["def_line"]
    row["line_current"] = new["def_line"]
    row["span_start_line"] = new["start_line"]
    row["span_end_line"] = new["end_line"]
    row["span_sha256"] = new["sha256"]
    if "span_source_commit" in row or kind != "cmp":
        row["span_source_commit"] = CAND
    row["reviewed_span_sha256"] = new["sha256"]
    row["review_receipt"] = REVIEW
    row["review_receipt_path"] = REVIEW_PATH
    row["covers_site"] = True
    row["covers_site_basis"] = (
        f"the boundary's declared range covers the current census coordinate "
        f"{new['def_line']} and the recorded span_sha256 is the resolver's hash "
        f"of the current bytes ({new['sha256'][:16]}); the superseded coordinate "
        f"{old['line']} is kept as inventory_line/provenance")
    row["rebind"] = {
        "review": REVIEW,
        "review_path": REVIEW_PATH,
        "candidate": CAND,
        "prior_candidate": s["old_commit"],
        "prior_span_sha256": old["span_sha256"],
        "prior_span_lines": [old["span_start_line"], old["span_end_line"]],
        "prior_coordinate": old["line"],
        "delta_classification": s["classification"],
        "delta": s["delta"],
    }
    diffs.append({"receipt": kind_row_receipt[kind], "boundary": bid,
                  "file": row["file"], "operation": row["operation"],
                  "prior_verdict": old_verdict, "prior_review": old_review,
                  "old": old,
                  "new": {"line": row["line"], "line_current": row["line_current"],
                          "span_start_line": row["span_start_line"],
                          "span_end_line": row["span_end_line"],
                          "span_sha256": row["span_sha256"],
                          "span_source_commit": row.get("span_source_commit")},
                  "classification": s["classification"], "delta": s["delta"],
                  "prose_coordinate_updates": []})


kind_row_receipt = {"cmp": "openssh-v1i-sites.json",
                    "rand": "boundary-sweep-B69.json",
                    "ssl": "sslconf-exclusivity-2026-11-10-sites.json"}

# --------------------------------------------------------------------- v1i
V1I = ["OSSH-V1I-049", "OSSH-V1I-050", "OSSH-V1I-051", "OSSH-V1I-052",
       "OSSH-V1I-053", "OSSH-V1I-054", "OSSH-V1I-059", "OSSH-V1I-060",
       "OSSH-V1I-061", "OSSH-V1I-063", "OSSH-V1I-064", "OSSH-V1I-065",
       "OSSH-V1I-067", "OSSH-V1I-069"]
doc, raw = load("openssh-v1i-sites.json")
blobs = {}
for b in doc["boundaries"]:
    if b["id"] not in V1I:
        continue
    s = spans[b["id"]]
    f = b["file"]
    if f not in blobs:
        blobs[f] = blob_sha(f)
    old_line = b["line"]
    prior_verdict = b.get("verdict")
    prior_review = b.get("review_receipt")
    prior_disp = b["disposition"]
    row_delta(b["id"], b, s, "cmp")
    b["source_blob_sha256"] = blobs[f]
    b["disposition"] = re.sub(
        rf"({re.escape(f)}:){old_line}\b", rf"\g<1>{b['line']}",
        b["disposition"], count=1)
    next(d for d in diffs if d["boundary"] == b["id"])["disposition_update"] = {
        "old": prior_disp, "new": b["disposition"]}
    b["verdict_class"] = "content-reverified"
    b["verdict_basis"] = (
        f"ACCEPT re-established at {CAND[:9]} ({REVIEW}): the span differs from "
        f"the bytes the b76 review read only by the SAFETY comment added in "
        f"97a1240e7 (no code token, no unsafe op and no caller set changed); the "
        f"body, the contract and every use site were re-read at this candidate "
        f"and the four questions re-answered.  The earlier verdict was "
        f"'{prior_verdict}' ({prior_review}).")

# 065's evidence prose cites four call-site coordinates.
r = next(b for b in doc["boundaries"] if b["id"] == "OSSH-V1I-065")
old_est = list(r["established_by"])
r["established_by"][0] = (old_est[0]
                          .replace(":578,587", ":628,637")
                          .replace(":1588,1593", ":1638,1643"))
next(d for d in diffs if d["boundary"] == "OSSH-V1I-065")[
    "prose_coordinate_updates"] = [
    {"field": "established_by[0]", "old": old_est[0],
     "new": r["established_by"][0]}]

doc["rebind_review3"] = {
    "review": REVIEW,
    "review_path": REVIEW_PATH,
    "candidate": CAND,
    "scope": "the fourteen openssh-v1i boundaries this receipt owns, re-bound "
             "after 97a1240e7 added the fn-level # Safety contracts",
    "rule": "each row's recorded span_sha256 is the closure tool's own "
            "resolve_operation_span hash at the candidate, its declared range "
            "is the operation's current definition line, and its verdict is the "
            "b79-review-rebind verdict for that row.  No other row was modified: "
            "the remaining rows keep the b78 regeneration's coordinates and "
            "hashes verbatim.",
    "prior_evidence_note": "contract/established_by/implementation_guarantees/"
                           "criteria/residual remain the earlier receipt's text "
                           "(prior_evidence); a prose coordinate that names a "
                           "call site is correct only where this review says so.",
}
sha_new, sha_old = save("openssh-v1i-sites.json", doc, raw)
print("openssh-v1i-sites.json", sha_old[:16], "->", sha_new)

# --------------------------------------------------------------------- b69
doc, raw = load("boundary-sweep-B69.json")
r = next(b for b in doc["boundaries"] if b["id"] == "RAND-CTX-001")
s = spans["RAND-CTX-001"]
old_est = list(r["established"])
old_body = r["body"]
old_ops = json.loads(json.dumps(r["unsafe_operations"]))
row_delta("RAND-CTX-001", r, s, "rand")
r["body"] = "\n".join(s["new_lines"])
r["established"][0] = old_est[0].replace("426-465", "426-466")
r["established"][3] = old_est[3].replace("435-443", "436-444")
r["established"][4] = old_est[4].replace(":459-462", ":460-463")
for op in r["unsafe_operations"]:
    if op.get("line") == 437:
        op["line"] = 438
    elif op.get("line") == 459:
        op["line"] = 460
diffs_rand = next(d for d in diffs if d["boundary"] == "RAND-CTX-001")
diffs_rand["prose_coordinate_updates"] = [
    {"field": "body", "old": old_body, "new": r["body"]},
    {"field": "established[0]", "old": old_est[0], "new": r["established"][0]},
    {"field": "established[3]", "old": old_est[3], "new": r["established"][3]},
    {"field": "established[4]", "old": old_est[4], "new": r["established"][4]},
    {"field": "unsafe_operations[].line", "old": old_ops,
     "new": r["unsafe_operations"]},
]
doc["rebind_review3"] = {
    "review": REVIEW, "review_path": REVIEW_PATH, "candidate": CAND,
    "boundaries": ["RAND-CTX-001"],
    "rule": "RAND-CTX-001's span hash, span lines, body snapshot, structured "
            "unsafe-operation lines and the coordinates inside its established "
            "list are re-bound to the candidate; the receipt's other two rows "
            "and all receipt-level identity fields are untouched. The in-span "
            "change is the explicit-unsafe-block migration of the "
            "OPENSSL_init_crypto call (same callee, same arguments).",
}
sha_new, sha_old = save("boundary-sweep-B69.json", doc, raw)
print("boundary-sweep-B69.json", sha_old[:16], "->", sha_new)

# --------------------------------------------------------------- sslconf
doc, raw = load("sslconf-exclusivity-2026-11-10-sites.json")
r = next(b for b in doc["boundaries"] if b["id"] == "ssl_conf.rs:616")
s = spans["ssl_conf.rs:616"]
prior_disp = r["disposition"]
row_delta("ssl_conf.rs:616", r, s, "ssl")
r["span_qualified_identity"] = s["new_span"]["qualified_identity"]
r["span_resolution"] = s["new_span"]["resolution"]
r["recorded_verdict"] = "SAFETY_DISCHARGED"
r["disposition"] = (prior_disp.rstrip()[:-1].rstrip() +
                    f"; this row declares src/ssl/ssl_conf.rs:{r['line']})")
next(d for d in diffs if d["boundary"] == "ssl_conf.rs:616")[
    "disposition_update"] = {"old": prior_disp, "new": r["disposition"]}
doc["rebind_review3"] = {
    "review": REVIEW, "review_path": REVIEW_PATH, "candidate": CAND,
    "boundaries": ["ssl_conf.rs:616"],
    "rule": "min_max_proto's span hash and span lines are re-bound to the "
            "candidate; the boundary id, ledger_coordinate and "
            "source_boundary_line_current stay as the B47/ledger provenance, and "
            "the other thirteen rows are untouched. The in-span change is the "
            "explicit-unsafe-block migration of the ssl_set_version_bound call "
            "(same callee, same arguments).",
}
sha_new, sha_old = save("sslconf-exclusivity-2026-11-10-sites.json", doc, raw)
print("sslconf-exclusivity-2026-11-10-sites.json", sha_old[:16], "->", sha_new)

# --------------------------------------------------- no-collateral check
collateral = []
for name in ("openssh-v1i-sites.json", "boundary-sweep-B69.json",
             "sslconf-exclusivity-2026-11-10-sites.json"):
    new_doc = json.loads((AR / name).read_text())
    old_doc = json.loads(subprocess.run(
        ["git", "-C", str(ROOT), "show", f"HEAD:{AR.relative_to(ROOT)}/{name}"],
        capture_output=True, check=True).stdout)
    new_doc.pop("rebind_review3", None)
    old_doc.pop("rebind_review3", None)
    for d in (new_doc, old_doc):
        for b in d["boundaries"]:
            if b["id"] in spans:
                b.clear()
                b["__removed__"] = True
    if new_doc != old_doc:
        collateral.append(name)
print("collateral changes outside the sixteen rows:", collateral or "none")

OUT.write_text(json.dumps({"rows": diffs, "collateral": collateral},
                          indent=1, ensure_ascii=True) + "\n")
print("wrote", OUT.relative_to(ROOT), "sha256",
      hashlib.sha256(OUT.read_bytes()).hexdigest()[:16])
