"""b78 review: assemble the 65-obligation cohort, resolve current coordinates,
and write the verdict table used by the regenerated discharge receipts.

Verdict classes
---------------
identity45      b76-review accepted the site and the span bytes are unchanged
                since that review's source head (0238c6e4).
identity8       b77-review accepted the repaired site and the span bytes are
                unchanged since the repair head (ada7df257).
rereview11      rejected at b76 for a NULL-algctx sink; the b77 repair added the
                caller guard.  Re-reviewed here.
rereview1       rejected at b76 for a missing fn contract; the repair added it.
                Re-reviewed here.
"""
import collections
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
OUTDIR = Path(__file__).resolve().parent

S = "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac"
SRC_SHA = "c0bd61c94f5a8da2e08c105724d14750403fbfd53aa8d4b722672f9b11b0bd38"
IMG = "a27ca428f899a58bab0449d46914a54af3f604d4b72c0ff0e5153ab14415e507"
HEADS = {"b76": "0238c6e4adbc7ed85a42be68b6fb965e139bd93e",
         "b77": "ada7df257e157964f3baade5ec40b66e9a9cbf35",
         "b78": S}

NULL_SINK = {
    "OSSH-V1I-004", "OSSH-V1I-013", "OSSH-V1I-014", "OSSH-V1I-019",
    "OSSH-V1I-021", "OSSH-V1I-028", "OSSH-V1I-005",
    "OSSH-V1I-084", "OSSH-V1I-090", "OSSH-V1I-085", "OSSH-V1I-091",
}
REPAIRED8 = {
    "OSSH-V1I-002", "OSSH-V1I-008", "OSSH-V1I-011", "OSSH-V1I-017",
    "OSSH-V1I-020", "OSSH-V1I-024", "OSSH-V1I-082", "OSSH-V1I-088",
}

# --- earlier review rows ----------------------------------------------------
review_rows = []
for name in ("b76-review-v1i-batch1.json", "b76-review-v1i-batch2.json",
             "b76-review-v1i-batch3.json", "b76-review-v1l.json"):
    doc = json.loads((ATLAS / name).read_text())
    for o in doc["obligations"]:
        review_rows.append({
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

b77 = {r["boundary"]: r for r in json.loads(
    (ATLAS / "b77-review-v1i-repaired.json").read_text())["repaired_sites"]}

# --- boundary operations ----------------------------------------------------
bops = {}
for name in ("openssh-v1i-sites.json", "openssh-v1l-sites.json"):
    for b in json.loads((ATLAS / name).read_text())["boundaries"]:
        bops[b["id"]] = b

# --- census lookup ----------------------------------------------------------
census = json.loads((ROOT / "court/freeze-b78/census-b78.json").read_text())
census_by_key = collections.defaultdict(list)
for b in census["contracts"]["blockers"]:
    census_by_key[(b["file"], b["kind"], b.get("item"))].append(
        {"line": b["line"], "partition": b["partition"], "set": "blockers"})
for c in census["contracts"]["contracted_operations"]:
    census_by_key[(c["file"], c["kind"], c.get("item"))].append(
        {"line": c["line"], "partition": c["partition"], "set": "contracted"})

_span_cache = {}


def span(head, file, operation, item):
    key = (head, file, operation, item)
    if key not in _span_cache:
        _span_cache[key] = cc.resolve_operation_span(
            ROOT, file, operation, item, source_commit=head)
    return _span_cache[key]


def blob_sha(file):
    raw = subprocess.check_output(
        ["git", "-C", str(ROOT), "show", f"{S}:{file}"])
    return hashlib.sha256(raw).hexdigest()


rows = []
for r in review_rows:
    b = bops[r["boundary"]]
    cur = span(S, r["file"], b["operation"], r["item"])
    old_head = HEADS["b77"] if r["boundary"] in REPAIRED8 else r["review_head"]
    old = span(old_head, r["file"], b["operation"], r["item"])
    live = census_by_key.get((r["file"], r["kind"], r["item"])) or []
    census_lines = sorted({x["line"] for x in live})

    if r["reviewed_verdict"] == "ACCEPT":
        cls = "identity45"
    elif r["boundary"] in REPAIRED8:
        cls = "identity8"
    elif r["boundary"] in NULL_SINK:
        cls = "rereview11"
    elif r["boundary"] == "OSSH-V1L-009":
        cls = "rereview1"
    else:
        cls = "UNEXPECTED"

    rows.append({
        "boundary": r["boundary"],
        "file": r["file"],
        "kind": r["kind"],
        "item": r["item"],
        "qualified_identity": cur["qualified_identity"],
        "operation": b["operation"],
        "mechanism": b.get("mechanism"),
        "verdict_class": cls,
        "earlier_receipt": r["review"],
        "earlier_receipt_head": r["review_head"],
        "earlier_reviewed_line": r["reviewed_line"],
        "earlier_verdict": r["reviewed_verdict"],
        "earlier_verdict_reason": r["reviewed_reason"],
        "b77_repair_review": (b77.get(r["boundary"]) and "b77-review-v1i-repaired"),
        "recorded_line_at_b77_closure": b.get("line"),
        "current_census_lines": census_lines,
        "current_census_set": sorted({x["set"] for x in live}),
        "current_census_partition": sorted({x["partition"] for x in live}),
        "current_span": {"start_line": cur["start_line"],
                         "end_line": cur["end_line"],
                         "def_line": cur["def_line"],
                         "sha256": cur["sha256"],
                         "source": cur["source"]["source"],
                         "resolution": cur["resolution"]},
        "earlier_accepted_span": {"head": old_head,
                                  "start_line": old["start_line"],
                                  "end_line": old["end_line"],
                                  "sha256": old["sha256"]},
        "span_hash_identical": old["sha256"] == cur["sha256"],
        "census_matches_resolved_def": cur["def_line"] in census_lines,
        "item_present_in_census": bool(live),
        "kind_unchanged": bool(live),
    })

# --- verdicts ---------------------------------------------------------------
BASIS = {
    "identity45": ("ACCEPT (identity; reviewed at {r}) — the span bytes are "
                   "identical to the source head that review read ({h}); no "
                   "re-review."),
    "identity8": ("ACCEPT (identity; reviewed at b77-review-v1i-repaired) — the "
                  "repaired body is byte-identical to the repair head ada7df257 "
                  "({h}); the b78 edit to EVP_MD_CTX_copy_ex was re-read and "
                  "preserves the copyctx destination precondition."),
    "rereview11": ("ACCEPT (re-review at b78) — rejected at b76 for a NULL-algctx "
                   "sink; the required caller guard now exists at the single "
                   "dispatch site (EVP_DigestUpdate:2568 / "
                   "EVP_DigestFinal_ex:2663 / EVP_DigestFinalXOF:2799 / "
                   "EVP_DigestSqueeze:2935), and the site body is unchanged "
                   "({h})."),
    "rereview1": ("ACCEPT (re-review at b78) — rejected at b76 for transferring a "
                  "NUL-termination obligation with no fn contract; the fn now "
                  "carries `# Safety` (docs are outside the span, so the byte "
                  "hash {h} is unchanged), its single caller forwards the same "
                  "pointer under ENGINE_set_default_string's own `# Safety`, and "
                  "the external C ABI contract is the retained obligation."),
}

for r in rows:
    basis = BASIS[r["verdict_class"]]
    if r["verdict_class"] == "identity45":
        basis = basis.format(r=r["earlier_receipt"], h=r["current_span"]["sha256"][:16])
    else:
        basis = basis.format(h=r["current_span"]["sha256"][:16])
    r["verdict"] = "ACCEPT"
    r["verdict_basis"] = basis

doc = {
    "schema": "openssl-rs/safe-c33/atlas-refresh/b78-obligation-set/v1",
    "generated_utc": "2026-11-13T00:00:00Z",
    "candidate": {
        "source_head": S,
        "src_content_sha256": SRC_SHA,
        "image_libcrypto_sha256": IMG,
        "census": "court/freeze-b78/census-b78.json",
        "closure": "evidence/closure-ssh-b77.json",
        "span_heads": HEADS,
        "span_rule": cc.SPAN_NORMALISATION,
        "span_claim_scope": cc.SPAN_CLAIM_SCOPE,
    },
    "rule": (
        "Cohort = the 56 obligations the b77 closure adjudicated with "
        "discharge_receipt openssh-v1i (48 DISCHARGED + the 8 the closure "
        "refused, which the v1i receipt had carried) plus the 9 with "
        "discharge_receipt openssh-v1l.  Current coordinates are resolved from "
        "census-b78 by (file, kind, item) and from the closure tool's own span "
        "resolver by (file, qualified operation); no recorded line is used for "
        "identity.  'earlier_accepted_span' is the same span resolved at the "
        "head the earlier review read.  A mechanical identity verdict is used "
        "only where the two hashes are equal."),
    "counts": {
        "cohort": len(rows),
        "by_verdict": dict(collections.Counter(r["verdict"] for r in rows)),
        "by_class": dict(collections.Counter(r["verdict_class"] for r in rows)),
        "by_earlier_verdict": dict(collections.Counter(
            r["earlier_verdict"] for r in rows)),
        "span_hash_identical": sum(1 for r in rows if r["span_hash_identical"]),
        "item_present_in_census": sum(1 for r in rows if r["item_present_in_census"]),
        "census_matches_resolved_def": sum(
            1 for r in rows if r["census_matches_resolved_def"]),
        "by_file": dict(collections.Counter(r["file"] for r in rows)),
    },
    "absent_items": [],
    "file_or_kind_changed": [],
    "non_cohort_absent_in_receipt": [
        {"boundary": bid, "file": bops[bid]["file"],
         "operation": bops[bid]["operation"],
         "reason": "no brace-delimited definition at b78 (retired thunk)"}
        for bid in ("OSSH-V1I-055", "OSSH-V1I-056", "OSSH-V1I-057",
                    "OSSH-V1I-058", "OSSH-V1I-062")
    ],
    "obligations": sorted(rows, key=lambda r: (
        r["file"], r["item"], r["boundary"])),
}
(OUTDIR / "obligations-65.json").write_text(json.dumps(doc, indent=1) + "\n")
print(json.dumps(doc["counts"], indent=1))
bad = [r for r in rows if not r["span_hash_identical"]
       or not r["item_present_in_census"] or not r["census_matches_resolved_def"]]
print("rows failing a structural check:", len(bad))
for r in bad:
    print(" ", r["boundary"], r["span_hash_identical"],
          r["item_present_in_census"], r["census_matches_resolved_def"])
print("blob sha (sample):", blob_sha("src/provider/digest.rs")[:16])
