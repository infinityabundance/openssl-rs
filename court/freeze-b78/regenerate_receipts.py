"""Regenerate openssh-v1i-sites.json and openssh-v1l-sites.json at b78.

Every declared coordinate is the current one; every span hash is recomputed with
the closure tool's own span rule at S.  A boundary is SAFETY_DISCHARGED only if
this batch's Task 2 recorded ACCEPT for it; every other boundary keeps a
non-discharging disposition with its reason.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
HERE = Path(__file__).resolve().parent
S = "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac"
SRC_SHA = "c0bd61c94f5a8da2e08c105724d14750403fbfd53aa8d4b722672f9b11b0bd38"
IMG = "a27ca428f899a58bab0449d46914a54af3f604d4b72c0ff0e5153ab14415e507"
TOOL = cc.sha256_file(ROOT / "forensics/tools/consumer_closure.py")

review = {r["boundary"]: r for r in json.loads(
    (HERE / "obligations-65.json").read_text())["obligations"]}
census = json.loads((ROOT / "court/freeze-b78/census-b78.json").read_text())
census_lines = {}
for rec in census["contracts"]["blockers"] + census["contracts"]["contracted_operations"]:
    census_lines.setdefault(
        (rec["file"], rec["kind"], rec.get("item")), []).append(rec["line"])

_blobs = {}


def blob_sha(file):
    if file not in _blobs:
        raw = subprocess.check_output(["git", "-C", str(ROOT), "show",
                                       f"{S}:{file}"])
        _blobs[file] = hashlib.sha256(raw).hexdigest()
    return _blobs[file]


REVIEW_RECEIPT = {
    "identity45": None,          # the earlier b76 batch, named per row
    "identity8": "b77-review-v1i-repaired",
    "rereview11": "b78-review-final",
    "rereview1": "b78-review-final",
}
REVIEW_PATH = {
    "identity8": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                 "b77-review-v1i-repaired.json",
    "rereview11": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                  "b78-review-final.json",
    "rereview1": "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                 "b78-review-final.json",
}

summary = {}
for name in ("openssh-v1i-sites.json", "openssh-v1l-sites.json"):
    # Read the PRIOR receipt from the committed HEAD, never from the working
    # copy: the generator must be idempotent and must keep the true superseded
    # coordinate in inventory_line.
    doc = json.loads(subprocess.check_output(
        ["git", "-C", str(ROOT), "show", f"HEAD:{ATLAS.relative_to(ROOT) / name}"]))
    out = []
    counts = {"ACCEPT": 0, "NOT_REVIEWED_IN_B78": 0, "ABSENT": 0,
              "already-retained": 0}
    for b in doc["boundaries"]:
        bid = b["id"]
        rec = dict(b)
        item = (b.get("operation") or "").split("::")[-1]
        try:
            sp = cc.resolve_operation_span(ROOT, b["file"], b["operation"],
                                           item, source_commit=S)
            resolved = True
        except cc.SpanResolutionError as exc:
            sp = None
            resolved = False
            rec["span_resolution_error"] = exc.classification
        r = review.get(bid)
        rec["inventory_line"] = b.get("line")
        rec["source_blob_sha256_basis"] = (
            "sha256 of the file's bytes at the candidate source head")
        rec["source_blob_sha256"] = blob_sha(b["file"])
        if resolved:
            rec["line"] = sp["def_line"]
            rec["line_current"] = sp["def_line"]
            rec["span_sha256"] = sp["sha256"]
            rec["span_schema"] = cc.SPAN_HASH_SCHEMA
            rec["span_normalisation"] = cc.SPAN_NORMALISATION
            rec["span_claim_scope"] = cc.SPAN_CLAIM_SCOPE
            rec["span_start_line"] = sp["start_line"]
            rec["span_end_line"] = sp["end_line"]
            rec["qualified_identity"] = sp["qualified_identity"]
        else:
            rec["line"] = b.get("line")
            rec["line_current"] = None
            rec.pop("span_sha256", None)

        if r is not None:
            rec["verdict"] = "ACCEPT"
            rec["verdict_class"] = r["verdict_class"]
            rec["verdict_basis"] = r["verdict_basis"]
            rec["review_receipt"] = (
                REVIEW_RECEIPT[r["verdict_class"]] or r["earlier_receipt"])
            if r["verdict_class"] == "identity45":
                rec["review_receipt_path"] = (
                    "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                    + r["earlier_receipt"] + ".json")
            else:
                rec["review_receipt_path"] = REVIEW_PATH[r["verdict_class"]]
            rec["reviewed_span_sha256"] = (
                r["earlier_accepted_span"]["sha256"]
                if r["verdict_class"] != "rereview11" else r["current_span"]["sha256"])
            rec["span_hash_identical_to_review"] = r["span_hash_identical"]
            note = ("discharged at this candidate; the basis and the review "
                    "link are in the receipt fields")
            rec["disposition"] = (
                f"SAFETY_DISCHARGED: {b['file']}:{sp['def_line']} — {note}")
            cur = sorted(set(census_lines.get((b["file"], b["kind"], item), [])))
            ranges = cc.scoped_ranges(rec["disposition"]).get(b["file"], [])
            rec["covers_site"] = (
                bool(sp) and sp["def_line"] in cur
                and any(lo <= sp["def_line"] <= hi for lo, hi in ranges))
            rec["covers_site_basis"] = (
                "the census records this operation at the declared definition "
                "line (the file also defines same-named operations in other "
                "modules, so the census line list is multi-valued) and the "
                "declared disposition range contains it"
                if rec["covers_site"] else
                "the census does not record the operation at the resolved "
                "definition line, or the declared range does not contain it")
            counts["ACCEPT"] += 1
        elif not resolved:
            rec["verdict"] = "ABSENT"
            rec["disposition"] = (
                "RETAINED (BLOCKED) — the item no longer exists at this "
                "candidate; a retired definition discharges nothing")
            rec["covers_site"] = False
            rec["covers_site_basis"] = "no live definition to cover"
            counts["ABSENT"] += 1
        else:
            rec["verdict"] = "NOT_REVIEWED_IN_B78"
            if cc.boundary_disposition_is_discharge(b.get("disposition")):
                mig = rec.get("span_sha256")
                rec["disposition"] = (
                    "RETAINED (BLOCKED) — the earlier discharge is withdrawn at "
                    "this candidate: this boundary is outside the reviewed "
                    "cohort and its content binding was not re-established here")
            rec["covers_site"] = False
            rec["covers_site_basis"] = (
                "not a reviewed cohort site; the declared range is the current "
                "definition line but no b78 review establishes a discharge")
            counts["NOT_REVIEWED_IN_B78"] += 1
        out.append(rec)

    new = {
        "schema": doc["schema"].replace("/v1", "/v2") if doc.get("schema") else None,
        "kind": doc["kind"],
        "receipt": doc.get("receipt"),
        "subphase": doc.get("subphase"),
        "date": "2026-11-13",
        "rebind": {
            "candidate": {
                "source_head": S,
                "src_content_sha256": SRC_SHA,
                "image_libcrypto_sha256": IMG,
                "census": "court/freeze-b78/census-b78.json",
                "closure_tool": "forensics/tools/consumer_closure.py",
                "closure_tool_sha256": TOOL,
            },
            "rule": (
                "EVERY boundary's coordinate was re-resolved at the candidate "
                "source head by (file, qualified operation) with the closure "
                "tool's own span resolver, and every span_sha256 is that "
                "resolver's hash.  The superseded coordinate is kept as "
                "inventory_line.  No recorded line is used for identity.  A "
                "boundary is SAFETY_DISCHARGED only where the b78 review "
                "recorded ACCEPT for it (verdict/review_receipt below); every "
                "other boundary carries a non-discharging disposition, so this "
                "receipt cannot discharge a site the review did not accept."),
            "reviewed_cohort": ("65 obligations = the 56 the b77 closure "
                                "adjudicated under openssh-v1i plus the 9 under "
                                "openssh-v1l"),
            "prior_evidence_note": (
                "contract/established_by/implementation_guarantees/criteria/"
                "residual are the earlier receipt's text, preserved as "
                "prior_evidence; where it cites a superseded line or a call "
                "path that no longer exists, the b78 verdict fields are the "
                "operative evidence."),
        },
        "candidate_identity": {
            "source_head": S,
            "src_content_sha256": SRC_SHA,
            "image_libcrypto_sha256": IMG,
        },
        "method": doc.get("method"),
        "boundaries": out,
        "negative_controls": doc.get("negative_controls"),
        "does_not_prove": list(doc.get("does_not_prove") or []) + [
            "It does not discharge any site that the b78 review recorded as "
            "anything other than ACCEPT; such a boundary carries a "
            "non-discharging disposition.",
            "It does not establish a boundary-level SAFETY_DISCHARGED for "
            "D-DIGEST-NULL-ALGCTX-1 or D-SHA3-FINAL-OUTLEN-1: those are "
            "mechanism records (docs/SECURITY_DIVERGENCE_POLICY.md), not a "
            "consumer-family graduation.",
            "A span hash binds the operation's own text only.  It does not "
            "cover dispatchers, shared guards, macro headers, caller closures "
            "or any code outside the brace-matched span.",
            "For a provider callback the accepted precondition is established "
            "by the core entry point named in the verdict basis; a third-party "
            "caller of the OpenSSL ABI that bypasses that entry point is "
            "outside this scope.",
        ],
        "non_claims": list(doc.get("non_claims") or []) + [
            "ACCEPT is a site-scoped contract verdict at this candidate; it is "
            "not a consumer graduation and not a SAFE_COMPATIBLE claim.",
        ],
    }
    if doc.get("supersedes"):
        new["supersedes"] = doc["supersedes"]
    path = ATLAS / name
    path.write_text(json.dumps(new, indent=1) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    summary[name] = {"receipt": new["receipt"], "boundaries": len(out),
                     "counts": counts, "sha256": digest,
                     "bytes": path.stat().st_size}
    print(name, counts, "sha256", digest)
print(json.dumps(summary, indent=1))
(HERE / "receipt-digests-b78.json").write_text(json.dumps(summary, indent=1) + "\n")
