"""b78 controls for the review and the regenerated receipts.

No compilation, no source modification: every mutation is applied to an
in-memory copy of the candidate blob.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

S = "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac"
results = []


def record(cid, purpose, expected, observed, ok):
    results.append({"id": cid, "purpose": purpose, "expected": expected,
                    "observed": observed, "pass": bool(ok)})


# C1/C2/C3 -- the span rule: docs excluded, code included, hash moves on code
text, _ = cc._git_blob_text(ROOT, S, "src/provider/digest.rs")
base = cc.resolve_operation_span(ROOT, "src/provider/digest.rs",
                                 "sha1::copyctx", "copyctx", source_text=text)
doc_text = text.replace(
    "    /// `OSSL_FUNC_digest_copyctx_fn` for the SHA-1 row.",
    "    /// `OSSL_FUNC_digest_copyctx_fn` for the SHA-1 row.\n"
    "    /// A doc-only line added by control C2.", 1)
doc_span = cc.resolve_operation_span(ROOT, "src/provider/digest.rs",
                                     "sha1::copyctx", "copyctx",
                                     source_text=doc_text)
code_text = text.replace(
    "        // SAFETY: both regions are valid for `size_of::<ShaCtx>()` bytes and may be the same",
    "        // SAFETY: both regions are valid for `size_of::<ShaCtx>()` bytes; may be the same",
    1)
code_span = cc.resolve_operation_span(ROOT, "src/provider/digest.rs",
                                      "sha1::copyctx", "copyctx",
                                      source_text=code_text)
record("C1-pristine-span", "resolve sha1::copyctx in the candidate blob",
       "672-682", f'{base["start_line"]}-{base["end_line"]}',
       (base["start_line"], base["end_line"]) == (672, 682))
record("C2-doc-only-edit", "a /// line above the fn must not move the span hash",
       "identical hash", "identical" if doc_span["sha256"] == base["sha256"]
       else "hash changed", doc_span["sha256"] == base["sha256"])
record("C3-code-edit", "a code line inside the span must change the hash",
       "different hash", "different" if code_span["sha256"] != base["sha256"]
       else "identical", code_span["sha256"] != base["sha256"])

# C4 -- identity is the qualified operation, never the last component alone
try:
    cc.resolve_operation_span(ROOT, "src/provider/digest.rs", "copyctx",
                              "copyctx", source_commit=S)
    amb = False
except cc.SpanResolutionError as exc:
    amb = exc.classification == "ambiguous-identity"
record("C4-unqualified-identity", "bare `copyctx` must not select a definition",
       "ambiguous-identity", "ambiguous-identity" if amb else "resolved", amb)

# C5 -- a retired item is an absence, not a discharge
try:
    cc.resolve_operation_span(ROOT, "src/cmp/cmp_ctx.rs", "x509_free_void",
                              "x509_free_void", source_commit=S)
    absent = False
except cc.SpanResolutionError as exc:
    absent = exc.classification == "span-unparsable"
record("C5-absent-item", "the retired x509_free_void thunk must not resolve",
       "span-unparsable", "span-unparsable" if absent else "resolved", absent)

# C6 -- the disposition gate
gate = (cc.boundary_disposition_is_discharge("SAFETY_DISCHARGED: x:1")
        and not cc.boundary_disposition_is_discharge("RETAINED (BLOCKED) — x")
        and not cc.boundary_disposition_is_discharge("SAFETY_DISCHARGED_PENDING"))
record("C6-disposition-gate", "only a SAFETY_DISCHARGED prefix discharges",
       "accept / reject / reject", "matched" if gate else "mismatched", gate)

# C7 -- covers_site arithmetic on the regenerated receipts
disp = json.loads((ROOT / "forensics/memory-safety/campaign/safe-c33/"
                   "atlas-refresh/openssh-v1i-sites.json").read_text())
census = json.loads((ROOT / "court/freeze-b78/census-b78.json").read_text())
lines = {}
for rec in census["contracts"]["blockers"] + census["contracts"]["contracted_operations"]:
    lines.setdefault((rec["file"], rec["kind"], rec.get("item")), []).append(rec["line"])
bad_cover, stale_cover = [], []
for b in disp["boundaries"]:
    if b.get("verdict") != "ACCEPT":
        continue
    ranges = cc.scoped_ranges(b["disposition"]).get(b["file"], [])
    current = lines.get((b["file"], b["kind"], b["operation"].split("::")[-1]), [])
    if not any(lo <= b["line"] <= hi for lo, hi in ranges):
        bad_cover.append(b["id"])
    old = b.get("inventory_line")
    if old is not None and old != b["line"] and any(lo <= old <= hi
                                                    for lo, hi in ranges):
        stale_cover.append(b["id"])
record("C7-covers-site", "every accepted row's declared range covers its current "
       "census line, and the superseded line is outside it",
       "0 uncovered, 0 stale-covered",
       f"{len(bad_cover)} uncovered {bad_cover[:4]}, {len(stale_cover)} stale",
       not bad_cover and not stale_cover)

# C7b -- the declared range is exactly the current definition line
inexact = []
for b in disp["boundaries"]:
    if b.get("verdict") != "ACCEPT":
        continue
    rng = cc.scoped_ranges(b["disposition"]).get(b["file"], [])
    if rng != [(b["line"], b["line"])]:
        inexact.append((b["id"], rng, b["line"]))
record("C7b-exact-range", "an accepted row declares the current line and no "
       "other range (no digit in the note is parsed as coverage)",
       "0 inexact", f"{len(inexact)} inexact {inexact[:3]}", not inexact)

# C8 -- recorded hash equals the recomputed hash at S for every accepted row
mismatch = []
for b in disp["boundaries"]:
    if b.get("verdict") != "ACCEPT":
        continue
    try:
        s = cc.resolve_operation_span(ROOT, b["file"], b["operation"],
                                      b["operation"].split("::")[-1],
                                      source_commit=S)
    except cc.SpanResolutionError as exc:
        mismatch.append((b["id"], exc.classification))
        continue
    if s["sha256"] != b.get("span_sha256"):
        mismatch.append((b["id"], "hash"))
record("C8-hash-binding", "each accepted row's span_sha256 reproduces at S",
       "0 mismatches", f"{len(mismatch)} mismatches {mismatch[:4]}", not mismatch)

Path(__file__).resolve().parent.joinpath("controls-b78.json").write_text(
    json.dumps({"candidate": S, "controls": results}, indent=1) + "\n")
for r in results:
    print(("PASS " if r["pass"] else "FAIL "), r["id"], "|", r["observed"])
print("all pass:", all(r["pass"] for r in results))
