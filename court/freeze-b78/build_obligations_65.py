"""Assemble the 65-obligation review cohort at b78.

Reads the b77 closure (obligation universe), the three b76 v1i review batches
and the b76 v1l review, then resolves each obligation's CURRENT coordinate from
court/freeze-b78/census-b78.json by (file, kind, item) - never by the recorded
line.
"""
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
OUT = Path(__file__).resolve().parent / "obligations-65.json"

closure = json.loads((ROOT / "evidence/closure-ssh-b77.json").read_text())
census = json.loads((ROOT / "court/freeze-b78/census-b78.json").read_text())

# --- earlier verdicts -------------------------------------------------------
earlier = {}
for name in ("b76-review-v1i-batch1.json", "b76-review-v1i-batch2.json",
             "b76-review-v1i-batch3.json", "b76-review-v1l.json"):
    doc = json.loads((ATLAS / name).read_text())
    for row in doc["obligations"]:
        sid = f'{row["file"]}::{row.get("kind", "UNSAFE_FN_DEF")}::{row["item"]}'
        earlier[sid] = {
            "receipt": name.replace(".json", ""),
            "boundary": row["boundary"],
            "file": row["file"],
            "line": row["line"],
            "item": row["item"],
            "verdict": row["verdict"],
            "verdict_reason": row["verdict_reason"],
        }

repaired = json.loads((ATLAS / "b77-review-v1i-repaired.json").read_text())
for row in repaired["repaired_sites"]:
    sid = row["stable_id"]
    earlier.setdefault(sid, {})
    earlier[sid].update({
        "receipt": "b77-review-v1i-repaired",
        "boundary": row["boundary"],
        "verdict": "ACCEPT",
        "verdict_reason": "re-reviewed and ACCEPTed at the b77 repair "
                          "(ada7df257); see b77-review-v1i-repaired.json",
        "b77": {
            "reviewed_span": row.get("reviewed_span"),
            "span_sha256_reviewed": row.get("span_sha256_reviewed"),
            "operation_body_unchanged_at_head": row.get(
                "operation_body_unchanged_at_head"),
            "retained_obligations": row.get("retained_obligations"),
        },
    })

# --- census lookup by stable identity ---------------------------------------
def load_census():
    by_key = collections.defaultdict(list)
    for b in census["contracts"]["blockers"]:
        by_key[(b["file"], b["kind"], b.get("item"))].append(
            {"line": b["line"], "partition": b["partition"],
             "source": "contracts.blockers"})
    for c in census["contracts"]["contracted_operations"]:
        by_key[(c["file"], c["kind"], c.get("item"))].append(
            {"line": c["line"], "partition": c["partition"],
             "source": "contracts.contracted_operations"})
    return by_key


census_by_key = load_census()

# --- cohort: 56 openssh-v1i + 9 openssh-v1l --------------------------------
def receipt_of(o):
    return o.get("discharge_receipt") or o.get("pending_discharge_receipt")


cohort = []
seen = set()
for o in closure["obligations"]:
    sid = o["stable_id"]
    prior = earlier.get(sid)
    if prior is None:
        continue
    rec = receipt_of(o)
    # the 8 BLOCKED rows carry no receipt; they are the v1i cohort's
    # previously-REJECTed repaired sites, identified by their earlier receipt.
    if rec not in ("openssh-v1i", "openssh-v1l", None):
        continue
    if rec is None and prior.get("receipt") not in (
            "b77-review-v1i-repaired",) and not prior.get("boundary", "").startswith(
            "OSSH-V1I"):
        continue
    if sid in seen:
        continue
    seen.add(sid)
    cohort.append((o, prior))

rows = []
for o, prior in cohort:
    f, kind, item = o["file"], o.get("kind"), o.get("item")
    live = census_by_key.get((f, kind, item)) or []
    lines = sorted({x["line"] for x in live})
    rows.append({
        "id": o["id"],
        "stable_id": o["stable_id"],
        "file": f,
        "kind": kind,
        "item": item,
        "mechanism": o.get("mechanism"),
        "recorded_line_b77": o["line"],
        "recorded_line_earlier_review": prior.get("line"),
        "current_census_lines": lines,
        "current_coordinate_resolution": (
            "unique" if len(lines) == 1 else
            "absent" if not lines else f"ambiguous({len(lines)})"),
        "current_census_source": sorted({x["source"] for x in live}),
        "current_partition": sorted({x["partition"] for x in live}),
        "earlier_receipt": prior.get("receipt"),
        "earlier_boundary": prior.get("boundary"),
        "earlier_verdict": prior.get("verdict"),
        "earlier_verdict_reason": prior.get("verdict_reason"),
        "earlier_b77_repair": prior.get("b77"),
        "b77_closure_status": o.get("status"),
        "b77_discharge_receipt": o.get("discharge_receipt"),
        "b77_discharge_boundary": o.get("discharge_boundary_id"),
    })

rows.sort(key=lambda r: (r["file"], r["item"] or "", r["current_census_lines"]))
doc = {
    "schema": "openssl-rs/safe-c33/atlas-refresh/b78-obligation-set/v1",
    "generated_utc": "2026-11-13T00:00:00Z",
    "candidate": {
        "source_head": "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac",
        "src_content_sha256":
            "c0bd61c94f5a8da2e08c105724d14750403fbfd53aa8d4b722672f9b11b0bd38",
        "image_libcrypto_sha256":
            "a27ca428f899a58bab0449d46914a54af3f604d4b72c0ff0e5153ab14415e507",
        "census": "court/freeze-b78/census-b78.json",
        "closure": "evidence/closure-ssh-b77.json",
    },
    "rule": ("The cohort is every obligation the b77 closure adjudicated with "
             "discharge_receipt openssh-v1i or openssh-v1l, plus the eight "
             "rows the v1i receipt had carried before the b77 repair, whose "
             "discharge the b77 closure refused (discharge_receipt null, "
             "BLOCKED).  Each obligation's CURRENT coordinate is resolved from "
             "census-b78 by (file, kind, item); the recorded line is reported "
             "but never used for identity."),
    "counts": {
        "cohort": len(rows),
        "by_earlier_receipt": dict(collections.Counter(
            r["earlier_receipt"] for r in rows)),
        "by_earlier_verdict": dict(collections.Counter(
            r["earlier_verdict"] for r in rows)),
        "current_resolution": dict(collections.Counter(
            r["current_coordinate_resolution"] for r in rows)),
        "by_file": dict(collections.Counter(r["file"] for r in rows)),
    },
    "obligations": rows,
}
OUT.write_text(json.dumps(doc, indent=1) + "\n")
print(json.dumps(doc["counts"], indent=1))
for r in rows:
    if r["current_coordinate_resolution"] != "unique":
        print("NOT-UNIQUE", r["stable_id"], r["current_census_lines"])
