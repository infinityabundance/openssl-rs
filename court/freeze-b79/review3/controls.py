#!/usr/bin/env python3
"""Review-3 controls for the sixteen re-bound rows.

Source-level only: uses the closure tool's own span resolver and adjudicator.
Modes:  pre | post | canaries
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path("/home/user/openssl-rs")
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

CAND = "08cb1148b40aa4cebc727e7c0b988505d3094ff0"
ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
CLOSURE = ROOT / "evidence/closure-ssh-b79b.json"
IDS = (["OSSH-V1I-%03d" % n for n in (49, 50, 51, 52, 53, 54, 59, 60, 61, 63,
                                      64, 65, 67, 69)]
       + ["RAND-CTX-001", "ssl_conf.rs:616"])

cc._EVIDENCE_ENV["source_commit"] = CAND


def plane(ids):
    return {"mechanism_discharges": {},
            "scoped_boundary_discharges": {i: {"receipt": "synthetic"}
                                           for i in ids},
            "err_scope": {}}


def obligations():
    """The sixteen obligations exactly as the b79b closure carried them."""
    doc = json.loads(CLOSURE.read_text())
    want = {i for i in IDS}
    by_item = {}
    for b in doc["obligations"]:
        if b.get("status") != "DISCHARGED":
            by_item[(b["file"], b["item"])] = b
    out = []
    for (f, item), b in by_item.items():
        out.append({
            "id": b["id"], "stable_id": b["stable_id"], "file": f,
            "line": b["line"],
            "current_census_line": b.get("current_census_line"),
            "kind": b["kind"], "item": item, "mechanism": b["mechanism"],
            "partition": "production"})
    return out


def run(atlas):
    by_file, by_id = cc.load_boundaries(atlas)
    rows = []
    for ob in obligations():
        res = cc.adjudicate(copy.deepcopy(ob), {},
                            by_file.get(ob["file"], []), plane(IDS),
                            repo=ROOT, enforce_conflicts=False)
        attempts = res.get("scoped_discharge_attempts") or []
        cls = [a.get("span_classification") for a in attempts
               if a.get("span_classification")]
        rows.append({"item": ob["item"], "status": res["status"],
                     "boundary": res.get("discharge_boundary_id"),
                     "class": cls[:1] or None,
                     "reason": (res.get("status_reason") or "")[:120]})
    return rows


def report(rows):
    bad = [r for r in rows if r["status"] != "DISCHARGED"]
    print(f"adjudicated {len(rows)}: DISCHARGED {len(rows) - len(bad)}, "
          f"not {len(bad)}")
    for r in rows:
        print(f'  {r["item"]:26s} {r["status"]:11s} '
              f'{(r["class"] or ["-"])[0]:22s} {r["boundary"] or ""}')
    return len(bad)


def canaries():
    """C5 doc-only invariant + C4 per-row content canary."""
    import shutil
    import tempfile

    rows = json.loads((ROOT / "court/freeze-b79/review3/spans.json").read_text())
    # C5: reverting the added SAFETY comment must reproduce the recorded hash.
    ok = 0
    for r in rows:
        if "old_lines" not in r:
            continue
        new_text = "\n".join(r["new_lines"])
        reverted = new_text
        for a, b in zip(r["new_lines"], r["old_lines"]):
            if a != b:
                reverted = reverted.replace(a, b, 1)
        res = cc.resolve_operation_span(ROOT, r["file"], r["operation"],
                                        r["operation"].split("::")[-1],
                                        source_text=reverted)
        if res["sha256"] == r["old_span"]["sha256"]:
            ok += 1
    print(f"C5 doc-only-invariant: reverting the added comment reproduces the "
          f"recorded hash for {ok}/{len(rows)} spans (the two annotation-only "
          f"rows are excluded by construction)")

    # C4: corrupt exactly one row's hash in a private copy of the receipts.
    tmp = Path(tempfile.mkdtemp(prefix="_tmp_rebind_"))
    for p in ATLAS.glob("*.json"):
        shutil.copy2(p, tmp / p.name)
    owner = {}
    for fname in ("openssh-v1i-sites.json", "boundary-sweep-B69.json",
                  "sslconf-exclusivity-2026-11-10-sites.json"):
        for b in json.loads((ATLAS / fname).read_text())["boundaries"]:
            if b["id"] in IDS:
                owner[b["id"]] = fname
    fired = 0
    for rid, fname in owner.items():
        doc2 = json.loads((ATLAS / fname).read_text())
        for b in doc2["boundaries"]:
            if b["id"] == rid:
                b["span_sha256"] = "0" * 64
        (tmp / fname).write_text(json.dumps(doc2, indent=1))
        got = run(tmp)
        bad = [r for r in got if r["status"] != "DISCHARGED"]
        item = next(x["operation"].split("::")[-1]
                    for x in rows if x["id"] == rid)
        ok = (len(bad) == 1 and bad[0]["item"] == item)
        print(f"C4 break-{rid:18s} blocked={bad[0]['item'] if bad else None!s:26s}"
              f"other15-discharged={len(bad) == 1} -> "
              f'{"FIRED" if ok else "MISSED"}')
        fired += ok
        shutil.copy2(ATLAS / fname, tmp / fname)
    print(f"C4 fired {fired}/{len(owner)}")
    shutil.rmtree(tmp)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "pre"
    if mode == "canaries":
        canaries()
    else:
        bad = report(run(ATLAS))
        sys.exit(0 if ((mode == "pre" and bad == 16)
                       or (mode == "post" and bad == 0)) else 1)
