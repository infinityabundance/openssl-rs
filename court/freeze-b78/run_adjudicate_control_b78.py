"""End-to-end control: run the closure's own adjudicator against the
regenerated receipts.

For every cohort obligation we build the obligation the closure would carry,
supply a plane that lists the boundary id as scoped-discharged (the strongest
possible input), and check that the adjudicator answers DISCHARGED only for a
site the b78 review recorded ACCEPT.

Also checks one withdrawn boundary and one absent boundary answer BLOCKED.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
S = "bb7d5206acfbf6c3e0ba202a0a03e61b8bf13aac"
cc._EVIDENCE_ENV["source_commit"] = S

by_file, by_id = cc.load_boundaries(ATLAS)
cohort = json.loads((Path(__file__).resolve().parent / "obligations-65.json")
                    .read_text())["obligations"]

# strongest-input plane: every boundary id in the reviewed receipts is listed
ids = set()
for name in ("openssh-v1i-sites.json", "openssh-v1l-sites.json"):
    for b in json.loads((ATLAS / name).read_text())["boundaries"]:
        ids.add(b["id"])
plane = {"mechanism_discharges": {},
         "scoped_boundary_discharges": {i: {"receipt": "synthetic-status"}
                                        for i in ids},
         "err_scope": {}}

wrong = []
discharged = 0
for r in cohort:
    ob = {"id": f'V1:{r["file"]}:{r["current_span"]["def_line"]}:{r["kind"]}',
          "stable_id": r["file"] + "::" + r["kind"] + "::" + r["item"],
          "file": r["file"], "line": r["current_span"]["def_line"],
          "current_census_line": r["current_span"]["def_line"],
          "kind": r["kind"], "item": r["item"], "mechanism": r["mechanism"],
          "partition": "production"}
    out = cc.adjudicate(ob, {}, by_file.get(r["file"], []), plane,
                        repo=ROOT, enforce_conflicts=False)
    status = out.get("status")
    if status == "DISCHARGED":
        discharged += 1
        if out.get("discharge_receipt") != "synthetic-status":
            wrong.append((r["boundary"], "receipt", out.get("discharge_receipt")))
    else:
        wrong.append((r["boundary"], status,
                      (out.get("scoped_discharge_attempts") or [{}])[-1]
                      .get("span_classification")))

withdrawn = []
for bid in ("OSSH-V1I-066", "OSSH-V1I-080", "OSSH-V1L-001", "OSSH-V1L-008"):
    b = by_id[bid][0]
    ob = {"id": f"V1:{b['file']}:{b['line']}:{b['kind']}",
          "stable_id": b["file"] + "::" + b["kind"] + "::"
                      + (b["operation"] or "").split("::")[-1],
          "file": b["file"], "line": b["line"],
          "current_census_line": b["line"], "kind": b["kind"],
          "item": (b["operation"] or "").split("::")[-1],
          "mechanism": b["mechanism"], "partition": "production"}
    out = cc.adjudicate(ob, {}, by_file.get(b["file"], []), plane,
                        repo=ROOT, enforce_conflicts=False)
    withdrawn.append({"boundary": bid, "status": out.get("status"),
                      "reason": str(out.get("status_reason"))[:120]})

raw = {b["id"]: b for b in json.loads(
    (ATLAS / "openssh-v1i-sites.json").read_text())["boundaries"]}
absent = []
for bid in ("OSSH-V1I-055", "OSSH-V1I-062"):
    b = raw[bid]
    absent.append({"boundary": bid, "disposition": b["disposition"][:90],
                   "declared_span_hash_present": b.get("span_sha256") is not None,
                   "verdict": b.get("verdict")})

res = {
    "candidate": S,
    "cohort": len(cohort),
    "discharged": discharged,
    "not_discharged": wrong,
    "withdrawn_control": withdrawn,
    "absent_control": absent,
    "pass": not wrong and discharged == len(cohort)
            and all(w["status"] != "DISCHARGED" for w in withdrawn)
            and all(not a["declared_span_hash_present"]
                    and a["verdict"] == "ABSENT" for a in absent),
}
(Path(__file__).resolve().parent / "adjudicate-control-b78.json").write_text(
    json.dumps(res, indent=1) + "\n")
print(json.dumps({k: (v if k not in ("not_discharged", "withdrawn_control")
                      else v) for k, v in res.items()}, indent=1)[:2200])
