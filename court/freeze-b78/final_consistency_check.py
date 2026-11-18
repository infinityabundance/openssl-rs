"""Final consistency check across the three artefacts written by this batch."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

ATLAS = ROOT / "forensics/memory-safety/campaign/safe-c33/atlas-refresh"
HERE = Path(__file__).resolve().parent

sha = {n: hashlib.sha256((ATLAS / n).read_bytes()).hexdigest()
       for n in ("openssh-v1i-sites.json", "openssh-v1l-sites.json",
                 "b78-review-final.json")}
dig = json.loads((HERE / "receipt-digests-b78.json").read_text())
rev = json.loads((ATLAS / "b78-review-final.json").read_text())
obs = json.loads((HERE / "obligations-65.json").read_text())
cohort = {r["boundary"] for r in obs["obligations"]}

checks = {}
checks["receipt-digests-match-files"] = all(
    dig[n]["sha256"] == sha[n] for n in (
        "openssh-v1i-sites.json", "openssh-v1l-sites.json"))
checks["review-receipt-records-them"] = all(
    rev["regenerated_receipts"][n]["sha256"] == sha[n] for n in (
        "openssh-v1i-sites.json", "openssh-v1l-sites.json"))

per_receipt = {}
bad = []
for n in ("openssh-v1i-sites.json", "openssh-v1l-sites.json"):
    bs = json.loads((ATLAS / n).read_text())["boundaries"]
    acc = [b for b in bs if b.get("verdict") == "ACCEPT"]
    per_receipt[n] = {"boundaries": len(bs), "ACCEPT": len(acc)}
    for b in bs:
        if b.get("verdict") == "ACCEPT":
            ok = (b["id"] in cohort and b.get("span_sha256")
                  and b.get("review_receipt") and b.get("verdict_basis")
                  and cc.boundary_disposition_is_discharge(b["disposition"])
                  and b["line"] == b["span_start_line"]
                  and b["covers_site"])
            if not ok:
                bad.append((n, b["id"], "accept-incomplete"))
        else:
            if cc.boundary_disposition_is_discharge(b.get("disposition")):
                bad.append((n, b["id"], "non-accept-rows-discharges"))
checks["per-receipt-consistency"] = not bad
checks["accepted-boundaries-equal-cohort"] = (
    sum(v["ACCEPT"] for v in per_receipt.values()) == len(cohort))
checks["cohort-65-all-accept"] = (
    len(obs["obligations"]) == 65
    and all(r["verdict"] == "ACCEPT" and r["span_hash_identical"]
            for r in obs["obligations"]))
checks["review-tally-matches"] = (
    rev["final_tally"] == {"cohort": 65, "ACCEPT": 65, "REJECT": 0, "ABSENT": 0})
checks["controls-all-pass"] = all(
    c["pass"] for c in json.loads((HERE / "controls-b78.json").read_text())["controls"])
checks["adjudication-control-pass"] = json.loads(
    (HERE / "adjudicate-control-b78.json").read_text())["pass"]

out = {"sha256": sha, "per_receipt": per_receipt, "problems": bad[:10],
       "checks": checks, "all_pass": all(checks.values())}
print(json.dumps(out, indent=1))
