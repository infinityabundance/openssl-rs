"""S48: rebind the runtime/functional atlas to the 0.0.36 install.

No family is measured.  Every recipe-backed row that was reuse-eligible at the
previous identity is marked with `reused_from_candidate_identity` (the same
durable marker the tool's `--reuse-committed --reuse-previous-candidate` path
writes), the atlas identity is moved to the rebuilt install, and
`candidate_identity_match` becomes false.
"""
import copy
import json
import sys

sys.path.insert(0, "/work/forensics/tools")
import downstream_runtime as dr  # noqa: E402

doc = json.loads(dr.OUT.read_text(encoding="utf-8"))
body = doc["body"]
old = copy.deepcopy(body["candidate_identity"])
cur = dr.bl.candidate_identity()
reuse = body["evidence_reuse"]
names = set(reuse.get("reused_families") or [])
if not names:
    raise SystemExit("atlas has no reused families; refusing to invent a rebind")

superseded = {}
for field in ("install_prefix", "libssl_so_3_sha256", "libcrypto_so_3_sha256"):
    if str(cur.get(field)) != str(old.get(field)):
        superseded[field] = {"committed": str(old.get(field)),
                             "current": str(cur.get(field))}
if not superseded:
    raise SystemExit("candidate identity did not move; nothing to rebind")

by_family = {}
for row in body["runs"]:
    by_family.setdefault(str(row.get("canonical_name")), []).append(row)
missing = sorted(names - set(by_family))
if missing:
    raise SystemExit(f"reused families absent from runs: {missing[:5]}")
unmarked = 0
for name in names:
    for row in by_family[name]:
        row["reused_from_candidate_identity"] = copy.deepcopy(old)
        unmarked += 1

body["candidate_identity"] = cur
reuse["mode"] = "committed-rows-carried-forward"
reuse["candidate_identity_match"] = False
reuse["superseded_identity"] = superseded
dr.write_outputs(body, body["authority"])
print(json.dumps({
    "candidate_identity": cur,
    "superseded_identity": superseded,
    "families_reused": len(names),
    "rows_marked": unmarked,
    "candidate_identity_match": reuse["candidate_identity_match"],
}, indent=2))
