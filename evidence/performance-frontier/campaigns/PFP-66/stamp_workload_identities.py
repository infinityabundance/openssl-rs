#!/usr/bin/env python3
"""PFP-66: stamp the machine-readable workload identity onto the two benchmark
records involved in the P-256 sign / sign+verify confusion.

The identity is the *timed operation list*, not the row name.  The canonical
PFP-0 declaration is `forensics/performance/WORKLOADS.json`'s
`timed_operations`; the two campaign records below time a different operation
set and therefore carry their own `workload_identity` block.  Both rows are
called `ecdsa256`; that name is a label, not the identity.

This script is deterministic and is run once.  It rewrites both JSON documents
with sorted keys so the record is stable across re-runs.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]

WORKLOADS = ROOT / "forensics" / "performance" / "WORKLOADS.json"
MA1 = ROOT / "evidence/performance-frontier/campaigns/M-A1/timing/raw/timing-summary.json"
PFP11 = ROOT / "evidence/performance-frontier/campaigns/PFP-11/raw/phase2-three-arm.json"

DESCRIPTIONS = {
    "ecdsa256": (
        "ECDSA_do_sign on P-256, timed alone; verification is run once outside "
        "the timed region (bench_pfp5.c ec_step, 15 interleaved --prepared reps)"
    ),
}


def identity(workload_id, operations, description=None):
    block = {"workload_id": workload_id, "timed_operations": list(operations)}
    if description:
        block["description"] = description
    return block


def dump(path, doc):
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    registry = json.loads(WORKLOADS.read_text(encoding="utf-8"))
    operations = {w["id"]: w["timed_operations"] for w in registry["workloads"]}

    ma1 = json.loads(MA1.read_text(encoding="utf-8"))
    for name, row in ma1["workloads"].items():
        row["workload_identity"] = identity(
            name, operations[name], DESCRIPTIONS.get(name)
        )
    dump(MA1, ma1)

    pfp11 = json.loads(PFP11.read_text(encoding="utf-8"))
    pfp11["p256"]["ecdsa256"]["workload_identity"] = identity(
        "ecdsa256",
        ["ECDSA_do_sign", "ECDSA_do_verify"],
        "sign-then-verify: ECDSA_do_sign and the ECDSA_do_verify correctness "
        "guard are both inside the timed loop (bench_p256.c:104-121)",
    )
    pfp11["p521"]["ecdsa-sign-p521"]["workload_identity"] = identity(
        "ecdsa-sign-p521", ["ECDSA_do_sign"]
    )
    pfp11["p521"]["ecdsa-verify-p521"]["workload_identity"] = identity(
        "ecdsa-verify-p521", ["ECDSA_do_verify"]
    )
    dump(PFP11, pfp11)

    print(f"stamped {MA1}")
    print(f"stamped {PFP11}")


if __name__ == "__main__":
    main()
