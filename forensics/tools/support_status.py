#!/usr/bin/env python3
"""openssl-rs — the support-status ladder: one derived status per catalogue node.

Phase 23 is the multitrack authority stratum (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). 23.15 says the
support-status ladder is the **derived support status of each release node** over `catalogued`,
`admitted-source`, `built-authority`, `atlas-complete`, `candidate-view`, `runtime-evidenced`,
`downstream-evidenced` and `maintained`, with `archaeological-only` where the node is studied and not
supported. This module derives that record -- `forensics/multitrack/support-status.json` -- over
**every** node of `forensics/release-catalog.json`.

One truth, two views
--------------------
23.10's `historical_population.py` already derives a per-node status from the same evidence planes,
and the plan's section 4.5 permits a subphase to record a measured correction rather than duplicate a
second hand-maintained truth. This plane therefore **reuses that one derivation**: it calls
`historical_population.derive_body()` and re-expresses each population record as the schema-validated
`support_status` row the plan's artefact table names, adding the two things the plan asks the
subphase for and 23.10 does not carry per node -- the **evidence for each rung attained**
(`evidence_by_rung`) and the **reason for each rung not attained** (`not_attained`). Both are read
from the population record and the ladder, never typed: the status and rungs have exactly one
derivation (23.10's), and this plane is reconciled with it node-for-node and rung-for-rung by
`RT-SUPPORT-STATUS`, so neither is a parallel truth.

The statuses are release/authority states, not the stratum's parity dimensions. `support_role`
records whether a node is a `support-target` or `archaeology`; it is ladder bookkeeping and **not** a
compatibility verdict. Nothing here is a `PARITY_VERIFIED` or any other one-boolean compatibility
claim: compatibility is directional and dimension-specific (`docs/PARITY_MODEL.md` sections 3 and 4),
and the stratum's compatibility claim lives in the compatibility views and matrix, never here.

The ladder's shape
------------------
`multitrack_schemas.SUPPORT_CORE` is the contiguous climb every supported node makes; the rungs above
it are each read from an independent evidence plane, so a node may attain them without the
intermediate additive rungs (0.9.8zh is `downstream-evidenced` from a real consumer without
`candidate-view`/`runtime-evidenced`). A node outside the public final-release lineage, or a final
release whose official source cannot be admitted, is `archaeological-only` and has climbed no rung.

Outputs
-------
  forensics/multitrack/support-status.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

import multitrack_schemas as mts  # noqa: E402
import historical_population as hp  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "support-status.json"
GENERATOR = "forensics/tools/support_status.py"

# The evidence artefact each rung is read from. `built-authority` is read from whichever receipt the
# authority node names (the historical receipts for the historical venue, the atlas build records
# for the forensic venue), so both paths are listed. `atlas-complete` is dynamic (one committed atlas
# per authority) and is recognised by `rung_of_evidence` rather than pinned here.
RUNG_EVIDENCE: dict[str, tuple[str, ...]] = {
    "catalogued": ("forensics/release-catalog.json",),
    "admitted-source": ("forensics/multitrack/historical-acquisition.json",
                        "forensics/authorities/AUTHORITIES.json"),
    "built-authority": ("forensics/multitrack/historical-build-receipts.json",
                        "forensics/atlas/BUILD_RECORDS.json"),
    "candidate-view": ("forensics/multitrack/compatibility-views.json",),
    "runtime-evidenced": ("forensics/multitrack/semantic-courts.json",),
    "downstream-evidenced": ("forensics/multitrack/downstream-multitrack.json",),
    "maintained": ("forensics/multitrack/default-authority.json",),
}

# Why a rung is not attained, one rung per evidence plane. It names the plane whose evidence is
# absent, so a node that stops low says why rather than leaving a blank.
NON_ATTAINMENT: dict[str, str] = {
    "catalogued": "the node is not on the public final-release lineage the ladder tracks",
    "admitted-source": "no acquisition record and no admitted-authority record names the release",
    "built-authority": "no authority node with a build receipt names the release",
    "atlas-complete": "the authority carries no committed atlas",
    "candidate-view": "no compatible candidate-to-reference view names the authority",
    "runtime-evidenced": "the authority is not one side of the executed oracle-to-oracle semantic "
                         "pair",
    "downstream-evidenced": "no passing unmodified downstream consumer was built against the "
                            "authority",
    "maintained": "the node is not the maintained candidate the default-authority alias names",
}


def rung_of_evidence(path: str) -> str | None:
    """The ladder rung an evidence entry backs, or `None` for an unclassified entry."""
    for rung, paths in RUNG_EVIDENCE.items():
        if path in paths:
            return rung
    if path.startswith("forensics/atlas/") and (path.endswith("/plane-census.json")
                                                or path.endswith("/ATLAS.md")):
        return "atlas-complete"
    return None


def body_hash(records: list[dict]) -> str:
    """The support-status body's content hash, a function of its committed rows."""
    return content_hash({"records": records})


def derive_body() -> dict:
    """The support-status body, a pure function of the 23.10 population and the committed evidence.

    Deterministic: every list is sorted, no wall-clock/environment value is read, and every rung's
    evidence and every non-attainment reason are read from the population record and the ladder
    rather than typed. The court re-derives this body through the same code and refuses a committed
    status that was typed rather than derived, and reconciles every row with its population record.
    """
    population = hp.derive_body()

    records: list[dict] = []
    for record in population.get("records") or []:
        rid = record["release_id"]
        rungs = list(record.get("rungs_attained") or [])
        status = record["status"]

        evidence = list(record.get("evidence") or [])
        evidence_by_rung: dict[str, dict] = {}
        for entry in evidence:
            rung = rung_of_evidence(str(entry.get("path")))
            if rung is not None and rung not in evidence_by_rung:
                evidence_by_rung[rung] = entry
        for rung in rungs:
            if rung not in evidence_by_rung:
                raise SystemExit(
                    f"support-status: {rid} attained {rung} but no evidence entry backs it"
                )

        archaeology = status == "archaeological-only"
        if archaeology:
            # Every rung is unclimbed, and the reason is the node's own archaeological disposition.
            not_attained = {rung: record["reason"] for rung in mts.SUPPORT_LADDER}
        else:
            not_attained = {rung: NON_ATTAINMENT[rung] for rung in mts.SUPPORT_LADDER
                            if rung not in rungs}

        records.append({
            "subject_id": rid,
            "display_version": record["display_version"],
            "release_channel": record["release_channel"],
            "epoch": record["epoch"],
            "scope": record["scope"],
            "status": status,
            "rungs_attained": rungs,
            "support_role": "archaeology" if archaeology else "support-target",
            "runtime_compatible": bool(record.get("runtime_compatible")),
            "reason": record["reason"],
            "evidence": evidence,
            "evidence_by_rung": evidence_by_rung,
            "not_attained": not_attained,
        })

    records.sort(key=lambda r: r["subject_id"])

    by_status: dict[str, int] = {}
    by_rung: dict[str, int] = {}
    by_role: dict[str, int] = {}
    by_scope: dict[str, int] = {}
    for r in records:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_role[r["support_role"]] = by_role.get(r["support_role"], 0) + 1
        by_scope[r["scope"]] = by_scope.get(r["scope"], 0) + 1
        for rung in r["rungs_attained"]:
            by_rung[rung] = by_rung.get(rung, 0) + 1

    counts = {
        "nodes": len(records),
        "by_status": {k: by_status[k] for k in sorted(by_status)},
        "by_rung": {k: by_rung[k] for k in sorted(by_rung)},
        "by_support_role": {k: by_role[k] for k in sorted(by_role)},
        "by_scope": {k: by_scope[k] for k in sorted(by_scope)},
        "support_targets": by_role.get("support-target", 0),
        "archaeology": by_role.get("archaeology", 0),
        "runtime_compatible": sum(1 for r in records if r["runtime_compatible"]),
    }

    body = {
        "rule": (
            "one support-status row per release-catalogue node, read from the 23.10 historical "
            "population and the evidence planes it is derived from, never typed. `status` is the "
            "highest rung of multitrack_schemas.SUPPORT_LADDER an evidence plane reached, "
            "`rungs_attained` names every rung reached with the artefact that backs it in "
            "`evidence_by_rung`, and every rung not reached carries its reason in `not_attained`. A "
            "node outside the public final-release lineage or whose official source cannot be "
            "admitted is `archaeological-only` with no rung, and `support_role` records that as "
            "archaeology rather than a support target. The statuses are release/authority states and "
            "are not the stratum's parity dimensions: no row is a compatibility claim"
        ),
        "scope": (
            "every node of forensics/release-catalog.json, reconciled node-for-node and rung-for-rung "
            "with the 23.10 historical population. The ladder's subject is the public mainline "
            "final-release lineage forward from OpenSSL 0.9.1c; a pre-release, an auxiliary branch or "
            "a release whose official source cannot be admitted is recorded archaeological-only "
            "rather than omitted"
        ),
        "ladder": list(mts.SUPPORT_LADDER),
        "core_rungs": list(mts.SUPPORT_CORE),
        "records": records,
        "counts": counts,
        "content_hash": body_hash(records),
        "boundary": (
            "the ladder records how far each release node reached, not how compatible anything is: "
            "`support_role` is ladder bookkeeping (`support-target` or `archaeology`) and is not a "
            "compatibility verdict, and no row is a `PARITY_VERIFIED` or any other one-boolean "
            "compatibility claim. The core rungs catalogued, admitted-source, built-authority and "
            "atlas-complete are the contiguous climb every supported node makes; candidate-view, "
            "runtime-evidenced, downstream-evidenced and maintained are each read from an "
            "independent evidence plane (23.10), so a node may attain them without the intermediate "
            "additive rungs -- 0.9.8zh is downstream-evidenced from a real consumer without "
            "candidate-view/runtime-evidenced. A status is derived from the evidence and never "
            "typed, and an archaeological-only node has climbed no rung"
        ),
    }
    return body


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    body = derive_body()

    for record in body["records"]:
        problems = mts.validate_support_status(record)
        if problems:
            raise SystemExit(f"support-status: derived row {record['subject_id']} is not "
                             f"schema-valid: {problems}")

    inputs = [
        InputRef(name="historical-population", path=hp.OUT),
        InputRef(name="release-catalog", path=hp.CATALOG),
        InputRef(name="authority-nodes", path=hp.AUTHORITY_NODES),
        InputRef(name="authority-registry", path=hp.AUTHORITIES),
        InputRef(name="build-records", path=hp.BUILD_RECORDS),
        InputRef(name="historical-acquisition", path=hp.HIST_ACQ),
        InputRef(name="historical-build-receipts", path=hp.HIST_RECEIPTS),
        InputRef(name="compatibility-views", path=hp.COMPAT_VIEWS),
        InputRef(name="semantic-courts", path=hp.SEMANTIC_COURTS),
        InputRef(name="downstream-multitrack", path=hp.DOWNSTREAM),
        InputRef(name="default-authority", path=hp.DEFAULT_AUTHORITY),
    ]
    doc = envelope(kind="support-status", authority=auth.id, inputs=inputs, body=body,
                   generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[support-status] {c['nodes']} node(s); status={c['by_status']}; "
          f"role={c['by_support_role']} runtime_compatible={c['runtime_compatible']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
