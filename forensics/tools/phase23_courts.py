#!/usr/bin/env python3
"""openssl-rs — Phase 23 courts: the multitrack authority machinery courts.

Each court is an instrument that makes the multitrack authority model of
`docs/RELEASE_GATES.md` section 1 mechanical over releases and authorities that are already
admitted, not a differential probe over a symbol set. This stratum owns no exported symbol: it
emits independently-evidenced compatibility *views*, so its evidence is about the model -- the
release nodes and their chronology, the authority nodes and their builds, the lineage and entity
relations between releases, the delta between two nodes, the directional and dimension-specific
compatibility views and edges, the negative obligations, the security lineage, the support status
of each node, and the assembled matrix. The method is Phases 3 through 21's where an artefact
carries the expectation: each court reads the artefact that holds its subject rather than typing the
expectation beside it, so the two cannot disagree, and a court whose control is not honest is
`fail` rather than `pass`.

**No court is registered at activation.** The stratum's obligations are not exports, so its first
runnable court is a later subphase's, and `run_courts.py` would refuse a stratum in `in-progress`
with no runner at all -- so this runner lands with an empty registry and names the twelve courts it
will stage, each with the subphase that lands it. The registry is the file `run_courts.py` checks
is reproduced, so a court silently dropped is a finding rather than a smaller green run. This is
the reverse of Phase 16's edge: the ledger's contract-unit states are measured from this registry,
so this runner does **not** bind the obligations ledger as an input.

The record kinds these courts will populate are defined and self-tested in
`forensics/tools/multitrack_schemas.py`; the registry records that schema inventory so the record
kinds are a file the evidence points at rather than prose the plan would have to restate.

The twelve courts, and the subphase that lands each
---------------------------------------------------
  * `RT-RELEASE-NODES` -- 23.1, the release-node catalogue.
  * `RT-AUTHORITY-NODES` -- 23.2, the authority-node registry.
  * `RT-LINEAGE-EDGES` -- 23.3, the lineage edges.
  * `RT-ENTITY-LINEAGE` -- 23.4, the entity lineage.
  * `RT-DELTA-ENGINE` -- 23.5, the delta engine.
  * `RT-COMPATIBILITY-VIEWS` -- 23.6, the compatibility views.
  * `RT-COMPATIBILITY-EDGES` -- 23.7, the directional compatibility edges.
  * `RT-NEGATIVE-OBLIGATIONS` -- 23.8, the negative obligations.
  * `RT-SECURITY-LINEAGE` -- 23.9, the security lineage.
  * `RT-SUPPORT-STATUS` -- 23.10, the support-status ladder.
  * `RT-COMPATIBILITY-MATRIX` -- 23.11, the compatibility matrix.
  * `MULTITRACK-SEAL` -- 23.12, the full matrix, the FRF/Gemel chain and the seal.

Every one is `pending` at activation. A passing court is an instrument, not a property claim, and
this stratum makes no one-boolean compatibility claim anywhere: compatibility is directional and
dimension-specific, cross-version receipts are never inherited, and a historical vulnerability is
observed but never reintroduced.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 4.2 is the precondition.
No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

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
    envelope,
    rel,
    resolve_authority,
    write_json,
)

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import multitrack_schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase23" / "COURTS.json"
GENERATOR = "forensics/tools/phase23_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-23-MULTITRACK-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "multitrack_schemas.py"

# The courts this stratum will stage. **Empty at activation**: 23.0 owns no runnable court, so the
# registry carries none. Each later subphase appends its court here in the commit that lands its
# instrument, and a court removed from the table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = []

# The twelve courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order.
PENDING_COURTS: dict[str, str] = {
    "RT-RELEASE-NODES": "23.1 -- the release-node catalogue",
    "RT-AUTHORITY-NODES": "23.2 -- the authority-node registry",
    "RT-LINEAGE-EDGES": "23.3 -- the lineage edges",
    "RT-ENTITY-LINEAGE": "23.4 -- the entity lineage",
    "RT-DELTA-ENGINE": "23.5 -- the delta engine",
    "RT-COMPATIBILITY-VIEWS": "23.6 -- the compatibility views",
    "RT-COMPATIBILITY-EDGES": "23.7 -- the directional compatibility edges",
    "RT-NEGATIVE-OBLIGATIONS": "23.8 -- the negative obligations",
    "RT-SECURITY-LINEAGE": "23.9 -- the security lineage",
    "RT-SUPPORT-STATUS": "23.10 -- the support-status ladder",
    "RT-COMPATIBILITY-MATRIX": "23.11 -- the compatibility matrix",
    "MULTITRACK-SEAL": "23.12 -- the full matrix, the FRF/Gemel chain and the seal",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    records: list[dict] = []
    for name, filename in COURTS:
        # No court is registered at activation, so this loop is inert. It is kept so the first
        # subphase that appends a court stages it here rather than inventing the shape.
        src = REPO_ROOT / "courts" / "phase23" / str(filename)
        records.append({"court": name, "verdict": "fail", "stage": "probe-missing",
                        "detail": rel(src)})

    passed = sum(1 for r in records if r["verdict"] == "pass")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        "all_pass": failed == 0 and len(records) == len(COURTS),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": failed},
        "pending_courts": PENDING_COURTS,
        "schemas": multitrack_schemas.inventory(),
        "claim": (
            "No court is registered at activation: Phase 23 owns no exported symbol, so no "
            "differential probe over a symbol set is its evidence, and its twelve courts -- "
            "RT-RELEASE-NODES, RT-AUTHORITY-NODES, RT-LINEAGE-EDGES, RT-ENTITY-LINEAGE, "
            "RT-DELTA-ENGINE, RT-COMPATIBILITY-VIEWS, RT-COMPATIBILITY-EDGES, "
            "RT-NEGATIVE-OBLIGATIONS, RT-SECURITY-LINEAGE, RT-SUPPORT-STATUS, "
            "RT-COMPATIBILITY-MATRIX and MULTITRACK-SEAL -- are pending with the subphases that "
            "land them (23.1 through 23.12). The stratum's record kinds are defined and "
            "self-tested in forensics/tools/multitrack_schemas.py, whose inventory this registry "
            "records: the release nodes and their two version schemes (the pre-3.0 MNNFFPPS "
            "encoding and the 3.0-plus MAJOR.MINOR.PATCH form), the authority nodes, the lineage "
            "edges, the entity lineage, the compatibility views, the compatibility edges, the "
            "negative obligations, the security lineage, the support-status ladder and the "
            "assembled matrix. The one thing the model forbids everywhere is a single boolean: "
            "compatibility is directional and dimension-specific, a cross-version receipt is "
            "never inherited, an authority is named explicitly and singularly, and a historical "
            "vulnerability is observed but never reintroduced. docs/PHASE-23-MULTITRACK-SUBPHASES.md "
            "sections 1, 2 and 4 record the measurement and the precondition."
        ),
    }

    inputs = [
        InputRef(name="phase-23-plan", path=PLAN),
        InputRef(name="multitrack-schemas", path=SCHEMAS),
    ]
    doc = envelope(kind="phase23-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  schema inventory: {len(body['schemas'])} record kind(s)")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
