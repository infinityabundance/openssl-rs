#!/usr/bin/env python3
"""openssl-rs — the Phase 22 obligation ledger, and its unit is a *plane*, not an export.

Phase 22 is the authority-exhaustiveness stratum (`docs/PHASE-22-SUBPHASES.md`). It owns no
`libcrypto` export: it adds no code to the crate, and a ledger that counted symbols would count
zero while the stratum was doing the most important work in the repository. What Phase 22 owes is a
set of **compatibility planes** — one extraction or reconciliation instrument per subphase, each
landing a named, content-addressed artefact.

This file is a *projection*, and every plane's state is derived from whether the artefact it names
exists on disk. Nothing here is typed status:

  * **implemented** — the plane's artefact exists.
  * **open** — it does not. This is the only list that blocks the stratum.
  * **deferred** — a plane whose extraction this stratum cannot perform for a stated reason, handed
    to a later phase. Empty at 22.0, and it must say *why* if it ever stops being empty.

`counts.open_in_this_stratum` is therefore a count of *unclassified surfaces*' instruments rather
than of unbuilt exports, which is the one place this ledger's arithmetic and every other stratum's
differ. `forensics/tools/phase_state.py` reads it the same way; `forensics/STATUS.md` renders it the
same way; and `forensics/tools/regression_guard.py` watches it non-increasing the same way, because
"the atlas stopped losing ground" is a claim worth guarding whatever the unit is.

Why the unit is a plane rather than a symbol
--------------------------------------------
A symbol is a compatibility surface. A plane is an *instrument that finds compatibility surfaces*.
Phase 22's risk is not that it fails to build something; it is that an instrument silently misses a
class of surface. That is why each plane's artefact is paired with an FRF sensitivity challenge in
22.15 (`docs/PHASE-22-SUBPHASES.md` section 6): a plane whose instrument cannot detect its own
defect class is not implemented, however green its output looks.

Outputs
-------
  forensics/phase22-obligations.json

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

GENERATOR = "forensics/tools/phase22_obligations.py"
OUT = REPO_ROOT / "forensics" / "phase22-obligations.json"

PLAN = "docs/PHASE-22-SUBPHASES.md"

# (subphase, the artefact whose existence is the plane's completion, what the plane is).
#
# The artefact path is the unit of completion, and it is a *file* rather than a boolean for the
# reason every other ledger in this repository derives its state: a boolean is a thing somebody has
# to remember to flip, and `D-DECODER-ABSENT-1` is the record of what that costs. A plane whose
# extractor has run leaves its artefact behind, and the artefact is content-addressed by the
# envelope's own inputs.
PLANES: list[tuple[str, str, str]] = [
    ("22.0", PLAN,
     "The plan, the dependency edge and the frozen Phase-11 baseline"),
    ("22.1", "forensics/atlas/phase22/compile-commands.json",
     "The exact build-command capture and the normalized compilation database"),
    ("22.2", "forensics/atlas/phase22/doxygen-entities.json",
     "The pinned Doxygen corpus and its entity graph"),
    ("22.3", "forensics/atlas/phase22/tu-ast.json",
     "Every active translation unit's Clang AST and the declaration/definition graph"),
    ("22.4", "forensics/atlas/phase22/conditional-surface.json",
     "The preprocessor and conditional-compilation graph"),
    ("22.5", "forensics/atlas/phase22/generated-lineage.json",
     "The generated-source and build genealogy"),
    ("22.6", "forensics/atlas/phase22/binary-reference-graph.json",
     "The object, archive, DSO and provider-module symbol and relocation graph"),
    ("22.7", "forensics/atlas/phase22/dispatch-graph.json",
     "The indirect dispatch, callback and registration graph"),
    ("22.8", "forensics/atlas/phase22/install-manifest.json",
     "The installed-distribution manifest"),
    ("22.9", "forensics/atlas/phase22/cli-surface.json",
     "The CLI grammar, aliases and digest/cipher pseudo-command surface"),
    ("22.10", "forensics/atlas/phase22/config-surface.json",
     "The configuration, environment and default-path surface"),
    ("22.11", "forensics/atlas/phase22/pod-contract.json",
     "The canonical POD contract oracle and the POD-runtime differential"),
    ("22.12", "forensics/atlas/phase22/reconciliation.json",
     "The cross-plane reconciliation"),
    ("22.13", "forensics/atlas/phase22/test-crosswalk.json",
     "The test, demo and fuzz semantic crosswalk"),
    ("22.14", "forensics/atlas/phase22/compatibility-closure.json",
     "The external-root reachability closure"),
    ("22.15", "forensics/atlas/phase22/frf-challenges.json",
     "The FRF challenges and the FRF-Fuzz sensitivity campaigns"),
    ("22.16", "forensics/atlas/phase22/gemel-checkpoint.json",
     "The Gemel checkpoint and the regenerated phase ledgers"),
    ("22.17", "docs/PHASE-22-ATLAS-SEAL.md",
     "The Phase-22 seal"),
]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)

    implemented: list[dict] = []
    open_rows: list[dict] = []
    for subphase, artefact, what in PLANES:
        row = {"subphase": subphase, "artefact": artefact, "plane": what}
        (implemented if (REPO_ROOT / artefact).exists() else open_rows).append(row)

    body = {
        "rule": (
            "the stratum's working set is its compatibility planes, one per subphase of "
            "docs/PHASE-22-SUBPHASES.md, and a plane is implemented when the artefact it names "
            "exists on disk; this stratum owns no export, so its unit is a plane rather than a "
            "symbol"
        ),
        "unit": "compatibility plane",
        "counts": {
            "atlas_owned": len(PLANES),
            "received_by_handoff": 0,
            "owned": len(PLANES),
            "implemented": len(implemented),
            "deferred_to_later_phase": 0,
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": [r["subphase"] for r in implemented],
        "open": open_rows,
        "deferred": [],
        "note": (
            "`open` is the only list that blocks this stratum, and its count is a count of "
            "instruments not yet built rather than of exports not yet written. The Phase-22 seal "
            "additionally requires that no UNKNOWN residual intersects a declared compatibility "
            "root (docs/PHASE-22-SUBPHASES.md sections 4 and 7); that condition is read from "
            "`forensics/atlas/phase22/compatibility-closure.json` once 22.14 lands it, not from "
            "this file. Nothing here is a parity claim: a landed plane says an instrument ran and "
            "left an artefact, never that the artefact is complete -- 22.15's FRF challenges are "
            "what tests that, and a failed challenge is a finding."
        ),
    }

    doc = envelope(
        kind="phase22-obligations",
        authority=auth.id,
        inputs=[InputRef(name="phase-22-plan", path=REPO_ROOT / PLAN)],
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT, doc)
    print(f"[phase22-obligations] {body['counts']['implemented']}/{body['counts']['owned']} "
          f"planes implemented, {len(open_rows)} open -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
