#!/usr/bin/env python3
"""openssl-rs — Phase 16 courts: the CLI / config / filesystem contract.

Each court would be a C probe in `courts/phase16/` compiled **twice** — once against the
admitted authority, once against the candidate distribution shell — and run, the two transcripts
compared line by line as every differential court from Phase 3 on does. **This stratum registers
none yet**, and the emptiness is a measurement rather than an omission.

Why the registry is empty
-------------------------
Phase 16 owns no exported symbol (`forensics/atlas/symbol-ownership.json` assigns it zero rows),
so there is no symbol set for a coverage-reference probe to take addresses from, and its
obligations — 39 legacy provider registration rows and six prerequisite deferrals — are not
exports any differential probe over a symbol set can observe. This stratum's behavioural courts
land with the subphases that build the things they drive, and each is named in `PENDING_COURTS`
with the artefact it needs. Registering a court here that has no probe would make `run_courts.py`
fail on a missing file rather than record the real state, so none is registered.

Why a runner exists at all
--------------------------
`run_courts.py` refuses a stratum that is not `not-started` and has no runner. Phase 16 is
`in-progress` from 16.0, so it must carry one; this file writes the empty registry that says so,
and `docs/PHASE-16-SUBPHASES.md` section 4.2 is the precondition.

The pending courts, and what each awaits
----------------------------------------
  * `RT-LEGACY-MODULE` — the 39 `providers/legacyprov.c` rows (16.1).
  * `RT-ENGINE-DYN` — `engine_load_dynamic_int` and the `dynamic`/`rdrand` built-ins (16.2).
  * `RT-DEFAULTS` — the `OPENSSLDIR` directory plane and the install context (16.3).
  * `RT-CLI`, `RT-CONFIG` — the `openssl` CLI and config loading, and the regenerated Phase-1
    capture (16.4).
  * `RT-STATEM-REMAINDER` — `ssl/statem/statem_clnt.c` and `statem_srvr.c` (16.5).

None is declared in `gen_frf_courts.py`: that registry is the stratum's seal, and a court with no
probe cannot carry a declaration.

SPDX-License-Identifier: Apache-2.0"""

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

OUT = REPO_ROOT / "artifacts" / "phase16" / "COURTS.json"
GENERATOR = "forensics/tools/phase16_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase16"

# The differential courts, in the order they land. `(name, probe filename)`. **Empty, and here
# that is a measurement**: this stratum's obligations are not exports, so it has no courted
# surface until a subphase lands one, and each is recorded in `PENDING_COURTS` below rather than
# registered before its probe exists.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that
# lands the probe and what the court will drive, so "nothing registered" is a stated distance
# rather than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-LEGACY-MODULE": "16.1: the 39 providers/legacyprov.c registration rows and the "
                        "ossl-modules/legacy.so loadable-module contract",
    "RT-ENGINE-DYN": "16.2: engine_load_dynamic_int and the dynamic/rdrand built-ins, through "
                     "DSO_load and OPENSSL_ENGINES",
    "RT-DEFAULTS": "16.3: the OPENSSLDIR directory plane and the install context",
    "RT-CLI": "16.4: the openssl CLI command dispatch and its option grammar",
    "RT-CONFIG": "16.4: config loading and the regenerated Phase-1 CLI capture",
    "RT-STATEM-REMAINDER": "16.5: the ssl/statem/statem_clnt.c and statem_srvr.c message layer",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    records: list[dict] = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        # No court is registered yet; a registered one lands with its probe and its runner arm
        # in the same commit, so this branch is the mechanism kept true rather than a claim.
        records.append({"court": name, "verdict": "fail", "stage": "not-implemented"})

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "This stratum owns no exported symbol, so it registers no coverage-reference probe: "
            "there is no symbol set to take addresses from, and the coverage atlas records "
            "nothing for it. Its obligations are 39 legacy provider registration rows and six "
            "prerequisite deferrals, which are not exports a differential probe over a symbol "
            "set can observe. Every behavioural court the plan names -- `RT-LEGACY-MODULE`, "
            "`RT-ENGINE-DYN`, `RT-DEFAULTS`, `RT-CLI`, `RT-CONFIG`, `RT-STATEM-REMAINDER` -- is "
            "named in `pending_courts` with the subphase that lands it, so this registry is "
            "empty by measurement and not by omission. docs/PHASE-16-SUBPHASES.md sections 3 and "
            "4 record what each court will compare and the precondition this runner satisfies."
        ),
    }

    inputs = [
        InputRef(name="phase-16-plan", path=REPO_ROOT / "docs" / "PHASE-16-SUBPHASES.md"),
        InputRef(name="phase16-obligations",
                 path=REPO_ROOT / "forensics" / "phase16-obligations.json"),
    ]
    doc = envelope(kind="phase16-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<18} pass")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<18} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
