#!/usr/bin/env python3
"""openssl-rs — Phase 21 courts: the maintenance delta machinery courts.

Each court is an instrument that makes the delta procedure of `docs/RELEASE_GATES.md` section 8
mechanical over two authorities that are already admitted, not a differential probe over a symbol
set. This stratum owns no exported symbol: it re-measures the implementation the strata before it
completed, so its evidence is about *the delta* — the identity and profile of the two authorities,
the added / removed / changed obligations between them across the atlas planes, the disposition of
every delta row, the courts the delta reaches, and what the stratum explicitly does not claim. The
method is Phases 3 through 20's where an artefact carries the expectation: each court reads the
artefact that holds its subject rather than typing the expectation beside it, so the two cannot
disagree, and a court whose control is not honest is `fail` rather than `pass`.

The pending courts
------------------
None of the five courts the plan names is runnable at activation. This stratum owns no exported
symbol, so no differential probe over a symbol set is its evidence; its first runnable court is a
later subphase's, and `COURTS` is therefore empty while `PENDING_COURTS` names each court with the
subphase that lands its instrument:

  * `RT-AUTHORITY-ADMISSION` (21.1) — the admission / identification of a new authority and the
    record of its identity and profile as the delta input pair, exercised on the already-admitted
    `openssl-3.6.3-historical` versus `openssl-3.6.4-production`;
  * `RT-ATLAS-DELTA` (21.2) — the added / removed / changed obligation delta between the two
    authorities across the atlas planes (exports, provider rows, prerequisite units), computed
    mechanically from committed artefacts;
  * `RT-DELTA-DISPOSITION` (21.3) — the disposition of every delta row (`implemented` / `deferred`
    / `not-in-profile` / `boundary`), requiring zero unexplained, so a newly discovered
    un-dispositioned delta row is a `fail` rather than a silent addition;
  * `RT-AFFECTED-COURT-SELECTION` (21.4) — the derivation of which courts a delta touches, recorded
    with the selection derivation, so the selected courts are re-run or re-derived;
  * `MAINTENANCE-BOUNDARY-REGISTER` (21.5) — the register that records the explicit non-claims
    (OpenSSL 4.x is a new compatibility profile, a 3.x receipt is never silently reinterpreted as
    evidence for 4, only the exercised delta is claimed, unknown stays unknown), and that fails the
    stratum if a recorded boundary drifts from its evidence.

There is no version-universality claim anywhere in this stratum; a passing court is an instrument
and a bounded measurement of the movement between the two authorities it names, and the property it
names may still carry findings. `docs/NON_CLAIMS.md` and `docs/SECURITY_DIVERGENCE_POLICY.md` are
the authorities on the explicit non-claims and on the fixed direction of the trajectory.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-21-SUBPHASES.md` section 4.2 is the precondition. No court is
registered in `gen_frf_courts.py`: that registry is the stratum's seal.

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

OUT = REPO_ROOT / "artifacts" / "phase21" / "COURTS.json"
GENERATOR = "forensics/tools/phase21_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-21-SUBPHASES.md"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. **Empty at activation**: this stratum owns no symbol for a differential probe to
# observe, so its first runnable instrument is a later subphase's.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-AUTHORITY-ADMISSION": (
        "21.1 lands the authority admission; it reads "
        "`forensics/authorities/AUTHORITIES.json` and the two `SOURCE_MANIFEST.{3.6.3,3.6.4}.json` "
        "files and records the delta's input pair — the identity and profile of "
        "`openssl-3.6.3-historical` and `openssl-3.6.4-production` — rather than typing a version, "
        "a checksum or a root hash"
    ),
    "RT-ATLAS-DELTA": (
        "21.2 lands the atlas delta; it computes the added / removed / changed obligations between "
        "the two authorities across the atlas planes the procedure names — exports, provider "
        "registration rows and prerequisite units — from the committed differential and the "
        "per-authority atlases, never hand-listed, and names a plane it cannot yet compare "
        "`not-measured` rather than counting it as motionless"
    ),
    "RT-DELTA-DISPOSITION": (
        "21.3 lands the delta disposition; it requires every delta row to be dispositioned "
        "(`implemented` / `deferred` / `not-in-profile` / `boundary`) with zero unexplained, so a "
        "newly discovered un-dispositioned delta row is a `fail`. A row whose disposition would "
        "re-adopt a historical behaviour against a security fix is a finding, not a disposition"
    ),
    "RT-AFFECTED-COURT-SELECTION": (
        "21.4 lands the affected-court selection; it derives which courts a delta touches, records "
        "the selection derivation, and re-runs or re-derives exactly those courts, so a delta "
        "reaches the courts its obligations do and no more"
    ),
    "MAINTENANCE-BOUNDARY-REGISTER": (
        "21.5 lands the register; it records the explicit non-claims — OpenSSL 4.x is a new "
        "compatibility profile and a 3.x receipt is never silently reinterpreted as evidence for "
        "4, only the exercised delta is claimed, and unknown stays unknown — and checks that every "
        "recorded boundary still matches the evidence that establishes it"
    ),
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase21"
    work.mkdir(parents=True, exist_ok=True)

    # No court is runnable at activation, so the registry is empty and every planned court is
    # `pending`. The runner still has to exist and write this file: `run_courts.py` refuses a
    # stratum in `in-progress` with no runner, and a committed courts file no run reproduces.
    records: list[dict] = []

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": len(records) - passed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "Phase 21's five courts are named and `pending`; none is registered as passing at "
            "activation. `RT-AUTHORITY-ADMISSION` is 21.1's: the admission / identification of a "
            "new authority and the record of its identity and profile as the delta input pair, "
            "exercised on the already-admitted `openssl-3.6.3-historical` versus "
            "`openssl-3.6.4-production`. `RT-ATLAS-DELTA` is 21.2's: the added / removed / changed "
            "obligation delta between the two authorities across the atlas planes (exports, "
            "provider rows, prerequisite units), computed mechanically from committed artefacts. "
            "`RT-DELTA-DISPOSITION` is 21.3's: the disposition of every delta row with zero "
            "unexplained. `RT-AFFECTED-COURT-SELECTION` is 21.4's: the derivation of which courts "
            "a delta touches, recorded with the selection derivation. `MAINTENANCE-BOUNDARY-"
            "REGISTER` is 21.5's: the register of the explicit non-claims. This stratum owns no "
            "exported symbol, so no differential probe over a symbol set is its evidence: the "
            "subject is the delta between two admitted authorities, with no version-universality "
            "claim — OpenSSL 4.x is a new compatibility profile and a 3.x receipt is never "
            "silently reinterpreted as evidence for 4 — only the exercised delta claimed, and "
            "unknown left unknown. A 3.6.3 behaviour that corresponds to an upstream security fix "
            "is not reintroduced. docs/PHASE-21-SUBPHASES.md sections 1, 3 and 4 record the "
            "measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-21-plan", path=PLAN),
    ]
    doc = envelope(kind="phase21-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
