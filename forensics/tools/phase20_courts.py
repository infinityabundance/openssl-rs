#!/usr/bin/env python3
"""openssl-rs — Phase 20 courts: the 3.6.4 custodian seal courts.

Each court is an instrument that compiles the custodian claim over the finished implementation,
not a differential probe over a symbol set. This stratum owns no exported symbol: it measures the
library the strata before it completed, so its evidence is about *the claim* -- the maturity level
the committed evidence supports, whether every closed obligation joins to an FRF receipt and the
store compiles the parity claim with zero blockers, whether every residual is dispositioned with no
`UNKNOWN` intersecting the claimed production profile, whether an authority-built binary runs
unmodified against the candidate over the machine-owned downstream corpus, and what the stratum
explicitly does not claim. The method is Phases 3 through 19's where an artefact carries the
expectation: each court reads the artefact that holds its subject rather than typing the expectation
beside it, so the two cannot disagree, and a court whose control is not honest is `fail` rather than
`pass`.

The pending courts
------------------
None of the five courts the plan names is runnable at activation. This stratum owns no exported
symbol, so no differential probe over a symbol set is its evidence; its first runnable court is a
later subphase's, and `COURTS` is therefore empty while `PENDING_COURTS` names each court with the
subphase that lands its instrument:

  * `RT-CUSTODIAN-MATURITY` (20.1) — the derivation of the L0-L9 maturity ladder of
    `docs/RELEASE_GATES.md` section 3 for `libcrypto` and `libssl` from committed evidence, naming
    only a level whose evidence is present and recording the gap as a finding when the evidence
    supports less than the level the seal might claim;
  * `RT-RECEIPT-CLOSURE` (20.2) — the join of every obligation recorded `implemented` or closed to
    its FRF receipt, and the FRF store's compiled parity claim with zero blockers;
  * `RT-CUSTODIAN-RESIDUALS` (20.3) — the disposition of every residual, requiring zero `UNKNOWN`
    intersecting the claimed production profile, so a newly discovered un-dispositioned residual is
    a `fail` rather than a silent addition;
  * `RT-SUBSTITUTION-WITNESS` (20.4) — the ABI-substitution witness chain and the machine-owned
    downstream corpus witness chain: binaries built against the admitted authority run unmodified
    against the candidate, over the Phase-17 corpus the court re-establishes as current and
    functional;
  * `CUSTODIAN-BOUNDARY-REGISTER` (20.5) — the register that records what is claimed, what is
    bounded, and the explicit non-claims (no FIPS validation, no universal parity from finite
    evidence, memory safety measured-not-established), and that fails the stratum if a recorded
    boundary drifts from its evidence.

There is no claim stronger than `docs/CUSTODIAN_CONTRACT.md` section 6's anywhere in this stratum; a
passing court is an instrument and a bounded measurement, and the property it names may still carry
findings. `docs/NON_CLAIMS.md` is the authority on the explicit non-claims.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-20-SUBPHASES.md` section 4.2 is the precondition. No court is
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

OUT = REPO_ROOT / "artifacts" / "phase20" / "COURTS.json"
GENERATOR = "forensics/tools/phase20_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-20-SUBPHASES.md"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. **Empty at activation**: this stratum owns no symbol for a differential probe to
# observe, so its first runnable instrument is a later subphase's.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-CUSTODIAN-MATURITY": (
        "20.1 lands the maturity derivation; it derives the L0-L9 ladder of "
        "`docs/RELEASE_GATES.md` section 3 for `libcrypto` and `libssl` from committed evidence, "
        "naming only a level whose evidence is present and recording the gap as a finding when the "
        "evidence supports less than the level the seal might claim"
    ),
    "RT-RECEIPT-CLOSURE": (
        "20.2 lands the receipt closure; it joins every obligation recorded `implemented` or "
        "closed to its FRF receipt and requires the FRF store's compiled parity claim to carry "
        "zero blockers"
    ),
    "RT-CUSTODIAN-RESIDUALS": (
        "20.3 lands the residual disposition; it requires every residual to be dispositioned and "
        "zero `UNKNOWN` to intersect the claimed production profile, so a newly discovered "
        "un-dispositioned residual is a `fail`"
    ),
    "RT-SUBSTITUTION-WITNESS": (
        "20.4 lands the substitution witness; it runs binaries built against the admitted "
        "authority unmodified against the candidate over the machine-owned Phase-17 downstream "
        "corpus, which it re-establishes as current and functional, and records each witness's "
        "build, run and observation"
    ),
    "CUSTODIAN-BOUNDARY-REGISTER": (
        "20.5 lands the register; it records what is claimed, what is bounded, and the explicit "
        "non-claims (no FIPS validation, no universal parity from finite evidence, memory safety "
        "measured-not-established), and checks that every recorded boundary still matches the "
        "evidence that establishes it"
    ),
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase20"
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
            "Phase 20's five courts are named and `pending`; none is registered as passing at "
            "activation. `RT-CUSTODIAN-MATURITY` is 20.1's: the derivation of the L0-L9 maturity "
            "ladder for `libcrypto` and `libssl` from committed evidence, naming only a level "
            "whose evidence is present. `RT-RECEIPT-CLOSURE` is 20.2's: the join of every "
            "obligation recorded `implemented` or closed to its FRF receipt, and the FRF store's "
            "compiled parity claim with zero blockers. `RT-CUSTODIAN-RESIDUALS` is 20.3's: the "
            "disposition of every residual, requiring zero `UNKNOWN` intersecting the claimed "
            "production profile. `RT-SUBSTITUTION-WITNESS` is 20.4's: the ABI-substitution witness "
            "chain and the machine-owned Phase-17 downstream corpus witness chain. "
            "`CUSTODIAN-BOUNDARY-REGISTER` is 20.5's: the register of what is claimed, what is "
            "bounded, and the explicit non-claims. This stratum owns no exported symbol, so no "
            "differential probe over a symbol set is its evidence: the subject is the custodian "
            "claim over a finished implementation, with no FIPS validation, no universal-parity "
            "claim from finite evidence and no claim that memory safety is established. "
            "docs/PHASE-20-SUBPHASES.md sections 1, 3 and 4 record the measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-20-plan", path=PLAN),
    ]
    doc = envelope(kind="phase20-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
