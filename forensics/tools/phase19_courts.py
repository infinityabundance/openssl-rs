#!/usr/bin/env python3
"""openssl-rs — Phase 19 courts: the performance / CPU dispatch courts.

Each court is an instrument over the finished implementation, not a differential probe over a
symbol set. This stratum owns no exported symbol: it measures the library the strata before it
completed, so its evidence is about *dispatch behaviour* and *deterministic work* — how the
candidate reports CPU capabilities and selects implementations, and how much work its primitive
paths perform — rather than a count of names. The method is Phases 3 through 18's where a
differential control is possible: the authority and the candidate are driven over the same
capability set or the same input and their observations compared, so the expectation cannot drift.
Where the subject is the *instrument's* sensitivity — can the work measure tell a deliberately
slowed path from a fast one — the court is candidate-only and carries a sensitivity control instead
(D13, D201), exactly as Phase 8's `CT-*` courts and Phase 18's `CT-PRIMITIVES` do.

The pending courts
------------------
None of the five courts the plan names is runnable at activation. This stratum owns no exported
symbol, so no differential probe over a symbol set is its evidence; its first runnable court is a
later subphase's, and `COURTS` is therefore empty while `PENDING_COURTS` names each court with the
subphase that lands its instrument:

  * `RT-CPU-CAPABILITY` (19.1) — the CPU-capability dispatch audit: how the candidate's
    CPU-capability surface (`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`)
    reports under a fixed and faulted CPUID facade, against the admitted authority, with an
    authority-linked differential control;
  * `RT-EVP-DISPATCH` (19.2) — the EVP / cipher dispatch comparison: which implementation a fetch
    or a cipher context selects for a given capability set, driven on both sides over the same set,
    with an authority-linked differential control;
  * `RT-PERFORMANCE-WORK` (19.3) — deterministic operation and block counts over the
    primitive-bearing paths (not wall-clock-only), driven on the authority and the candidate over
    the same inputs, recording every path whose work differs as a finding;
  * `RT-PERFORMANCE-SENSITIVITY` (19.4) — the instrument-sensitivity control: a deliberately slowed
    path must be caught, so a measure that cannot tell a slow path from a fast one is `fail`
    rather than `pass`; candidate-only;
  * `PERFORMANCE-BOUNDARY-REGISTER` (19.5) — the register that records what is measured, what is
    not, and the explicit non-claims (no benchmark-parity claim, no assembly-versus-Rust
    equivalence claim), and that fails the stratum if a recorded boundary drifts from its evidence.

There is no benchmark-parity claim and no assembly-versus-Rust equivalence claim anywhere in this
stratum, and no verdict is ever taken from wall-clock time alone.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-19-SUBPHASES.md` section 4.2 is the precondition. No court is
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

OUT = REPO_ROOT / "artifacts" / "phase19" / "COURTS.json"
GENERATOR = "forensics/tools/phase19_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-19-SUBPHASES.md"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. **Empty at activation**: this stratum owns no symbol for a differential probe to
# observe, so its first runnable instrument is a later subphase's.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-CPU-CAPABILITY": (
        "19.1 lands the capability-set driver; it drives the CPU-capability surface "
        "(`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`) under a fixed and "
        "faulted CPUID facade against the authority, with an authority-linked differential control"
    ),
    "RT-EVP-DISPATCH": (
        "19.2 lands the selection comparison; it drives which implementation a fetch or cipher "
        "context selects for a given capability set on both sides, with an authority-linked "
        "differential control"
    ),
    "RT-PERFORMANCE-WORK": (
        "19.3 lands the deterministic work court; it counts operations and blocks over the "
        "primitive-bearing paths (not wall-clock-only) on both sides and records every path whose "
        "work differs as a finding"
    ),
    "RT-PERFORMANCE-SENSITIVITY": (
        "19.4 lands the sensitivity control; it requires a deliberately slowed path to be caught, "
        "so the work measure is proven able to tell a slow path from a fast one"
    ),
    "PERFORMANCE-BOUNDARY-REGISTER": (
        "19.5 lands the register; it records what is measured, what is not, and the explicit "
        "non-claims (no benchmark-parity claim, no assembly-versus-Rust equivalence claim), and "
        "checks that every recorded boundary still matches the evidence that establishes it"
    ),
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase19"
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
            "Phase 19's five courts are named and `pending`; none is registered as passing at "
            "activation. `RT-CPU-CAPABILITY` is 19.1's: a CPU-capability dispatch audit that "
            "drives the candidate's capability surface under a fixed and faulted CPUID facade "
            "against the authority, with an authority-linked differential control. "
            "`RT-EVP-DISPATCH` is 19.2's: an EVP / cipher dispatch comparison of which "
            "implementation is selected for a given capability set, on both sides. "
            "`RT-PERFORMANCE-WORK` is 19.3's: deterministic operation and block counts over the "
            "primitive-bearing paths (not wall-clock-only) on both sides, recording every path "
            "whose work differs as a finding. `RT-PERFORMANCE-SENSITIVITY` is 19.4's: the "
            "instrument-sensitivity control, candidate-only, which requires a deliberately slowed "
            "path to be caught. `PERFORMANCE-BOUNDARY-REGISTER` is 19.5's: the register of what is "
            "measured, what is not, and the explicit non-claims. This stratum owns no exported "
            "symbol, so no differential probe over a symbol set is its evidence: the subject is "
            "dispatch behaviour and deterministic work over a finished implementation, with no "
            "benchmark-parity claim and no assembly-versus-Rust equivalence claim. "
            "docs/PHASE-19-SUBPHASES.md sections 1, 3 and 4 record the measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-19-plan", path=PLAN),
    ]
    doc = envelope(kind="phase19-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
