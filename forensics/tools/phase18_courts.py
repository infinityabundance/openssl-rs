#!/usr/bin/env python3
"""openssl-rs — Phase 18 courts: the hostile fuzz / security / side-channel hardening courts.

Each court is an instrument over the finished implementation, not a differential probe over a
symbol set. This stratum owns no exported symbol: it hardens the library the sixteen strata
before it completed, so its evidence is a *hostile* one — a malformed-input corpus driven against
the candidate with crash/OOM/timeout detection and an authority-linked control, a
secret-independence check over the primitive-bearing paths with a sensitivity control, and a
resource-exhaustion court over the reduced engine's fixed buffers — rather than a count of names.
The method is Phases 3 through 17's where a differential control is possible: the authority and
the candidate are driven over the same corpus and their observations compared, so the expectation
cannot drift. Where the subject is a `CT-*` secret-independence property the court is
candidate-only and carries a sensitivity control instead (D13, D201), exactly as Phase 8's
`CT-*` courts do.

The pending courts
------------------
None of the five courts the plan names is runnable at activation. This stratum owns no exported
symbol, so no differential probe over a symbol set is its evidence; its first runnable court is a
later subphase's, and `COURTS` is therefore empty while `PENDING_COURTS` names each court with the
subphase that lands its instrument:

  * `RT-HOSTILE-TLS` (18.1) — a hostile TLS corpus of malformed records, handshake messages and
    extension bodies, driven through the record layer and the TLS 1.3 flight, with
    crash/OOM/timeout detection and an authority-linked differential control;
  * `RT-HOSTILE-X509` (18.2) — a hostile X.509 / malformed-input corpus: certificates, extensions
    and DER/PEM containers with truncated, oversized and ill-formed encodings, with an
    authority-linked differential control;
  * `CT-PRIMITIVES` (18.3) — secret-independence checks for the primitive-bearing paths (BN, RSA,
    EC, the AEADs and the TLS key schedule), with a sensitivity control that a deliberate
    branch-on-secret is caught;
  * `RT-MEM-HARDENING` (18.4) — memory-safety and resource-exhaustion hardening for the reduced
    engine's fixed buffers and its allocation-failure paths, with an injected-failure control;
  * `HOSTILE-BOUNDARY-REGISTER` (18.5) — the register that records what is hardened, what is
    measured and what is explicitly not claimed, and that fails the stratum if a recorded
    boundary drifts from its evidence.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-18-SUBPHASES.md` section 4.2 is the precondition. No court
is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

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

OUT = REPO_ROOT / "artifacts" / "phase18" / "COURTS.json"
GENERATOR = "forensics/tools/phase18_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-18-SUBPHASES.md"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. **Empty at activation**: this stratum owns no symbol for a differential probe to
# observe, so its first runnable instrument is a later subphase's.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance
# rather than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-HOSTILE-TLS": (
        "18.1 lands the corpus and its driver; it drives malformed records, handshake messages "
        "and extension bodies through the record layer and the TLS 1.3 flight with "
        "crash/OOM/timeout detection and an authority-linked differential control"
    ),
    "RT-HOSTILE-X509": (
        "18.2 lands the corpus; it drives truncated, oversized and ill-formed certificates, "
        "extensions and DER/PEM containers with an authority-linked differential control"
    ),
    "CT-PRIMITIVES": (
        "18.3 lands the check; it measures secret-independence over the primitive-bearing paths "
        "(BN, RSA, EC, the AEADs and the TLS key schedule) and carries a sensitivity control"
    ),
    "RT-MEM-HARDENING": (
        "18.4 lands the court; it exercises the reduced engine's fixed buffers and its "
        "allocation-failure paths, with an injected-failure control"
    ),
    "HOSTILE-BOUNDARY-REGISTER": (
        "18.5 lands the register; it checks that every recorded hardened/measured/not-claimed "
        "boundary still matches the evidence that establishes it"
    ),
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase18"
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
            "Phase 18's five courts are named and `pending`; none is registered as passing at "
            "activation. `RT-HOSTILE-TLS` is 18.1's: a hostile corpus of malformed records, "
            "handshake messages and extension bodies, driven through the record layer and the "
            "TLS 1.3 flight with crash/OOM/timeout detection and an authority-linked differential "
            "control. `RT-HOSTILE-X509` is 18.2's: a hostile X.509 / malformed-input corpus of "
            "truncated, oversized and ill-formed certificates, extensions and DER/PEM containers, "
            "with an authority-linked differential control. `CT-PRIMITIVES` is 18.3's: "
            "secret-independence checks over the primitive-bearing paths (BN, RSA, EC, the AEADs "
            "and the TLS key schedule), with a sensitivity control that a deliberate "
            "branch-on-secret is caught. `RT-MEM-HARDENING` is 18.4's: memory-safety and "
            "resource-exhaustion hardening for the reduced engine's fixed buffers and its "
            "allocation-failure paths, with an injected-failure control. "
            "`HOSTILE-BOUNDARY-REGISTER` is 18.5's: the register of what is hardened, what is "
            "measured and what is explicitly not claimed. This stratum owns no exported symbol, "
            "so no differential probe over a symbol set is its evidence: the subject is a hostile "
            "input against a finished implementation. docs/PHASE-18-SUBPHASES.md sections 1, 3 "
            "and 4 record the measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-18-plan", path=PLAN),
    ]
    doc = envelope(kind="phase18-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<26} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
