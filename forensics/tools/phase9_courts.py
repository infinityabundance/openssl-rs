#!/usr/bin/env python3
"""openssl-rs — Phase 9 courts: RAND, the DRBGs and the entropy sources.

Each court is a C probe in `courts/phase9/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-8's, for the same reason: a unit test encodes what its author believes
the contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

**This runner lands with no courts, and that is 9.0's shape rather than an omission.** A stratum
lands its ledger and its wiring in its first subphase and its first probe in the subphase that
gives it something to observe -- Phase 6 and Phase 8 both did exactly this, and Phase 8's own
`COURTS` comment records it. What a probe cannot do here is anything at all: every one of this
stratum's ninety-three exports is unimplemented, and calling a scaffold aborts the candidate. So
the runner is honest about the state instead of writing a court that observes nothing: the
`PENDING_COURTS` table below names each court the plan gives this stratum and the subphase that
brings it, and every name there is printed on each run. A court that is *not run yet* has to look
different from a court that passed, which is what Phase 8's `PENDING_CORRECTNESS_COURTS` exists
for and what this table inherits.

What a differential court can establish here, and what it cannot
----------------------------------------------------------------
A probe can compare, byte for byte: the parameters a DRBG reports, the refusal reason and
coordinate for every invalid-parameter arm, the state transitions (`EVP_RAND_STATE_ERROR` after a
failed instantiate, `_READY` after a successful one), the reseed-interval boundary, the observable
refusal of the prediction-resistance path, and -- with a `TEST-RAND` row and a fixed seed -- the
exact bytes both sides produce. It **cannot** establish that either side's output is
unpredictable, because that is a property of the seeding pool rather than of a transcript.
`docs/PHASE-9-SUBPHASES.md` section 3.3 records that as not courted rather than leaving it
implied; a court that compared pool *contents* would be comparing two machines.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
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

OUT = REPO_ROOT / "artifacts" / "phase9" / "COURTS.json"
GENERATOR = "forensics/tools/phase9_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase9"

# The differential courts, in the order they will land. `(name, probe filename)`, and the probe
# is declared in the same commit as the entry, so a runner that names a probe which does not
# exist cannot be committed -- the check below fails instead.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here
# can pass, and each is printed with the subphase that brings it so that "not run yet" cannot be
# read as "passed". This is the whole evidence state of the stratum until 9.1 lands.
PENDING_COURTS: dict[str, str] = {
    "RT-BN-RAND": "9.1 -- the BN random family against the authority, with a fixed seed source "
                  "on both sides. It cannot be written before the front exists, because the "
                  "authority's own `BN_rand` reaches it.",
    "RT-RAND": "9.2 -- `rand.h`'s twenty-five exports: the method table, the thread-local "
               "primary/public/private DRBGs, the file helpers, and the refusal arms.",
    "RT-DRBG": "9.3-9.4 -- the DRBG framework and the three instantiations, through the "
               "provider they are published by, including the parameter surface and the "
               "state machine.",
    "CT-DRBG": "9.4 -- the DRBGs' construction vectors, which the pinned tree already carries: "
               "`test/recipes/30-test_evp_data/evprand.txt` mirror the NIST CAVP "
               "`drbgtestvectors.zip` sets, with the URL written in the file, and "
               "`evpkdf_hmac_drbg.txt` carries the HMAC-DRBG KDF cases. No network fetch is "
               "needed and none is permitted (docs/AUTHORITY_POLICY.md)."
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase9"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        # A probe is added by the subphase that gives it something to observe; when the first one
        # lands, its runner goes in beside this block rather than into a second file, so the
        # pending table above shrinks by one in the same commit.
        raise SystemExit(
            f"phase9-courts: {name} names {rel(src)}, and this runner has no arm for it yet; "
            "9.1 adds both together"
        )

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "**Zero courts have landed.** `courts` is empty because every export this "
            "stratum owns is unimplemented and a probe that called one would abort the "
            "candidate, which is not an observation. `all_pass` is therefore true of an "
            "empty set and is NOT evidence that anything works; `pending_courts` names the "
            "four courts the plan gives this stratum and the subphase that brings each. A "
            "passing RT-* court, when one lands, will mean the candidate produced the same "
            "observable transcript as the authority for the behaviours that probe exercises "
            "-- differential compatibility, NOT that its output is unpredictable "
            "(docs/PARITY_MODEL.md, docs/PHASE-9-SUBPHASES.md section 3.3)."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase9-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<14} pass")
        else:
            print(f"  {r['court']:<14} FAIL   stage={r.get('stage', 'compare')}")
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<14} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
