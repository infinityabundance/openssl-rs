#!/usr/bin/env python3
"""openssl-rs — Phase 17 courts: the downstream replacement court.

Each court is a C probe in `courts/phase17/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are compared
line by line, keyed on `key=value`, and every difference is a residual. The method is Phases 3
through 16's, for the same reason: a probe measures what the authority actually does, and the
comparison is between two *executions* of the same program, so the expectation cannot drift.

The pending courts
------------------
None of the four courts the plan names is runnable at activation. This stratum owns no exported
symbol, so no differential probe over a symbol set is its evidence; its first runnable court is a
later subphase's, and `COURTS` is therefore empty while `PENDING_COURTS` names each court with the
subphase that lands its probe:

  * `RT-CLI-BODIES` (17.1) — the 52 `apps/<name>.c` command bodies behind the
    `src/apps/openssl.rs` dispatcher and its generated `src/apps/tables.rs` option tables;
  * `RT-TLS13-INTEROP` (17.2) — a real TLS 1.3 client/server flight, ClientHello through Finished
    plus an application-data exchange, over the record layer, the extension units and the key
    schedule (D530's first entrance criterion);
  * `RT-CROSS-DSO-STATE` (17.3) — an error raised through the libssl path and read through the
    libcrypto path (and the same for `CONF`), requiring one queue across the candidate's whole-crate
    archives, where the authority shares one `libcrypto.so.3` via `DT_NEEDED` (D530's second);
  * `RT-DOWNSTREAM-CONSUMER` (17.4) — a real downstream consumer built against the candidate
    distribution shell the way an out-of-tree package links it.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-17-SUBPHASES.md` section 4.2 is the precondition. No court is
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

OUT = REPO_ROOT / "artifacts" / "phase17" / "COURTS.json"
GENERATOR = "forensics/tools/phase17_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-17-SUBPHASES.md"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed. **Empty at activation**: this stratum owns no symbol for a differential probe
# to observe, so its first runnable court is a later subphase's.
COURTS: list[tuple[str, str]] = []

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the probe and what the court will drive, so "nothing registered" is a stated distance rather than
# a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-CLI-BODIES": (
        "17.1 lands the probe; it drives the 52 `apps/<name>.c` command bodies behind the "
        "src/apps/openssl.rs dispatcher and its generated src/apps/tables.rs option tables, and "
        "compares the authority's and the candidate's transcripts"
    ),
    "RT-TLS13-INTEROP": (
        "17.2 lands the probe; it drives a real TLS 1.3 client/server flight, ClientHello through "
        "Finished plus an application-data exchange, and compares the two transcripts"
    ),
    "RT-CROSS-DSO-STATE": (
        "17.3 lands the probe; it raises an ERR through the libssl path and reads it through the "
        "libcrypto path (and the same for CONF), requiring one queue across the whole-crate DSOs"
    ),
    "RT-DOWNSTREAM-CONSUMER": (
        "17.4 lands the probe; it builds a real downstream consumer against the candidate "
        "distribution shell and compares its transcript with the authority's"
    ),
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase17"
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
            "Phase 17's four courts are named and `pending`; none is registered as passing at "
            "activation. `RT-CLI-BODIES` is 17.1's: it drives the 52 `apps/<name>.c` command "
            "bodies behind the src/apps/openssl.rs dispatcher and its generated "
            "src/apps/tables.rs option tables. `RT-TLS13-INTEROP` is 17.2's: it drives a real TLS "
            "1.3 client/server flight, ClientHello through Finished plus an application-data "
            "exchange, over the record layer, the extension units "
            "(ssl/extensions_clnt.c/ssl/extensions_srvr.c), the key schedule "
            "(ssl/t1_enc.c/ssl/tls13_enc.c) and the 56 message bodies D529 handed forward. "
            "`RT-CROSS-DSO-STATE` is 17.3's: it raises an ERR through the libssl path and reads it "
            "through the libcrypto path (and the same for CONF), requiring one queue across the "
            "candidate's whole-crate archives, where the authority shares one libcrypto.so.3 via "
            "DT_NEEDED. `RT-DOWNSTREAM-CONSUMER` is 17.4's: it builds a real downstream consumer "
            "against the candidate distribution shell. This stratum owns no exported symbol, so no "
            "differential probe over a symbol set is its evidence. docs/PHASE-17-SUBPHASES.md "
            "sections 1, 3 and 4 record the measurement and the courts (docs/DECISIONS.md D530)."
        ),
    }

    inputs = [
        InputRef(name="phase-17-plan", path=PLAN),
        InputRef(name="prerequisites", path=PREREQUISITES),
    ]
    doc = envelope(kind="phase17-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<24} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
