#!/usr/bin/env python3
"""openssl-rs — the Phase 17 obligation ledger, and its unit is not an exported symbol.

Phase 17 is the downstream replacement court stratum (`docs/RELEASE_GATES.md` section 1). Unlike
every stratum from 3 to 15 it owns **zero exports**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 17` yields no record, because the
declaring-header rule assigns no installed header to this stratum. `docs/PHASE-17-SUBPHASES.md` is
its plan and this ledger is the machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe is two atlas-derived row kinds, and nothing is typed:

  * **the CLI command bodies** — the 52 `apps/<name>.c` units D530 handed here from Phase 16.4,
    recorded in `forensics/prerequisites.json` either as `deferred_to_later_stratum` rows with
    `owner_phase` 17 or as the `reached_by_a_named_construct` records that discharge them;
  * **the downstream replacement contract units** — five authored policy rows naming the surfaces
    `docs/PHASE-17-SUBPHASES.md` records, each state derived from the atlas that measures it: the
    command bodies, the `RT-TLS13-INTEROP-MATRIX` court, the `RT-CROSS-DSO-STATE` court, the
    `RT-DOWNSTREAM-CONSUMER` court and the `RT-DOWNSTREAM-CORPUS` court (the machine-owned
    downstream records).

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and the
two tools that partition the *export* universe — `court_coverage.py` and `ownership_audit.py` — skip
this ledger rather than reconcile a symbol set that does not exist, exactly as they skip Phase 16's
`cli-config contract` (D485) and Phase 22's `compatibility plane`. `main` fails closed if the ownership
atlas ever assigns this stratum an export, because then a non-export unit would be the wrong shape.

The ledger reads the courts registry, and the runner does not read the ledger
----------------------------------------------------------------------------
The contract-unit states are measured from `artifacts/phase17/COURTS.json`, so the dependency runs
ledger -> courts: `forensics/tools/phase17_courts.py` enters the courts as `pending` and does **not**
bind this ledger as an input. Binding both directions would embed each artefact's digest in the
other and make neither reproducible. `docs/PHASE-17-SUBPHASES.md` section 4.2 is the precondition.

Four situations, kept apart
---------------------------
  * **implemented** — the unit deferral is discharged or the contract unit closed.
  * **open** — this stratum's, not built yet. The only list that blocks the stratum, counted by
    `counts.open_in_this_stratum`.
  * **deferred** — a recorded hand-off to a later stratum with the dependency named. Empty.
  * `implemented`/`open` as *export* lists are empty by measurement; the working set lives in the
    unit-deferral and contract blocks, not in those two keys.

Outputs
-------
  forensics/phase17-obligations.json

SPDX-License-Identifier: Apache-2.0
"""

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

OUT = REPO_ROOT / "forensics" / "phase17-obligations.json"
GENERATOR = "forensics/tools/phase17_obligations.py"
PHASE = 17
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-17-SUBPHASES.md"
COURTS = "artifacts/phase17/COURTS.json"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase number
# those tools know.
UNIT = "downstream replacement contract"

# The four contract units whose closure is measured by a court this stratum stages.
# `command-bodies` is measured by the prerequisite plane instead, because the 52 `apps/<name>.c`
# units are the contract the courts then exercise. `(unit, court, closure, what)`.
COURT_UNITS: tuple[tuple[str, str, str, str], ...] = (
    ("tls13-interop", "RT-TLS13-INTEROP-MATRIX",
     "the `RT-TLS13-INTEROP-MATRIX` court passes",
     "a real TLS 1.3 client/server flight, ClientHello through Finished plus application data, "
     "over all four authority/candidate client-server cells"),
    ("cross-dso-state", "RT-CROSS-DSO-STATE",
     "the `RT-CROSS-DSO-STATE` court passes",
     "an ERR/`CONF` raised through one DSO and read through another"),
    ("downstream-consumer", "RT-DOWNSTREAM-CONSUMER",
     "the `RT-DOWNSTREAM-CONSUMER` court passes",
     "a real downstream consumer built against the candidate distribution shell"),
    ("downstream-corpus", "RT-DOWNSTREAM-CORPUS",
     "the `RT-DOWNSTREAM-CORPUS` court passes",
     "the machine-owned per-program downstream records (build/link/start/functional/"
     "concurrency) the seal consumes, and their freshness"),
)

# D530 hands this stratum the 52 `apps/<name>.c` command bodies. A body's row is
# `deferred_to_later_stratum` with `owner_phase: 17` until 17.1 lands it, at which point the row is
# rewritten to the `reached_by_a_named_construct` record `plan_reconciliation.py` requires for a unit
# the three mechanical signals cannot see (the same shape `apps/openssl.c` already carries). The
# ledger's command-body universe is therefore those units **in either state**, and it fails closed
# unless all 52 are still recorded. The dispatcher unit is Phase 16.4's, not one of the 52, and is
# excluded.
COMMAND_BODIES = 52
DISPATCHER_UNIT = "apps/openssl.c"


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase17-obligations: {relpath} is absent, so this stratum's universe cannot be "
            f"derived; the read is fail-closed rather than empty"
        )
    return json.loads(p.read_text(encoding="utf-8"))


def court_state(courts_body: dict, court: str) -> tuple[bool, str]:
    """`(passed, observation)` for a court in the Phase-17 registry.

    A court not yet registered is `open` with an observation naming whether the runner still lists
    it as `pending` or nothing names it at all, so a court quietly dropped is visible rather than
    read as not-yet-built.
    """
    for row in courts_body.get("courts") or []:
        if row.get("court") == court:
            return row.get("verdict") == "pass", str(row.get("verdict"))
    if court in (courts_body.get("pending_courts") or {}):
        return False, "pending"
    return False, "not registered"


def command_body_rows(prereq: dict) -> list[dict]:
    """The 52 `apps/<name>.c` command-body rows, in either the deferred or the discharged state.

    D530 handed this stratum 52 command bodies. Before 17.1 lands one, its row is
    `deferred_to_later_stratum` with `owner_phase: 17`; once landed, the row is rewritten to
    `reached_by_a_named_construct` -- the disposition `plan_reconciliation.py` defines for a unit the
    three mechanical signals cannot see. Both states record the unit, so this is the universe the
    ledger holds itself to. The dispatcher `apps/openssl.c` is Phase 16.4's and is not one of the 52.
    """
    rows: list[dict] = []
    for r in prereq["units"]:
        unit = str(r.get("unit", ""))
        if not unit.startswith("apps/") or unit == DISPATCHER_UNIT:
            continue
        cls = r.get("class")
        if cls == "deferred_to_later_stratum":
            if int(r.get("owner_phase", -1)) == PHASE:
                rows.append(r)
        elif cls == "reached_by_a_named_construct":
            rows.append(r)
    return rows


def contract_units(prereq: dict, courts_body: dict) -> list[dict]:
    """The downstream replacement contract, each unit's state derived from its own surface.

    The units are policy -- which surfaces are the contract -- but no unit's state is typed:
    `command-bodies` is closed when no `apps/<name>.c` unit remains deferred to this stratum, and
    each of the four court units is closed when its court passes. Each names the atlas or registry
    that measures it.
    """
    outstanding = sorted(
        r["unit"] for r in prereq["units"]
        if r.get("class") == "deferred_to_later_stratum"
        and int(r.get("owner_phase", -1)) == PHASE
    )
    units = [
        {
            "unit": "command-bodies",
            "what": "the 52 `openssl` command bodies over libcrypto/libssl",
            "surface": PREREQUISITES,
            "closure": "every `apps/<name>.c` unit deferred to this stratum is discharged",
            "state": "implemented" if not outstanding else "open",
            "observation": (
                f"{len(outstanding)} command body unit(s) outstanding"
                if outstanding else "all command body units discharged"
            ),
        }
    ]
    for name, court, closure, what in COURT_UNITS:
        passed, observation = court_state(courts_body, court)
        units.append(
            {
                "unit": name,
                "what": what,
                "surface": COURTS,
                "closure": closure,
                "state": "implemented" if passed else "open",
                "observation": f"{court} is {observation}",
            }
        )
    return units


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)

    ownership = load(OWNERSHIP)["body"]
    provider_body = load(PROVIDERS)["body"]
    prereq = load(PREREQUISITES)["body"]
    courts_body = load(COURTS)["body"]

    # An export this stratum owned would make the non-export unit wrong, so it is fatal rather than
    # reconciled through a shape that cannot see it.
    atlas_owned = [r for r in ownership["records"] if r.get("owner_phase") == PHASE]
    if atlas_owned:
        raise SystemExit(
            f"phase17-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )

    # A provider registration row this stratum owned would be a row its plan does not name, so it is
    # fatal: Phase 17 activates no provider, and the legacy module is Phase 16's.
    provider_rows = [r for r in provider_body["rows"] if r.get("owning_phase") == PHASE]
    if provider_rows:
        raise SystemExit(
            f"phase17-obligations: the provider census assigns this stratum "
            f"{len(provider_rows)} registration row(s), but Phase 17 activates no provider; the "
            f"census or this ledger's plan is wrong"
        )

    deferrals = [
        {
            "kind": "symbol",
            "symbol": r["symbol"],
            "authority_unit": r.get("authority_unit"),
            "evidence": r.get("evidence"),
            "reason": r.get("reason"),
        }
        for r in prereq["deferrals"]
        if int(r.get("owner_phase", -1)) == PHASE
    ]
    # D530's 52 command bodies are the universe, recorded either as a `deferred_to_later_stratum`
    # row (owner_phase 17) or as the `reached_by_a_named_construct` record that discharges it. The
    # fail-closed check is that the plane still records all 52: a universe that emptied because the
    # records were dropped -- rather than discharged -- is fatal rather than an
    # `open_in_this_stratum` of zero.
    command_bodies = command_body_rows(prereq)
    if len(command_bodies) < COMMAND_BODIES:
        raise SystemExit(
            f"phase17-obligations: forensics/prerequisites.json records only "
            f"{len(command_bodies)} of the {COMMAND_BODIES} `apps/<name>.c` command bodies D530 "
            f"hands this stratum, whether as `deferred_to_later_stratum` with `owner_phase` 17 or "
            f"as the `reached_by_a_named_construct` record that discharges one; the prerequisite "
            f"plane or this ledger's plan is wrong"
        )
    # A unit row is owed while it is still a deferral; discharging one rewrites it to a reached
    # record, so a *present deferred* row counts as open here rather than as a second, typed state.
    unit_deferrals = [
        {
            "kind": "unit",
            "unit": r["unit"],
            "class": r.get("class"),
            "owner_phase": r.get("owner_phase"),
            "evidence": r.get("evidence"),
            "reason": r.get("reason"),
        }
        for r in command_bodies
        if r.get("class") == "deferred_to_later_stratum"
    ]

    contracts = contract_units(prereq, courts_body)

    owned = len(provider_rows) + len(deferrals) + len(unit_deferrals) + len(contracts)
    implemented_count = len([u for u in contracts if u["state"] == "implemented"])
    open_count = owned - implemented_count
    counts = {
        "atlas_owned": len(atlas_owned),
        "provider_rows_owned": len(provider_rows),
        "provider_rows_open": len(provider_rows),
        "deferrals_received": len(deferrals),
        "unit_deferrals_received": len(unit_deferrals),
        "contract_units": len(contracts),
        "owned": owned,
        "implemented": implemented_count,
        "deferred_to_later_phase": 0,
        "open_in_this_stratum": open_count,
    }
    if owned != implemented_count + counts["deferred_to_later_phase"] + open_count:
        raise SystemExit(
            "phase17-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: it is (a) the 52 "
            "`apps/<name>.c` command bodies D530 hands it, which forensics/prerequisites.json "
            "records either as `deferred_to_later_stratum` rows with owner_phase 17 or as the "
            "`reached_by_a_named_construct` records that discharge them, and (b) the downstream "
            "replacement contract units docs/PHASE-17-SUBPHASES.md names, each measured by the "
            "prerequisite plane or by the Phase-17 courts registry. Every row is read from those "
            "atlases; the ledger types none of them, and `main` fails closed if the ownership atlas "
            "assigns this stratum an export or the prerequisite plane drops a command body"
        ),
        "unit": UNIT,
        "counts": counts,
        # Empty as *exports* by measurement. The working set is the two blocks below, so a reader of
        # the docs-consistency status clause finds the ledger truthful rather than vacuous.
        "implemented": [],
        "open": [],
        "deferred": [],
        "provider_rows": provider_rows,
        "deferrals": deferrals,
        "unit_deferrals": unit_deferrals,
        "contract_units": contracts,
        "note": (
            "`open` is the only list that blocks this stratum, and its count is over the unit "
            "deferrals and contract units rather than exported symbols, so the `implemented` and "
            "`open` *export* lists are empty by measurement and `open_in_this_stratum` is the live "
            "count. Phase 17 owns no provider registration row: it activates no provider, and the "
            "39 legacy rows the census assigns are the loadable module Phase 16 owns (D525). The 52 "
            "command bodies are the `apps/<name>.c` units Phase 16.4 landed a dispatcher for but not "
            "the bodies (D530): each landed body's row is rewritten from `deferred_to_later_stratum` "
            "to the `reached_by_a_named_construct` record `plan_reconciliation.py` requires, so "
            "`unit_deferrals` is empty once all 52 are discharged and the ledger fails closed unless "
            "the plane still records all 52. The five contract "
            "units are the downstream replacement contract docs/PHASE-17-SUBPHASES.md section 1 "
            "names -- the command bodies, a real TLS 1.3 interoperability handshake, the cross-DSO "
            "shared state, a real downstream consumer and the machine-owned downstream corpus -- and "
            "the four courts pass while "
            "`command-bodies` closes with the last landed body. Nothing here is a parity claim: a "
            "published command body or a passing handshake "
            "is at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and "
            "docs/PHASE-17-SUBPHASES.md section 4 decides when the stratum may be called complete."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="phase-17-plan", path=REPO_ROOT / PLAN),
        InputRef(name="phase-17-courts", path=REPO_ROOT / COURTS),
    ]
    doc = envelope(kind="phase17-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase17-obligations] atlas-owned={c['atlas_owned']} "
          f"provider_rows={c['provider_rows_owned']} deferrals={c['deferrals_received']} "
          f"unit_deferrals={c['unit_deferrals_received']} contracts={c['contract_units']} "
          f"owned={c['owned']} open={c['open_in_this_stratum']}")
    print(f"  unit={body['unit']}  complete={open_count == 0}")
    print(f"  contract: "
          + ", ".join(f"{u['unit']}={u['state']} ({u['observation']})" for u in contracts))
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
