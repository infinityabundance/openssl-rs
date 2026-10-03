#!/usr/bin/env python3
"""openssl-rs — the Phase 16 obligation ledger, and its unit is not an exported symbol.

Phase 16 is the CLI / config / filesystem contract stratum (`docs/RELEASE_GATES.md` section 1).
Unlike every stratum from 3 to 15 it owns **zero exports**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 16` yields no record, because the
declaring-header rule assigns no installed header to this stratum. `docs/PHASE-16-SUBPHASES.md`
is its plan and this ledger is the machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe is three atlas-derived row kinds, and nothing is typed:

  * **the legacy provider registration rows** — every row of
    `forensics/atlas/provider-algorithms.json` whose `owning_phase` is 16 (the 39 rows of
    `providers/legacyprov.c`), handed here by `forensics/atlas/provider-algorithm-plans.json`
    rather than to Phase 13, whose subphases do not activate the legacy provider (D525);
  * **the prerequisite deferrals** — every `deferrals` and `units` row of
    `forensics/prerequisites.json` whose `owner_phase` is 16;
  * **the CLI / config / filesystem contract units** — three units whose authority surface one
    of those atlases (or the Phase-1 capture) measures, and whose state is derived from it.

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and
the two tools that partition the *export* universe — `court_coverage.py` and
`ownership_audit.py` — skip this ledger rather than reconcile a symbol set that does not exist,
exactly as they skip Phase 22's `compatibility plane` (D485). `main` fails closed if the
ownership atlas ever assigns this stratum an export, because then a non-export unit would be the
wrong shape.

Four situations, kept apart
---------------------------
  * **implemented** — the row is published, the deferral discharged, or the contract unit closed.
  * **open** — this stratum's, not built yet. The only list that blocks the stratum, counted by
    `counts.open_in_this_stratum`.
  * **deferred** — a recorded hand-off to a later stratum with the dependency named. Empty.
  * `implemented`/`open` as *export* lists are empty by measurement; the working set lives in the
    provider, deferral and contract blocks, not in those two keys.

Outputs
-------
  forensics/phase16-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase16-obligations.json"
GENERATOR = "forensics/tools/phase16_obligations.py"
PHASE = 16
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PROVIDER_PLANS = "forensics/atlas/provider-algorithm-plans.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-16-SUBPHASES.md"
CLI_CAPTURE = "forensics/atlas/openssl-3.6.4-production/cli-commands.json"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase
# number those tools know.
UNIT = "cli-config contract"

# The two default-path deferrals whose discharge closes the `config` contract unit. Named here
# because the *unit* is authored policy; their state is read from `forensics/prerequisites.json`.
CONFIG_DEFERRAL_SYMBOLS = ("ossl_get_openssldir", "ossl_get_wininstallcontext")


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase16-obligations: {relpath} is absent, so this stratum's universe cannot be "
            f"derived; the read is fail-closed rather than empty"
        )
    return json.loads(p.read_text(encoding="utf-8"))


def contract_units(prereq: dict, provider_rows: list[dict]) -> list[dict]:
    """The CLI / config / filesystem contract, each unit's state derived from its surface.

    The three units are policy -- which surfaces are the contract -- but no unit's state is
    typed: `cli` is closed when the Phase-1 capture carries a structured option count for every
    command, `config` when the two default-path deferrals have been discharged from
    `forensics/prerequisites.json`, and `filesystem` when every provider row this stratum owns is
    published. Each names the atlas that measures it.
    """
    cli = load(CLI_CAPTURE)["body"]
    commands = cli.get("commands") or []
    structured = [c for c in commands if int(c.get("option_count") or 0) > 0]
    cli_closed = bool(commands) and len(structured) == len(commands)

    deferral_symbols = {
        r["symbol"] for r in prereq["deferrals"] if int(r.get("owner_phase", -1)) == PHASE
    }
    outstanding = sorted(s for s in CONFIG_DEFERRAL_SYMBOLS if s in deferral_symbols)
    config_closed = not outstanding

    published = [r for r in provider_rows if r["implementation_state"] == "implemented"]
    filesystem_closed = bool(provider_rows) and len(published) == len(provider_rows)

    return [
        {
            "unit": "cli",
            "what": "the `openssl` CLI and its command dispatch over libcrypto/libssl",
            "surface": CLI_CAPTURE,
            "closure": "every command the Phase-1 capture lists carries a structured option count",
            "state": "implemented" if cli_closed else "open",
            "observation": (
                f"{len(structured)}/{len(commands)} command(s) carry a structured option count"
            ),
        },
        {
            "unit": "config",
            "what": "config loading and the default-path / directory plane",
            "surface": PREREQUISITES,
            "closure": "the default-path deferrals are discharged",
            "state": "implemented" if config_closed else "open",
            "observation": (
                f"{len(outstanding)} default-path deferral(s) outstanding"
                + (f": {', '.join(outstanding)}" if outstanding else "")
            ),
        },
        {
            "unit": "filesystem",
            "what": "the installed distribution layout, including the `ossl-modules/` module contract",
            "surface": PROVIDERS,
            "closure": "every provider registration row this stratum owns is published",
            "state": "implemented" if filesystem_closed else "open",
            "observation": (
                f"{len(published)}/{len(provider_rows)} provider row(s) implemented"
            ),
        },
    ]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)

    ownership = load(OWNERSHIP)["body"]
    provider_body = load(PROVIDERS)["body"]
    provider_plans = load(PROVIDER_PLANS)
    prereq = load(PREREQUISITES)["body"]

    # An export this stratum owned would make the non-export unit wrong, so it is fatal rather
    # than reconciled through a shape that cannot see it.
    atlas_owned = [
        r for r in ownership["records"] if r.get("owner_phase") == PHASE
    ]
    if atlas_owned:
        raise SystemExit(
            f"phase16-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )

    provider_rows = [
        {
            "provider": r["provider"],
            "operation": r["operation"],
            "algorithm_names": r["algorithm_names"],
            "source": r["source"],
            "table_symbol": r["table_symbol"],
            "implementation_state": r["implementation_state"],
            "planned_by": r["plan_match"],
        }
        for r in provider_body["rows"]
        if r.get("owning_phase") == PHASE
    ]
    if not provider_rows:
        raise SystemExit(
            "phase16-obligations: the provider census assigns this stratum no row, but "
            "provider-algorithm-plans.json hands it the legacy module; the census or the plan "
            "is wrong"
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
    unit_deferrals = [
        {
            "kind": "unit",
            "unit": r["unit"],
            "class": r.get("class"),
            "owner_phase": r.get("owner_phase"),
            "evidence": r.get("evidence"),
            "reason": r.get("reason"),
        }
        for r in prereq["units"]
        if int(r.get("owner_phase", -1)) == PHASE
    ]

    contracts = contract_units(prereq, provider_rows)

    published_provider = [
        r for r in provider_rows if r["implementation_state"] == "implemented"
    ]
    closed_contracts = [u for u in contracts if u["state"] == "implemented"]
    # A deferral row is owed while it is recorded; discharging one means removing it from
    # `forensics/prerequisites.json`, which the prerequisite gate enforces as `stale_deferral`.
    # So a present row counts as open here rather than as a second, typed state.
    owned = len(provider_rows) + len(deferrals) + len(unit_deferrals) + len(contracts)
    implemented_count = len(published_provider) + len(closed_contracts)
    open_count = owned - implemented_count

    counts = {
        "atlas_owned": len(atlas_owned),
        "provider_rows_owned": len(provider_rows),
        "provider_rows_open": len(provider_rows) - len(published_provider),
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
            "phase16-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: it is (a) every "
            "provider registration row forensics/atlas/provider-algorithms.json assigns phase "
            "16, (b) every deferral forensics/prerequisites.json records with owner_phase 16, "
            "and (c) the CLI / config / filesystem contract units docs/PHASE-16-SUBPHASES.md "
            "names. Every row is read from those atlases; the ledger types none of them, and "
            "`main` fails closed if the ownership atlas assigns this stratum an export"
        ),
        "unit": UNIT,
        "counts": counts,
        # Empty as *exports* by measurement. The working set is the three blocks below, so a
        # reader of the docs-consistency status clause finds the ledger truthful rather than
        # vacuous.
        "implemented": [],
        "open": [],
        "deferred": [],
        "provider_rows": provider_rows,
        "deferrals": deferrals,
        "unit_deferrals": unit_deferrals,
        "contract_units": contracts,
        "note": (
            "`open` is the only list that blocks this stratum, and its count is over provider "
            "registration rows, prerequisite deferrals and contract units rather than exported "
            "symbols, so the `implemented` and `open` *export* lists are empty by measurement and "
            "`open_in_this_stratum` is the live count. A provider row is a registration row, not "
            "an export: the provider-row rule in `phase_state.py` and the provider-row census "
            "remain the arbiter of its state, and `handed on` is the census's `projection`, not a "
            "state a row carries (D237, D295). The 39 legacy rows belong to the loadable module "
            "the candidate ships as a scaffold `ossl-modules/legacy.so`, which Phase 13's "
            "subphases do not activate and which this stratum owns as the installed-module "
            "contract (D525). The six prerequisite deferrals are the `OPENSSLDIR` directory "
            "plane, the install context, the absent dynamic ENGINE loader (D528) and the CLI "
            "capture defect (D490), plus the two TLS message-layer units Phase 15 sealed without. "
            "Nothing here is a parity claim: a published provider row or a landed CLI is at most "
            "`IMPLEMENTED` in docs/PARITY_MODEL.md terms, and docs/PHASE-16-SUBPHASES.md section "
            "4 decides when the stratum may be called complete."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="provider-algorithm-plans", path=REPO_ROOT / PROVIDER_PLANS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="cli-capture", path=REPO_ROOT / CLI_CAPTURE),
        InputRef(name="phase-16-plan", path=REPO_ROOT / PLAN),
    ]
    doc = envelope(kind="phase16-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase16-obligations] atlas-owned={c['atlas_owned']} "
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
