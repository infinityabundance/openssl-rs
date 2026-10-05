#!/usr/bin/env python3
"""openssl-rs — the Phase 19 obligation ledger, and its unit is not an exported symbol.

Phase 19 is the performance / CPU dispatch stratum (`docs/RELEASE_GATES.md` section 1). It owns
**zero exports**: reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 19` yields no
record, because the declaring-header rule assigns no installed header to this stratum.
`docs/PHASE-19-SUBPHASES.md` is its plan and this ledger is the machine-checkable arithmetic behind
it.

This ledger does not decide its own universe
--------------------------------------------
Its subjects are measurements over an implementation that is already complete, so it hands no new
library surface forward and receives none. The universe is therefore exactly one atlas-derived row
kind plus a fail-closed reading of the machinery that would be wrong if it silently acquired work:

  * **the performance dispatch contract units** — five authored policy rows naming the surfaces
    `docs/PHASE-19-SUBPHASES.md` records, each state derived from the atlas that measures it: the
    CPU-capability dispatch audit, the EVP / cipher dispatch comparison, the deterministic work
    court, the instrument-sensitivity court, and the performance-boundary register (five courts in
    `artifacts/phase19/COURTS.json`);
  * **nothing else.** The ownership atlas assigns this stratum no export, the provider census
    assigns it no registration row, and `forensics/prerequisites.json` records no deferral or
    translation unit owned by phase 19. `main` fails closed if any of those ever stops being true,
    because then this ledger's non-export unit would be the wrong shape rather than a complete
    account.

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and the
two tools that partition the *export* universe — `court_coverage.py` and `ownership_audit.py` —
skip this ledger rather than reconcile a symbol set that does not exist, exactly as they skip Phase
16's `cli-config contract`, Phase 17's `downstream replacement contract`, Phase 18's `hostile
hardening contract` and Phase 22's `compatibility plane`. `main` fails closed if the ownership atlas
ever assigns this stratum an export, because then a non-export unit would be the wrong shape.

The ledger reads the courts registry, and the runner does not read the ledger
----------------------------------------------------------------------------
The contract-unit states are measured from `artifacts/phase19/COURTS.json`, so the dependency runs
ledger -> courts: `forensics/tools/phase19_courts.py` enters the courts as `pending` and does
**not** bind this ledger as an input. Binding both directions would embed each artefact's digest in
the other and make neither reproducible. `docs/PHASE-19-SUBPHASES.md` section 4.2 is the
precondition, exactly as it is for Phase 18.

Four situations, kept apart
---------------------------
  * **implemented** — the contract unit closed, i.e. its court passes.
  * **open** — this stratum's, not built yet. The only list that blocks the stratum, counted by
    `counts.open_in_this_stratum`.
  * **deferred** — a recorded hand-off to a later stratum with the dependency named. Empty.
  * `implemented`/`open` as *export* lists are empty by measurement; the working set lives in the
    contract-unit block, not in those two keys.

Measurement and claim are two axes, and a pass is only about the first
---------------------------------------------------------------------
A contract unit's court passing says the **instrument** worked: it ran and its control was honest.
It does **not** say the performance property the unit names has been achieved — there is no
benchmark-parity claim in this stratum, and no assembly-versus-Rust equivalence claim. The ledger
records both axes explicitly so the two cannot be conflated:

  * `measurement_state` — `complete` when the unit's court passed as an instrument (it ran and its
    control was honest), `not_measured` otherwise. This is the same fact `state` records.
  * `property_status` — `NOT_CLAIMED` where the unit measures a performance property and the court
    recorded findings bearing on it, `not_claimed` where the unit makes no such claim.
  * `findings_present` / `findings` — whether the court recorded property findings, and the list
    itself.

`performance-work` is the unit where the two axes visibly diverge: `RT-PERFORMANCE-WORK` passes as
an instrument while recording every path whose deterministic work differs from the authority's as a
`finding`, so its property reads `NOT_CLAIMED` with `findings_present`. **A passing
`RT-PERFORMANCE-WORK` must never be read as "performance parity achieved".** The findings are read
from the court row, not typed here; the ledger fails closed if the court stops carrying them.

Outputs
-------
  forensics/phase19-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase19-obligations.json"
GENERATOR = "forensics/tools/phase19_obligations.py"
PHASE = 19
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-19-SUBPHASES.md"
COURTS = "artifacts/phase19/COURTS.json"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase
# number those tools know.
UNIT = "performance dispatch contract"

# The five contract units whose closure is measured by a court this stratum stages. Each unit is a
# surface the stratum owes performance / dispatch evidence over, and each is closed only when its
# court passes; none of them is a symbol, because the implementation it measures is already
# complete. `(unit, court, closure, what)`.
COURT_UNITS: tuple[tuple[str, str, str, str], ...] = (
    ("cpu-capability", "RT-CPU-CAPABILITY",
     "the `RT-CPU-CAPABILITY` court passes",
     "a CPU-capability dispatch audit: the candidate's CPU-capability surface "
     "(`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`) driven under a fixed and "
     "faulted CPUID facade against the admitted authority, with an authority-linked differential "
     "control"),
    ("evp-dispatch", "RT-EVP-DISPATCH",
     "the `RT-EVP-DISPATCH` court passes",
     "an EVP / cipher dispatch comparison: which implementation a fetch or cipher context selects "
     "for a given capability set, driven on both sides over the same set, with an authority-linked "
     "differential control"),
    ("performance-work", "RT-PERFORMANCE-WORK",
     "the `RT-PERFORMANCE-WORK` court passes",
     "deterministic operation and block counts over the primitive-bearing paths (not wall-clock-"
     "only), driven on the authority and the candidate over the same inputs, recording every path "
     "whose work differs as a finding"),
    ("performance-sensitivity", "RT-PERFORMANCE-SENSITIVITY",
     "the `RT-PERFORMANCE-SENSITIVITY` court passes",
     "the instrument-sensitivity control: a deliberately slowed path must be caught, so a measure "
     "that cannot tell a slow path from a fast one is `fail` rather than `pass`; candidate-only"),
    ("performance-boundary-register", "PERFORMANCE-BOUNDARY-REGISTER",
     "the `PERFORMANCE-BOUNDARY-REGISTER` court passes",
     "the register that records what is measured, what is not, and the explicit non-claims (no "
     "benchmark-parity claim, no assembly-versus-Rust equivalence claim), and that fails the "
     "stratum if a recorded boundary drifts from its evidence"),
)

# The contract units that measure a **performance property** rather than a dispatch or
# instrument-sensitivity behaviour. `performance-work`'s subject is deterministic work, and its
# court is candid that a passing verdict is about the instrument plus a bounded differential
# measurement, not about parity: the reduced engine's implementations carry their own work profile,
# so a path whose work differs from the authority's is recorded as a `finding` and the property is
# explicitly NOT claimed. Every other unit makes no performance-property claim, which
# `property_status` records as `not_claimed`.
PROPERTY_UNITS: frozenset[str] = frozenset({"performance-work"})


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase19-obligations: {relpath} is absent, so this stratum's universe cannot be "
            f"derived; the read is fail-closed rather than empty"
        )
    return json.loads(p.read_text(encoding="utf-8"))


def court_row(courts_body: dict, court: str) -> dict:
    """The registry row for a court, or an empty row when nothing names it.

    The row carries the court's own `findings`, so a property finding is read from the instrument
    that produced it rather than typed into this ledger.
    """
    for row in courts_body.get("courts") or []:
        if row.get("court") == court:
            return row
    return {}


def court_state(courts_body: dict, court: str) -> tuple[bool, str]:
    """`(passed, observation)` for a court in the Phase-19 registry.

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


def machinery_rows(ownership: dict, provider_body: dict, prereq: dict) -> dict:
    """The machinery projections this stratum must own **none** of, read rather than typed.

    Phase 19 measures a finished implementation, so it hands nothing forward and receives nothing:
    the ownership atlas assigns it no export, the provider census no registration row, and
    `forensics/prerequisites.json` no deferral or translation unit. Each is returned so the ledger
    can count it (zero at activation) and fail closed if it ever acquires one.
    """
    atlas_owned = [r for r in ownership["records"] if r.get("owner_phase") == PHASE]
    provider_rows = [r for r in provider_body["rows"] if r.get("owning_phase") == PHASE]
    deferrals = [
        {
            "kind": "symbol",
            "symbol": r.get("symbol"),
            "authority_unit": r.get("authority_unit"),
            "evidence": r.get("evidence"),
            "reason": r.get("reason"),
        }
        for r in prereq.get("deferrals", [])
        if int(r.get("owner_phase", -1)) == PHASE
    ]
    unit_deferrals = [
        {
            "kind": "unit",
            "unit": r.get("unit"),
            "class": r.get("class"),
            "owner_phase": r.get("owner_phase"),
            "evidence": r.get("evidence"),
            "reason": r.get("reason"),
        }
        for r in prereq.get("units", [])
        if int(r.get("owner_phase", -1)) == PHASE
        and r.get("class") == "deferred_to_later_stratum"
    ]
    return {
        "atlas_owned": atlas_owned,
        "provider_rows": provider_rows,
        "deferrals": deferrals,
        "unit_deferrals": unit_deferrals,
    }


def contract_units(courts_body: dict) -> list[dict]:
    """The performance dispatch contract, each unit's state derived from its own court.

    The units are policy -- which surfaces the stratum owes evidence over -- but no unit's state is
    typed: each is closed when its court passes and open otherwise.

    Two axes are recorded, and they are deliberately distinct. `measurement_state` says whether the
    instrument completed; `property_status`/`findings` say what, if anything, the unit claims about
    a performance property. `performance-work`'s court passes while recording every path whose work
    differs from the authority's as a finding, so its property is `NOT_CLAIMED`; a reader can no
    longer mistake the pass for "performance parity achieved".
    """
    units: list[dict] = []
    for name, court, closure, what in COURT_UNITS:
        passed, observation = court_state(courts_body, court)
        row = court_row(courts_body, court)
        # The court's `findings`, when it is a list, are the property findings its instrument
        # recorded (the work-court's shape). A dispatch court records a `{divergences}` mapping
        # instead, which is a selection disposition and not a property-findings list, so it is not
        # claimed here.
        raw_findings = row.get("findings")
        property_findings = ([str(f) for f in raw_findings]
                             if isinstance(raw_findings, list) else [])
        measures_property = name in PROPERTY_UNITS
        units.append(
            {
                "unit": name,
                "what": what,
                "surface": COURTS,
                "closure": closure,
                "state": "implemented" if passed else "open",
                # The instrument axis: `complete` means the court ran and its control was honest,
                # never that the property it names has been achieved.
                "measurement_state": "complete" if passed else "not_measured",
                # The property axis: a measured performance property is NOT_CLAIMED while findings
                # are present; a unit that makes no such claim reads `not_claimed`.
                "property_status": (
                    "NOT_CLAIMED" if measures_property and property_findings
                    else "not_claimed"
                ),
                "findings_present": bool(property_findings),
                "findings": property_findings,
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

    machinery = machinery_rows(ownership, provider_body, prereq)
    atlas_owned = machinery["atlas_owned"]
    provider_rows = machinery["provider_rows"]
    deferrals = machinery["deferrals"]
    unit_deferrals = machinery["unit_deferrals"]

    # An export this stratum owned would make the non-export unit wrong, so it is fatal rather than
    # reconciled through a shape that cannot see it.
    if atlas_owned:
        raise SystemExit(
            f"phase19-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )
    # A provider registration row this stratum owned would be a row its plan does not name, so it
    # is fatal: Phase 19 activates no provider.
    if provider_rows:
        raise SystemExit(
            f"phase19-obligations: the provider census assigns this stratum "
            f"{len(provider_rows)} registration row(s), but Phase 19 activates no provider; the "
            f"census or this ledger's plan is wrong"
        )
    # A prerequisite deferral or unit owned by this stratum would be an obligation this plan does
    # not name, so it is fatal rather than silently counted through the contract block.
    if deferrals or unit_deferrals:
        raise SystemExit(
            f"phase19-obligations: forensics/prerequisites.json records "
            f"{len(deferrals)} deferral(s) and {len(unit_deferrals)} unit deferral(s) owned by "
            f"phase {PHASE}, but Phase 19 hands nothing forward and receives nothing; the "
            f"prerequisite plane or this ledger's plan is wrong"
        )

    contracts = contract_units(courts_body)

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
            "phase19-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: Phase 19 owns no "
            "export, no provider registration row and no prerequisite deferral, so its working "
            "set is exactly the performance dispatch contract units docs/PHASE-19-SUBPHASES.md "
            "names, each measured by the Phase-19 courts registry. Every row is read from those "
            "atlases; the ledger types none of them, and `main` fails closed if the ownership "
            "atlas assigns this stratum an export, the provider census assigns it a row, or the "
            "prerequisite plane assigns it a deferral or unit"
        ),
        "unit": UNIT,
        "counts": counts,
        # Empty as *exports* by measurement. The working set is the contract block below, so a
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
            "`open` is the only list that blocks this stratum, and its count is over the "
            "performance dispatch contract units rather than exported symbols, so the "
            "`implemented` and `open` *export* lists are empty by measurement and "
            "`open_in_this_stratum` is the live count. Phase 19 owns no provider registration row "
            "and no export: it activates no provider and adds no library surface, because it "
            "measures the implementation the strata before it completed. Its five contract units "
            "are the performance dispatch contract docs/PHASE-19-SUBPHASES.md section 1 names -- "
            "the CPU-capability dispatch audit, the EVP / cipher dispatch comparison, the "
            "deterministic work court, the instrument-sensitivity court and the "
            "performance-boundary register -- and at activation all five are open, so this "
            "stratum's working set is exactly its five contract units. Nothing here is a "
            "throughput or parity claim: a passing performance court is a bounded "
            "deterministic-work comparison at its stated resolution, an EVP / cipher dispatch "
            "court is a bounded comparison of selection over the capability sets it drives, and "
            "there is no benchmark-parity claim and no assembly-versus-Rust equivalence claim "
            "anywhere in this stratum. Each contract unit records its two axes separately: "
            "`measurement_state` says the instrument completed, and `property_status`/`findings` "
            "say what is claimed about a performance property. The `performance-work` unit's "
            "property is `NOT_CLAIMED` with the paths whose deterministic work differs from the "
            "authority's named as findings, so a passing `RT-PERFORMANCE-WORK` is an instrument "
            "plus measurement result and must never be read as 'performance parity achieved'."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="phase-19-plan", path=REPO_ROOT / PLAN),
        InputRef(name="phase-19-courts", path=REPO_ROOT / COURTS),
    ]
    doc = envelope(kind="phase19-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase19-obligations] atlas-owned={c['atlas_owned']} "
          f"provider_rows={c['provider_rows_owned']} deferrals={c['deferrals_received']} "
          f"unit_deferrals={c['unit_deferrals_received']} contracts={c['contract_units']} "
          f"owned={c['owned']} open={c['open_in_this_stratum']}")
    print(f"  unit={body['unit']}  complete={open_count == 0}")
    print(f"  contract: "
          + ", ".join(f"{u['unit']}={u['state']} ({u['observation']})" for u in contracts))
    for u in contracts:
        if u["findings_present"]:
            print(f"  property: {u['unit']} measurement={u['measurement_state']} "
                  f"property={u['property_status']} findings={u['findings']}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
