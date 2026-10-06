#!/usr/bin/env python3
"""openssl-rs — the Phase 20 obligation ledger, and its unit is not an exported symbol.

Phase 20 is the 3.6.4 custodian seal stratum (`docs/RELEASE_GATES.md` section 1, maturity level
**L9 high-assurance custodian seal**, section 3). It owns **zero exports**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 20` yields no record, because the
declaring-header rule assigns no installed header to this stratum. `docs/PHASE-20-SUBPHASES.md` is
its plan and this ledger is the machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
Its subjects are claims compiled over an implementation that is already complete, so it hands no new
library surface forward and receives none. The universe is therefore exactly one atlas-derived row
kind plus a fail-closed reading of the machinery that would be wrong if it silently acquired work:

  * **the custodian seal contract units** — five authored policy rows naming the surfaces
    `docs/PHASE-20-SUBPHASES.md` records, each state derived from the atlas that measures it: the
    maturity derivation, the receipt closure, the residual disposition, the substitution witness and
    the custodian-boundary register (five courts in `artifacts/phase20/COURTS.json`);
  * **nothing else.** The ownership atlas assigns this stratum no export, the provider census
    assigns it no registration row, and `forensics/prerequisites.json` records no deferral or
    translation unit owned by phase 20. `main` fails closed if any of those ever stops being true,
    because then this ledger's non-export unit would be the wrong shape rather than a complete
    account.

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and the
two tools that partition the *export* universe — `court_coverage.py` and `ownership_audit.py` —
skip this ledger rather than reconcile a symbol set that does not exist, exactly as they skip Phase
16's `cli-config contract`, Phase 17's `downstream replacement contract`, Phase 18's `hostile
hardening contract`, Phase 19's `performance dispatch contract` and Phase 22's `compatibility
plane`. `main` fails closed if the ownership atlas ever assigns this stratum an export, because then
a non-export unit would be the wrong shape.

The ledger reads the courts registry, and the runner does not read the ledger
----------------------------------------------------------------------------
The contract-unit states are measured from `artifacts/phase20/COURTS.json`, so the dependency runs
ledger -> courts: `forensics/tools/phase20_courts.py` enters the courts as `pending` and does
**not** bind this ledger as an input. Binding both directions would embed each artefact's digest in
the other and make neither reproducible. `docs/PHASE-20-SUBPHASES.md` section 4.2 is the
precondition, exactly as it is for Phases 18 and 19.

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
It does **not** say the custodian property the unit names has been achieved — this stratum makes no
claim that `docs/CUSTODIAN_CONTRACT.md` section 6's custodian-compatibility holds merely because a
court passed, and no FIPS, universal-parity or established-memory-safety claim at all. The ledger
records both axes explicitly so the two cannot be conflated:

  * `measurement_state` — `complete` when the unit's court passed as an instrument (it ran and its
    control was honest), `not_measured` otherwise. This is the same fact `state` records.
  * `property_status` — `NOT_CLAIMED` where the unit measures a custodian property and the court
    recorded findings bearing on it, `not_claimed` where the unit makes no such claim.
  * `findings_present` / `findings` — whether the court recorded property findings, and the list
    itself.

`custodian-maturity` is the unit where the two axes visibly diverge: `RT-CUSTODIAN-MATURITY` passes
as an instrument while recording, as a `finding`, where the level the committed evidence supports is
lower than the level the seal might otherwise name, so its property reads `NOT_CLAIMED` with
`findings_present`. **A passing `RT-CUSTODIAN-MATURITY` must never be read as "L9 custodian seal
achieved".** `custodian-residuals` is the second property unit: a real un-dispositioned or
`UNKNOWN`-intersecting residual is a `finding` and reads `NOT_CLAIMED`, while a genuinely closed set
records zero findings and reads `not_claimed`. The findings are read from the court row, not typed
here; the ledger fails closed if the maturity court stops carrying them.

Outputs
-------
  forensics/phase20-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase20-obligations.json"
GENERATOR = "forensics/tools/phase20_obligations.py"
PHASE = 20
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-20-SUBPHASES.md"
COURTS = "artifacts/phase20/COURTS.json"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase
# number those tools know.
UNIT = "custodian seal contract"

# The five contract units whose closure is measured by a court this stratum stages. Each unit is a
# surface the stratum owes custodian-seal evidence over, and each is closed only when its court
# passes; none of them is a symbol, because the implementation whose claim it compiles is already
# complete. `(unit, court, closure, what)`.
COURT_UNITS: tuple[tuple[str, str, str, str], ...] = (
    ("custodian-maturity", "RT-CUSTODIAN-MATURITY",
     "the `RT-CUSTODIAN-MATURITY` court passes",
     "the derivation of the L0-L9 maturity ladder of `docs/RELEASE_GATES.md` section 3 for "
     "`libcrypto` and `libssl` from committed evidence, naming only a level whose evidence is "
     "present and recording the gap as a finding when the evidence supports less than the level "
     "the seal might claim"),
    ("receipt-closure", "RT-RECEIPT-CLOSURE",
     "the `RT-RECEIPT-CLOSURE` court passes",
     "the join of every obligation recorded `implemented` or closed to its FRF receipt, and the "
     "FRF store's compiled parity claim with zero blockers, so `docs/CUSTODIAN_CONTRACT.md` "
     "section 6's claim is a join over immutable receipts rather than an assertion"),
    ("custodian-residuals", "RT-CUSTODIAN-RESIDUALS",
     "the `RT-CUSTODIAN-RESIDUALS` court passes",
     "the disposition of every residual, requiring zero `UNKNOWN` intersecting the claimed "
     "production profile, so a newly discovered un-dispositioned residual is a `fail` rather than "
     "a silent addition"),
    ("substitution-witness", "RT-SUBSTITUTION-WITNESS",
     "the `RT-SUBSTITUTION-WITNESS` court passes",
     "the ABI-substitution witness chain and the machine-owned downstream corpus witness chain: "
     "binaries built against the admitted authority run unmodified against the candidate, over "
     "the Phase-17 corpus the court re-establishes as current and functional"),
    ("custodian-boundary-register", "CUSTODIAN-BOUNDARY-REGISTER",
     "the `CUSTODIAN-BOUNDARY-REGISTER` court passes",
     "the register that records what is claimed, what is bounded, and the explicit non-claims (no "
     "FIPS validation, no universal parity from finite evidence, memory safety "
     "measured-not-established), and that fails the stratum if a recorded boundary drifts from its "
     "evidence"),
)

# The contract units that measure a **custodian property** rather than an instrument-sensitivity
# behaviour. `custodian-maturity`'s subject is the level the committed evidence supports, and its
# court is candid that a passing verdict is about the instrument plus a derived measurement, not
# about the level: where the evidence supports less than the level the seal might name, the gap is
# recorded as a `finding` and the property is explicitly NOT claimed. `custodian-residuals`'s subject
# is the closed residual set: while a real un-dispositioned or `UNKNOWN`-intersecting residual is a
# finding, the property reads `NOT_CLAIMED`; on a genuinely closed set it records zero findings and
# reads `not_claimed`, exactly as `receipt-closure` does. Every other unit makes no custodian-property
# claim, which `property_status` records as `not_claimed`.
PROPERTY_UNITS: frozenset[str] = frozenset({"custodian-maturity", "custodian-residuals"})

# The property units whose property is **never** claimable by a passing instrument: the level the
# seal names is established by the stratum's own seal (20.6), not by the court, so a passing
# `custodian-maturity` that stopped carrying the gap as a finding would let the pass be read as "L9
# custodian seal achieved". `custodian-residuals` is deliberately **not** here: on a genuinely closed
# residual set zero findings is the correct and complete answer, and requiring a finding would make
# the court unable to report closure.
SEAL_GAP_UNITS: frozenset[str] = frozenset({"custodian-maturity"})


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase20-obligations: {relpath} is absent, so this stratum's universe cannot be "
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
    """`(passed, observation)` for a court in the Phase-20 registry.

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

    Phase 20 compiles a claim over a finished implementation, so it hands nothing forward and
    receives nothing: the ownership atlas assigns it no export, the provider census no registration
    row, and `forensics/prerequisites.json` no deferral or translation unit. Each is returned so the
    ledger can count it (zero at activation) and fail closed if it ever acquires one.
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
    """The custodian seal contract, each unit's state derived from its own court.

    The units are policy -- which surfaces the stratum owes evidence over -- but no unit's state is
    typed: each is closed when its court passes and open otherwise.

    Two axes are recorded, and they are deliberately distinct. `measurement_state` says whether the
    instrument completed; `property_status`/`findings` say what, if anything, the unit claims about
    a custodian property. `custodian-maturity`'s court passes while recording, as a finding, where
    the level the committed evidence supports falls short of the level the seal might name, so its
    property is `NOT_CLAIMED`; a reader can no longer mistake the pass for "L9 custodian seal
    achieved".
    """
    units: list[dict] = []
    for name, court, closure, what in COURT_UNITS:
        passed, observation = court_state(courts_body, court)
        row = court_row(courts_body, court)
        # The court's `findings`, when it is a list, are the property findings its instrument
        # recorded (the maturity-court's shape). A witness or residual court records a different
        # mapping instead, which is a disposition and not a property-findings list, so it is not
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
                # The property axis: a measured custodian property is NOT_CLAIMED while findings
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
            f"phase20-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )
    # A provider registration row this stratum owned would be a row its plan does not name, so it
    # is fatal: Phase 20 activates no provider.
    if provider_rows:
        raise SystemExit(
            f"phase20-obligations: the provider census assigns this stratum "
            f"{len(provider_rows)} registration row(s), but Phase 20 activates no provider; the "
            f"census or this ledger's plan is wrong"
        )
    # A prerequisite deferral or unit owned by this stratum would be an obligation this plan does
    # not name, so it is fatal rather than silently counted through the contract block.
    if deferrals or unit_deferrals:
        raise SystemExit(
            f"phase20-obligations: forensics/prerequisites.json records "
            f"{len(deferrals)} deferral(s) and {len(unit_deferrals)} unit deferral(s) owned by "
            f"phase {PHASE}, but Phase 20 hands nothing forward and receives nothing; the "
            f"prerequisite plane or this ledger's plan is wrong"
        )

    contracts = contract_units(courts_body)

    # The two-axis rule is a hard invariant for a *seal-gap* unit while its property is unclaimed:
    # a passing `custodian-maturity` that stopped carrying the gap to the level the seal names would
    # let the pass be read as "L9 custodian seal achieved", exactly what this ledger exists to
    # prevent. `custodian-residuals` is not a seal-gap unit: a genuinely closed residual set is a
    # complete pass with zero findings, and the invariant must not force a finding onto it.
    for unit in contracts:
        if unit["unit"] in SEAL_GAP_UNITS and unit["state"] == "implemented" \
                and not unit["findings_present"]:
            raise SystemExit(
                f"phase20-obligations: {unit['unit']} passed as an instrument but carries no "
                f"property finding, so a passing {unit['observation']} could be read as the "
                f"property it does not claim; the court must record the gap to the level the "
                f"seal names"
            )

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
            "phase20-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: Phase 20 owns no "
            "export, no provider registration row and no prerequisite deferral, so its working "
            "set is exactly the custodian seal contract units docs/PHASE-20-SUBPHASES.md names, "
            "each measured by the Phase-20 courts registry. Every row is read from those atlases; "
            "the ledger types none of them, and `main` fails closed if the ownership atlas assigns "
            "this stratum an export, the provider census assigns it a row, or the prerequisite "
            "plane assigns it a deferral or unit"
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
            "`open` is the only list that blocks this stratum, and its count is over the custodian "
            "seal contract units rather than exported symbols, so the `implemented` and `open` "
            "*export* lists are empty by measurement and `open_in_this_stratum` is the live count. "
            "Phase 20 owns no provider registration row and no export: it activates no provider "
            "and adds no library surface, because it compiles the custodian claim over the "
            "implementation the strata before it completed. Its five contract units are the "
            "custodian seal contract docs/PHASE-20-SUBPHASES.md section 1 names -- the maturity "
            "derivation, the receipt closure, the residual disposition, the substitution witness "
            "and the custodian-boundary register -- and its `counts` block is the live record of "
            "which of them are implemented: 20.1 landed the maturity derivation, 20.2 the receipt "
            "closure, 20.3 the residual disposition, 20.4 the substitution witness and 20.5 the "
            "custodian-boundary-register, so all five contract units are implemented and "
            "`open_in_this_stratum` is zero; 20.6's seal `docs/PHASE-20-CUSTODIAN-SEAL.md` is the "
            "stratum's closure, and because Phase 20 owns no FRF-declarable court its FRF/Gemel "
            "chain entry is vacuous by the rule's own scoping, so the seal document is the "
            "required evidence and it has landed. Nothing here "
            "is a claim "
            "stronger than docs/CUSTODIAN_CONTRACT.md section 6's: a passing custodian court is an "
            "instrument and a bounded measurement, not a universal-parity claim, and there is no "
            "FIPS-validation claim, no claim of universal parity from finite evidence, and no "
            "claim that memory safety is established. Each contract unit records its two axes "
            "separately: `measurement_state` says the instrument completed, and "
            "`property_status`/`findings` say what is claimed about a custodian property. The "
            "`custodian-maturity` unit's property is `NOT_CLAIMED` with the gap between the "
            "evidence-supported level and the level the seal might name recorded as a finding, so "
            "a passing `RT-CUSTODIAN-MATURITY` is an instrument plus a derived measurement and "
            "must never be read as 'L9 custodian seal achieved'."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="phase-20-plan", path=REPO_ROOT / PLAN),
        InputRef(name="phase-20-courts", path=REPO_ROOT / COURTS),
    ]
    doc = envelope(kind="phase20-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase20-obligations] atlas-owned={c['atlas_owned']} "
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
