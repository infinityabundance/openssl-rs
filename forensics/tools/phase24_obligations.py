#!/usr/bin/env python3
"""openssl-rs — the Phase 24 obligation ledger, and its unit is not an exported symbol.

Phase 24 is the downstream-1000 stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md`), the content-addressed, reproducible,
machine-queryable atlas of 1,000 precommitted real OpenSSL downstream project families that
measures whether `openssl-rs` survives the ways real software depends on OpenSSL. It owns **zero
exports**: reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 24` yields no
record, because the declaring-header rule assigns no installed header to this stratum.
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` is its plan and this ledger is the machine-checkable
arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
Its subjects are measured *runs* over a frozen population of downstream project families, so it
hands no new library surface forward and receives none. The universe is therefore exactly one
atlas-derived row kind plus a fail-closed reading of the machinery that would be wrong if it
silently acquired work:

  * **the downstream 1000 contract units** — eighteen authored policy rows naming the surfaces
    `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` records, each state derived from the atlas that
    measures it: the ranking-source acquisition, the candidate universe, the authority-baseline
    census, the P1000+reserve freeze, the holdout partition, the build/link atlas, the
    runtime/functional atlas, the failure discovery/minimization loop, the high-value deep tier,
    the hostility augmentation, the candidate freeze and holdout, the final full P1000 run, the
    atlas reconciliation, the FRF/Gemel closure, the downstream-1000 seal, the biggest-mover
    shared-blocker analysis, the biggest-mover remediation and the recipe-admission campaign
    (eighteen courts in `artifacts/phase24/COURTS.json`);
  * **nothing else.** The ownership atlas assigns this stratum no export, the provider census
    assigns it no registration row, and `forensics/prerequisites.json` records no deferral or
    translation unit owned by phase 24. `main` fails closed if any of those ever stops being true,
    because then this ledger's non-export unit would be the wrong shape rather than a complete
    account.

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and the
two tools that partition the *export* universe — `court_coverage.py` and `ownership_audit.py` —
skip this ledger rather than reconcile a symbol set that does not exist, exactly as they skip Phase
16's `cli-config contract` through Phase 23's `multitrack authority contract`.

The ledger reads the courts registry, and the runner does not read the ledger
----------------------------------------------------------------------------
The contract-unit states are measured from `artifacts/phase24/COURTS.json`, so the dependency runs
ledger -> courts: `forensics/tools/phase24_courts.py` enters the courts as `pending` and does
**not** bind this ledger as an input. Binding both directions would embed each artefact's digest in
the other and make neither reproducible. `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 4.2
is the precondition, exactly as it is for Phases 17 through 23.

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
It does **not** say the property the unit names has been achieved — a passing downstream atlas is
never a security proof, and a build is never a functional proof. The ledger records both axes
explicitly so the two cannot be conflated:

  * `measurement_state` — `complete` when the unit's court passed as an instrument, `not_measured`
    otherwise. This is the same fact `state` records.
  * `property_status` — `NOT_CLAIMED` where the unit measures a property and the court recorded
    findings bearing on it, `not_claimed` where the unit makes no such claim.
  * `findings_present` / `findings` — whether the court recorded property findings, and the list
    itself.

Outputs
-------
  forensics/phase24-obligations.json

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

# The Docker-only execution guard. Its call is the first statement of `main`: this generator reads
# committed atlases and executes nothing, so the guard admits it as `metadata_only` on any host
# exactly as the other strata's obligation generators run host-side; a tool that would configure,
# build or run a downstream project is not in that list and is refused on the host.
import phase24_guard  # noqa: E402

OUT = REPO_ROOT / "forensics" / "phase24-obligations.json"
GENERATOR = "forensics/tools/phase24_obligations.py"
PHASE = 24
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"
COURTS = "artifacts/phase24/COURTS.json"
GUARD = "forensics/tools/phase24_guard.py"
SCHEMAS = "forensics/tools/downstream_schemas.py"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase
# number those tools know.
UNIT = "downstream 1000 contract"

# The nineteen contract units whose closure is measured by a court this stratum stages. Each unit is
# a surface the stratum owes downstream-1000 evidence over, and each is closed only when its court
# passes; none of them is a symbol, because the model measures runs over a frozen population of
# downstream project families. `(unit, court, closure, what)`.
COURT_UNITS: tuple[tuple[str, str, str, str], ...] = (
    ("ranking-sources", "RT-RANKING-SOURCES",
     "the `RT-RANKING-SOURCES` court passes",
     "the frozen, multi-source ranking evidence acquired and content-addressed **before** any "
     "candidate result exists, so the population cannot be selected by what the candidate happens "
     "to pass (the pre-commitment rule)"),
    ("candidate-universe", "RT-CANDIDATE-UNIVERSE",
     "the `RT-CANDIDATE-UNIVERSE` court passes",
     "one family node per real downstream project **family** -- never a package alias -- with its "
     "specimens kept separate, its OpenSSL linkage (direct or transitive) named, and its ranking "
     "provenance recorded"),
    ("authority-census", "RT-AUTHORITY-CENSUS",
     "the `RT-AUTHORITY-CENSUS` court passes",
     "one authority-baseline census per specimen, recording the level the pristine-source build "
     "reached against the admitted authority, so a candidate pass is normalized against what the "
     "authority itself achieved"),
    ("family-freeze", "RT-FAMILY-FREEZE",
     "the `RT-FAMILY-FREEZE` court passes",
     "the frozen P1000 population of 1,000 counted families plus the reserve, selected from the "
     "precommitted ranking evidence and content-addressed before any candidate result"),
    ("holdout-partition", "RT-HOLDOUT-PARTITION",
     "the `RT-HOLDOUT-PARTITION` court passes",
     "the precommitted holdout partition, fixed before the candidate was run against the "
     "development population and never used to choose a patch"),
    ("build-link-atlas", "RT-BUILD-LINK-ATLAS",
     "the `RT-BUILD-LINK-ATLAS` court passes",
     "one build/link run per specimen per subject (authority and candidate), reaching the "
     "configured, built and linked levels with candidate linkage proven"),
    ("runtime-functional-atlas", "RT-RUNTIME-FUNCTIONAL-ATLAS",
     "the `RT-RUNTIME-FUNCTIONAL-ATLAS` court passes",
     "one runtime/functional run per specimen that reached the build/link levels, reaching the "
     "loaded, runtime and functional levels where the authority baseline did"),
    ("failure-minimization", "RT-FAILURE-MINIMIZATION",
     "the `RT-FAILURE-MINIMIZATION` court passes",
     "every discovered failure classified from the failure taxonomy, preserved and minimized, so "
     "a failure is a named, reproducible record rather than a discarded run"),
    ("high-value-tier", "RT-HIGH-VALUE-TIER",
     "the `RT-HIGH-VALUE-TIER` court passes",
     "the high-value deep tier: the families that depend on OpenSSL most deeply are measured past "
     "the shallow levels, to the functional level, where they can be"),
    ("hostility-augmentation", "RT-HOSTILITY-AUGMENTATION",
     "the `RT-HOSTILITY-AUGMENTATION` court passes",
     "the separate hostility-augmentation corpus, kept apart from the counted P1000 families and "
     "never mixed into the population's rates"),
    ("candidate-freeze", "RT-CANDIDATE-FREEZE",
     "the `RT-CANDIDATE-FREEZE` court passes",
     "the candidate identity frozen and content-addressed, and the precommitted holdout run "
     "against it exactly once, so the holdout is a real out-of-sample measurement"),
    ("p1000-run", "RT-P1000-RUN",
     "the `RT-P1000-RUN` court passes",
     "the final full P1000 run over the frozen population at the frozen candidate, so every "
     "family's drop-in verdict is measured against the same candidate rather than a moving one"),
    ("atlas-reconciliation", "RT-ATLAS-RECONCILIATION",
     "the `RT-ATLAS-RECONCILIATION` court passes",
     "the reconciliation of the atlas: every counted family has a verdict, every residual is "
     "classified, every failure is preserved and minimized, and the drop-in rates are computed "
     "over the frozen population rather than typed"),
    ("frf-gemel-closure", "RT-FRF-CLOSURE",
     "the `RT-FRF-CLOSURE` court passes",
     "the FRF/Gemel chain closure where the stratum stages a declarable court, so a passing atlas "
     "is not read as a chain that never ran"),
    ("downstream-1000-seal", "DOWNSTREAM-1000-SEAL",
     "the `DOWNSTREAM-1000-SEAL` court passes",
     "the seal `docs/PHASE-24-DOWNSTREAM-1000-SEAL.md`, which closes the atlas as the stratum's "
     "claim and records the four non-claims it never exceeds"),
    ("blocker-leverage", "RT-BLOCKER-LEVERAGE",
     "the `RT-BLOCKER-LEVERAGE` court passes",
     "the biggest-mover shared-blocker analysis `forensics/downstream/shared-blockers.json`, which "
     "partitions the counted families by their deepest blocker, ranks the classes by their mover "
     "potential and per-fix leverage, and renders `docs/PHASE-24-BIGGEST-MOVERS.md`, the "
     "`README.md` block and the census's biggest-movers section so 24.17 can act on the biggest "
     "movers rather than on the largest class by breadth"),
    ("blocker-remediation", "RT-BLOCKER-REMEDIATION",
     "the `RT-BLOCKER-REMEDIATION` court passes",
     "the biggest-mover remediation record `forensics/downstream/blocker-remediation.json`, which "
     "records the exact recipe/flag/fixture each repair applied, preserves the 24.16 blocker "
     "partition as its `before`, re-derives the re-measured `after` from the committed planes, and "
     "computes the movement -- so what was repaired and what the planes then measured is a "
     "measurement rather than a claim, and what could not be repaired in the fixed venue is "
     "recorded still-blocked"),
    ("recipe-campaign", "RT-RECIPE-CAMPAIGN",
     "the `RT-RECIPE-CAMPAIGN` court passes",
     "the recipe-admission campaign record `forensics/downstream/recipe-campaign.json`, which selects "
     "a candidate list from the committed evidence by a stated heuristic rule, attempts at least 40 "
     "recipe-less counted families, classifies each release tarball's build system empirically, and "
     "admits only the venue-buildable ones into the shared recipe catalogue under the "
     "identical-build-intent rule -- recording every attempt (admitted or not) with its outcome and "
     "reason, so the campaign's yield is visible and a recipe that was not built is never admitted"),
    ("close-batch", "RT-CLOSE-BATCH",
     "the `RT-CLOSE-BATCH` court passes",
     "the close-candidate reclamation batch `forensics/downstream/close-batch.json`, which attempts "
     "the 24.18 linkage misses, its dead-URL pins and a fresh deterministic draw from the remaining "
     "recipe-less counted families, admits only the recipes actually built and linked against both "
     "subjects under the identical-build-intent rule, classifies a family that builds but links no "
     "OpenSSL subject as a finding rather than forcing it to link, and records every attempt with "
     "its outcome and reason"),
)

# The contract units that measure a **property** rather than an instrument behaviour. The atlas
# reconciliation's subject is the population's drop-in rates: while a real residual or a preserved
# failure is a `finding`, the property reads `NOT_CLAIMED`; on a fully reconciled atlas it records
# zero findings and reads `not_claimed`.
PROPERTY_UNITS: frozenset[str] = frozenset({"atlas-reconciliation", "downstream-1000-seal"})

# The property units whose property is **never** claimable by a passing instrument. The seal is the
# stratum's claim, and a passing seal is an instrument plus an observation record: it records the
# four non-claims (a selected empirical population is not a random sample; 1000/1000 is not a
# security proof; a build is not a functional proof; transitive and direct consumers are different
# evidence) as findings, so the seal's property is never read as "the downstream ecosystem is
# safe". The set is kept so the two-axis invariant below is the same shape every stratum uses.
SEAL_GAP_UNITS: frozenset[str] = frozenset({"downstream-1000-seal"})


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase24-obligations: {relpath} is absent, so this stratum's universe cannot be "
            f"derived; the read is fail-closed rather than empty"
        )
    return json.loads(p.read_text(encoding="utf-8"))


def court_row(courts_body: dict, court: str) -> dict:
    """The registry row for a court, or an empty row when nothing names it."""
    for row in courts_body.get("courts") or []:
        if row.get("court") == court:
            return row
    return {}


def court_state(courts_body: dict, court: str) -> tuple[bool, str]:
    """`(passed, observation)` for a court in the Phase-24 registry.

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

    Phase 24 measures runs over downstream projects that are already identified, so it hands
    nothing forward and receives nothing: the ownership atlas assigns it no export, the provider
    census no registration row, and `forensics/prerequisites.json` no deferral or translation
    unit. Each is returned so the ledger can count it (zero at activation) and fail closed if it
    ever acquires one.
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
    """The downstream 1000 contract, each unit's state derived from its own court.

    Two axes are recorded, and they are deliberately distinct. `measurement_state` says whether the
    instrument completed; `property_status`/`findings` say what, if anything, the unit claims about
    a property. The seal's court passes while recording the four non-claims as findings, so its
    property is `NOT_CLAIMED`.
    """
    units: list[dict] = []
    for name, court, closure, what in COURT_UNITS:
        passed, observation = court_state(courts_body, court)
        row = court_row(courts_body, court)
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
                "measurement_state": "complete" if passed else "not_measured",
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
    del args

    # The Docker-only execution guard, called first. This ledger generator executes nothing, so the
    # guard admits it as `metadata_only`; a host invocation of an execution entry point is refused.
    phase24_guard.require_admitted()

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    ownership = load(OWNERSHIP)["body"]
    provider_body = load(PROVIDERS)["body"]
    prereq = load(PREREQUISITES)["body"]
    courts_body = load(COURTS)["body"]

    machinery = machinery_rows(ownership, provider_body, prereq)
    atlas_owned = machinery["atlas_owned"]
    provider_rows = machinery["provider_rows"]
    deferrals = machinery["deferrals"]
    unit_deferrals = machinery["unit_deferrals"]

    if atlas_owned:
        raise SystemExit(
            f"phase24-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )
    if provider_rows:
        raise SystemExit(
            f"phase24-obligations: the provider census assigns this stratum "
            f"{len(provider_rows)} registration row(s), but Phase 24 activates no provider; the "
            f"census or this ledger's plan is wrong"
        )
    if deferrals or unit_deferrals:
        raise SystemExit(
            f"phase24-obligations: forensics/prerequisites.json records "
            f"{len(deferrals)} deferral(s) and {len(unit_deferrals)} unit deferral(s) owned by "
            f"phase {PHASE}, but Phase 24 hands nothing forward and receives nothing; the "
            f"prerequisite plane or this ledger's plan is wrong"
        )

    contracts = contract_units(courts_body)

    for unit in contracts:
        if unit["unit"] in SEAL_GAP_UNITS and unit["state"] == "implemented" \
                and not unit["findings_present"]:
            raise SystemExit(
                f"phase24-obligations: {unit['unit']} passed as an instrument but carries no "
                f"property finding, so a passing {unit['observation']} could be read as the "
                f"property it does not claim; the court must record the gap"
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
            "phase24-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: Phase 24 owns no "
            "export, no provider registration row and no prerequisite deferral, so its working "
            "set is exactly the downstream 1000 contract units "
            "docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md names, each measured by the Phase-24 "
            "courts registry. Every row is read from those atlases; the ledger types none of "
            "them, and `main` fails closed if the ownership atlas assigns this stratum an export, "
            "the provider census assigns it a row, or the prerequisite plane assigns it a "
            "deferral or unit"
        ),
        "unit": UNIT,
        "counts": counts,
        "implemented": [],
        "open": [],
        "deferred": [],
        "provider_rows": provider_rows,
        "deferrals": deferrals,
        "unit_deferrals": unit_deferrals,
        "contract_units": contracts,
        "note": (
            "`open` is the only list that blocks this stratum, and its count is over the "
            "downstream 1000 contract units rather than exported symbols, so the `implemented` "
            "and `open` *export* lists are empty by measurement and `open_in_this_stratum` is the "
            "live count. Phase 24 owns no provider registration row and no export: it activates "
            "no provider and adds no library surface, because it measures runs over a frozen "
            "population of downstream project families. Its nineteen contract units are the "
            "downstream 1000 contract docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md section 1 names "
            "-- the ranking-source acquisition, the candidate universe, the authority-baseline "
            "census, the P1000+reserve freeze, the holdout partition, the build/link atlas, the "
            "runtime/functional atlas, the failure discovery/minimization loop, the high-value "
            "deep tier, the hostility augmentation, the candidate freeze and holdout, the final "
            "full P1000 run, the atlas reconciliation, the FRF/Gemel closure, the downstream-1000 "
            "seal, the biggest-mover shared-blocker analysis, the biggest-mover remediation, the "
            "recipe-admission campaign and the close-candidate reclamation -- "
            "and its `counts` block is the live record of which of them are implemented. "
            "Every entry point calls the Docker-only execution guard "
            "(`forensics/tools/phase24_guard.py`) first, so on the host the stratum refuses "
            "rather than compiling or running anything (docs/REPRODUCIBILITY.md section 1). "
            "The stratum's explicit non-claims are: a selected empirical population is not a "
            "random sample, so its rates do not generalise to all downstream software; 1000/1000 "
            "is not a security proof, so a full pass is not a guarantee that any consumer is "
            "safe; a build is not a functional proof, so compiling and linking is not behaving; "
            "and transitive and direct consumers are different evidence, so a project that only "
            "links a library transitively is a different measurement from one that calls the API "
            "directly. `DROP_IN_PASS` is baseline-normalized and never a boolean of its own: it "
            "requires the same pristine source, the authority baseline succeeded, the candidate "
            "reached the authority-applicable level, candidate linkage proven, and zero "
            "candidate-specific downstream patches; residuals are classified from the residual "
            "classes and failures preserved and minimized from the failure taxonomy. Each "
            "contract unit records its two axes separately: `measurement_state` says the "
            "instrument completed, and `property_status`/`findings` say what is claimed. The "
            "`downstream-1000-seal` unit's property is `NOT_CLAIMED` with the four non-claims "
            "named as findings, so a passing `DOWNSTREAM-1000-SEAL` is an instrument plus an "
            "observation record and must never be read as 'the downstream ecosystem is safe'."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="phase-24-plan", path=REPO_ROOT / PLAN),
        InputRef(name="phase-24-courts", path=REPO_ROOT / COURTS),
        InputRef(name="phase24-guard", path=REPO_ROOT / GUARD),
        InputRef(name="downstream-schemas", path=REPO_ROOT / SCHEMAS),
    ]
    doc = envelope(kind="phase24-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase24-obligations] atlas-owned={c['atlas_owned']} "
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
