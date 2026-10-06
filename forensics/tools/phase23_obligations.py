#!/usr/bin/env python3
"""openssl-rs — the Phase 23 obligation ledger, and its unit is not an exported symbol.

Phase 23 is the multitrack authority stratum (`docs/RELEASE_GATES.md` section 1), the model that
lets one Rust implementation emit independently-evidenced compatibility views for the OpenSSL
release lineage. It owns **zero exports**: reading `forensics/atlas/symbol-ownership.json` for
`owner_phase == 23` yields no record, because the declaring-header rule assigns no installed header
to this stratum. `docs/PHASE-23-MULTITRACK-SUBPHASES.md` is its plan and this ledger is the
machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
Its subjects are compatibility *views* over releases and authorities that are already admitted, so
it hands no new library surface forward and receives none. The universe is therefore exactly one
atlas-derived row kind plus a fail-closed reading of the machinery that would be wrong if it
silently acquired work:

  * **the multitrack authority contract units** — twelve authored policy rows naming the surfaces
    `docs/PHASE-23-MULTITRACK-SUBPHASES.md` records, each state derived from the atlas that
    measures it: the release-node catalogue, the authority-node registry, the lineage edges, the
    entity lineage, the delta engine, the compatibility views, the directional compatibility
    edges, the negative obligations, the security lineage, the support-status ladder, the
    compatibility matrix and the multitrack seal (twelve courts in `artifacts/phase23/COURTS.json`);
  * **nothing else.** The ownership atlas assigns this stratum no export, the provider census
    assigns it no registration row, and `forensics/prerequisites.json` records no deferral or
    translation unit owned by phase 23. `main` fails closed if any of those ever stops being true,
    because then this ledger's non-export unit would be the wrong shape rather than a complete
    account.

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and the
two tools that partition the *export* universe — `court_coverage.py` and `ownership_audit.py` —
skip this ledger rather than reconcile a symbol set that does not exist, exactly as they skip Phase
16's `cli-config contract` through Phase 21's `maintenance delta contract`. `main` fails closed if
the ownership atlas ever assigns this stratum an export, because then a non-export unit would be
the wrong shape.

The ledger reads the courts registry, and the runner does not read the ledger
----------------------------------------------------------------------------
The contract-unit states are measured from `artifacts/phase23/COURTS.json`, so the dependency runs
ledger -> courts: `forensics/tools/phase23_courts.py` enters the courts as `pending` and does
**not** bind this ledger as an input. Binding both directions would embed each artefact's digest in
the other and make neither reproducible. `docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 4.2 is the
precondition, exactly as it is for Phases 17 through 21.

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
It does **not** say the property the unit names has been achieved — a passing compatibility court
is never a single boolean, and this stratum makes no one-boolean compatibility claim at all. The
ledger records both axes explicitly so the two cannot be conflated:

  * `measurement_state` — `complete` when the unit's court passed as an instrument, `not_measured`
    otherwise. This is the same fact `state` records.
  * `property_status` — `NOT_CLAIMED` where the unit measures a property and the court recorded
    findings bearing on it, `not_claimed` where the unit makes no such claim.
  * `findings_present` / `findings` — whether the court recorded property findings, and the list
    itself.

`security-lineage` is the property unit: `RT-SECURITY-LINEAGE` passes as an instrument while
recording, as a `finding`, every historical vulnerability observation it could not bind to a
non-reintroduction record, so its property reads `NOT_CLAIMED` with `findings_present`. **A
passing `RT-SECURITY-LINEAGE` must never be read as "the lineage is secure".** The findings are
read from the court row, not typed here; the ledger fails closed if a unit that must carry them
stops doing so.

Outputs
-------
  forensics/phase23-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase23-obligations.json"
GENERATOR = "forensics/tools/phase23_obligations.py"
PHASE = 23
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-23-MULTITRACK-SUBPHASES.md"
COURTS = "artifacts/phase23/COURTS.json"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase
# number those tools know.
UNIT = "multitrack authority contract"

# The twelve contract units whose closure is measured by a court this stratum stages. Each unit is
# a surface the stratum owes multitrack-authority evidence over, and each is closed only when its
# court passes; none of them is a symbol, because the model emits views over releases and
# authorities that are already admitted. `(unit, court, closure, what)`.
COURT_UNITS: tuple[tuple[str, str, str, str], ...] = (
    ("release-nodes", "RT-RELEASE-CATALOG",
     "the `RT-RELEASE-CATALOG` court passes",
     "one release node per upstream release from OpenSSL 0.9.1c forward, read from the committed "
     "archaeology snapshot (`forensics/multitrack/release-archaeology.json`) and the upstream "
     "lineage rather than typed, with the version parser and scheme model in "
     "`forensics/tools/multitrack_schemas.py`"),
    ("authority-nodes", "RT-AUTHORITY-NODES",
     "the `RT-AUTHORITY-NODES` court passes",
     "one authority node per built authority, recording platform, arch, build profile, toolchain, "
     "build environment and binary/installed hashes, so a view is always bounded to a named, "
     "content-addressed build"),
    ("lineage-edges", "RT-LINEAGE-EDGES",
     "the `RT-LINEAGE-EDGES` court passes",
     "the typed chronological / git-ancestry / branch-fork / maintenance-successor / "
     "security-backport edges between release nodes, each stating the direction it is read in"),
    ("entity-lineage", "RT-ENTITY-LINEAGE",
     "the `RT-ENTITY-LINEAGE` court passes",
     "what became of each public entity across releases, with the relation vocabulary of the plan "
     "-- renamed, moved, signature-changed, layout-changed, kind-changed, split, merged, "
     "deprecated, removed, reintroduced, semantic-successor -- and `unknown_relationship` where the "
     "evidence does not settle it"),
    ("delta-engine", "RT-DELTA-ENGINE",
     "the `RT-DELTA-ENGINE` court passes",
     "the added / removed / changed surface between two nodes, computed mechanically from the "
     "atlas and the entity lineage in the direction the lineage edge names, never hand-listed"),
    ("compatibility-views", "RT-COMPATIBILITY-VIEWS",
     "the `RT-COMPATIBILITY-VIEWS` court passes",
     "a directional, dimension-specific view per support status, each naming its reference release "
     "and the release-specific evidence it was derived from -- never a boolean, and never "
     "inheriting a receipt across a version"),
    ("directional-compatibility-edges", "RT-COMPATIBILITY-EDGES",
     "the `RT-COMPATIBILITY-EDGES` court passes",
     "the directional compatibility edges between releases or authorities on one dimension each, "
     "with an evidence kind that is never numeric ordering"),
    ("negative-obligations", "RT-NEGATIVE-OBLIGATIONS",
     "the `RT-NEGATIVE-OBLIGATIONS` court passes",
     "the `must_not_exist` / `must_be_opaque` / `must_not_be_exported` obligations beside the "
     "positive ones, each with evidence and a state, so an absence is a checkable claim rather "
     "than an omission"),
    ("security-lineage", "RT-SECURITY-LINEAGE",
     "the `RT-SECURITY-LINEAGE` court passes",
     "the historical vulnerabilities of the lineage, observed and never reintroduced, with the "
     "observation and the non-reintroduction each recorded so a view can never re-adopt a fixed "
     "behaviour"),
    ("support-status", "RT-SUPPORT-STATUS",
     "the `RT-SUPPORT-STATUS` court passes",
     "the derived support status of each release node over the ladder catalogued, "
     "admitted-source, built-authority, atlas-complete, candidate-view, runtime-evidenced, "
     "downstream-evidenced and maintained, with `archaeological-only` where the node is studied "
     "and not supported"),
    ("compatibility-matrix", "RT-COMPATIBILITY-MATRIX",
     "the `RT-COMPATIBILITY-MATRIX` court passes",
     "the assembled matrix joining the views, the edges, the negative obligations and the "
     "security lineage over the lineage, with every cell a directional, dimension-specific record "
     "and no cell a single boolean"),
    ("multitrack-seal", "MULTITRACK-SEAL",
     "the `MULTITRACK-SEAL` court passes",
     "the closure of the matrix as the stratum's claim, the FRF/Gemel chain rule where the stratum "
     "stages a declarable court, and the seal `docs/PHASE-23-MULTITRACK-SEAL.md`"),
)

# The contract units that measure a **property** rather than an instrument behaviour. The
# security lineage's subject is the non-reintroduction of historical vulnerabilities: while a real
# observation that cannot be bound to a non-reintroduction record is a `finding`, the property
# reads `NOT_CLAIMED`; on a complete lineage it records zero findings and reads `not_claimed`.
PROPERTY_UNITS: frozenset[str] = frozenset({"security-lineage"})

# The property units whose property is **never** claimable by a passing instrument. Phase 23 leaves
# this empty: like Phase 21 and unlike Phase 20's `custodian-maturity`, no multitrack unit's pass
# can be misread as the whole model's claim, because the claim's boundary is the matrix's and is
# carried by `RT-COMPATIBILITY-MATRIX`. The set is kept so the two-axis invariant below is the
# same shape every stratum uses.
SEAL_GAP_UNITS: frozenset[str] = frozenset()


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase23-obligations: {relpath} is absent, so this stratum's universe cannot be "
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
    """`(passed, observation)` for a court in the Phase-23 registry.

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

    Phase 23 emits views over releases and authorities that are already admitted, so it hands
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
    """The multitrack authority contract, each unit's state derived from its own court.

    Two axes are recorded, and they are deliberately distinct. `measurement_state` says whether the
    instrument completed; `property_status`/`findings` say what, if anything, the unit claims about
    a property. `security-lineage`'s court passes while recording every observation it could not
    bind to a non-reintroduction record as a finding, so its property is `NOT_CLAIMED`.
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

    if atlas_owned:
        raise SystemExit(
            f"phase23-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )
    if provider_rows:
        raise SystemExit(
            f"phase23-obligations: the provider census assigns this stratum "
            f"{len(provider_rows)} registration row(s), but Phase 23 activates no provider; the "
            f"census or this ledger's plan is wrong"
        )
    if deferrals or unit_deferrals:
        raise SystemExit(
            f"phase23-obligations: forensics/prerequisites.json records "
            f"{len(deferrals)} deferral(s) and {len(unit_deferrals)} unit deferral(s) owned by "
            f"phase {PHASE}, but Phase 23 hands nothing forward and receives nothing; the "
            f"prerequisite plane or this ledger's plan is wrong"
        )

    contracts = contract_units(courts_body)

    for unit in contracts:
        if unit["unit"] in SEAL_GAP_UNITS and unit["state"] == "implemented" \
                and not unit["findings_present"]:
            raise SystemExit(
                f"phase23-obligations: {unit['unit']} passed as an instrument but carries no "
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
            "phase23-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: Phase 23 owns no "
            "export, no provider registration row and no prerequisite deferral, so its working "
            "set is exactly the multitrack authority contract units docs/PHASE-23-MULTITRACK-SUBPHASES.md "
            "names, each measured by the Phase-23 courts registry. Every row is read from those "
            "atlases; the ledger types none of them, and `main` fails closed if the ownership "
            "atlas assigns this stratum an export, the provider census assigns it a row, or the "
            "prerequisite plane assigns it a deferral or unit"
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
            "multitrack authority contract units rather than exported symbols, so the "
            "`implemented` and `open` *export* lists are empty by measurement and "
            "`open_in_this_stratum` is the live count. Phase 23 owns no provider registration row "
            "and no export: it activates no provider and adds no library surface, because it emits "
            "compatibility views over releases and authorities that are already admitted. Its "
            "twelve contract units are the multitrack authority contract "
            "docs/PHASE-23-MULTITRACK-SUBPHASES.md section 1 names -- the release-node catalogue, "
            "the authority-node registry, the lineage edges, the entity lineage, the delta engine, "
            "the compatibility views, the directional compatibility edges, the negative "
            "obligations, the security lineage, the support-status ladder, the compatibility "
            "matrix and the multitrack seal -- and its `counts` block is the live record of which "
            "of them are implemented: at activation none has a court, so `open_in_this_stratum` "
            "is twelve. Nothing here is a one-boolean compatibility claim: compatibility is "
            "directional and dimension-specific (docs/PARITY_MODEL.md sections 3 and 4), a "
            "cross-version receipt is never inherited (docs/RELEASE_GATES.md section 8, D533), an "
            "authority is named explicitly and singularly rather than selected by a Cargo feature "
            "(D534), and a historical vulnerability is observed but never reintroduced "
            "(docs/SECURITY_DIVERGENCE_POLICY.md section 1). The stratum's explicit non-claims "
            "are: historical API compatibility is not security approval; reproducing an old "
            "algorithm is not recommending it; OpenSSL compatibility is not FIPS validation; one "
            "platform/profile is not every platform/profile; an archaeological source node is not "
            "runtime parity; and upstream's ABI promise is not candidate evidence. Each "
            "contract unit records its two axes separately: `measurement_state` says the "
            "instrument completed, and `property_status`/`findings` say what is claimed. The "
            "`security-lineage` unit's property is `NOT_CLAIMED` with every unbound observation "
            "named as a finding, so a passing `RT-SECURITY-LINEAGE` is an instrument plus an "
            "observation record and must never be read as 'the lineage is secure'."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="phase-23-plan", path=REPO_ROOT / PLAN),
        InputRef(name="phase-23-courts", path=REPO_ROOT / COURTS),
    ]
    doc = envelope(kind="phase23-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase23-obligations] atlas-owned={c['atlas_owned']} "
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
