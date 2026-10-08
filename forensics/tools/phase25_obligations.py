#!/usr/bin/env python3
"""openssl-rs — the Phase 25 obligation ledger, and its unit is not an exported symbol.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`), the memory-safety atlas, the unsafe
trusted-computing-base census and the historical CVE extinction court. It owns **zero exports**:
reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 25` yields no record, because
the declaring-header rule assigns no installed header to this stratum.
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` is its plan and this ledger is the machine-checkable
arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
Its subjects are the twenty-two contract units the plan names, one per subphase 25.0 through 25.21,
so it hands no new library surface forward and receives none. The universe is therefore exactly one
atlas-derived row kind plus a fail-closed reading of the machinery that would be wrong if it
silently acquired work:

  * **the memory-safety contract units** — twenty-two authored policy rows naming the surfaces
    `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` records, each state derived from the atlas that
    measures it: the constitution, the compiler-backed source census, the non-Rust TCB, the safety
    obligations, the ownership/allocation/callback planes, the Phase-22 and Phase-24 crosswalks, the
    exposure/data-flow classification, the unsafe reduction, Miri, ASan/MSan, TSan, Kani, the
    Phase-18 fuzz crosswalk, the Phase-24 downstream safety coverage, the historical CVE census, the
    historical CVE replay, the vulnerability-mechanism reconciliation, the red team, the full clean
    regeneration, the FRF/Gemel closure and the memory-safety seal (twenty-two courts in
    `artifacts/phase25/COURTS.json`);
  * **nothing else.** The ownership atlas assigns this stratum no export, the provider census
    assigns it no registration row, and `forensics/prerequisites.json` records no deferral or
    translation unit owned by phase 25. `main` fails closed if any of those ever stops being true,
    because then this ledger's non-export unit would be the wrong shape rather than a complete
    account.

Because the unit is not a symbol, `body.unit` names it in `atlas_common.NON_EXPORT_UNITS`, and the
two tools that partition the *export* universe — `court_coverage.py` and `ownership_audit.py` —
skip this ledger rather than reconcile a symbol set that does not exist, exactly as they skip Phase
16's `cli-config contract` through Phase 24's `downstream 1000 contract`.

The ledger reads the courts registry, and the runner does not read the ledger
----------------------------------------------------------------------------
The contract-unit states are measured from `artifacts/phase25/COURTS.json`, so the dependency runs
ledger -> courts: `forensics/tools/phase25_courts.py` enters the courts as `pending` and does
**not** bind this ledger as an input. Binding both directions would embed each artefact's digest in
the other and make neither reproducible. `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 4 is the
precondition, exactly as it is for Phases 17 through 24.

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
It does **not** say the property the unit names has been achieved — a passing census is never a
proof of memory safety, and a passing sanitizer is never exhaustive. The ledger records both axes
explicitly so the two cannot be conflated:

  * `measurement_state` — `complete` when the unit's court passed as an instrument, `not_measured`
    otherwise. This is the same fact `state` records.
  * `property_status` — `NOT_CLAIMED` where the unit measures a property and the court recorded
    findings bearing on it, `not_claimed` where the unit makes no such claim.
  * `findings_present` / `findings` — whether the court recorded property findings, and the list
    itself.

Outputs
-------
  forensics/phase25-obligations.json

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
# exactly as the other strata's obligation generators run host-side; a tool that would compile,
# instrument, prove or replay is not in that list and is refused on the host.
import phase25_guard  # noqa: E402

OUT = REPO_ROOT / "forensics" / "phase25-obligations.json"
GENERATOR = "forensics/tools/phase25_obligations.py"
PHASE = 25
OWNERSHIP = "forensics/atlas/symbol-ownership.json"
PROVIDERS = "forensics/atlas/provider-algorithms.json"
PREREQUISITES = "forensics/prerequisites.json"
PLAN = "docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
COURTS = "artifacts/phase25/COURTS.json"
GUARD = "forensics/tools/phase25_guard.py"
SCHEMAS = "forensics/tools/memory_safety_schemas.py"

# The ledger's unit. Its presence in `atlas_common.NON_EXPORT_UNITS` is what makes the
# export-partitioning tools skip this ledger; it is a property of the document, not a phase
# number those tools know.
UNIT = "memory-safety contract"

# The twenty-two contract units whose closure is measured by a court this stratum stages. Each unit
# is a surface the stratum owes memory-safety evidence over, and each is closed only when its court
# passes; none of them is a symbol, because the model measures compiler-derived unsafe operations
# over the shipped first-party surface. `(unit, court, closure, what)`.
COURT_UNITS: tuple[tuple[str, str, str, str], ...] = (
    ("constitution", "MS-CONSTITUTION",
     "the `MS-CONSTITUTION` court passes",
     "the plan, the record schemas, the Docker-only execution guard, the committed venue manifest, "
     "the ledger and the runner -- the authored non-export constitution the later subphases fill, "
     "with the closed vocabularies of unsafe-operation kinds, obligation dimensions, exposure "
     "classes, tool states, CVE taxonomy, CVE replay states, risk tiers and panic/unwind classes"),
    ("source-census", "MS-SOURCE-CENSUS",
     "the `MS-SOURCE-CENSUS` court passes",
     "one compiler-derived row per shipped first-party source/build file, with the unsafe "
     "operations the **compiler** establishes rather than a regex or a LOC projection, so the "
     "primary unit is a compiler-derived unsafe operation and LOC is a secondary projection"),
    ("non-rust-tcb", "MS-NON-RUST-TCB",
     "the `MS-NON-RUST-TCB` court passes",
     "the non-Rust part of the trusted computing base: the first-party C sources and headers, the "
     "inline assembly, the exported FFI boundaries, the C adapters and the variadic boundaries, "
     "each classified and given a safety contract"),
    ("safety-obligations", "MS-SAFETY-OBLIGATIONS",
     "the `MS-SAFETY-OBLIGATIONS` court passes",
     "one safety obligation per unsafe site along its dimension (nullability, lifetime, aliasing, "
     "alignment, initialization, bounds, ownership, refcount, thread affinity, ABI, unwind, type "
     "validity and the rest), each naming how it is discharged or recorded open"),
    ("ownership-planes", "MS-OWNERSHIP-PLANES",
     "the `MS-OWNERSHIP-PLANES` court passes",
     "the ownership, allocation and callback planes: the allocation/deallocation associations, the "
     "ownership edges across the Rust/C boundary, the callback lifetimes, the unsafe Send/Sync "
     "impls, the global/static state and the panic/unwind boundaries"),
    ("phase22-crosswalk", "MS-PHASE22-CROSSWALK",
     "the `MS-PHASE22-CROSSWALK` court passes",
     "the crosswalk from the memory-safety census to the Phase-22 whole-program reachability "
     "atlas, so each unsafe site's reachability is the Phase-22 authority's answer rather than a "
     "second, typed one"),
    ("phase24-crosswalk", "MS-PHASE24-CROSSWALK",
     "the `MS-PHASE24-CROSSWALK` court passes",
     "the crosswalk from the memory-safety census to the Phase-24 downstream-1000 atlas, so each "
     "unsafe site's downstream usage is the Phase-24 measurement's answer rather than a typed one"),
    ("exposure-classification", "MS-EXPOSURE-CLASSIFICATION",
     "the `MS-EXPOSURE-CLASSIFICATION` court passes",
     "the exposure/data-flow classification of every unsafe site into the closed exposure classes "
     "(unreachable-profile, test-only, internal, local-API, config, CLI-input, network-client, "
     "network-server, downstream-runtime-observed), so a site is reachable by measurement rather "
     "than by assertion"),
    ("unsafe-reduction", "MS-UNSAFE-REDUCTION",
     "the `MS-UNSAFE-REDUCTION` court passes",
     "the unsafe reduction worklist: the reachable unsafe sites reduced by a safe intrinsic or a "
     "checked wrapper where the venue can, each reduction with its before/after compiler-derived "
     "sites and the sites that remain named rather than dropped, so nothing is weakened to shrink "
     "the count"),
    ("miri", "MS-MIRI",
     "the `MS-MIRI` court passes",
     "the Miri results over the claimed profile, each with its tool state (pass, fail, "
     "not-reachable or unsupported) and its unsupported reason where it could not express the "
     "question, so an unsupported target is never read as a pass"),
    ("asan-msan", "MS-ASAN-MSMAN",
     "the `MS-ASAN-MSMAN` court passes",
     "the ASan and MSan results over the claimed profile, each with its tool state and its "
     "unsupported reason, so a sanitizer that cannot instrument a target is recorded rather than "
     "counted as clean"),
    ("tsan", "MS-TSAN",
     "the `MS-TSAN` court passes",
     "the TSan results over the concurrency-relevant surface of the claimed profile, each with its "
     "tool state and its unsupported reason, so a data race the tool could not observe is not read "
     "as absent"),
    ("kani", "MS-KANI",
     "the `MS-KANI` court passes",
     "the Kani harness results over the stated harnesses and their targets, each with its tool "
     "state and its unsupported reason, and no claim beyond the harnesses that exist: Kani proves "
     "what a supported harness expresses, not unsupported or concurrent whole-program behaviour"),
    ("phase18-fuzz-crosswalk", "MS-PHASE18-FUZZ-CROSSWALK",
     "the `MS-PHASE18-FUZZ-CROSSWALK` court passes",
     "the crosswalk from the memory-safety census to the Phase-18 hostile-fuzz courts, so a "
     "discovered memory-safety failure is a preserved Phase-18 record rather than a discarded run"),
    ("phase24-safety-coverage", "MS-PHASE24-SAFETY-COVERAGE",
     "the `MS-PHASE24-SAFETY-COVERAGE` court passes",
     "the safety coverage of the Phase-24 downstream corpus: which unreduced unsafe sites the "
     "downstream runs actually exercise, and which reachable sites no downstream measurement "
     "observes, so a reachable site is never assumed exercised"),
    ("historical-cve-census", "MS-HISTORICAL-CVE",
     "the `MS-HISTORICAL-CVE` court passes",
     "the historical OpenSSL CVE census, each memory-safety-relevant CVE classified from the closed "
     "CVE taxonomy with its affected versions and its fix, so the record is a classified census "
     "rather than a count"),
    ("cve-replay", "MS-CVE-REPLAY",
     "the `MS-CVE-REPLAY` court passes",
     "the historical CVE replay: each CVE's disposition for the exact admitted candidate in the "
     "closed replay states, where a `CANDIDATE_STRUCTURALLY_EXCLUDED` disposition must cite the "
     "structure that makes the mechanism inexpressible and an unsafe path that remains is named "
     "rather than erased"),
    ("mechanism-reconciliation", "MS-MECHANISM-RECONCILIATION",
     "the `MS-MECHANISM-RECONCILIATION` court passes",
     "the vulnerability-mechanism reconciliation: each mechanism class is reconciled against the "
     "candidate's structure and the replay evidence, and a structural immunity is stated with its "
     "reason and its evidence, so historical CVE extinction is a mechanism statement and never a "
     "prediction of a future CVE count"),
    ("red-team", "MS-RED-TEAM",
     "the `MS-RED-TEAM` court passes",
     "the red-team pass over the claimed profile: the reachable unsafe sites attacked with "
     "adversarial inputs and configurations, each attempt recorded with its outcome, so an "
     "unexplained reachable unsafe site is a finding rather than an omission"),
    ("clean-regeneration", "MS-CLEAN-REGEN",
     "the `MS-CLEAN-REGEN` court passes",
     "the full clean regeneration of the memory-safety census and its evidence from the frozen "
     "candidate and the frozen toolchain, so the atlas is reproducible rather than assembled, and "
     "a PASS that does not survive the regeneration is a finding"),
    ("frf-gemel-closure", "MS-FRF-CLOSURE",
     "the `MS-FRF-CLOSURE` court passes",
     "the FRF/Gemel chain closure where the stratum stages a declarable court, so a passing atlas "
     "is not read as a chain that never ran"),
    ("memory-safety-seal", "MS-SEAL",
     "the `MS-SEAL` court passes",
     "the seal `docs/PHASE-25-MEMORY-SAFETY-SEAL.md`, which closes the bounded claim and records "
     "the non-claims it never exceeds"),
)

# The contract units that measure a **property** rather than an instrument behaviour. The
# mechanism reconciliation's subject is the candidate's immunity to the historical mechanisms, and
# the seal's subject is the bounded claim: a recorded finding on either reads `NOT_CLAIMED`.
PROPERTY_UNITS: frozenset[str] = frozenset({"mechanism-reconciliation", "memory-safety-seal"})

# The property units whose property is **never** claimable by a passing instrument. The seal is the
# stratum's claim, and a passing seal is an instrument plus an observation record: it records the
# non-claims (safe Rust does not prove protocol correctness; unsafe Rust is not inherently
# vulnerable; unsafe LOC is not a vulnerability count; Miri/ASan/TSan are not exhaustive; Kani does
# not prove unsupported or concurrent whole-program behaviour; historical CVE extinction does not
# predict a future CVE count; compatibility is not security; memory safety is not cryptographic
# correctness; absence of a crash is not structural proof) as findings, so the seal's property is
# never read as "the candidate is memory safe". The set is kept so the two-axis invariant below is
# the same shape every stratum uses.
SEAL_GAP_UNITS: frozenset[str] = frozenset({"memory-safety-seal"})


def load(relpath: str) -> dict:
    """Read an atlas, failing closed when it is absent.

    A missing atlas is a fatal rather than an empty result: a ledger whose universe silently
    shrinks to nothing is exactly the failure mode this file exists to prevent.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        raise SystemExit(
            f"phase25-obligations: {relpath} is absent, so this stratum's universe cannot be "
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
    """`(passed, observation)` for a court in the Phase-25 registry.

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

    Phase 25 measures compiler-derived unsafe operations over the shipped surface, so it hands
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
    """The memory-safety contract, each unit's state derived from its own court.

    Two axes are recorded, and they are deliberately distinct. `measurement_state` says whether the
    instrument completed; `property_status`/`findings` say what, if anything, the unit claims about
    a property. The seal's court passes while recording the non-claims as findings, so its property
    is `NOT_CLAIMED`.
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
    phase25_guard.require_admitted()

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
            f"phase25-obligations: the ownership atlas now assigns this stratum "
            f"{len(atlas_owned)} export(s) ({', '.join(r['symbol'] for r in atlas_owned[:6])}), "
            f"but this ledger's unit is `{UNIT}`; a stratum with exports needs an export ledger"
        )
    if provider_rows:
        raise SystemExit(
            f"phase25-obligations: the provider census assigns this stratum "
            f"{len(provider_rows)} registration row(s), but Phase 25 activates no provider; the "
            f"census or this ledger's plan is wrong"
        )
    if deferrals or unit_deferrals:
        raise SystemExit(
            f"phase25-obligations: forensics/prerequisites.json records "
            f"{len(deferrals)} deferral(s) and {len(unit_deferrals)} unit deferral(s) owned by "
            f"phase {PHASE}, but Phase 25 hands nothing forward and receives nothing; the "
            f"prerequisite plane or this ledger's plan is wrong"
        )

    contracts = contract_units(courts_body)

    for unit in contracts:
        if unit["unit"] in SEAL_GAP_UNITS and unit["state"] == "implemented" \
                and not unit["findings_present"]:
            raise SystemExit(
                f"phase25-obligations: {unit['unit']} passed as an instrument but carries no "
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
            "phase25-obligations: the ledger does not account for exactly its own working set: "
            f"owned={owned} implemented={implemented_count} open={open_count}"
        )

    body = {
        "rule": (
            "this stratum's working set is not a set of exported symbols: Phase 25 owns no "
            "export, no provider registration row and no prerequisite deferral, so its working "
            "set is exactly the memory-safety contract units "
            "docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md names, each measured by the Phase-25 "
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
            "memory-safety contract units rather than exported symbols, so the `implemented` and "
            "`open` *export* lists are empty by measurement and `open_in_this_stratum` is the live "
            "count. Phase 25 owns no provider registration row and no export: it activates no "
            "provider and adds no library surface, because it measures compiler-derived unsafe "
            "operations over the shipped first-party surface. Its twenty-two contract units are "
            "the memory-safety contract docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 1 names "
            "-- the constitution, the compiler-backed source census, the non-Rust TCB, the safety "
            "obligations, the ownership/allocation/callback planes, the Phase-22 and Phase-24 "
            "crosswalks, the exposure/data-flow classification, the unsafe reduction, Miri, "
            "ASan/MSan, TSan, Kani, the Phase-18 fuzz crosswalk, the Phase-24 downstream safety "
            "coverage, the historical CVE census, the historical CVE replay, the "
            "vulnerability-mechanism reconciliation, the red team, the full clean regeneration, "
            "the FRF/Gemel closure and the memory-safety seal -- and its `counts` block is the "
            "live record of which of them are implemented: at activation none has a court, so "
            "`open_in_this_stratum` is twenty-two. Every entry point calls the Docker-only "
            "execution guard (`forensics/tools/phase25_guard.py`) first, so on the host the "
            "stratum refuses rather than compiling, instrumenting, proving or replaying anything "
            "(docs/REPRODUCIBILITY.md section 1). The primary unit is a **compiler-derived unsafe "
            "operation**, and lines of unsafe code are a secondary projection, never the security "
            "claim. The stratum's explicit non-claims are: safe Rust does not prove protocol "
            "correctness; unsafe Rust is not inherently vulnerable; unsafe LOC is not a "
            "vulnerability count; Miri, ASan and TSan are not exhaustive; Kani does not prove "
            "unsupported or concurrent whole-program behaviour; historical CVE extinction does not "
            "predict a future CVE count; compatibility is not security; memory safety is not "
            "cryptographic correctness; and absence of a crash is not structural proof. A tool "
            "state of `UNSUPPORTED` is never `PASS`, and a `CANDIDATE_STRUCTURALLY_EXCLUDED` CVE "
            "replay must cite its evidence. Each contract unit records its two axes separately: "
            "`measurement_state` says the instrument completed, and `property_status`/`findings` "
            "say what is claimed. The `memory-safety-seal` unit's property is `NOT_CLAIMED` with "
            "the non-claims named as findings, so a passing `MS-SEAL` is an instrument plus an "
            "observation record and must never be read as 'the candidate is memory safe'."
        ),
    }

    inputs = [
        InputRef(name="symbol-ownership", path=REPO_ROOT / OWNERSHIP),
        InputRef(name="provider-algorithms", path=REPO_ROOT / PROVIDERS),
        InputRef(name="prerequisites", path=REPO_ROOT / PREREQUISITES),
        InputRef(name="phase-25-plan", path=REPO_ROOT / PLAN),
        InputRef(name="phase-25-courts", path=REPO_ROOT / COURTS),
        InputRef(name="phase25-guard", path=REPO_ROOT / GUARD),
        InputRef(name="memory-safety-schemas", path=REPO_ROOT / SCHEMAS),
    ]
    doc = envelope(kind="phase25-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = counts
    print(f"[phase25-obligations] atlas-owned={c['atlas_owned']} "
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
