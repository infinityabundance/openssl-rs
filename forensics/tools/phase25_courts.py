#!/usr/bin/env python3
"""openssl-rs — Phase 25 courts: the memory-safety, unsafe-TCB and CVE-extinction courts.

Each court is an instrument that makes the memory-safety model of `docs/RELEASE_GATES.md` section 1
mechanical over the exact admitted candidate's shipped first-party source/build surface, not a
differential probe over a symbol set. This stratum owns no exported symbol: it inventories the
memory-safety-relevant trusted computing base, maps compiler-derived unsafe operations to their
safety contracts, their Phase-22 reachability, their Phase-24 downstream usage and the available
dynamic/formal evidence, and reconciles the historical OpenSSL CVEs against the candidate's
structure. The method is Phases 3 through 24's where an artefact carries the expectation: each
court reads the artefact that holds its subject rather than typing the expectation beside it, so the
two cannot disagree, and a court whose control is not honest is `fail` rather than `pass`.

**No court was registered at activation, and 25.1 registers the first.** The stratum's
obligations are not exports, so its first runnable court is a later subphase's, and
`run_courts.py` would refuse a stratum in `in-progress` with no runner at all -- so this runner
landed at activation with an empty registry, naming the twenty-two courts it will stage each with
the subphase that lands it. **25.1 registers `MS-SOURCE-CENSUS`**, the compiler-backed source
census: it reads the committed `artifacts/phase25/source-census.json` and re-runs the 25.1 pure
checks (`ms_census.census_findings`, `ms_census.census_sensitivity_control`) over it without a
compiler, so the census's own measurement is the court's subject. The registry is the file
`run_courts.py` checks is reproduced, so a court silently dropped is a finding rather than a
smaller green run. This is the reverse of Phase 16's edge: the ledger's contract-unit states are
measured from this registry, so this runner does **not** bind the obligations ledger as an input.

**Every entry point calls the Docker-only execution guard first.** Phase 25's whole subject is
executing tools -- a compiler-backed census, Miri, ASan/MSan, TSan, Kani, the CVE replays -- and
`docs/REPRODUCIBILITY.md` section 1 says nothing executes on the host, so
`phase25_guard.require_admitted()` is the first statement of `main`. `--self-test` proves a host
invocation is refused by handing the guard the shape of a host invocation.

The record kinds these courts will populate are defined and self-tested in
`forensics/tools/memory_safety_schemas.py`; the registry records that schema inventory, and the
closed vocabularies (the unsafe-operation kinds, the obligation dimensions, the exposure classes,
the tool states, the CVE taxonomy, the CVE replay states, the risk tiers and the panic/unwind
classes), so the record kinds are a file the evidence points at rather than prose the plan would
have to restate.

The twenty-two courts, and the subphase that lands each
-------------------------------------------------------
  * `MS-CONSTITUTION` -- 25.0, the constitution.
  * `MS-SOURCE-CENSUS` -- 25.1, the compiler-backed census.
  * `MS-NON-RUST-TCB` -- 25.2, the non-Rust TCB.
  * `MS-SAFETY-OBLIGATIONS` -- 25.3, the safety obligations.
  * `MS-OWNERSHIP-PLANES` -- 25.4, the ownership/allocation/callback planes.
  * `MS-PHASE22-CROSSWALK` -- 25.5, the Phase-22 crosswalk.
  * `MS-PHASE24-CROSSWALK` -- 25.6, the Phase-24 crosswalk.
  * `MS-EXPOSURE-CLASSIFICATION` -- 25.7, the exposure/data-flow classification.
  * `MS-UNSAFE-REDUCTION` -- 25.8, the unsafe reduction.
  * `MS-MIRI` -- 25.9, Miri.
  * `MS-ASAN-MSMAN` -- 25.10, ASan/MSan.
  * `MS-TSAN` -- 25.11, TSan.
  * `MS-KANI` -- 25.12, Kani.
  * `MS-PHASE18-FUZZ-CROSSWALK` -- 25.13, the Phase-18 fuzz crosswalk.
  * `MS-PHASE24-SAFETY-COVERAGE` -- 25.14, the Phase-24 downstream safety coverage.
  * `MS-HISTORICAL-CVE` -- 25.15, the historical CVE census.
  * `MS-CVE-REPLAY` -- 25.16, the historical CVE replay.
  * `MS-MECHANISM-RECONCILIATION` -- 25.17, the vulnerability-mechanism reconciliation.
  * `MS-RED-TEAM` -- 25.18, the red team.
  * `MS-CLEAN-REGEN` -- 25.19, the full clean regeneration.
  * `MS-FRF-CLOSURE` -- 25.20, the FRF/Gemel closure.
  * `MS-SEAL` -- 25.21, the seal.

Every one is `pending` at activation and each becomes a registered, re-derivable court as the
subphase that lands its instrument commits. A passing court is an instrument, not a property claim,
and this stratum makes no claim beyond its bounded one: safe Rust does not prove protocol
correctness, unsafe Rust is not inherently vulnerable, unsafe LOC is not a vulnerability count,
Miri/ASan/TSan are not exhaustive, Kani does not prove unsupported or concurrent whole-program
behaviour, and historical CVE extinction does not predict a future CVE count.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 4 is the precondition.
No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

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

# The Docker-only execution guard. Its call is the first statement of `main`, and `--self-test`
# proves a host invocation is refused.
import phase25_guard  # noqa: E402

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import memory_safety_schemas  # noqa: E402

# 25.1's census tool and the artefact it writes. The court re-runs the tool's pure
# `census_findings` / `census_sensitivity_control` over the committed artefact; it does **not** run
# the compiler (the measurement that produced the artefact is the `ms_census.py --measure` run).
import ms_census  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "COURTS.json"
GENERATOR = "forensics/tools/phase25_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
# 25.1's compiler-backed source census.
SOURCE_CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
MS_CENSUS_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_census.py"
SOURCE_CENSUS_COURT = "MS-SOURCE-CENSUS"

# The courts this stratum stages. **25.0 owns no runnable court**, so this table was empty at
# activation; **25.1 registers `MS-SOURCE-CENSUS`**, the compiler-backed source census, and each
# later subphase appends its court here in the commit that lands its instrument. A court removed
# from the table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (SOURCE_CENSUS_COURT, "_ms_source_census_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. 25.1 removed
# `MS-SOURCE-CENSUS`, so twenty-one remain. Ordered as the plan orders them.
PENDING_COURTS: dict[str, str] = {
    "MS-CONSTITUTION": "25.0 -- the constitution (the plan, schemas, guard, manifest, ledger and runner)",
    "MS-NON-RUST-TCB": "25.2 -- the non-Rust trusted computing base",
    "MS-SAFETY-OBLIGATIONS": "25.3 -- the safety obligations",
    "MS-OWNERSHIP-PLANES": "25.4 -- the ownership/allocation/callback planes",
    "MS-PHASE22-CROSSWALK": "25.5 -- the Phase-22 reachability crosswalk",
    "MS-PHASE24-CROSSWALK": "25.6 -- the Phase-24 downstream crosswalk",
    "MS-EXPOSURE-CLASSIFICATION": "25.7 -- the exposure/data-flow classification",
    "MS-UNSAFE-REDUCTION": "25.8 -- the unsafe reduction",
    "MS-MIRI": "25.9 -- Miri",
    "MS-ASAN-MSMAN": "25.10 -- ASan/MSan",
    "MS-TSAN": "25.11 -- TSan",
    "MS-KANI": "25.12 -- Kani",
    "MS-PHASE18-FUZZ-CROSSWALK": "25.13 -- the Phase-18 fuzz crosswalk",
    "MS-PHASE24-SAFETY-COVERAGE": "25.14 -- the Phase-24 downstream safety coverage",
    "MS-HISTORICAL-CVE": "25.15 -- the historical CVE census",
    "MS-CVE-REPLAY": "25.16 -- the historical CVE replay",
    "MS-MECHANISM-RECONCILIATION": "25.17 -- the vulnerability-mechanism reconciliation",
    "MS-RED-TEAM": "25.18 -- the red team",
    "MS-CLEAN-REGEN": "25.19 -- the full clean regeneration",
    "MS-FRF-CLOSURE": "25.20 -- the FRF/Gemel closure",
    "MS-SEAL": "25.21 -- the memory-safety seal",
}


def _ms_source_census_court(name: str) -> dict:
    """`MS-SOURCE-CENSUS`: 25.1's court, the compiler-backed source census.

    Stages no probe. It reads the committed `artifacts/phase25/source-census.json` and re-runs the
    25.1 pure checks `ms_census.census_findings` and `ms_census.census_sensitivity_control` over the
    committed artefact -- no compiler, no clippy, no nightly; the measurement that produced the
    census is `ms_census.py --measure`, and this court only re-derives from what it wrote. It
    establishes that every shipped first-party file is accounted for with a matching digest; that
    every site is compiler-derived and resolves to a compiler-identified context; that site and
    context ids are stable and unique; that the context/site back-references are consistent; that
    the per-file counts, the counts block and the LOC arithmetic are derived rather than typed; and
    that every cross-check disagreement is recorded as a classified residual. Five seeded
    mutations -- a fabricated raw dereference, an unsafe operation hidden by dropping its
    macro-generated context, a removed safety contract, a site forged as safe, and a dropped file
    -- are each caught with specificity holding. It is an **instrument**: it can pass while the
    census records real property findings (contexts with no source-stated contract, contexts that
    hold no classified operation, and the cross-check residuals), which are recorded as the row's
    `findings` so a passing census is never read as a memory-safety claim.
    """
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    doc = json.loads(SOURCE_CENSUS.read_text(encoding="utf-8"))
    body = doc.get("body", doc)
    problems = ms_census.census_findings(body)
    control = ms_census.census_sensitivity_control(body)

    counts = body.get("counts") or {}
    loc = body.get("loc") or {}
    cross = body.get("crosschecks") or {}
    toolchain = body.get("toolchain") or {}
    residuals = body.get("residuals") or []

    # Property findings: what the census observes that is not a defect of the instrument. They are
    # recorded so a passing court is never read as the property it does not claim.
    findings = [
        f"{counts.get('uncontracted_contexts', 0)} compiler-identified unsafe context(s) carry no "
        f"source-stated SAFETY contract (recorded open; 25.3 owns the obligations)",
        f"{counts.get('contexts_without_site', 0)} unsafe context(s) hold no classified operation "
        f"(a declaration, not an operation)",
        f"{len(residuals)} cross-check residual(s): "
        + "; ".join(f"{r.get('source')}/{r.get('class')}" for r in residuals),
    ]

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/source-census.json and "
            "re-runs the 25.1 pure checks (ms_census.census_findings and "
            "ms_census.census_sensitivity_control) over it, without a compiler. The census was "
            "derived by one clippy run with the built-in `unsafe_code` lint (the enumerating "
            "authority) plus the three named documentation lints, --message-format=json, and the "
            "macro-expanded source from a pinned nightly. It establishes file coverage, "
            "compiler-derivedness of every site, stable/unique ids, consistent back-references, "
            "derived counts and the LOC split, and that every cross-check disagreement is a "
            "classified residual; five seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the census court reads the committed census and re-derives only its pure checks, so "
            "it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "toolchain": toolchain,
        "counts": {
            "files": counts.get("files", 0),
            "unsafe_contexts": counts.get("unsafe_contexts", 0),
            "sites": counts.get("sites", 0),
            "generated_files": counts.get("generated_files", 0),
            "uncontracted_contexts": counts.get("uncontracted_contexts", 0),
            "contexts_without_site": counts.get("contexts_without_site", 0),
            "residuals": len(residuals),
        },
        "sites_by_kind": counts.get("sites_by_kind") or {},
        "contexts_by_kind": counts.get("contexts_by_kind") or {},
        "loc": loc,
        "crosschecks": {
            "geiger": (cross.get("geiger") or {}).get("status"),
            "lexical_unsafe_keywords": (cross.get("lexical") or {}).get(
                "unsafe_keyword_occurrences"),
            "residual_count": cross.get("residual_count"),
        },
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--self-test", action="store_true",
                    help="prove a host invocation of this runner is refused by the guard")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. The runner is an execution entry point (its
    # later courts compile the census, run the sanitizers, the proof harnesses and the CVE replays),
    # so the manifest does not list it `metadata_only` and a host invocation is refused.
    phase25_guard.require_admitted()

    if args.self_test:
        # Prove the guard refuses a host invocation of this runner, without running on a host.
        refusal = phase25_guard.host_refusal_reasons("phase25_courts.py")
        if not refusal:
            print("[phase25-courts] self-test FAILED: the guard admitted a host invocation of "
                  "the runner")
            return 1
        marker = phase25_guard.load_manifest().get("marker")
        flag = phase25_guard.load_manifest().get("env_flag")
        joined = " ".join(refusal)
        if str(marker) not in joined or str(flag) not in joined:
            print("[phase25-courts] self-test FAILED: the refusal does not name the marker and "
                  "the opt-in flag")
            return 1
        print(f"[phase25-courts] self-test ok: the guard refuses a host invocation of the runner "
              f"({len(refusal)} reason(s), naming the marker and the opt-in flag)")
        return 0

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    records: list[dict] = []
    for name, handler in COURTS:
        # Each registered court stages no probe -- this stratum owns no exported symbol, so no
        # differential probe over a symbol set is its evidence -- and each is computed here rather
        # than read back from disk, so no digest cycle forms. The handler is named in the table and
        # resolved here, so a court added to COURTS without a function is a loud failure.
        fn = globals().get(str(handler))
        if fn is None:
            records.append({"court": name, "verdict": "fail", "stage": "handler-missing",
                            "detail": str(handler)})
            continue
        records.append(fn(name))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        "all_pass": failed == 0 and len(records) == len(COURTS),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": failed},
        "pending_courts": PENDING_COURTS,
        "schemas": memory_safety_schemas.inventory(),
        "unsafe_operation_kinds": list(memory_safety_schemas.UNSAFE_OPERATION_KINDS),
        "obligation_dimensions": list(memory_safety_schemas.OBLIGATION_DIMENSIONS),
        "exposure_classes": list(memory_safety_schemas.EXPOSURE_CLASSES),
        "externally_reachable_exposure": sorted(memory_safety_schemas.EXTERNALLY_REACHABLE_EXPOSURE),
        "tool_states": list(memory_safety_schemas.TOOL_STATES),
        "cve_taxonomy": list(memory_safety_schemas.CVE_TAXONOMY),
        "cve_replay_states": list(memory_safety_schemas.CVE_REPLAY_STATES),
        "risk_tiers": list(memory_safety_schemas.RISK_TIERS),
        "panic_unwind_classes": list(memory_safety_schemas.PANIC_UNWIND_CLASSES),
        "claim": (
            "**25.1 registers `MS-SOURCE-CENSUS`**, the compiler-backed source census: it reads the "
            "committed artifacts/phase25/source-census.json and re-runs the 25.1 pure checks over "
            "it without a compiler, so the census's own measurement (`ms_census.py --measure`, one "
            "clippy run plus a pinned-nightly expansion) is the court's subject and the court is a "
            "pure re-derivation of it. Phase 25 owns no exported symbol, so no differential probe "
            "over a symbol set is its evidence; the remaining twenty-one of its twenty-two courts "
            "-- MS-CONSTITUTION, MS-NON-RUST-TCB, MS-SAFETY-OBLIGATIONS, "
            "MS-OWNERSHIP-PLANES, MS-PHASE22-CROSSWALK, MS-PHASE24-CROSSWALK, "
            "MS-EXPOSURE-CLASSIFICATION, MS-UNSAFE-REDUCTION, MS-MIRI, MS-ASAN-MSMAN, MS-TSAN, "
            "MS-KANI, MS-PHASE18-FUZZ-CROSSWALK, MS-PHASE24-SAFETY-COVERAGE, MS-HISTORICAL-CVE, "
            "MS-CVE-REPLAY, MS-MECHANISM-RECONCILIATION, MS-RED-TEAM, MS-CLEAN-REGEN, "
            "MS-FRF-CLOSURE and MS-SEAL -- are pending with the subphases that land them (25.2 "
            "through 25.21). The stratum's record kinds are defined and self-tested in "
            "forensics/tools/memory_safety_schemas.py, whose inventory this registry records: the "
            "source-census row, the compiler-derived unsafe site, the unsafe context, the safety "
            "obligation, the FFI boundary, the C adapter, the allocation site, the ownership edge, "
            "the callback lifetime, the unsafe Send/Sync impl, the global state, the panic "
            "boundary, the Miri/ASan/MSan/TSan/Kani results, the Phase-18 fuzz crosswalk, the "
            "coverage row, the historical CVE, the CVE replay, the vulnerability mechanism, the "
            "residual and the seal-class summary. The **primary unit is a compiler-derived unsafe "
            "operation**, and lines of unsafe code are a secondary projection, never the security "
            "claim. Every entry point calls the Docker-only execution guard "
            "(forensics/tools/phase25_guard.py) first, so nothing in this stratum executes on the "
            "host. A tool state of UNSUPPORTED is never PASS, and a CANDIDATE_STRUCTURALLY_EXCLUDED "
            "CVE replay must cite its evidence. The bounded claim is that the memory-safety-"
            "relevant trusted computing base of the exact admitted candidate has been exhaustively "
            "inventoried over its first-party shipped source/build surface, with unsafe operations "
            "mapped to their safety contracts, Phase-22 reachability, Phase-24 downstream usage and "
            "available dynamic/formal evidence, and with no unexplained reachable unsafe site in "
            "the claimed profile. It is not 'no memory-safety bug can exist' and not '100% memory "
            "safe'; docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 0, 1, 2 and 4 record the "
            "measurement and the precondition."
        ),
    }

    inputs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="source-census", path=SOURCE_CENSUS),
        InputRef(name="ms-census-tool", path=MS_CENSUS_TOOL),
    ]
    doc = envelope(kind="phase25-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            c = r.get("counts") or {}
            ctrl = r.get("control") or {}
            print(f"  {r['court']:<32} pass   (no probe, files={c.get('files')} "
                  f"contexts={c.get('unsafe_contexts')} sites={c.get('sites')} "
                  f"residuals={c.get('residuals')} uncontracted={c.get('uncontracted_contexts')}; "
                  f"{len(r.get('findings') or [])} finding(s); control honest={ctrl.get('honest')} "
                  f"specificity={ctrl.get('specificity_holds')} "
                  f"caught={ctrl.get('caught')}/{ctrl.get('seeded')})")
    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  schema inventory: {len(body['schemas'])} record kind(s)")
    print(f"  unsafe-operation kinds: {len(body['unsafe_operation_kinds'])}; "
          f"obligation dimensions: {len(body['obligation_dimensions'])}; "
          f"exposure classes: {len(body['exposure_classes'])}; "
          f"tool states: {len(body['tool_states'])}")
    print(f"  CVE taxonomy: {len(body['cve_taxonomy'])} class(es); "
          f"CVE replay states: {len(body['cve_replay_states'])}; "
          f"risk tiers: {len(body['risk_tiers'])}; "
          f"panic/unwind classes: {len(body['panic_unwind_classes'])}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
