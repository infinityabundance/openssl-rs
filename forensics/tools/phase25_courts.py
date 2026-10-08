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

**No court is registered at activation.** The stratum's obligations are not exports, so its first
runnable court is a later subphase's, and `run_courts.py` would refuse a stratum in `in-progress`
with no runner at all -- so this runner lands with an empty registry and names the twenty-two courts
it will stage, each with the subphase that lands it. The registry is the file `run_courts.py`
checks is reproduced, so a court silently dropped is a finding rather than a smaller green run. This
is the reverse of Phase 16's edge: the ledger's contract-unit states are measured from this
registry, so this runner does **not** bind the obligations ledger as an input.

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

Every one is `pending` at activation. A passing court is an instrument, not a property claim, and
this stratum makes no claim beyond its bounded one: safe Rust does not prove protocol correctness,
unsafe Rust is not inherently vulnerable, unsafe LOC is not a vulnerability count, Miri/ASan/TSan
are not exhaustive, Kani does not prove unsupported or concurrent whole-program behaviour, and
historical CVE extinction does not predict a future CVE count.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 4 is the precondition.
No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0
"""

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

# The Docker-only execution guard. Its call is the first statement of `main`, and `--self-test`
# proves a host invocation is refused.
import phase25_guard  # noqa: E402

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import memory_safety_schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "COURTS.json"
GENERATOR = "forensics/tools/phase25_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# The courts this stratum will stage. **Empty at activation**: 25.0 owns no runnable court, so the
# registry carries none. Each later subphase appends its court here in the commit that lands its
# instrument, and a court removed from the table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = []

# The twenty-two courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order.
PENDING_COURTS: dict[str, str] = {
    "MS-CONSTITUTION": "25.0 -- the constitution (the plan, schemas, guard, manifest, ledger and runner)",
    "MS-SOURCE-CENSUS": "25.1 -- the compiler-backed source census",
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
    for name, filename in COURTS:
        # No court is registered at activation, so this loop is inert. It is kept so the first
        # subphase that appends a court stages it here rather than inventing the shape.
        src = REPO_ROOT / "courts" / "phase25" / str(filename)
        records.append({"court": name, "verdict": "fail", "stage": "probe-missing",
                        "detail": rel(src)})

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
            "No court is registered at activation: Phase 25 owns no exported symbol, so no "
            "differential probe over a symbol set is its evidence, and its twenty-two courts -- "
            "MS-CONSTITUTION, MS-SOURCE-CENSUS, MS-NON-RUST-TCB, MS-SAFETY-OBLIGATIONS, "
            "MS-OWNERSHIP-PLANES, MS-PHASE22-CROSSWALK, MS-PHASE24-CROSSWALK, "
            "MS-EXPOSURE-CLASSIFICATION, MS-UNSAFE-REDUCTION, MS-MIRI, MS-ASAN-MSMAN, MS-TSAN, "
            "MS-KANI, MS-PHASE18-FUZZ-CROSSWALK, MS-PHASE24-SAFETY-COVERAGE, MS-HISTORICAL-CVE, "
            "MS-CVE-REPLAY, MS-MECHANISM-RECONCILIATION, MS-RED-TEAM, MS-CLEAN-REGEN, "
            "MS-FRF-CLOSURE and MS-SEAL -- are pending with the subphases that land them (25.0 "
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
    ]
    doc = envelope(kind="phase25-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

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
