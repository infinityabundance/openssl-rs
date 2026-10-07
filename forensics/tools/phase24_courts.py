#!/usr/bin/env python3
"""openssl-rs — Phase 24 courts: the downstream-1000 replacement-atlas courts.

Each court is an instrument that makes the downstream-1000 model of `docs/RELEASE_GATES.md`
section 1 mechanical over a frozen, precommitted population of real OpenSSL downstream project
families, not a differential probe over a symbol set. This stratum owns no exported symbol: it
measures whether `openssl-rs` survives the ways real software depends on OpenSSL, so its evidence
is about the ways software consumes the library -- the ranking sources that selected the
population, the families and their separate specimens, the authority baseline each specimen
reached, the frozen P1000 and holdout, the build/link and runtime/functional runs, the classified
residuals, the preserved and minimized failures, the hostility augmentation, the candidate freeze,
the full P1000 run, the reconciliation and the seal. The method is Phases 3 through 23's where an
artefact carries the expectation: each court reads the artefact that holds its subject rather than
typing the expectation beside it, so the two cannot disagree, and a court whose control is not
honest is `fail` rather than `pass`.

**No court is registered at activation.** The stratum's obligations are not exports, so its first
runnable court is a later subphase's, and `run_courts.py` would refuse a stratum in `in-progress`
with no runner at all -- so this runner lands with an empty registry and names the fifteen courts
it will stage, each with the subphase that lands it. The registry is the file `run_courts.py`
checks is reproduced, so a court silently dropped is a finding rather than a smaller green run.
This is the reverse of Phase 16's edge: the ledger's contract-unit states are measured from this
registry, so this runner does **not** bind the obligations ledger as an input.

**Every entry point calls the Docker-only execution guard first.** Phase 24's whole subject is
compiling, linking and running other software, and `docs/REPRODUCIBILITY.md` section 1 says nothing
executes on the host, so `phase24_guard.require_admitted()` is the first statement of `main`.
`--self-test` proves a host invocation is refused by handing the guard the shape of a host
invocation.

The record kinds these courts will populate are defined and self-tested in
`forensics/tools/downstream_schemas.py`; the registry records that schema inventory, and the closed
vocabularies (the L0-L8 execution ladder, the failure taxonomy and the residual classes), so the
record kinds are a file the evidence points at rather than prose the plan would have to restate.

The fifteen courts, and the subphase that lands each
----------------------------------------------------
  * `RT-RANKING-SOURCES` -- 24.1, the frozen ranking-source acquisition.
  * `RT-CANDIDATE-UNIVERSE` -- 24.2, the candidate family universe.
  * `RT-AUTHORITY-BASELINE` -- 24.3, the authority-baseline census.
  * `RT-FAMILY-FREEZE` -- 24.4, the P1000 + reserve freeze.
  * `RT-HOLDOUT-PARTITION` -- 24.5, the precommitted holdout.
  * `RT-BUILD-LINK-ATLAS` -- 24.6, the build/link atlas.
  * `RT-RUNTIME-FUNCTIONAL-ATLAS` -- 24.7, the runtime/functional atlas.
  * `RT-FAILURE-MINIMIZATION` -- 24.8, the failure discovery/minimization loop.
  * `RT-HIGH-VALUE-TIER` -- 24.9, the high-value deep tier.
  * `RT-HOSTILITY-AUGMENTATION` -- 24.10, the separate hostility corpus.
  * `RT-CANDIDATE-FREEZE` -- 24.11, the candidate freeze and holdout.
  * `RT-P1000-RUN` -- 24.12, the final full P1000 run.
  * `RT-ATLAS-RECONCILIATION` -- 24.13, the atlas reconciliation.
  * `RT-FRF-CLOSURE` -- 24.14, the FRF/Gemel closure.
  * `DOWNSTREAM-1000-SEAL` -- 24.15, the seal.

Every one is `pending` at activation. A passing court is an instrument, not a property claim, and
this stratum makes no property claim beyond the atlas: a selected empirical population is not a
random sample, 1000/1000 is not a security proof, a build is not a functional proof, and transitive
and direct consumers are different evidence.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 4.2 is the
precondition. No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

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
import phase24_guard  # noqa: E402

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import downstream_schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase24" / "COURTS.json"
GENERATOR = "forensics/tools/phase24_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "downstream" / "container.json"

# The courts this stratum will stage. **Empty at activation**: 24.0 owns no runnable court, so the
# registry carries none. Each later subphase appends its court here in the commit that lands its
# instrument, and a court removed from the table leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = []

# The fifteen courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order.
PENDING_COURTS: dict[str, str] = {
    "RT-RANKING-SOURCES": "24.1 -- the frozen ranking-source acquisition",
    "RT-CANDIDATE-UNIVERSE": "24.2 -- the candidate family universe",
    "RT-AUTHORITY-BASELINE": "24.3 -- the authority-baseline census",
    "RT-FAMILY-FREEZE": "24.4 -- the P1000 + reserve freeze",
    "RT-HOLDOUT-PARTITION": "24.5 -- the precommitted holdout partition",
    "RT-BUILD-LINK-ATLAS": "24.6 -- the build/link atlas",
    "RT-RUNTIME-FUNCTIONAL-ATLAS": "24.7 -- the runtime/functional atlas",
    "RT-FAILURE-MINIMIZATION": "24.8 -- the failure discovery/minimization loop",
    "RT-HIGH-VALUE-TIER": "24.9 -- the high-value deep tier",
    "RT-HOSTILITY-AUGMENTATION": "24.10 -- the separate hostility-augmentation corpus",
    "RT-CANDIDATE-FREEZE": "24.11 -- the candidate freeze and holdout",
    "RT-P1000-RUN": "24.12 -- the final full P1000 run",
    "RT-ATLAS-RECONCILIATION": "24.13 -- the atlas reconciliation",
    "RT-FRF-CLOSURE": "24.14 -- the FRF/Gemel closure",
    "DOWNSTREAM-1000-SEAL": "24.15 -- the downstream-1000 seal",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--self-test", action="store_true",
                    help="prove a host invocation of this runner is refused by the guard")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. The runner is an execution entry point (its
    # later courts configure, build and run downstream projects), so the manifest does not list it
    # `metadata_only` and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        # Prove the guard refuses a host invocation of this runner, without running on a host.
        refusal = phase24_guard.host_refusal_reasons("phase24_courts.py")
        if not refusal:
            print("[phase24-courts] self-test FAILED: the guard admitted a host invocation of "
                  "the runner")
            return 1
        marker = phase24_guard.load_manifest().get("marker")
        flag = phase24_guard.load_manifest().get("env_flag")
        joined = " ".join(refusal)
        if str(marker) not in joined or str(flag) not in joined:
            print("[phase24-courts] self-test FAILED: the refusal does not name the marker and "
                  "the opt-in flag")
            return 1
        print(f"[phase24-courts] self-test ok: the guard refuses a host invocation of the runner "
              f"({len(refusal)} reason(s), naming the marker and the opt-in flag)")
        return 0

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    records: list[dict] = []
    for name, filename in COURTS:
        # No court is registered at activation, so this loop is inert. It is kept so the first
        # subphase that appends a court stages it here rather than inventing the shape.
        src = REPO_ROOT / "courts" / "phase24" / str(filename)
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
        "schemas": downstream_schemas.inventory(),
        "execution_levels": list(downstream_schemas.EXECUTION_LEVELS),
        "failure_classes": list(downstream_schemas.FAILURE_CLASSES),
        "residual_classes": list(downstream_schemas.RESIDUAL_CLASSES),
        "drop_in_verdicts": list(downstream_schemas.DROP_IN_VERDICTS),
        "claim": (
            "No court is registered at activation: Phase 24 owns no exported symbol, so no "
            "differential probe over a symbol set is its evidence, and its fifteen courts -- "
            "RT-RANKING-SOURCES, RT-CANDIDATE-UNIVERSE, RT-AUTHORITY-BASELINE, RT-FAMILY-FREEZE, "
            "RT-HOLDOUT-PARTITION, RT-BUILD-LINK-ATLAS, RT-RUNTIME-FUNCTIONAL-ATLAS, "
            "RT-FAILURE-MINIMIZATION, RT-HIGH-VALUE-TIER, RT-HOSTILITY-AUGMENTATION, "
            "RT-CANDIDATE-FREEZE, RT-P1000-RUN, RT-ATLAS-RECONCILIATION, RT-FRF-CLOSURE and "
            "DOWNSTREAM-1000-SEAL -- are pending with the subphases that land them (24.1 through "
            "24.15). The stratum's record kinds are defined and self-tested in "
            "forensics/tools/downstream_schemas.py, whose inventory this registry records: the "
            "family (the counted unit, never a package alias), the separate specimen, the "
            "variant, the frozen ranking-source row, the execution-level row over the L0-L8 "
            "ladder, the run, the classified residual, the preserved-and-minimized failure and "
            "the baseline-normalized drop-in verdict. Every entry point calls the Docker-only "
            "execution guard (forensics/tools/phase24_guard.py) first, so nothing in this stratum "
            "executes on the host. The four things the model never claims are: a selected "
            "empirical population is not a random sample; 1000/1000 is not a security proof; a "
            "build is not a functional proof; and transitive and direct consumers are different "
            "evidence. DROP_IN_PASS is baseline-normalized -- the same pristine source, a "
            "succeeded authority baseline, the candidate reaching the authority-applicable level, "
            "candidate linkage proven, and zero candidate-specific downstream patches. "
            "docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 1, 2 and 4 record the "
            "measurement and the precondition."
        ),
    }

    inputs = [
        InputRef(name="phase-24-plan", path=PLAN),
        InputRef(name="downstream-schemas", path=SCHEMAS),
        InputRef(name="phase24-guard", path=GUARD),
        InputRef(name="phase24-container-manifest", path=MANIFEST),
    ]
    doc = envelope(kind="phase24-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  schema inventory: {len(body['schemas'])} record kind(s)")
    print(f"  execution ladder: {len(body['execution_levels'])} level(s); "
          f"{len(body['failure_classes'])} failure class(es); "
          f"{len(body['residual_classes'])} residual class(es)")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
