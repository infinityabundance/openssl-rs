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

**The first court is registered by 24.1.** The stratum's obligations are not exports, so its
first runnable court is a later subphase's, and `run_courts.py` would refuse a stratum in
`in-progress` with no runner at all -- so this runner lands at activation with an empty registry
and names the fifteen courts it will stage. **24.1 registers `RT-RANKING-SOURCES`**, the frozen
ranking-source acquisition: it reads `forensics/downstream/ranking-sources.json` and the committed
normalized inputs under `forensics/downstream/ranking/normalized/`, re-derives the frozen
`selection_input_root_hash`, and checks every source is content-addressed with a retrieval
timestamp and a parser version, that an unavailable source carries a reason and is not counted
present, and that the acquisition is reproducible -- with an instrument-sensitivity control that
seeds four mutations and requires each caught. The registry is the file `run_courts.py` checks is
reproduced, so a court silently dropped is a finding rather than a smaller green run. This is the
reverse of Phase 16's edge: the ledger's contract-unit states are measured from this registry, so
this runner does **not** bind the obligations ledger as an input.

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
  * `RT-RANKING-SOURCES` -- 24.1, the frozen ranking-source acquisition (registered).
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

Every one was `pending` at activation; 24.1 registers `RT-RANKING-SOURCES` and the remaining
fourteen are pending. A passing court is an instrument, not a property claim, and this stratum
makes no property claim beyond the atlas: a selected empirical population is not a random sample,
1000/1000 is not a security proof, a build is not a functional proof, and transitive and direct
consumers are different evidence.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 4.2 is the
precondition. No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

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
import phase24_guard  # noqa: E402

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import downstream_schemas  # noqa: E402

# The 24.1 acquisition tool, imported so the court re-runs its pure validation and sensitivity
# control over the committed manifest (never fetching) through the same code path the manifest was
# produced by (never a second, drifting predicate).
import downstream_sources  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase24" / "COURTS.json"
GENERATOR = "forensics/tools/phase24_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "downstream" / "container.json"

# 24.1's subject: the frozen ranking-source manifest and the committed normalized inputs the court
# re-hashes and re-derives the frozen root from. The court reads them; it never fetches.
RANKING_SOURCES = REPO_ROOT / "forensics" / "downstream" / "ranking-sources.json"
RANKING_SOURCES_COURT = "RT-RANKING-SOURCES"

# The courts this stratum stages. 24.1 registers `RT-RANKING-SOURCES`; each later subphase appends
# its court here in the commit that lands its instrument, and a court removed from the table leaves
# the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (RANKING_SOURCES_COURT, "_ranking_sources_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order. `RT-RANKING-SOURCES` moves out of
# this table and into `COURTS` in the commit that lands its instrument (24.1).
PENDING_COURTS: dict[str, str] = {
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


def _ranking_sources_court(name: str) -> dict:
    """`RT-RANKING-SOURCES`: 24.1's court, the frozen ranking-source acquisition.

    Stages no probe. It reads the committed manifest `forensics/downstream/ranking-sources.json`
    and the committed normalized inputs, re-derives the frozen `selection_input_root_hash`, and
    establishes that every source is content-addressed (raw payload SHA-256 and normalization
    SHA-256) with a retrieval timestamp and a parser version, that an available source's committed
    normalized input hashes to its recorded digest, that an unavailable source carries a reason and
    is not counted present, and that the acquisition is reproducible from its committed recipe and
    digest. Four seeded mutations are each caught with specificity holding. A passing ranking-source
    manifest is a **precommitment**, not a ranking claim: it says the selection input was frozen
    before any candidate result, not that any family is important.
    """
    if not RANKING_SOURCES.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the ranking-source manifest {rel(RANKING_SOURCES)} is absent"],
                "findings": [], "control": {}}

    body = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))
    manifest = body.get("body", body)
    normalized = downstream_sources.load_committed(manifest)
    findings = downstream_sources.ranking_source_findings(manifest, normalized)
    control = downstream_sources.ranking_sensitivity_control(manifest, normalized)

    counts = manifest.get("counts") or {}
    sources = [{
        "source_id": row.get("source_id"),
        "kind": row.get("kind"),
        "availability": row.get("availability"),
        "sha256": row.get("sha256"),
        "retrieved_at": row.get("retrieved_at"),
        "size_bytes": row.get("size_bytes"),
        "row_count": row.get("row_count"),
        "repository_timestamp": row.get("repository_timestamp"),
        "parser_version": row.get("parser_version"),
    } for row in manifest.get("sources", [])]

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/ranking-sources.json and the committed "
            "normalized inputs under forensics/downstream/ranking/normalized/, and re-runs the "
            "24.1 validation and sensitivity control over the committed manifest without "
            "fetching. It establishes that every source is content-addressed by its raw payload "
            "SHA-256 and its normalization SHA-256, carries a retrieval timestamp and a parser "
            "version, and is reproducible from its deterministic retrieval recipe; that an "
            "available source's committed normalized input hashes to its recorded digest; that "
            "the frozen selection_input_root_hash reproduces from the present sources; and that "
            "an unavailable source carries a reason and is not counted present. A source stripped "
            "of its hash, a mutated normalized payload, an unavailable source counted present and "
            "a missing retrieval timestamp are each detected with specificity holding "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 1, 2 and 3.4)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the ranking-source court reads a committed manifest and committed normalized inputs "
            "and stages no artifacts/phase24/probes/ pair, so it takes no transcript to diff and "
            "carries no FRF declaration"
        ),
        "selection_input_root_hash": manifest.get("selection_input_root_hash"),
        "counts": {
            "sources": counts.get("sources", len(sources)),
            "available": counts.get("available", 0),
            "unavailable": counts.get("unavailable", 0),
            "normalized_rows": counts.get("normalized_rows", 0),
        },
        "sources": sources,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
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
        "schemas": downstream_schemas.inventory(),
        "execution_levels": list(downstream_schemas.EXECUTION_LEVELS),
        "failure_classes": list(downstream_schemas.FAILURE_CLASSES),
        "residual_classes": list(downstream_schemas.RESIDUAL_CLASSES),
        "drop_in_verdicts": list(downstream_schemas.DROP_IN_VERDICTS),
        "claim": (
            "`RT-RANKING-SOURCES` is 24.1's court: the frozen ranking-source acquisition. It "
            "stages no probe and reads forensics/downstream/ranking-sources.json and the "
            "committed normalized inputs under forensics/downstream/ranking/normalized/, "
            "re-running the 24.1 validation and sensitivity control without fetching. It "
            "establishes that every acquired ranking / reverse-dependency source -- the Debian "
            "reverse-dependency graph and Popcon counts, the Fedora and Alpine reverse package "
            "dependencies, Homebrew openssl@3's dependency relationships and analytics, the "
            "OpenSSF Scorecard and the crates.io reverse-dependency count -- is content-addressed "
            "by its raw payload SHA-256 and its normalization SHA-256, carries a retrieval "
            "timestamp and a parser version, and is reproducible from its deterministic retrieval "
            "recipe; that the frozen selection_input_root_hash reproduces from the present "
            "sources; and that an unavailable source (the OpenSSF Criticality Score, which has no "
            "reproducible public endpoint) carries a reason and is not counted present. A source "
            "stripped of its hash, a mutated normalized payload, an unavailable source counted "
            "present and a missing retrieval timestamp are each detected with specificity "
            "holding. A passing ranking-source manifest is a precommitment, not a ranking claim: "
            "it says the selection input was frozen before any candidate result. The remaining "
            "fourteen courts -- RT-CANDIDATE-UNIVERSE, RT-AUTHORITY-BASELINE, RT-FAMILY-FREEZE, "
            "RT-HOLDOUT-PARTITION, RT-BUILD-LINK-ATLAS, RT-RUNTIME-FUNCTIONAL-ATLAS, "
            "RT-FAILURE-MINIMIZATION, RT-HIGH-VALUE-TIER, RT-HOSTILITY-AUGMENTATION, "
            "RT-CANDIDATE-FREEZE, RT-P1000-RUN, RT-ATLAS-RECONCILIATION, RT-FRF-CLOSURE and "
            "DOWNSTREAM-1000-SEAL -- are pending with the subphases that land them (24.2 through "
            "24.15). Phase 24 owns no exported symbol, so no differential probe over a symbol "
            "set is its evidence. The stratum's record kinds are defined and self-tested in "
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
    # 24.1's subject: the committed ranking-source manifest and every committed normalized input /
    # raw payload it binds, so the court's evidence is content-addressed rather than restated.
    if RANKING_SOURCES.is_file():
        inputs.append(InputRef(name="ranking-sources", path=RANKING_SOURCES))
        rbody = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))
        for row in (rbody.get("body", rbody).get("sources") or []):
            path = row.get("normalized_path")
            if path:
                inputs.append(InputRef(name=f"normalized/{row['source_id']}",
                                       path=REPO_ROOT / path))
            for payload in row.get("raw_payloads") or []:
                if payload.get("committed_path"):
                    inputs.append(InputRef(
                        name=f"raw/{row['source_id']}/{payload['role']}",
                        path=REPO_ROOT / payload["committed_path"]))
    doc = envelope(kind="phase24-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass" and r["court"] == RANKING_SOURCES_COURT:
            c = r["control"]
            counts = r["counts"]
            print(f"  {r['court']:<32} pass   (no probe, {counts['sources']} source(s) "
                  f"{counts['available']} available {counts['unavailable']} unavailable; "
                  f"{counts['normalized_rows']} normalized row(s); "
                  f"root={r['selection_input_root_hash'][:16]}...; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"no-hash->{c['caught_no_hash']} "
                  f"mutated->{c['caught_mutated_payload']} "
                  f"counted-present->{c['caught_unavailable_counted_present']} "
                  f"no-timestamp->{c['caught_missing_retrieval_timestamp']})")
            for s in r["sources"]:
                print(f"      {s['source_id']:<28} {s['kind']:<18} {s['availability']:<11} "
                      f"{(s['sha256'] or '')[:12]:<12} rows={s['row_count']:<5} "
                      f"retrieved={s['retrieved_at']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] != "pass":
            print(f"  {r['court']:<32} FAIL   stage={r.get('stage', 'derive')}")
            for p in (r.get("problems") or [])[:12]:
                print(f"      {p}")
            for f in (r.get("findings") or [])[:12]:
                print(f"      finding: {f}")
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
