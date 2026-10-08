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
ranking-source acquisition, **24.2 registers `RT-CANDIDATE-UNIVERSE`**, the candidate family
universe, **24.3 registers `RT-AUTHORITY-CENSUS`**, the authority-baseline census, and **24.4
registers `RT-FAMILY-FREEZE`**, the P1000 + reserve freeze, and **24.5 registers
registers `RT-HOLDOUT-PARTITION`**, the precommitted holdout partition, and **24.6 registers
`RT-BUILD-LINK-ATLAS`**, the build/link atlas, and **24.7 registers
`RT-RUNTIME-FUNCTIONAL-ATLAS`**, the runtime/functional atlas, and **24.8 registers
`RT-FAILURE-MINIMIZATION`**, the failure discovery/minimization loop, and **24.9 registers
`RT-HIGH-VALUE-TIER`**, the high-value deep tier, and **24.10 registers
`RT-HOSTILITY-AUGMENTATION`**, the separate hostility-augmentation corpus, and **24.11 registers
`RT-CANDIDATE-FREEZE`**, the candidate freeze and the once-run holdout, **24.12 registers
`RT-P1000-RUN`**, the final full P1000 run at the frozen candidate, and **24.13 registers
`RT-ATLAS-RECONCILIATION`**, the reconciliation of the atlas. `RT-RANKING-SOURCES` reads `forensics/downstream/ranking-sources.json` and the committed
normalized inputs under `forensics/downstream/ranking/normalized/`, re-derives the frozen
`selection_input_root_hash`, and checks every source is content-addressed with a retrieval
timestamp and a parser version, that an unavailable source carries a reason and is not counted
present, and that the acquisition is reproducible -- with an instrument-sensitivity control that
seeds four mutations and requires each caught. `RT-CANDIDATE-UNIVERSE` reads the committed
`forensics/downstream/candidates.json` and `forensics/downstream/families.json`, re-derives them
from those same committed normalized inputs, and checks every family is schema-valid and
provenance-backed, that aliases of one upstream collapse to one family, that a fork is not
independent without evidence, that a transitive consumer is not counted as direct, and that the
universe is substantially larger than 1,000 before deduplication -- with an instrument-sensitivity
control that seeds four mutations and requires each caught. `RT-AUTHORITY-CENSUS` reads the
committed `forensics/downstream/authority-baselines.jsonl` and
`forensics/downstream/usage-fingerprints.json`, re-derives the provisional census cohort from the
committed families, and checks every cohort member has an authority result classified, that an
`AUTHORITY_BASELINE_FAIL` carries an authority failure class and a reason and is never a candidate
failure, that a `AUTHORITY_BASELINE_PASS`'s linkage proof resolves the admitted authority and not a
system libssl, and that no candidate execution occurred -- with an instrument-sensitivity control
that seeds four mutations and requires each caught. `RT-FAMILY-FREEZE` reads the committed
`forensics/downstream/family-freeze.json` and the committed `forensics/downstream/families.json`,
re-derives the ranked universe from those families by the frozen selection rule, and checks that
atlas. It establishes that the recorded P1000 is exactly the derived top-1,000 and the reserve the
derived remainder in rank order; that the P1000 is distinct and disjoint from the reserve; that both
are a subset of the universe; that the recorded selection root reproduces and its input hashes match
the committed files; and that no candidate-subject run exists in the pre-freeze plane (the
candidate-result artefacts the stratum produces after the freeze -- 24.6's build/link atlas onward
-- are excluded, because the freeze enabled them) --
with an instrument-sensitivity control that seeds five mutations and requires each caught.
`RT-HOLDOUT-PARTITION` reads the committed `forensics/downstream/holdout.json`, the committed
frozen `forensics/downstream/family-freeze.json` and the committed
`forensics/downstream/families.json`, re-derives the partition from the frozen P1000 by the frozen
rank-band rule, and checks that atlas. It establishes that the two cohorts union to exactly the
frozen P1000; that they are disjoint and each family_id appears exactly once; that every family_id
is a real committed family; that each band of 100 contributes exactly 20 holdout / 80 development;
that the cohorts reproduce from the frozen rule; that the partition root reproduces; and that no
candidate-subject run exists anywhere in the downstream plane -- with an instrument-sensitivity
control that seeds six mutations and requires each caught. `RT-CANDIDATE-FREEZE` reads the committed
`forensics/downstream/candidate-freeze.json`, the committed `forensics/downstream/holdout.json`, the
frozen `forensics/downstream/family-freeze.json`, the committed 24.6 build/link atlas, the committed
24.7 runtime/functional atlas, the committed 24.8 failures plane, the committed 24.9 high-value tier
and the committed 24.10 hostility corpus, re-deriving the frozen candidate identity from the
committed install and the precommitted holdout set from the frozen P1000 by the 24.5 rule without
re-running the holdout and without rebuilding anything. It establishes that the candidate identity
reproduces from the committed install; that the holdout set equals the precommitted partition and
carries a matching `partition_root_hash`; that `first_run` is present, equals the summary derived
from the holdout run, and is attested unchanged by every rerun; that every holdout family has an
accounting row; that a candidate row never claims a level above the authority-applicable baseline;
that a family's verdict is the derived baseline-normalized one; that `candidate_specific_patch_count`
is 0; that the counts are derived rather than typed; and that no holdout family is a source of a fix
in the development-side failure plane -- with an instrument-sensitivity control that seeds six
mutations and requires each caught. `RT-P1000-RUN` reads the committed
`forensics/downstream/p1000-run.json`, the frozen `forensics/downstream/family-freeze.json` and the
committed 24.11 `forensics/downstream/candidate-freeze.json`, re-deriving the candidate install's
identity and re-running the 24.12 validation and sensitivity control over the committed run without
rebuilding anything. It establishes that the candidate identity equals the frozen 24.11 identity
(excluding the recorded provenance, so the run is against the same candidate); that there is exactly
one `drop_in_verdict` per counted family, with none missing, extra or fabricated; that a
`DROP_IN_PASS` is refused without all five of the brief's section 20 conditions; that
`DROP_IN_UNKNOWN` is 0; that the ladder equals the derived per-level counts and the verdict
histogram; that a family this venue cannot pose the drop-in question for is `DROP_IN_NOT_APPLICABLE`
with a reason; that `candidate_specific_patch_count` is 0; and that the counts are derived rather
than typed -- with an instrument-sensitivity control that seeds five mutations and requires each
caught. `RT-ATLAS-RECONCILIATION` reads the committed `forensics/downstream/reconciliation.json` and
re-runs the 24.13 re-derivation and sensitivity control over the committed artefact without
rebuilding anything. It establishes that every counted family has exactly one re-derived
`drop_in_verdict` with `DROP_IN_UNKNOWN` 0; that every residual across every plane is classified from
the closed vocabulary with an unclassified and an `unknown` count of 0; that every failure is
preserved -- the counted P1000 measured set's plus the separate hostility corpus's two candidate
failures, scoped out of every P1000 rate; that the drop-in rates equal the derived rates and never sum
the direct and transitive consumers; that the ladder equals the verdict counts with `UNKNOWN` 0 and
the raw family count visible; that the coverage and the Phase-22 direct/inferred projection are
consistent with the planes; and that the counts are derived rather than typed -- with an
instrument-sensitivity control that seeds six mutations and requires each caught. It is an
**instrument**: it can pass while the atlas carries real property findings (a large
`NOT_APPLICABLE` share, a thin measured surface, a non-empty residual set), which are recorded as the
row's `findings` so the ledger reads `property_status` honestly. The
registry is the file `run_courts.py`
checks is reproduced, so a court silently dropped is a finding rather than a smaller green run.
This is the reverse of Phase 16's edge: the ledger's contract-unit states are measured from this
registry, so this runner does **not** bind the obligations ledger as an input. **24.14 registers
`RT-FRF-CLOSURE`**, the FRF/Gemel chain closure. It stages no probe: it reads the committed
`forensics/atlas/phase24/frf-closure.json`, re-derives the FRF chain staging from the
`gen_frf_courts.py` registry and the `artifacts/phase24/probes/` directory (never from `COURTS.json`,
which would cycle) and the Gemel checkpoint projection from the committed
`forensics/GEMEL_TRAJECTORY.md` (never the store), and re-runs the 24.14 classification over the
committed challenges. It establishes that each Phase-24 plane's own pure checker detected its own
defect class, that no Phase-24 court is declarable so the FRF/Gemel chain entry is vacuous by
`frf_gemel_blocking_reason`'s own scoping, and that the classifier is not a rubber stamp -- a
registered challenge whose observed result is mutated in memory is reported `NOT_DETECTED`. It is an
**instrument**: it can pass while its property finding records that the stratum stages no declarable
court, so a passing closure is never read as a chain that ran.

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
  * `RT-CANDIDATE-UNIVERSE` -- 24.2, the candidate family universe (registered).
  * `RT-AUTHORITY-CENSUS` -- 24.3, the authority-baseline census (registered).
  * `RT-FAMILY-FREEZE` -- 24.4, the P1000 + reserve freeze (registered).
  * `RT-HOLDOUT-PARTITION` -- 24.5, the precommitted holdout (registered).
  * `RT-BUILD-LINK-ATLAS` -- 24.6, the build/link atlas (registered).
  * `RT-RUNTIME-FUNCTIONAL-ATLAS` -- 24.7, the runtime/functional atlas (registered).
  * `RT-FAILURE-MINIMIZATION` -- 24.8, the failure discovery/minimization loop (registered).
  * `RT-HIGH-VALUE-TIER` -- 24.9, the high-value deep tier (registered).
  * `RT-HOSTILITY-AUGMENTATION` -- 24.10, the separate hostility corpus (registered).
  * `RT-CANDIDATE-FREEZE` -- 24.11, the candidate freeze and holdout (registered).
  * `RT-P1000-RUN` -- 24.12, the final full P1000 run (registered).
  * `RT-ATLAS-RECONCILIATION` -- 24.13, the atlas reconciliation (registered).
  * `RT-FRF-CLOSURE` -- 24.14, the FRF/Gemel closure (registered).
  * `DOWNSTREAM-1000-SEAL` -- 24.15, the seal.

Every one was `pending` at activation; 24.1 registers `RT-RANKING-SOURCES`, 24.2 registers
`RT-CANDIDATE-UNIVERSE`, 24.3 registers `RT-AUTHORITY-CENSUS`, 24.4 registers
`RT-FAMILY-FREEZE`, 24.5 registers `RT-HOLDOUT-PARTITION`, 24.6 registers
`RT-BUILD-LINK-ATLAS`, 24.7 registers `RT-RUNTIME-FUNCTIONAL-ATLAS`, 24.8 registers
`RT-FAILURE-MINIMIZATION`, 24.9 registers `RT-HIGH-VALUE-TIER`, 24.10 registers
`RT-HOSTILITY-AUGMENTATION`, 24.11 registers `RT-CANDIDATE-FREEZE`, 24.12 registers
`RT-P1000-RUN`, 24.13 registers `RT-ATLAS-RECONCILIATION` and 24.14 registers `RT-FRF-CLOSURE`,
and the remaining one -- the downstream-1000 seal -- is pending. A passing court is an instrument,
not a property claim, and this stratum makes no property claim beyond the atlas: a selected
empirical population is not a random sample, 1000/1000 is not a security proof, a build is not a
functional proof, and transitive and direct consumers are different evidence.

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
    content_hash,
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

# The 24.2 candidate-universe tool, imported so the court re-runs its derivation and sensitivity
# control over the committed ranking evidence (never fetching and never re-running the generator's
# own writes) through the same code path the artefacts were produced by.
import downstream_universe  # noqa: E402

# The 24.3 authority-baseline census tool, imported so the court re-runs its pure validation and
# sensitivity control over the committed census and fingerprint artefacts (never rebuilding) through
# the same code path the artefacts were produced by.
import downstream_census  # noqa: E402

# The 24.4 P1000 + reserve freeze tool, imported so the court re-derives the population from the
# committed families and re-runs its validation and sensitivity control over the committed freeze
# (never re-selecting) through the same code path the artefact was produced by.
import downstream_freeze  # noqa: E402

# The 24.5 precommitted holdout-partition tool, imported so the court re-derives the partition from
# the committed frozen P1000 and re-runs its validation and sensitivity control over the committed
# artefact (never re-dividing and never running a candidate) through the same code path the artefact
# was produced by.
import downstream_holdout  # noqa: E402

# The 24.6 build/link atlas tool, imported so the court re-runs its pure validation and sensitivity
# control over the committed build/link atlas (never rebuilding and never launching a downstream
# program) through the same code path the artefact was produced by.
import downstream_build_link  # noqa: E402

# The 24.7 runtime/functional atlas tool, imported so the court re-runs its pure validation and
# sensitivity control over the committed runtime/functional atlas (never rebuilding and never
# launching a downstream program) through the same code path the artefact was produced by.
import downstream_runtime  # noqa: E402

# The 24.8 failure discovery/minimization tool, imported so the court re-runs its pure validation and
# sensitivity control over the committed failures plane (never rebuilding and never launching
# anything) through the same code path the artefact was produced by.
import downstream_failures  # noqa: E402

# The 24.9 high-value deep tier tool, imported so the court re-runs its pure validation and
# sensitivity control over the committed tier (never rebuilding and never launching a program)
# through the same code path the artefact was produced by.
import downstream_high_value  # noqa: E402

# The 24.10 hostility-augmentation tool, imported so the court re-runs its pure selection, validation
# and sensitivity control over the committed corpus (never rebuilding and never launching a probe)
# through the same code path the artefact was produced by.
import downstream_hostility  # noqa: E402

# The 24.11 candidate-freeze tool, imported so the court re-derives the frozen candidate identity from
# the committed install, the precommitted holdout set from 24.5, and re-runs the validation and
# sensitivity control over the committed freeze (never re-running the holdout) through the same code
# path the artefact was produced by.
import downstream_candidate_freeze  # noqa: E402

# The 24.12 final-P1000-run tool, imported so the court re-derives the candidate identity from the
# committed install and re-runs the validation and sensitivity control over the committed run (never
# rebuilding and never launching anything) through the same code path the artefact was produced by.
import downstream_p1000_run  # noqa: E402

# The 24.13 atlas-reconciliation tool, imported so the court re-derives the whole accounted view from
# the committed planes and re-runs the validation and sensitivity control over the committed
# reconciliation (never rebuilding and never launching anything) through the same code path the
# artefact was produced by.
import downstream_reconciliation  # noqa: E402

# The 24.14 FRF/Gemel closure tool, imported so the court re-runs its per-plane challenge
# classification, its chain-staging derivation and its Gemel-projection derivation over the committed
# closure (never fetching, never opening the store and never launching a probe) through the same code
# path the artefact was produced by. The tool executes nothing, so it is declared `metadata_only` in
# the container manifest and the guard admits it host-side; it does not import this runner, so the
# edge runs closure -> court and binding it back would form a digest cycle neither artefact could
# reproduce.
import phase24_frf  # noqa: E402

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

# 24.2's subject: the candidate identity universe and the deduplicated project families the court
# re-derives from those same committed normalized inputs.
CANDIDATES = REPO_ROOT / "forensics" / "downstream" / "candidates.json"
FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
CANDIDATE_UNIVERSE_COURT = "RT-CANDIDATE-UNIVERSE"

# 24.3's subject: the authority-baseline census (one `run` row per cohort member) and the usage
# fingerprints (the specimens, variants, link surface and linkage proof) the court re-validates.
AUTHORITY_BASELINES = REPO_ROOT / "forensics" / "downstream" / "authority-baselines.jsonl"
USAGE_FINGERPRINTS = REPO_ROOT / "forensics" / "downstream" / "usage-fingerprints.json"
AUTHORITY_CENSUS_COURT = "RT-AUTHORITY-CENSUS"

# 24.4's subject: the frozen P1000 + reserve, re-derived from the committed families and the frozen
# 24.1 ranking evidence. The court reads it; it never selects a population and never runs a
# candidate.
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
FAMILY_FREEZE_COURT = "RT-FAMILY-FREEZE"

# 24.5's subject: the precommitted development/holdout partition, re-derived from the committed
# frozen P1000. The court reads it; it never re-divides the population and never runs a candidate.
HOLDOUT = REPO_ROOT / "forensics" / "downstream" / "holdout.json"
HOLDOUT_PARTITION_COURT = "RT-HOLDOUT-PARTITION"

# 24.6's subject: the build/link atlas, one build/link run per specimen per subject. The court reads
# it and re-runs the pure validation; it never rebuilds and never launches a downstream program.
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
BUILD_LINK_ATLAS_COURT = "RT-BUILD-LINK-ATLAS"

# 24.7's subject: the runtime/functional atlas, one load/run/behave run per specimen per subject. The
# court reads it and re-runs the pure validation; it never rebuilds and never launches a program.
RUNTIME_FUNCTIONAL_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS_COURT = "RT-RUNTIME-FUNCTIONAL-ATLAS"

# 24.8's subject: the classified, preserved, minimized failures plane and the minimized fixtures it
# references. The court reads both and re-runs the pure validation; it never rebuilds, launches or
# minimizes anything.
DOWNSTREAM_FAILURES = REPO_ROOT / "forensics" / "downstream" / "failures.json"
DOWNSTREAM_FAILURES_DIR = REPO_ROOT / "forensics" / "downstream" / "failures"
FAILURE_MINIMIZATION_COURT = "RT-FAILURE-MINIMIZATION"

# 24.9's subject: the high-value deep tier, the deepest families by the committed 24.3 usage
# fingerprints plus the precedented deep consumers (Git, CPython), measured to the functional level
# under both subjects. The court reads it and re-runs the pure validation; it never rebuilds.
HIGH_VALUE_TIER = REPO_ROOT / "forensics" / "downstream" / "high-value-tier.json"
HIGH_VALUE_TIER_COURT = "RT-HIGH-VALUE-TIER"

# 24.10's subject: the separate hostility-augmentation corpus, a bounded set of rare-surface probes
# (custom BIO, legacy ENGINE, provider config, error queue, layout, fork/reinit, threading, dlopen,
# PKCS#12, CMS, cross-implementation TLS, static) selected by maximum marginal contract novelty over
# the P1000-covered surface and measured against both subjects. The court reads it and re-runs the
# pure selection/validation; it never rebuilds a probe.
HOSTILITY_CORPUS = REPO_ROOT / "forensics" / "downstream" / "hostility-corpus.json"
HOSTILITY_AUGMENTATION_COURT = "RT-HOSTILITY-AUGMENTATION"

# 24.11's subject: the frozen candidate identity and the precommitted holdout run against it exactly
# once. The court reads it and re-runs the pure validation; it re-derives the candidate identity from
# the committed install and never re-runs the holdout.
CANDIDATE_FREEZE = REPO_ROOT / "forensics" / "downstream" / "candidate-freeze.json"
CANDIDATE_FREEZE_COURT = "RT-CANDIDATE-FREEZE"

# 24.12's subject: the final full P1000 run at the frozen candidate, one derived `drop_in_verdict`
# per counted family and the ladder. The court reads it and re-runs the pure validation; it
# re-derives the candidate identity from the committed install and never rebuilds.
P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"
P1000_RUN_COURT = "RT-P1000-RUN"

# 24.13's subject: the reconciliation of the atlas, one accounted view of every committed plane --
# every counted family's re-derived verdict, every classified residual, every preserved failure (the
# P1000 measured set's plus the separate hostility corpus's two), the computed rates over the frozen
# population, the ladder, the Phase-22 coverage projection and the usage clusters. The court reads it
# and re-runs the pure re-derivation; it never rebuilds and never launches anything.
RECONCILIATION = REPO_ROOT / "forensics" / "downstream" / "reconciliation.json"
ATLAS_RECONCILIATION_COURT = "RT-ATLAS-RECONCILIATION"

# 24.14's subject: the FRF/Gemel closure. The FRF challenges plane (one record per Phase-24 plane,
# each the plane's own pure checker driven over its committed artefact and over the controlled
# mutations its own sensitivity control seeds), the FRF chain staging (why no Phase-24 court is
# declarable, and what stands in its place) and the Gemel checkpoint projection (the state of the
# committed `forensics/GEMEL_TRAJECTORY.md`, never the store). The court reads it and re-runs the
# pure classification, the chain derivation and the Gemel derivation; it stages no probe.
FRF_CLOSURE = REPO_ROOT / "forensics" / "atlas" / "phase24" / "frf-closure.json"
FRF_CLOSURE_COURT = "RT-FRF-CLOSURE"

# The courts this stratum stages. 24.1 registers `RT-RANKING-SOURCES`, 24.2 `RT-CANDIDATE-UNIVERSE`,
# 24.3 `RT-AUTHORITY-CENSUS`, 24.4 `RT-FAMILY-FREEZE`, 24.5 `RT-HOLDOUT-PARTITION`, 24.6
# `RT-BUILD-LINK-ATLAS`, 24.7 `RT-RUNTIME-FUNCTIONAL-ATLAS`, 24.8 `RT-FAILURE-MINIMIZATION`, 24.9
# `RT-HIGH-VALUE-TIER`, 24.10 `RT-HOSTILITY-AUGMENTATION`, 24.11 `RT-CANDIDATE-FREEZE`, 24.12
# `RT-P1000-RUN`, 24.13 `RT-ATLAS-RECONCILIATION` and 24.14 `RT-FRF-CLOSURE`; each later subphase
# appends its court here in the commit that lands its instrument, and a court removed from the table
# leaves the registry and fails `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (RANKING_SOURCES_COURT, "_ranking_sources_court"),
    (CANDIDATE_UNIVERSE_COURT, "_candidate_universe_court"),
    (AUTHORITY_CENSUS_COURT, "_authority_census_court"),
    (FAMILY_FREEZE_COURT, "_family_freeze_court"),
    (HOLDOUT_PARTITION_COURT, "_holdout_partition_court"),
    (BUILD_LINK_ATLAS_COURT, "_build_link_atlas_court"),
    (RUNTIME_FUNCTIONAL_ATLAS_COURT, "_runtime_functional_atlas_court"),
    (FAILURE_MINIMIZATION_COURT, "_failure_minimization_court"),
    (HIGH_VALUE_TIER_COURT, "_high_value_tier_court"),
    (HOSTILITY_AUGMENTATION_COURT, "_hostility_augmentation_court"),
    (CANDIDATE_FREEZE_COURT, "_candidate_freeze_court"),
    (P1000_RUN_COURT, "_p1000_run_court"),
    (ATLAS_RECONCILIATION_COURT, "_atlas_reconciliation_court"),
    (FRF_CLOSURE_COURT, "_frf_closure_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. Ordered as the
# plan orders them, so the registry reads as the execution order. A court moves out of this table
# and into `COURTS` in the commit that lands its instrument.
PENDING_COURTS: dict[str, str] = {
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


def _candidate_universe_court(name: str) -> dict:
    """`RT-CANDIDATE-UNIVERSE`: 24.2's court, the candidate family universe.

    Stages no probe. It reads the committed candidate universe `forensics/downstream/candidates.json`
    and the committed families `forensics/downstream/families.json`, re-derives both from the
    committed 24.1 normalized inputs, and establishes that every family is schema-valid and
    provenance-backed, that aliases of one upstream collapse to one family (and the
    `libcurl4`/`curl`/`curl-dev`/`curl-doc` alias set is one family, not four), that a fork is not
    independent without explicit evidence, that a transitive consumer is not counted as direct, and
    that the universe is substantially larger than 1,000 before deduplication. Four seeded
    mutations are each caught with specificity holding. A passing candidate universe is a
    **precommitment**, not a ranking claim: it says the discoverable population was normalised into
    families from the frozen evidence, not that any family is important.
    """
    if not (CANDIDATES.is_file() and FAMILIES.is_file()):
        missing = [rel(p) for p in (CANDIDATES, FAMILIES) if not p.is_file()]
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the candidate-universe artefact {m} is absent" for m in missing],
                "findings": [], "control": {}}

    manifest = json.loads(RANKING_SOURCES.read_text(encoding="utf-8"))["body"]
    committed_c = json.loads(CANDIDATES.read_text(encoding="utf-8"))["body"]
    committed_f = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    normalized = downstream_sources.load_committed(manifest)
    derived_c, derived_f = downstream_universe.derive_universe(manifest, normalized)

    findings = downstream_universe.universe_findings(manifest, committed_c, committed_f)
    if content_hash(derived_c) != content_hash(committed_c):
        findings.append("candidates.json does not reproduce from the committed ranking evidence")
    if content_hash(derived_f) != content_hash(committed_f):
        findings.append("families.json does not reproduce from the committed ranking evidence")

    control = downstream_universe.universe_sensitivity_control(manifest, committed_c, committed_f)

    identities = committed_c.get("identities") or []
    families = committed_f.get("families") or []
    excluded = committed_f.get("excluded") or []
    names = {str(i["package"]).lower() for i in identities}
    curl = next((f for f in families if f["canonical_name"] == "curl"), None)
    forked = next((f for f in families if f.get("fork_merged")), None)
    examples = {
        "alias_collapse": ({
            "family": curl["family_id"],
            "aliases": curl["aliases"],
            "distro_packages": curl["distro_packages"],
            "ecosystem_packages": curl["ecosystem_packages"],
        } if curl else None),
        "provider_group": {
            "canonical_name": "openssl",
            "class": downstream_universe.NOT_ACTUALLY,
            "excluded_identities": sum(1 for e in excluded
                                       if e.get("canonical_name") == "openssl"),
        },
        # A package whose only OpenSSL link is through libcurl is not a direct consumer and is not
        # in the universe: `git` names neither a provider nor a soname, so the reverse scan never
        # admits it.
        "transitive_through_libcurl_absent": "git" not in names,
        # A fork sharing a base name with a real family is merged into it (no evidence of
        # materially different OpenSSL integration); a fork that stands alone without evidence
        # would be a finding.
        "fork_merge": ({
            "family": forked["family_id"],
            "merged": forked["fork_merged"],
            "aliases": forked["aliases"],
        } if forked else None),
        "forks_independent_without_evidence": sorted(
            f["family_id"] for f in families if f.get("fork_of") and not f.get("fork_evidence")),
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    ccounts = committed_c.get("counts") or {}
    fcounts = committed_f.get("counts") or {}
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/candidates.json and "
            "forensics/downstream/families.json, re-derives both from the committed "
            "forensics/downstream/ranking/normalized/ inputs, and re-runs the 24.2 validation and "
            "sensitivity control over the committed artefacts. It establishes that every family "
            "is schema-valid (kind `family`) and provenance-backed, that a package alias set "
            "collapses to one family, that the OpenSSL providers and a name collision "
            "(`libcrypto++`) are not counted as consumers, that a fork is not independent without "
            "evidence, that a transitive consumer is not counted as direct, and that the universe "
            "is substantially larger than 1,000 before deduplication. A double-counted alias, a "
            "transitive consumer promoted to direct, a fork counted independent with no evidence "
            "and a family with no provenance are each detected with specificity holding "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.1, 3.6 and 4.5)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the candidate-universe court re-derives committed artefacts from committed inputs "
            "and stages no artifacts/phase24/probes/ pair, so it takes no transcript to diff and "
            "carries no FRF declaration"
        ),
        "counts": {
            "identities": ccounts.get("identities", len(identities)),
            "families": fcounts.get("families", len(families)),
            "aliases_collapsed": fcounts.get("aliases_collapsed", 0),
            "forks_merged": fcounts.get("forks_merged", 0),
            "excluded": len(excluded),
        },
        "identities_by_directness": ccounts.get("by_directness", {}),
        "families_by_directness": fcounts.get("by_directness", {}),
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _authority_census_court(name: str) -> dict:
    """`RT-AUTHORITY-CENSUS`: 24.3's court, the authority-baseline census.

    Stages no probe. It reads the committed census `forensics/downstream/authority-baselines.jsonl`
    (one `run` row per provisional cohort member) and the fingerprint envelope
    `forensics/downstream/usage-fingerprints.json`, re-derives the provisional cohort from the
    committed families, and establishes that every cohort member has an authority result
    classified; that an `AUTHORITY_BASELINE_FAIL` carries an authority failure class and a reason
    and is never counted as a candidate failure; that a `AUTHORITY_BASELINE_PASS`'s linkage proof
    resolves the admitted authority and not a system libssl; that the cohort selection rule is
    recorded and reproduces from the frozen sources; and that no candidate execution occurred. Four
    seeded mutations are each caught with specificity holding. A passing census is a **measurement**,
    not a candidate result: it says how far the authority itself reached, and no candidate ran.
    """
    if not (AUTHORITY_BASELINES.is_file() and USAGE_FINGERPRINTS.is_file()):
        missing = [rel(p) for p in (AUTHORITY_BASELINES, USAGE_FINGERPRINTS) if not p.is_file()]
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the authority-baseline census artefact {m} is absent"
                             for m in missing],
                "findings": [], "control": {}}

    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    rows = downstream_census._load_outcomes()
    body = downstream_census._load_fingerprints()
    findings = downstream_census.census_findings(families_body, rows, body)
    control = downstream_census.census_sensitivity_control(families_body, rows, body)

    counts = body.get("counts") or {}
    cohort = body.get("cohort") or []
    fails = [r for r in rows if r.get("classification") == downstream_census.CLASS_FAIL]
    passes = [r for r in rows if r.get("classification") == downstream_census.CLASS_PASS]
    fingerprints = {str(f.get("family_id")): f for f in body.get("fingerprints") or []}
    examples = {
        "rule": body.get("rule"),
        "cohort_min_sources": body.get("cohort_min_sources"),
        "cohort_size": len(cohort),
        "authority_prefix": body.get("authority_prefix"),
        "authority_baseline_fails": [
            {"family": r.get("canonical_name"), "level": r.get("level"),
             "failure_class": r.get("failure_class"), "reason": r.get("failure_reason")}
            for r in sorted(fails, key=lambda r: r.get("rank") or 0)
        ],
        "authority_linkage_proof": {
            str(r.get("canonical_name")): (fingerprints.get(str(r.get("family_id"))) or
                                           {}).get("linkage_proof")
            for r in passes
        },
        "candidate_rows": [r.get("run_id") for r in rows if r.get("subject") == "candidate"],
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/authority-baselines.jsonl and "
            "forensics/downstream/usage-fingerprints.json, re-derives the provisional census "
            "cohort from the committed forensics/downstream/families.json, and re-runs the 24.3 "
            "validation and sensitivity control over the committed artefacts without rebuilding. "
            "It establishes that every cohort member has an authority result classified; that an "
            "`AUTHORITY_BASELINE_FAIL` carries an authority failure class from the taxonomy and a "
            "reason, and is never counted as a candidate failure; that a `AUTHORITY_BASELINE_PASS`'s "
            "linkage proof resolves the admitted authority's own libssl/libcrypto and never a "
            "system one; that the cohort selection rule is recorded and reproduces from the frozen "
            "sources; and that no candidate execution occurred. A build claiming authority linkage "
            "while resolving a system libssl, an `AUTHORITY_BASELINE_FAIL` counted as a candidate "
            "failure, a cohort member with no source hash and a fingerprint with no imported "
            "symbols claimed as a pass are each detected with specificity holding "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.1, 3.2 and 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the authority-census court reads committed census and fingerprint artefacts and "
            "stages no artifacts/phase24/probes/ pair, so it takes no transcript to diff and "
            "carries no FRF declaration"
        ),
        "counts": {
            "cohort": counts.get("cohort", len(cohort)),
            "passed": counts.get("passed", len(passes)),
            "failed": counts.get("failed", len(fails)),
            "acquired": counts.get("acquired", 0),
            "linked_to_authority": counts.get("linked_to_authority", 0),
            "launched": counts.get("launched", 0),
            "no_recipe": counts.get("no_recipe", 0),
            "with_recipe": counts.get("with_recipe", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _family_freeze_court(name: str) -> dict:
    """`RT-FAMILY-FREEZE`: 24.4's court, the P1000 + reserve freeze.

    Stages no probe. It reads the committed freeze `forensics/downstream/family-freeze.json` and the
    committed families `forensics/downstream/families.json`, re-derives the ranked universe from
    those families by the frozen selection rule, and establishes that the recorded P1000 is exactly
    the derived top-1,000 and the reserve the derived remainder in rank order; that the P1000 is
    distinct and disjoint from the reserve; that both are a subset of the universe; that ranks are
    positions and the recorded signal is each family's own; that the recorded selection root
    reproduces and its `selection_input_root_hash` and input hashes match the committed files; and
    that **no candidate-subject run exists in the pre-freeze plane** (the candidate-result artefacts
    the stratum produces after the freeze -- 24.6's build/link atlas onward -- are excluded), so the
    population is
    frozen before any candidate result. Five seeded mutations are each caught with specificity
    holding. A passing freeze is a **precommitment**, not a result: it says the population was
    selected from the frozen ranking evidence before any candidate ran. The anti-pattern it refuses
    is a family **typed into the 1,000 because a candidate passed it** -- a rigged population.
    """
    if not FAMILY_FREEZE.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the family-freeze artefact {rel(FAMILY_FREEZE)} is absent"],
                "findings": [], "control": {}}

    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    findings = downstream_freeze.freeze_findings(families_body, freeze_body)
    control = downstream_freeze.freeze_sensitivity_control(families_body, freeze_body)

    counts = freeze_body.get("counts") or {}
    p1000 = freeze_body.get("p1000") or []
    reserve = freeze_body.get("reserve") or []
    examples = {
        "rule": freeze_body.get("rule"),
        "selection_input_root": freeze_body.get("selection_input_root"),
        "selection_root_hash": freeze_body.get("selection_root_hash"),
        "p1000_head": p1000[:5],
        "reserve_head": reserve[:3],
        "reserve_size": len(reserve),
        "candidate_rows": [
            hit for where, doc in downstream_freeze.load_plane()
            for hit in downstream_freeze._candidate_rows(doc, where)],
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/family-freeze.json and "
            "forensics/downstream/families.json, re-derives the ranked universe from the committed "
            "families by the frozen selection rule (source breadth, then distro breadth, then "
            "popularity, then canonical name, then family_id), and re-runs the 24.4 validation and "
            "sensitivity control over the committed artefact without selecting or running "
            "anything. It establishes that the recorded P1000 is exactly the derived top-1,000 and "
            "the reserve the derived remainder in rank order; that the P1000 is distinct and "
            "disjoint from the reserve; that both are a subset of the universe; that ranks are "
            "positions and the recorded signal is each family's own; that the recorded selection "
            "root reproduces and its selection_input_root_hash, families sha256 and rule sha256 "
            "match the committed files; and that no candidate-subject run exists anywhere in the "
            "downstream plane. The five seeded mutations -- two P1000 members' order swapped, a "
            "P1000 member deleted so the count is wrong, a family id shared between the P1000 and "
            "the reserve, a mutated selection root, and a fabricated candidate-subject run row in "
            "the downstream plane -- are each detected with specificity holding. The anti-pattern "
            "it refuses is a family typed into the 1,000 because a candidate passed it: the "
            "population is frozen before any candidate result "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 1, 2, 3.1, 3.4 and 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the family-freeze court re-derives the population from committed inputs and stages no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "selection_root_hash": freeze_body.get("selection_root_hash"),
        "counts": {
            "p1000": counts.get("p1000", len(p1000)),
            "reserve": counts.get("reserve", len(reserve)),
            "universe": counts.get("universe", 0),
            "direct": (counts.get("by_directness") or {}).get("direct", 0),
            "transitive": (counts.get("by_directness") or {}).get("transitive", 0),
            "candidate_results_present": counts.get("candidate_results_present", False),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _holdout_partition_court(name: str) -> dict:
    """`RT-HOLDOUT-PARTITION`: 24.5's court, the precommitted holdout partition.

    Stages no probe. It reads the committed partition `forensics/downstream/holdout.json`, the
    committed frozen P1000 `forensics/downstream/family-freeze.json` and the committed families
    `forensics/downstream/families.json`, re-derives the partition from the frozen rule, and
    establishes that the two cohorts union to exactly the frozen P1000; that they are disjoint and
    each family_id appears exactly once; that every family_id is a real committed family; that each
    band of 100 contributes exactly 20 holdout / 80 development; that the cohorts reproduce from the
    frozen rule; that the partition root reproduces; that the counts are read rather than typed;
    that the partition is a **pure function of the frozen P1000** (no family outside it); and that
    **no candidate-subject run exists in the pre-freeze plane** (the candidate-result artefacts
    the stratum produces after the freeze -- 24.6's build/link atlas onward -- are excluded), so the
    split is fixed
    before any candidate result. Six seeded mutations are each caught with specificity holding. A
    passing partition is a **precommitment**, not a result. The anti-pattern it refuses is a holdout
    chosen after seeing a candidate failure -- a holdout that is no longer out-of-sample.
    """
    if not HOLDOUT.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the holdout artefact {rel(HOLDOUT)} is absent"],
                "findings": [], "control": {}}

    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    holdout_body = json.loads(HOLDOUT.read_text(encoding="utf-8"))["body"]
    findings = downstream_holdout.holdout_findings(families_body, freeze_body, holdout_body)
    control = downstream_holdout.holdout_sensitivity_control(families_body, freeze_body, holdout_body)

    counts = holdout_body.get("counts") or {}
    partition = holdout_body.get("partition") or {}
    development = partition.get("development") or []
    holdout = partition.get("holdout") or []
    per_band = {b: sum(1 for r in holdout if r.get("band") == b)
                for b in range(1, downstream_holdout.BANDS + 1)}
    examples = {
        "rule": holdout_body.get("rule"),
        "p1000_tag": holdout_body.get("p1000_tag"),
        "partition_root_hash": holdout_body.get("partition_root_hash"),
        "holdout_status": holdout_body.get("holdout_status"),
        "development_head": development[:3],
        "holdout_head": holdout[:3],
        "per_band_holdout": per_band,
        "candidate_rows": [
            hit for where, doc in downstream_freeze.load_plane()
            for hit in downstream_freeze._candidate_rows(doc, where)],
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/holdout.json, "
            "forensics/downstream/family-freeze.json and forensics/downstream/families.json, "
            "re-derives the partition from the committed frozen P1000 by the frozen rule (rank "
            "bands of 100, each band ordered by content_hash('phase24-holdout-v1:'+family_id) "
            "ascending, tiebreak by family_id, the first 20 holdout and the remaining 80 "
            "development), and re-runs the 24.5 validation and sensitivity control over the "
            "committed artefact without re-dividing or running anything. It establishes that the "
            "two cohorts union to exactly the frozen P1000; that they are disjoint and each "
            "family_id appears exactly once; that every family_id is a real committed family; "
            "that each band contributes exactly 20 holdout / 80 development; that the cohorts "
            "reproduce from the frozen rule; that the partition root reproduces; that the counts "
            "are read rather than typed; that the partition is a pure function of the frozen P1000; "
            "and that no candidate-subject run exists in the pre-freeze plane (the candidate-result "
            "artefacts the stratum produces after the freeze -- 24.6's build/link atlas onward -- "
            "are excluded). The six "
            "seeded mutations -- one development family moved into the holdout cohort, one holdout "
            "member deleted, a family_id duplicated into both cohorts, a P1000-external family "
            "added, a mutated partition root, and a fabricated candidate-subject run row in the "
            "downstream plane -- are each detected with specificity holding. The anti-pattern it "
            "refuses is a holdout chosen after seeing a candidate failure: the holdout is fixed "
            "before any candidate result and run exactly once (docs/PHASE-24-DOWNSTREAM-1000-"
            "SUBPHASES.md sections 1, 2, 3.4 and 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the holdout-partition court re-derives the partition from committed inputs and stages "
            "no artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no "
            "FRF declaration"
        ),
        "partition_root_hash": holdout_body.get("partition_root_hash"),
        "counts": {
            "p1000": counts.get("p1000", len(freeze_body.get("p1000") or [])),
            "development": counts.get("development", len(development)),
            "holdout": counts.get("holdout", len(holdout)),
            "per_band_holdout": counts.get("per_band_holdout", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _build_link_atlas_court(name: str) -> dict:
    """`RT-BUILD-LINK-ATLAS`: 24.6's court, the build/link atlas.

    Stages no probe. It reads the committed atlas `forensics/downstream/build-link-atlas.json`, the
    committed frozen P1000 `forensics/downstream/family-freeze.json` and the committed families
    `forensics/downstream/families.json`, and re-runs the 24.6 validation and sensitivity control
    over the committed artefact **without rebuilding and without launching anything**. It
    establishes that every frozen P1000 family is accounted for under both subjects; that every
    recipe-backed family has both an authority and a candidate row for the same specimen and the
    same recipe (identical build intent); that a candidate `L4-linked` row's linkage proof resolves
    the candidate install and never the authority prefix nor a system library; that an authority
    `L4-linked` row resolves the authority; that `candidate_specific_patch_count` is 0; that every
    non-measured row carries a reason and a schema-valid residual/failure class; and that the counts
    are derived rather than typed. Five seeded mutations are each caught with specificity holding. A
    passing atlas is a **measurement**, not a functional proof: it says how far a pristine
    downstream build reached and that the candidate's libssl/libcrypto resolved, not that any
    consumer works.
    """
    if not BUILD_LINK_ATLAS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the build/link atlas artefact {rel(BUILD_LINK_ATLAS)} is absent"],
                "findings": [], "control": {}}

    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    atlas_body = downstream_build_link._load_atlas()
    findings = downstream_build_link.build_link_findings(families_body, freeze_body, atlas_body)
    control = downstream_build_link.build_link_sensitivity_control(families_body, freeze_body,
                                                                   atlas_body)

    counts = atlas_body.get("counts") or {}
    runs = atlas_body.get("runs") or []
    cand = [r for r in runs if r.get("subject") == "candidate" and r.get("has_recipe")]
    by = counts.get("by_subject") or {}
    examples = {
        "rule": atlas_body.get("rule"),
        "candidate_identity": atlas_body.get("candidate_identity"),
        "authority_prefix": atlas_body.get("authority_prefix"),
        "candidate_linkage_proof": {
            str(r.get("canonical_name")): {
                "resolved": {k: v.get("resolved")
                             for k, v in ((r.get("linkage") or {}).get("sonames") or {}).items()},
                "default_resolution": (r.get("linkage") or {}).get("default_resolution"),
                "version_needs": (r.get("linkage") or {}).get("version_needs"),
            }
            for r in cand if r.get("level") == downstream_build_link.L4
        },
        "candidate_failures": [
            {"family": r.get("canonical_name"), "level": r.get("level"),
             "failure_class": r.get("failure_class"), "reason": r.get("reason")}
            for r in cand if r.get("outcome") in ("failed", "not_attempted")
        ],
        "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/build-link-atlas.json, "
            "forensics/downstream/family-freeze.json and forensics/downstream/families.json and "
            "re-runs the 24.6 validation and sensitivity control over the committed artefact "
            "without rebuilding and without launching anything. It establishes that every frozen "
            "P1000 family is accounted for under both subjects; that every recipe-backed family "
            "has both an authority and a candidate row for the same specimen and the same recipe "
            "(identical build intent); that a candidate L4-linked row's linkage proof resolves the "
            "candidate install and never the authority prefix nor a system library; that an "
            "authority L4-linked row resolves the authority; that candidate_specific_patch_count "
            "is 0; that every non-measured row carries a reason and a schema-valid "
            "residual/failure class; and that the counts are derived rather than typed. The six "
            "seeded mutations -- a candidate L4 row whose linkage resolves the authority, a "
            "recipe-backed family missing its authority row (non-identical intent), a positive "
            "candidate_specific_patch_count, a non-measured row with no residual class, a "
            "candidate L4 row whose linkage resolves a system library, and a candidate row that "
            "built a different pristine source tree -- are each detected with "
            "specificity holding. A passing atlas is a measurement, not a functional proof: the "
            "linkage proof establishes that the candidate's libssl/libcrypto resolved, not that "
            "any consumer works (docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.1, 3.2, "
            "3.6 and the brief's sections 21-22)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the build/link atlas court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "candidate_identity": atlas_body.get("candidate_identity"),
        "counts": {
            "p1000": counts.get("p1000", 0),
            "rows": counts.get("rows", len(runs)),
            "with_recipe": counts.get("with_recipe", 0),
            "no_recipe": counts.get("no_recipe", 0),
            "authority_linked": (by.get("authority") or {}).get("linked", 0),
            "candidate_linked": (by.get("candidate") or {}).get("linked", 0),
            "candidate_configured": (by.get("candidate") or {}).get("configured", 0),
            "candidate_built": (by.get("candidate") or {}).get("built", 0),
            "candidate_failed": (by.get("candidate") or {}).get("failed", 0),
            "candidate_linkage_proven": counts.get("candidate_linkage_proven", 0),
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _runtime_functional_atlas_court(name: str) -> dict:
    """`RT-RUNTIME-FUNCTIONAL-ATLAS`: 24.7's court, the runtime/functional atlas.

    Stages no probe. It reads the committed atlas
    `forensics/downstream/runtime-functional-atlas.json`, the committed frozen P1000
    `forensics/downstream/family-freeze.json`, the committed families
    `forensics/downstream/families.json` and the committed 24.6 build/link atlas
    `forensics/downstream/build-link-atlas.json`, and re-runs the 24.7 validation and sensitivity
    control over the committed artefact **without rebuilding and without launching anything**. It
    establishes that every frozen P1000 family is accounted for under both subjects; that a family
    that reached `L4-linked` in 24.6 has runtime rows under both subjects; that a runtime row never
    reaches above the level its build/link row permits (a subject that never linked cannot load);
    that an `L5+` row is backed by a real load proof resolving the subject prefix and never the
    authority's (for a candidate); that an `L6`/`L7` row carries a non-empty normalised transcript
    hash and a normalisation tag that erases no evidence; that the candidate's
    authority-applicable baseline is re-derived from the authority rows (never inflated to justify
    a pass); that `candidate_specific_patch_count` is 0; that every non-measured row carries a
    reason and a schema-valid residual/failure class; and that the counts are derived rather than
    typed. Six seeded mutations are each caught with specificity holding. A passing atlas is a
    **measurement**, not a security proof: it says a pristine downstream program loaded the
    subject's libssl/libcrypto and completed one deterministic local workload, not that any consumer
    is safe.
    """
    if not RUNTIME_FUNCTIONAL_ATLAS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the runtime/functional atlas artefact {rel(RUNTIME_FUNCTIONAL_ATLAS)} "
                             f"is absent"], "findings": [], "control": {}}

    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    build_link_body = downstream_build_link._load_atlas()
    atlas_body = downstream_runtime._load_atlas()
    findings = downstream_runtime.runtime_findings(families_body, freeze_body, build_link_body,
                                                   atlas_body)
    control = downstream_runtime.runtime_sensitivity_control(families_body, freeze_body,
                                                             build_link_body, atlas_body)

    counts = atlas_body.get("counts") or {}
    runs = atlas_body.get("runs") or []
    by = counts.get("by_subject") or {}
    loaded = [r for r in runs if r.get("has_recipe")
              and downstream_runtime.RANK.get(str(r.get("level")), -1)
              >= downstream_runtime.RANK[downstream_runtime.L5]]
    examples = {
        "rule": atlas_body.get("rule"),
        "candidate_identity": atlas_body.get("candidate_identity"),
        "authority_applicable_level": counts.get("authority_applicable_level"),
        "loaded": [
            {"family": r.get("canonical_name"), "subject": r.get("subject"),
             "level": r.get("level"), "outcome": r.get("outcome"),
             "workload": r.get("workload"), "residual_class": r.get("residual_class")}
            for r in loaded
        ],
        "candidate_failures": [
            {"family": r.get("canonical_name"), "level": r.get("level"),
             "failure_class": r.get("failure_class"), "reason": r.get("reason")}
            for r in runs if r.get("subject") == "candidate" and r.get("has_recipe")
            and r.get("outcome") in ("failed", "not_attempted")
        ],
        "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/runtime-functional-atlas.json, "
            "forensics/downstream/family-freeze.json, forensics/downstream/families.json and "
            "forensics/downstream/build-link-atlas.json and re-runs the 24.7 validation and "
            "sensitivity control over the committed artefact without rebuilding and without "
            "launching anything. It establishes that every frozen P1000 family is accounted for "
            "under both subjects; that a family that reached L4-linked in 24.6 has runtime rows "
            "under both subjects; that a runtime row never reaches above the level its build/link "
            "row permits; that an L5+ row is backed by a real load proof resolving the subject "
            "prefix and never the authority's; that an L6/L7 row carries a non-empty normalised "
            "transcript hash and a normalisation tag that erases no evidence; that the candidate's "
            "authority-applicable baseline is re-derived from the authority rows; that "
            "candidate_specific_patch_count is 0; and that the counts are derived rather than "
            "typed. The six seeded mutations -- a candidate row whose level passes only by "
            "inflating its authority baseline, an L5 row with no load proof, an L6 row with an "
            "empty transcript hash, a missing authority runtime row for a family that reached L4, "
            "a normalisation that erases a return code, and a runtime row reaching above its "
            "build/link permit -- are each detected with specificity holding. A passing atlas is a "
            "measurement, not a security proof: it says a pristine downstream program loaded the "
            "subject's libssl/libcrypto and completed one deterministic local workload "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.1, 3.2, 3.6 and the "
            "brief's sections 18, 43 and 46)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the runtime/functional atlas court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "candidate_identity": atlas_body.get("candidate_identity"),
        "counts": {
            "p1000": counts.get("p1000", 0),
            "rows": counts.get("rows", len(runs)),
            "with_recipe": counts.get("with_recipe", 0),
            "no_recipe": counts.get("no_recipe", 0),
            "authority_loaded": (by.get("authority") or {}).get("loaded", 0),
            "authority_runtime": (by.get("authority") or {}).get("runtime", 0),
            "authority_functional": (by.get("authority") or {}).get("functional", 0),
            "candidate_loaded": (by.get("candidate") or {}).get("loaded", 0),
            "candidate_runtime": (by.get("candidate") or {}).get("runtime", 0),
            "candidate_functional": (by.get("candidate") or {}).get("functional", 0),
            "candidate_reaches_baseline": counts.get("candidate_reaches_baseline", 0),
            "candidate_reaches_linked_baseline": counts.get("candidate_reaches_linked_baseline", 0),
            "candidate_below_baseline": counts.get("candidate_below_baseline", 0),
            "candidate_baseline_not_linked": counts.get("candidate_baseline_not_linked", 0),
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _failure_minimization_court(name: str) -> dict:
    """`RT-FAILURE-MINIMIZATION`: 24.8's court, the failure discovery/minimization loop.

    Stages no probe. It reads the committed failures plane `forensics/downstream/failures.json`, its
    minimized fixtures under `forensics/downstream/failures/`, the committed 24.6 build/link atlas,
    the committed 24.7 runtime/functional atlas, the committed frozen P1000 and the committed
    families, and re-runs the 24.8 validation and sensitivity control over the committed artefact
    **without rebuilding, launching or minimizing anything**. It establishes that every non-resolved
    leftover the two atlases record has exactly one classified record and that no record is
    fabricated; that a `candidate-specific` record's ruling really derives from the
    authority-applicable baseline (the candidate fell below a level the authority reached) and a
    `venue-limited` one really has an authority failure at the same or a lower level in the same
    admitted venue; that every candidate-specific record carries a minimized fixture on disk that
    hashes to its record and a runnable command; that `unclassified` is 0; that the genealogy
    references only real failures and never asserts a fix commit that nothing establishes; and that
    the counts are derived rather than typed. Six seeded mutations are each caught with specificity
    holding. A passing court is an **instrument**: it says every discovered failure is a named,
    reproducible record, not that any consumer is safe, and it makes no claim to have fixed
    anything.
    """
    if not DOWNSTREAM_FAILURES.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the failures artefact {rel(DOWNSTREAM_FAILURES)} is absent"],
                "findings": [], "control": {}}

    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    build_link_body = downstream_build_link._load_atlas()
    runtime_body = downstream_runtime._load_atlas()
    failures_body = downstream_failures._load_json(DOWNSTREAM_FAILURES)
    findings = downstream_failures.failure_findings(freeze_body, build_link_body, runtime_body,
                                                   failures_body)
    control = downstream_failures.failure_sensitivity_control(
        freeze_body, build_link_body, runtime_body, failures_body)

    counts = failures_body.get("counts") or {}
    planned = next((r for r in failures_body.get("failures") or []
                    if r.get("disposition") == "candidate-specific"), None)
    examples = {
        "rule": failures_body.get("rule"),
        "by_disposition": counts.get("by_disposition"),
        "by_failure_class": counts.get("by_failure_class"),
        "by_residual_class": counts.get("by_residual_class"),
        "divergences": failures_body.get("divergences"),
        "candidate_specific_families": counts.get("candidate_specific_families"),
        "first_candidate_specific": ({k: planned.get(k) for k in
                                      ("failure_id", "consumer", "residual_class",
                                       "failure_class", "first_divergent_observation")}
                                     if planned else None),
        "genealogy_head": (failures_body.get("genealogy") or [])[:3],
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/failures.json and its minimized "
            "fixtures under forensics/downstream/failures/, the 24.6 build/link atlas, the 24.7 "
            "runtime/functional atlas, forensics/downstream/family-freeze.json and "
            "forensics/downstream/families.json, and re-runs the 24.8 validation and sensitivity "
            "control over the committed plane without rebuilding, launching or minimizing "
            "anything. It establishes that every non-resolved leftover the two atlases record has "
            "exactly one classified record and that none is fabricated; that a candidate-specific "
            "record derives from the authority-applicable baseline (the candidate fell below a "
            "level the authority reached) and a venue-limited record has an authority failure at "
            "the same or a lower level in the same admitted venue, so a venue limitation is never "
            "counted as a candidate defect (the brief's section 44); that every candidate-specific "
            "record carries a minimized fixture on disk that hashes to its record and a runnable "
            "command; that unclassified is 0; that the genealogy references only real failures and "
            "asserts no fix commit; and that the counts are derived rather than typed. The six "
            "seeded mutations -- a candidate failure mislabeled candidate-specific without an "
            "authority failure to justify it, a venue-limited failure with no authority failure "
            "behind it, a settled leftover marked unclassified, a settled leftover omitted, a "
            "minimized claim whose fixture is missing on disk, and a fabricated fix commit -- are "
            "each detected with specificity holding. A passing court is an instrument: a "
            "discovered-and-minimized failure is a preserved record, not a fix, and a minimized "
            "reproducer is not the consumer (docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections "
            "2, 3.5 and 4.9 and the brief's sections 30, 31, 32, 44, 46 and 72)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the failure-minimization court reads committed artefacts and fixtures and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "counts": {
            "leftovers": counts.get("leftovers", 0),
            "candidate_specific": counts.get("candidate_specific", 0),
            "venue_limited": counts.get("venue_limited", 0),
            "intentional_out_of_scope": counts.get("intentional_out_of_scope", 0),
            "minimized": counts.get("minimized", 0),
            "unclassified": counts.get("unclassified", 0),
            "divergences": counts.get("divergences", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _high_value_tier_court(name: str) -> dict:
    """`RT-HIGH-VALUE-TIER`: 24.9's court, the high-value deep tier.

    Stages no probe. It reads the committed tier `forensics/downstream/high-value-tier.json`, the
    committed 24.3 usage fingerprints `forensics/downstream/usage-fingerprints.json`, the committed
    24.7 runtime/functional atlas, the committed frozen P1000 `forensics/downstream/family-freeze.json`
    and the committed families `forensics/downstream/families.json`, and re-runs the 24.9 validation
    and sensitivity control over the committed artefact **without rebuilding and without launching
    anything**. It establishes that the tier reproduces from the frozen depth rule (the committed
    24.3 fingerprints, ordered by distinct imported symbols, then API-family breadth, then distinct
    headers, then direct-before-transitive, then canonical name/family_id) and reads no candidate row;
    that every tier member is a real committed direct-consumer family with both-subject runs; that a
    carried row cites a committed 24.7 row agreeing on its level and transcript hash; that an `L5+`
    row is backed by a real load proof resolving the subject prefix and never the authority's; that
    an `L6`/`L7` row carries a non-empty normalised transcript hash and a normalisation that erases
    no evidence; that a candidate row never claims a level above the authority-applicable baseline;
    that every non-selected P1000 family carries a reason and the accounting covers the whole P1000;
    that `candidate_specific_patch_count` is 0; and that the counts are derived rather than typed.
    Six seeded mutations are each caught with specificity holding. A passing tier is a
    **measurement**, not a security proof: it says the deepest families the committed evidence
    selects loaded the subject's libssl/libcrypto and completed one deterministic local workload, not
    that any consumer outside the tier is safe.
    """
    if not HIGH_VALUE_TIER.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the high-value tier artefact {rel(HIGH_VALUE_TIER)} is absent"],
                "findings": [], "control": {}}

    fingerprints_body = json.loads(USAGE_FINGERPRINTS.read_text(encoding="utf-8"))["body"]
    runtime_body = downstream_runtime._load_atlas()
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    tier_body = json.loads(HIGH_VALUE_TIER.read_text(encoding="utf-8"))["body"]
    findings = downstream_high_value.high_value_findings(fingerprints_body, runtime_body,
                                                         families_body, freeze_body, tier_body)
    control = downstream_high_value.high_value_sensitivity_control(
        fingerprints_body, runtime_body, families_body, freeze_body, tier_body)

    counts = tier_body.get("counts") or {}
    by = counts.get("by_subject") or {}
    tier = tier_body.get("tier") or []
    runs = tier_body.get("runs") or []
    examples = {
        "rule": tier_body.get("rule"),
        "tier": [{"family": m.get("canonical_name"), "family_id": m.get("family_id"),
                  "source": m.get("source"), "depth_rank": m.get("depth_rank"),
                  "authority_applicable_baseline": m.get("authority_applicable_baseline"),
                  "admission": m.get("admission")} for m in tier],
        "precedent_consumers": tier_body.get("precedent_consumers"),
        "authority_applicable_level": counts.get("authority_applicable_level"),
        "runs": [{"family": r.get("canonical_name"), "subject": r.get("subject"),
                  "level": r.get("level"), "outcome": r.get("outcome"),
                  "carried_from": r.get("carried_from"), "workload": r.get("workload"),
                  "residual_class": r.get("residual_class")} for r in runs],
        "tier_not_measured": counts.get("tier_not_measured"),
        "accounting": counts.get("accounting"),
        "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/high-value-tier.json, "
            "forensics/downstream/usage-fingerprints.json, the 24.7 runtime/functional atlas, "
            "forensics/downstream/family-freeze.json and forensics/downstream/families.json and "
            "re-runs the 24.9 validation and sensitivity control over the committed artefact "
            "without rebuilding and without launching anything. It establishes that the tier "
            "reproduces from the frozen depth rule (the committed 24.3 usage fingerprints, ordered "
            "by distinct imported OpenSSL symbols, then API-family breadth, then distinct headers, "
            "then direct-before-transitive, then canonical name/family_id) and reads no candidate "
            "row; that every tier member is a real committed direct-consumer family with "
            "both-subject runs; that a carried row cites a committed 24.7 row agreeing on its level "
            "and transcript hash; that an L5+ row is backed by a real load proof resolving the "
            "subject prefix and never the authority's; that an L6/L7 row carries a non-empty "
            "normalised transcript hash and a normalisation that erases no evidence; that a "
            "candidate row never claims a level above the authority-applicable baseline; that every "
            "non-selected P1000 family carries a reason and the accounting covers the whole P1000; "
            "that candidate_specific_patch_count is 0; and that the counts are derived rather than "
            "typed. The six seeded mutations -- a tier member dropped, a family added to the tier by "
            "a candidate result rather than the depth rule, a candidate L7 above the authority "
            "baseline marked pass, an L5 row with no load proof, an empty transcript at L6, and a "
            "not-selected P1000 family with no reason -- are each detected with specificity holding. "
            "A passing tier is a measurement, not a security proof: it says the deepest families the "
            "committed evidence selects loaded the subject's libssl/libcrypto and completed one "
            "deterministic local workload, not that any consumer outside it is safe "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.1, 3.2 and 3.6 and the "
            "brief's sections 19, 30, 31, 43, 44 and 46)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the high-value-tier court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "candidate_identity": tier_body.get("candidate_identity"),
        "counts": {
            "tier_size": counts.get("tier_size", 0),
            "tier_fingerprint": counts.get("tier_fingerprint", 0),
            "tier_precedent": counts.get("tier_precedent", 0),
            "tier_in_p1000": counts.get("tier_in_p1000", 0),
            "tier_outside_p1000": counts.get("tier_outside_p1000", 0),
            "rows": counts.get("rows", len(runs)),
            "p1000_accounted": counts.get("p1000_accounted", 0),
            "accounting_tier_measured": (counts.get("accounting") or {}).get("tier_measured", 0),
            "accounting_not_selected": (counts.get("accounting") or {}).get("not_selected", 0),
            "authority_loaded": (by.get("authority") or {}).get("loaded", 0),
            "authority_runtime": (by.get("authority") or {}).get("runtime", 0),
            "authority_functional": (by.get("authority") or {}).get("functional", 0),
            "candidate_loaded": (by.get("candidate") or {}).get("loaded", 0),
            "candidate_runtime": (by.get("candidate") or {}).get("runtime", 0),
            "candidate_functional": (by.get("candidate") or {}).get("functional", 0),
            "candidate_reaches_baseline": counts.get("candidate_reaches_baseline", 0),
            "candidate_failures": counts.get("candidate_failures") or {},
            "tier_not_measured": len(counts.get("tier_not_measured") or []),
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _hostility_augmentation_court(name: str) -> dict:
    """`RT-HOSTILITY-AUGMENTATION`: 24.10's court, the separate hostility-augmentation corpus.

    Stages no probe. It reads the committed corpus `forensics/downstream/hostility-corpus.json`, the
    committed P1000 union inputs (the 24.3 usage fingerprints and the 24.6/24.7/24.9 atlases), the
    Phase-22 public-entity inventory and the committed frozen P1000
    `forensics/downstream/family-freeze.json`, and re-runs the 24.10 selection, validation and
    sensitivity control over the committed artefact **without rebuilding a probe**. It establishes
    that the corpus reproduces from the frozen maximum-marginal-novelty rule over the covered
    surface and reads no candidate row; that the corpus is **separate** -- no member is a P1000
    counted family, no member carries a frozen `family_id`, and the frozen P1000 count is unchanged;
    that every member contributes at least one new public entity not in the covered surface; that
    every member has both-subject runs; that each member's linkage is subject-correct with a real
    load proof on an `L5+` row (a candidate row never resolves the authority); that the transcript
    normalisation is applied identically to both subjects; that `candidate_specific_patch_count` is
    0; and that the counts are derived rather than typed. Six seeded mutations are each caught with
    specificity holding. A passing corpus is a **separate instrument**, not a rate: it says the rare
    surfaces were exercised against both subjects, and its results are never mixed into the counted
    population's rates.
    """
    if not HOSTILITY_CORPUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the hostility corpus artefact {rel(HOSTILITY_CORPUS)} is absent"],
                "findings": [], "control": {}}

    inputs = downstream_hostility.load_inputs()
    corpus_body = json.loads(HOSTILITY_CORPUS.read_text(encoding="utf-8"))["body"]
    findings = downstream_hostility.hostility_findings(inputs, corpus_body)
    control = downstream_hostility.hostility_sensitivity_control(inputs, corpus_body)

    counts = corpus_body.get("counts") or {}
    by = counts.get("by_subject") or {}
    corpus = corpus_body.get("corpus") or []
    runs = corpus_body.get("runs") or []
    examples = {
        "rule": corpus_body.get("rule"),
        "covered_surface": {
            "symbol_count": (corpus_body.get("covered_surface") or {}).get("symbol_count"),
            "header_count": (corpus_body.get("covered_surface") or {}).get("header_count"),
            "api_family_count": (corpus_body.get("covered_surface") or {}).get("api_family_count"),
            "hash": (corpus_body.get("covered_surface") or {}).get("hash"),
        },
        "corpus": [{"surface_id": m.get("surface_id"), "selection_rank": m.get("selection_rank"),
                    "variant": m.get("variant"), "probe_kind": m.get("probe_kind"),
                    "marginal_novelty": m.get("marginal_novelty"),
                    "marginal_new_entities": m.get("marginal_new_entities"),
                    "legacy_entities": m.get("legacy_entities")} for m in corpus],
        "not_selected": corpus_body.get("not_selected"),
        "runs": [{"probe_id": r.get("probe_id"), "subject": r.get("subject"),
                  "direction": r.get("direction"), "level": r.get("level"),
                  "outcome": r.get("outcome"), "residual_class": r.get("residual_class"),
                  "failure_class": r.get("failure_class"), "divergence": r.get("divergence")}
                 for r in runs],
        "candidate_failures": counts.get("candidate_failures") or {},
        "separated_by_design": counts.get("separated_by_design"),
        "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/hostility-corpus.json, the committed "
            "P1000 union inputs (the 24.3 usage fingerprints and the 24.6/24.7/24.9 atlases), the "
            "Phase-22 public-entity inventory and forensics/downstream/family-freeze.json and "
            "re-runs the 24.10 maximum-marginal-novelty selection, validation and sensitivity "
            "control over the committed artefact without rebuilding a probe. It establishes that "
            "the corpus reproduces from the frozen novelty rule over the covered surface; that the "
            "corpus is separate -- no member is a P1000 counted family, no member carries a frozen "
            "family_id and the frozen P1000 count is unchanged; that every member contributes at "
            "least one new public entity and has both-subject runs; that each member's linkage is "
            "subject-correct with a real load proof on an L5+ row; that the transcript "
            "normalisation is applied identically to both subjects; that "
            "candidate_specific_patch_count is 0; and that the counts are derived rather than "
            "typed. The six seeded mutations -- a hostility member injected into the P1000 counts, "
            "a corpus member with no new entity, a candidate row resolving the authority, a missing "
            "authority run, an unnormalised transcript and a corpus member beyond the bound -- are "
            "each detected with specificity holding. A passing corpus is a separate instrument, not "
            "a rate: its results are never mixed into the counted population's rates "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.7 and 4.9 and the brief's "
            "sections 12, 19, 36, 43, 46, 61, 62, 63 and 64)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the hostility-augmentation court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "candidate_identity": corpus_body.get("candidate_identity"),
        "counts": {
            "corpus_size": counts.get("corpus_size", 0),
            "corpus_c": counts.get("corpus_c", 0),
            "corpus_network": counts.get("corpus_network", 0),
            "corpus_bound": counts.get("corpus_bound", 0),
            "new_public_entities": counts.get("new_public_entities", 0),
            "distinct_new_public_entities": counts.get("distinct_new_public_entities", 0),
            "covered_surface_symbols": counts.get("covered_surface_symbols", 0),
            "rows": counts.get("rows", len(runs)),
            "authority_loaded": (by.get("authority") or {}).get("loaded", 0),
            "authority_runtime": (by.get("authority") or {}).get("runtime", 0),
            "authority_functional": (by.get("authority") or {}).get("functional", 0),
            "candidate_loaded": (by.get("candidate") or {}).get("loaded", 0),
            "candidate_runtime": (by.get("candidate") or {}).get("runtime", 0),
            "candidate_functional": (by.get("candidate") or {}).get("functional", 0),
            "candidate_failed": (by.get("candidate") or {}).get("failed", 0),
            "candidate_failures": counts.get("candidate_failures") or {},
            "divergences": counts.get("divergences", 0),
            "linkage_proven": counts.get("linkage_proven", 0),
            "p1000": counts.get("p1000", 0),
            "p1000_hostility_overlap": counts.get("p1000_hostility_overlap", 0),
            "separated_by_design": counts.get("separated_by_design"),
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _candidate_freeze_court(name: str) -> dict:
    """`RT-CANDIDATE-FREEZE`: 24.11's court, the candidate freeze and the once-run holdout.

    Stages no probe. It reads the committed freeze `forensics/downstream/candidate-freeze.json`, the
    committed precommitted holdout `forensics/downstream/holdout.json`, the frozen P1000
    `forensics/downstream/family-freeze.json`, the committed 24.6 build/link atlas, the committed 24.7
    runtime/functional atlas, the committed 24.8 failures plane, the committed 24.9 high-value tier
    and the committed 24.10 hostility corpus, and re-runs the 24.11 validation and sensitivity control
    over the committed artefact **without re-running the holdout and without rebuilding anything**.
    It establishes that the frozen candidate identity reproduces from the committed install (the
    libssl/libcrypto digests, the headers, pkg-config, provider modules and the crate version, with
    the source commit carried as recorded, existence-checked provenance rather than a live-HEAD
    binding); that the holdout set equals the precommitted partition, reproduces from the frozen
    P1000 by the 24.5 rule, and carries a matching `partition_root_hash`; that `first_run` is present,
    equals the summary derived from the holdout run, and is attested unchanged by every rerun; that
    every holdout family has an accounting row; that a candidate row never claims a level above the
    authority-applicable baseline; that a family's verdict is the derived baseline-normalized one;
    that `candidate_specific_patch_count` is 0; that the counts are derived rather than typed; and
    that no holdout family is a source of a fix in the development-side failure plane. Six seeded
    mutations are each caught with specificity holding. A passing freeze is a **measurement**, not a
    security proof: a holdout result over a selected population is an out-of-sample measurement of
    that population, not of all downstream software, and a venue-limited holdout member is neither a
    pass nor a fail.
    """
    if not CANDIDATE_FREEZE.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the candidate-freeze artefact {rel(CANDIDATE_FREEZE)} is absent"],
                "findings": [], "control": {}}

    inputs = downstream_candidate_freeze.load_inputs()
    body = json.loads(CANDIDATE_FREEZE.read_text(encoding="utf-8"))["body"]
    findings = downstream_candidate_freeze.candidate_freeze_findings(inputs, body)
    control = downstream_candidate_freeze.candidate_freeze_sensitivity_control(inputs, body)

    counts = body.get("counts") or {}
    by = counts.get("by_subject") or {}
    ident = body.get("candidate_identity") or {}
    hb = body.get("holdout") or {}
    fr = body.get("first_run") or {}
    account = body.get("accounting") or []
    rows = (body.get("holdout_run") or {}).get("runs") or []
    verdicts = (body.get("holdout_run") or {}).get("verdicts") or []
    examples = {
        "rule": body.get("rule"),
        "candidate_identity": ident,
        "holdout": hb,
        "first_run": fr,
        "learning_curve": body.get("learning_curve"),
        "reruns": [{"rerun_index": r.get("rerun_index"),
                    "candidate_identity_hash": r.get("candidate_identity_hash"),
                    "first_run_hash": r.get("first_run_hash")} for r in body.get("reruns") or []],
        "accounting_head": account[:6],
        "accounting_venue_limited": sum(1 for a in account
                                        if a.get("selection") == "venue_limited"),
        "heldout_runs": [{"family": r.get("canonical_name"), "subject": r.get("subject"),
                          "level": r.get("level"), "outcome": r.get("outcome"),
                          "residual_class": r.get("residual_class"),
                          "failure_class": r.get("failure_class")} for r in rows
                         if str(r.get("level")) != downstream_candidate_freeze.L0],
        "verdicts": [{"family": v.get("canonical_name"), "verdict": v.get("verdict"),
                      "authority_applicable_level": v.get("authority_applicable_level"),
                      "candidate_level": v.get("candidate_level")} for v in verdicts],
        "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/candidate-freeze.json, "
            "forensics/downstream/holdout.json, forensics/downstream/family-freeze.json, the 24.6 "
            "build/link atlas, the 24.7 runtime/functional atlas, the 24.8 failures plane, the 24.9 "
            "high-value tier and the 24.10 hostility corpus, and re-runs the 24.11 validation and "
            "sensitivity control over the committed artefact without re-running the holdout and "
            "without rebuilding anything. It establishes that the frozen candidate identity "
            "reproduces from the committed install (the libssl/libcrypto digests, the exported "
            "headers, pkg-config metadata, provider modules and the crate version, with the source "
            "commit carried as recorded, existence-checked provenance rather than a live-HEAD "
            "binding); that the holdout set equals the precommitted partition, reproduces from the "
            "frozen P1000 by the 24.5 rule and carries a matching partition_root_hash; that "
            "first_run is present, equals the summary derived from the holdout run, and is attested "
            "unchanged by every rerun; that every holdout family has an accounting row; that a "
            "candidate row never claims a level above the authority-applicable baseline; that a "
            "family's verdict is the derived baseline-normalized one; that "
            "candidate_specific_patch_count is 0; that the counts are derived rather than typed; "
            "and that no holdout family is a source of a fix in the development-side failure plane. "
            "The six seeded mutations -- a precommitted holdout member swapped for a development "
            "member, a mutated partition root, a first_run rewritten after a rerun, a candidate "
            "level above the authority-applicable baseline, a holdout family cited as a fix source, "
            "and a mutated count -- are each detected with specificity holding. A passing freeze is "
            "a measurement, not a security proof: a holdout result over a selected population is an "
            "out-of-sample measurement of that population, not of all downstream software, and a "
            "venue-limited holdout member is neither a pass nor a fail "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.4 and 4.9 and the brief's "
            "sections 41, 42 and 46)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the candidate-freeze court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "candidate_identity": ident,
        "counts": {
            "holdout_families": counts.get("holdout_families", 0),
            "recipe_backed_families": counts.get("recipe_backed_families", 0),
            "measurable_families": counts.get("measurable_families", 0),
            "venue_limited_families": counts.get("venue_limited_families", 0),
            "rows": counts.get("rows", len(rows)),
            "accounting_measured": (counts.get("accounting") or {}).get("measured", 0),
            "accounting_venue_limited": (counts.get("accounting") or {}).get("venue_limited", 0),
            "authority_functional": (by.get("authority") or {}).get("functional", 0),
            "candidate_functional": (by.get("candidate") or {}).get("functional", 0),
            "candidate_reaches_baseline": counts.get("candidate_reaches_baseline", 0),
            "candidate_failures": counts.get("candidate_failures") or {},
            "verdicts": counts.get("verdicts") or {},
            "reruns": len(body.get("reruns") or []),
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _p1000_run_court(name: str) -> dict:
    """`RT-P1000-RUN`: 24.12's court, the final full P1000 run at the frozen candidate.

    Stages no probe. It reads the committed run `forensics/downstream/p1000-run.json`, the frozen
    P1000 `forensics/downstream/family-freeze.json` and the committed 24.11 candidate freeze
    `forensics/downstream/candidate-freeze.json`, and re-runs the 24.12 validation and sensitivity
    control over the committed artefact **without rebuilding anything**. It establishes that the
    candidate identity equals the frozen 24.11 identity (excluding the recorded provenance, so the
    run is against the same candidate); that there is exactly one `drop_in_verdict` per counted
    family, with none missing, extra or fabricated; that a `DROP_IN_PASS` is refused without all
    five of the brief's section 20 conditions; that `DROP_IN_UNKNOWN` is 0; that the ladder equals
    the derived per-level counts and the verdict histogram; that a family this venue cannot pose the
    drop-in question for is `DROP_IN_NOT_APPLICABLE` with a reason; that
    `candidate_specific_patch_count` is 0; and that the counts are derived rather than typed. Five
    seeded mutations are each caught with specificity holding. A passing run is a **measurement**:
    the ladder is over a selected population of 1,000 families, not a percentage of all downstream
    software.
    """
    if not P1000_RUN.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the P1000-run artefact {rel(P1000_RUN)} is absent"],
                "findings": [], "control": {}}

    inputs = downstream_p1000_run.load_inputs()
    body = json.loads(P1000_RUN.read_text(encoding="utf-8"))["body"]
    findings = downstream_p1000_run.p1000_findings(inputs, body)
    control = downstream_p1000_run.p1000_sensitivity_control(inputs, body)

    ladder = body.get("ladder") or {}
    counts = body.get("counts") or {}
    verdicts = body.get("verdicts") or []
    receipts = body.get("per_consumer_receipts") or []
    measured = [v for v in verdicts if str(v.get("verdict")) != "DROP_IN_NOT_APPLICABLE"]
    examples = {
        "rule": body.get("rule"),
        "candidate_identity": body.get("candidate_identity"),
        "population": body.get("population"),
        "ladder": ladder,
        "counts": counts,
        "measured_verdicts": [
            {"family": v.get("canonical_name"), "verdict": v.get("verdict"),
             "authority_applicable_level": v.get("authority_applicable_level"),
             "candidate_level": v.get("candidate_level"),
             "residual_class": v.get("residual_class"), "reason": v.get("reason")}
            for v in measured],
        "not_applicable_head": [
            {"family": v.get("canonical_name"), "residual_class": v.get("residual_class"),
             "reason": v.get("reason")}
            for v in verdicts if str(v.get("verdict")) == "DROP_IN_NOT_APPLICABLE"][:5],
        "measured_receipts": [r for r in receipts
                              if str(r.get("result")) != "DROP_IN_NOT_APPLICABLE"][:8],
    }

    verdict = "pass" if (not findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/p1000-run.json, "
            "forensics/downstream/family-freeze.json and forensics/downstream/candidate-freeze.json, "
            "and re-runs the 24.12 validation and sensitivity control over the committed artefact "
            "without rebuilding anything. It establishes that the candidate identity equals the "
            "frozen 24.11 identity (excluding the recorded provenance, so the run is against the "
            "same candidate); that there is exactly one drop_in_verdict per counted family, with "
            "none missing, extra or fabricated; that a DROP_IN_PASS is refused without all five of "
            "the brief's section 20 conditions (the same pristine source, a succeeded authority "
            "baseline that reached at least L4-linked, the candidate reaching the "
            "authority-applicable level, candidate linkage proven and zero candidate-specific "
            "patches); that DROP_IN_UNKNOWN is 0; that the ladder equals the derived per-level "
            "counts and the verdict histogram; that a family this venue cannot pose the drop-in "
            "question for is DROP_IN_NOT_APPLICABLE with a reason; that "
            "candidate_specific_patch_count is 0; and that the counts are derived rather than "
            "typed. The five seeded mutations -- a PASS asserted without an authority baseline, a "
            "PASS with a positive patch count, a duplicated verdict, a candidate level below the "
            "authority-applicable level marked PASS, and a mismatched candidate identity -- are "
            "each detected with specificity holding. A passing run is a measurement, not a security "
            "proof: the ladder is over a selected population of 1,000 families, not a percentage "
            "of all downstream software, and a venue-limited family is neither a pass nor a fail "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.4 and 4.9 and the brief's "
            "sections 20, 52 and 55)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the P1000-run court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "candidate_identity": body.get("candidate_identity") or {},
        "ladder": ladder,
        "counts": {
            "families": counts.get("families", 0),
            "rows": counts.get("rows", 0),
            "recipe_backed_families": counts.get("recipe_backed_families", 0),
            "measurable_families": counts.get("measurable_families", 0),
            "not_applicable_families": counts.get("not_applicable_families", 0),
            "measurable_reaches_baseline": counts.get("measurable_reaches_baseline", 0),
            "verdicts": counts.get("verdicts") or {},
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "findings": findings,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _atlas_reconciliation_court(name: str) -> dict:
    """`RT-ATLAS-RECONCILIATION`: 24.13's court, the reconciliation of the atlas.

    Stages no probe. It reads the committed reconciliation
    `forensics/downstream/reconciliation.json` and re-runs the 24.13 re-derivation and sensitivity
    control over the committed artefact **without rebuilding anything**. It establishes that every
    counted family has exactly one re-derived `drop_in_verdict` with `DROP_IN_UNKNOWN` 0; that every
    residual across every plane is classified from the closed vocabulary with an unclassified and an
    `unknown` count of 0; that every failure is preserved -- the counted P1000 measured set's plus
    the separate hostility corpus's two candidate failures, which are scoped **out** of every P1000
    rate; that the drop-in rates equal the derived rates and that the direct and transitive consumers
    are never summed; that the ladder equals the verdict counts with `UNKNOWN` 0 and the raw family
    count visible; that the coverage and the Phase-22 projection are consistent with the planes; and
    that the counts are derived rather than typed. Six seeded mutations are each caught with
    specificity holding.

    The court is an **instrument**, not the property: it can pass while the atlas carries real
    property findings (a large `NOT_APPLICABLE` share, a thin measured surface, a non-empty residual
    set). Those are recorded as the row's `findings`, so the ledger reads `property_status`
    honestly; the invariant violations that fail the instrument are `instrument_findings`.
    """
    if not RECONCILIATION.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the reconciliation artefact {rel(RECONCILIATION)} is absent"],
                "findings": [], "instrument_findings": [], "control": {}}

    inputs = downstream_reconciliation.load_inputs()
    body = json.loads(RECONCILIATION.read_text(encoding="utf-8"))["body"]
    instrument_findings = downstream_reconciliation.reconciliation_findings(inputs, body)
    control = downstream_reconciliation.reconciliation_sensitivity_control(inputs, body)
    prop = downstream_reconciliation.reconciliation_property(body)

    rates = body.get("rates") or {}
    ladder = body.get("ladder") or {}
    coverage = body.get("coverage") or {}
    counts = body.get("counts") or {}
    residuals = body.get("residuals") or {}
    failures = body.get("failures_summary") or {}
    clusters = body.get("clusters") or {}
    phase22 = body.get("phase22_projection") or {}
    verdicts = body.get("verdicts") or []
    measured = [v for v in verdicts if str(v.get("verdict")) != "DROP_IN_NOT_APPLICABLE"]
    fp1000 = failures.get("p1000") or {}
    fhost = failures.get("hostility") or {}
    examples = {
        "rule": body.get("rule"),
        "population": body.get("population"),
        "unweighted_rates": rates.get("unweighted"),
        "measurable_rates": rates.get("measurable"),
        "ladder": ladder,
        "coverage": coverage,
        "phase22_projection": {
            "direct": phase22.get("direct"),
            "inferred": phase22.get("inferred"),
            "compatibility_views": phase22.get("compatibility_views"),
            "separated": phase22.get("separated"),
        },
        "residuals": {
            "total": residuals.get("total"),
            "unresolved": residuals.get("unresolved"),
            "unknown": residuals.get("unknown"),
            "unclassified": residuals.get("unclassified"),
            "histogram": residuals.get("histogram"),
        },
        "failures_summary": {
            "p1000": {k: fp1000.get(k) for k in
                      ("total", "preserved", "minimized", "candidate_specific",
                       "by_failure_class", "by_disposition", "by_residual_class", "divergences")},
            "hostility": {k: fhost.get(k) for k in ("total", "preserved", "minimized",
                                                   "candidate_specific", "scoped")},
            "all_preserved": failures.get("all_preserved"),
            "hostility_records": [
                {k: r.get(k) for k in ("failure_id", "run_id", "class", "preserved",
                                       "minimized")}
                for r in fhost.get("records") or []],
        },
        "clusters": {
            "cluster_count": clusters.get("cluster_count"),
            "distinct_stressors": clusters.get("distinct_stressors"),
            "clusters": clusters.get("clusters"),
            "marginal": clusters.get("marginal"),
            "marginal_consumers": clusters.get("marginal_consumers"),
        },
        "measured_verdicts": [
            {k: v.get(k) for k in ("canonical_name", "verdict", "authority_applicable_level",
                                   "candidate_level", "residual_class")}
            for v in measured],
        "not_applicable_head": [
            {k: v.get(k) for k in ("canonical_name", "residual_class")}
            for v in verdicts if str(v.get("verdict")) == "DROP_IN_NOT_APPLICABLE"][:5],
        "property_findings": body.get("property_findings"),
    }

    verdict = "pass" if (not instrument_findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/downstream/reconciliation.json and every committed "
            "downstream plane it reconciles, and re-runs the 24.13 re-derivation and sensitivity "
            "control over the committed artefact without rebuilding anything. It establishes that "
            "every counted family has exactly one re-derived drop_in_verdict with DROP_IN_UNKNOWN "
            "0; that every residual across every plane is classified from the closed vocabulary "
            "with an unclassified and an unknown count of 0; that every failure is preserved -- the "
            "counted P1000 measured set's plus the separate hostility corpus's two candidate "
            "failures, classified and scoped out of every P1000 rate; that the drop-in rates equal "
            "the derived rates, are unweighted over the frozen population and never sum the direct "
            "and transitive consumers; that the ladder equals the verdict counts with UNKNOWN 0 and "
            "the raw family count visible; that the coverage and the Phase-22 direct/inferred "
            "projection are consistent with the planes; and that the counts are derived rather "
            "than typed. The six seeded mutations -- a counted family with no verdict, a residual "
            "left unknown, a failure dropped from the summary, a hostility result mixed into the "
            "P1000 rate, a typed rate that disagrees with the verdicts, and a failure not "
            "preserved -- are each detected with specificity holding. The court is an instrument, "
            "not the property: it can pass while the atlas carries real property findings, which "
            "are recorded as findings and make property_status NOT_CLAIMED "
            "(docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md sections 2, 3.3, 3.5, 3.6 and 3.7 and "
            "the brief's sections 34, 35, 36, 37, 52 and 53)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the atlas-reconciliation court reads committed artefacts and brings no "
            "artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "findings": prop["property_findings"],
        "property_status": prop["property_status"],
        "instrument_findings": instrument_findings,
        "rates": rates,
        "ladder": ladder,
        "coverage": {
            "measured": coverage.get("measured"),
            "known_universe": coverage.get("known_universe"),
            "ratios": coverage.get("ratios"),
        },
        "counts": {
            "families": counts.get("families", 0),
            "measurable_families": counts.get("measurable_families", 0),
            "not_applicable_families": counts.get("not_applicable_families", 0),
            "verdicts": counts.get("verdicts") or {},
            "status": counts.get("status") or {},
            "residuals_total": counts.get("residuals_total", 0),
            "residuals_unresolved": counts.get("residuals_unresolved", 0),
            "residuals_unknown": counts.get("residuals_unknown", 0),
            "residuals_unclassified": counts.get("residuals_unclassified", 0),
            "failures_p1000": counts.get("failures_p1000", 0),
            "failures_hostility": counts.get("failures_hostility", 0),
            "failures_preserved": counts.get("failures_preserved", 0),
            "coverage_symbols": counts.get("coverage_symbols", 0),
            "coverage_headers": counts.get("coverage_headers", 0),
            "coverage_api_families": counts.get("coverage_api_families", 0),
            "phase22_reachable_entities": counts.get("phase22_reachable_entities", 0),
            "usage_clusters": counts.get("usage_clusters", 0),
            "distinct_stressors": counts.get("distinct_stressors", 0),
            "marginal_consumers": counts.get("marginal_consumers", 0),
            "candidate_specific_patch_count": counts.get("candidate_specific_patch_count", 0),
        },
        "examples": examples,
        "control": control,
        "problems": [],
        "verdict": verdict,
    }


def _frf_closure_court(name: str) -> dict:
    """`RT-FRF-CLOSURE`: 24.14's court, the FRF/Gemel chain closure.

    Stages no probe. It reads the committed closure `forensics/atlas/phase24/frf-closure.json` and
    re-runs the 24.14 classification with **no** side effects, plus two things re-derived from the
    live committed tree: the FRF chain staging (read from the `gen_frf_courts.py` registry and the
    tree's `artifacts/phase24/probes/` directory, never from `COURTS.json`) and the Gemel checkpoint
    projection (read from the committed `forensics/GEMEL_TRAJECTORY.md`, never the store). It
    establishes that every Phase-24 plane's own checker detected its own defect class, that the
    classification of every registered challenge re-derives from its recorded expected/observed, that
    the recorded chain staging and Gemel projection reproduce from the committed evidence, that no
    Phase-24 court is declarable so the FRF/Gemel chain entry is vacuous by
    `frf_gemel_blocking_reason`'s own scoping, and that the classifier is not a rubber stamp: a
    registered challenge whose observed result is mutated in memory is reported `NOT_DETECTED`, an
    injected Phase-24 declaration and an injected probe pair are each caught, a stripped current
    checkpoint and a checkpointless projection are each caught, and a flipped recorded status is a
    finding. The court is an **instrument**: it passes while its property finding records that the
    stratum stages no declarable court, so a passing closure is never read as a chain that ran.
    """
    if not FRF_CLOSURE.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the FRF closure artefact {rel(FRF_CLOSURE)} is absent"],
                "findings": [], "instrument_findings": [], "control": {}}

    body = json.loads(FRF_CLOSURE.read_text(encoding="utf-8"))["body"]
    evidence = phase24_frf.collect_evidence()
    instrument_findings = phase24_frf.frf_closure_findings(body, evidence)
    control = phase24_frf.frf_closure_sensitivity_control(body, evidence)
    prop = phase24_frf.frf_closure_property(body, evidence)

    counts = body.get("counts") or {}
    chain = body.get("chain") or {}
    gemel = body.get("gemel") or {}
    challenges = body.get("challenges") or []
    examples = {
        "harness": body.get("harness"),
        "chain": chain,
        "gemel": gemel,
        "challenges": [
            {"plane": c.get("plane"), "instrument": c.get("instrument"),
             "status": c.get("status"), "defect_class": c.get("defect_class"),
             "mutations": c.get("mutations")}
            for c in challenges
        ],
        "property_findings": body.get("property_findings"),
    }

    verdict = "pass" if (not instrument_findings and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads forensics/atlas/phase24/frf-closure.json and re-runs the "
            "24.14 classification with no side effects, re-deriving the FRF chain staging from the "
            "gen_frf_courts.py registry and the artifacts/phase24/probes/ directory and the Gemel "
            "checkpoint projection from the committed forensics/GEMEL_TRAJECTORY.md (never the "
            "store, never COURTS.json). It establishes that each Phase-24 plane's own pure checker "
            "detected its own defect class, that every registered challenge's classification "
            "re-derives from its recorded expected/observed, that the recorded chain staging and "
            "Gemel projection reproduce, and that no Phase-24 court is declarable so the FRF/Gemel "
            "chain entry is vacuous by frf_gemel_blocking_reason's own scoping. The classifier is "
            "not a rubber stamp: a registered challenge whose observed result is mutated in memory "
            "is reported NOT_DETECTED, an injected Phase-24 declaration and an injected probe pair "
            "are each caught, a stripped current checkpoint and a checkpointless projection are "
            "each caught, and a flipped recorded status is a finding, with specificity holding. "
            "The court is an instrument, not the property: it can pass while its property finding "
            "records that the stratum stages no declarable court, so a passing closure is never "
            "read as a chain that ran (docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md section 2's 24.14 "
            "row and docs/RELEASE_GATES.md section 2 items 6, 8 and 10)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the FRF/Gemel closure court reads committed artefacts and the FRF registry and stages "
            "no artifacts/phase24/probes/ pair, so it takes no transcript to diff and carries no "
            "FRF declaration"
        ),
        "challenges": counts.get("planes", len(challenges)),
        "detected": counts.get("detected", 0),
        "not_detected": counts.get("not_detected", 0),
        "not_driven": counts.get("not_driven", 0),
        "failed_planes": [c.get("plane") for c in challenges if c.get("status") != "DETECTED"],
        "chain": chain,
        "gemel": gemel,
        "findings": prop["property_findings"],
        "property_status": prop["property_status"],
        "instrument_findings": instrument_findings,
        "counts": {
            "planes": counts.get("planes", len(challenges)),
            "detected": counts.get("detected", 0),
            "not_detected": counts.get("not_detected", 0),
            "not_driven": counts.get("not_driven", 0),
            "declared_courts": len(chain.get("declared_courts") or []),
            "probe_pairs": len(chain.get("probe_pairs") or []),
            "chain_vacuous": bool(chain.get("vacuous")),
            "gemel_current": gemel.get("current"),
            "gemel_checkpoints": gemel.get("checkpoint_count", 0),
            "gemel_checkpoint_owed": bool(gemel.get("checkpoint_owed")),
        },
        "examples": examples,
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
            "it says the selection input was frozen before any candidate result. "
            "`RT-CANDIDATE-UNIVERSE` is 24.2's court: the candidate family universe. It stages "
            "no probe and reads forensics/downstream/candidates.json and "
            "forensics/downstream/families.json, re-deriving both from the committed "
            "forensics/downstream/ranking/normalized/ inputs. It establishes that every family "
            "is schema-valid (kind `family`) and provenance-backed; that aliases of one upstream "
            "collapse to one family (the libcurl4/curl/curl-dev/curl-doc set is one family, not "
            "four); that the OpenSSL providers and a name collision (`libcrypto++`) are not "
            "counted as consumers; that a fork is not independent without explicit evidence of "
            "materially different OpenSSL integration; that a transitive consumer is not counted "
            "as direct; and that the universe is substantially larger than 1,000 before "
            "deduplication. A double-counted distro alias, a transitive consumer promoted to "
            "direct, a fork counted independent with no evidence and a family with no provenance "
            "are each detected with specificity holding. "
            "`RT-AUTHORITY-CENSUS` is 24.3's court: the authority-baseline census. It stages no "
            "probe and reads forensics/downstream/authority-baselines.jsonl and "
            "forensics/downstream/usage-fingerprints.json, re-deriving the provisional census "
            "cohort from the committed families. It establishes that every cohort member has an "
            "authority result classified; that an `AUTHORITY_BASELINE_FAIL` carries an authority "
            "failure class from the taxonomy and a reason, and is never counted as a candidate "
            "failure; that a `AUTHORITY_BASELINE_PASS`'s linkage proof resolves the admitted "
            "authority's own libssl/libcrypto and never a system one; that the cohort selection "
            "rule is recorded and reproduces from the frozen sources; and that no candidate "
            "execution occurred. A build claiming authority linkage while resolving a system "
            "libssl, an authority failure counted as a candidate failure, a cohort member with "
            "no source hash and a fingerprint with no imported symbols claimed as a pass are each "
            "detected with specificity holding. A passing census is a measurement, not a "
            "candidate result: the authority side reached the level it records, and no candidate "
            "ran. "
            "`RT-FAMILY-FREEZE` is 24.4's court: the P1000 + reserve freeze. It stages no probe "
            "and reads forensics/downstream/family-freeze.json and "
            "forensics/downstream/families.json, re-deriving the ranked universe from the "
            "committed families by the frozen selection rule (source breadth, then distro "
            "breadth, then popularity, then canonical name, then family_id). It establishes that "
            "the recorded P1000 is exactly the derived top-1,000 and the reserve the derived "
            "remainder in rank order; that the P1000 is distinct and disjoint from the reserve; "
            "that both are a subset of the universe; that ranks are positions and the recorded "
            "signal is each family's own; that the recorded selection root reproduces and its "
            "selection_input_root_hash, families sha256 and rule sha256 match the committed "
            "files; and that no candidate-subject run exists in the pre-freeze plane (the "
            "candidate-result artefacts the stratum produces after the freeze -- 24.6's build/link "
            "atlas onward -- are excluded), so "
            "the population is frozen before any candidate result. Two P1000 members' order "
            "swapped, a P1000 member deleted so the count is wrong, a family id shared between "
            "the P1000 and the reserve, a mutated selection root, and a fabricated "
            "candidate-subject run row in the downstream plane are each detected with specificity "
            "holding. A passing freeze is a precommitment, not a result, and it refuses the "
            "anti-pattern of a family typed into the 1,000 because a candidate passed it. "
            "`RT-HOLDOUT-PARTITION` is 24.5's court: the precommitted holdout partition. It "
            "stages no probe and reads forensics/downstream/holdout.json, "
            "forensics/downstream/family-freeze.json and forensics/downstream/families.json, "
            "re-deriving the partition from the committed frozen P1000 by the frozen rank-band "
            "rule (bands of 100, each band ordered by content_hash('phase24-holdout-v1:'+family_id) "
            "ascending, tiebreak by family_id, the first 20 holdout and the remaining 80 "
            "development). It establishes that the two cohorts union to exactly the frozen P1000; "
            "that they are disjoint and each family_id appears exactly once; that every family_id "
            "is a real committed family; that each band contributes exactly 20 holdout / 80 "
            "development; that the cohorts reproduce from the frozen rule; that the partition root "
            "reproduces; that the counts are read rather than typed; that the partition is a pure "
            "function of the frozen P1000 (no family outside it); and that no candidate-subject run "
            "exists anywhere in the downstream plane, so the split is fixed before any candidate "
            "result. One development family moved into the holdout cohort, one holdout member "
            "deleted, a family_id duplicated into both cohorts, a P1000-external family added, a "
            "mutated partition root, and a fabricated candidate-subject run row in the downstream "
            "plane are each detected with specificity holding. A passing partition is a "
            "precommitment, not a result, and it refuses the anti-pattern of a holdout chosen "
            "after seeing a candidate failure -- a holdout that is no longer out-of-sample. "
            "`RT-BUILD-LINK-ATLAS` is 24.6's court: the build/link atlas. It stages no probe "
            "and reads forensics/downstream/build-link-atlas.json, "
            "forensics/downstream/family-freeze.json and forensics/downstream/families.json, "
            "re-running the 24.6 validation and sensitivity control over the committed artefact "
            "without rebuilding. It establishes that every frozen P1000 family is accounted for "
            "under both subjects; that every recipe-backed family has both an authority and a "
            "candidate row for the same specimen and the same recipe (identical build intent); "
            "that a candidate L4-linked row's linkage proof resolves the candidate install and "
            "never the authority prefix nor a system library; that an authority L4-linked row "
            "resolves the authority; that candidate_specific_patch_count is 0; that every "
            "non-measured row carries a reason and a schema-valid residual/failure class; and "
            "that the counts are derived rather than typed. A candidate L4 row whose linkage "
            "resolves the authority, a recipe-backed family missing its authority row, a "
            "positive candidate-specific patch count, a non-measured row with no residual "
            "class, and a candidate L4 row whose linkage resolves a system library are each "
            "detected with specificity holding. A passing atlas is a measurement, not a "
            "functional proof: the linkage proof says the candidate's libssl/libcrypto "
            "resolved, not that any consumer works. "
            "`RT-RUNTIME-FUNCTIONAL-ATLAS` is 24.7's court: the runtime/functional atlas. It stages "
            "no probe and reads forensics/downstream/runtime-functional-atlas.json, "
            "forensics/downstream/family-freeze.json, forensics/downstream/families.json and the "
            "24.6 build/link atlas, re-running the 24.7 validation and sensitivity control over "
            "the committed artefact without rebuilding and without launching anything. It "
            "establishes that every frozen P1000 family is accounted for under both subjects; "
            "that a family that reached L4-linked in 24.6 has runtime rows under both subjects; "
            "that a runtime row never reaches above the level its build/link row permits; that an "
            "L5+ row is backed by a real load proof resolving the subject prefix and never the "
            "authority's; that an L6/L7 row carries a non-empty normalised transcript hash and a "
            "normalisation tag that erases no evidence; that the candidate's authority-applicable "
            "baseline is re-derived from the authority rows rather than inflated to justify a "
            "pass; that candidate_specific_patch_count is 0; and that the counts are derived "
            "rather than typed. A candidate row whose level passes only by inflating its "
            "authority baseline, an L5 row with no load proof, an L6 row with an empty transcript, "
            "a missing authority runtime row for an L4 family, a normalisation that erases a "
            "return code, and a runtime row above its build/link permit are each detected with "
            "specificity holding. A passing atlas is a measurement, not a security proof: it says "
            "a pristine downstream program loaded the subject's libssl/libcrypto and completed "
            "one deterministic local workload, not that any consumer is safe. "
            "`RT-FAILURE-MINIMIZATION` is 24.8's court: the failure discovery/minimization loop. It "
            "stages no probe and reads forensics/downstream/failures.json and its minimized "
            "fixtures under forensics/downstream/failures/, the 24.6 build/link atlas, the 24.7 "
            "runtime/functional atlas, forensics/downstream/family-freeze.json and "
            "forensics/downstream/families.json, re-running the 24.8 validation and sensitivity "
            "control over the committed plane without rebuilding, launching or minimizing "
            "anything. It establishes that every non-resolved leftover the two atlases record has "
            "exactly one classified record and that none is fabricated; that a candidate-specific "
            "record derives from the authority-applicable baseline (the candidate fell below a "
            "level the authority reached) and a venue-limited record has an authority failure at "
            "the same or a lower level in the same admitted venue, so a venue/environment "
            "limitation is never counted as a candidate defect; that every candidate-specific "
            "record carries a minimized fixture on disk that hashes to its record and a runnable "
            "command; that unclassified is 0; that the genealogy references only real failures and "
            "asserts no fix commit; and that the counts are derived rather than typed. A candidate "
            "failure mislabeled candidate-specific without an authority failure to justify it, a "
            "venue-limited failure with no authority failure behind it, a settled leftover marked "
            "unclassified, a settled leftover omitted, a minimized claim whose fixture is missing "
            "on disk, and a fabricated fix commit are each detected with specificity holding. A "
            "passing court is an instrument: a discovered-and-minimized failure is a preserved "
            "record, not a fix, and a minimized reproducer is not the consumer. "
            "`RT-HIGH-VALUE-TIER` is 24.9's court: the high-value deep tier. It stages no probe and "
            "reads forensics/downstream/high-value-tier.json, "
            "forensics/downstream/usage-fingerprints.json, the 24.7 runtime/functional atlas, "
            "forensics/downstream/family-freeze.json and forensics/downstream/families.json, "
            "re-running the 24.9 validation and sensitivity control over the committed artefact "
            "without rebuilding and without launching anything. It establishes that the tier "
            "reproduces from the frozen depth rule (the committed 24.3 usage fingerprints, ordered "
            "by distinct imported OpenSSL symbols, then API-family breadth, then distinct headers, "
            "then direct-before-transitive, then canonical name/family_id) and reads no candidate "
            "row; that every tier member is a real committed direct-consumer family with "
            "both-subject runs; that a carried row cites a committed 24.7 row agreeing on its level "
            "and transcript hash; that an L5+ row is backed by a real load proof resolving the "
            "subject prefix and never the authority's; that an L6/L7 row carries a non-empty "
            "normalised transcript hash and a normalisation that erases no evidence; that a "
            "candidate row never claims a level above the authority-applicable baseline; that "
            "every non-selected P1000 family carries a reason and the accounting covers the whole "
            "P1000; that candidate_specific_patch_count is 0; and that the counts are derived "
            "rather than typed. A tier member dropped, a family added to the tier by a candidate "
            "result, a candidate L7 above the authority baseline marked pass, an L5 row with no "
            "load proof, an empty transcript at L6, and a not-selected P1000 family with no reason "
            "are each detected with specificity holding. A passing tier is a measurement, not a "
            "security proof: it says the deepest families the committed evidence selects loaded "
            "the subject's libssl/libcrypto and completed one deterministic local workload, not "
            "that any consumer outside it is safe. "
            "`RT-HOSTILITY-AUGMENTATION` is 24.10's court: the separate hostility-augmentation "
            "corpus. It stages no probe and reads forensics/downstream/hostility-corpus.json, the "
            "committed P1000 union inputs (the 24.3 usage fingerprints and the 24.6/24.7/24.9 "
            "atlases), the Phase-22 public-entity inventory and "
            "forensics/downstream/family-freeze.json, re-running the 24.10 maximum-marginal-novelty "
            "selection, validation and sensitivity control over the committed artefact without "
            "rebuilding a probe. It establishes that the corpus reproduces from the frozen novelty "
            "rule over the covered surface; that the corpus is separate -- no member is a P1000 "
            "counted family, no member carries a frozen family_id and the frozen P1000 count is "
            "unchanged; that every member contributes at least one new public entity and has "
            "both-subject runs; that each member's linkage is subject-correct with a real load "
            "proof on an L5+ row; that the transcript normalisation is applied identically to both "
            "subjects; that candidate_specific_patch_count is 0; and that the counts are derived "
            "rather than typed. A hostility member injected into the P1000 counts, a corpus member "
            "with no new entity, a candidate row resolving the authority, a missing authority run, "
            "an unnormalised transcript and a corpus member beyond the bound are each detected with "
            "specificity holding. A passing corpus is a separate instrument, not a rate: its "
            "results are never mixed into the counted population's rates. "
            "`RT-CANDIDATE-FREEZE` is 24.11's court: the candidate freeze and the once-run holdout. "
            "It stages no probe and reads forensics/downstream/candidate-freeze.json, "
            "forensics/downstream/holdout.json, forensics/downstream/family-freeze.json, the 24.6 "
            "build/link atlas, the 24.7 runtime/functional atlas, the 24.8 failures plane, the 24.9 "
            "high-value tier and the 24.10 hostility corpus, re-deriving the frozen candidate "
            "identity from the committed install and the precommitted holdout set from the frozen "
            "P1000 by the 24.5 rule without re-running the holdout and without rebuilding anything. "
            "It establishes that the candidate identity reproduces from the committed install (the "
            "libssl/libcrypto digests, the exported headers, pkg-config metadata, provider modules "
            "and the crate version, with the source commit carried as recorded, existence-checked "
            "provenance rather than a live-HEAD binding); that the holdout set equals the precommitted "
            "partition and carries a matching partition_root_hash; that first_run is present, equals "
            "the summary derived from the holdout run, and is attested unchanged by every rerun; "
            "that every holdout family has an accounting row; that a candidate row never claims a "
            "level above the authority-applicable baseline; that a family's verdict is the derived "
            "baseline-normalized one; that candidate_specific_patch_count is 0; that the counts are "
            "derived rather than typed; and that no holdout family is a source of a fix in the "
            "development-side failure plane. A precommitted holdout member swapped for a development "
            "member, a mutated partition root, a first_run rewritten after a rerun, a candidate "
            "level above the authority baseline, a holdout family cited as a fix source and a "
            "mutated count are each detected with specificity holding. A passing freeze is a "
            "measurement, not a security proof: a holdout result over a selected population is an "
            "out-of-sample measurement of that population, not of all downstream software, and a "
            "venue-limited holdout member is neither a pass nor a fail. "
            "`RT-P1000-RUN` is 24.12's court: the final full P1000 run at the frozen candidate. "
            "It stages no probe and reads forensics/downstream/p1000-run.json, "
            "forensics/downstream/family-freeze.json and forensics/downstream/candidate-freeze.json, "
            "re-deriving the candidate install's identity and re-running the 24.12 validation and "
            "sensitivity control over the committed run without rebuilding anything. It establishes "
            "that the candidate identity equals the frozen 24.11 identity (excluding the recorded "
            "provenance, so the run is against the same candidate); that there is exactly one "
            "drop_in_verdict per counted family, with none missing, extra or fabricated; that a "
            "DROP_IN_PASS is refused without all five of the brief's section 20 conditions (the "
            "same pristine source, a succeeded authority baseline that reached at least L4-linked, "
            "the candidate reaching the authority-applicable level, candidate linkage proven and "
            "zero candidate-specific patches); that DROP_IN_UNKNOWN is 0; that the ladder equals "
            "the derived per-level counts and the verdict histogram; that a family this venue "
            "cannot pose the drop-in question for is DROP_IN_NOT_APPLICABLE with a reason; that "
            "candidate_specific_patch_count is 0; and that the counts are derived rather than "
            "typed. A PASS asserted without an authority baseline, a PASS with a positive patch "
            "count, a duplicated verdict, a candidate level below the authority-applicable level "
            "marked PASS, and a mismatched candidate identity are each detected with specificity "
            "holding. A passing run is a measurement, not a security proof: the ladder is over a "
            "selected population of 1,000 families, not a percentage of all downstream software, "
            "and a venue-limited family is neither a pass nor a fail. "
            "`RT-ATLAS-RECONCILIATION` is 24.13's court: the reconciliation of the atlas. It stages "
            "no probe and reads forensics/downstream/reconciliation.json and every committed "
            "downstream plane it reconciles, re-running the 24.13 re-derivation and sensitivity "
            "control over the committed artefact without rebuilding anything. It establishes that "
            "every counted family has exactly one re-derived drop_in_verdict with DROP_IN_UNKNOWN "
            "0; that every residual across every plane is classified from the closed vocabulary "
            "with an unclassified and an unknown count of 0; that every failure is preserved -- "
            "the counted P1000 measured set's plus the separate hostility corpus's two candidate "
            "failures, scoped out of every P1000 rate; that the drop-in rates equal the derived "
            "rates, are unweighted over the frozen population and never sum the direct and "
            "transitive consumers; that the ladder equals the verdict counts with UNKNOWN 0 and "
            "the raw family count visible; that the coverage and the Phase-22 direct/inferred "
            "projection are consistent with the planes; and that the counts are derived rather "
            "than typed. A counted family with no verdict, a residual left unknown, a failure "
            "dropped from the summary, a hostility result mixed into the P1000 rate, a typed rate "
            "that disagrees with the verdicts, and a failure not preserved are each detected with "
            "specificity holding. The court is an instrument, not the property: it can pass while "
            "the atlas carries real property findings (a large NOT_APPLICABLE share, a thin "
            "measured surface, a non-empty residual set), which are recorded as findings and make "
            "property_status NOT_CLAIMED. "
            "`RT-FRF-CLOSURE` is 24.14's court: the FRF/Gemel chain closure. It stages no probe and "
            "reads forensics/atlas/phase24/frf-closure.json, re-running the 24.14 classification "
            "with no side effects. It establishes that each Phase-24 plane's own pure checker "
            "detected its own defect class (the thirteen challenges), that the recorded chain "
            "staging reproduces from the gen_frf_courts.py registry and the artifacts/phase24/ "
            "probes/ directory and the recorded Gemel projection from the committed "
            "forensics/GEMEL_TRAJECTORY.md, and that no Phase-24 court is declarable so the "
            "FRF/Gemel chain entry is vacuous by frf_gemel_blocking_reason's own scoping. A "
            "registered challenge whose observed result is mutated in memory is reported "
            "NOT_DETECTED, an injected Phase-24 declaration and an injected probe pair are each "
            "caught, a stripped current checkpoint and a checkpointless projection are each caught, "
            "and a flipped recorded status is a finding. The court is an instrument: it can pass "
            "while its property finding records that the stratum stages no declarable court, so a "
            "passing closure is never read as a chain that ran. "
            "The remaining court -- DOWNSTREAM-1000-SEAL -- is pending with the subphase that lands "
            "it (24.15). Phase 24 owns no exported "
            "symbol, so no differential probe over a symbol "
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
    # 24.2's subject: the committed candidate universe and families it re-derives, bound so a
    # family record the court reads is content-addressed rather than restated.
    for ref_name, path in (("candidates", CANDIDATES), ("families", FAMILIES)):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.3's subject: the committed authority-baseline census (one `run` row per cohort member),
    # the usage fingerprints and the tool that produced them, bound so a row the court reads is
    # content-addressed rather than restated.
    for ref_name, path in (("authority-baselines", AUTHORITY_BASELINES),
                           ("usage-fingerprints", USAGE_FINGERPRINTS),
                           ("downstream-census", REPO_ROOT / "forensics" / "tools"
                            / "downstream_census.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.4's subject: the committed frozen P1000 + reserve and the tool that derived it, bound so a
    # population row the court reads is content-addressed rather than restated.
    for ref_name, path in (("family-freeze", FAMILY_FREEZE),
                           ("downstream-freeze", REPO_ROOT / "forensics" / "tools"
                            / "downstream_freeze.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.5's subject: the committed precommitted holdout partition and the tool that derived it,
    # bound so a partition row the court reads is content-addressed rather than restated.
    for ref_name, path in (("holdout", HOLDOUT),
                           ("downstream-holdout", REPO_ROOT / "forensics" / "tools"
                            / "downstream_holdout.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.6's subject: the committed build/link atlas and the tool that produced it, bound so a run
    # row the court reads is content-addressed rather than restated.
    for ref_name, path in (("build-link-atlas", BUILD_LINK_ATLAS),
                           ("downstream-build-link", REPO_ROOT / "forensics" / "tools"
                            / "downstream_build_link.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.7's subject: the committed runtime/functional atlas and the tool that produced it, bound so
    # a run row the court reads is content-addressed rather than restated.
    for ref_name, path in (("runtime-functional-atlas", RUNTIME_FUNCTIONAL_ATLAS),
                           ("downstream-runtime", REPO_ROOT / "forensics" / "tools"
                            / "downstream_runtime.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.8's subject: the committed failures plane (the classified, preserved, minimized leftovers)
    # and the tool that produced it, plus every minimized fixture it references, bound so a record and
    # its reproducer the court reads are content-addressed rather than restated.
    for ref_name, path in (("failures", DOWNSTREAM_FAILURES),
                           ("downstream-failures", REPO_ROOT / "forensics" / "tools"
                            / "downstream_failures.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    if DOWNSTREAM_FAILURES.is_file():
        fbody = downstream_failures._load_json(DOWNSTREAM_FAILURES)
        for rec in (fbody.get("failures") or []):
            rep = rec.get("reproducer") or {}
            d = rep.get("dir")
            if d:
                for name in sorted(rep.get("files") or {}):
                    fp = REPO_ROOT / d / name
                    if fp.is_file():
                        inputs.append(InputRef(
                            name=f"fixture/{downstream_failures._sanitize(rec['failure_id'])}/{name}",
                            path=fp))
    # 24.9's subject: the committed high-value deep tier and the tool that produced it, bound so a
    # tier row and an accounting row the court reads are content-addressed rather than restated.
    for ref_name, path in (("high-value-tier", HIGH_VALUE_TIER),
                           ("downstream-high-value", REPO_ROOT / "forensics" / "tools"
                            / "downstream_high_value.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.10's subject: the committed hostility corpus, the tool that produced it, its committed probe
    # sources and the Phase-22 public-entity inventory it was selected against, bound so a corpus row
    # and a probe source the court reads are content-addressed rather than restated.
    for ref_name, path in (("hostility-corpus", HOSTILITY_CORPUS),
                           ("downstream-hostility", REPO_ROOT / "forensics" / "tools"
                            / "downstream_hostility.py"),
                           ("phase22-implemented-surface",
                            REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    for probe in sorted((REPO_ROOT / "forensics" / "downstream" / "hostility").glob("*")):
        if probe.is_file():
            inputs.append(InputRef(name=f"hostility-probe/{probe.name}", path=probe))
    # 24.11's subject: the committed candidate freeze and the tool that produced it, bound so a
    # holdout row and an accounting row the court reads are content-addressed rather than restated.
    for ref_name, path in (("candidate-freeze", CANDIDATE_FREEZE),
                           ("downstream-candidate-freeze", REPO_ROOT / "forensics" / "tools"
                            / "downstream_candidate_freeze.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.12's subject: the committed final P1000 run and the tool that produced it, bound so a run
    # row, a verdict, a ladder count and a receipt the court reads are content-addressed rather than
    # restated.
    for ref_name, path in (("p1000-run", P1000_RUN),
                           ("downstream-p1000-run", REPO_ROOT / "forensics" / "tools"
                            / "downstream_p1000_run.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.13's subject: the committed reconciliation and the tool that produced it, bound so a
    # verdict, a residual, a preserved failure, a rate, a ladder count, a coverage figure and a
    # cluster the court reads are content-addressed rather than restated.
    for ref_name, path in (("reconciliation", RECONCILIATION),
                           ("downstream-reconciliation", REPO_ROOT / "forensics" / "tools"
                            / "downstream_reconciliation.py")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
    # 24.14's subject: the committed FRF/Gemel closure and the tool that produced it, bound so a
    # challenge delta, the chain staging and the Gemel projection the court reads are content-
    # addressed rather than restated.
    for ref_name, path in (("frf-closure", FRF_CLOSURE),
                           ("phase24-frf", REPO_ROOT / "forensics" / "tools"
                            / "phase24_frf.py"),
                           ("gemel-trajectory", REPO_ROOT / "forensics" / "GEMEL_TRAJECTORY.md")):
        if path.is_file():
            inputs.append(InputRef(name=ref_name, path=path))
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
        elif r["verdict"] == "pass" and r["court"] == CANDIDATE_UNIVERSE_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, {counts['identities']} identity(ies) "
                  f"-> {counts['families']} family(ies), {counts['aliases_collapsed']} alias "
                  f"collapse(s), {counts['forks_merged']} fork merge(s), {counts['excluded']} "
                  f"excluded non-consumer; {len(r['findings'])} finding(s); "
                  f"control honest={c['honest']} specificity={c['specificity_holds']} "
                  f"alias->{c['caught_alias_double_counted']} "
                  f"promoted->{c['caught_transitive_promoted_to_direct']} "
                  f"fork->{c['caught_fork_independent_without_evidence']} "
                  f"no-provenance->{c['caught_family_without_provenance']})")
            print(f"      identities by directness: {r['identities_by_directness']}")
            print(f"      families by directness: {r['families_by_directness']}")
            print(f"      alias collapse: {ex['alias_collapse']}")
            print(f"      provider group: openssl excluded={ex['provider_group']['excluded_identities']} "
                  f"class={ex['provider_group']['class']}; "
                  f"transitive-through-libcurl absent={ex['transitive_through_libcurl_absent']}; "
                  f"fork merge={ex['fork_merge']}; "
                  f"forks-independent-without-evidence="
                  f"{ex['forks_independent_without_evidence']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == AUTHORITY_CENSUS_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, cohort={counts['cohort']} "
                  f"passed={counts['passed']} failed={counts['failed']} "
                  f"linked={counts['linked_to_authority']} launched={counts['launched']} "
                  f"no-recipe={counts['no_recipe']} with-recipe={counts['with_recipe']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"system-linkage->{c['caught_authority_linkage_but_system']} "
                  f"candidate-failure->{c['caught_authority_fail_as_candidate_failure']} "
                  f"no-source-hash->{c['caught_cohort_member_without_source_hash']} "
                  f"no-symbols->{c['caught_fingerprint_without_symbols_claimed_pass']})")
            print(f"      cohort rule: min_sources={ex['cohort_min_sources']} "
                  f"size={ex['cohort_size']} authority={ex['authority_prefix']}")
            for f in ex["authority_baseline_fails"]:
                print(f"      AUTHORITY_BASELINE_FAIL {f['family']:<16} {f['level']:<18} "
                      f"{f['failure_class']:<24} {(f['reason'] or '')[:70]}")
            for fam, proof in sorted((ex["authority_linkage_proof"] or {}).items()):
                if not proof:
                    continue
                son = ", ".join(f"{k}->{v['resolved']}"
                                for k, v in sorted(proof["sonames"].items()))
                print(f"      authority-linkage {fam:<12} {son}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == FAMILY_FREEZE_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, universe={counts['universe']} "
                  f"p1000={counts['p1000']} reserve={counts['reserve']} "
                  f"direct={counts['direct']} transitive={counts['transitive']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"order->{c['caught_p1000_order_swapped']} "
                  f"short->{c['caught_p1000_short']} "
                  f"overlap->{c['caught_p1000_reserve_overlap']} "
                  f"root->{c['caught_mutated_selection_root']} "
                  f"candidate->{c['caught_candidate_result_present']})")
            print(f"      rule: id={ex['rule']['id']} rank_key={ex['rule']['rank_key']} "
                  f"p1000_size={ex['rule']['p1000_size']} reserve_rule={ex['rule']['reserve_rule']!r}")
            print(f"      selection_root_hash={ex['selection_root_hash']} "
                  f"inputs={ex['selection_input_root']}")
            for row in ex["p1000_head"]:
                print(f"      p1000[{row['p1000_rank']:>4}] {row['family_id']:<34} "
                      f"{row['openssl_linkage']:<10} sb={row['source_breadth']} "
                      f"db={row['distro_breadth']} pop={row['popularity']}")
            for row in ex["reserve_head"]:
                print(f"      reserve[{row['reserve_rank']:>4}] {row['family_id']:<34} "
                      f"cursor={row['replacement_cursor']} "
                      f"{row['openssl_linkage']:<10} sb={row['source_breadth']}")
            print(f"      candidate-subject rows in the downstream plane: {ex['candidate_rows']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == HOLDOUT_PARTITION_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, p1000={counts['p1000']} "
                  f"development={counts['development']} holdout={counts['holdout']} "
                  f"per_band_holdout={counts['per_band_holdout']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"moved->{c['caught_holdout_member_moved']} "
                  f"deleted->{c['caught_holdout_member_deleted']} "
                  f"duplicated->{c['caught_family_id_in_both_cohorts']} "
                  f"external->{c['caught_p1000_external_family']} "
                  f"root->{c['caught_mutated_partition_root']} "
                  f"candidate->{c['caught_candidate_result_present']})")
            print(f"      rule: id={ex['rule']['id']} seed={ex['rule']['seed']} "
                  f"fraction={ex['rule']['fraction']} bands={ex['rule']['bands']} "
                  f"per_band_holdout={ex['rule']['per_band_holdout']} "
                  f"status={ex['holdout_status']}")
            print(f"      partition_root_hash={ex['partition_root_hash']}")
            print(f"      per-band holdout: {ex['per_band_holdout']}")
            for row in ex["development_head"]:
                print(f"      development[{row['p1000_rank']:>4}] band={row['band']} "
                      f"{row['family_id']:<34} {row['openssl_linkage']:<10} "
                      f"{row['canonical_name']}")
            for row in ex["holdout_head"]:
                print(f"      holdout[{row['p1000_rank']:>4}] band={row['band']} "
                      f"{row['family_id']:<34} {row['openssl_linkage']:<10} "
                      f"{row['canonical_name']}")
            print(f"      candidate-subject rows in the downstream plane: {ex['candidate_rows']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == BUILD_LINK_ATLAS_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, p1000={counts['p1000']} "
                  f"rows={counts['rows']} with_recipe={counts['with_recipe']} "
                  f"no_recipe={counts['no_recipe']} auth_linked={counts['authority_linked']} "
                  f"cand_linked={counts['candidate_linked']} "
                  f"cand_failed={counts['candidate_failed']} "
                  f"linkage_proven={counts['candidate_linkage_proven']} "
                  f"patches={counts['candidate_specific_patch_count']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"authority-link->{c['caught_candidate_linkage_resolves_authority']} "
                  f"missing-authority->{c['caught_recipe_family_missing_authority_row']} "
                  f"patch-count->{c['caught_positive_candidate_specific_patch_count']} "
                  f"no-residual->{c['caught_failed_row_without_residual']} "
                  f"system->{c['caught_candidate_system_libssl']} "
                  f"source-root->{c['caught_candidate_different_source_root']})")
            ident = ex.get("candidate_identity") or {}
            print(f"      candidate install={ident.get('install_prefix')} "
                  f"libssl={str(ident.get('libssl_so_3_sha256'))[:12]} "
                  f"libcrypto={str(ident.get('libcrypto_so_3_sha256'))[:12]}")
            for fam, proof in sorted((ex.get("candidate_linkage_proof") or {}).items()):
                son = ", ".join(f"{k}->{v}" for k, v in sorted(proof["resolved"].items()))
                print(f"      candidate-linkage {fam:<12} {son} "
                      f"needs={proof.get('version_needs')}")
            for f in ex.get("candidate_failures") or []:
                print(f"      candidate-failure {f['family']:<12} {f['level']:<16} "
                      f"{f['failure_class']:<24} {(f['reason'] or '')[:70]}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == RUNTIME_FUNCTIONAL_ATLAS_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, p1000={counts['p1000']} "
                  f"rows={counts['rows']} with_recipe={counts['with_recipe']} "
                  f"no_recipe={counts['no_recipe']} "
                  f"auth_loaded={counts['authority_loaded']} "
                  f"auth_runtime={counts['authority_runtime']} "
                  f"auth_functional={counts['authority_functional']} "
                  f"cand_loaded={counts['candidate_loaded']} "
                  f"cand_runtime={counts['candidate_runtime']} "
                  f"cand_functional={counts['candidate_functional']} "
                  f"reaches_baseline={counts['candidate_reaches_baseline']} "
                  f"reaches_linked={counts['candidate_reaches_linked_baseline']} "
                  f"not_linked={counts['candidate_baseline_not_linked']} "
                  f"patches={counts['candidate_specific_patch_count']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"baseline->{c['caught_candidate_level_above_authority_baseline']} "
                  f"no-proof->{c['caught_loaded_row_without_proof']} "
                  f"no-transcript->{c['caught_runtime_row_without_transcript']} "
                  f"missing-authority->{c['caught_missing_authority_runtime_row']} "
                  f"norm-erases->{c['caught_normalisation_erases_return_code']} "
                  f"above-permit->{c['caught_runtime_above_build_link_permit']})")
            for row in ex.get("loaded") or []:
                print(f"      loaded {row['subject']:<9} {row['family']:<10} {row['level']:<16} "
                      f"{str(row.get('workload'))[:60]}")
            for f in ex.get("candidate_failures") or []:
                print(f"      candidate-failure {f['family']:<12} {f['level']:<16} "
                      f"{str(f['failure_class']):<20} {(f['reason'] or '')[:70]}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == FAILURE_MINIMIZATION_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, leftovers={counts['leftovers']} "
                  f"candidate_specific={counts['candidate_specific']} "
                  f"venue_limited={counts['venue_limited']} "
                  f"out_of_scope={counts['intentional_out_of_scope']} "
                  f"minimized={counts['minimized']} unclassified={counts['unclassified']} "
                  f"divergences={counts['divergences']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"not-derived->{c['caught_candidate_specific_not_derived']} "
                  f"no-authority-failure->{c['caught_venue_limited_without_authority_failure']} "
                  f"unclassified->{c['caught_leftover_marked_unclassified']} "
                  f"omitted->{c['caught_leftover_omitted']} "
                  f"missing-fixture->{c['caught_minimized_fixture_missing']} "
                  f"fix-commit->{c['caught_fabricated_fix_commit']})")
            print(f"      by_disposition: {ex.get('by_disposition')}")
            print(f"      by_failure_class: {ex.get('by_failure_class')}")
            print(f"      by_residual_class: {ex.get('by_residual_class')}")
            print(f"      candidate-specific families: {ex.get('candidate_specific_families')} "
                  f"(a discovered-and-minimized failure is a preserved record, not a fix)")
            for d in ex.get("divergences") or []:
                print(f"      divergence {d['atlas']} {d['consumer']}: "
                      f"authority={d['authority_failure_class']} "
                      f"candidate={d['candidate_failure_class']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == HIGH_VALUE_TIER_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, tier={counts['tier_size']} "
                  f"fingerprint={counts['tier_fingerprint']} precedent={counts['tier_precedent']} "
                  f"in_p1000={counts['tier_in_p1000']} outside={counts['tier_outside_p1000']} "
                  f"auth_functional={counts['authority_functional']} "
                  f"cand_functional={counts['candidate_functional']} "
                  f"reaches_baseline={counts['candidate_reaches_baseline']} "
                  f"accounting={counts['accounting_tier_measured']}/"
                  f"{counts['accounting_not_selected']} "
                  f"patches={counts['candidate_specific_patch_count']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"dropped->{c['caught_tier_member_dropped']} "
                  f"candidate-added->{c['caught_family_added_by_candidate_result']} "
                  f"above-baseline->{c['caught_candidate_level_above_authority_baseline']} "
                  f"no-proof->{c['caught_loaded_row_without_proof']} "
                  f"no-transcript->{c['caught_runtime_row_without_transcript']} "
                  f"no-reason->{c['caught_non_selected_family_without_reason']})")
            for m in ex.get("tier") or []:
                print(f"      tier {m['source']:<11} rank={str(m['depth_rank']):<4} "
                      f"{m['family']:<10} baseline={m['authority_applicable_baseline']}")
            for row in ex.get("runs") or []:
                print(f"      run  {row['subject']:<9} {row['family']:<10} {row['level']:<16} "
                      f"{row['outcome']:<8} {str(row.get('carried_from') or row.get('workload') or '')[:52]}")
            print(f"      tier_not_measured: {ex.get('tier_not_measured')}")
            print(f"      candidate_failures: {counts['candidate_failures']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == HOSTILITY_AUGMENTATION_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, corpus={counts['corpus_size']} "
                  f"c={counts['corpus_c']} network={counts['corpus_network']} "
                  f"bound={counts['corpus_bound']} "
                  f"new_entities={counts['distinct_new_public_entities']} "
                  f"covered={counts['covered_surface_symbols']} "
                  f"auth_functional={counts['authority_functional']} "
                  f"cand_functional={counts['candidate_functional']} "
                  f"cand_failed={counts['candidate_failed']} "
                  f"divergences={counts['divergences']} "
                  f"p1000={counts['p1000']} overlap={counts['p1000_hostility_overlap']} "
                  f"separated={counts['separated_by_design']} "
                  f"patches={counts['candidate_specific_patch_count']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"injected->{c['caught_hostility_member_injected_into_p1000']} "
                  f"no-new-entity->{c['caught_corpus_member_without_new_entity']} "
                  f"resolves-authority->{c['caught_candidate_row_resolves_authority']} "
                  f"missing-authority->{c['caught_missing_authority_run']} "
                  f"unnormalised->{c['caught_unnormalised_transcript']} "
                  f"beyond-bound->{c['caught_corpus_member_beyond_bound']})")
            cs = ex.get("covered_surface") or {}
            print(f"      covered surface: symbols={cs.get('symbol_count')} "
                  f"headers={cs.get('header_count')} api_families={cs.get('api_family_count')} "
                  f"hash={str(cs.get('hash'))[:16]}")
            for m in ex.get("corpus") or []:
                print(f"      corpus[{m['selection_rank']:>2}] {m['surface_id']:<28} "
                      f"{str(m['variant']):<22} marg={m['marginal_novelty']} "
                      f"legacy={m['legacy_entities']}")
            for row in ex.get("runs") or []:
                print(f"      run  {row['subject']:<9} {str(row.get('direction') or ''):<22} "
                      f"{row['probe_id']:<28} {row['level']:<16} {row['outcome']:<8} "
                      f"div={row.get('divergence')}")
            print(f"      candidate_failures: {counts['candidate_failures']}")
            print(f"      not_selected: {[m['surface_id'] for m in ex.get('not_selected') or []]}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == CANDIDATE_FREEZE_COURT:
            c = r["control"]
            counts = r["counts"]
            ex = r["examples"]
            ident = r["candidate_identity"]
            print(f"  {r['court']:<32} pass   (no probe, holdout={counts['holdout_families']} "
                  f"recipe_backed={counts['recipe_backed_families']} "
                  f"measurable={counts['measurable_families']} "
                  f"venue_limited={counts['venue_limited_families']} "
                  f"reach_baseline={counts['candidate_reaches_baseline']} "
                  f"verdicts={counts['verdicts']} reruns={counts['reruns']} "
                  f"patches={counts['candidate_specific_patch_count']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"swapped->{c['caught_holdout_member_swapped_for_development']} "
                  f"root->{c['caught_mutated_partition_root']} "
                  f"rewritten->{c['caught_first_run_rewritten_after_rerun']} "
                  f"above-baseline->{c['caught_candidate_level_above_authority_baseline']} "
                  f"fix-source->{c['caught_holdout_family_cited_as_fix']} "
                  f"counts->{c['caught_mutated_count']})")
            print(f"      candidate identity: libssl={str(ident.get('libssl_sha256'))[:12]} "
                  f"libcrypto={str(ident.get('libcrypto_sha256'))[:12]} "
                  f"headers={(ident.get('headers') or {}).get('count')} "
                  f"pkgconfig={(ident.get('pkgconfig') or {}).get('count')} "
                  f"modules={(ident.get('ossl_modules') or {}).get('count')} "
                  f"version={ident.get('crate_version')} "
                  f"commit={str(ident.get('source_commit'))[:12]} "
                  f"image={(ident.get('container') or {}).get('image')} "
                  f"platform={(ident.get('container') or {}).get('platform')}")
            print(f"      identity_hash={ident.get('identity_hash')}")
            hb = ex.get("holdout") or {}
            print(f"      holdout: partition_root_hash={hb.get('partition_root_hash')} "
                  f"set_hash={hb.get('set_hash')} families={hb.get('family_count')}")
            fr = ex.get("first_run") or {}
            print(f"      first_run: reaches_baseline={fr.get('candidate_reaches_baseline')} "
                  f"verdicts={fr.get('verdicts')} candidate_failures={fr.get('candidate_failures')}")
            for row in ex.get("heldout_runs") or []:
                print(f"      holdout-run {row['subject']:<9} {row['family']:<12} {row['level']:<16} "
                      f"{row['outcome']:<8} {str(row.get('residual_class') or '')}")
            for v in ex.get("verdicts") or []:
                print(f"      verdict {v['family']:<12} {v['verdict']:<24} "
                      f"baseline={v['authority_applicable_level']} candidate={v['candidate_level']}")
            print(f"      candidate_failures: {counts['candidate_failures']}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == P1000_RUN_COURT:
            c = r["control"]
            counts = r["counts"]
            lad = r["ladder"]
            ex = r["examples"]
            ident = r["candidate_identity"]
            print(f"  {r['court']:<32} pass   (no probe, families={counts['families']} "
                  f"recipe_backed={counts['recipe_backed_families']} "
                  f"measurable={counts['measurable_families']} "
                  f"not_applicable={counts['not_applicable_families']} "
                  f"reaches_baseline={counts['measurable_reaches_baseline']} "
                  f"verdicts={counts['verdicts']} "
                  f"patches={counts['candidate_specific_patch_count']}; "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"no-baseline->{c['caught_pass_without_authority_baseline']} "
                  f"patch-count->{c['caught_pass_with_positive_patch_count']} "
                  f"duplicate->{c['caught_duplicated_verdict']} "
                  f"below-baseline->{c['caught_candidate_level_below_baseline_marked_pass']} "
                  f"identity->{c['caught_mismatched_candidate_identity']})")
            print(f"      candidate identity: libssl={str(ident.get('libssl_sha256'))[:12]} "
                  f"libcrypto={str(ident.get('libcrypto_sha256'))[:12]} "
                  f"version={ident.get('crate_version')} "
                  f"identity_hash={ident.get('identity_hash')}")
            print(f"      ladder: families={lad.get('families')} "
                  f"measurable={lad.get('measurable_families')} "
                  f"not_applicable={lad.get('not_applicable_families')} "
                  f"levels={lad.get('levels')}")
            print(f"      verdicts: {lad.get('verdicts')}")
            for v in ex.get("measured_verdicts") or []:
                print(f"      verdict {v['family']:<12} {v['verdict']:<24} "
                      f"baseline={v['authority_applicable_level']} "
                      f"candidate={v['candidate_level']} residual={v['residual_class']}")
            for v in ex.get("not_applicable_head") or []:
                print(f"      not-applicable {v['family']:<12} residual={v['residual_class']} "
                      f"{(v['reason'] or '')[:70]}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == ATLAS_RECONCILIATION_COURT:
            c = r["control"]
            counts = r["counts"]
            lad = r["ladder"]
            rates = r["rates"]["unweighted"]
            cov = r["coverage"]
            ex = r["examples"]
            print(f"  {r['court']:<32} pass   (no probe, families={counts['families']} "
                  f"measurable={counts['measurable_families']} "
                  f"not_applicable={counts['not_applicable_families']} "
                  f"verdicts={counts['verdicts']}; "
                  f"{len(r['instrument_findings'])} instrument finding(s); "
                  f"control honest={c['honest']} specificity={c['specificity_holds']} "
                  f"no-verdict->{c['caught_counted_family_without_a_verdict']} "
                  f"unknown-residual->{c['caught_residual_left_unknown']} "
                  f"dropped-failure->{c['caught_failure_dropped_from_summary']} "
                  f"hostility-rate->{c['caught_hostility_mixed_into_p1000_rate']} "
                  f"typed-rate->{c['caught_typed_rate_disagrees_with_verdicts']} "
                  f"not-preserved->{c['caught_failure_not_preserved']})")
            print(f"      unweighted rates: PASS={rates['PASS']['count']}({rates['PASS']['rate']}) "
                  f"PARTIAL={rates['PARTIAL']['count']}({rates['PARTIAL']['rate']}) "
                  f"FAIL={rates['FAIL']['count']} UNKNOWN={rates['UNKNOWN']['count']} "
                  f"NOT_APPLICABLE={rates['NOT_APPLICABLE']['count']}"
                  f"({rates['NOT_APPLICABLE']['rate']})")
            print(f"      ladder: levels={lad['levels']} status={lad['status']} "
                  f"raw_family_count={lad['raw_family_count']} UNKNOWN={lad['unknown']}")
            print(f"      coverage: symbols={cov['measured']['symbols']}/"
                  f"{cov['known_universe']['exported_symbols']} "
                  f"headers={cov['measured']['headers']}/{cov['known_universe']['headers']} "
                  f"api_families={cov['measured']['api_families']}/"
                  f"{cov['known_universe']['api_families']} ratios={cov['ratios']}")
            print(f"      residuals: total={counts['residuals_total']} "
                  f"unresolved={counts['residuals_unresolved']} "
                  f"unknown={counts['residuals_unknown']} "
                  f"unclassified={counts['residuals_unclassified']} "
                  f"histogram={ex['residuals']['histogram']}")
            print(f"      failures: p1000={counts['failures_p1000']} "
                  f"hostility={counts['failures_hostility']} "
                  f"preserved={counts['failures_preserved']} "
                  f"all_preserved={ex['failures_summary']['all_preserved']}")
            for fr in ex["failures_summary"]["hostility_records"] or []:
                print(f"      hostility-failure {fr['class']:<18} {fr['run_id']:<46} "
                      f"preserved={fr['preserved']} minimized={fr['minimized']}")
            print(f"      clusters: {counts['usage_clusters']} cluster(s) over "
                  f"{ex['clusters']['clusters']} "
                  f"distinct_stressors={counts['distinct_stressors']} "
                  f"marginal_consumers={counts['marginal_consumers']}")
            phase22 = ex["phase22_projection"]
            print(f"      phase22: direct(symbols={phase22['direct']['symbols']}) "
                  f"inferred(reachable_entities={phase22['inferred']['reachable_entities']}) "
                  f"views={phase22['compatibility_views']['by_status']}")
            for v in ex.get("measured_verdicts") or []:
                print(f"      verdict {v['canonical_name']:<12} {v['verdict']:<24} "
                      f"baseline={v['authority_applicable_level']} "
                      f"candidate={v['candidate_level']} residual={v['residual_class']}")
            print(f"      property_status={r['property_status']} "
                  f"property_findings={len(r['findings'])}")
            for f in r["instrument_findings"]:
                print(f"      instrument finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == FRF_CLOSURE_COURT:
            c = r["control"]
            counts = r["counts"]
            chain = r["chain"]
            gemel = r["gemel"]
            print(f"  {r['court']:<32} pass   (no probe, planes={counts['planes']} "
                  f"detected={counts['detected']} not_detected={counts['not_detected']} "
                  f"not_driven={counts['not_driven']}; "
                  f"{len(r['instrument_findings'])} instrument finding(s); "
                  f"control honest={c['honest']} specificity={c['specificity_holds']} "
                  f"mutated->{c['caught_mutated_observed']} "
                  f"declaration->{c['caught_injected_declaration']} "
                  f"probe->{c['caught_injected_probe']} "
                  f"checkpoint->{c['caught_missing_checkpoint']} "
                  f"no-checkpoints->{c['caught_missing_checkpoints']} "
                  f"flipped->{c['caught_flipped_status']})")
            print(f"      chain: phase={chain['phase']} declared={chain['declared_courts']} "
                  f"probes={chain['probe_pairs']} vacuous={chain['vacuous']}")
            print(f"      gemel: projection={gemel['projection']} current={gemel['current']} "
                  f"checkpoints={gemel['checkpoint_count']} "
                  f"chain_named={gemel['checkpoints_naming_frf_chain']} "
                  f"owed={gemel['checkpoint_owed']}")
            for ch in r["examples"]["challenges"]:
                caught = sum(1 for v in (ch["mutations"] or {}).values() if v)
                print(f"      plane {ch['plane']:<6} {ch['instrument']:<26} {ch['status']:<12} "
                      f"mutations={caught}/{len(ch['mutations'] or {})}")
            print(f"      property_status={r['property_status']} findings={len(r['findings'])}")
            for f in r["instrument_findings"]:
                print(f"      instrument finding: {f}")
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
