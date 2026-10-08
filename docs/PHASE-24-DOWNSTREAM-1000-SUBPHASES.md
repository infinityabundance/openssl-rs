# Phase 24 — the downstream-1000 stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 24 is the stratum `docs/RELEASE_GATES.md` §1 names "Downstream-1000 replacement atlas and
empirical drop-in corpus". It is admitted once the multitrack authority stratum (Phase 23) is
complete, and it is dependency-ordered after it rather than after the highest number:
`forensics/tools/phase_state.py`'s `REQUIRES[24]` is `(23,)`, and because Phase 23 requires Phase 21
(which requires Phase 22) that single edge transitively requires the authority archaeology, the
maintenance-delta machinery and the multitrack authority lineage. No existing phase is renumbered.

Like Phases 16 through 23 it owns **no exported symbol**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 24` yields nothing, because the
declaring-header rule assigns no installed header to this stratum. Its unit is therefore not a
symbol. As with Phases 18 through 23 it **hands nothing forward and receives nothing**: it adds no
library surface, takes no unit or symbol deferral from an earlier stratum, and activates no
provider.

What it owes is a **content-addressed, reproducible, machine-queryable atlas of 1,000 precommitted
real OpenSSL downstream project families**, built to measure whether `openssl-rs` survives the ways
real software depends on OpenSSL. The vocabulary is fixed here:

* a **family** — the **counted unit**: a real downstream project family, **never a package
  alias**. A family is identified by a `family_id`, a name, its source ecosystem, its project URL,
  and its `openssl_linkage` (`direct` or `transitive`). Counting package aliases would let one
  project inflate the population; the atlas never claims a package-manager name as a family.
* a **specimen** — one concrete, **pristine** source tree of a family at a named version: its
  `pristine_source_sha256`, its `upstream_ref` and its licence. A specimen is **separate from the
  family**: a family may have several specimens, and a specimen is never mistaken for the family.
* a **variant** — one build/configuration of a specimen: its build profile, platform, arch and its
  **patch set** (`pristine`, `build-system-only` or `candidate-specific`). Only a `pristine`
  variant may take part in a `DROP_IN_PASS`.
* a **ranking source** — a frozen, multi-source evidence row (`popularity`, `language-registry`,
  `distro-package`, `issue-tracker`, `vendor-adoption`, `security-advisory` or `curated`) that
  ranked candidate families **before** any candidate result existed: its URL, fetch date, SHA-256,
  `frozen` flag and row count. The population is selected from these, never from the candidate.
* a **run** — one execution of one specimen/variant at one **execution level**, under one
  **subject** (`authority` or `candidate`), with an outcome and a residual class.
* an **execution level** — one rung of the ordered ladder **L0 through L8**:
  `L0-catalogued`, `L1-admitted-source`, `L2-configured`, `L3-built`, `L4-linked`, `L5-loaded`,
  `L6-runtime`, `L7-functional`, `L8-authority-equivalent`. The **authority-applicable baseline**
  for a specimen is the highest level its authority runs reached; a candidate run reaches the
  authority-applicable level when its own level is at least that rank.
* a **residual** — a classified leftover the run did not resolve, from the closed **residual class**
  vocabulary (brief §30): `none`, `unavailable`, `unbuildable`, `unlinked`, `runtime-failure`,
  `functional-divergence`, `candidate-patch-required`, `authority-unsupported`, `out-of-scope`,
  `unknown`.
* a **drop-in verdict** — the baseline-normalized verdict for a specimen, from `DROP_IN_PASS`,
  `DROP_IN_FAIL`, `DROP_IN_PARTIAL`, `DROP_IN_UNKNOWN` or `DROP_IN_NOT_APPLICABLE`. It is **never
  a boolean of its own**.

The **failure taxonomy** (brief §31) is the closed vocabulary a discovered failure is named from —
`acquire-failure`, `configure-failure`, `authority-build-failure`, `candidate-build-failure`,
`link-failure`, `load-failure`, `runtime-failure`, `functional-failure`, `abi-failure`,
`semantic-failure`, `cli-config-mismatch`, `provider-registration-mismatch`, `patch-required`,
`harness-failure` — and every failure is **preserved and minimized** rather than discarded.

**`DROP_IN_PASS` requires all five of**: the **same pristine source** (a `pristine` variant sharing
the specimen's `pristine_source_id`); the **authority baseline succeeded**; the candidate
**reached the authority-applicable level**; **candidate linkage proven** (`linkage_proven`); and
**zero candidate-specific downstream patches** (`candidate_specific_patch_count` 0). The schema
refuses a `DROP_IN_PASS` asserted without an authority baseline or with a positive patch count.

It is **not** a random sample and it makes no claim beyond its population, and it is **not** a
per-project set of implementations. One implementation is the subject; the atlas is the instrument.
A passing court is an **instrument**, not a property: it ran and its control was honest, and the
property it names may still carry findings.

The load-bearing non-claims belong to every subphase, and they are recorded in the ledger's
`ledger_note`, in `docs/NON_CLAIMS.md` and here:

* **a selected empirical population is not a random sample** — 1,000 families chosen from frozen
  ranking evidence are a *selected* population, and their drop-in rates do not generalise to all
  downstream software;
* **1000/1000 is not a security proof** — a full pass is not a guarantee that any consumer is safe,
  and it makes no statement about an unmeasured consumer;
* **a build is not a functional proof** — reaching `L3-built` or `L4-linked` is not behaving; only
  the functional levels are behavioural evidence;
* **transitive and direct consumers are different evidence** — a project that only links a library
  transitively is a different measurement from one that calls the API directly, and the two are
  never summed.

A residual that cannot be classified is recorded `unknown`; a failure that cannot be minimized is
recorded with the minimization it reached. `docs/NON_CLAIMS.md`, `docs/AUTHORITY_POLICY.md`,
`docs/PARITY_MODEL.md`, `docs/ABI_POLICY.md` and `docs/REPRODUCIBILITY.md` are the authorities on
what may be said; a subphase that discovers its unit is somewhere else records that rather than
forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase24-obligations.json` is
authoritative for the present. The activation measurement was taken against `phase24-downstream-1000`
off `main` `92547a01` (openssl-rs 0.0.27, Phase 23 complete).

**Phase 24 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for `owner_phase ==
24` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger fails closed if
that ever stops being true rather than silently counting a symbol through a non-export unit.

**It receives zero provider registration rows.** Reading `forensics/atlas/provider-algorithms.json`
for `owning_phase == 24` gives no row: this stratum activates no provider. The ledger fails closed
if the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading `forensics/prerequisites.json`
for `owner_phase == 24`: no `deferrals` row and no `units` row. The plane's records and deferrals
are all owned by earlier strata, so this stratum's working set is entirely its own authored
contract.

**The downstream 1000 contract is seventeen units**, each derived from the court that measures it,
and each court lands with the subphase that builds its instrument: `ranking-sources`,
`candidate-universe`, `authority-census`, `family-freeze`, `holdout-partition`,
`build-link-atlas`, `runtime-functional-atlas`, `failure-minimization`, `high-value-tier`,
`hostility-augmentation`, `candidate-freeze`, `p1000-run`, `atlas-reconciliation`,
`frf-gemel-closure`, `downstream-1000-seal`, `blocker-leverage` and `blocker-remediation`. All
fifteen of the first units are open at activation, so the ledger's live
`counts.open_in_this_stratum` was fifteen at activation, and the corrected activation measurement
was fifteen `pending` courts over fifteen units; 24.16 re-opens the stratum with a sixteenth unit
after the seal (the plan's §4.12 correction), and 24.17 re-opens it once more with a seventeenth
unit (the plan's §4.13 correction).

**The downstream evidence plane already has its schema.** 24.0 lands
`forensics/tools/downstream_schemas.py`, which defines and validates the record kinds the later
subphases populate and fixes the closed vocabularies (the L0-L8 ladder, the failure taxonomy and
the residual classes). 24.0 invents none of the evidence: it names the record kinds the later
subphases will fill.

**This stratum begins on nothing of its own.** No downstream-1000 court exists at activation, so
`open_in_this_stratum` opens at the whole working set (sixteen) and moves only as the subphases
below land. **That split moves as the stratum lands its own units: the ledger's `counts` is the
live record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 24.0 | **The constitution, the schemas, the guard, the ledger and the runner** | `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md`, `forensics/tools/downstream_schemas.py`, the Docker-only execution guard `forensics/tools/phase24_guard.py`, the committed venue manifest `forensics/downstream/container.json` and the measurement in §1. The ledger (`forensics/phase24-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase24_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 23 | — |
| 24.1 | **The frozen ranking-source acquisition** | the multi-source ranking evidence (`forensics/downstream/ranking-sources.json`) acquired from the named sources, each row's URL, fetch date and SHA-256 frozen **before** any candidate result exists, so the population cannot be selected by what the candidate passes. | 24.0 | `RT-RANKING-SOURCES` |
| 24.2 | **The candidate family universe** | the multi-ecosystem candidate package-identity universe discovered from the frozen dependency/ranking evidence (`forensics/downstream/candidates.json`) and the deduplicated **project families** it normalises into -- one family node per real downstream project family, never a package alias, each classified by directness and provenance-backed (`forensics/downstream/families.json`, schema kind `family`), with specimens kept separate for 24.3. | 24.1 | `RT-CANDIDATE-UNIVERSE` |
| 24.3 | **The authority-baseline census** | one authority-baseline census per specimen, recording the level the **pristine-source** build reached against the admitted authority, so a candidate pass is normalized against what the authority itself achieved (`forensics/downstream/authority-baselines.jsonl` and `forensics/downstream/usage-fingerprints.json`). | 24.2 | `RT-AUTHORITY-CENSUS` |
| 24.4 | **The P1000 + reserve freeze** | the frozen population of 1,000 counted families plus the reserve, selected from the precommitted ranking evidence and content-addressed before any candidate result (`forensics/downstream/family-freeze.json`). | 24.3 | `RT-FAMILY-FREEZE` |
| 24.5 | **The precommitted holdout partition** | the holdout partition fixed before the candidate was run against the development population and never used to choose a patch (`forensics/downstream/holdout.json`). | 24.4 | `RT-HOLDOUT-PARTITION` |
| 24.6 | **The build/link atlas** | one build/link run per specimen per subject, reaching `L2-configured`, `L3-built` and `L4-linked`, with candidate linkage proven (`forensics/downstream/build-link-atlas.json`). | 24.5 | `RT-BUILD-LINK-ATLAS` |
| 24.7 | **The runtime/functional atlas** | one runtime/functional run per specimen that reached the build/link levels, reaching `L5-loaded`, `L6-runtime` and `L7-functional` where the authority baseline did (`forensics/downstream/runtime-functional-atlas.json`). | 24.6 | `RT-RUNTIME-FUNCTIONAL-ATLAS` |
| 24.8 | **The failure discovery/minimization loop** | every discovered failure classified from the failure taxonomy, **preserved and minimized** (`forensics/downstream/failures.json` and the minimized fixtures under `forensics/downstream/failures/`), so a failure is a named, reproducible record rather than a discarded run. | 24.6, 24.7 | `RT-FAILURE-MINIMIZATION` |
| 24.9 | **The high-value deep tier** | the families that depend on OpenSSL most deeply measured past the shallow levels, to the functional level where they can be (`forensics/downstream/high-value-tier.json`). | 24.7, 24.8 | `RT-HIGH-VALUE-TIER` |
| 24.10 | **The hostility augmentation** | the separate hostility-augmentation corpus (`forensics/downstream/hostility-corpus.json`), kept apart from the counted P1000 families and never mixed into the population's rates. | 24.7 | `RT-HOSTILITY-AUGMENTATION` |
| 24.11 | **The candidate freeze and holdout** | the candidate identity frozen and content-addressed (`forensics/downstream/candidate-freeze.json`), and the precommitted holdout run against it exactly once, so the holdout is a real out-of-sample measurement. | 24.5, 24.9, 24.10 | `RT-CANDIDATE-FREEZE` |
| 24.12 | **The final full P1000 run** | the final full P1000 run over the frozen population at the frozen candidate (`forensics/downstream/p1000-run.json`), so every family's drop-in verdict is measured against the same candidate. | 24.11 | `RT-P1000-RUN` |
| 24.13 | **The atlas reconciliation** | the reconciliation of the atlas (`forensics/downstream/reconciliation.json`): every counted family has a verdict, every residual is classified, every failure is preserved and minimized, and the drop-in rates are computed over the frozen population rather than typed. | 24.12 | `RT-ATLAS-RECONCILIATION` |
| 24.14 | **The FRF/Gemel closure** | the FRF/Gemel chain closure where the stratum stages a declarable court, so a passing atlas is not read as a chain that never ran. | 24.13 | `RT-FRF-CLOSURE` |
| 24.15 | **The seal** | the closure of the atlas as the stratum's claim and the four non-claims it never exceeds. Evidence: `docs/PHASE-24-DOWNSTREAM-1000-SEAL.md` (at the seal). | 24.0-24.14 | `DOWNSTREAM-1000-SEAL` |
| 24.16 | **The biggest-mover shared-blocker analysis** | the partitioned, ranked shared-blocker analysis of the counted population (`forensics/downstream/shared-blockers.json`), the detailed report `docs/PHASE-24-BIGGEST-MOVERS.md`, the compact marker-bounded block in `README.md` and the `Biggest movers` section of the generated `docs/SEAL-CENSUS.md`, so 24.17 can act on the biggest movers rather than on the largest class by breadth. It is analysis, not repair, and its recipe queue is a labelled **heuristic**. | 24.15 | `RT-BLOCKER-LEVERAGE` |
| 24.17 | **The biggest-mover remediation** | the before/after record of the repairs (`forensics/downstream/blocker-remediation.json`) and the preserved pre-remediation baseline it reads (`forensics/downstream/blocker-remediation-baseline.json`): for every blocker class 24.16 named it records the exact recipe/flag/fixture each repair applied, preserves the 24.16 partition as `before`, re-derives the re-measured `after` from the committed planes and computes the movement. It fixes only what the fixed venue can run and records what it cannot as still-blocked. | 24.16 | `RT-BLOCKER-REMEDIATION` |

The rows above the seal partition the working set by source: each subphase row lands the instrument
for exactly one of the seventeen contract units. The partition is derived from
`forensics/phase24-obligations.json` joined to `artifacts/phase24/COURTS.json`, not typed.

**The evidence artefacts this stratum produces (brief §26).** The later subphases populate the
**downstream evidence plane**, each artefact validated against a record kind in
`forensics/tools/downstream_schemas.py`:

| artefact | record kind | schema |
|---|---|---|
| `forensics/downstream/ranking-sources.json` | ranking-source rows | `ranking_source` |
| `forensics/downstream/execution-levels.json` | the L0-L8 ladder | `execution_level` |
| `forensics/downstream/candidates.json` | the candidate package-identity universe | the 24.2 court's own checks |
| `forensics/downstream/families.json` | the deduplicated project families | `family` |
| `forensics/downstream/authority-baselines.jsonl` | the authority-baseline census | `run` |
| `forensics/downstream/usage-fingerprints.json` | the usage fingerprints and linkage proof | `run`, `specimen`, `variant` |
| `forensics/downstream/family-freeze.json` | the frozen P1000 + reserve | `family` |
| `forensics/downstream/holdout.json` | the holdout partition | `family` |
| `forensics/downstream/build-link-atlas.json` | build/link runs and variants | `run`, `variant` |
| `forensics/downstream/runtime-functional-atlas.json` | runtime/functional runs | `run` |
| `forensics/downstream/failures.json` | the classified, preserved, minimized failures | `failure` |
| `forensics/downstream/high-value-tier.json` | the high-value deep tier | `run` |
| `forensics/downstream/hostility-corpus.json` | the separate hostility corpus | `run` |
| `forensics/downstream/candidate-freeze.json` | the candidate freeze and the once-run holdout | `drop_in_verdict` |
| `forensics/downstream/p1000-run.json` | the final full P1000 run | `run`, `drop_in_verdict` |
| `forensics/downstream/reconciliation.json` | residuals, verdicts and the computed rates | `residual`, `drop_in_verdict` |
| `docs/PHASE-24-DOWNSTREAM-1000-SEAL.md` | the seal | — |

24.0 invents none of these artefacts: it defines and self-tests the schemas the later subphases will
be validated against, and the runner records the schema inventory and the closed vocabularies so
the record kinds are a file the evidence points at rather than prose.

## 3. What each subphase must honour

**3.1 The counted unit is the family, and a specimen is separate.** A family is a real project
family, never a package alias; a specimen is one concrete source tree of a family. A subphase that
is tempted to count a package name records the family instead, and a family measured on one
specimen is never claimed for all its versions.

**3.2 `DROP_IN_PASS` is baseline-normalized, and the schema refuses the shortcuts.** A pass requires
the same pristine source, a succeeded authority baseline, the candidate reaching the
authority-applicable level, proven linkage, and zero candidate-specific patches. A pass asserted
without an authority baseline or with a positive patch count fails the schema by name.

**3.3 The instrument-versus-property split keeps a pass from being read as the property.** A
passing court is an instrument: it ran and its control was honest. The property it names -- a fully
reconciled atlas, a fully classified residual set -- is carried by `property_status` and `findings`,
and where the evidence falls short the unit reads `NOT_CLAIMED` with the gap named. The seal records
the four non-claims as findings, so a passing seal is never "the downstream ecosystem is safe".

**3.4 The population is frozen before any candidate result.** The ranking sources are acquired and
content-addressed before the candidate is run; the P1000 and the holdout are frozen from them; the
holdout is run exactly once against a frozen candidate. A subphase that would select a family by
what the candidate passes records a `finding` rather than a counted family.

**3.5 Every residual is classified and every failure preserved and minimized.** A leftover names a
residual class from the closed vocabulary; a failure names a class from the failure taxonomy and is
preserved and minimized. `unknown` is a recorded class, never traded for confidence.

**3.6 The direct and transitive consumers are kept apart.** `openssl_linkage` names which a family
is, and the two are never summed into one rate. A subphase that measures a transitive consumer
records it as such.

**3.7 The hostility augmentation is separate from the counted population.** The hostility corpus is
kept apart and never mixed into the counted P1000 families' rates.

**3.8 Nothing executes on the host.** Every entry point calls the Docker-only execution guard
(`forensics/tools/phase24_guard.py`) first, so a host invocation is refused rather than producing
unreproducible evidence (`docs/REPRODUCIBILITY.md` §1).

**3.9 The seventeen units land in one ordered chain behind the runner.** 24.1 through 24.14 land the
fourteen instruments; 24.15 lands the seal that closes the atlas; 24.16 lands the biggest-mover
shared-blocker analysis over the finished measurement; 24.17 lands the remediation of the biggest
movers it named; each lands its code, its court and its regenerated artefacts in one commit, and the
ledger's `open_in_this_stratum` moves only when a court in `artifacts/phase24/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase24-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `downstream 1000 contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase
16's `cli-config contract` through Phase 23's `multitrack authority contract` are. The ledger fails
closed if the ownership atlas ever assigns this stratum an export, if the provider census assigns
it a registration row, or if the prerequisite plane assigns it a deferral or a translation unit,
because then the non-export unit would be the wrong shape.

**4.2 The precondition this plan places on 24.0, and it is not optional.** `run_courts.py` refuses
a stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase24_courts.py` with **no runnable court**: its obligations are not exports, so
no differential probe over a symbol set is its evidence, and its sixteen courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The direction
of the `phase24_courts.py` ↔ `phase24_obligations.py` edge is the reverse of Phase 16's**: the
ledger's contract-unit states are measured from the courts registry, so the registry is generated
first and `phase24_courts.py` does **not** bind the ledger as an input. A cycle in which each
embedded the other's digest would make neither reproducible. So the activation order is: the
runner and its pending registry, the ledger, the schemas and the guard land **together**, or
`run_courts.py` fails and the tree carries an activation whose runner is refused.

**4.3 The Docker-only execution guard is the stratum's first-class precondition.** Phase 24's
subject is other software's build and run behaviour, so `docs/REPRODUCIBILITY.md` §1's
"nothing executes on the host" is the stratum's own precondition rather than a procedural rule.
24.0 lands `forensics/tools/phase24_guard.py`, which fails closed unless the container marker
(`/.dockerenv`) is present **and** `PHASE24_CONTAINER` is `1` **and** the environment records an
admitted image identity and platform matching the committed manifest
`forensics/downstream/container.json`. The venue records the admitted values: every
`docker/openssl-rs-court.sh exec` sets the three variables, so a host invocation -- which has no
marker -- is refused with a clear message. The guard exposes the check as a pure function, so the
runner's self-test proves a host invocation is refused without running on a host. The manifest
lists the Phase-24 **metadata-only** generators (`phase24_obligations.py`), which read committed
atlases and execute nothing: the guard admits them on any host exactly as the other strata's
obligation generators run host-side, and a generator that would compile or run a downstream project
is deliberately absent from the list.

**4.4 The prerequisite and provider planes are not this stratum's universe, and the plan says
so.** No row of `forensics/prerequisites.json` and no row of
`forensics/atlas/provider-algorithms.json` is owned by phase 24, so this plan names no prerequisite
unit and no provider row for it and plan reconciliation has no unit of this stratum's to judge; a
subphase that discovers its unit is elsewhere records that rather than forcing a row (§0, §5).

**4.5 The seal will correct this plan if the record kinds differ.** Phase 24 activates over record
kinds it defines in 24.0 but does not yet populate, so §1's measurement is a read of what exists
and a design of what will. If a subphase finds that a record kind the brief names is better split,
or that a class list needs a member the schema does not have, it records the correction here and in
the seal rather than folding it into the prose it corrects. The correction is checked by the
subphase's court rather than asserted.

**4.6 A selected empirical population is not a random sample, and the atlas says so.** The
population is *selected* from frozen ranking evidence, so its rates are a measurement of that
population and never of all downstream software. Every reconciliation records the selection rule
and the population it measured, and the seal records the non-claim, so a rate is never read as a
population-wide probability.

**4.7 The candidate universe is two artefacts, and a family carries a directness class (24.2).**
The candidate universe is not one file: `forensics/downstream/candidates.json` holds the package
**identities** (the several thousand `(ecosystem, package)` rows the frozen evidence discovers,
with the source row each came from) and `forensics/downstream/families.json` holds the
deduplicated project **families** (schema kind `family`) the identities collapse to. A provider
identity -- the OpenSSL packages themselves, or a name collision such as Crypto++'s `libcrypto++`
-- is classified `NOT_ACTUALLY_OPENSSL` and excluded from the family universe rather than counted.
This extends the `family` record with the brief section 9 fields (a canonical name, the alias set,
the distro/ecosystem package listings, the licence, the popularity/criticality signals and the
selection provenance) and adds the brief section 8 seven-class `directness_class`, which
`openssl_linkage` (`direct`/`transitive`) is checked against; the `RT-CANDIDATE-UNIVERSE` court
checks the correction rather than this paragraph asserting it. The measured universe is recorded
in the court's registry row and in `forensics/downstream/candidates.json`'s own counts, not typed
here.

**4.8 The census court and unit are renamed, and the census is authority-side only (24.3).** The
working names this plan used for 24.3 -- the court `RT-AUTHORITY-BASELINE`, the unit
`authority-baseline-census` and the artefact `forensics/downstream/authority-baseline.json` -- are
corrected here: the court is `RT-AUTHORITY-CENSUS`, the unit is `authority-census`, and the census
lands as two artefacts, `forensics/downstream/authority-baselines.jsonl` (one schema-`run` row per
cohort member) and `forensics/downstream/usage-fingerprints.json` (the separate specimens, the
pristine variants, the imported OpenSSL symbols, the headers and the linkage proof). The rename is a
name correction to the plan's prose and not a record-kind change, so §1 and §2 carry the corrected
names and the court checks the correction rather than this paragraph asserting it. The census is
**authority-side only**: it runs the acquire -> configure -> compile -> link -> launch ladder against
the admitted authority and never executes a candidate, so a family the authority cannot build is
`AUTHORITY_BASELINE_FAIL` with a precise reason and is never counted as a candidate failure. Its
cohort is a **bounded, provisional** census cohort (the families carried by at least four frozen
ranking sources), recorded and reproducible from the frozen 24.1 evidence; the real P1000 freeze is
24.4, and the provisional cohort selects nothing. `RT-AUTHORITY-CENSUS` checks all of this.

**4.9 The freeze-time candidate scan is time-scoped, so the candidate runs the freeze enabled are
not read as pre-freeze contamination (24.6).** The freeze (24.4) and the holdout (24.5) each scan
the committed downstream plane and fail if a candidate-subject run exists, which is §3.4's rule
that the population is frozen before any candidate result. 24.6 is the first subphase that
**legitimately** runs the candidate, so its build/link atlas carries candidate rows the freeze
itself made possible, and every later subphase's artefact carries them too. The scan is therefore
scoped to the plane as it existed at freeze time: the artefact set the stratum produces only after
the freeze (`build-link-atlas.json`, `runtime-functional-atlas.json`, `failures.json`,
`high-value-tier.json`, `hostility-corpus.json`, `candidate-freeze.json`, `p1000-run.json`,
`reconciliation.json`) is excluded, so the property the scan names -- that no candidate result
existed *at freeze time* -- is preserved rather than a later subphase's honest measurement being
recorded as contamination. A candidate-subject row in any other artefact is still a finding, and
the sensitivity control still catches a fabricated candidate row injected under any path outside
that set. The population's own frozen-before-any-candidate property is enforced separately: the
freeze is a pure function of the committed families and ranking evidence and its court re-derives
it. `RT-FAMILY-FREEZE`, `RT-HOLDOUT-PARTITION` and `RT-BUILD-LINK-ATLAS` check this.

**4.10 The frozen candidate identity is the install content-address, and the source commit is
recorded provenance, not a live-HEAD binding (24.11, corrected in 24.12).** 24.11 first built the
candidate identity from the drop-in install digests together with `source_commit = git rev-parse
HEAD` and compared the whole record against a freshly re-derived one. That is a self-reference: the
commit necessarily moves when the artefact's own commit lands, so the recorded identity can never
equal live HEAD afterwards and the court fails on the next commit. The identity is corrected to
content-address the **install** -- the `libssl`/`libcrypto` digests, the headers, the pkg-config
metadata, the provider modules, the crate name and version and the admitted venue -- and to carry
the source commit as **recorded provenance** that is excluded from `identity_hash` and from the live
equality check, and is instead required to name a commit that exists in the repository history
(`git cat-file -e <sha>^{commit}`). A recorded `unknown` is admitted only where git is genuinely
absent. `RT-CANDIDATE-FREEZE` and `RT-P1000-RUN` check this, and 24.12's full run asserts the
install still matches the frozen identity by its install fields, not by live HEAD.

**4.11 The stratum stages no declarable court, so 24.14's FRF/Gemel chain entry is vacuous, and the plan's "where the stratum stages a declarable court" is the conditional this no-probe shape resolves to the vacuity (24.14).** §2's 24.14 row gives the subphase one obligation -- the FRF/Gemel chain closure *"where the stratum stages a declarable court, so a passing atlas is not read as a chain that never ran"* -- and Phase 24 owns no exported symbol and stages no probe, so **no Phase-24 court is declared in `gen_frf_courts.py` and no `artifacts/phase24/probes/<probe>.{authority,candidate}` pair is staged**. The chain entry is therefore **vacuous by `phase_state.py`'s own scoping**: `frf_gemel_blocking_reason(24)` is `""`, and the stratum owes no `.frf` declaration, receipt, adjudicated challenge or sensitivity-backed claim, and no Gemel checkpoint. That is not a chain that never ran, and what stands in the chain's place is recorded in `forensics/atlas/phase24/frf-closure.json` and re-checked by `RT-FRF-CLOSURE`: the **`RT-FRF-CLOSURE` harness challenge** -- each of the thirteen Phase-24 planes' own pure checker driven over its committed artefact and over the controlled mutations its own sensitivity control seeds, with the classifier proved not a rubber stamp (13 `DETECTED`, 0 `NOT_DETECTED`, 0 `NOT_DRIVEN`) -- plus the committed **Gemel checkpoint projection** `forensics/GEMEL_TRAJECTORY.md`, whose `current:` is the boundary a later session resumes from. The correction is that §2's wording is a **conditional**, and this stratum's shape resolves it to the vacuity rather than to a row: the plan is not rewritten to stage a declarable court that does not exist, and the seal records the same reading (`docs/PHASE-24-DOWNSTREAM-1000-SEAL.md` §8 and §13). `RT-FRF-CLOSURE` checks the correction rather than this paragraph asserting it.

**4.12 The biggest-mover shared-blocker analysis is a new contract unit after the seal, and it re-opens the stratum (24.16).** The seal (24.15) closed the atlas, and this subphase adds a sixteenth unit -- `blocker-leverage`, closed by the `RT-BLOCKER-LEVERAGE` court -- so a complete stratum is re-opened while the new court is unregistered and closes again when it passes. The correction is that the stratum's working set is now **sixteen** contract units, not fifteen: §1's count, §2's row and §3.9 are updated, `phase24_obligations.py`'s `COURT_UNITS` gains the unit, and `phase_state.py`'s ledger note names sixteen. The unit is an **analysis**, not a repair: `forensics/tools/downstream_blockers.py` partitions the 1,000 counted families by their deepest blocker (each counted exactly once) and ranks the classes by their **mover potential** and **per-fix leverage**, and `forensics/tools/render_biggest_movers.py` renders the detailed report `docs/PHASE-24-BIGGEST-MOVERS.md`, the compact marker-bounded block in `README.md` and the `Biggest movers (generated)` section of `docs/SEAL-CENSUS.md`, each from `forensics/downstream/shared-blockers.json` alone. **A heuristic ranking of buildability is not a measurement of buildability**: the feasible recipe queue the analysis emits is labelled a heuristic wherever it appears, and moving one-rung-per-blocker is a structural count, not a measurement that any family would pass if repaired. The seal court is re-derived to require the report link, so a seal that has lost the analysis fails rather than passing as a smaller green run. `RT-BLOCKER-LEVERAGE` and `DOWNSTREAM-1000-SEAL` check the correction rather than this paragraph asserting it.

**4.13 The biggest-mover remediation is a new contract unit after the seal, and it re-opens the stratum once more (24.17).** 24.16 partitioned the counted families by their deepest blocker and named which moves the most, but it repaired nothing: its recipe queue is a labelled heuristic. This subphase adds a seventeenth unit -- `blocker-remediation`, closed by the `RT-BLOCKER-REMEDIATION` court -- so a complete stratum is re-opened while the new court is unregistered and closes again when it passes. It acts on the biggest movers **empirically**: it fixes the recipe-backed blockers the fixed venue can run (24.17's `recipe-fix:kmod` adds `--disable-manpages`; `recipe-fix:openvpn` pins the 2.5 line and configures without libnl/libcap-ng; `recipe-fix:isync` adds `-Wl,-rpath-link` so the authority prefix resolves libssl's transitive libcrypto), and it records the two it cannot as `still-blocked` with the exact missing tool (`libssh` needs `cmake`; `lighttpd` needs autotools/cmake/meson, admitting no generated `configure`); it adds the two missing deterministic local fixtures (`fixture:pure-ftpd`, an authenticated explicit-TLS FTPS login driven by the authority's own `openssl s_client`; `fixture:isync`, a local IMAP4rev1-over-TLS peer the subject `mbsync` syncs from); and it admits a bounded, deterministic batch of recipe-less counted families whose pinned release tarball ships a build entry point the venue can execute. The criterion is **empirical**, not a heuristic: the batch is the families actually built and measured, and the candidates the venue could not build are recorded with the reason. `forensics/tools/downstream_remediation.py` records it: for every blocker class 24.16 named it reads the preserved pre-remediation baseline `forensics/downstream/blocker-remediation-baseline.json` as `before`, re-derives the re-measured `after` from the committed planes through 24.16's own code path, computes the `movement`, and names the exact recipe/flag/fixture each `action` applied. **Before/after are measured, never typed**: a resolving action must show its families moved in the re-measured planes, a still-blocked action must show they did not and name its missing tool, and a movement figure that disagrees with the planes is a finding. It executes nothing, so it is declared `metadata_only` in the container manifest. The correction is that the stratum's working set is now **seventeen** contract units, not sixteen: §1's count, §2's row and §3.9 are updated, `phase24_obligations.py`'s `COURT_UNITS` gains the unit, and `phase_state.py`'s ledger note names seventeen. The seal cites the record and its measured movement, so a seal that has lost the remediation fails rather than passing as a smaller green run. `RT-BLOCKER-REMEDIATION` and `DOWNSTREAM-1000-SEAL` check the correction rather than this paragraph asserting it.

## 5. Process

This stratum inherits Phases 8 through 23's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the seventeen-unit measurement in §1. A subphase that discovers its unit
is elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the seventeen downstream 1000 contract
units, recorded in the ledger's contract-unit block rather than as open exports.
