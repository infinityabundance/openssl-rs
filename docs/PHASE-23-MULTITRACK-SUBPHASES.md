# Phase 23 — the multitrack authority stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 23 is the stratum `docs/RELEASE_GATES.md` §1 names "Multitrack authority compatibility and
OpenSSL lineage". It is admitted once the authority archaeology (Phase 1, strengthened by Phase 22)
and the maintenance-delta machinery (Phase 21) are complete, and it is dependency-ordered after
them rather than after the highest number: `forensics/tools/phase_state.py`'s `REQUIRES[23]` is
`(21,)`, and because Phase 21 requires Phase 22 that single edge transitively requires both. No
existing phase is renumbered.

Like Phases 16 through 21 it owns **no exported symbol**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 23` yields nothing, because the
declaring-header rule assigns no installed header to this stratum. Its unit is therefore not a
symbol. As with Phases 18, 19, 20 and 21 it **hands nothing forward and receives nothing**: it
adds no library surface, takes no unit or symbol deferral from an earlier stratum, and activates
no provider.

What it owes is the **multitrack authority model itself**: one Rust implementation that can emit
**independently-evidenced compatibility views** for the OpenSSL release lineage, from the first
real release (OpenSSL 0.9.1c) through the latest admitted stable release and forward to future
releases, without a per-version fork, without a Cargo feature per version, and without a runtime
version switch in one DSO. The architecture is infrastructure for the lifetime of the project, and
its vocabulary is fixed here:

* a **release node** — one upstream OpenSSL release: its identity (`release_id`,
  `display_version`), the `version_scheme` its number is encoded in (`pre-3.0-mnnffpps` or
  `3.0-plus-major-minor-patch`), its `release_channel` (`final`, `alpha`, `beta`, `development` or
  `historical_auxiliary`), `release_date`, whether it is `public` or `extended` and `mainline` or
  `auxiliary`, its `upstream_tag` and `upstream_commit`, the `official_source_artifact` and its
  `source_sha256`, its declared support class and compatibility family, its licence epoch, its
  `known_parent_edges` and the provenance of its metadata. A release node is a *fact about
  upstream*, not a claim about this crate.
* an **authority node** — one *built* authority over a release: the release it is built from, the
  platform, architecture, build profile, toolchain and build environment, and the binary and
  installed hashes. A release may have several authority nodes (different platforms or profiles);
  an authority node is what a court can be run against.
* a **lineage edge** — a typed relationship between two release nodes (or authority nodes):
  `chronological_successor`, `git_ancestry`, `branch_fork`, `maintenance_successor`,
  `security_backport`, `declared_abi_compatibility` or `observed_compatibility`. A lineage edge is
  a **relationship**, not evidence: it never carries a compatibility claim.
* **entity lineage** — what became of one public entity (an export, a type, a macro, a field, an
  algorithm name) across releases: `same_entity`, `renamed_to`, `moved_to`, `signature_changed`,
  `layout_changed`, `kind_changed`, `split_into`, `merged_from`, `deprecated`, `removed`,
  `reintroduced`, `semantic_successor` or `unknown_relationship`.
* a **compatibility view** — a **directional** and **dimension-specific** statement that this
  implementation, at a named support status, behaves compatibly with a named reference release on
  one named dimension, with the release-specific evidence it was derived from and its explicit
  non-claims. It is never a single boolean.
* a **compatibility edge** — a directional edge between two releases (or authorities) on one
  dimension, carrying the evidence kind it rests on. Numeric ordering is **not** an evidence kind:
  compatibility is never derived from the version number.

The **delta engine** computes, between two nodes, the added / removed / changed surface the
compatibility views are about, mechanically from committed evidence rather than by hand. The
**negative obligations** record what *must be absent* (`must_not_exist`, `must_be_opaque`,
`must_not_be_exported`) with the same standing as what must be present. The **security lineage**
records the historical vulnerabilities of the lineage as observations that are never reintroduced
(`docs/SECURITY_DIVERGENCE_POLICY.md` §1).

It is **not** a stronger claim than the evidence supports, and it is **not** a per-version set of
implementations. One implementation crate emits documentary, independently-evidenced views; the
view is the claim, the crate is the subject. A passing court is an **instrument**, not a property:
it ran and its control was honest, and the property it names may still carry findings.

The load-bearing non-claims belong to every subphase, and they are recorded in the ledger's
`ledger_note`, in `docs/NON_CLAIMS.md` and here:

* **historical API compatibility is not security approval** — reproducing an old release's visible
  surface does not endorse its security posture;
* **reproducing an old algorithm is not recommending it** — a legacy algorithm exercised for
  compatibility is not a recommendation to use it;
* **OpenSSL compatibility is not FIPS validation** — `docs/FIPS_CLAIMS.md` is the authority, and a
  compatibility view makes no validation claim;
* **one platform/profile is not every platform/profile** — a view is bounded to the platform,
  architecture, profile and toolchain of the authority node it names;
* **an archaeological source node is not runtime parity** — a release node derived from source is
  not an authority node that was built and exercised;
* **upstream's ABI promise is not candidate evidence** — an upstream `declared_abi_compatibility`
  edge is upstream's statement, not this crate's measured behaviour.

A historical vulnerability is observed in the security lineage and **never reintroduced**
(`docs/SECURITY_DIVERGENCE_POLICY.md` §1 and §3). Unknown stays unknown (`docs/PARITY_MODEL.md`
§1); a relationship or dimension that cannot be resolved is recorded `unknown_relationship` or
`not_measured`, never traded for confidence. `docs/NON_CLAIMS.md`, `docs/AUTHORITY_POLICY.md`,
`docs/PARITY_MODEL.md`, `docs/ABI_POLICY.md` and `docs/SECURITY_DIVERGENCE_POLICY.md` are the
authorities on what may be said; a subphase that discovers its unit is somewhere else records that
rather than forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase23-obligations.json` is
authoritative for the present. The activation measurement was taken against `main` `46af10f4`
(openssl-rs 0.0.26, Phase 21 released and Phase 22 complete).

**Phase 23 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for `owner_phase ==
23` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger fails closed if
that ever stops being true rather than silently counting a symbol through a non-export unit.

**It receives zero provider registration rows.** Reading `forensics/atlas/provider-algorithms.json`
for `owning_phase == 23` gives no row: this stratum activates no provider. The ledger fails closed
if the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading `forensics/prerequisites.json`
for `owner_phase == 23`: no `deferrals` row and no `units` row. The plane's records and deferrals
are all owned by earlier strata, so this stratum's working set is entirely its own authored
contract.

**The multitrack authority contract is seventeen units**, each derived from the court that
measures it, and each court lands with the subphase that builds its instrument:
`release-nodes`, `authority-nodes`, `atlas-parameterization`, `lineage-edges`, `entity-lineage`,
`delta-engine`, `abi-history-facades`, `semantic-courts`, `compatibility-views`,
`historical-population`, `downstream-multitrack`, `directional-compatibility-edges`,
`negative-obligations`, `security-lineage`, `support-status`, `compatibility-matrix` and
`multitrack-seal`. Three of the seventeen have closed -- `release-nodes` (23.1), `authority-nodes`
(23.2) and `atlas-parameterization` (23.3, docs/DECISIONS.md D538) -- and the ledger's live `counts`
is the record of that: `open_in_this_stratum` is the
number of still-open units, not the whole working set. The five units this plan's first draft
omitted -- `atlas-parameterization`, `abi-history-facades`, `semantic-courts`,
`historical-population` and `downstream-multitrack` -- are the brief §52 slices §4.8 restores,
and the corrected activation measurement is seventeen `pending` courts over seventeen units.

**The multitrack evidence plane already has its schema.** 23.0 lands
`forensics/tools/multitrack_schemas.py`, which defines and validates the record kinds the later
subphases populate and which parses both OpenSSL version schemes. The strata this plan rests on
have already admitted the two authorities it starts from -- `openssl-3.6.3-historical` and
`openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`, `docs/AUTHORITY_POLICY.md`
§1) -- and the maintenance-delta planning of Phase 21 named their relationship. 23.0 invents none
of the authority evidence: it names the record kinds the later subphases will fill.

**This stratum is never a single boolean.** No compatibility view is derivable from a version
comparison, and `multitrack_schemas.validate_compatibility_edge` rejects a `version_order`
evidence kind. The version parser exists to establish *chronology* and to name a scheme, never to
infer compatibility (`docs/PARITY_MODEL.md` §4).

**Phase 23 begins on nothing of its own.** No multitrack court exists at activation, so the
corrected `open_in_this_stratum` opens at the whole working set (seventeen) and moves only as the
subphases below land. **That split moves as the stratum lands its own units: the ledger's `counts` is the
live record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 23.0 | **The plan, the schemas, the ledger and the runner** | `docs/PHASE-23-MULTITRACK-SUBPHASES.md`, `forensics/tools/multitrack_schemas.py` and the measurement in §1. The ledger (`forensics/phase23-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase23_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 21 | — |
| 23.1 | **The release catalogue and lineage query tooling** | one release node per upstream release, from OpenSSL 0.9.1c forward, read from the committed archaeology snapshot and the upstream lineage rather than typed, with the version parser and scheme model in `forensics/tools/multitrack_schemas.py`; the typed lineage between them (`forensics/authority-lineage.json`) and the query tool `forensics/tools/authority_graph.py`. | 23.0 | `RT-RELEASE-CATALOG` |
| 23.2 | **The authority-node registry** | one authority node per built authority, over the releases an authority has been admitted for, recording platform, arch, build profile, toolchain, build environment and binary/installed hashes. | 23.1 | `RT-AUTHORITY-NODES` |
| 23.3 | **Parameterize the atlases** | the Phase 1 / Phase 22 archaeology generators generalized to be **parameterized by authority identity** -- one parameterized generator rather than a `phase1_old.py` per version -- with a court that regenerates the current 3.6.4 atlas through the parameterized generator and proves it **byte-identical** to the committed one, so the refactor never moves the evidence it exists to make reusable. | 23.0, 23.1, 23.2 | `RT-ATLAS-PARAMETERIZATION` |
| 23.4 | **The lineage edges** | the typed chronological / git-ancestry / branch-fork / maintenance-successor / security-backport edges between release nodes, each stating the direction it is read in. | 23.1 | `RT-LINEAGE-EDGES` |
| 23.5 | **The entity lineage** | what became of each public entity across releases, with the relation vocabulary of §0 and `unknown_relationship` where the evidence does not settle it. | 23.1, 23.4 | `RT-ENTITY-LINEAGE` |
| 23.6 | **The delta engine** | the added / removed / changed surface between two nodes, computed mechanically from the atlas and the entity lineage, never hand-listed, in the direction the lineage edge names. | 23.4, 23.5 | `RT-DELTA-ENGINE` |
| 23.7 | **The ABI / history façades** | the historical public-layout (`#[repr(C)]`) façades, the prototype wrappers, the initialization / threading epochs, and the ENGINE -> Provider -> no-ENGINE architecture model, each a **narrow adapter over the shared implementation** rather than a per-version fork. | 23.2, 23.6 | `RT-ABI-HISTORY-FACADES` |
| 23.8 | **The semantic multitrack courts** | the **oracle-to-oracle** (authority A vs authority B) and **candidate-to-authority** courts, with side-specific adapters that emit the same **normalized observation vocabulary**, so the candidate and the oracle are read the same way and a comparison is a comparison rather than a translation. | 23.2, 23.6, 23.7 | `RT-SEMANTIC-COURTS` |
| 23.9 | **The compatibility views** | a directional, dimension-specific view per support status, each naming its reference release, its dimension and the release-specific evidence it was derived from -- never a boolean, and never inheriting a receipt across a version. | 23.6, 23.8 | `RT-COMPATIBILITY-VIEWS` |
| 23.10 | **The historical population** | the systematic **admission and courting of the public final-release lineage forward from the first release** (OpenSSL 0.9.1c), recording **honest unavailability** where a release cannot be reproducibly built rather than counting it runtime-compatible. | 23.2, 23.3, 23.9 | `RT-HISTORICAL-POPULATION` |
| 23.11 | **The downstream multitrack court** | at least **one meaningful unmodified real downstream consumer per major compatibility epoch**, exercised as this stratum's own multitrack court rather than as Phase 17's replacement corpus. | 23.9, 23.10 | `RT-DOWNSTREAM-MULTITRACK` |
| 23.12 | **The directional compatibility edges** | the directional compatibility edges between releases or authorities on one dimension each, with an evidence kind that is never numeric ordering. | 23.9 | `RT-COMPATIBILITY-EDGES` |
| 23.13 | **The negative obligations** | the `must_not_exist` / `must_be_opaque` / `must_not_be_exported` obligations (beside the positive `must_exist` / `must_be_public` / `must_be_exported`), each with evidence and a state, so an absence is a checkable claim rather than an omission. | 23.1 | `RT-NEGATIVE-OBLIGATIONS` |
| 23.14 | **The security lineage** | the historical vulnerabilities of the lineage, observed and never reintroduced, with the observation and the non-reintroduction each recorded so a view can never re-adopt a fixed behaviour. | 23.4, 23.9 | `RT-SECURITY-LINEAGE` |
| 23.15 | **The support-status ladder** | the derived support status of each release node, over `catalogued`, `admitted-source`, `built-authority`, `atlas-complete`, `candidate-view`, `runtime-evidenced`, `downstream-evidenced` and `maintained`, with `archaeological-only` where the node is studied and not supported. | 23.1, 23.2, 23.11 | `RT-SUPPORT-STATUS` |
| 23.16 | **The compatibility matrix** | the assembled matrix that joins the views, the edges, the negative obligations and the security lineage over the lineage, with every cell a directional, dimension-specific record and no cell a single boolean. | 23.9, 23.11-23.15 | `RT-COMPATIBILITY-MATRIX` |
| 23.17 | **The full matrix, the FRF/Gemel chain and the seal** | the closure of the matrix as the stratum's claim, the FRF/Gemel chain rule where the stratum stages a declarable court, and the seal. Evidence: `docs/PHASE-23-MULTITRACK-SEAL.md` (at the seal). | 23.0-23.16 | `MULTITRACK-SEAL` |

The rows above the seal partition the working set by source: each subphase row lands the instrument
for exactly one of the seventeen contract units. The partition is derived from
`forensics/phase23-obligations.json` joined to `artifacts/phase23/COURTS.json`, not typed.

**The brief §52 slice -> subphase -> court/unit map, so no slice can be silently dropped.** The
brief's execution order (§52) has seventeen contract slices plus the plan/schema/runner slice. The
repository's first draft of this table covered only twelve of them: it omitted five and renumbered
the capabilities that followed the omissions down to fill the gap. This table maps every brief
slice to the subphase that lands it and the court/unit that closes it, and records where the
repository's numbers differed before the reconciliation of §4.8.

| brief §52 slice | subphase | court / unit | what changed |
|---|---|---|---|
| 23.0 plan / schemas / ledger / runner | 23.0 | — (the runner itself) | unchanged |
| 23.1 release catalogue | 23.1 | `RT-RELEASE-CATALOG` / `release-nodes` | unchanged (closed) |
| 23.2 authority-node registry | 23.2 | `RT-AUTHORITY-NODES` / `authority-nodes` | unchanged (closed) |
| 23.3 **parameterize the atlases** | 23.3 | `RT-ATLAS-PARAMETERIZATION` / `atlas-parameterization` | **restored** -- was omitted; `lineage-edges` had been numbered 23.3 |
| 23.4 lineage edges | 23.4 | `RT-LINEAGE-EDGES` / `lineage-edges` | renumbered from 23.3 |
| 23.5 entity lineage | 23.5 | `RT-ENTITY-LINEAGE` / `entity-lineage` | renumbered from 23.4 |
| 23.6 delta engine | 23.6 | `RT-DELTA-ENGINE` / `delta-engine` | renumbered from 23.5 |
| 23.7 **ABI / history façades** | 23.7 | `RT-ABI-HISTORY-FACADES` / `abi-history-facades` | **restored** -- was omitted; `directional-compatibility-edges` had been numbered 23.7 |
| 23.8 **semantic multitrack courts** | 23.8 | `RT-SEMANTIC-COURTS` / `semantic-courts` | **restored** -- was omitted; `negative-obligations` had been numbered 23.8 |
| 23.9 compatibility views | 23.9 | `RT-COMPATIBILITY-VIEWS` / `compatibility-views` | renumbered from 23.6 |
| 23.10 **historical population** | 23.10 | `RT-HISTORICAL-POPULATION` / `historical-population` | **restored** -- was omitted; `support-status` had been numbered 23.10 |
| 23.11 **downstream multitrack court** | 23.11 | `RT-DOWNSTREAM-MULTITRACK` / `downstream-multitrack` | **restored** -- was omitted; `compatibility-matrix` had been numbered 23.11 |
| 23.12 directional compatibility edges | 23.12 | `RT-COMPATIBILITY-EDGES` / `directional-compatibility-edges` | renumbered from 23.7 |
| 23.13 negative obligations | 23.13 | `RT-NEGATIVE-OBLIGATIONS` / `negative-obligations` | renumbered from 23.8 |
| 23.14 security lineage | 23.14 | `RT-SECURITY-LINEAGE` / `security-lineage` | renumbered from 23.9 |
| 23.15 support status | 23.15 | `RT-SUPPORT-STATUS` / `support-status` | renumbered from 23.10 |
| 23.16 compatibility matrix | 23.16 | `RT-COMPATIBILITY-MATRIX` / `compatibility-matrix` | renumbered from 23.11 |
| 23.17 seal | 23.17 | `MULTITRACK-SEAL` / `multitrack-seal` | renumbered from 23.12 |

**The brief §49 seal requirements, and where each is discharged.** §49 fixes what the seal must
state rather than bury; every requirement is carried by a subphase below, and the seal (23.17)
closes over all of them. A requirement whose evidence is not yet measured reads `NOT_CLAIMED` with
the gap named, never as satisfied.

| brief §49 seal requirement | discharged by |
|---|---|
| the full compatibility matrix closed as the stratum's claim, every cell directional and dimension-specific, no cell a boolean | 23.16, sealed by 23.17 |
| the FRF/Gemel chain rule where the stratum stages a declarable court | 23.17 |
| the six explicit non-claims of §0 recorded in the ledger note, `docs/NON_CLAIMS.md` and the seal | 23.0 (the ledger note), 23.17 (the seal) |
| honest unavailability: a release that cannot be reproducibly built is recorded `unavailable` and is never counted runtime-compatible | 23.10 |
| the historical security lineage observed and never reintroduced | 23.14 |
| reproducibility: a regenerated atlas is byte-identical, and the seal defers its counts to the generated census rather than typing them | 23.3, 23.17 |
| the seal document `docs/PHASE-23-MULTITRACK-SEAL.md` and the `phase_state.py` closure rule that keeps the stratum `in-progress` until it exists | 23.17 |

**The evidence artefacts this stratum produces (§38 of the brief).** The later subphases populate
the **multitrack evidence plane**, each artefact validated against a record kind in
`forensics/tools/multitrack_schemas.py`:

| artefact | record kind | schema |
|---|---|---|
| `forensics/release-catalog.json` | release nodes | `release_node` |
| `forensics/authority-nodes.json` | authority nodes | `authority_node` |
| `forensics/authority-lineage.json` | lineage edges | `lineage_edge` |
| `forensics/multitrack/entity-lineage.json` | entity lineage | `entity_lineage` |
| `forensics/multitrack/delta-receipts.json` | delta-engine records | `delta_receipt` |
| `forensics/multitrack/compatibility-views.json` | compatibility views | `compatibility_view` |
| `forensics/multitrack/compatibility-edges.json` | directional compatibility edges | `compatibility_edge` |
| `forensics/multitrack/negative-obligations.json` | negative obligations | `negative_obligation` |
| `forensics/multitrack/security-lineage.json` | security-lineage observations | `security_observation` |
| `forensics/multitrack/support-status.json` | support-status rows | `support_status` |
| `forensics/multitrack/compatibility-matrix.json` | the assembled matrix | `compatibility_matrix` |
| `forensics/atlas/parameterization-receipt.json` | the parameterization proof: the 3.6.4 atlas regenerated through the parameterized generator, byte-identical | `parameterization_receipt` (added by 23.3) |
| `forensics/multitrack/abi-facades.json` | the historical public-layout and prototype façade records | `abi_facade` (added by 23.7) |
| `forensics/multitrack/semantic-courts.json` | the normalized oracle-to-oracle and candidate-to-authority observations | `semantic_observation` (added by 23.8) |
| `forensics/multitrack/historical-population.json` | the admitted / courted final-release records and their honest unavailability | `population_record` (added by 23.10) |
| `forensics/multitrack/downstream-multitrack.json` | the per-epoch unmodified downstream consumer results | `downstream_epoch` (added by 23.11) |
| `docs/PHASE-23-MULTITRACK-SEAL.md` | the seal | — |

23.0 invents none of these artefacts: it defines and self-tests the schemas the original
subphases will be validated against, and the runner records the schema inventory so the record
kinds are a file the evidence points at rather than prose. The five corrected subphases add the
record kinds their rows name to `forensics/tools/multitrack_schemas.py` in the commit that lands
each, exactly as §4.5 permits; a corrected subphase that finds a record kind needs a different
split records the correction in §4 and in the seal rather than folding it into this prose.

## 3. What each subphase must honour

**3.1 A compatibility claim is directional and dimension-specific, and it says so.** There is no
single "compatible" flag anywhere in the stratum. Every view and every edge names its `dimension`
and its `direction`, and a claim in one direction never implies the other (`docs/PARITY_MODEL.md`
§4). A subphase that is tempted to collapse a matrix cell to one boolean records the dimensions
rather than the boolean.

**3.2 The instrument-versus-property split keeps a pass from being read as the property.** A
passing court is an instrument: it ran and its control was honest. The property it names -- a fully
resolved compatibility view, a lineage with no unresolved entity -- is carried by
`property_status` and `findings`, and where the evidence falls short the unit reads `NOT_CLAIMED`
with the gap named. `docs/PARITY_MODEL.md` is the authority on what the labels mean, and a
subphase may not promote an instrument's pass into a property claim it did not measure.

**3.3 Cross-version receipts are never inherited.** A receipt, claim or court result compiled
against one authority or release is evidence about that authority and release and no other. A
view that cites a lineage edge must still carry the release-specific evidence it rests on; it
never inherits evidence across the edge (D533). The rule is the general form of
`docs/RELEASE_GATES.md` §8's "an OpenSSL 3 receipt is never silently reinterpreted as evidence for
OpenSSL 4".

**3.4 Authority selection is explicit and singular.** A view names the authority or release it is
about, and no Cargo feature and no build-time switch selects it (D534). One implementation crate,
one behaviour fixed by the source; the version dimension lives in evidence, not in the compiled
artefact's configuration.

**3.5 The records are read from the artefacts that carry them.** A release node's identity is read
from the source manifest and the upstream lineage, never typed; an authority node's hashes are
read from its build records, never typed; a delta is computed from the atlas and the entity
lineage, never hand-listed. The version parser establishes chronology and names the scheme, and it
does **not** derive compatibility from the order it computes.

**3.6 Negative obligations are first-class.** A surface that must not exist, must be opaque or
must not be exported is recorded as an obligation with a state and evidence, with the same standing
as a surface that must exist (D536). An obligation that cannot be adjudicated reads `unknown`
rather than satisfied.

**3.7 The security lineage observes, and never reintroduces.** Every historical vulnerability the
lineage records is an observation, and no view, edge or matrix cell may re-adopt the behaviour the
fixed release moved away from (`docs/SECURITY_DIVERGENCE_POLICY.md` §1 and §3). A row whose
disposition would reintroduce it is a `finding`, and the stratum fails rather than record it.

**3.8 The seventeen units land in one ordered chain behind the runner.** 23.1 through 23.16 land
the sixteen instruments; 23.17 lands the FRF/Gemel chain rule where the stratum stages a declarable
court and the seal that closes the matrix; each lands its code, its court and its regenerated
artefacts in one commit, and the ledger's `open_in_this_stratum` moves only when a court in
`artifacts/phase23/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase23-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `multitrack authority contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase
16's `cli-config contract` through Phase 21's `maintenance delta contract` are. The ledger fails
closed if the ownership atlas ever assigns this stratum an export, if the provider census assigns
it a registration row, or if the prerequisite plane assigns it a deferral or a translation unit,
because then the non-export unit would be the wrong shape.

**4.2 The precondition this plan places on 23.0, and it is not optional.** `run_courts.py` refuses
a stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase23_courts.py` with **no runnable court**: its obligations are not exports, so
no differential probe over a symbol set is its evidence, and its seventeen courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The direction
of the `phase23_courts.py` ↔ `phase23_obligations.py` edge is the reverse of Phase 16's**: the
ledger's contract-unit states are measured from the courts registry, so the registry is generated
first and `phase23_courts.py` does **not** bind the ledger as an input. A cycle in which each
embedded the other's digest would make neither reproducible. So the activation order is: the
runner and its pending registry, the ledger, the schemas and the plan land **together**, or
`run_courts.py` fails and the tree carries an activation whose runner is refused.

**4.3 A version order is not a compatibility claim, and the schemas refuse the substitution.**
The parser in `forensics/tools/multitrack_schemas.py` decodes both OpenSSL encodings -- the
pre-3.0 `MNNFFPPS` form behind `OPENSSL_VERSION_NUMBER` and the 3.0-plus
`MAJOR.MINOR.PATCH` form -- and orders the lineage correctly, including the letter releases
(`0.9.8` < `0.9.8zh`, `1.0.2` < `1.0.2u`). It exists so the lineage has a chronology and a named
scheme. It is explicitly **not** a compatibility function: `validate_compatibility_edge` rejects an
edge whose evidence kind is `version_order`, so ordering can never stand in for measurement
(D535, `docs/PARITY_MODEL.md` §4).

**4.4 The prerequisite and provider planes are not this stratum's universe, and the plan says
so.** No row of `forensics/prerequisites.json` and no row of
`forensics/atlas/provider-algorithms.json` is owned by phase 23, so this plan names no prerequisite
unit and no provider row for it and plan reconciliation has no unit of this stratum's to judge; a
subphase that discovers its unit is elsewhere records that rather than forcing a row (§0, §5).
The atlases are nevertheless *inputs*: the delta engine and the entity lineage read them.

**4.5 The seal will correct this plan if the record kinds differ.** Phases 16 through 21 activated
with their universe entirely authored. Phase 23 activates over record kinds it defines in 23.0 but
does not yet populate, so §1's measurement is a read of what exists and a design of what will. If
a subphase finds that a record kind the brief names is better split, or that a dimension it needs
is not in the schema, it records the correction here and in the seal rather than folding it into
the prose it corrects. The correction is checked by the subphase's court rather than asserted.

**4.6 A historical vulnerability is an observation, and the security lineage is the record.**
23.14's subject is the lineage's own security history: each observation names the release the
vulnerability affected, the release that fixed it and the evidence; the stratum records them so the
matrix can never re-adopt the fixed behaviour. This is the direction `docs/SECURITY_DIVERGENCE_POLICY.md`
§1 fixes, generalised from the 3.6.3-versus-3.6.4 delta Phase 21 computed to the whole lineage.

**4.7 The authority-node registry landed at `forensics/authority-nodes.json`, and the historical
venue is a separate pin.** Two corrections 23.2 records against this plan, each checked by its court
rather than asserted here.

* **The registry path.** §2's artefact table named `forensics/multitrack/authority-nodes.json`; it
  landed at `forensics/authority-nodes.json`, the same top-level placement 23.1's
  `forensics/release-catalog.json` uses, with the archaeology *inputs* under `forensics/multitrack/`.
  The artefact's record kind is unchanged (`authority_node`), so this is a path correction, not a
  record-kind split.
* **The build venue is separate, and one historical authority is real.** The forensic court image
  (`docker/openssl-rs-court.Dockerfile`) does not change. Historical acquisition and building run in
  `docker/openssl-rs-historical.Dockerfile` — a separately pinned Debian bullseye image with an older
  toolchain (GCC 10, Perl 5.32) than the court's (GCC 12, Perl 5.36) — driven by
  `docker/openssl-rs-historical.sh` under the same resource guard. The first historical authority is
  **OpenSSL 0.9.8zh**, acquired from the official release asset the catalogue's tag names, verified
  against the upstream-published SHA-256, and built (`linux-x86_64-historical-shared`, serial `make`,
  installed prefix) into a committed build receipt. The root release **0.9.1c** and **0.9.6m** are
  recorded **unavailable** in the registry's `unavailable` list because no upstream-published digest
  could be fetched for either; they are never nodes and never runtime-compatible. Nothing ancient
  was patched: 0.9.8zh's one internal symlink (`apps/md4.c`) is allowed by the acquisition extractor
  because it provably stays inside the tree, and the build runs in a copy so the pristine tree keeps
  the root hash its source manifest records.

**4.8 The stratum's first plan dropped five brief-required slices, and this reconciliation restores
them (measured).** The plan's first §2 table read the stratum into **twelve** units. The phase brief's
execution order (§52) requires **seventeen**: the same twelve and five more that the first draft
never numbered. A capability the brief requires must never be silently dropped, so this correction
is made by measurement -- the brief's slice list against the ledger's unit set and the runner's
registry -- and not by preference. The five restored slices are:

  * **23.3 parameterize the atlases** (brief §52 23.3, §8) -- one parameterized archaeology generator
    rather than a `phase1_old.py` per version, with the current 3.6.4 atlas proved byte-identical;
    the repository had put `lineage-edges` at 23.3.
  * **23.7 ABI / history façades** (brief §52 23.7, §18/§19/§21/§22) -- the historical public-layout
    `#[repr(C)]` façades, prototype wrappers, initialization/threading epochs and the
    ENGINE -> Provider -> no-ENGINE model, as narrow adapters over the shared implementation; the
    repository had put `directional-compatibility-edges` at 23.7.
  * **23.8 semantic multitrack courts** (brief §52 23.8, §12) -- oracle-to-oracle and
    candidate-to-authority courts over a shared normalized observation vocabulary; the repository had
    put `negative-obligations` at 23.8.
  * **23.10 historical population** (brief §52 23.10, §31) -- the systematic admission and courting of
    the public final-release lineage forward from the first release, with honest unavailability; the
    repository had put `support-status` at 23.10.
  * **23.11 downstream multitrack court** (brief §52 23.11, §34) -- at least one meaningful unmodified
    real downstream consumer per major compatibility epoch; the repository had put
    `compatibility-matrix` at 23.11.

The correction keeps `release-nodes` (23.1) and `authority-nodes` (23.2) exactly where they were and
renumbers only phase 23's own remaining capabilities: `lineage-edges` 23.3 -> 23.4, `entity-lineage`
23.4 -> 23.5, `delta-engine` 23.5 -> 23.6, `compatibility-views` 23.6 -> 23.9,
`directional-compatibility-edges` 23.7 -> 23.12, `negative-obligations` 23.8 -> 23.13,
`security-lineage` 23.9 -> 23.14, `support-status` 23.10 -> 23.15, `compatibility-matrix`
23.11 -> 23.16 and `multitrack-seal` 23.12 -> 23.17. The brief's slice numbers and the
repository's subphase numbers now coincide; they did not before, and the `what changed` column of
§2's brief-slice map is the record. No phase outside 23 is renumbered, and the corrected unit set is
seventeen units with `release-nodes` and `authority-nodes` implemented, `open_in_this_stratum`
fifteen, and fifteen `pending` courts. The correction is recorded in `docs/DECISIONS.md` D537 and is
checked by the ledger (which counts the seventeen units) and the runner (whose registry names a
court and a landing subphase for each), not asserted here.

**4.9 The delta engine corrects the record in three measured ways (23.6, D539).** Three corrections
23.6 records against this plan, each checked by its court rather than asserted here.

* **The delta's dimension is two-layered, and the schema's closed vocabulary is unchanged.** The
  brief's delta dimensions are finer than the schema's compatibility vocabulary. Rather than widen
  `multitrack_schemas.COMPAT_DIMENSIONS` -- which the views, edges and matrix also read -- a *row*
  names a fine dimension (`DELTA_DIMENSIONS` in `forensics/tools/authority_delta.py`:
  `api_presence`, `macro_value`, `public_layout`, `abi_symbol_version`, `deprecation_state`, ...)
  and a *receipt* names the coarse dimension the fine one maps onto (`source_api`, `abi`, `...`).
  Every receipt is still a `delta_receipt` validated against the schema's `COMPAT_DIMENSIONS`, so
  no record kind or validator changed; the fine vocabulary lives with the engine and the court, not
  in the schema. A dimension the evidence cannot support is recorded in `absent_dimensions` with
  its reason, never asserted.
* **The canonical delta is stored on the release-graph edge, not at the plan's aggregate path.**
  §2's artefact table named `forensics/multitrack/delta-receipts.json`; 23.6 lands one file per
  canonical lineage edge at `forensics/deltas/<from_release>--<to_release>.json`, each body carrying
  its `delta_receipt` rows. A longer path is **composed** from the edge deltas it traverses
  (`authority_delta compose`), and an edge whose pair is not covered is recorded as a gap rather
  than recomputed, so no pairwise product is committed (the brief §11 rule). The record kind is
  unchanged (`delta_receipt`), so this is a path and granularity correction, not a record-kind
  split.
* **One observable the brief's list does not name is recorded, with its provenance and its
  adjudication.** An exported symbol's ELF symbol-table size (`st_size`) changes across the covered
  pair without the symbol's presence, version node or prototype changing. It is recorded as the
  `abi_symbol_presence` row's `st_size` facet, with the adjudication that it is an
  implementation-size observation and **not an ABI contract change**, so the movement 23.5 records
  as evidence is visible in the delta without being read as a compatibility obligation.

The measured 3.6.3 -> 3.6.4 delta is: two macros added (`api_presence`), five version-stamp macros
changed (`macro_value`) and twenty exported symbols whose machine-code size changed
(`abi_symbol_presence`, `st_size`); every other measured dimension is present and unchanged, and
nine dimensions the committed atlases carry no structured evidence for are recorded absent with
their reason.

**4.10 The ABI/history façades establish one small historical generation, and name the boundary
(23.7, D540).** 23.7 lands the compatibility-policy layer as `src/compat/` and the historical
façade plane as `forensics/multitrack/abi-facades.json` (record kind `abi_facade`, added to
`forensics/tools/multitrack_schemas.py`), and its court `RT-ABI-HISTORY-FACADES` checks it against
the authority's own evidence rather than restating it. Four measured corrections:

* **The generation proved is 0.9.8zh, and the 1.0.x epoch is recorded not established.** The
  façade layouts are measured by compiling a probe against the acquired 0.9.8zh release's own
  configured headers in the historical venue (`gen_abi_facades.py --measure`), and each record
  cites its header and that header's SHA-256 in the committed `SOURCE_MANIFEST.0.9.8zh.json`. No
  1.0.x authority is admitted with an acquired source tree in this subphase, so the 1.0.x layouts
  and the pre-1.1.0 aggregates the subphase does not name (`BIO`, `RSA`, `X509`, `SSL`, ...) are
  recorded in the plane's `not_established` with their reason rather than inferred from a sibling.
  The court fails if the boundary is not named.
* **The public-layout façade is the pre-1.1.0 side of a real opacity transition.** In 0.9.8zh
  `struct env_md_ctx_st` and `struct hmac_ctx_st` are defined in full in installed headers; in the
  3.6.4 production authority both are opaque (`complete: false`, forward-declared in `types.h`).
  The court requires the production authority to mark each façade's canonical tag opaque, and
  records the cross-era tag rename (`env_md_ctx_st` in 0.9.8zh, `evp_md_ctx_st` from 1.1.0).
  `HMAC_CTX` embeds three `EVP_MD_CTX` by value at 0.9.8zh — which is exactly why a blind cast of
  the old representation to the canonical `EvpMdCtx`/`HmacCtx` is impossible, and why the adapters
  are explicit field copies.
* **The prototype wrappers are the era-specific declaration, not a per-version fork.** A C symbol
  has no runtime signature, so the same exported name carries a different declaration across eras
  (`HMAC_Init_ex`/`HMAC_Update`/`HMAC_Final` return `void` in 0.9.8zh and `int` from 1.1.0;
  `EVP_MD_CTX_init`/`_create`/`_destroy` are functions in 0.9.8zh and macros in 3.6.4;
  `CRYPTO_set_locking_callback` is a function in 0.9.8zh and a no-op macro in 3.6.4). Each record
  names both declarations and the safe wrapper over the shared implementation; the court requires
  the eras to differ and the canonical declaration to be the production atlas's own. The
  ENGINE -> Provider -> no-ENGINE architecture and the init/thread epochs (explicit global init and
  application locking callbacks for 0.9.8zh; automatic init, `OPENSSL_cleanup` and internal thread
  support for 3.6.4) are cross-checked against the historical plane census and the production
  atlas.
* **The compatibility selection is a build parameter, and the default compiles no façade.**
  `build.rs` reads `OPENSSL_RS_COMPAT`, resolves an unset value through the committed alias
  `forensics/multitrack/default-authority.json` (never the catalogue's newest release), refuses any
  other value, and sets the `openssl_rs_compat_facades` cfg only for the historical selection. So
  the default 3.6.4 production candidate compiles none of the façades, and there is no Cargo feature
  per authority (D534). The court re-derives the generated `src/compat/layout_generated.rs` — the
  `#[repr(C)]` structs and their compile-time `sizeof`/`alignof`/`offsetof`/field-width assertions —
  from the committed measurement and fails if it drifts, and it checks that every façade module is
  cfg-gated behind the non-default selection.

**4.11 The semantic courts read two authorities through one vocabulary, and the adapter never erases
a difference (23.8, D541).** 23.8 lands the oracle-to-oracle and candidate-to-authority courts as
`courts/phase23/semantic_probe.c`, the plane `forensics/multitrack/semantic-courts.json` (record kind
`semantic_observation`, added to `forensics/tools/multitrack_schemas.py`), the generator
`forensics/tools/gen_semantic_courts.py` and the court `RT-SEMANTIC-COURTS`. Four measured
corrections, each checked by the court rather than asserted here.

* **The runnable pair is 3.6.3 vs 3.6.4, and the raw transcripts are part of the artefact.** Both
authorities are built in the forensic court venue, so the same probe source is compiled once against
each prefix and run; both raw transcripts (stdout, stderr and exit) are preserved in the artefact,
and the default (court and `regen_all.sh`) run re-derives every normalized observation from *those
bytes* through the same adapter. The measured movement is **ten classified differences over twenty
observations**: seven `release_identity` version-stamp readings, two `declaration_added`
declarations (`SSL_VALUE_QUIC_MAX_PENDING_CONNS`, `X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH`) and one
`declaration_added` error-reason reading. Ten observations agree, including the four exported
symbols whose machine-code size the 23.6 engine records changed (`OSSL_parse_url`, `BN_uadd`,
`BN_ucmp`, `OPENSSL_uni2utf8`), whose behaviour agrees and so corroborates the engine's
implementation-size adjudication.
* **Where a declaration differs incompatibly the probe carries a side-specific adapter, and every
side emits the same vocabulary.** `SSL_VALUE_QUIC_MAX_PENDING_CONNS` and
`X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH` are public in 3.6.4 and absent from 3.6.3, so an access
would not compile on the older side; the `#ifdef` adapter emits the same `OBS <key>=<value>` key on
both sides -- the value on the side that declares it, the literal `<absent>` on the side that does
not -- so the difference is preserved in the vocabulary rather than erased by it. The court
re-derives the observations from the raw bytes and refuses an adapter that maps a raw difference to
agreement.
* **Every difference is fed to the 23.6 delta engine where the engine carries the entity, and one
reading fills a dimension the engine records absent.** A classified difference names the fine delta
dimension and the entity id the engine keys its row by, and the court requires the row to resolve in
the committed `forensics/deltas/openssl-3.6.3--openssl-3.6.4.json`; the `error.reason.*` readings
name `error_behavior`, which the engine records in `absent_dimensions` for want of a committed
per-authority plane, so 23.8 supplies the behavioural reading rather than restating a source claim.
* **The candidate-to-authority dimension is discharged by the existing courts, not duplicated, and
a pair the venue cannot run is recorded not-run.** The plane names the Phase-2 ABI family
(`ABI-CONSTANTS`, `ABI-MATRIX`, `ABI-SUBSTITUTION`, `ABI-LINK`, `ABI-LOAD`, `ABI-LAYOUT`,
`ABI-SYMBOL`) and the Phase-17 runtime family (`RT-TLS13-INTEROP`, `RT-CLI-BODIES`,
`RT-CROSS-DSO-STATE`, `RT-DOWNSTREAM-CONSUMER`), and the court verifies each is registered and
passing rather than taking the statement on trust; what 23.8 adds is the shared vocabulary so the
candidate and the oracle are read the same way. The 0.9.8zh epoch lives in the separately pinned
historical venue (`docs/REPRODUCIBILITY.md` sections 1.1 and 1.2), so both 0.9.8zh pairs are
recorded `not_run` with that reason and are never counted as passing.

## 5. Process

This stratum inherits Phases 8 through 21's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the seventeen-unit measurement in §1. A subphase that discovers its unit
is elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-23-MULTITRACK-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the seventeen multitrack authority
contract units, recorded in the ledger's contract-unit block rather than as open exports.
