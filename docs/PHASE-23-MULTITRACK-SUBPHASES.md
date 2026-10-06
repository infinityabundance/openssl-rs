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

**The multitrack authority contract is twelve units**, each derived from the court that measures
it: `release-nodes`, `authority-nodes`, `lineage-edges`, `entity-lineage`, `delta-engine`,
`compatibility-views`, `directional-compatibility-edges`, `negative-obligations`,
`security-lineage`, `support-status`, `compatibility-matrix` and `multitrack-seal`. At activation
the runner registers none of them: its registry is empty, its twelve courts are `pending`, and all
twelve units are open, so `open_in_this_stratum` opens at the whole working set (twelve).

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

**Phase 23 begins on nothing of its own.** No multitrack court exists at activation, so
`open_in_this_stratum` opens at the whole working set (twelve) and moves only as the subphases
below land. **That split moves as the stratum lands its own units: the ledger's `counts` is the
live record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 23.0 | **The plan, the schemas, the ledger and the runner** | `docs/PHASE-23-MULTITRACK-SUBPHASES.md`, `forensics/tools/multitrack_schemas.py` and the measurement in §1. The ledger (`forensics/phase23-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase23_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 21 | — |
| 23.1 | **The release-node catalogue** | one release node per upstream release, from OpenSSL 0.9.1c forward, read from the committed source manifests and the upstream lineage rather than typed, with the version parser and scheme model in `forensics/tools/multitrack_schemas.py`. | 23.0 | `RT-RELEASE-NODES` |
| 23.2 | **The authority-node registry** | one authority node per built authority, over the releases an authority has been admitted for, recording platform, arch, build profile, toolchain, build environment and binary/installed hashes. | 23.1 | `RT-AUTHORITY-NODES` |
| 23.3 | **The lineage edges** | the typed chronological / git-ancestry / branch-fork / maintenance-successor / security-backport edges between release nodes, each stating the direction it is read in. | 23.1 | `RT-LINEAGE-EDGES` |
| 23.4 | **The entity lineage** | what became of each public entity across releases, with the relation vocabulary of §0 and `unknown_relationship` where the evidence does not settle it. | 23.1, 23.3 | `RT-ENTITY-LINEAGE` |
| 23.5 | **The delta engine** | the added / removed / changed surface between two nodes, computed mechanically from the atlas and the entity lineage, never hand-listed, in the direction the lineage edge names. | 23.3, 23.4 | `RT-DELTA-ENGINE` |
| 23.6 | **The compatibility views** | a directional, dimension-specific view per support status, each naming its reference release, its dimension and the release-specific evidence it was derived from -- never a boolean, and never inheriting a receipt across a version. | 23.5 | `RT-COMPATIBILITY-VIEWS` |
| 23.7 | **The directional compatibility edges** | the directional compatibility edges between releases or authorities on one dimension each, with an evidence kind that is never numeric ordering. | 23.6 | `RT-COMPATIBILITY-EDGES` |
| 23.8 | **The negative obligations** | the `must_not_exist` / `must_be_opaque` / `must_not_be_exported` obligations (beside the positive `must_exist` / `must_be_public` / `must_be_exported`), each with evidence and a state, so an absence is a checkable claim rather than an omission. | 23.1 | `RT-NEGATIVE-OBLIGATIONS` |
| 23.9 | **The security lineage** | the historical vulnerabilities of the lineage, observed and never reintroduced, with the observation and the non-reintroduction each recorded so a view can never re-adopt a fixed behaviour. | 23.3, 23.6 | `RT-SECURITY-LINEAGE` |
| 23.10 | **The support-status ladder** | the derived support status of each release node, over `catalogued`, `admitted-source`, `built-authority`, `atlas-complete`, `candidate-view`, `runtime-evidenced`, `downstream-evidenced` and `maintained`, with `archaeological-only` where the node is studied and not supported. | 23.1, 23.2 | `RT-SUPPORT-STATUS` |
| 23.11 | **The compatibility matrix** | the assembled matrix that joins the views, the edges, the negative obligations and the security lineage over the lineage, with every cell a directional, dimension-specific record and no cell a single boolean. | 23.1–23.10 | `RT-COMPATIBILITY-MATRIX` |
| 23.12 | **The full matrix, the FRF/Gemel chain and the seal** | the closure of the matrix as the stratum's claim, the FRF/Gemel chain rule where the stratum stages a declarable court, and the seal. Evidence: `docs/PHASE-23-MULTITRACK-SEAL.md` (at the seal). | 23.0–23.11 | `MULTITRACK-SEAL` |

The rows above the seal partition the working set by source: each subphase row lands the instrument
for exactly one of the twelve contract units. The partition is derived from
`forensics/phase23-obligations.json` joined to `artifacts/phase23/COURTS.json`, not typed.

**The evidence artefacts this stratum produces (§38 of the brief).** The later subphases populate
the **multitrack evidence plane**, each artefact validated against a record kind in
`forensics/tools/multitrack_schemas.py`:

| artefact | record kind | schema |
|---|---|---|
| `forensics/multitrack/release-nodes.json` | release nodes | `release_node` |
| `forensics/multitrack/authority-nodes.json` | authority nodes | `authority_node` |
| `forensics/multitrack/lineage-edges.json` | lineage edges | `lineage_edge` |
| `forensics/multitrack/entity-lineage.json` | entity lineage | `entity_lineage` |
| `forensics/multitrack/delta-receipts.json` | delta-engine records | `delta_receipt` |
| `forensics/multitrack/compatibility-views.json` | compatibility views | `compatibility_view` |
| `forensics/multitrack/compatibility-edges.json` | directional compatibility edges | `compatibility_edge` |
| `forensics/multitrack/negative-obligations.json` | negative obligations | `negative_obligation` |
| `forensics/multitrack/security-lineage.json` | security-lineage observations | `security_observation` |
| `forensics/multitrack/support-status.json` | support-status rows | `support_status` |
| `forensics/multitrack/compatibility-matrix.json` | the assembled matrix | `compatibility_matrix` |
| `docs/PHASE-23-MULTITRACK-SEAL.md` | the seal | — |

23.0 invents none of these artefacts: it defines and self-tests the schemas they will be validated
against, and the runner records the schema inventory so the record kinds are a file the evidence
points at rather than prose.

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

**3.8 The twelve units land in one ordered chain behind the runner.** 23.1 through 23.11 land the
eleven instruments; 23.12 lands the FRF/Gemel chain rule where the stratum stages a declarable
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
no differential probe over a symbol set is its evidence, and its twelve courts are named in
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
23.9's subject is the lineage's own security history: each observation names the release the
vulnerability affected, the release that fixed it and the evidence; the stratum records them so the
matrix can never re-adopt the fixed behaviour. This is the direction `docs/SECURITY_DIVERGENCE_POLICY.md`
§1 fixes, generalised from the 3.6.3-versus-3.6.4 delta Phase 21 computed to the whole lineage.

## 5. Process

This stratum inherits Phases 8 through 21's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the twelve-unit measurement in §1. A subphase that discovers its unit
is elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-23-MULTITRACK-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the twelve multitrack authority contract
units, recorded in the ledger's contract-unit block rather than as open exports.
