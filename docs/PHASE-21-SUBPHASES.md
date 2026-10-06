# Phase 21 — the maintenance delta machinery stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 21 is the stratum `docs/RELEASE_GATES.md` §1 names "Maintenance delta machinery", the
machinery §8's "Future version policy" requires:

```
admit new authority -> regenerate atlas -> oracle/oracle differential
-> identify added/removed/changed obligations -> implement delta
-> re-run affected courts -> re-run selected global downstream courts
-> emit new receipts
```

Like Phases 16 through 20 it owns **no exported symbol**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 21` yields nothing, because the
declaring-header rule assigns no installed header to this stratum. Its unit is therefore not a
symbol. As with Phases 18, 19 and 20 it **hands nothing forward and receives nothing**: the two
authorities whose delta it computes are already admitted, their differential is already committed,
and the implementation it re-measures is the one Phases 3 through 20 completed, so it adds no
library surface and takes no unit or symbol deferral from an earlier stratum.

What it owes is the **delta procedure itself**, made mechanical over the two authorities that are
already on disk -- `openssl-3.6.3-historical` and `openssl-3.6.4-production`
(`forensics/authorities/AUTHORITIES.json`, `docs/AUTHORITY_POLICY.md` §1) -- and over the
`forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json`
differential `forensics/tools/atlas_differential.py` already produces. The five things it must
produce, and the plan's subphases below are these:

* an **authority admission**: the identity and profile of the delta's *from* and *to* authorities,
  recorded as the delta's input pair, so the delta is always a statement about two named,
  content-addressed builds rather than about "the new version";
* an **atlas delta**: the added / removed / changed obligations between the two authorities,
  computed across the atlas planes the delta procedure names -- exports
  (`forensics/atlas/symbol-ownership.json`'s source, the per-authority symbol atlases), provider
  registration rows (`forensics/atlas/provider-algorithms.json`) and prerequisite units
  (`forensics/prerequisites.json`) -- mechanically from committed artefacts, never hand-listed;
* a **delta disposition**: every delta row dispositioned (`implemented` / `deferred` /
  `not-in-profile` / `boundary`), with **zero unexplained** rows, so a newly discovered
  un-dispositioned delta row is a `fail` rather than a silent addition;
* an **affected-court selection**: the derivation of which courts a delta touches, recorded with
  the selection derivation, so a delta re-runs or re-derives exactly the courts its obligations
  reach and no more;
* the **maintenance-boundary register**, recording the explicit non-claims -- OpenSSL 4.x is a new
  compatibility profile and a 3.x receipt is **never** silently reinterpreted as evidence for 4
  (`docs/RELEASE_GATES.md` §8, `docs/NON_CLAIMS.md` §3's "No version universality"), only the
  exercised delta is claimed, and unknown stays unknown (`docs/PARITY_MODEL.md` §1).

It is **not** a new implementation and it is **not** a stronger parity claim than the evidence
supports. A passing delta court is an **instrument**, not a property: it ran and its control was
honest, and the property it measures may still carry findings. Three non-claims are named here and
belong to every subphase: **no version universality** (a 3.x receipt is not evidence for OpenSSL
4.x; `docs/NON_CLAIMS.md` §3 and `docs/RELEASE_GATES.md` §8), **only the exercised delta is
claimed** (a delta court measures the movement between the two authorities it names, not the
absence of movement elsewhere), and **unknown stays unknown** (`docs/PARITY_MODEL.md` §1; a delta
row that is not dispositioned is `UNKNOWN`, a research result, never a resting state). A 3.6.3
behaviour that corresponds to an upstream security fix is **not** reintroduced
(`docs/SECURITY_DIVERGENCE_POLICY.md` §1 and §3): the differential's `added`/`changed` rows are the
places where the fixed authority moved, and the delta implementation follows the fixed authority,
never the historical one. `docs/NON_CLAIMS.md`, `docs/AUTHORITY_POLICY.md` and
`docs/PARITY_MODEL.md` are the authorities on what may be said; a subphase that discovers its unit
is somewhere else records that rather than forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase21-obligations.json` is
authoritative for the present. The activation measurement was taken against `main` `ce63f41e`
(openssl-rs 0.0.25, Phase 20 released).

**Phase 21 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for `owner_phase ==
21` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger fails closed if that
ever stops being true rather than silently counting a symbol through a non-export unit.

**It receives zero provider registration rows.** Reading `forensics/atlas/provider-algorithms.json`
for `owning_phase == 21` gives no row: this stratum activates no provider. The ledger fails closed if
the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading `forensics/prerequisites.json`
for `owner_phase == 21`: no `deferrals` row and no `units` row. The plane's records and deferrals are
all owned by earlier strata, and the `forensics/phase*-obligations.json` files record no hand-off
owned by phase 21, so its working set is entirely its own authored contract.

**The maintenance delta contract is five units**, each derived from the court that measures it:
`authority-admission` (`RT-AUTHORITY-ADMISSION`), `atlas-delta` (`RT-ATLAS-DELTA`),
`delta-disposition` (`RT-DELTA-DISPOSITION`), `affected-court-selection`
(`RT-AFFECTED-COURT-SELECTION`) and `maintenance-boundary-register`
(`MAINTENANCE-BOUNDARY-REGISTER`). At activation the runner registers all five as `pending`, so all
five units are open.

**The two authorities and their differential already exist, and the plan reuses them.** The admitted
pair is `openssl-3.6.3-historical` → `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`;
`docs/AUTHORITY_POLICY.md` §1), and the committed differential
`forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json` records the
movement `forensics/tools/atlas_differential.py` computes. On the current tree that movement is
**total 2**: `symbol_movement` 0, `declared_declaration_movement` 2 (the two macros
`SSL_VALUE_QUIC_MAX_PENDING_CONNS` and `X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH`, both added in
3.6.4), `abi_layout_movement` 0, `provider_algorithm_movement` 0 and `cli_movement` 0. The two
`SOURCE_MANIFEST.{3.6.3,3.6.4}.json` files under `forensics/authorities/` are the per-file source
identity the admission court reads, and `docs/SECURITY_DIVERGENCE_POLICY.md` §1 is why the delta runs
from the historical authority **to** the fixed one and never the reverse. 21.0 invents none of this:
it names the inputs the existing tools and registries already committed.

**A passing delta court is an instrument, not a property claim, and the ledger records the two axes
separately.** Each contract unit carries `measurement_state` (the instrument ran and its control was
honest) beside `property_status` and `findings` (what, if anything, the unit claims about the delta).
`delta-disposition` is the unit where the two diverge: `RT-DELTA-DISPOSITION` passes as an instrument
while recording, as `findings`, every delta row it could not disposition, so the property reads
`NOT_CLAIMED` with `findings_present`. **A passing `RT-DELTA-DISPOSITION` must never be read as
"the delta is implemented".** The findings are read from the court row rather than typed, and
`forensics/phase21-obligations.json` carries both axes for every unit.

**The ledger's unit is not an exported symbol.** `forensics/phase21-obligations.json` publishes
`unit: "maintenance delta contract"`, its `implemented`/`open` export lists are empty *by
measurement*, and its working set is counted in `open_in_this_stratum` over the five contract units.
`atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that partition the export universe
(`court_coverage.py`, `ownership_audit.py`) skip this ledger rather than reconcile a symbol set that
does not exist.

**Phase 21 begins on nothing of its own.** No delta court exists at activation, so
`open_in_this_stratum` opens at the whole working set (five) and moves only as the subphases below
land. **That split moves as the stratum lands its own units: the ledger's `counts` is the live record
and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 21.0 | **The plan, the ledger and the runner** | `docs/PHASE-21-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase21-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase21_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 20 | — |
| 21.1 | **The authority-admission court** | the admission / identification of a new authority and the record of its identity and profile as the delta input pair, exercised on the already-admitted `openssl-3.6.3-historical` versus `openssl-3.6.4-production`. | 21.0 | `RT-AUTHORITY-ADMISSION` |
| 21.2 | **The atlas-delta court** | the added / removed / changed obligation delta between the two authorities, computed across the atlas planes the procedure names -- exports, provider registration rows and prerequisite units -- mechanically from committed artefacts, never hand-listed. | 21.0 | `RT-ATLAS-DELTA` |
| 21.3 | **The delta-disposition court** | the disposition of every delta row (`implemented` / `deferred` / `not-in-profile` / `boundary`), requiring zero unexplained, so a newly discovered un-dispositioned delta row is a `fail` rather than a silent addition. | 21.0 | `RT-DELTA-DISPOSITION` |
| 21.4 | **The affected-court selection** | the derivation of which courts a delta touches, recorded with the selection derivation, so the selected courts are re-run or re-derived and a delta reaches exactly the courts its obligations do. | 21.0 | `RT-AFFECTED-COURT-SELECTION` |
| 21.5 | **The maintenance-boundary register** | the register that records the explicit non-claims -- OpenSSL 4.x is a new compatibility profile and a 3.x receipt is never silently reinterpreted as evidence for 4, only the exercised delta is claimed, unknown stays unknown -- and that fails the stratum if a recorded boundary drifts from its evidence. | 21.1–21.4 | `MAINTENANCE-BOUNDARY-REGISTER` |
| 21.6 | **The seal** | nothing in the crate — evidence: `docs/PHASE-21-MAINTENANCE-SEAL.md` (at the seal) | 21.0–21.5 | — |

The rows above the seal partition the working set by source: each subphase row lands the instrument
for exactly one of the five contract units. The partition is derived from
`forensics/phase21-obligations.json` joined to `artifacts/phase21/COURTS.json`, not typed.

## 3. What each subphase must honour

**3.1 A delta court is bounded to its measured surfaces, and it says so.** A passing
`RT-ATLAS-DELTA` says the comparison ran over the planes and the two authority identities it names
and produced the delta it recorded, not that every obligation moving anywhere is known. The surfaces
a court names, the artefacts it reads and the claim it binds are recorded in the court's row, and a
surface the court does not reach is named `pending` rather than counted as passing (§3.7).

**3.2 The instrument-versus-property split keeps a pass from being read as the property.** A passing
court is an instrument: it ran and its control was honest. The property it names -- a fully
dispositioned delta, an admission that establishes an authority -- is carried by `property_status`
and `findings`, and where the evidence falls short the unit reads `NOT_CLAIMED` with the gap named,
exactly as Phase 20's `custodian-maturity` does. `docs/PARITY_MODEL.md` is the authority on what the
labels mean, and a subphase may not promote an instrument's pass into a property claim it did not
measure.

**3.3 The delta is computed, never named ahead of its evidence.** `RT-ATLAS-DELTA` reads the
`added` / `removed` / `changed` sets from the committed differential and the per-authority atlases
and records what they hold; it does not maintain a hand-written list of "what changed in 3.6.4".
Where a plane's movement is not computed -- because the tool that would compute it is not yet a
delta input -- the plane is named `not-measured` rather than counted as motionless.

**3.4 The identities and the differential are read from the artefacts that carry them.**
`RT-AUTHORITY-ADMISSION` reads `forensics/authorities/AUTHORITIES.json` and the two
`SOURCE_MANIFEST.{3.6.3,3.6.4}.json` files; it does not type a version, a checksum or a root hash.
`RT-ATLAS-DELTA` reads the differential `forensics/tools/atlas_differential.py` writes and the
per-authority atlases; the two cannot disagree with the evidence, and a differential that no longer
matches its authorities is visible as a `fail`.

**3.5 The security direction is fixed, and the delta follows the fixed authority.**
`docs/SECURITY_DIVERGENCE_POLICY.md` §1 and §3 require the trajectory to run from
`openssl-3.6.3-historical` to `openssl-3.6.4-production` and a 3.6.3 behaviour that corresponds to an
upstream security fix to be **not** reintroduced. A delta row whose disposition would re-adopt the
historical behaviour against a security fix is a `finding`, and the disposition vocabulary has no
value that reintroduces it.

**3.6 The register is the stratum's own non-claims, and it is mechanical.** 21.5 records, per
surface, whether it is *claimed* (a passing court covers it) or *bounded* (explicitly outside this
stratum -- including **version universality**, **only the exercised delta is claimed** and
**unknown stays unknown**), and the `MAINTENANCE-BOUNDARY-REGISTER` court fails the stratum if a
recorded boundary drifts from the evidence that establishes it. It is the stratum's answer to
`docs/NON_CLAIMS.md`, and it may not claim more than the courts above measured.

**3.7 The five units land in one ordered chain behind the runner.** 21.1 through 21.4 land the four
delta courts; 21.5 lands the register that binds them; each lands its code, its court and its
regenerated artefacts in one commit, and the ledger's `open_in_this_stratum` moves only when a court
in `artifacts/phase21/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase21-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `maintenance delta contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase 16's
`cli-config contract`, Phase 17's `downstream replacement contract`, Phase 18's `hostile hardening
contract`, Phase 19's `performance dispatch contract` and Phase 20's `custodian seal contract` are
(D485). The ledger fails closed if the ownership atlas ever assigns this stratum an export, if the
provider census assigns it a registration row, or if the prerequisite plane assigns it a deferral or
a translation unit, because then the non-export unit would be the wrong shape.

**4.2 The precondition this plan places on 21.0, and it is not optional.** `run_courts.py` refuses a
stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase21_courts.py` with **no runnable court**: its obligations are not exports, so
no differential probe over a symbol set is its evidence, and its five courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The direction
of the `phase21_courts.py` ↔ `phase21_obligations.py` edge is the reverse of Phase 16's**: the
ledger's contract-unit states are measured from the courts registry, so the registry is generated
first and `phase21_courts.py` does **not** bind the ledger as an input. A cycle in which each
embedded the other's digest would make neither reproducible. So the activation order is: the runner
and its pending registry, the ledger, and the plan land **together**, or `run_courts.py` fails and
the tree carries an activation whose runner is refused.

**4.3 A maintenance delta is bounded evidence, not a version-universality claim.** The delta procedure
of `docs/RELEASE_GATES.md` §8 is the maintenance path *within a compatibility profile*; 21.5's
register records that OpenSSL 4.x is a **new compatibility profile** and that a 3.x receipt is never
silently reinterpreted as evidence for 4. The delta this stratum can carry is exactly the movement
between the two authorities it names, and no more. "Only the exercised delta is claimed" and
"unknown stays unknown" are the other two load-bearing non-claims of §0, and a passing court does
not widen them.

**4.4 The prerequisite plane is not this stratum's universe, and the plan says so.** No row of
`forensics/prerequisites.json` is owned by phase 21, so this plan names no prerequisite unit and
plan reconciliation has no unit of this stratum's to judge; a subphase that discovers its unit is
elsewhere records that rather than forcing a row (§0, §5). The plane is nevertheless one of the
delta's *inputs*: `RT-ATLAS-DELTA` reads its rows to compute the delta, even though phase 21 owns
none of them.

**4.5 This plan is the first whose inputs already exist, and the seal will correct it if their shape
differs.** Phases 16 through 20 activated with their universe entirely authored. Phase 21 activates
over real, already-committed inputs -- two admitted authorities, their differential, and the source
manifests -- so the measurement in §1 is a read of those artefacts, not a promise about them. If a
subphase finds that a plane the procedure names has no committed delta tool (for instance the
provider-row and prerequisite-unit planes, which `atlas_differential.py` does not yet compare), it
records that as a `not-measured` surface with its reason rather than counting it as motionless, and
the correction is recorded here and in the seal rather than folded into the prose it corrects.

## 5. Process

This stratum inherits Phases 8 through 20's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the five-row measurement in §1. A subphase that discovers its unit is
elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-21-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the five maintenance delta contract units,
recorded in the ledger's contract-unit block rather than as open exports.
