# Phase 20 — the 3.6.4 custodian seal stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 20 is the stratum `docs/RELEASE_GATES.md` §1 names "3.6.4 custodian seal", whose maturity
level §3 names **L9 high-assurance custodian seal**. Like Phases 16 through 19 it owns **no exported
symbol**: reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 20` yields nothing,
because the declaring-header rule assigns no installed header to this stratum. Its unit is therefore
not a symbol. As with Phases 18 and 19 it **hands nothing forward and receives nothing**: the
implementation whose claim it compiles is the one Phases 3 through 19 completed, so it adds no
library surface and takes no unit or symbol deferral from an earlier stratum.

What it owes is the **custodian claim**, compiled from immutable receipts over the finished
implementation, and that claim is the bounded one `docs/CUSTODIAN_CONTRACT.md` §6 and §9 and
`docs/RELEASE_GATES.md` §2 and §9 license. The five things it must produce, and the plan's subphases
below are these:

* a **maturity derivation**: the L0–L9 ladder of `docs/RELEASE_GATES.md` §3 derived for `libcrypto`
  and `libssl` from committed evidence, so the seal may not name a level whose evidence is absent;
* a **receipt closure**: every obligation recorded `implemented` or closed joined to its FRF
  receipt, and the FRF store compiling the parity claim with zero blockers;
* a **residual disposition**: every residual dispositioned, with zero `UNKNOWN` intersecting the
  claimed production profile, so a newly discovered un-dispositioned residual fails the court;
* a **substitution witness**: the ABI-substitution witness chain and the machine-owned downstream
  corpus witness chain — binaries built against the admitted authority running unmodified against
  the candidate, over the Phase-17 corpus the court re-establishes as current and functional;
* the **custodian-boundary register**, recording what is claimed, what is bounded, and the explicit
  non-claims.

It is **not** a new implementation and it is **not** a stronger parity claim than the evidence
supports. A passing custodian court is an **instrument**, not a property: it ran and its control was
honest, and the property it measures may still carry findings. Three non-claims are named here and
belong to every subphase: **no FIPS validation** (`docs/FIPS_CLAIMS.md` and `docs/NON_CLAIMS.md`
§3), **no universal parity from finite evidence** (`docs/NON_CLAIMS.md` §1), and **memory safety
measured, not established** (`docs/UNSAFE.md`). `docs/NON_CLAIMS.md` and `docs/CUSTODIAN_CONTRACT.md`
are the authorities on what may be said; a subphase that discovers its unit is somewhere else records
that rather than forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase20-obligations.json` is
authoritative for the present. The activation measurement was taken against `main` `e0a7eba4`
(openssl-rs 0.0.24, Phase 19 released).

**Phase 20 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for `owner_phase ==
20` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger fails closed if that
ever stops being true rather than silently counting a symbol through a non-export unit.

**It receives zero provider registration rows.** Reading `forensics/atlas/provider-algorithms.json`
for `owning_phase == 20` gives no row: this stratum activates no provider. The ledger fails closed if
the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading `forensics/prerequisites.json`
for `owner_phase == 20`: no `deferrals` row and no `units` row. The plane's records and deferrals are
all owned by earlier strata, and the `forensics/phase*-obligations.json` files record no hand-off
owned by phase 20, so its working set is entirely its own authored contract.

**The custodian seal contract is five units**, each derived from the court that measures it:
`custodian-maturity` (`RT-CUSTODIAN-MATURITY`), `receipt-closure` (`RT-RECEIPT-CLOSURE`),
`custodian-residuals` (`RT-CUSTODIAN-RESIDUALS`), `substitution-witness` (`RT-SUBSTITUTION-WITNESS`)
and `custodian-boundary-register` (`CUSTODIAN-BOUNDARY-REGISTER`). At activation the runner registers
all five as `pending`, so all five units are open.

**A passing custodian court is an instrument, not a property claim, and the ledger records the two
axes separately.** Each contract unit carries `measurement_state` (the instrument ran and its control
was honest) beside `property_status` and `findings` (what, if anything, the unit claims about the
custodian property). `custodian-maturity` is the unit where the two diverge: `RT-CUSTODIAN-MATURITY`
passes as an instrument while recording, as `findings`, where the level the committed evidence
supports is lower than the level the seal might otherwise name, so the property reads `NOT_CLAIMED`
with `findings_present`. **A passing `RT-CUSTODIAN-MATURITY` must never be read as "L9 custodian seal
achieved".** The findings are read from the court row rather than typed, and
`forensics/phase20-obligations.json` carries both axes for every unit.

**The ledger's unit is not an exported symbol.** `forensics/phase20-obligations.json` publishes
`unit: "custodian seal contract"`, its `implemented`/`open` export lists are empty *by measurement*,
and its working set is counted in `open_in_this_stratum` over the five contract units.
`atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that partition the export universe
(`court_coverage.py`, `ownership_audit.py`) skip this ledger rather than reconcile a symbol set that
does not exist.

**Phase 20 begins on nothing of its own.** No custodian court exists at activation, so
`open_in_this_stratum` opens at the whole working set (five) and moves only as the subphases below
land. **That split moves as the stratum lands its own units: the ledger's `counts` is the live record
and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 20.0 | **The plan and the ledger** | `docs/PHASE-20-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase20-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase20_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 19 | — |
| 20.1 | **The custodian-maturity court** | the derivation of the L0–L9 ladder for `libcrypto` and `libssl` from committed evidence, naming only a level whose evidence is present and recording the gap as a finding when the evidence supports less than the level the seal might claim. | 20.0 | `RT-CUSTODIAN-MATURITY` |
| 20.2 | **The receipt-closure court** | the join of every obligation recorded `implemented` or closed to its FRF receipt, and the compiled parity claim's blocker set, so the claim `docs/CUSTODIAN_CONTRACT.md` §6 makes is a join over immutable receipts rather than an assertion. | 20.0 | `RT-RECEIPT-CLOSURE` |
| 20.3 | **The residual-disposition court** | the disposition of every residual, requiring zero `UNKNOWN` intersecting the claimed production profile, so a newly discovered un-dispositioned residual is a `fail` rather than a silent addition. | 20.0 | `RT-CUSTODIAN-RESIDUALS` |
| 20.4 | **The substitution-witness court** | the ABI-substitution witness chain and the machine-owned downstream corpus witness chain: binaries built against the admitted authority run unmodified against the candidate, over the Phase-17 corpus the court re-establishes as current and functional. | 20.0 | `RT-SUBSTITUTION-WITNESS` |
| 20.5 | **The custodian-boundary register** | the register that records what is claimed, what is bounded, and the explicit non-claims — no FIPS validation, no universal parity from finite evidence, memory safety measured-not-established — and that fails the stratum if a recorded boundary drifts from its evidence. | 20.1–20.4 | `CUSTODIAN-BOUNDARY-REGISTER` |
| 20.6 | **The seal** | nothing in the crate — evidence: `docs/PHASE-20-CUSTODIAN-SEAL.md` (at the seal) | 20.0–20.5 | — |

The rows above the seal partition the working set by source: each subphase row lands the instrument
for exactly one of the five contract units. The partition is derived from
`forensics/phase20-obligations.json` joined to `artifacts/phase20/COURTS.json`, not typed.

## 3. What each subphase must honour

**3.1 A custodian court is bounded to its measured surfaces, and it says so.** A passing
`RT-RECEIPT-CLOSURE` says the join ran over the receipts it names and produced the blocker set it
recorded, not that every obligation is universally established. The surfaces a court names, the
artefacts it reads and the claim it binds are recorded in the court's row, and a surface the court
does not reach is named `pending` rather than counted as passing (§3.7).

**3.2 The instrument-versus-property split keeps a pass from being read as the property.** A passing
court is an instrument: it ran and its control was honest. The property it names — custodian
compatibility, an L9 level, a closed residual set — is carried by `property_status` and `findings`,
and where the evidence falls short the unit reads `NOT_CLAIMED` with the gap named, exactly as Phase
19's `performance-work` does. `docs/PARITY_MODEL.md` is the authority on what the labels mean, and a
subphase may not promote an instrument's pass into a property claim it did not measure.

**3.3 Maturity is derived, never named ahead of its evidence.** `RT-CUSTODIAN-MATURITY` reads the
levels it can support from committed artefacts — the ledgers, the court results, the coverage joins,
the provider census — and records the highest level whose evidence is present. The seal may not name
a level the derivation does not reach, and a level claimed without its evidence is `fail` rather than
a stronger verdict.

**3.4 The receipts and the residuals are read from the artefacts that carry them.** The closure court
does not maintain its own list of receipts and the residual court does not maintain its own list of
residuals: both read the registers the earlier strata and the FRF store write, so the two cannot
disagree with the evidence and a residual that is added without a disposition is visible as a
`fail`. `UNKNOWN` remains a result, not a resting state (`docs/PARITY_MODEL.md` §1).

**3.5 The substitution witness is a machine-owned chain, not a rerun by hand.** `RT-SUBSTITUTION-
WITNESS` records, per witness, the binary it was built against, the run that exercised it and the
observation it produced, so a witness that is not reproduced by the run is a finding rather than a
remembered result. The downstream corpus it leans on is the Phase-17 corpus, and the court
re-establishes that corpus as current and functional rather than assuming it.

**3.6 The register is the stratum's own non-claims, and it is mechanical.** 20.5 records, per
surface, whether it is *claimed* (a passing court covers it) or *bounded* (explicitly outside this
stratum — including **FIPS validation**, **universal parity from finite evidence** and
**established memory safety**), and the `CUSTODIAN-BOUNDARY-REGISTER` court fails the stratum if a
recorded boundary drifts from the evidence that establishes it. It is the stratum's answer to
`docs/NON_CLAIMS.md`, and it may not claim more than the courts above measured.

**3.7 The five units land in one ordered chain behind the runner.** 20.1 through 20.4 land the four
custodian courts; 20.5 lands the register that binds them; each lands its code, its court and its
regenerated artefacts in one commit, and the ledger's `open_in_this_stratum` moves only when a court
in `artifacts/phase20/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase20-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `custodian seal contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase 16's
`cli-config contract`, Phase 17's `downstream replacement contract`, Phase 18's `hostile hardening
contract` and Phase 19's `performance dispatch contract` are (D485). The ledger fails closed if the
ownership atlas ever assigns this stratum an export, if the provider census assigns it a
registration row, or if the prerequisite plane assigns it a deferral or a translation unit, because
then the non-export unit would be the wrong shape.

**4.2 The precondition this plan places on 20.0, and it is not optional.** `run_courts.py` refuses a
stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase20_courts.py` with **no runnable court**: its obligations are not exports, so
no differential probe over a symbol set is its evidence, and its five courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The direction
of the `phase20_courts.py` ↔ `phase20_obligations.py` edge is the reverse of Phase 16's**: the
ledger's contract-unit states are measured from the courts registry, so the registry is generated
first and `phase20_courts.py` does **not** bind the ledger as an input. A cycle in which each
embedded the other's digest would make neither reproducible. **No court is registered in
`gen_frf_courts.py`**: that registry is the stratum's seal. So the activation order is: the runner
and its pending registry, the ledger, and the plan land **together**, or `run_courts.py` fails and
the tree carries an activation whose runner is refused.

**4.3 A custodian seal is bounded evidence, not a universal claim.** Phase 19 *measured* the
candidate's dispatch behaviour and deterministic work; Phase 20 *compiles the claim* over the
implementation Phases 3 through 19 finished. The claim it may license is exactly
`docs/CUSTODIAN_CONTRACT.md` §6's — source/API compatibility, binary ABI compatibility and
externally observable semantic compatibility over the stated authority, build profile and platform,
with no unresolved residual intersecting the claimed scope — and no more. The three load-bearing
non-claims are named in §0: **no FIPS validation**, **no universal parity from finite evidence**, and
**memory safety measured, not established**. A passing court does not widen them.

**4.4 The prerequisite plane is not this stratum's universe, and the plan says so.** No row of
`forensics/prerequisites.json` is owned by phase 20, so this plan names no prerequisite unit and
plan reconciliation has no unit of this stratum's to judge; a subphase that discovers its unit is
elsewhere records that rather than forcing a row (§0, §5).

## 5. Process

This stratum inherits Phases 8 through 19's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase table
above was written from the five-row measurement in §1. A subphase that discovers its unit is
elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-20-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the five custodian seal contract units,
recorded in the ledger's contract-unit block rather than as open exports.
