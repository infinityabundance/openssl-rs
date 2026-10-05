# Phase 18 — the hostile fuzz / security / side-channel hardening stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 18 is the stratum `docs/RELEASE_GATES.md` §1 names "Hostile fuzz / security / side-channel
hardening". Like Phases 16 and 17 it owns **no exported symbol**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 18` yields nothing, because the
declaring-header rule assigns no installed header to this stratum. Its unit is therefore not a
symbol. Unlike Phases 16 and 17 it also **hands nothing forward and receives nothing**: the
implementation it hardens is already the one Phases 3 through 15 completed, so it adds no library
surface and takes no unit or symbol deferral from an earlier stratum.

What it owes is *hardening evidence over the finished implementation*, and that evidence is
adversarial in its subject rather than differential in its instrument. The four things it must
produce, and the plan's subphases below are these:

* a **hostile TLS / X.509 corpus**: malformed records, handshake messages, extension bodies and
  certificates, driven with crash / OOM / timeout detection and an authority-linked differential
  control, reusing the real downstreams and the `courts/` probe harness;
* **side-channel-relevant constant-time / secret-independence checks** for the primitive-bearing
  paths (BN, RSA, EC, the AEADs and the key schedule), as a candidate-only `CT-*` court with a
  sensitivity control, in the sense Phases 8 and 9 already use for `CT-*`;
* **memory-safety / resource-exhaustion hardening** for the reduced engine's fixed buffers — the
  earlier greater-than-16-KiB write overflow is the concrete case — and for its
  allocation-failure paths; and
* the **hostile-boundary register**, recording what is hardened, what is measured and what is
  explicitly *not* claimed.

It is **not** a security proof, and it is not a parity claim. A passing hostile court is a
bounded differential or property result over the corpus it drives; a `CT-*` pass is a bounded
secret-independence check rather than a proof; and a register entry is a record of a boundary,
not a guarantee that the boundary cannot be crossed. `docs/SECURITY_DIVERGENCE_POLICY.md` and
`docs/NON_CLAIMS.md` are the authorities on what may be said; a subphase that discovers its unit
is somewhere else records that rather than forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase18-obligations.json` is
authoritative for the present. The activation measurement was taken against `main` `abc8a1c0`
(openssl-rs 0.0.22, Phase 17 released).

**Phase 18 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for
`owner_phase == 18` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger
fails closed if that ever stops being true rather than silently counting a symbol through a
non-export unit.

**It receives zero provider registration rows.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 18` gives no row: this stratum
activates no provider. The ledger fails closed if the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading
`forensics/prerequisites.json` for `owner_phase == 18`: no `deferrals` row and no `units` row.
(The plane holds 152 unit records and one symbol deferral in total, all owned by earlier strata.)
No earlier stratum's obligation ledger records a hand-off to Phase 18 — the eight
`forensics/phase*-obligations.json` files that exist record nothing owned by this stratum — so its
working set is entirely its own authored contract.

**The hostile hardening contract is five units**, each derived from the court that measures it:
`hostile-tls` (`RT-HOSTILE-TLS`), `hostile-x509` (`RT-HOSTILE-X509`), `constant-time`
(`CT-PRIMITIVES`), `memory-hardening` (`RT-MEM-HARDENING`) and `hostile-boundary-register`
(`HOSTILE-BOUNDARY-REGISTER`). At activation the runner registers all five as `pending`, so all
five units are open.

**The ledger's unit is not an exported symbol.** `forensics/phase18-obligations.json` publishes
`unit: "hostile hardening contract"`, its `implemented`/`open` export lists are empty *by
measurement*, and its working set is counted in `open_in_this_stratum` over the five contract
units. `atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that partition the export
universe (`court_coverage.py`, `ownership_audit.py`) skip this ledger rather than reconcile a
symbol set that does not exist.

**Phase 18 begins on nothing of its own.** No hardening court exists at activation, so
`open_in_this_stratum` opens at the whole working set (five) and moves only as the subphases
below land. **That split moves as the stratum lands its own units: the ledger's `counts` is the
live record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 18.0 | **The plan and the ledger** | `docs/PHASE-18-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase18-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase18_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 17 | — |
| 18.1 | **The hostile TLS corpus** | the malformed-record / handshake-message / extension-body corpus and its driver over the real record layer and the TLS 1.3 flight (`src/ssl/`), with crash / OOM / timeout detection and an authority-linked differential control over the same corpus bytes. | 18.0 | `RT-HOSTILE-TLS` |
| 18.2 | **The hostile X.509 / malformed-input corpus** | truncated, oversized and ill-formed certificates, extensions and DER/PEM containers over the `src/x509/`, `src/asn1/` and `src/pem/` readers, with an authority-linked differential control. | 18.1 | `RT-HOSTILE-X509` |
| 18.3 | **The constant-time / secret-independence checks** | a candidate-only `CT-*` court over the primitive-bearing paths (BN, RSA, EC, the AEADs and the TLS key schedule), carrying a sensitivity control that a deliberate branch-on-secret is caught, in the shape Phases 8 and 9 use for `CT-*`. | 18.0 | `CT-PRIMITIVES` |
| 18.4 | **The memory-safety / resource-exhaustion hardening** | the reduced engine's fixed buffers — the earlier greater-than-16-KiB write overflow is the concrete case — and its allocation-failure paths, with an injected-failure control. | 18.3 | `RT-MEM-HARDENING` |
| 18.5 | **The hostile-boundary register** | the register that records what is hardened, what is measured and what is explicitly not claimed, and that fails the stratum if a recorded boundary drifts from its evidence. | 18.1–18.4 | `HOSTILE-BOUNDARY-REGISTER` |
| 18.6 | **The seal** | nothing in the crate — evidence: `docs/PHASE-18-HARDENING-SEAL.md` (at the seal) | 18.0–18.5 | — |

The rows above the seal partition the working set by source: each subphase row lands the
instrument for exactly one of the five contract units. The partition is derived from
`forensics/phase18-obligations.json` joined to `artifacts/phase18/COURTS.json`, not typed.

## 3. What each subphase must honour

**3.1 A hostile court is bounded to its corpus, and it says so.** A passing `RT-HOSTILE-*` court
says the corpus it drove produced the observations it recorded, not that the parser is safe
against every input. The corpus, its size and its provenance are recorded in the court's row, and
a surface the corpus does not reach is named `pending` rather than counted as passing (§3.5).

**3.2 The differential control keeps the expectation honest, and the property control keeps it
from being vacuous.** Where the same corpus bytes have an authority behaviour, the authority and
the candidate are driven over them and the two observations are compared, so a hostile input's
disposition cannot be invented. Where the subject is a `CT-*` secret-independence property there
is no authority transcript to diff, so the court must carry a **sensitivity control**: a
deliberately branch-on-secret variant must be caught, or the court is `fail` rather than `pass`.
A control that cannot fail is not evidence.

**3.3 Crash, OOM and timeout are findings, not aborts.** A hostile run that takes the process
down, exhausts the allocation budget or fails to terminate is a recorded finding for that corpus
entry with its exit status, rather than a harness crash that stops the court. The container's
memory cap and per-process `RLIMIT_DATA` (`docker/openssl-rs-court.sh`) are what bound a runaway
entry; the court records the bound it ran under.

**3.4 Memory hardening names the buffer and the bound.** 18.4's subject is a *fixed* buffer whose
length was previously exceedable — the greater-than-16-KiB write overflow — so the court drives
the boundary at, just below and just above the recorded capacity, and the injected-failure
control drives the allocation-failure path rather than assuming it. A buffer that is merely
`unsafe` to use is recorded, not silently fixed.

**3.5 The register is the stratum's own non-claims, and it is mechanical.** 18.5 records, per
surface, whether it is *hardened* (a change landed), *measured* (a court covers it) or
*not claimed* (explicitly outside this stratum), and the `HOSTILE-BOUNDARY-REGISTER` court fails
the stratum if a recorded boundary drifts from the evidence that establishes it. It is the
stratum's answer to `docs/NON_CLAIMS.md`, and it may not claim more than the courts above
measured.

**3.6 Nothing here is a parity claim about the library.** A passing hostile court is a bounded
differential or property result, and a register entry is a record. `PARITY_VERIFIED` is not
claimed for any symbol by this stratum, and a name that cannot be driven is named `pending`
rather than counted as passing.

**3.7 The five units land in one ordered chain behind the runner.** 18.1 and 18.2 land the two
corpora; 18.3 and 18.4 land the two property/resource courts; 18.5 lands the register that binds
them; each lands its code, its court and its regenerated artefacts in one commit, and the
ledger's `open_in_this_stratum` moves only when a court in `artifacts/phase18/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The
atlas gives this stratum zero exports, so `forensics/phase18-obligations.json` cannot be the
export projection Phases 3 through 15 publish. Its unit is `hostile hardening contract`, recorded
in `atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as
Phase 16's `cli-config contract` and Phase 17's `downstream replacement contract` are (D485). The
ledger fails closed if the ownership atlas ever assigns this stratum an export, if the provider
census assigns it a registration row, or if the prerequisite plane assigns it a deferral or a
translation unit, because then the non-export unit would be the wrong shape.

**4.2 The precondition this plan places on 18.0, and it is not optional.** `run_courts.py`
refuses a stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase18_courts.py` with **no runnable court**: its obligations are not exports,
so no differential probe over a symbol set is its evidence, and its five courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The
direction of the `phase18_courts.py` <-> `phase18_obligations.py` edge is the reverse of Phase
16's**: the ledger's contract-unit states are measured from the courts registry, so the registry
is generated first and `phase18_courts.py` does **not** bind the ledger as an input. A cycle in
which each embedded the other's digest would make neither reproducible. **No court is registered
in `gen_frf_courts.py`**: that registry is the stratum's seal. So the activation order is: the
runner and its pending registry, the ledger, and the plan land **together**, or `run_courts.py`
fails and the tree carries an activation whose runner is refused.

**4.3 "Hostile hardening" here is bounded evidence, not a security claim.** Phase 17 *exercised*
the candidate as a consumer would; Phase 18 *attacks* the candidate's own parsers and arithmetic
with malformed input and measures secret-independence. The two are different strata and different
planes, and this plan reconciles them by naming which surface each contract unit is measured
against rather than by widening the ownership table. The non-claims this stratum carries are the
register's, and `docs/SECURITY_DIVERGENCE_POLICY.md` is the authority on where a boundary record
lifecycle ends and a safety claim begins.

**4.4 The prerequisite plane is not this stratum's universe, and the plan says so.** No row of
`forensics/prerequisites.json` is owned by phase 18, so this plan names no prerequisite unit and
plan reconciliation has nothing of this stratum's to judge; a subphase that discovers its unit is
elsewhere records that rather than forcing a row (§0, §5).

## 5. Process

This stratum inherits Phases 8 through 17's process unchanged: a subphase lands its code, its
court and its regenerated artefacts in **one commit**; every name a subphase lands carries a
court edge where it has one; and an artefact that a source change moves is regenerated in the
same commit. `docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the five-row measurement in §1. A subphase that discovers its unit
is elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-18-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the five hostile hardening contract
units, recorded in the ledger's contract-unit block rather than as open exports.
