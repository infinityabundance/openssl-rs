# ETP-T15 — adjudication reconciliation: receipt

**Item:** ETP-T15, reconciliation of the OpenSSH b85c graduation and the
`NOT ESTABLISHED` adjudication as distinct records with their actual provenance.
**Verdict:** `DONE` for the reconciliation, the classification, the four claim
records, the cohort counters, the machinery changes and the two-direction
controls. It promotes nothing: the only movement is downward, from an
unsupported `SAFE_COMPATIBLE` label to `RISK_ACCEPTED` or `SUPERSEDED`.
**Date:** 2026-11-23.

---

## 1. Source identity and environment

| field | value |
|---|---|
| branch | `staging` |
| HEAD at start | `576e26d2d23269c1991af5d8aeef84b1e90d7ef2` |
| worktree at start | clean (`git status --porcelain` empty) |
| `free -g`, available | 19 GiB |
| derived cap | `min(8, 19 − 16)` = **3g** (2g floor met) |
| court | `openssl-rs-court-tools:1`, `OPENSSL_RS_COURT_MEM=3g`, `OPENSSL_RS_COURT_MEMSWAP=3g` |
| Python | 3.11.2, standard library only |
| Rust build | not run: no `src/` change, and `available` (19 GiB) is below the §6.1 24 GiB build threshold |

Every command ran inside the court at that cap, one at a time. No `src/`,
`docker/` or build file was touched.

---

## 2. What the two records assert

**Graduation** (`evidence/SAFE-COMPATIBLE-openssh-b85c.json`, original SHA-256
`41e5797d…`): `kind: safe-compatible-graduation-record`; `verdict.value:
SAFE_COMPATIBLE`; families `ssh`, `sshd`; candidate `b85c`; `decided_by:
"decision-maker (campaign principal)"`; `source_head: 17042ccf2`;
`freeze_sha256: b08131b1…`; `tool_sha256: 3e86a74d…`; `mechanism_verdicts` all
seven `SAFETY_DISCHARGED`; `dissent.statement`: "This graduation is a
principal-decided risk acceptance over the recorded evidence, not an independent
acceptance of the assurance case."

**Adjudication** (`evidence/b85c-adjudication.json`, unchanged SHA-256
`24e11717…`): `kind: independent-adversarial-adjudication`; candidate `b85c`;
`head_at_adjudication: bfa39a6c3`; `evidence_source_head: 17042ccf2`;
`verdict.state: "NOT ESTABLISHED"`; `verdict.reason` names five of seven
mechanisms `NOT_ESTABLISHED`, both scoped discharges' retained preconditions, the
four cross-cutting obligations and the freeze's own `safe_compatible=false`.

**Freeze** (`evidence/FREEZE-b85c.json`, unchanged `b08131b1…`):
`safe_compatible.value: false`; `safe_compatible.l7_replay.not_graduated: true`;
`safe_compatible.reason` names two scoped discharges and five
`NOT_ESTABLISHED`, and states "No independent SAFE_COMPATIBLE adjudication was
run at b85c."

**Independence:** the adjudication asserts independence; ETP-T8 records it as
**not established** (no reviewer identity, same undeclared party, reproduction in
this repository's working environment against project-produced artefacts). No
reviewer, organisation or key was created.

---

## 3. Classification and the record change

| state | definition | applied |
|---|---|---|
| `SAFE_COMPATIBLE` | the §7 dependency closure is discharged: every applicable mechanism `SAFETY_DISCHARGED`, every caller precondition established, no hidden obligation | **not supported** |
| `RISK_ACCEPTED` | an authorised principal decision to proceed with named unresolved obligations; asserts no safety property | **applied to the graduation** |
| `NOT_ESTABLISHED` | the evidence does not justify the requested property | **the property state** |

Why: five of seven applicable mechanisms are `NOT_ESTABLISHED` at
mechanism-wide grade; both scoped discharges retain un-established caller
preconditions; all four cross-cutting obligations are `NOT_ESTABLISHED`;
`0 BLOCKED` is receipt coverage and 65 `REVIEW_REQUIRED` rows are still counted
as discharged; the freeze records `safe_compatible=false`. The record's own prose
already calls the decision a principal risk acceptance.

`evidence/SAFE-COMPATIBLE-openssh-b85c.json` is now a `risk-acceptance-record`
with `classification.state: RISK_ACCEPTED`, `safe_compatible_established: false`,
the fifteen accepted obligations named, the corrected mechanism states (two
scoped, five `NOT_ESTABLISHED`), the unchanged dissent, and `supersedes` carrying
the original path, digest, kind, verdict and `mechanism_verdicts` text. The
original bytes are preserved byte-for-byte at
`evidence/etp-t15/history/SAFE-COMPATIBLE-openssh-b85c.json`.

New live SHA-256: `dde0d376…`. The adjudication is byte-identical.

---

## 4. Cohort counter

| identity | §7 `SAFE_COMPATIBLE` | risk-accepted | source |
|---|---|---|---|
| before 2026-11-17 | 0/33 | not recorded | `PROGRESS.md` |
| 2026-11-17 → 2026-11-23 | **1/33** | not recorded | `CAMPAIGN-STATUS.json` |
| after reconciliation | **0/33** | **1** (`openssh`) | `CAMPAIGN-STATUS.json#consumers` |

Preserved: `consumers.safe_compatible_before_reconciliation: 1`,
`consumers.note_before_reconciliation` (the full previous note),
`safe_compatible_graduation.history` (previous receipt, integer, note and history
copy digest), the header note in `PROGRESS.md`, the new reconciliation section
and the superseded-labelled 2026-11-17 section in `STATUS-2026-10-20.md`, and the
whole pre-change ledger at
`evidence/etp-t15/history/CAMPAIGN-STATUS.before-reconciliation.json`.

`families_total` and `l7_functional` remain 33; they are compatibility counts,
not graduations.

---

## 5. The four gate refusals

| claim | before | after | diagnosis | repair |
|---|---|---|---|---|
| `ETP0-CLM-030` | `CONTRADICTED` | `RISK_ACCEPTED` | record asserts more than its evidence | graduation reclassified; original bytes preserved; accepted obligations named |
| `ETP0-CLM-004` | `CONTRADICTED` | `SUPERSEDED` | seal prose asserts more than the tracked registry | erratum identifies the prose as the wrong side; the measurement stands |
| `ETP0-CLM-005` | `CONTRADICTED` | `SUPERSEDED` | prose internally inconsistent; machine `claim` field says 50 % while `threshold_percent` and `SEP_PCT` say 150 % | erratum names 150 % authoritative; the `claim`-field defect is recorded, not papered over |
| `ETP0-CLM-032` | `CONTRADICTED` | `SUPERSEDED` | ledger self-contradiction; 1/33 inherited the graduation's error | counter repaired to 0/33 §7 + 1 risk-accepted, with history preserved |

Resolved: the four `RG_CLAIM_CONTRADICTED` items. **Remaining:** 31 refusals,
none about the four claims — 19 `RG_CLAIM_UNCERTIFIABLE_EVIDENCE`, 11
`RG_CLAIM_HISTORICAL_EVIDENCE` (the ETP-T9 identity triage over other claims) and
1 `RG_PACKAGE_MISSING` (no ETP-6 package supplied). The claim item now reports no
`CONTRADICTED`, `REFUTED`, `WITHDRAWN` or graduation-over-`NOT_ESTABLISHED` item.

---

## 6. Two-direction demonstration

**Repaired record passes.**

- `etp_claims.py validate` → `valid: true`, **0 refusals, 35 claims**; each of the
  four reconciliations re-derives its historical and superseding records.
- `etp_claims.py conjoin` → `SUPERSEDED` (no longer `CONTRADICTED`), weakest
  members named.
- `release_gate.py --graduation` → **0** `RG_CLAIM_CONTRADICTED`; 31 other
  refusals remain.
- `release_gate.py --self-test` → **16 cases, 0 failures**, including the
  repaired `RISK_ACCEPTED` positive control.

**Old `SAFE_COMPATIBLE` assertion still refused.**

- `evidence/etp5/probes/p1-openssh-graduation-promotion.json` → refused with
  `EG_GRADUATED_WITH_OPEN_OBLIGATION`, `EG_GRADUATED_WITHOUT_CLOSURE`,
  `EG_SAFE_COMPATIBLE_EXCLUSION_FAILS_BAR` (and a digest mismatch against the
  superseded bytes).
- `release_gate.py --graduation --claims
  evidence/etp-t15/history/claims.before-reconciliation.json` → still emits the
  four `RG_CLAIM_CONTRADICTED` refusals for `-004`, `-005`, `-030` and `-032`.
- A reconciliation used to raise a `CONTRADICTED` claim → refused with
  `EG_RECONCILIATION_PROMOTION`, proven in the self-test and the
  `ReconciliationControls` unit tests.
- Closure discipline: the live risk record reports `FAIL` and is accepted
  (`aggregate_refusals: []`); the historical `SAFE_COMPATIBLE` bytes still
  produce `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`.
- Independence: the risk-acceptance assignment produces **0** findings;
  `validate` passes 50 assignments with 0 structural refusals; `check` produces 8
  findings, all on `A-ADJ-B85C` (the adjudication's unsupported assertion). The
  historical ETP-T8 record still produces 13.

---

## 7. The other three contradicted claims

`ETP0-CLM-004` — **a record asserting more than its evidence.** The seal prose is
wrong: the tracked registry records `all_pass: false`, `pass 4 / fail 1` with
`HOSTILE-BOUNDARY-REGISTER` failing on 56 `UNSAFE-FOOTPRINT` bounds, and the
ledger records `implemented` 4 / `open_in_this_stratum` 1. The measurement is not
wrong. `docs/PHASE-18-HARDENING-SEAL-ERRATUM.md` records this; the failing court
is not made to pass and the open unit is not closed.

`ETP0-CLM-005` — **a record defect in a descriptive field.** The probe
(`SEP_PCT 150`) and `threshold_percent: 150` agree; the seal prose says 110, 50
and 150 in different sections. Separately, `artifacts/phase18/COURTS.json#claim`
still says 50 % while its own `threshold_percent` says 150. That second defect is
a record defect, recorded as a finding and **not repaired**, because a
measurement artefact is not rewritten to make its prose agree.

`ETP0-CLM-032` — **a record defect repaired to one value.** The ledger carried
`1` and `0/33` in the same file; `PROGRESS.md` and `STATUS-2026-10-20.md`
disagreed. The 1/33 reading inherited the graduation's error. The ledger now
records 0/33 §7 and 1 risk-accepted family, and the three documents agree.

No measurement was found wrong. No finding was suppressed.

---

## 8. Deliverables and digests

| path | content | SHA-256 |
|---|---|---|
| `docs/ADJUDICATION-RECONCILIATION.md` | the two records, provenance, classification, reconciliation, machinery, non-claims | `a1cae922…` |
| `evidence/etp-t15/RECONCILIATION.json` | machine record (schema `openssl-rs/etp-t15/reconciliation/1`) | `b8c11c86…` |
| `evidence/etp-t15/INDEPENDENCE.json` | superseding independence projection for the risk record | `729f69b3…` |
| `evidence/etp-t15/history/README.md` | names each historical identity and digest | `f20055b7…` |
| `evidence/etp-t15/apply_claims.py` | reproduces the four reconciled claims from the historical copy and the current reconciliation digest | `37fed307…` |
| `evidence/etp-t15/make_independence_record.py` | reproduces `INDEPENDENCE.json` from the ETP-T8 projection, the live graduation and the live claims | `93bc0065…` |
| `evidence/SAFE-COMPATIBLE-openssh-b85c.json` | reclassified risk-acceptance record | `dde0d376…` |
| `docs/PHASE-18-HARDENING-SEAL-ERRATUM.md` | correction of three seal statements | `1e4521b8…` |
| `evidence/etp/claims.json` | four reconciled claims; 35/35 valid | `ddd70dfb…` |
| `evidence/etp/claim.schema.json` | `RISK_ACCEPTED` and the `reconciliation` record | `bb44ba69…` |
| `evidence/etp-t1/TRACEABILITY.json` | regenerated from the reconciled claims; 361 nodes / 475 edges / 43 orphans unchanged | `8ce6881f…` |
| `CAMPAIGN-STATUS.json` | reclassified graduation block and counters, history retained | `8affeac4…` |
| `PROGRESS.md` | reconciliation note, previous state retained | `adcbb62b…` |
| `STATUS-2026-10-20.md` | reconciliation section, current table corrected, 2026-11-17 section marked superseded | `c311c25b…` |

Historical copies: `SAFE-COMPATIBLE-openssh-b85c.json` `41e5797d…`,
`claims.before-reconciliation.json` `65d8105b…`,
`CAMPAIGN-STATUS.before-reconciliation.json` `abb8a6cb…`,
`PROGRESS.before-reconciliation.md` `4839a213…`,
`STATUS-2026-10-20.before-reconciliation.md` `7c966f89…`,
`TRACEABILITY.before-reconciliation.json` `d5920c80…`.

`evidence/etp-t15/RECONCILIATION.json` is accepted by `python3 -m json.tool`.

### Machinery changed

| tool | change |
|---|---|
| `forensics/tools/etp_claims.py` | `RISK_ACCEPTED` verdict; `reconciliation` record; `EG_RECONCILIATION_UNBOUND`, `EG_RECONCILIATION_PROMOTION`, `EG_RISK_ACCEPTED_WITHOUT_OBLIGATION`; digest-checked records; deterministic meet ordering |
| `forensics/tools/release_gate.py` | `RISK_ACCEPTED` is non-assertive; self-test gains the repaired positive control and both refusal directions |
| `forensics/tools/independence.py` | `RISK_ACCEPTED` rank; the seed derives the class from the live classification; historical inputs can be passed explicitly |
| `forensics/tools/closure_discipline.py` | `_aggregate_graduation` accepts a path/name for the historical control; fixed loop-variable shadowing of the aggregate name |
| `forensics/tools/tests/test_etp_claims.py` | reconciliation controls (6), updated typed-claim checks |
| `forensics/tools/tests/test_closure_discipline.py` | live-accepted and historical-refused controls |
| `forensics/tools/tests/test_independence.py` | historical reproduction and live risk-acceptance controls |

---

## 9. Validators and gate output

| command | result |
|---|---|
| `etp_claims.py validate` | `valid: true`, 0 refusals, 35 claims |
| `etp_claims.py conjoin` | `SUPERSEDED` |
| `python3 -m unittest discover -s forensics/tools/tests` | **525 tests, 0 failures** |
| five affected modules (`etp_claims`, `closure_discipline`, `independence`, `release_gate`, `traceability`) | **197 tests, 0 failures** |
| `release_gate.py --self-test` | **16 cases, 0 failures** |
| `release_gate.py --graduation` | exit 1, 31 refusals (19 uncertifiable, 11 historical, 1 package), 0 contradicted |
| `closure_discipline.py check` | `aggregate_refusals: []` |
| `independence.py validate --assignments evidence/etp-t15/INDEPENDENCE.json` | PASS, 50 assignments, 0 structural refusals |
| `independence.py check --assignments evidence/etp-t15/INDEPENDENCE.json` | 8 findings, all `A-ADJ-B85C`; 0 for `A-REL-OPENSSH-B85C` |
| `docs_consistency.py` | exit 0 |
| `python3 -m json.tool` on both new JSON records | accepted |

A Rust build and the library suite were not run: no `src/` file changed and
`available` was below the §6.1 build threshold.

---

## 10. Non-claims

- No `SAFE_COMPATIBLE` graduation, mechanism discharge, compatibility result or
  cryptographic result is established by this item.
- The b85c closure, the L7 workloads and every instrument were not re-run.
- The adjudication's independence is not established; it remains refused.
- The Phase-18 failing court is not made to pass; the open unit is not closed.
- The `artifacts/phase18/COURTS.json#claim` field is not repaired; it is recorded.
- `RISK_ACCEPTED` is not a pass and not a graduation. The release gate still
  refuses `SAFE_COMPATIBLE` without the §7 closure.
- The historical copies are the record of what was asserted; this receipt is the
  record of what the evidence supports.
