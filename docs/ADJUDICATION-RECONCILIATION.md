# Adjudication reconciliation — the b85c graduation and the b85c adjudication (ETP-T15)

**Item:** ETP-T15. **Date:** 2026-11-23. **Machine record:**
`evidence/etp-t15/RECONCILIATION.json`. **Historical records:**
`evidence/etp-t15/history/` (README names each identity).

This document reconciles two records that were issued at the same evidence
source head and assert different things about the same property. It does not
re-run the b85c measurement, does not promote any verdict, and does not delete
or rewrite either record. The graduation is reclassified; the adjudication is
left byte-identical; both remain readable at their own provenance.

---

## 1. What each record asserts

### 1.1 The graduation record

At the reconciliation identity `evidence/SAFE-COMPATIBLE-openssh-b85c.json` was
reclassified. Its historical bytes (SHA-256 `41e5797d50bff7b62b25e25184f739bc3d68115396f32c4236d00a14e0301dd2`)
are preserved at `evidence/etp-t15/history/SAFE-COMPATIBLE-openssh-b85c.json`
and stated:

| field | value |
|---|---|
| `kind` | `safe-compatible-graduation-record` |
| `verdict.value` | `SAFE_COMPATIBLE` |
| `verdict.families` | `["ssh", "sshd"]` |
| `verdict.candidate` | `b85c` |
| `verdict.decided_by` | `decision-maker (campaign principal)` |
| `verdict.basis` | "the recorded closure, element-7 and L7 evidence at candidate b85c" |
| `verdict.scope` | "the OpenSSH consumer closure conservatively established at b85c, at the exact artefact digests recorded in evidence/FREEZE-b85c.json" |
| `identity.freeze_sha256` | `b08131b1ca7849a3e7f801b87f427774df346366344a2b24bd8207fcb847ec4e` |
| `identity.tool_sha256` | `3e86a74dbbe9095ca98ef3b8d889ec67a9447e59ef1caceecaa72152202988a1` |
| `identity.source_head` | `17042ccf2` |
| `mechanism_verdicts` | all seven named `SAFETY_DISCHARGED` |
| `dissent.statement` | "an independent adjudicator returned NOT ESTABLISHED at this candidate … This graduation is a principal-decided risk acceptance over the recorded evidence, not an independent acceptance of the assurance case." |
| `risk_accepted.by` | `decision-maker (campaign principal)` |
| `human-readable claim` | `risk_accepted.statement`: "All seven mechanisms are SAFETY_DISCHARGED at the OpenSSH scope." |

Three of those statements are not supported by the records the same file cites,
and the file itself says so in two places: it calls the decision a principal risk
acceptance, and it preserves a `NOT ESTABLISHED` dissent.

### 1.2 The adjudication record

`evidence/b85c-adjudication.json` (SHA-256
`24e11717aa72bf0c39425987d826df3cc59da0c4d05e4d280dc4ab99a9f4ab5d`,
unchanged by this item) states:

| field | value |
|---|---|
| `kind` | `independent-adversarial-adjudication` |
| `candidate_tag` | `b85c` |
| `head_at_adjudication` | `bfa39a6c3` |
| `evidence_source_head` | `17042ccf29bc39df638c63e69d3be6c6f965eef7` |
| `source_content_commit` | `5edca576b569b4a7bd6acfb09b77938ee555c147` |
| `freeze.sha256` | `b08131b1ca7849a3e7f801b87f427774df346366344a2b24bd8207fcb847ec4e` |
| `author_role` | "independent adversarial adjudicator; produced none of the b85c source, closures, receipts, instruments or reviews" |
| `verdict.state` | `NOT ESTABLISHED` |
| `verdict.for` | `["SAFE_COMPATIBLE (ssh)", "SAFE_COMPATIBLE (sshd)"]` |
| `verdict.reason` | "Both repaired defects reproduce and the count-level claims hold, but SAFE_COMPATIBLE is refused by the candidate's own section-7 argument and by the campaign ledger: five of seven applicable mechanisms are NOT_ESTABLISHED, all four cross-cutting obligations are NOT_ESTABLISHED, the two 'SAFETY_DISCHARGED (scoped)' mechanisms each retain an un-established caller precondition, and the closure's 0 BLOCKED is receipt coverage that still counts rows the ledger records as reopened/BLOCKED. The freeze itself records safe_compatible=false and 'NOT graduated'." |
| `item2_closures.limit` | "verdict.safe_compatible is hard-coded false in the instrument … DISCHARGED means an existing committed receipt covers the exact site, and the tool did not re-audit that receipt" |
| `item4_mechanisms.result` | `FAILS section 7` |
| `item5_ledger.result` | `REMAINING SAFETY-RELEVANT ITEMS; the ledger contradicts the zero-blocked reading` |
| `non_claims[1]` | "Failure of this claim is not a finding of memory unsafety; it is a finding that the section-7 graduation criteria are not established at b85c." |

Its `verdict.state` is the same as the freeze's own machine value:

- `evidence/FREEZE-b85c.json#safe_compatible.value` is `false`, and its `reason`
  says "the criterion-3 argument is SAFETY_DISCHARGED for two mechanisms under
  scoped claims … and NOT_ESTABLISHED for the other five … No independent
  SAFE_COMPATIBLE adjudication was run at b85c.";
- `safe_compatible.l7_replay.not_graduated` is `true`;
- `not_graduated` is present at the top level.

### 1.3 Provenance and independence

The two records were issued at different **head** commits but over the same
**evidence source head** `17042ccf2` and the same freeze digest. They are two
records at one evidence identity, which is why the claim algebra types their
coexistence as a hard contradiction when both are typed at that identity.

Independence is **declared by the adjudication and not established**. The
ETP-T8 record states the finding without inventing a party:

- `evidence/etp-t8/ASSIGNMENTS.json#A-ADJ-B85C.finding`: "The adjudication
  asserts independence, names no reviewer identity, organisation or key, ran in
  this repository's working environment against stored project artefacts, and
  is filled by the same undeclared party as the source it judges."
- `evidence/etp-t8/ASSIGNMENTS.json#A-REL-OPENSSH-B85C.finding`: "The record
  itself states that the graduation is a principal-decided risk acceptance, not
  an independent acceptance. The release authority declares no identity,
  organisation, infrastructure or key."

No reviewer, organisation or key is created by this reconciliation. The
adjudication's independence remains refused by the independence checker, and
that refusal is a correct finding about the record, not a defect in it.

---

## 2. The classification

Three states are used, and they are not interchangeable.

| state | meaning | what it requires |
|---|---|---|
| `SAFE_COMPATIBLE` | the consumer family's §7 dependency closure is discharged: every applicable mechanism `SAFETY_DISCHARGED`, every caller precondition established, no hidden obligation, compatibility against the exact converted implementation. | evidence that meets AGENTS.md §7 as a whole. |
| `RISK_ACCEPTED` | an authorised principal decision to proceed while named obligations remain unresolved. It asserts no safety property and grants no graduation. | a named decision-maker, named accepted obligations, and the dissent retained. |
| `NOT_ESTABLISHED` | the evidence does not justify the requested property. | the unresolved obligations named, with what would settle each. |

At b85c the evidence supports `NOT_ESTABLISHED` for the requested
`SAFE_COMPATIBLE` property and supports `RISK_ACCEPTED` for the decision that
was actually taken. It does not support `SAFE_COMPATIBLE`:

1. Five of seven applicable mechanisms are `NOT_ESTABLISHED` at mechanism-wide
   grade (`EVP_PKEY_PROVIDER` 116, `X509_VERIFY_POLICY` 122,
   `RAND_CMS_STORE_KEYFMT` 27, `C_ABI_CONTRACT` 5, `BIO` 2 of 290 obligations).
   AGENTS.md §7 requires **every** applicable mechanism to be
   `SAFETY_DISCHARGED`.
2. The two `SAFETY_DISCHARGED (scoped)` mechanisms retain un-established caller
   preconditions: `SSL_SESSION` retains the sslconf-exclusivity obligation;
   `RUNTIME_CONCURRENCY` retains exclusive ownership (its own R1 says no test
   performs the forbidden release shape). §7 criterion 2 requires caller
   preconditions to be established.
3. All four cross-cutting obligations (callbacks/reentrancy,
   aliasing/ownership, panic safety, secret memory) are `NOT_ESTABLISHED`.
4. `0 BLOCKED` is receipt coverage, not current adjudication: the closure tool
   never promotes, DISCHARGED means an existing receipt covers the exact site,
   and 65 `REVIEW_REQUIRED` rows are still counted as discharged.
5. The freeze the record names already records `safe_compatible: false` and
   `not_graduated: true`.

The record's own prose says the decision is "a principal-decided risk
acceptance over the recorded evidence, not an independent acceptance of the
assurance case". `RISK_ACCEPTED` is therefore the label the record's own
provenance supports. The classification is not a promotion: it is lower than the
label it replaces, and it removes the assertion the evidence contradicts.

---

## 3. The reconciliation applied

### 3.1 The live graduation record

`evidence/SAFE-COMPATIBLE-openssh-b85c.json` now states:

- `kind`: `risk-acceptance-record`; `receipt`: `RISK-ACCEPTED-openssh-b85c`;
- `classification.state`: `RISK_ACCEPTED`; `classification.safe_compatible_established`: `false`;
- `supersedes`: the original path, its SHA-256 `41e5797d…`, the historical copy,
  its SHA-256, `original_verdict: SAFE_COMPATIBLE`, and the original
  `mechanism_verdicts` text preserved verbatim;
- `mechanism_verdicts`: two `SAFETY_DISCHARGED (scoped)`, five
  `NOT_ESTABLISHED`, with the note that all seven are applicable and the two
  scoped discharges retain caller preconditions;
- `cross_cutting`: all four `NOT_ESTABLISHED`;
- `accepted_obligations`: the named unresolved obligations the decision accepts;
- `dissent`: unchanged in substance, with `independence_established: false` and
  the ETP-T8 finding named;
- `cohort_counter`: `safe_compatible_families: 0`, `risk_accepted_families: 1`;
- `non_claims`: includes "this record does not establish SAFE_COMPATIBLE for any
  consumer family".

Every unchanged measurement (closure counts, element-7 PASS, L7 workloads) stays
in the record with its original source. Nothing is added to the evidence.

### 3.2 What is preserved

| record | disposition |
|---|---|
| `evidence/SAFE-COMPATIBLE-openssh-b85c.json` (original bytes) | preserved byte-for-byte at `evidence/etp-t15/history/SAFE-COMPATIBLE-openssh-b85c.json`, SHA-256 `41e5797d…` |
| `evidence/b85c-adjudication.json` | unchanged, SHA-256 `24e11717…` |
| `evidence/FREEZE-b85c.json` | unchanged, SHA-256 `b08131b1…` |
| `evidence/b85c-row-reconciliation.json` | unchanged, SHA-256 `a684b6af…` |
| `evidence/etp/claims.json` (before) | preserved at `evidence/etp-t15/history/claims.before-reconciliation.json`, SHA-256 `65d8105b…` |
| `CAMPAIGN-STATUS.json` (before) | preserved at `evidence/etp-t15/history/CAMPAIGN-STATUS.before-reconciliation.json`, SHA-256 `abb8a6cb…` |
| `PROGRESS.md` (before) | preserved at `evidence/etp-t15/history/PROGRESS.before-reconciliation.md`, SHA-256 `4839a213…` |
| `STATUS-2026-10-20.md` (before) | preserved at `evidence/etp-t15/history/STATUS-2026-10-20.before-reconciliation.md`, SHA-256 `7c966f89…` |

The live `CAMPAIGN-STATUS.json` and `PROGRESS.md` keep the previous values in
their own `history` / `note_before_reconciliation` fields, so a reader of either
document sees both the current value and the value it replaced.

### 3.3 The cohort counter

| identity | §7 `SAFE_COMPATIBLE` families | risk-accepted families | source |
|---|---|---|---|
| before 2026-11-17 | 0/33 | 0 | `PROGRESS.md`; history copy |
| 2026-11-17 to 2026-11-23 | **1/33** (`openssh`) | not recorded separately | `CAMPAIGN-STATUS.json#consumers.safe_compatible`; history copy |
| after the reconciliation | **0/33** | **1** (`openssh`) | `CAMPAIGN-STATUS.json#consumers` |

The 2026-11-17 advance counted a risk-accepted family as graduated. The
reconciliation reverses that count and records the family once, in
`consumers.risk_accepted`. The previous 1/33 value, the note that carried it, and
the earlier 0/33 state are preserved in
`CAMPAIGN-STATUS.json#consumers.note_before_reconciliation`,
`consumers.safe_compatible_before_reconciliation`, and the history copies.

No other cohort counter is changed. `families_total` remains 33 and
`l7_functional` remains 33; those are compatibility counts, not graduations.

---

## 4. The other three contradicted claims

The gate refused four claims. Each was diagnosed separately; the diagnoses are
not the same class.

### 4.1 `ETP0-CLM-004` — a record asserting more than its evidence

**Diagnosis:** the record that is wrong is the **seal prose**, not the
measurement. `docs/PHASE-18-HARDENING-SEAL.md` states `all_pass` true and 5 of 5
courts passing; the tracked `artifacts/phase18/COURTS.json` records `all_pass:
false`, `{"pass": 4, "fail": 1, "total": 5}`, with
`HOSTILE-BOUNDARY-REGISTER` failing on 56 `UNSAFE-FOOTPRINT` bound violations.
The obligation prose likewise says `implemented` 5 / `open_in_this_stratum` 0,
while the tracked ledger records `implemented` 4 / `open_in_this_stratum` 1, with
the unit `hostile-boundary-register` open and `measurement_state: not_measured`.

**Repair:** `docs/PHASE-18-HARDENING-SEAL-ERRATUM.md` states the tracked values
and identifies the prose as the wrong side. The claim becomes `SUPERSEDED`; its
two original parties are preserved in `reconciliation.original_parties`; the
contradiction obligations are `DISCHARGED` against the erratum. The failing court
is **not** made to pass, and the open unit is **not** closed.

**Finding:** the seal prose is wrong at its own date. The measurement is not
wrong.

### 4.2 `ETP0-CLM-005` — a record defect in a descriptive field, alongside a
prose inconsistency

**Diagnosis:** two separate defects, one of them a genuine record defect.

- The **seal prose** is internally inconsistent: 110 percent in §18.3, a 50
  percent floor in §0 and §6, and 150 percent in §6.3. The probe source
  (`SEP_PCT 150`) and the machine field `threshold_percent: 150` agree. The
  measurement is self-consistent; the prose is not.
- The **machine record** is internally inconsistent in one descriptive field:
  `artifacts/phase18/COURTS.json#claim` still says 50 percent while its own
  `threshold_percent` says 150. That is a **record defect in a descriptive
  field**, not a measurement defect, and it is recorded here rather than
  repaired: a measurement artefact is not rewritten to make its prose agree.

**Repair:** the erratum names 150 as the authoritative value, records the 110 and
50-percent prose statements as wrong, and records the `claim`-field defect as a
finding against the record. The claim becomes `SUPERSEDED`; the measurement is
not changed.

### 4.3 `ETP0-CLM-030` — the same class as the graduation: a record asserting more
than its evidence

**Diagnosis:** the graduation record issued `SAFE_COMPATIBLE` while its own cited
closure receipts record `verdict.safe_compatible = false`, the freeze records
`safe_compatible: false` and `not_graduated: true`, and the adjudication records
`NOT ESTABLISHED`. This is the same class as 4.1: the record asserts more than
its evidence.

**Repair:** the record is reclassified `RISK_ACCEPTED` (section 3.1), the original
bytes are preserved, and the claim's verdict becomes `RISK_ACCEPTED` with the
accepted obligations named. `SAFE_COMPATIBLE` remains `NOT_ESTABLISHED`.

### 4.4 `ETP0-CLM-032` — a record defect, repaired to one value

**Diagnosis:** `CAMPAIGN-STATUS.json` contradicted itself: `consumers.safe_compatible
= 1` and `safe_compatible_graduation.verdict = SAFE_COMPATIBLE` in one field,
while its own `consumers.note` and `non_claims[0]` said 0/33, and `PROGRESS.md`
said the counter was not advanced while `STATUS-2026-10-20.md` said 1/33. This is
not a measurement defect: it is a ledger that carried two answers because the
graduation it counted was itself wrong (4.3).

**Repair:** the ledger now records `consumers.safe_compatible = 0` and
`consumers.risk_accepted = 1` for `openssh`, with the previous 1/33 value and note
in its history block. `PROGRESS.md` and `STATUS-2026-10-20.md` agree. The claim
becomes `SUPERSEDED`; the previous disagreement remains in the history copies.

**Finding:** the 1/33 reading was not an independent measurement; it inherited
the graduation's error.

---

## 5. Making the machinery agree

The reconciliation is only complete if the checkers read the new record as what
it is and still refuse the old assertion.

| checker | before | after |
|---|---|---|
| `etp_claims.py` | `ETP0-CLM-030` `CONTRADICTED`; cohort meet `CONTRADICTED` | `RISK_ACCEPTED` with a bound reconciliation; the cohort meet is no longer `CONTRADICTED` |
| `release_gate.py` | four `RG_CLAIM_CONTRADICTED` | no `RG_CLAIM_CONTRADICTED`; the remaining refusals are other artefacts |
| `independence.py` | `A-REL-OPENSSH-B85C` typed as a `SAFE_COMPATIBLE_RELEASE` | typed as a risk acceptance that asserts no independence; the adjudication's unsupported independence assertion is still refused |
| `closure_discipline.py` | the graduation aggregate reports `PASS` while carrying a `NOT_ESTABLISHED` dissent | it reports `FAIL` and its blocked rows are visible; no `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW` refusal |

The claim vocabulary gains `RISK_ACCEPTED` and a `reconciliation` record. A claim
derived from a `CONTRADICTED` ETP-0 verdict may move only to `RISK_ACCEPTED` or
`SUPERSEDED`, only with:

- `resolution_owner: ETP-T15`;
- `original_verdict` equal to the recorded ETP-0 verdict;
- both original parties preserved;
- a tracked historical copy and a tracked superseding record, both digest-checked;
- at least one open obligation for `RISK_ACCEPTED` (an acceptance with nothing
  open is a positive claim and is refused).

`ESTABLISHED`, `PARTIAL` and `SAFE_COMPATIBLE` are not reachable through a
reconciliation; a moved claim that tries is refused as
`EG_RECONCILIATION_PROMOTION`.

### 5.1 Two-direction demonstration

**Repaired record accepted.** `python3 forensics/tools/etp_claims.py validate`
returns `valid: true`, 0 refusals, 35 claims at the reconciliation identity; the
four claims carry bound reconciliations whose historical and superseding records
re-derive. `release_gate.py --graduation` no longer emits
`RG_CLAIM_CONTRADICTED` for `-004`, `-005`, `-030` or `-032`.

**Old assertion still refused.** The ETP-5 probe
`evidence/etp5/probes/p1-openssh-graduation-promotion.json` still types the
promotion as `SAFE_COMPATIBLE`, and the validator still refuses it with
`EG_GRADUATED_WITH_OPEN_OBLIGATION` and `EG_GRADUATED_WITHOUT_CLOSURE`. A claim
that sets `SAFE_COMPATIBLE` over the b85c record is refused by the same rules; a
reconciliation block is not permitted to raise a `CONTRADICTED` claim to it
(`EG_RECONCILIATION_PROMOTION`). The gate's self-test gains that direction.

**Closure discipline both ways.** The live risk-acceptance record reports `FAIL`
and is accepted; the historical `SAFE_COMPATIBLE` bytes, audited as a record,
still produce `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW` because they report `PASS`
while carrying the `NOT_ESTABLISHED` dissent.

**Independence both ways.** The risk-acceptance assignment asserts no
independence and produces no independence refusal; the historical
`SAFE_COMPATIBLE_RELEASE` shape and the adjudication's unsupported independence
assertion are still refused.

---

## 6. Non-claims

- This reconciliation does not establish `SAFE_COMPATIBLE` for any family, any
  mechanism discharge, any compatibility result or any cryptographic result.
- It does not re-run the b85c closure, the L7 workloads or any instrument.
- It does not establish the adjudication's independence; it records that the
  independence is not established.
- It does not make the Phase-18 failing court pass or close the open contract
  unit.
- It does not repair the `artifacts/phase18/COURTS.json#claim` field; that defect
  is recorded.
- `RISK_ACCEPTED` is not a pass and is not a graduation. A release still requires
  the §7 closure, and the release gate still refuses `SAFE_COMPATIBLE` without it.
- The historical copies are the record of what was asserted; this document is
  the record of what the evidence supports.
