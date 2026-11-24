# Suppression governance: a suppressed finding remains a finding

This document is the normative description of how the project treats a suppression.
The implementation is `forensics/tools/suppression_governance.py`; the controls are
`forensics/tools/tests/test_suppression_governance.py`; the recorded evidence is
`evidence/a6/{SUPPRESSIONS,INVALIDATION,CONTROLS}.json`, produced deterministically by
`evidence/a6/build_evidence.py`. The receipt is `evidence/a6/RECEIPT.md`.

`docs/FINDING-IDENTITY.md` is normative for rule, logical and exact identity;
`docs/COMPLETENESS-ADMISSION.md` is normative for what a record's population admits;
`docs/SARIF-PROFILE.md` §4.4 records that A1 never emits `result.suppressions`. This
document is normative for a narrower question: **when a finding is suppressed, what
must the record establish, and what may a reader conclude?**

## 1. The problem

A suppression is the most direct way to make a finding stop being visible without
making it stop being true. Five recorded habits do the damage, and every one has a
real form in tracked evidence:

* **An aggregate read as a census.** `evidence/etp-t4/SAFETY-SITES.json` states 1,999
  suppressions with a per-lint partition and no member row. The number can be quoted;
  no suppressed diagnostic can be named, reviewed or re-read (A0 finding F02, and the
  `AGGREGATE_ONLY` admission in `docs/COMPLETENESS-ADMISSION.md` §6).
* **A token list read as a member list.** `evidence/etp-t3/SPECIFICATIONS.json`
  records five known-nonconformance entries whose member lists are identifier tokens.
  A token may cover many occurrences; it is a key, not a finding identity.
* **A role read as a reviewer.** The only reviewer-shaped field in the OpenSSH risk
  acceptance is `classification.decided_by = "decision-maker (campaign principal)"`.
  The party accepting a risk is not the party reviewing it (Article 5), and no
  tracked record establishes that string as a reviewer.
* **An acceptance with no expiry.** Every real suppression-shaped record in the tree
  states no expiry, and none declares itself unbounded. The absence is silent, so a
  permanent acceptance is indistinguishable from one that was never finished.
* **A disposition read as an absence.** A1 emits a superseded disposition with
  `superseded: true` and the finding still in the emission; the profile forbids
  `result.suppressions` precisely because an absent and an empty suppression list
  mean different things.

The rule is singular:

> A suppressed finding remains a finding. Suppression is a disposition of a finding
> that is still in the population, never an absence from it.

## 2. The rule

A suppression must carry, for a reader who was not present when it was made:

1. the **identity it targets**, and which of the three identity levels the target is
   (`rule`, `logical` or `exact`);
2. the **scope it is authorised at**, which may never be broader than its target;
3. a **justification** that states why the disposition is acceptable;
4. a **reviewer identity token** and **where that token is recorded**;
5. the **time it was made**;
6. an **expiry**, or an explicit declaration that it is unbounded -- which is itself a
   finding, never a silent default;
7. the **policy basis** it was authorised under;
8. the **member findings** it disposes of, by identity, and whether those members are
   recorded.

A suppression that fails any of these is `NON_ACTIONABLE`: it is present in the
register, it is refused, and it suppresses nothing. Refusing it is not the same as
deleting it. The finding it names is still in the population and is counted as
unsuppressed (`reconcile` returns `suppressed=0` and `unsuppressed=enumerated` for the
recorded register). Enforced by `test_no_real_suppression_is_actionable` and
`test_the_reconciliation_balances_and_removes_nothing`.

## 3. Identity levels and what each scope licenses

The three identities are A3's, and they are not interchangeable:

| target level | construction | a suppression at this level disposes of | it does not dispose of |
|---|---|---|---|
| `rule` | `SHA-256("a1-rule/v1" NUL ruleId)` | the class, within the stated scope and artefact | one occurrence, one logical finding, or any finding outside the artefact the record names |
| `logical` | `SHA-256("a1-logical/v1" NUL ruleId NUL logicalKey)` | the same underlying finding across locations and runs | any one exact occurrence: a logical match is not `same-occurrence` |
| `exact` | `SHA-256("a1-exact/v1" NUL ruleId NUL logicalKey NUL subjectUri NUL digestScope ":" digest NUL regionKey)` | this occurrence, in this artefact, at this digest, for this candidate | another occurrence, another artefact, or the same finding at another candidate |

The **authorised scope** is the maximum reuse the record claims. It is refused when it
exceeds the target: a `rule`-scoped suppression of one exact occurrence covers findings
it never named (`SG_REFUSED_UNBOUNDED_SCOPE`), and an `exact`-scoped use of a logical
target would let a second exact occurrence inherit the first one's disposition
(`SG_REFUSED_LOGICAL_AS_EXACT`). A target level of `none` -- a record that names no
identity at all -- is refused with `SG_REFUSED_TARGET_NOT_IN_POPULATION` and, when it
claims any scope, `SG_REFUSED_UNBOUNDED_SCOPE`.

This is the A3 reuse prohibition applied to dispositions: `Permit.authorises_exact_reuse`
is false for `same-logical-finding` and for `code-motion`, so neither transfers a
suppression from one exact occurrence to another. Enforced by
`test_a_scope_broader_than_its_target_is_refused`,
`test_logical_scope_cannot_authorise_a_second_exact_occurrence` and
`test_a_cross_artefact_member_is_refused`.

## 4. The required fields

`forensics/tools/suppression_governance.py` records, per suppression:

| field | what it must establish | refused with |
|---|---|---|
| `id` | a stable name for the record | construction error (no code) |
| `record`, `locator`, `recordSha256` | the tracked record, the JSON locator in it, and the digest of its bytes | `SG_REFUSED_TARGET_NOT_IN_POPULATION` when the record or locator is absent |
| `target.scope`, `target.identity` | the identity and which level it is | `SG_REFUSED_TARGET_NOT_IN_POPULATION` |
| `authorisedScope` | the maximum reuse claimed | `SG_REFUSED_UNBOUNDED_SCOPE`, `SG_REFUSED_LOGICAL_AS_EXACT` |
| `justification` | non-empty text stating why the disposition is acceptable; a remediation plan is not a justification | `SG_REFUSED_NO_JUSTIFICATION` |
| `reviewer`, `reviewerRecordedIn` | a token plus the record that establishes it as a reviewer | `SG_REFUSED_NO_REVIEWER`, `SG_REFUSED_UNRECORDED_REVIEWER` |
| `recordedAt` | when the suppression was made | not refused directly; a record with no time cannot be checked against a policy change or an expiry |
| `expiresAt`, `unbounded` | the expiry, or an explicit unbounded declaration | `SG_REFUSED_NO_EXPIRY`; an expiry at or before the evaluation date is `SG_REFUSED_EXPIRED` |
| `policyBasis`, `policyToken` | the policy that permitted the suppression | no direct refusal; the policy-change trigger cannot run without an identity, and is recorded `NOT_RUN` |
| `memberIds`, `membersRecorded` | the findings actually disposed of | `SG_REFUSED_NO_MEMBER_IDENTITIES` |
| `candidate` | the candidate identity the suppression was made against | `SG_REFUSED_STALE_CANDIDATE` |
| `artefact` | the binding the suppression names | `SG_REFUSED_CROSS_ARTEFACT_INHERITANCE` when a member is bound elsewhere |

`Suppression.from_dict` refuses a missing member list with
`SG_REFUSED_NO_MEMBER_IDENTITIES` and a missing target with
`SG_REFUSED_TARGET_NOT_IN_POPULATION`; it never defaults a field. Enforced by
`test_the_reader_refuses_a_missing_member_list` and
`test_the_reader_refuses_a_record_with_no_target`.

### 4.1 The reviewer register

A reviewer token is **recorded** when a tracked record under `evidence/**/*.json`
carries it in a `reviewer` field. The register is bounded (files above 40,000,000 bytes
are skipped), sorted, and excludes `evidence/a6/` so this item cannot establish a
reviewer by citing itself. A token whose only occurrences are guard control fixtures
(`/controls/`) is not established: a fixture proves the guard works, it does not review
a real suppression. A `decided_by` field is not a reviewer field: the accepting party
and the reviewing party are different roles (Article 5). At the base commit the
register holds 10 tokens, all role descriptions such as "independent adjudicator (not
the author)". That is a real limit: a recorded role description is not an independent
identity, and A6 checks that the token exists, not that the independence claim is true
(Article 5 remains a separate obligation).

## 5. The dispositions

Every disposition keeps the finding in the population.

| disposition | what it licenses | what it does not license |
|---|---|---|
| `ACTIVE` | all required fields are established and the suppression disposes of its members, which remain in the population | that the finding is false, fixed, unreachable or safe; an active suppression is an accepted disposition, not a result |
| `EXPIRED` | the suppression was valid until its expiry and no longer authorises a disposition; the finding is still there | that the suppression never existed; the record and its history remain |
| `INVALIDATED` | a recorded trigger changed the identity the suppression was bound to; the record states why it no longer authorises a disposition | that the finding entered or left the population; invalidation is a disposition of the suppression, not of the finding |
| `NON_ACTIONABLE` | the record cannot be read as a governed suppression because a required field is missing or contradicted; its findings are unsuppressed | that the record is absent, or that its findings are absent; the record is present and refused |
| `PENDING_REVIEW` | the record was submitted and no review has established it; the finding is not suppressed | a provisional acceptance; a pending suppression authorises nothing |

A record with any refusal code is never `ACTIVE`. Enforced by
`test_a_suppressed_finding_dropped_from_the_population_is_refused` and
`test_expiry_changes_the_disposition_to_expired_not_invalidated`.

## 6. Invalidation triggers

A suppression auto-invalidates on seven triggers. Each returns an `Invalidation` with
a status (`FIRED`, `NOT_FIRED` or `NOT_RUN`), the resulting disposition and a reason
that cites the identity that changed. `invalidate` never deletes the finding or the
record; `apply_invalidation` appends the reason to the record and keeps the prior
record recoverable (Article 10). Enforced by
`test_invalidation_records_a_reason_and_deletes_nothing` and one test per trigger in
`InvalidationTriggerTests`.

| trigger | the identity that changes | disposition | a trigger that cannot run |
|---|---|---|---|
| `candidate-identity-change` | the candidate the suppression was recorded against | `INVALIDATED` | `NOT_RUN` when the current candidate is unavailable |
| `source-tree-digest-change` | the digest of the tree the finding was observed in | `INVALIDATED` | `NOT_RUN` when the current tree digest was not recomputed |
| `tool-identity-change` | the analyser that produced the finding | `INVALIDATED` | `NOT_RUN` when the record and the current identity name different instruments |
| `expiry` | the recorded expiry date | `EXPIRED` | `NOT_RUN` when no expiry is recorded; `SG_REFUSED_NO_EXPIRY` applies |
| `target-absent-from-population` | the target's presence in the finding population | `INVALIDATED` | `NOT_RUN` when no population is supplied |
| `new-occurrence-at-logical-identity` | a new exact occurrence at the logical identity | `INVALIDATED` | `NOT_RUN` when the record states no logical identity |
| `policy-basis-change` | the policy that permitted the suppression | `INVALIDATED` | `NOT_RUN` when the record states no policy-basis identity |

A `NOT_RUN` trigger is deferred, never passed (Article 3). Enforced by
`test_an_unrecorded_identity_is_not_run_rather_than_fired`.

## 7. The refusal codes

Every code is stable and is cited verbatim by the tool, the tests, the receipt and this
document. The third column is the wrong conclusion the code prevents.

| code | condition | prevents |
|---|---|---|
| `SG_REFUSED_SUPPRESSION_AS_ABSENCE` | a suppressed finding is dropped from the population or counted as absent because it is suppressed | that suppressing a finding removes it, so the population and the register disagree while the total appears to fall |
| `SG_REFUSED_NO_MEMBER_IDENTITIES` | the record states a total but no member identity, or records member locators that are not the findings it disposes of | that an aggregate is a census; a number with no member row cannot be reviewed, re-read or checked |
| `SG_REFUSED_NO_JUSTIFICATION` | no reason the suppression is acceptable is recorded | that a suppression is justified because it exists, and that a remediation plan is a justification |
| `SG_REFUSED_NO_REVIEWER` | the record names nobody who reviewed the suppression | that a suppression was reviewed because it was written down; an author's own record is not a review |
| `SG_REFUSED_UNRECORDED_REVIEWER` | the reviewer token is not established by a tracked record as a reviewer | that a role description is a reviewer identity; an invented reviewer is a false independence claim |
| `SG_REFUSED_NO_EXPIRY` | no expiry is recorded, or the record declares itself unbounded | that a permanent suppression is a governed one; without an expiry a stale acceptance is read as current |
| `SG_REFUSED_EXPIRED` | the recorded expiry is at or before the evaluation date but the suppression is presented as active | that a lapsed acceptance still authorises a disposition |
| `SG_REFUSED_UNBOUNDED_SCOPE` | the authorised scope is broader than the identity the record targets | that a suppression of one occurrence or one logical finding authorises a rule, an artefact or a tree |
| `SG_REFUSED_LOGICAL_AS_EXACT` | a logical target is used to authorise an exact occurrence | that one occurrence's disposition transfers to a different occurrence of the same logical finding |
| `SG_REFUSED_CROSS_ARTEFACT_INHERITANCE` | a suppression is applied to a member bound to a different artefact than the one it records | that a suppression of a finding in one artefact disposes of a finding in another |
| `SG_REFUSED_STALE_CANDIDATE` | the candidate is not recorded, or differs from the candidate under evaluation | that an acceptance at one candidate governs another |
| `SG_REFUSED_TARGET_NOT_IN_POPULATION` | no target identity is recorded, or the target is not in the finding population | that a suppression targets a finding that exists; a suppression of everything targets everything |
| `SG_REFUSED_INVALIDATED` | the recorded disposition is `INVALIDATED`, or a recorded invalidation fired | that an invalidated suppression remains in force, or that invalidation deleted the finding or the record |
| `SG_REFUSED_COUNT_UNBALANCED` | a member is counted twice, a stated member count disagrees with the member list, or suppressed plus unsuppressed does not equal the population | that the register accounts for the population when its parts do not add up |

Every code has at least one control in `evidence/a6/CONTROLS.json`; the mapping is one
control per code plus a policy-change control, enforced by
`test_the_controls_cover_every_code`.

## 8. The real register and its verdicts

`evidence/a6/SUPPRESSIONS.json` records every suppression-shaped record in a tracked
record, with the fields the record actually states and the disposition it is admitted
at. The register holds 11 records: 8 suppressions and 3 records read and classified as
not suppressions. **No real suppression is actionable.** The verdicts are:

| record | locator | target | members | reviewer | expiry | disposition | refusal codes |
|---|---|---|---:|---|---|---|---|
| `t4-suppressions` | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions` | none | 1999 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_UNBOUNDED_SCOPE`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t4-test-modules` | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions/test_modules` | none | 550 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_UNBOUNDED_SCOPE`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t3-known-nonconformance-agents-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/0` | rule | 17 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t3-known-nonconformance-docs-etp-todo-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/1` | rule | 89 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t3-known-nonconformance-docs-ownership-model-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/2` | rule | 1 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t3-known-nonconformance-docs-parity-model-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/3` | rule | 1 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t3-known-nonconformance-docs-hazard-register-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/4` | rule | 14 | no | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_NO_JUSTIFICATION`<br>`SG_REFUSED_NO_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `openssh-risk-acceptance-b85c` | `evidence/SAFE-COMPATIBLE-openssh-b85c.json` `/accepted_obligations` | none | 15 | yes | none | NON_ACTIONABLE | `SG_REFUSED_TARGET_NOT_IN_POPULATION`<br>`SG_REFUSED_NO_MEMBER_IDENTITIES`<br>`SG_REFUSED_UNRECORDED_REVIEWER`<br>`SG_REFUSED_NO_EXPIRY`<br>`SG_REFUSED_UNBOUNDED_SCOPE`<br>`SG_REFUSED_STALE_CANDIDATE` |
| `t10-closure-exclusions` | `evidence/etp-t10/EXCLUSIONS.json` `/rows` | none | 1121 | no | none | NON_ACTIONABLE | — |
| `a1-superseded-disposition` | `evidence/a1/SARIF.json` `/runs/2/results/210` | exact | 1 | no | none | NON_ACTIONABLE | — |
| `t3-spec-guard-control-fixture` | `evidence/etp-t3/SPECIFICATIONS.json` `/controls/0/exemptions/0` | none | 1 | yes | none | NON_ACTIONABLE | — |

Totals, read from `evidence/a6/SUPPRESSIONS.json`:

| measure | count |
|---|---|
| records | 11 |
| suppressions | 8 |
| not suppressions | 3 |
| actionable | 0 |
| `ACTIVE` | 0 |
| `EXPIRED` | 0 |
| `INVALIDATED` | 0 |
| `NON_ACTIONABLE` | 11 |
| `PENDING_REVIEW` | 0 |

The eight suppressions are refused for eight codes. The counts by code are: 8
`SG_REFUSED_TARGET_NOT_IN_POPULATION`, 8 `SG_REFUSED_NO_MEMBER_IDENTITIES`, 8
`SG_REFUSED_NO_EXPIRY`, 8 `SG_REFUSED_STALE_CANDIDATE`, 7
`SG_REFUSED_NO_JUSTIFICATION`, 7 `SG_REFUSED_NO_REVIEWER`, 3
`SG_REFUSED_UNBOUNDED_SCOPE` and 1 `SG_REFUSED_UNRECORDED_REVIEWER`.

**All eight are aggregate or token-level records with no finding population behind
them.** The 1,999 suppressions have no member row; the 550 test modules are regions,
not findings; the 122 known-nonconformance tokens are keys, not findings; and the 15
accepted obligations are obligations, not findings. `reconcile` therefore reports
`suppressed=0` and `unsuppressed=4245` over the A1 population: the suppressed findings
are not in that population, and the register does not manufacture them.

### 8.1 The invalidation result at the base commit

`evidence/a6/INVALIDATION.json` evaluates all seven triggers for all 11 records at
candidate `63dab01cf35a2ea7a643a67a2bf1c6b07608b0f9` (as-of `2026-11-24`, read from
`git rev-parse HEAD` and `git show -s --format=%cs HEAD`).

| trigger | fired | not fired | not run |
|---|---:|---:|---:|
| `candidate-identity-change` | 8 | 0 | 3 |
| `source-tree-digest-change` | 0 | 0 | 11 |
| `tool-identity-change` | 0 | 2 | 9 |
| `expiry` | 0 | 0 | 11 |
| `target-absent-from-population` | 8 | 0 | 3 |
| `new-occurrence-at-logical-identity` | 0 | 0 | 11 |
| `policy-basis-change` | 0 | 0 | 11 |

All 8 suppressions are `INVALIDATED`: their recorded candidate is not the candidate
under evaluation, and their target is absent from the finding population. The tool
identity is unchanged for the two `etp-t4` records (the recorded
`scanner_sha256` equals the current file digest) and `NOT_RUN` for the other nine
because they record no instrument, or a different one. The source-tree, expiry,
new-occurrence and policy triggers are `NOT_RUN`, not passed: no current tree digest
was recomputed, no expiry is recorded, no logical identity is recorded, and no
policy-basis identity is recorded.

## 9. Records examined and why they are not suppressions

A record that removes no finding from a population is not a suppression in this model,
and it is recorded with the reason rather than forced into the refusal table:

* **`evidence/etp-t10/EXCLUSIONS.json` (`t10-closure-exclusions`).** An exclusion row
  argues that a closure edge is outside the conservative upper bound, with a reason, a
  procedure and a checkable result. All 1,121 rows remain in the population, 377 pass
  the closure bar and 744 fail it, and A5 admits the row-set as `COMPLETE`. It removes
  no finding, so it is not a suppression. Its own bar is the appropriate check.
* **`evidence/a1/SARIF.json` (`a1-superseded-disposition`).** The superseded
  disposition is emitted with `superseded: true` and its exact identity
  (`/runs/2/results/210`). It is a disposition of a finding that remains present, which
  is the model's rule, but it suppresses nothing: A1 emits no `result.suppressions`.
* **`evidence/etp-t3/SPECIFICATIONS.json` (`t3-spec-guard-control-fixture`).** The only
  exemption with a reviewer is a guard fixture. It proves the exemption mechanism
  accepts a justified exemption; it disposes of no real finding. Its `reviewed` field
  is a commit token (`794a7c549`), not a date, which is recorded verbatim and not read
  as the time the exemption was made.

Real spec-guard exemptions are zero: all 10 registered specifications have an empty
`exemptions` array. The 122 tokens of the five known-nonconformance entries are
suppressions of `SP_INTERNAL_IDENTIFIER` refusals, which is why they are in the register
and refused rather than dismissed.

## 10. Controls and measured figures

`evidence/a6/CONTROLS.json` records 15 controls over the 14 refusal codes -- one per
code, plus a policy-change control that asserts the invalidation trigger produces
`SG_REFUSED_INVALIDATED` -- each built in memory from the A1 finding population.
`evidence/a6/INVALIDATION.json` records one synthetic control per trigger; all seven
fire.

| control | kind | code asserted |
|---|---|---|
| `suppression-as-absence` | reconciliation | `SG_REFUSED_SUPPRESSION_AS_ABSENCE` |
| `aggregate-read-as-census` | admission | `SG_REFUSED_NO_MEMBER_IDENTITIES` |
| `no-justification` | admission | `SG_REFUSED_NO_JUSTIFICATION` |
| `no-reviewer` | admission | `SG_REFUSED_NO_REVIEWER` |
| `unrecorded-reviewer` | admission | `SG_REFUSED_UNRECORDED_REVIEWER` |
| `no-expiry` | admission | `SG_REFUSED_NO_EXPIRY` |
| `expired-read-as-active` | admission | `SG_REFUSED_EXPIRED` |
| `unbounded-scope` | admission | `SG_REFUSED_UNBOUNDED_SCOPE` |
| `logical-as-exact` | admission | `SG_REFUSED_LOGICAL_AS_EXACT` |
| `cross-artefact-inheritance` | admission | `SG_REFUSED_CROSS_ARTEFACT_INHERITANCE` |
| `stale-candidate` | admission | `SG_REFUSED_STALE_CANDIDATE` |
| `target-absent-from-population` | admission | `SG_REFUSED_TARGET_NOT_IN_POPULATION` |
| `invalidated-read-as-active` | admission | `SG_REFUSED_INVALIDATED` |
| `count-unbalanced` | reconciliation | `SG_REFUSED_COUNT_UNBALANCED` |
| `policy-change` | invalidation | `SG_REFUSED_INVALIDATED` |

Measured quantities:

| quantity | measured |
|---|---|
| suppression-shaped records read | 11 |
| suppressions | 8 |
| actionable suppressions | 0 |
| refusal codes | 14 |
| controls | 15, covering 14 codes |
| invalidation triggers | 7 |
| invalidation controls | 7, all fired |
| recorded suppressions invalidated at the base candidate | 8 |
| finding population | 4,245 exact identities, 4,066 logical, 24 rules |
| reconciliation | suppressed 0, unsuppressed 4,245, balanced |
| new `unittest` controls | 68 |

The reconciliation refuses an absence, a duplicate count and a stated count that
disagrees with the member list. Enforced by
`test_an_unbalanced_reconciliation_is_refused`,
`test_a_population_that_does_not_match_its_second_statement_is_refused` and
`test_a_suppressed_finding_dropped_from_the_population_is_refused`.

## 11. Non-claims

* A suppression is not a safety, compatibility or cryptographic result. It records a
  decision, not a finding about the code.
* An `ACTIVE` suppression does not make a finding false. Identity and disposition are
  not truth, and the model says nothing about reachability or severity (Article 1).
* An `INVALIDATED` suppression does not make a finding not exist. The finding remains
  in the population and the record remains in the register (Article 10).
* `NON_ACTIONABLE` does not say the record is wrong or that the suppression was
  unnecessary. It says the record does not establish the fields a governed suppression
  requires, so it authorises nothing.
* A reviewer token proves that a tracked record carries the string, not that the
  reviewer is independent, competent or a different party (Article 5).
* The `NOT_RUN` triggers are deferred, never passed. No source-tree digest was
  recomputed and no policy-basis identity is recorded, so neither trigger can be said
  to have been evaluated.
* The finding population used for reconciliation is the A1 emission, not the
  population the lint suppressions apply to. The suppressions are refused because they
  name no target identity, not because the lint diagnostics are A1 findings.
* This document does not change any record it reads. It reads them.

## 12. `NOT_RUN`

* **Independent review.** The author of the tool, the document and the controls is not
  an independent reviewer, and no third party has reviewed the field-to-code mapping.
* **BOUNDARY and SEAL.** No caller or dependency-closure audit of the register readers,
  no sanitizer or Miri run (the item is Python only), and no held-out verification.
* **Recomputing the source-tree digest.** The scanner's tree digest was not recomputed,
  so `source-tree-digest-change` is `NOT_RUN` for every record.
* **The policy-basis identity.** No record states a policy digest, so the
  `policy-basis-change` trigger cannot be evaluated and is `NOT_RUN`.
* **New occurrences.** No real suppression records a logical identity, so
  `new-occurrence-at-logical-identity` is `NOT_RUN`.
* **Reviewer independence.** The register establishes that a token exists. Article 5
  independence is not established, and no reviewer was invented to fill a gap.
* **The suppressions' own populations.** The 1,999 lint suppressions, the 122 tokens,
  the 550 test regions and the 15 obligations are not member censuses of findings, and
  this item does not reconstruct them.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test` was run.

## 13. Reproducing the evidence

```
python3 evidence/a6/build_evidence.py            # writes the three JSON records
python3 -m json.tool evidence/a6/SUPPRESSIONS.json
python3 -m json.tool evidence/a6/INVALIDATION.json
python3 -m json.tool evidence/a6/CONTROLS.json
python3 forensics/tools/suppression_governance.py register
python3 forensics/tools/suppression_governance.py admit <id>
python3 forensics/tools/suppression_governance.py invalidate <id> --trigger <trigger>
python3 forensics/tools/suppression_governance.py reconcile
python3 -m unittest discover -s forensics/tools/tests -p test_suppression_governance.py
```

The producer reads every record and every count, asserts the design expectations, and
stops rather than writing a number it did not read. Re-running it at the recorded
candidate (`--candidate <commit> --as-of <date>`, taken from the document's own
`currentIdentity`) reproduces the three files byte-for-byte; the control is
`test_the_producer_is_deterministic`. A run at a later HEAD evaluates the suppressions at
that candidate and legitimately records different `STALE_CANDIDATE` reasons, which is
the point of the trigger.
