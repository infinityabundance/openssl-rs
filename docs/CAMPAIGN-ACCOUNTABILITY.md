# Campaign accountability: an opening, bound amendments, and one terminator

This document is the normative description of **B3** (`docs/ETP-ADDENDUM-B.md`
§B.13–B.14, §B.30). It describes the mechanism implemented in
`forensics/tools/campaign.py`, the controls in
`forensics/tools/tests/test_campaign.py`, and the records in `evidence/b3/`.

The rule is temporal and omission-sensitive:

> A campaign that publishes only what passed is indistinguishable, from the
> published results alone, from a campaign in which nothing failed. Freeze the
> plan **before** the work, close against it **after** the work, and refuse a
> closure that leaves an applicable failure absent. A campaign may close with
> failures recorded; it may not close with failures missing.

## 1. The problem

A producer chooses what to publish. It can report the six checks that passed and
silently omit the one that failed, the one that was never run, and the one that
was skipped. A reader who inspects only the published outcomes sees a
well-formed, internally consistent set — and cannot see the omission, because
there is no claim to contradict.

Nothing in a single claim, a signature, an inclusion proof or a summary count
detects a claim that was never written. The defence is a plan that existed
before the results:

- the **opening** records what the campaign promised to check;
- the **closure** accounts for every planned check, including the failures;
- the **reconciliation** compares that plan with a plan the campaign does not
  own.

## 2. The opening contract

An opening is `{campaignId, openedAt, plan: [{checkId, description, required}]}`.
It is the campaign's own frozen scope. `openedAt` is a declared instant, not a
clock reading; the producer writes literals so the record is reproducible.

- Every `checkId` is unique. A repeated id is refused
  (`AC_REFUSED_MANIFEST_INVALID`; enforced by the `manifest-invalid` control).
- The plan is non-empty. A campaign with no checks is not a campaign
  (`AC_REFUSED_MANIFEST_INVALID`; enforced by the `manifest-invalid` control).
- `required` is explicit. A closure must account for every required check; an
  optional check may be omitted only when the summary's counts say so.
- A campaign with no opening is refused
  (`AC_REFUSED_NO_OPENING`; enforced by the `no-opening` control).
- Two openings are refused
  (`AC_REFUSED_DOUBLE_OPENING`; enforced by the `double-opening` control). Two
  plans would let the campaign choose, after execution, which one it was always
  measuring.
- `opening.campaignId`, when present, must equal the campaign's id
  (`AC_REFUSED_MANIFEST_INVALID`).

## 3. The amendment contract

An amendment is `{at, reason, adds, removes, supersedes, by}`. It is a dated,
bound event, not an edit to the opening:

- `by` and `reason` are non-empty: an amendment names who made it and why.
- `adds` may introduce a new check (a string id, or a
  `{checkId, description, required}` entry). Adding an id the plan already
  contains is refused.
- `removes` may withdraw a planned check **prospectively**.
- `supersedes` records that a planned check's recorded plan entry was replaced
  (for example, a queue row's text changed). It keeps the id in the plan, so a
  closure still has to account for it.
- An amendment that adds, removes and supersedes nothing is unbound and refused
  (`AC_REFUSED_UNBOUND_AMENDMENT`; enforced by the `unbound-amendment` control
  and `test_an_amendment_that_binds_to_nothing_is_refused`).
- An amendment that names a check the plan does not contain is unbound and
  refused (`AC_REFUSED_UNBOUND_AMENDMENT`; enforced by
  `test_an_amendment_that_names_an_unplanned_check_is_refused`).

**Retroactivity.** An amendment may not rewrite history. It is refused
(`AC_REFUSED_RETROACTIVE_AMENDMENT`) when it:

- carries a non-empty `outcomeEdits` field;
- `supersedes` a check that has an outcome recorded in the closure or in the
  recorded closure history; or
- `removes` a check that has a recorded outcome.

Enforced by the `retroactive-amendment` control and by
`test_an_amendment_that_supersedes_an_outcome_is_retroactive`,
`test_an_amendment_that_removes_a_closed_check_is_retroactive` and
`test_an_amendment_that_edits_an_outcome_is_retroactive`.

**Order.** An amendment dated before the opening, or after the terminator, is
refused (`AC_REFUSED_ORDER`; enforced by the `amendment-after-terminator` control
and `test_an_amendment_before_the_opening_is_out_of_order`, and by the
`order-terminator` control and
`test_an_amendment_after_the_terminator_is_out_of_order`).

## 4. The terminator contract

A campaign is terminated by **exactly one** of:

- a **closure** `{at, outcomes, summary}`; or
- an **abandonment** `{at, reason, notDone: [{checkId, why}]}`.

- No terminator: the record is a valid **open** campaign and reports `OPEN`.
  A caller that asked for a finished record (`require_terminator=True`), or a
  record whose `state` claims a terminal state, is refused
  (`AC_REFUSED_NO_TERMINATOR`; enforced by the `no-terminator` and
  `claimed-closed-without-terminator` controls and
  `test_a_campaign_with_no_terminator_is_open_and_refused_only_when_required`).
- Two terminators — two closures, two abandonments, or one of each — are refused
  (`AC_REFUSED_DOUBLE_TERMINATOR`; enforced by the `double-terminator` control
  and `test_two_closures_are_refused` and
  `test_a_closure_and_an_abandonment_are_two_terminators`). Two terminators
  would let the campaign cite whichever one reads better.
- A terminator dated before its opening is refused
  (`AC_REFUSED_ORDER`; enforced by the `order-terminator` control and
  `test_a_terminator_before_its_opening_is_out_of_order`).
- An abandonment must carry a `notDone` entry with a `why` for **every required
  planned check**. A silent abandonment is refused
  (`AC_REFUSED_ABANDONMENT_SILENT`; enforced by the `abandonment-silent`
  control and `test_an_abandonment_that_omits_a_required_check_is_refused`).
- A record whose declared `state` disagrees with the state it validates to is
  refused (`AC_REFUSED_MANIFEST_INVALID`; enforced by
  `test_a_record_that_misnames_its_own_state_is_refused`).

## 5. The omission-sensitive closure

### 5.1 Outcomes

Each outcome is `{checkId, result, evidence, reason}` with `result` in
`PASS`, `FAIL`, `SKIP`, `NOT_RUN`. A `PASS` or `FAIL` carries evidence; a `SKIP`
or `NOT_RUN` carries a reason. An outcome without its required binding is
refused (`AC_REFUSED_MANIFEST_INVALID`; enforced by
`test_a_pass_without_evidence_is_not_an_outcome` and
`test_a_skip_without_a_reason_is_not_an_outcome`).

- An outcome for a check the plan never contained is refused
  (`AC_REFUSED_UNPLANNED_OUTCOME`; enforced by the `unplanned-outcome` control).
- Two outcomes for one check are refused
  (`AC_REFUSED_DUPLICATE_OUTCOME`; enforced by the `duplicate-outcome` control).
  A reader must not be able to choose between two results.

### 5.2 The exact rule

> **A failure may be recorded. It may not be omitted.**

A closure that records `FAIL` is valid and reports `CLOSED_WITH_FAILURES`
(enforced by `test_a_recorded_failure_is_accepted`). A closure that leaves a
required planned check absent is refused, even when the absent check is the one
that failed (`AC_REFUSED_OMITTED_CHECK`; enforced by the `omitted-check` control
and `test_a_closure_that_omits_the_failed_check_is_refused`).

A `SKIP` or `NOT_RUN` may also be recorded; both make the closure
`CLOSED_WITH_FAILURES` (`test_a_skip_recorded_without_a_success_claim_is_accepted`
and `test_a_not_run_recorded_without_a_success_claim_is_accepted`). They may
not be counted as success:

- a success summary over a recorded `FAIL` is refused
  (`AC_REFUSED_FAILURE_OMITTED`; enforced by the `failure-omitted` control);
- a success summary over a recorded `SKIP` is refused
  (`AC_REFUSED_SKIP_AS_PASS`; enforced by the `skip-as-pass` control and
  `test_skip_in_a_success_summary_is_refused`);
- a success summary over a recorded `NOT_RUN` is refused
  (`AC_REFUSED_NOT_RUN_AS_PASS`; enforced by the `not-run-as-pass` control and
  `test_not_run_in_a_success_summary_is_refused`).

### 5.3 Summary counts

The summary is `{text, claimsSuccess, counts}` with integer
`pass`, `fail`, `skip`, `notRun`, `planned`, `accounted`. The counts must equal
the outcome tallies, `planned` must equal the effective plan size, `accounted`
must equal the number of outcomes, and `accounted` must equal
`pass + fail + skip + notRun`. A summary whose counts do not reconcile is
refused (`AC_REFUSED_COUNT_MISMATCH`; enforced by the `count-mismatch` control
and `test_counts_that_do_not_reconcile_are_refused`).

### 5.4 Closure state

A closure is `CLOSED_CLEAN` only when every planned check has an outcome, every
outcome is `PASS`, and the summary claims success. Otherwise it is
`CLOSED_WITH_FAILURES`. A clean closure is a statement about the outcomes that
are present; it is **not** a success claim about the subject (see §9).

### 5.5 Recorded closure history

A campaign may carry a `closureHistory`: earlier closure records that it
preserves rather than erases. A history entry is not a terminator; it does not
make the campaign closed. It must be dated before the final terminator
(`AC_REFUSED_ORDER`) and its outcomes are validated structurally. It is how a
campaign whose observations changed after a repair keeps the earlier failure
visible. Each final outcome may also carry a `history` of its earlier results.

## 6. Reconciliation against an independent plan

`reconcile(campaign, independent)` compares the campaign's **effective plan**
(the opening after every amendment) with a plan the campaign does not own: the
A17 forward freeze, or a registry such as A22's eight experiments.

- A required independent check that the campaign plan does not contain means the
  plan was narrowed. Reconcile refuses it
  (`AC_REFUSED_PLAN_NARROWED`; enforced by the `plan-narrowed` control and
  `test_a_narrowed_plan_is_refused`). Recording the removal as an amendment
  does not make the omission disappear from the comparison.
- `produced` and `missing` are read from the independent plan's declared paths,
  or — for a plan with no path — from the campaign's recorded `PASS` outcomes.
  A produced member is not a pass: it is bytes at a path, or a recorded result.
- For an **open** campaign, produced/missing is explicitly a **live
  observation** (`liveView: true`), not a closure of the independent plan. The
  A17 forward freeze remains `OPEN`; nothing in this item closes it.
- A closed campaign also reports `notPassed`: the independent checks whose
  recorded outcome is not `PASS`. A recorded failure is reported, not refused.
  Reconciliation refuses a **narrowed plan**, not a recorded failure.

Enforced by `test_a_superset_plan_is_not_narrowed`,
`test_produced_and_missing_are_read_from_the_declared_paths` and
`test_a_closed_campaign_reports_checks_it_did_not_pass`.

## 7. The two real campaigns

### 7.1 `etp-programme` — `OPEN`

The **programme campaign** is the ETP programme itself.

| field | value |
|---|---|
| opening | the queue in `docs/ETP-TODO.md` at the A17 forward freeze's candidate `731b066e2` |
| opening instant | `2026-11-24T00:20:00Z` (`evidence/a17/FREEZE-forward.json#/frozenAt`) |
| plan | 86 queue rows, every one required |
| amendments | 16 — one per later commit that changed a queue row (adds, removes or supersedes derived from the queue text; the commit subject, author and date are recorded) |
| terminator | **none** |
| state | **`OPEN`** |

The campaign has **not closed**. The record says so, the CLI says so
(`code=AC_OPEN`), and the reconciliation does not close the A17 freeze either.
The produced/missing sets are a live observation at the recorded base: at the
time this record was produced, the forward freeze's A18–A27 receipts, B0's two
members and B1–B3 receipts were present, and B4–B8 were not. Those counts move
when a later item lands; the freeze's `STATUS.json` keeps its freeze-time facts.

### 7.2 `a22-adversarial-qualification` — `CLOSED_CLEAN`

A22 planned **eight experiments** as eight checks
(`evidence/a22/EXPERIMENTS.json`). It is closed with **8 `PASS`, 0 `FAIL`,
0 `SKIP`, 0 `NOT_RUN`**, from `evidence/a22/RESULTS.json` re-measured at
`e4029e0d5` after the repair recorded in `evidence/defects/e5-e6/RECEIPT.md`.

The **earlier closure is preserved, not erased**. The record carries a
`closureHistory` entry from `d3050312f`:

| id | earlier result | final result |
|---|---|---|
| E1–E4 | `PASS` | `PASS` |
| E5 | `FAIL` (verdict `DEFECT`, 0/3) | `PASS` (3/3) |
| E6 | `SKIP` (verdict `PARTIAL`, 1/2) | `PASS` (2/2) |
| E7–E8 | `PASS` | `PASS` |

The earlier summary is `6 qualified / 1 defect / 1 partial / 0 not-run;
allQualified=false; codes=AQ_DEFECT_FOUND`, and it is recorded as
`claimsSuccess: false`. Each final outcome carries the earlier result in its
`history`. `test_the_earlier_defect_and_partial_are_preserved` checks it.

This campaign is **reconstructed**: the plan text comes from
`EXPERIMENTS.json` and the opening instant from the item's recorded start
commit, so the record is an accountable summary of A22's records, not an
authenticated preregistration. `source.reconstructed` says so.

## 8. The controls

`evidence/b3/CONTROLS.json` holds **22 `control-only` fixtures**: one per
refusal code (with two controls for `AC_REFUSED_NO_TERMINATOR`,
`AC_REFUSED_ORDER` and `AC_REFUSED_MANIFEST_INVALID`, because different wrong
inputs reach them) and two positive controls. `coversEveryCode: true`.

The required controls are present and named:

- a closure that omits a failed check (`omitted-check`);
- a summary that calls a `SKIP` a pass (`skip-as-pass`);
- a `NOT_RUN` counted as a pass (`not-run-as-pass`);
- a retroactive amendment (`retroactive-amendment`);
- two terminators (`double-terminator`);
- an unplanned outcome (`unplanned-outcome`);
- a duplicate outcome (`duplicate-outcome`);
- a silent abandonment (`abandonment-silent`);
- an out-of-order terminator (`order-terminator`, plus
  `amendment-after-terminator`);
- a narrowed plan (`plan-narrowed`);
- the positive controls `positive-closed-clean` and
  `positive-closed-with-failures`.

A control that fires proves the refusal works. It is not a defect report and not
evidence that the substituted form occurs in the tree.

## 9. Non-claims

- **A clean closure is not a success claim.** `CLOSED_CLEAN` means every planned
  check has a `PASS` outcome and the summary claims success. It does not mean the
  checks were correct, sufficient, or independently reviewed, and it is not a
  safety, compatibility or cryptographic result.
- **An abandonment is not a closure.** `ABANDONED` records that the campaign did
  not finish and says which required checks were not done. It is not a clean
  result and not a failure result; it is an unfinished campaign made visible.
- **An open campaign is not a closed one.** `OPEN` is a state, not an omission
  defect. The programme campaign is open by design; its missing members are
  reported, not hidden.
- **The plan is only as good as the opening.** Reconciliation detects omission
  relative to an independent plan; it does not establish that the plan contained
  every check that mattered.
- **A recorded outcome is not authenticated.** The tool reads the outcome a
  record states. It does not verify the evidence path, the command or the
  result. There is no independent closer and no trust root here.
- **The programme record is a reconstruction of the queue, not a claim that the
  queue was complete.** It is derived from `docs/ETP-TODO.md` at a recorded
  commit.

## 10. The refusal table

Every code is stable. "Enforced by" names the control or test that fires it.

| code | wrong conclusion it prevents | enforced by |
|---|---|---|
| `AC_REFUSED_NO_OPENING` | a campaign with no frozen plan read as accountable | `no-opening` control, `test_no_opening_is_refused` |
| `AC_REFUSED_DOUBLE_OPENING` | two plans, so the later one can be chosen after execution | `double-opening` control, `test_two_openings_are_refused` |
| `AC_REFUSED_NO_TERMINATOR` | an unfinished campaign read as finished | `no-terminator`, `claimed-closed-without-terminator` controls, `test_a_campaign_with_no_terminator_is_open_and_refused_only_when_required` |
| `AC_REFUSED_DOUBLE_TERMINATOR` | a closure and an abandonment, so either can be cited later | `double-terminator` control, `test_two_closures_are_refused` |
| `AC_REFUSED_RETROACTIVE_AMENDMENT` | an amendment that rewrites an outcome already recorded | `retroactive-amendment` control, `test_an_amendment_that_supersedes_an_outcome_is_retroactive` |
| `AC_REFUSED_UNBOUND_AMENDMENT` | an amendment that binds to no planned check | `unbound-amendment` control, `test_an_amendment_that_binds_to_nothing_is_refused` |
| `AC_REFUSED_OMITTED_CHECK` | a closure that leaves a required planned check absent | `omitted-check` control, `test_a_closure_that_omits_the_failed_check_is_refused` |
| `AC_REFUSED_FAILURE_OMITTED` | a success summary over a recorded `FAIL` | `failure-omitted` control, `test_a_recorded_failure_is_accepted` |
| `AC_REFUSED_SKIP_AS_PASS` | a success summary over a recorded `SKIP` | `skip-as-pass` control, `test_skip_in_a_success_summary_is_refused` |
| `AC_REFUSED_NOT_RUN_AS_PASS` | a success summary over a recorded `NOT_RUN` | `not-run-as-pass` control, `test_not_run_in_a_success_summary_is_refused` |
| `AC_REFUSED_UNPLANNED_OUTCOME` | an outcome for a check the plan never contained | `unplanned-outcome` control, `test_an_outcome_for_an_unplanned_check_is_refused` |
| `AC_REFUSED_DUPLICATE_OUTCOME` | two results for one check, so a reader can choose | `duplicate-outcome` control, `test_a_duplicate_outcome_is_refused` |
| `AC_REFUSED_ABANDONMENT_SILENT` | an abandonment that does not say which required checks were not done | `abandonment-silent` control, `test_an_abandonment_that_omits_a_required_check_is_refused` |
| `AC_REFUSED_ORDER` | a closure before its opening, or an amendment after the terminator | `order-terminator`, `amendment-after-terminator` controls, `test_an_amendment_after_the_terminator_is_out_of_order` |
| `AC_REFUSED_COUNT_MISMATCH` | a summary whose counts do not reconcile with its outcomes | `count-mismatch` control, `test_counts_that_do_not_reconcile_are_refused` |
| `AC_REFUSED_PLAN_NARROWED` | a campaign that silently dropped a required independent check | `plan-narrowed` control, `test_a_narrowed_plan_is_refused` |
| `AC_REFUSED_MANIFEST_INVALID` | a malformed record read as a campaign | `manifest-invalid`, `unknown-result` controls, `test_an_unknown_result_is_refused` |

Non-refusal codes: `AC_OK`, `AC_USAGE`, `AC_INVALID`, `AC_OPEN`,
`AC_CLOSED_CLEAN`, `AC_CLOSED_WITH_FAILURES`, `AC_ABANDONED`.

**Prefix disjointness.** A5's completeness admission already owns the `CA_`
prefix. B3 uses `AC_` for both its refusal codes and its state codes, so no code
is shared across the two modules. `test_the_two_modules_do_not_share_a_code`
asserts the two sets are disjoint and that neither module emits the other's
prefix.

## 11. Enforcement map

| claim | enforced by |
|---|---|
| every refusal code has a control that observes it | `Controls.test_one_control_per_refusal_code_and_none_missed`, `build_controls()['coversEveryCode']` |
| a failure may be recorded | `test_a_recorded_failure_is_accepted`, `positive-closed-with-failures` |
| a failure may not be omitted | `test_a_closure_that_omits_the_failed_check_is_refused`, `omitted-check` |
| a `SKIP` or `NOT_RUN` cannot be a success | `skip-as-pass`, `not-run-as-pass`, the corresponding tests |
| an amendment cannot rewrite an outcome | `retroactive-amendment`, three `AmendmentRules` tests |
| exactly one terminator | `no-terminator`, `claimed-closed-without-terminator`, `double-terminator` |
| an abandonment says what was not done | `abandonment-silent`, `AbandonmentRules` |
| a plan may not be narrowed silently | `plan-narrowed`, `test_a_narrowed_plan_is_refused` |
| the two real campaigns are the states they claim | `RealCampaigns`, `EvidenceRecords` |
| the records are reproducible | `Determinism` (two runs byte-identical, `--check` accepted) |
| the document and the tool agree | `Documentation` (every code, both campaigns, the non-claims) |
| `AC_` and `CA_` do not collide | `test_the_two_modules_do_not_share_a_code` |

## `NOT_RUN`

- **An independent closer.** No independent party closed either campaign. The
  records are produced by the same tool that validates them.
- **An authenticated opening.** A22's opening is reconstructed from its records;
  it is not a DSSE-authenticated preregistration, and no transparency-log
  inclusion exists for it.
- **A closure of the A17 forward freeze.** It remains `OPEN` with no
  reconciliation. B3 reports a live produced/missing view; it does not close the
  freeze and does not replace `evidence/a17/RECONCILIATION-*`.
- **A trust root, a witness or a timestamp.** None exists here; the records are
  bookkeeping, not authenticated publication.
- **Independent review, a BOUNDARY audit and a SEAL.** None ran for this item.
- **A Rust build or test.** No Rust source was modified, so no `cargo` command
  and no Rust suite result is claimed.
- **Completeness of either plan.** The programme plan is the queue as written;
  A22's plan is its experiment registry. Whether either contained every check
  that mattered is a judgement no check here establishes.
