# Completeness admission: expected versus examined

This document is the normative description of how the project admits a population
at a completeness it has actually observed. The implementation is
`forensics/tools/completeness.py`; the controls are
`forensics/tools/tests/test_completeness.py`; the recorded evidence is
`evidence/a5/{POPULATIONS,ADMISSION,CONTROLS}.json`, produced deterministically by
`evidence/a5/build_evidence.py`. The receipt is `evidence/a5/RECEIPT.md`.

`docs/ETP-CLAIM-ALGEBRA.md` is normative for a claim's quantified population and
`docs/CLOSURE-DISCIPLINE.md` is normative for what an omitted closure edge must
carry. This document is normative for a narrower question: **given a population a
record states, was it examined, and at what completeness may that be said?**

## 1. The problem

A record can state a count, a sample, a truncation or a remainder, and a reader can
turn any of them into a completeness claim the record never made. Four habits do
the damage, and all four are present in tracked evidence:

* **An absent input read as a population of zero.** A record names a sidecar, an
  inventory or a candidate DSO that is not in the tree; the missing observation is
  read as "no members". Absence and zero are different facts.
* **An exit status read as completeness.** A harness exits zero after skipping,
  stopping early or running a subset. A zero exit says the process finished, not
  that everything was examined. The O10 negative control in `docs/ETP-TODO.md`
  records the concrete case: the harness exits 0 and prints a skip line.
* **A sample or a truncation read as a census.** `evidence/closure-curl-049.json`
  lists 200 residual sites against a recorded population of 449 (A0 finding F01,
  now bounded); `evidence/etp-t4/SAFETY-SITES.json` reports 1,999 suppressions with
  no member row (A0 finding F02).
* **A count with no denominator read as complete.** `evidence/etp6/MANIFEST.json`
  lists 1,633 verified inputs and states no expected package population (A0 finding
  F03); `courts/phase18/interop/MANIFEST-o11-A.json` reports 73 executed scripts
  and states no script population.

The rule is singular:

> A claim of completeness requires an expected population stated by a record, an
> examined count equal to it, no omitted members, and every examined member
> identified. Anything less is admitted at the weaker state it supports.

## 2. The states

Six base states answer the question. Two further states are needed because tracked
records actually take those shapes; both are **weaker** than `COMPLETE` and neither
licenses a completeness claim. Adding them narrows what may be claimed; it does not
widen the definition of complete.

| state | what it licenses | what it does not license |
|---|---|---|
| `COMPLETE` | every member of the declared population is present and identified; the expected count is stated by a record; examined equals it; nothing is omitted | anything about the tree the population was drawn from. A complete record-set is not a complete tree, and completeness is not correctness |
| `SAMPLED` | a declared selection rule drew the examined members from a stated expected population, and the examined members are identified | a census. The unexamined remainder is a remainder whose properties are unknown unless a bound names them |
| `TRUNCATED_BOUNDED` | an enumeration stopped at a stated bound or cap; the omitted remainder is counted and the selection rule is recorded | a census, or anything about the omitted members. The bound states how many were not examined, not what they would have shown |
| `ABSENT` | the record or the named input is not present, so nothing was examined and no member count follows | an empty population. Absence is a missing observation, not an observation of zero |
| `EMPTY` | the record is present and states that the population has zero members | an absent population. Zero examined is a result only when a record says the expected population is zero |
| `UNKNOWN` | the expected population is not stated, or the declaration is too weak to place it, so no completeness claim can be made | any count as complete, and any state stronger than itself |
| `AGGREGATE_ONLY` | a total is stated without the identity of the members; the count can be quoted and nothing can be reviewed or re-run from it | a census or a sample. A number with no member row is not an examined population |
| `DEFERRED` | nothing was examined and every omitted member is named, so the gap is known exactly and is not an absence | any result. A named not-run analysis is a declaration of a gap, never evidence of the property it would have measured |

`COMPLETE` and `EMPTY` both license "nothing is missing", but they are different
states with different consequences: `EMPTY` also records that the population was
examined and is zero. A declaration of `COMPLETE` over a population whose expected
count is zero is admitted **as `EMPTY`**, and the recorded state is `EMPTY`, never
`COMPLETE` (enforced by `test_a_complete_declaration_over_an_empty_population_is_admitted_as_empty`).

## 3. Permitted and forbidden transitions

The facts determine a **supported** state. A declaration is admitted when it claims
no more than the facts support; an under-claim is admitted at the supported state.

| declared | supported | outcome |
|---|---|---|
| any state | the same state | admitted |
| `COMPLETE` | `COMPLETE` | admitted |
| `COMPLETE` | `EMPTY` | admitted as `EMPTY` |
| `SAMPLED`, `TRUNCATED_BOUNDED` | `COMPLETE`, `EMPTY`, `SAMPLED`, `TRUNCATED_BOUNDED` | admitted at the supported state (an under-claim) |
| `UNKNOWN`, `AGGREGATE_ONLY`, `DEFERRED` | any present state | admitted at the supported state (an under-claim) |
| `COMPLETE` | `SAMPLED` | refused `CA_REFUSED_SAMPLE_AS_CENSUS` |
| `COMPLETE` | `TRUNCATED_BOUNDED` | refused `CA_REFUSED_TRUNCATION_AS_COMPLETE` |
| `COMPLETE` | `ABSENT` | refused `CA_REFUSED_ABSENT_AS_OBSERVED` |
| `COMPLETE` | `AGGREGATE_ONLY` | refused `CA_REFUSED_OMITTED_UNRECORDED` or `CA_REFUSED_MEMBER_UNIDENTIFIED` |
| `COMPLETE` | `DEFERRED` | refused `CA_REFUSED_OMITTED_UNRECORDED` |
| `COMPLETE` | `UNKNOWN` | refused `CA_REFUSED_UNKNOWN_AS_COMPLETE` or `CA_REFUSED_UNRECORDED_POPULATION` |
| `EMPTY` | `ABSENT` | refused `CA_REFUSED_ABSENT_AS_EMPTY` |
| `ABSENT` | `EMPTY` | refused `CA_REFUSED_EMPTY_AS_ABSENT` |
| `ABSENT` | any present state other than `EMPTY` | refused `CA_REFUSED_STATE_CONTRADICTED` |
| `EMPTY` | any state other than `EMPTY` | refused `CA_REFUSED_STATE_CONTRADICTED` |
| `SAMPLED`, `TRUNCATED_BOUNDED` | `ABSENT` | refused `CA_REFUSED_ABSENT_AS_OBSERVED` |
| `SAMPLED`, `TRUNCATED_BOUNDED` | `UNKNOWN` with no expected population | refused `CA_REFUSED_SAMPLE_WITHOUT_POPULATION` |
| no state named | any | refused `CA_REFUSED_STATE_UNDECLARED` |

The two directions of the absent/empty confusion are separate controls
(`absent-as-empty` and `empty-as-absent` in `evidence/a5/CONTROLS.json`) and two
tests that assert the positive half as well
(`test_absent_is_admitted_as_absent_and_not_as_empty`,
`test_empty_is_admitted_as_empty_and_not_as_absent`).

## 4. The rules

1. **Absent is not empty.** A population whose record or named input is not present
   is `ABSENT`; a population whose record states zero members is `EMPTY`. Presence
   must be recorded, not defaulted: a missing presence field is refused
   (`CA_REFUSED_UNRECORDED_POPULATION`), never read as present. Presence of a named
   sidecar is decided by `git ls-files`, and the deciding command is recorded in
   `presenceBasis`. Enforced by `test_a_missing_presence_is_refused_not_defaulted_to_present`
   and `CA_REFUSED_ABSENT_AS_EMPTY` / `CA_REFUSED_EMPTY_AS_ABSENT`.
2. **An exit status is not a population.** No count may be sourced from a process
   exit, and `from_exit_status` refuses unconditionally. A zero exit after a skip
   or an early stop is exactly the case the rule exists for: a scan that exits zero
   after stopping early is a truncation, and it is `TRUNCATED_BOUNDED` only if the
   record states the bound and counts the remainder. The exit status contributes
   nothing to either state. Enforced by `CA_REFUSED_EXIT_AS_COMPLETENESS` and
   `test_an_exit_status_cannot_stand_in_for_a_population`.
3. **A sample is not a census.** A declaration of `COMPLETE` where a selection rule
   drew the examined members is refused. Enforced by
   `CA_REFUSED_SAMPLE_AS_CENSUS`.
4. **A truncation carries its bound and its unrecoverable-omitted flag.** A
   truncation is admitted at `TRUNCATED_BOUNDED` only when the record states a cap
   or bound and counts the omitted remainder; an unbounded partial list with no
   bound is `UNKNOWN` or `AGGREGATE_ONLY`, never a census. Enforced by
   `CA_REFUSED_TRUNCATION_AS_COMPLETE` and `test_complete_over_a_truncation`.
5. **An expected population pre-exists the examined count.** An examined count is
   read as a fraction only when the same record states the expected population. A
   numerator without a denominator is refused, not assumed to be a sample of
   something known. Enforced by `CA_REFUSED_SAMPLE_WITHOUT_POPULATION` and
   `CA_REFUSED_UNRECORDED_POPULATION`.
6. **A census identifies its members.** A count whose members have no identity is
   `AGGREGATE_ONLY`; it cannot be re-read, deduplicated or checked. Enforced by
   `CA_REFUSED_MEMBER_UNIDENTIFIED` and `CA_REFUSED_OMITTED_UNRECORDED`.
7. **The counts partition.** `examined + omitted == expected`, and
   `examined <= expected`. A partition that does not add up is refused before any
   state is derived. Enforced by `CA_REFUSED_COUNT_INCONSISTENT`.
8. **A census counts each member once.** `distinctMembers` must equal `examined`
   where the record identifies its members. Enforced by
   `CA_REFUSED_DUPLICATE_MEMBER`.
9. **The declaration is bound to the bytes it read.** `verify_declaration` re-reads
   the native record and compares every count and every cited SHA-256. A changed
   record invalidates the admission; two declarations of one id that disagree are
   refused. Enforced by `CA_REFUSED_POPULATION_DRIFT` and
   `curl-edge-records` in `evidence/a5/ADMISSION.json`.
10. **A state must be declared.** The state is never inferred from the count, since
    the count is what is in question. Enforced by `CA_REFUSED_STATE_UNDECLARED`.
11. **A reader refuses, it does not default.** `read_population(document, locator)`
    requires every field; a missing expected count is not zero, a missing presence
    field is not present, and a missing omission flag is not "recorded". Enforced by
    `test_a_missing_expected_is_refused_not_defaulted_to_zero`,
    `test_a_missing_presence_is_refused_not_defaulted_to_present` and
    `test_a_missing_omitted_flag_is_refused`.

## 5. The refusal codes

Every code is stable and is cited verbatim by the tool, the tests and the receipt.
The second column is the condition; the third is the wrong conclusion the code
prevents.

| code | condition | prevents |
|---|---|---|
| `CA_REFUSED_ABSENT_AS_EMPTY` | an absent record or input is read as a population of zero | that a missing observation is an observation of nothing, so a tool that did not run is read as a tool that found no defect |
| `CA_REFUSED_EMPTY_AS_ABSENT` | an examined empty population is recorded as absent | that the examination did not happen, which discards a real zero result |
| `CA_REFUSED_ABSENT_AS_OBSERVED` | an absent population is presented as complete, sampled or otherwise observed | that members were examined when the record that would name them is not present |
| `CA_REFUSED_UNRECORDED_POPULATION` | no record states the expected population | that a count is a census because no other number was offered |
| `CA_REFUSED_EXIT_AS_COMPLETENESS` | an exit status is used as a population or as proof of completeness | that a zero exit means nothing was skipped |
| `CA_REFUSED_OMITTED_UNRECORDED` | members are omitted and the omission is neither identified nor bounded | that a total stands for the members |
| `CA_REFUSED_TRUNCATION_AS_COMPLETE` | a bounded enumeration is presented as a census | that every member was examined, when the bound says how many were not |
| `CA_REFUSED_SAMPLE_AS_CENSUS` | a declared sample is presented as a census | that the unexamined remainder shares the sample's property |
| `CA_REFUSED_UNKNOWN_AS_COMPLETE` | a population of unknown extent is presented as complete | that an unbounded observation is a bounded one |
| `CA_REFUSED_POPULATION_DRIFT` | two records state different populations for one subject, or the live record no longer matches the declaration | that a count read at one identity applies at another |
| `CA_REFUSED_COUNT_INCONSISTENT` | examined + omitted != expected, or examined > expected | that the stated parts account for the whole |
| `CA_REFUSED_DUPLICATE_MEMBER` | a census counts one member twice | that N distinct members were examined when fewer were |
| `CA_REFUSED_MEMBER_UNIDENTIFIED` | a count is stated but the examined members are not identified | that the count can be audited |
| `CA_REFUSED_SAMPLE_WITHOUT_POPULATION` | a sample reports its examined count before a record states its expected population | that the examined count is a fraction of something known |
| `CA_REFUSED_STATE_UNDECLARED` | a declaration names no admission state | that the state can be inferred from the count |
| `CA_REFUSED_STATE_CONTRADICTED` | the declared state is contradicted and no more specific code applies | that a declaration is its own evidence |

## 6. The recorded inventory

`evidence/a5/POPULATIONS.json` records each population's subject, kind, expected,
examined and omitted counts, whether omitted members are recorded, whether the
examined members are identified, whether the population is present, whether a bound
or selection rule is declared, the record and locator that state each number, and
the SHA-256 of every cited record. `evidence/a5/ADMISSION.json` records the state
each one is admitted at.

| population | record and locator | expected | examined | omitted | omitted members recorded | state | verdict |
|---|---|---:|---:|---:|---|---|---|
| `a1-sarif-results` | `evidence/a1/SARIF.json` `/runs` | 4245 | 4245 | 0 | true | COMPLETE | admitted |
| `t4-unsafe-sites` | `evidence/etp-t4/SAFETY-SITES.json` `/sites/rows` | 62297 | 62297 | 0 | true | COMPLETE | admitted |
| `t4-suppressions` | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions` | 1999 | 0 | 1999 | false | AGGREGATE_ONLY | CA_REFUSED_OMITTED_UNRECORDED |
| `t4-ignored-tests` | `evidence/etp-t4/SAFETY-SITES.json` `/assertions/ignored` | 54 | 54 | 0 | true | COMPLETE | admitted |
| `t10-closure-exclusions` | `evidence/etp-t10/EXCLUSIONS.json` `/rows` | 1121 | 1121 | 0 | true | COMPLETE | admitted |
| `curl-residual-sites` | `evidence/closure-curl-049.json` `/precision/residual_sites_bound` | 449 | 200 | 249 | false | TRUNCATED_BOUNDED | admitted |
| `curl-edge-records` | `evidence/closure-curl-049.json` `/edge_provenance` | 103992 | 0 | 103992 | false | ABSENT | CA_REFUSED_ABSENT_AS_OBSERVED |
| `curl-edge-sample` | `evidence/closure-curl-049.json` `/edge_provenance/records_sample` | 2109 | 500 | 1609 | false | TRUNCATED_BOUNDED | admitted |
| `ssh-edge-records` | `evidence/closure-ssh-b86.json` `/edge_provenance` | 51997 | 0 | 51997 | false | ABSENT | CA_REFUSED_ABSENT_AS_OBSERVED |
| `ssh-edge-sample` | `evidence/closure-ssh-b86.json` `/edge_provenance/records_sample` | 956 | 500 | 456 | false | TRUNCATED_BOUNDED | admitted |
| `timing-not-run` | `evidence/timing-bn-findings.json` `/not_run` | 7 | 0 | 7 | true | DEFERRED | admitted |
| `o11-interop-scripts` | `courts/phase18/interop/MANIFEST-o11-A.json` `/result/counts` | unknown | 73 | unknown | false | UNKNOWN | admitted |
| `t11-satisfied-runs` | `evidence/etp-t11/RUNS.json` `/runs` | 6 | 6 | 0 | true | AGGREGATE_ONLY | CA_REFUSED_MEMBER_UNIDENTIFIED |
| `etp6-package-inputs` | `evidence/etp6/MANIFEST.json` `/inputs` | unknown | 1633 | unknown | false | UNKNOWN | CA_REFUSED_UNRECORDED_POPULATION |
| `p1000-campaign-families` | `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` `/consumers/p1000_corpus` | 1000 | 245 | 755 | false | TRUNCATED_BOUNDED | admitted |
| `etp-claims` | `evidence/etp/claims.json` `/claims` | 35 | 35 | 0 | true | COMPLETE | admitted |

Totals, read from `evidence/a5/ADMISSION.json`:

| measure | count |
|---|---|
| populations | 16 |
| admitted | 11 |
| refused | 5 |
| `COMPLETE` | 5 |
| `TRUNCATED_BOUNDED` | 4 |
| `ABSENT` | 2 |
| `AGGREGATE_ONLY` | 2 |
| `UNKNOWN` | 2 |
| `DEFERRED` | 1 |
| `EMPTY` | 0 |
| `SAMPLED` | 0 |

The five `COMPLETE` populations are record-sets or censuses whose members are
present and identified. None is a claim that the tree contains nothing else:

* `a1-sarif-results` is complete over the 4,245 results the six runs project. It
  says nothing about findings no run projected. The A1 consumer rule already states
  that absence of a result is not absence of a defect (`completeness is A5`).
* `t4-unsafe-sites` is complete over the 62,297-row lexical census. The scanner is
  a heuristic and the census is of what it emits, not of every unsafe operation.
* `t4-ignored-tests` is complete over the 54 `#[ignore]` entries the record lists.
  A2's preservation projection enumerates 0 of them because its export omits that
  block; the native population is complete, A2's export of it is not, and the two
  statements are about different objects.
* `t10-closure-exclusions` is complete over the 1,121 exclusion rows. 377 rows pass
  the closure bar and 744 fail; that is the rows' content, not their completeness.
  A complete row-set of failing arguments is not a complete closure.
* `etp-claims` is complete over the 35 claims, and the ETP-0 inventory states the
  same 35 identities.

The five refusals are real, and each names a population a reader could otherwise
mistake for complete:

* `t4-suppressions` (A0 finding F02): the record states a total of 1,999 with a
  per-lint partition and no member row. A consumer reads the partition as the whole
  suppression population; the admission refuses `CA_REFUSED_OMITTED_UNRECORDED`
  and records `AGGREGATE_ONLY`.
* `curl-edge-records` and `ssh-edge-records`: `sample_policy` states that the
  complete population is the JSONL sidecar named by `records_path`. That path is
  under `court/tmp/`, which `/court/` in `.gitignore` excludes; `git ls-files` does
  not list it, so the member population is absent from the tracked evidence while
  the counts (103,992 and 51,997) are asserted. The admission refuses
  `CA_REFUSED_ABSENT_AS_OBSERVED` and records `ABSENT`. The bytes exist on the
  authoring host; an untracked file is not evidence.
* `t11-satisfied-runs` (A0 finding F09): six runs declare `status: SATISFIED` with
  `identity: null`, so the record states how many declarations there are and does
  not identify what any of them examined. The admission refuses
  `CA_REFUSED_MEMBER_UNIDENTIFIED` and records `AGGREGATE_ONLY`.
* `etp6-package-inputs` (A0 finding F03): the manifest states 1,633 verified inputs
  and no expected package population. The admission refuses
  `CA_REFUSED_UNRECORDED_POPULATION` and records `UNKNOWN`.

Twelve of the sixteen codes did not fire on a recorded population. That is a
negative result, not a pass: the records that would trigger them were either
repaired (F01's bound) or never claimed the stronger state. Every one of the twelve
is exercised by a control in `evidence/a5/CONTROLS.json`.

### 6.1 What the inventory does not cover

`python3 forensics/tools/completeness.py discover` performs a bounded structural
scan of `evidence/**/*.json`: it skips `evidence/a5` (this item's own records),
skips files above 40,000,000 bytes, names any file it could not parse, and reports
a mapping with at least two of the declaration keys (or a `not_run` key). It is
discovery, never admission. At the base commit the scan read 362 files and found
109 population-shaped blocks:

| category | blocks | admitted here |
|---|---:|---|
| claim quantification (`evidence/etp/claims.json`, its history, the ETP-5 probes, the schema) | 85 | no — owned by the claim algebra's `quantification`, not by a record population |
| A2 preservation projection (`evidence/a2/`) | 8 | no — these restate the native populations read here, from A2's export view |
| admitted-reader records (`a1/SARIF.json`, `closure-curl-049.json`, `timing-bn-findings.json`) | 4 | yes, via the native readers |
| narrative or summary blocks | 12 | no — they restate a population they do not enumerate |
| **total** | **109** | **16 populations admitted** |

The 85 claim-quantification blocks are a retained obligation, not a pass. The scan
key set does not include a bare `total` (too common to be a population
declaration), so a record that states only a total is found by its registered
reader, not by the scan. `docs/ETP-CLAIM-ALGEBRA.md` already refuses a cohort whose
member list does not cover its population (`EG_QUANTIFICATION_COVERAGE`); this
document does not duplicate that check.

## 7. Controls and measured figures

`evidence/a5/CONTROLS.json` records 17 controls over the 16 codes, each built in
memory from a real declaration. A control is a mutation of a declaration or a
constructor call; it is not a source change and not a defect report.

| control | base population | code asserted |
|---|---|---|
| `sample-as-census` | `curl-edge-sample` | `CA_REFUSED_SAMPLE_AS_CENSUS` |
| `truncation-as-complete` | `curl-residual-sites` | `CA_REFUSED_TRUNCATION_AS_COMPLETE` |
| `absent-as-empty` | `curl-edge-records` | `CA_REFUSED_ABSENT_AS_EMPTY` |
| `empty-as-absent` | `t4-ignored-tests` | `CA_REFUSED_EMPTY_AS_ABSENT` |
| `exit-as-completeness` | `curl-edge-records` | `CA_REFUSED_EXIT_AS_COMPLETENESS` |
| `omitted-unrecorded` | `t4-suppressions` | `CA_REFUSED_OMITTED_UNRECORDED` |
| `unknown-as-complete` | `o11-interop-scripts` | `CA_REFUSED_UNKNOWN_AS_COMPLETE` |
| `population-drift` | `curl-residual-sites` | `CA_REFUSED_POPULATION_DRIFT` |
| `count-inconsistent-sum` | `t4-ignored-tests` | `CA_REFUSED_COUNT_INCONSISTENT` |
| `count-inconsistent-exceeds` | `t4-ignored-tests` | `CA_REFUSED_COUNT_INCONSISTENT` |
| `duplicate-member` | `t4-unsafe-sites` | `CA_REFUSED_DUPLICATE_MEMBER` |
| `member-unidentified` | `t11-satisfied-runs` | `CA_REFUSED_MEMBER_UNIDENTIFIED` |
| `sample-without-population` | `curl-edge-sample` | `CA_REFUSED_SAMPLE_WITHOUT_POPULATION` |
| `state-undeclared` | `t4-unsafe-sites` | `CA_REFUSED_STATE_UNDECLARED` |
| `absent-as-observed` | `ssh-edge-records` | `CA_REFUSED_ABSENT_AS_OBSERVED` |
| `absent-declared-over-present` | `t4-unsafe-sites` | `CA_REFUSED_STATE_CONTRADICTED` |
| `unrecorded-population` | `etp6-package-inputs` | `CA_REFUSED_UNRECORDED_POPULATION` |

Measured quantities:

| quantity | measured |
|---|---|
| populations admitted | 16 |
| states | 5 `COMPLETE`, 4 `TRUNCATED_BOUNDED`, 2 `ABSENT`, 2 `AGGREGATE_ONLY`, 2 `UNKNOWN`, 1 `DEFERRED`, 0 `EMPTY`, 0 `SAMPLED` |
| refusals on recorded populations | 5, over 4 codes |
| refusal codes | 16 |
| controls | 17, covering 16 codes |
| structural scan | 362 files, 109 declaration hits, 0 oversize, 0 unreadable |
| new `unittest` controls | 72 |

Four codes fired on a recorded population: `CA_REFUSED_OMITTED_UNRECORDED`,
`CA_REFUSED_ABSENT_AS_OBSERVED`, `CA_REFUSED_MEMBER_UNIDENTIFIED` and
`CA_REFUSED_UNRECORDED_POPULATION`.

## 8. Non-claims

* Admission is not a safety result, a compatibility result or a cryptographic
  result. It says what was examined, not what the examination found.
* `COMPLETE` for a record-set is not `COMPLETE` for the tree. The five complete
  populations are complete over what their records enumerate.
* `TRUNCATED_BOUNDED` does not say the omitted members are unimportant; it says
  they were not examined and how many there are.
* `ABSENT` is not a defect in the input; it says the evidence record does not carry
  the population. The bytes may exist elsewhere, untracked.
* `AGGREGATE_ONLY` does not say the total is wrong; it says the total cannot be
  audited from the record.
* `DEFERRED` is not `PASS`. A named not-run analysis licenses nothing about the
  property it would have measured.
* The scan in §6.1 finds population-shaped blocks, not every population. Its key
  set and its size bound are stated so the limit is visible.
* This document does not change `docs/ETP-CLAIM-ALGEBRA.md`,
  `docs/CLOSURE-DISCIPLINE.md`, `docs/SARIF-PROFILE.md` or any evidence record it
  reads. It reads them.

## 9. `NOT_RUN`

* **Independent review.** The author of the tool, the document and the controls is
  not an independent reviewer, and no third party has reviewed the state-to-code
  mapping.
* **BOUNDARY and SEAL.** No caller or dependency-closure audit of the populations
  beyond the registered readers, no Miri or sanitizer run (the item is Python
  only), and no held-out verification.
* **The 85 claim-quantification blocks.** They are recorded as a retained
  obligation in §6.1 and are not admitted here; the claim algebra owns them.
* **The A2 export view.** `evidence/a2/PRESERVATION.json` records `enumerated`
  counts for its own export, which are not the native populations read here. A2's
  export completeness is not audited by this item.
* **Any population whose record is outside `evidence/`.** The structural scan is
  scoped to `evidence/**/*.json` plus the registered readers; `courts/`,
  `forensics/` and `docs/` are read only through a registered reader
  (`courts/phase18/interop/MANIFEST-o11-A.json`,
  `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json`).
* **The evidence commit.** The admission is bound to the SHA-256 of every cited
  record. A later edit to any cited record invalidates the declaration
  (`CA_REFUSED_POPULATION_DRIFT`); the receipt records the base commit.
