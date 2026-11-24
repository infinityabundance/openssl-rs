# A5 receipt — completeness admission

## 1. Identity of this batch

| field | value |
|---|---|
| item | A5 (completeness and execution admission: expected versus examined population, absent versus empty, an exit status is not completeness) |
| branch | `staging` |
| HEAD at the start | `d7fb15776` (`a4: a location is emitted only when the record carries it`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | total 45, used 12, free 28, available **33** GiB; swap total 45, used 14, free 31 |
| derived court cap | `min(8g, 33 − 16) = 8g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no build; no `src/`, `docker/` or other item's evidence modified |

The derived cap was 8 GiB and the running container's cap is 6 GiB, which is below
it. The container was reused rather than restarted, because one court already held
the memory budget and restarting it would not lower the cap. No Rust build was
required; the gates are Python only.

## 2. What was delivered

| path | role |
|---|---|
| `docs/COMPLETENESS-ADMISSION.md` | normative document: the problem; the six base states and two weaker states with what each licenses and does not; the permitted and forbidden transitions; the eleven rules; all sixteen refusal codes with the wrong conclusion each prevents; the recorded inventory and verdicts; the controls and measured figures; the bounded discovery scan; non-claims; `NOT_RUN` |
| `forensics/tools/completeness.py` | the model and checker: the declaration, the eight states, the sixteen refusal codes, `read_population`, the sixteen registered readers, `admit`, `verify_declaration`, `detect_drift`, the bounded discovery scan, and the `inventory` / `admit` / `check` / `discover` command line |
| `forensics/tools/tests/test_completeness.py` | 72 controls: registry, construction refusals, the reader, the states, every forbidden transition, absent/empty in both directions, the recorded round trip, the producer, the command line, and document synchronisation |
| `evidence/a5/build_evidence.py` | deterministic producer of the three JSON records; asserts every admission state and refusal code and every partition, and writes no count it did not read |
| `evidence/a5/POPULATIONS.json` | the inventory: 16 populations with expected, examined, omitted, whether omitted members are recorded, whether members are identified, presence, bound and selection flags, the record and locator that state each number, and the SHA-256 of every cited record |
| `evidence/a5/ADMISSION.json` | per population: declared, examined, omitted, members recorded, state, and the refusal code where one applies |
| `evidence/a5/CONTROLS.json` | 17 controls over the 16 codes, each built in memory from a real declaration |
| `evidence/a5/RECEIPT.md` | this receipt |

No existing record was changed. `docs/ETP-TODO.md` gained the A5 row only; no
other row was touched.

## 3. The rule

> A claim of completeness requires an expected population stated by a record, an
> examined count equal to it, no omitted members, and every examined member
> identified. Anything weaker is admitted at the weaker state it supports.

`Population` carries the declared state and the facts. `supported_state` derives
the strongest honest state. `admit` compares the declaration with it and returns a
stable refusal code when the declaration claims more. `read_population` is the
single reader used by every registered record adapter: a missing field is a
refusal, never a default. `verify_declaration` re-reads the native record and
compares every count and every cited SHA-256, so an admission cannot outlive the
bytes it read.

## 4. The recorded inventory

Sixteen populations, 11 admitted and 5 refused.

| population | record and locator | expected | examined | omitted | members recorded | state | verdict |
|---|---|---:|---:|---:|---|---|---|
| `a1-sarif-results` | `evidence/a1/SARIF.json` `/runs` | 4245 | 4245 | 0 | true | COMPLETE | admitted |
| `t4-unsafe-sites` | `evidence/etp-t4/SAFETY-SITES.json` `/sites/rows` | 62297 | 62297 | 0 | true | COMPLETE | admitted |
| `t4-suppressions` | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions` | 1999 | 0 | 1999 | false | AGGREGATE_ONLY | `CA_REFUSED_OMITTED_UNRECORDED` |
| `t4-ignored-tests` | `evidence/etp-t4/SAFETY-SITES.json` `/assertions/ignored` | 54 | 54 | 0 | true | COMPLETE | admitted |
| `t10-closure-exclusions` | `evidence/etp-t10/EXCLUSIONS.json` `/rows` | 1121 | 1121 | 0 | true | COMPLETE | admitted |
| `curl-residual-sites` | `evidence/closure-curl-049.json` `/precision/residual_sites_bound` | 449 | 200 | 249 | false | TRUNCATED_BOUNDED | admitted |
| `curl-edge-records` | `evidence/closure-curl-049.json` `/edge_provenance` | 103992 | 0 | 103992 | false | ABSENT | `CA_REFUSED_ABSENT_AS_OBSERVED` |
| `curl-edge-sample` | `evidence/closure-curl-049.json` `/edge_provenance/records_sample` | 2109 | 500 | 1609 | false | TRUNCATED_BOUNDED | admitted |
| `ssh-edge-records` | `evidence/closure-ssh-b86.json` `/edge_provenance` | 51997 | 0 | 51997 | false | ABSENT | `CA_REFUSED_ABSENT_AS_OBSERVED` |
| `ssh-edge-sample` | `evidence/closure-ssh-b86.json` `/edge_provenance/records_sample` | 956 | 500 | 456 | false | TRUNCATED_BOUNDED | admitted |
| `timing-not-run` | `evidence/timing-bn-findings.json` `/not_run` | 7 | 0 | 7 | true | DEFERRED | admitted |
| `o11-interop-scripts` | `courts/phase18/interop/MANIFEST-o11-A.json` `/result/counts` | unknown | 73 | unknown | false | UNKNOWN | admitted |
| `t11-satisfied-runs` | `evidence/etp-t11/RUNS.json` `/runs` | 6 | 6 | 0 | true | AGGREGATE_ONLY | `CA_REFUSED_MEMBER_UNIDENTIFIED` |
| `etp6-package-inputs` | `evidence/etp6/MANIFEST.json` `/inputs` | unknown | 1633 | unknown | false | UNKNOWN | `CA_REFUSED_UNRECORDED_POPULATION` |
| `p1000-campaign-families` | `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` `/consumers/p1000_corpus` | 1000 | 245 | 755 | false | TRUNCATED_BOUNDED | admitted |
| `etp-claims` | `evidence/etp/claims.json` `/claims` | 35 | 35 | 0 | true | COMPLETE | admitted |

States by id, read from `evidence/a5/ADMISSION.json`:

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

`COMPLETE`: `a1-sarif-results`, `t4-unsafe-sites`, `t4-ignored-tests`,
`t10-closure-exclusions`, `etp-claims`.
`TRUNCATED_BOUNDED`: `curl-residual-sites`, `curl-edge-sample`,
`ssh-edge-sample`, `p1000-campaign-families`.
`ABSENT`: `curl-edge-records`, `ssh-edge-records`.
`AGGREGATE_ONLY`: `t4-suppressions`, `t11-satisfied-runs`.
`UNKNOWN`: `o11-interop-scripts`, `etp6-package-inputs`.
`DEFERRED`: `timing-not-run`.
`EMPTY`: none. `SAMPLED`: none.

Every one of the five `COMPLETE` populations is complete over a record-set or a
census whose members are present and identified. None is a completeness claim about
the tree. `t10-closure-exclusions` is the clearest: all 1,121 rows are present and
identified, and 744 of them fail the closure bar. A complete row-set of failing
arguments is not a complete closure.

**Refusals that fired on a real record, over four codes:**

* `t4-suppressions` → `CA_REFUSED_OMITTED_UNRECORDED`. The record states 1,999
  suppressions with a per-lint partition and no member row (A0 finding F02).
* `curl-edge-records` → `CA_REFUSED_ABSENT_AS_OBSERVED`. The record states 103,992
  edge records and names their complete population at a `court/tmp` sidecar that
  `git ls-files` does not list.
* `ssh-edge-records` → `CA_REFUSED_ABSENT_AS_OBSERVED`. The same shape for 51,997
  records.
* `t11-satisfied-runs` → `CA_REFUSED_MEMBER_UNIDENTIFIED`. Six runs declare
  `status: SATISFIED` with `identity: null` (A0 finding F09).
* `etp6-package-inputs` → `CA_REFUSED_UNRECORDED_POPULATION`. 1,633 inputs with no
  expected package population (A0 finding F03).

The remaining twelve codes did not fire on a recorded population. That is a
negative result, not a pass: F01's bound was repaired before this item, and the
other records do not claim the stronger state. Each of the twelve is exercised by a
control.

## 5. Controls and measured figures

| quantity | measured |
|---|---|
| populations admitted | 16 |
| admitted / refused | 11 / 5 |
| states | 5 `COMPLETE`, 4 `TRUNCATED_BOUNDED`, 2 `ABSENT`, 2 `AGGREGATE_ONLY`, 2 `UNKNOWN`, 1 `DEFERRED`, 0 `EMPTY`, 0 `SAMPLED` |
| refusal codes | 16 |
| controls | 17, covering 16 codes |
| codes that fired on a real record | 4 |
| structural scan | 362 files, 109 population-shaped blocks, 0 oversize, 0 unreadable |
| new `unittest` controls | 72 |

The 17 controls and the code each asserts:

| control | base population | code |
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

A control mutates a declaration in memory or calls a constructor that must refuse.
It is not a source change and not a defect report.

The bounded discovery scan, `python3 forensics/tools/completeness.py discover`,
read 362 files, skipped none for size, failed to parse none, and found 109
population-shaped blocks: 85 claim-quantification blocks, 8 A2 preservation
projections, 4 in records read here, 12 narrative or summary blocks. The 85 are a
retained obligation; the claim algebra owns them. The scan's key set and 40 MB size
bound are recorded in the output, because the scan reports what it found and not
what exists.

## 6. A defect found in an existing record

**The two edge-record populations are claimed complete by reference to an untracked
sidecar.** `evidence/closure-curl-049.json` and `evidence/closure-ssh-b86.json`
state in `edge_provenance.sample_policy` that "the complete population is the JSONL
sidecar named by records_path". Both `records_path` values are under `court/tmp/`,
and `.gitignore:26` excludes `/court/`.

| field | value |
|---|---|
| old recorded statement | `edge_provenance.sample_policy`: the complete population is the JSONL sidecar named by `records_path`; `records_path` = `court/tmp/v4-consumer-closure/edge-records.7dfe9b54e8a477d1.jsonl` (curl) and `court/tmp/closure-b86-ssh/edge-records.c7fe11e19137dc1f.jsonl` (ssh); `edge_provenance.count` = 103,992 and 51,997 |
| new observation | `git ls-files --error-unmatch` returns 1 for both paths; `git check-ignore -v` reports `.gitignore:26:/court/`; the bytes exist on the authoring host (2,719,187,746 and 1,343,452,632 bytes) and are not part of the tracked evidence |
| admission | `ABSENT`, refused `CA_REFUSED_ABSENT_AS_OBSERVED`; recorded in `evidence/a5/ADMISSION.json` |
| preservation | the record is not edited. The recorded statement and the `git ls-files` result are both preserved: the statement in the record, the observation in `POPULATIONS.json` under `presenceBasis`, and both here. The old value is not replaced. |

This is not a new repair and not a contradiction of A0: A0 finding F01 recorded that
the 200 residual rows have no bound (repaired at `evidence/closure-curl-049.json`
`precision.residual_sites_bound`), and its text already said the omitted members are
written to the sidecar. What A5 adds is the observation that the sidecar is not
tracked, so the population is absent from the evidence record and the 500-row
`records_sample` is the only tracked member list.

Two further findings are recorded, not repaired, because they are other items'
records:

* **`evidence/etp-t11/RUNS.json` (A0 F09).** Six runs declare `SATISFIED` with
  `identity: null`. `evidence/etp-t11/TIERS.json` is `REFUSED` and reports
  `by_state.SATISFIED = 0` over 78 requirements. A5 does not compare the two counts
  as like-for-like, because one counts run declarations and the other requirement
  admissions; it records the six declarations as `AGGREGATE_ONLY` and refuses the
  completeness claim with `CA_REFUSED_MEMBER_UNIDENTIFIED`.
* **`evidence/a2/PRESERVATION.json`.** Its `ignored_tests` population records
  `enumerated: 0` for 54 declared entries. The native record holds 54 member rows
  and A5 admits them as `COMPLETE`. The two statements are about different objects:
  A2 records what its export carries, A5 records what the native record enumerates.
  Neither is edited, and the difference is recorded in
  `docs/COMPLETENESS-ADMISSION.md` §6.

The A4 known nonconformance in `docs/ETP-TODO.md` was respected: the A5 row was
written without adding an internal identifier to the recorded token set.
`spec_guard.py check` returned `0 unclassified, 0 unjustified exemptions`.

## 7. Gates actually run

All commands ran inside the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 12 28 0 5 33` (available 33 GiB); `Swap: 45 14 31` |
| new controls | `python3 -m unittest forensics.tools.tests.test_completeness` | `Ran 72 tests in 4.770s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 773 tests in 46.358s`; `OK` (**773 tests, 0 failures, 0 errors**; 701 before this item; no test removed, none ignored) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 |
| inventory well-formedness | `python3 -m json.tool evidence/a5/POPULATIONS.json` | exit 0 |
| admission well-formedness | `python3 -m json.tool evidence/a5/ADMISSION.json` | exit 0 |
| controls well-formedness | `python3 -m json.tool evidence/a5/CONTROLS.json` | exit 0 |
| producer | `python3 evidence/a5/build_evidence.py` twice | `populations=16 admitted=11 refused=5 ABSENT=2 AGGREGATE_ONLY=2 COMPLETE=5 DEFERRED=1 TRUNCATED_BOUNDED=4 UNKNOWN=2`; the three files were byte-identical across the two runs |
| producer identity | `sha256sum evidence/a5/*.json` | `a166c8584510831ad6387af8b37df3797920f4b15f5e4708fe75f4a3813bc5f4` `POPULATIONS.json`; `d4871ec97ae3a27b8ec820896e292429e44b4db4d11d2671a69b9dc0230ddc0a` `ADMISSION.json`; `f4e9551f0659038ce01f705566a7b71aff009ef9eddb49f52f316c4949fc8d58` `CONTROLS.json` |
| inventory command | `python3 forensics/tools/completeness.py inventory` | exit 1 (5 refusals); totals `admitted 11, refused 5`; state counts `ABSENT 2, AGGREGATE_ONLY 2, COMPLETE 5, DEFERRED 1, EMPTY 0, SAMPLED 0, TRUNCATED_BOUNDED 4, UNKNOWN 2` |
| admit each population | `python3 forensics/tools/completeness.py admit <id>` | exit 0 for the 11 admitted populations; exit 1 for `t4-suppressions`, `curl-edge-records`, `ssh-edge-records`, `t11-satisfied-runs`, `etp6-package-inputs`, each printing its code |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| worktree | `git --no-pager status --porcelain` | the new and modified paths listed in §2, and nothing else |

**Reproducibility.** Re-running the producer reproduces all three files
byte-for-byte. The producer reads each count from the named record, asserts a
second statement in that record, and writes no count it did not read; a record whose
count cannot be derived stops it with a refusal.

**An intermittent pre-existing failure, not observed here.** The whole-suite gate
has a known intermittent failure whose text contains a live `MemAvailable` reading
and `24 GiB floor`; it did not occur in this item's runs. No failure was suppressed.

## 8. Obligations retained

* The 85 claim-quantification blocks are population-shaped and are not admitted
  here. They are owned by the claim algebra's `quantification`, and
  `EG_QUANTIFICATION_COVERAGE` is the existing check for a cohort whose member list
  does not cover its population. This is a retained obligation, not a pass.
* The discovery scan finds blocks by a stated key set and a 40 MB size bound. A
  record that states only a bare `total` is not found by the scan; it is found by
  its registered reader if it has one.
* Two edge-record populations are `ABSENT` because their sidecar is untracked. The
  admission records the absence; it does not recover the population.
* Twelve refusal codes did not fire on a recorded population. The controls exercise
  them; the controls are not evidence that the substituted forms occur.
* `COMPLETE` is a statement about a record-set, never about the tree. The five
  complete populations license no claim that the tree contains nothing else.
* Every admission is bound to the SHA-256 of its cited records. A later edit
  invalidates the declaration as `CA_REFUSED_POPULATION_DRIFT`.

## 9. `NOT_RUN`

* **BOUNDARY.** No caller or dependency-closure audit of the registered readers, no
  sanitizer or Miri run, and no negative-control canary outside the tool's own
  refusal controls.
* **SEAL.** No full forensic regeneration, no compatibility or cryptographic
  assurance against this candidate, and no held-out verification.
* **Independent review.** The author of the document, the tool and the controls is
  not an independent reviewer, and no third party has reviewed the state-to-code
  mapping.
* **The claim-quantification blocks.** 85 blocks recorded as a retained obligation
  and not admitted.
* **The A2 export view.** `evidence/a2/PRESERVATION.json` describes A2's export, not
  the native records read here; its export completeness is not audited.
* **Populations outside the scan.** The scan is scoped to `evidence/**/*.json` plus
  the registered readers; `courts/`, `forensics/` and `docs/` are read only through
  a registered reader.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test` was
  run.

## 10. Non-claims

Admission is not a safety, compatibility or cryptographic result. It says what was
examined, not what the examination found. A complete record-set is not a complete
tree, a bounded truncation says nothing about the members it omitted, an absent
population is not an empty one, and an aggregate does not license a review of its
members. No claim algebra rule, closure-discipline rule, SARIF profile rule or
evidence record was relaxed or rewritten.
