# Baseline disposition: an absence is not a resolution

This document is the normative description of how the project distinguishes
root-cause elimination from a tool that stopped reporting. The implementation is
`forensics/tools/baseline.py`; the controls are
`forensics/tools/tests/test_baseline.py`; the recorded evidence is
`evidence/a7/{BASELINES,DELTA,CONTROLS}.json`, produced deterministically by
`evidence/a7/build_evidence.py`. The receipt is `evidence/a7/RECEIPT.md`.

`docs/FINDING-IDENTITY.md` is normative for rule, logical and exact identity;
`docs/COMPLETENESS-ADMISSION.md` is normative for whether a population was
examined; `docs/SUPPRESSION-GOVERNANCE.md` is normative for what a suppression
disposes of. This document is normative for a narrower question: **when a
finding is absent from a later report, what may be concluded, and on what
evidence?**

## 1. The problem

A shrinking report looks like progress. Four real forms are in this tree:

* **A contradicted claim reclassified at the same identity.** The live
  `evidence/etp/claims.json` reads no claim `CONTRADICTED`, while the preserved
  before-reconciliation copy reads four (`ETP0-CLM-004`, `-005`, `-030`,
  `-032`). The four are still claims; their verdict changed to `SUPERSEDED` or
  `RISK_ACCEPTED`. The contradiction finding moved; it was not eliminated.
* **A status change read as a discharge.** `evidence/closure-ssh-b50.json`
  records 11 obligations whose status changed from `BLOCKED` to `DISCHARGED`
  against `evidence/closure-ssh-b50-baseline.json`, at the same recorded
  repository head and the same candidate DSO digest. All 312 obligation
  identities are still present. The eleven moved; none left the population.
* **A repaired oracle whose later population was never admitted complete.** The
  HAZ-15 record shows the external-key sign, buffer and error-queue axes no
  longer distinguishing after the correction. That is a real behavioural change,
  but the record states no expected observation population, records no harness
  identity, and the returned length remains a channel recorded separately. The
  absence is not a resolution the baseline model can certify.
* **A tool change with nothing lost.** The A3 migration re-projects the 4,245 A1
  results under the new identity model and reproduces every fingerprint. The tool
  changed and no member is absent, which is exactly what the tool-change refusal
  is for: it prevents an absence being attributed to a fix, not a successful
  migration.

The rule is singular:

> A finding that is absent from a later report is not thereby resolved. A delta
> between two baselines must say *why* the member is absent, and only one class of
> reason is a resolution.

## 2. The baseline contract

A baseline is a **finding population bound to a candidate identity**. It records:

| field | what it establishes |
|---|---|
| `id` | a stable name for the baseline |
| `candidate` | the commit, branch and the identity of what the baseline was taken over (a DSO digest, a source-tree digest, or the per-run identities). A mixed artefact records every per-run identity and no single token; it is not relabelled |
| `tool` | the analyser path and digest, and whether the digest is actually recorded. An unrecorded tool is not a default |
| `scope` | the population id, the expected and examined counts, the A5 completeness state and the record/locator that states it |
| `members` | the exact and logical identities from A3, one per occurrence, or `aggregate: true` with no members and a declared count |
| `suppressions` | the A6 suppression dispositions that name a target this scope could contain |
| `takenAt` | the time the record states, or `not-recorded` |
| `record` | the tracked file, the JSON locator and the file digest |

An aggregate is a total with no member row. It can be quoted and cannot be
diffed per identity: `BL_REFUSED_AGGREGATE_AS_MEMBERS` refuses a delta that is
handed one. An absent second population is not an empty one:
`BL_REFUSED_NO_BASELINE` refuses a delta with one side missing. A member with no
recorded exact or logical identity is `BL_REFUSED_IDENTITY_UNSTABLE`.

The six A5 states are recorded, never upgraded. A scope whose state is `SAMPLED`,
`TRUNCATED_BOUNDED`, `ABSENT`, `EMPTY`, `UNKNOWN`, `AGGREGATE_ONLY` or `DEFERRED`
cannot support a resolution, even if every member that the record lists is
identified.

## 3. The dispositions

Every before-member appears in the delta with exactly one disposition. No member
is deleted from the report because it is absent.

| disposition | what it licenses | what it does not license |
|---|---|---|
| `STILL_PRESENT` | the exact identity is in both populations | that the finding is true, open, reachable or severe; presence is not state |
| `RESOLVED` | the exact and logical identity are absent from a later population that is `COMPLETE` for the same scope, scanned by the same recorded tool identity, with no exclusion or suppression added, at a later recorded candidate | a safety proof, a proof that the mechanism cannot recur, anything about a population outside the declared scope, or anything about the omitted members of a non-complete population |
| `MOVED` | the logical identity is preserved and the exact identity changed; the finding is still in the later population at another occurrence or state | a resolution; a relocated, reclassified or re-statused finding has not left the population |
| `NEW` | the identity appears in the later population and not in the earlier one | that the finding is new in the tree, novel, severe or introduced by the change |
| `SUPPRESSED_ABSENT` | the identity is absent and a suppression on the later side covers it | a resolution; a suppressed finding remains a finding (A6) |
| `EXCLUDED_ABSENT` | the identity is absent and an exclusion on the later side covers it | a resolution; an exclusion is an argued boundary, not a fix |
| `UNSCANNED_ABSENT` | the identity is absent, but the later population is not `COMPLETE` for the scope | a resolution; an unexamined member is not an absent one (A5) |
| `TOOL_CHANGED_ABSENT` | the identity is absent and the tool identity is not established as unchanged | a resolution; a changed analyser is not a fixed mechanism |
| `POPULATION_SHRUNK_ABSENT` | the identity is absent and the later population declares fewer members for the same scope | a resolution; a smaller report is not a cleaner tree |
| `UNKNOWN` | the recorded fields do not establish why the identity is absent | any conclusion; an unknown reason is not a pass (Article 3) |

`STILL_PRESENT`, `RESOLVED` and `NEW` are the only dispositions that need no
refusal code. Every other disposition names the condition that produced it,
enforced by `test_a_weaker_disposition_without_a_code_is_refused`.

## 4. The five-condition RESOLVED rule

Only `RESOLVED` requires all five conditions. Each is checked before the
disposition is emitted; the first unmet condition names the reason. A claim of
`RESOLVED` that fails any condition is refused, never reclassified.

| condition | what must hold | if it fails | enforced by |
|---|---|---|---|
| **a. complete later population** | the later scope is `COMPLETE` for the same scope id, its declared expected count equals its member count, and the expected count did not shrink | `UNSCANNED_ABSENT` + `BL_REFUSED_PARTIAL_SCAN`, or `POPULATION_SHRUNK_ABSENT` + `BL_REFUSED_POPULATION_SHRINK` | `test_condition_a_later_population_must_be_complete`, `test_a_population_shrink_is_not_a_resolution` |
| **b. unchanged tool** | the tool identity is recorded on both sides and the digests are equal | `TOOL_CHANGED_ABSENT` + `BL_REFUSED_TOOL_CHANGE` | `test_condition_b_tool_identity_must_be_unchanged_and_recorded` |
| **c. identity absent** | the exact identity is not in the later member set | `STILL_PRESENT` or `MOVED`; never `RESOLVED` | `test_condition_c_identity_must_be_absent`, `test_a_moved_identity_is_not_a_resolution` |
| **d. no exclusion or suppression** | no exclusion or suppression on the later side covers the exact or logical identity | `EXCLUDED_ABSENT` + `BL_REFUSED_EXCLUSION_AS_RESOLUTION`, or `SUPPRESSED_ABSENT` + `BL_REFUSED_SUPPRESSION_AS_RESOLUTION` | `test_condition_d_no_exclusion_or_suppression` |
| **e. recorded later candidate** | each side records a single candidate token, the later side is the one being claimed, and the tokens differ | `UNKNOWN` + `BL_REFUSED_CANDIDATE_UNRECORDED`, or `UNKNOWN` + `BL_REFUSED_ABSENCE_AS_RESOLUTION` when the tokens are equal | `test_condition_e_candidate_must_be_recorded_and_later` |

The positive path is `test_the_positive_path_reaches_resolved`: a before
population of two members and a later complete population of the same size with
one member replaced reaches `RESOLVED` for the replaced member and `NEW` for its
replacement, with no code. That is the only shape that reaches `RESOLVED` in the
controls, and no real delta reaches it.

A resolution at one candidate is refused even when every other field agrees: at a
single candidate a deterministic tool reports the same population, so a
disappearance is a changed record, a changed scope or a changed tool
(`BL_REFUSED_ABSENCE_AS_RESOLUTION`). This is the refusal that catches the
claims record, whose before and after bytes both cite the same source commit.

**Conservative limitation, stated.** A later population that is complete over a
*smaller* expected count is `POPULATION_SHRUNK_ABSENT`, not `RESOLVED`, even when
the shrink is a legitimate consequence of a fix. The model cannot distinguish the
two from the recorded fields, so it refuses the stronger conclusion. A resolution
needs a later population that is complete over the same expected count, which in
practice means the scope's item population is recorded separately from the
finding population. That separation is a retained obligation, not an implied
capability.

## 5. The refusal codes

Every code is stable and is cited verbatim by the tool, the tests, the receipt and
this document. The third column is the wrong conclusion the code prevents.

| code | condition | prevents |
|---|---|---|
| `BL_REFUSED_ABSENCE_AS_RESOLUTION` | an absent member is read as resolved without the other conditions, or a member is absent from a population at the same candidate as the earlier one | that a finding disappeared because the report stopped listing it; at one candidate a disappearance is a changed record, scope or tool |
| `BL_REFUSED_POPULATION_SHRINK` | the later population declares fewer members for the same scope | that a smaller report is a cleaner tree; the omitted members are unexamined and their properties unknown |
| `BL_REFUSED_TOOL_CHANGE` | the tool identity changed, or is not recorded on one side | that a finding was fixed when the analyser changed; a different tool is a different observation |
| `BL_REFUSED_EXCLUSION_AS_RESOLUTION` | an exclusion on the later side covers the member | that excluding a finding from the examined population eliminates it |
| `BL_REFUSED_SUPPRESSION_AS_RESOLUTION` | a suppression on the later side covers the member | that a suppressed finding is gone; it remains a finding |
| `BL_REFUSED_PARTIAL_SCAN` | the later population is not `COMPLETE`, or its member set does not cover its declared expected count | that an unexamined member was examined and found absent |
| `BL_REFUSED_MOVED_AS_RESOLVED` | the logical identity is present while the exact identity changed, and the movement is read as a resolution | that a relocated, reclassified or re-statused finding was fixed |
| `BL_REFUSED_CANDIDATE_UNRECORDED` | a candidate identity is missing, mixed across runs, or the later side is not recorded as a later candidate | that the later population was taken at the candidate being claimed |
| `BL_REFUSED_AGGREGATE_AS_MEMBERS` | a baseline states a total without member identities, or a count is read as a member set | that a number is a census; an aggregate cannot support a per-identity delta |
| `BL_REFUSED_NO_BASELINE` | no second population exists at a second identity, or the two baselines are not the same scope | that a delta can be computed from one population or across different populations |
| `BL_REFUSED_IDENTITY_UNSTABLE` | a member carries no recorded exact or logical identity, or the identity is not a full-length sha-256 | that an unidentifiable member can be tracked across populations |

Each code has exactly one control in `evidence/a7/CONTROLS.json`, and a test in
`forensics/tools/tests/test_baseline.py`: `test_absence_as_resolution`,
`test_population_shrink`, `test_tool_change`,
`test_exclusion_as_resolution`, `test_suppression_as_resolution`,
`test_partial_scan`, `test_moved_as_resolved`, `test_candidate_unrecorded`,
`test_aggregate_as_members`, `test_no_baseline` and `test_identity_unstable`.
The coverage is enforced by `test_the_controls_cover_every_code_once`.

## 6. The real baselines

`evidence/a7/BASELINES.json` records 16 baselines: 10 enumerate their members and
6 are aggregates. The enumerated baselines carry **9,274** member identities; the
aggregate baselines carry **65,934** declared counts. Three records are named as
not baselines rather than forced into the model.

| baseline | candidate recorded | tool | scope and A5 state | members | record and locator |
|---|---|---|---|---|---|
| `a1-sarif-results` | six per-run candidates, mixed; no single token | SARIF adapter `35614b90…` | `a1-sarif-results`, `COMPLETE` | 4,245 | `evidence/a1/SARIF.json` `/runs` |
| `a1-fingerprints-model` | the same six runs, mixed | `finding_identity.py` | `a1-sarif-results`, `COMPLETE` | 4,245 | `evidence/a3/MIGRATION.json` `/streamSha256New` |
| `etp-claims-before` | commit `9372bb28b…` | not recorded | `etp-claims`, `COMPLETE` | 35 | `evidence/etp-t15/history/claims.before-reconciliation.json` `/claims` |
| `etp-claims-after` | commit `9372bb28b…` (stale; see §6.2) | `apply_claims.py` | `etp-claims`, `COMPLETE` | 35 | `evidence/etp/claims.json` `/claims` |
| `closure-ssh-b50-baseline` | `84f624012…` and DSO `e7cbb9ee…` | `consumer_closure.py` | `closure-ssh-b50-obligations`, `COMPLETE` (not A5-registered) | 312 | `evidence/closure-ssh-b50-baseline.json` `/obligations` |
| `closure-ssh-b50-applied` | `84f624012…` and DSO `e7cbb9ee…` | `consumer_closure.py` | the same scope, `COMPLETE` | 312 | `evidence/closure-ssh-b50.json` `/obligations` |
| `haz15-prefix` | DSO `c816b3d1…` | not recorded | `haz15-padding-observations`, `UNKNOWN` | 2 | `evidence/haz-15/observables.json` `/finding_prefix` |
| `haz15-postfix` | DSO `5761b715…` | not recorded | the same scope, `UNKNOWN` | 2 | `evidence/haz-15/observables.json` `/finding_postfix` |
| `haz16-classification` | `5d38094cc…` (9-hex short head, not a full commit) | not recorded | `haz16-ffi-mutation-classification`, `COMPLETE` (not A5-registered) | 79 | `evidence/haz-16/CLASSIFICATION.json` `/rows` |
| `t4-unsafe-sites` | `246e3058…` | `unsafe_obligations.py` | `t4-unsafe-sites`, `COMPLETE` | aggregate 62,297 | `evidence/etp-t4/SAFETY-SITES.json` `/sites/rows` |
| `t4-suppressions` | `246e3058…` | `unsafe_obligations.py` | `t4-suppressions`, `AGGREGATE_ONLY` | aggregate 1,999 | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions` |
| `t4-ignored-tests` | `246e3058…` | `unsafe_obligations.py` | `t4-ignored-tests`, `COMPLETE` | aggregate 54 | `evidence/etp-t4/SAFETY-SITES.json` `/assertions/ignored` |
| `t10-closure-exclusions` | `7e70b667…` | not recorded | `t10-closure-exclusions`, `COMPLETE` | aggregate 1,121 | `evidence/etp-t10/EXCLUSIONS.json` `/rows` |
| `curl-residual-sites` | `17e45eec…` and DSO `fd25cc9e…` | `consumer_closure.py` | `curl-residual-sites`, `TRUNCATED_BOUNDED` | aggregate 200 of 449 | `evidence/closure-curl-049.json` `/precision/residual_sites_bound` |
| `curl-obligations` | `17e45eec…` and DSO `fd25cc9e…` | `consumer_closure.py` | `curl-production-obligations`, `COMPLETE` | 7 | `evidence/closure-curl-049.json` `/obligations` |
| `a3-logical-collisions` | the six A1 runs, mixed | `finding_identity.py` | `a1-logical-collision-members`, `COMPLETE` | aggregate 263 (84 groups) | `evidence/a3/COLLISIONS.json` `/recorded` |

The three records named as not baselines are
`forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` (a status
record, not a finding population), `forensics/receipts/EVIDENCE_RECEIPT.*.json`
(file manifests with an aggregate hash, not findings), and
`evidence/baseline-20261120.json` (an identity and reconciliation baseline, not a
finding population). Naming them is the honest alternative to forcing a count
into the model.

### 6.1 What the candidate fields do not hide

The A1 artefact carries six runs at six candidate identities. The baseline
records all six per-run candidates and marks the baseline mixed; it does not
invent a single commit and does not relabel an earlier candidate as the current
one. The A3 migration and the collision report inherit the same mixed candidate.
A mixed baseline has no candidate token, so any absence from it is `UNKNOWN`
with `BL_REFUSED_CANDIDATE_UNRECORDED`; the real migration delta has no absence,
so it is admitted with 4,245 `STILL_PRESENT`.

The closure pair records the same repository head and the same candidate DSO
digest on both sides. That is why the eleven status changes are `MOVED` and the
delta carries `BL_REFUSED_ABSENCE_AS_RESOLUTION`: the changes happened at one
candidate, and a status change is a disposition of an obligation, not a new code
state.

### 6.2 A defect in an existing record, preserved

`evidence/etp/claims.json` and its preserved before-reconciliation copy
`evidence/etp-t15/history/claims.before-reconciliation.json` both record
`source_identity.commit = 9372bb28b2fbe2f71cf2aa2ab501414d45e87d42`, although
their verdicts differ and the live bytes were edited after the reconciliation.
`evidence/etp-t15/RECONCILIATION.json` names `base_commit = 576e26d2d…`, and the
live file changed at `e0b727d06` and again at `2d31a23fb`. The record's own
candidate field did not advance with its bytes.

| field | old value (preserved history copy) | new value (live record) |
|---|---|---|
| file SHA-256 | `65d8105b744c80ae01e76af8bf3370c478ab116c7fc9b0f16f63eea5d5c579de` | `2968ffd6976f19bd701c58636b51cceed192e42c928dd2116217449a7b85a1bb` |
| `source_identity.commit` | `9372bb28b…` | `9372bb28b…` (unchanged) |
| verdicts | 17 `ESTABLISHED`, 13 `PARTIAL`, 4 `CONTRADICTED`, 1 `SUPERSEDED` | 17 `ESTABLISHED`, 13 `PARTIAL`, 4 `SUPERSEDED`, 1 `RISK_ACCEPTED` |

The old file is not edited. The baseline records the same candidate token on both
sides and marks the later one stale in its note, so the delta cannot read the four
disappearances as resolutions: the per-identity dispositions are `MOVED` and the
delta carries `BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED`
and `BL_REFUSED_TOOL_CHANGE`. Repairing the record is a separate decision for its
owner; this item preserves the old and new values and does not rewrite either.

## 7. The real deltas and their verdicts

`evidence/a7/DELTA.json` records four deltas over 4,596 records: **4,577
`STILL_PRESENT`, 15 `MOVED`, 2 `NEW`, 2 `UNSCANNED_ABSENT` and 0 `RESOLVED`**.
One delta is admitted and three are refused.

| delta | before → after | dispositions | codes | verdict |
|---|---|---|---|---|
| `a3-fingerprint-migration` | `a1-sarif-results` → `a1-fingerprints-model` | `STILL_PRESENT=4245` | none | admitted: the tool changed and every exact identity was reproduced; no absence is claimed |
| `claims-reconciliation` | `etp-claims-before` → `etp-claims-after` | `STILL_PRESENT=31`, `MOVED=4` | `BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED`, `BL_REFUSED_TOOL_CHANGE` | refused: the four contradictions were reclassified at the same recorded candidate; not one is resolved |
| `closure-ssh-b50-status` | `closure-ssh-b50-baseline` → `closure-ssh-b50-applied` | `STILL_PRESENT=301`, `MOVED=11` | `BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED` | refused: eleven obligations changed status at the same candidate; none left the population |
| `haz15-padding-observation` | `haz15-prefix` → `haz15-postfix` | `UNSCANNED_ABSENT=2`, `NEW=2` | `BL_REFUSED_PARTIAL_SCAN`, `BL_REFUSED_TOOL_CHANGE` | refused: the sign/buffer/queue findings are absent, but the later population is `UNKNOWN` and the harness identity is unrecorded; the returned-length finding appears |

**No real delta reaches `RESOLVED`.** That is a negative result, not a pass. The
only repair that looks like a resolution in this tree (the HAZ-15 oracle) is
refused because the later observation population was never admitted complete and
the harness identity was never recorded. The producer asserts
`real_resolutions == 0`; a later real resolution would stop the producer until
this document is revised.

### 7.1 Areas with no second population

Seven areas have a baseline but no second population at a second identity. They
are recorded as `NO_BASELINE` with the reason, not synthesised:

| area | reason |
|---|---|
| `a1-sarif-results` | one emission over six runs; no second scan of the same six scopes at a later candidate |
| `t4-unsafe-sites` | one lexical scan at `246e3058`; no second census |
| `t10-closure-exclusions` | one row-set at `7e70b667`; no second row-set |
| `curl-residual-sites` | one closure record, and its own residual population is `TRUNCATED_BOUNDED` at 200 of 449 |
| `haz16-classification` | the before population is enumerated (79 rows, 3 `PARTIAL_EXPOSED`); the three repairs are a mechanism description with a test and a revert control, not a second 79-row population |
| `a3-logical-collisions` | derived from one A1 emission; no second collision population |
| `phase1-baseline-20261120` | an identity and reconciliation baseline, not a finding population |

## 8. Controls and measured figures

`evidence/a7/CONTROLS.json` records 11 controls over the 11 refusal codes, one
per code, each built in memory from the real claim member identities. A control
proves the refusal fires; it is not a source change and not a defect report.

| control | code asserted | asserted disposition |
|---|---|---|
| `absence-as-resolution` | `BL_REFUSED_ABSENCE_AS_RESOLUTION` | `UNKNOWN` |
| `population-shrink` | `BL_REFUSED_POPULATION_SHRINK` | `POPULATION_SHRUNK_ABSENT` |
| `tool-change` | `BL_REFUSED_TOOL_CHANGE` | `TOOL_CHANGED_ABSENT` |
| `exclusion-as-resolution` | `BL_REFUSED_EXCLUSION_AS_RESOLUTION` | `EXCLUDED_ABSENT` |
| `suppression-as-resolution` | `BL_REFUSED_SUPPRESSION_AS_RESOLUTION` | `SUPPRESSED_ABSENT` |
| `partial-scan` | `BL_REFUSED_PARTIAL_SCAN` | `UNSCANNED_ABSENT` |
| `moved-as-resolved` | `BL_REFUSED_MOVED_AS_RESOLVED` | `MOVED` |
| `candidate-unrecorded` | `BL_REFUSED_CANDIDATE_UNRECORDED` | `UNKNOWN` |
| `aggregate-as-members` | `BL_REFUSED_AGGREGATE_AS_MEMBERS` | — (construction refusal) |
| `no-baseline` | `BL_REFUSED_NO_BASELINE` | — (construction refusal) |
| `identity-unstable` | `BL_REFUSED_IDENTITY_UNSTABLE` | `UNKNOWN` |

Measured quantities, read from the recorded documents:

| quantity | measured |
|---|---|
| baselines | 16 |
| enumerated baselines / member identities | 10 / 9,274 |
| aggregate baselines / declared counts | 6 / 65,934 |
| records named not baselines | 3 |
| deltas | 4 |
| admitted / refused deltas | 1 / 3 |
| delta records | 4,596 |
| dispositions | 4,577 `STILL_PRESENT`, 15 `MOVED`, 2 `NEW`, 2 `UNSCANNED_ABSENT`, 0 `RESOLVED` |
| `NO_BASELINE` areas | 7 |
| refusal codes | 11 |
| controls | 11, one per code |
| codes that fired on real data | 4: `BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED`, `BL_REFUSED_PARTIAL_SCAN`, `BL_REFUSED_TOOL_CHANGE` |

The other seven codes did not fire on a real delta. That is a negative result, not
a pass: no real delta has a later aggregate, an unrecorded side, a shrunk
expected count, an exclusion, a suppression or an unstable identity that would
trigger them. Each is exercised by its control, and the coverage is enforced by
`test_the_controls_cover_every_code_once`.

## 9. Non-claims

* A resolution is not a safety proof. `RESOLVED` says an identity is absent from a
  complete later population; it says nothing about a mechanism, a proof, a
  boundary or a consumer.
* A baseline is not a census of the tree. It is a population a record enumerates.
* `RESOLVED` is scoped to the population examined. A complete record-set is not a
  complete tree.
* `STILL_PRESENT` does not say a finding is open; `NEW` does not say it is a new
  defect; `MOVED` does not say it is fixed; `UNKNOWN` is not a pass (Article 3).
* An aggregate is not a census; a `NO_BASELINE` area is not a clean area.
* The A1 artefact's six per-run candidates are not one candidate and are not
  relabelled as the current one.
* The five-condition rule is conservative in one stated direction: a later
  population complete over a smaller expected count is
  `POPULATION_SHRUNK_ABSENT`, even when the shrink is a legitimate consequence of
  a fix, because the recorded fields do not distinguish the two.
* This document does not change any record it reads. It reads them and preserves
  the old and new values of the one defect it names.

## 10. `NOT_RUN`

* **Independent review.** The author of the tool, the document and the controls is
  not an independent reviewer, and no third party has reviewed the
  disposition-to-code mapping.
* **BOUNDARY and SEAL.** No caller or dependency-closure audit of the baseline
  readers, no sanitizer or Miri run (the item is Python only), and no held-out
  verification.
* **The seven `NO_BASELINE` areas.** No second population exists at a second
  identity; none was synthesised. A later scan that closes one of them must be
  bound to its own candidate and tool before a delta can be computed.
* **The HAZ-16 after population.** The three repairs are a mechanism description
  with a test and a revert control; the classification was not re-run, so no
  second 79-row population exists.
* **The claims record's later candidate.** The live record still states the
  earlier source commit; the reconciliation record names `576e26d2d…`, but the
  claims record itself does not. The candidate is recorded as stale, not repaired.
* **The historical claim producer's digest.** The before-reconciliation record
  names no producer; the tool identity is recorded as unrecorded, not guessed.
* **A real `RESOLVED`.** No real delta reaches it. The only positive path is the
  in-memory control `test_the_positive_path_reaches_resolved`.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test`
  was run.

## 11. Reproducing the evidence

```
python3 evidence/a7/build_evidence.py            # writes the three JSON records
python3 -m json.tool evidence/a7/BASELINES.json
python3 -m json.tool evidence/a7/DELTA.json
python3 -m json.tool evidence/a7/CONTROLS.json
python3 forensics/tools/baseline.py delta
python3 forensics/tools/baseline.py explain <identity>
python3 forensics/tools/baseline.py admit <delta-id>
python3 -m unittest discover -s forensics/tools/tests -p test_baseline.py
```

The producer reads every identity and count from its record, asserts the design
expectations, and stops rather than writing a count it did not read. Re-running it
at one source identity reproduces the three files byte-for-byte; the control is
`test_the_producer_is_deterministic`.
