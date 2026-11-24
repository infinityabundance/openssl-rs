# A6 receipt — suppression governance

## 1. Identity of this batch

| field | value |
|---|---|
| item | A6 (suppression governance: a suppressed finding remains a finding; justification, scope, reviewer, expiry, consequences; auto-invalidate on change) |
| branch | `staging` |
| HEAD at the start | `63dab01cf` (`a5: admit a population only at the completeness it supports`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | total 45, used 12, free 28, available **33** GiB; swap total 45, used 14, free 31 |
| derived court cap | `min(8g, 33 − 16) = 8g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no build; no `src/`, `docker/` or other item's evidence modified |

The derived cap was 8 GiB and the running container's cap is 6 GiB, below it. The
container was reused rather than restarted, because one court already held the memory
budget and restarting it would not lower the cap. No Rust build was required; every
gate is Python only.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `docs/SUPPRESSION-GOVERNANCE.md` | 403 | normative document: the problem; the rule; the three identity levels and what each scope licenses; the required fields; the five dispositions; the seven invalidation triggers; all fourteen refusal codes with the wrong conclusion each prevents; the real register and verdicts; the records read and why they are not suppressions; the controls and measured figures; non-claims; `NOT_RUN` |
| `forensics/tools/suppression_governance.py` | 2577 | the model and checker: the record, the three target levels, the scopes, the dispositions, the fourteen codes, `admit`, `invalidate`, `apply_invalidation`, `reconcile`, the reviewer register, the real-record readers, the controls, and the `register` / `admit` / `invalidate` / `reconcile` command line |
| `forensics/tools/tests/test_suppression_governance.py` | 742 | 68 controls: the registry, construction refusals, the reader refusals, the real register round trip, the semantic rules, one test per invalidation trigger, the producer determinism, the CLI exit codes, and document synchronisation |
| `evidence/a6/build_evidence.py` | 204 | deterministic producer of the three JSON records; asserts every design expectation and writes no count it did not read |
| `evidence/a6/SUPPRESSIONS.json` | 38,385 bytes | 11 suppression-shaped records with their recorded fields verbatim, the disposition each is admitted at and the refusal codes |
| `evidence/a6/INVALIDATION.json` | 28,141 bytes | all seven triggers for all 11 records at the base candidate, and one synthetic control per trigger |
| `evidence/a6/CONTROLS.json` | 5,832 bytes | 15 controls over the 14 codes: one per code plus a policy-change control, each built in memory from the A1 finding population |
| `evidence/a6/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` gained the A6 row only; no other row was touched. No existing record
was edited.

## 3. The rule

> A suppressed finding remains a finding. Suppression is a disposition of a finding
> that is still in the population, never an absence from it.

A suppression must carry the identity it targets and that identity's level (rule,
logical or exact), the scope it is authorised at, a justification, a reviewer token and
where that token is recorded, the time it was made, an expiry or an explicit unbounded
claim, the policy basis, and the member identities. A record missing any of them is
`NON_ACTIONABLE`: it is present, it is refused, and it suppresses nothing. `reconcile`
refuses a population that omits a member the register disposes of
(`SG_REFUSED_SUPPRESSION_AS_ABSENCE`) and a register whose totals do not add up
(`SG_REFUSED_COUNT_UNBALANCED`).

## 4. The real register and its verdicts

`evidence/a6/SUPPRESSIONS.json` records 11 suppression-shaped records: 8 suppressions
and 3 records read and classified as not suppressions. **No real suppression is
actionable.** The full table is `docs/SUPPRESSION-GOVERNANCE.md` §8; the recorded
verdicts are:

| record | locator | target | members | reviewer | expiry | disposition | codes |
|---|---|---|---:|---|---|---|---|
| `t4-suppressions` | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions` | none | 1999 | no | none | NON_ACTIONABLE | 7 (target absent, no members, no justification, no reviewer, no expiry, unbounded scope, stale candidate) |
| `t4-test-modules` | `evidence/etp-t4/SAFETY-SITES.json` `/suppressions/test_modules` | none | 550 | no | none | NON_ACTIONABLE | the same 7 |
| `t3-known-nonconformance-agents-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/0` | rule | 17 tokens | no | none | NON_ACTIONABLE | 6 (target absent, no members, no justification, no reviewer, no expiry, stale candidate) |
| `t3-known-nonconformance-docs-etp-todo-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/1` | rule | 89 tokens | no | none | NON_ACTIONABLE | the same 6 |
| `t3-known-nonconformance-docs-ownership-model-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/2` | rule | 1 token | no | none | NON_ACTIONABLE | the same 6 |
| `t3-known-nonconformance-docs-parity-model-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/3` | rule | 1 token | no | none | NON_ACTIONABLE | the same 6 |
| `t3-known-nonconformance-docs-hazard-register-md` | `evidence/etp-t3/SPECIFICATIONS.json` `/known_failures/4` | rule | 14 tokens | no | none | NON_ACTIONABLE | the same 6 |
| `openssh-risk-acceptance-b85c` | `evidence/SAFE-COMPATIBLE-openssh-b85c.json` `/accepted_obligations` | none | 15 obligations | role only | none | NON_ACTIONABLE | 6 (target absent, no members, unrecorded reviewer, no expiry, unbounded scope, stale candidate) |
| `t10-closure-exclusions` | `evidence/etp-t10/EXCLUSIONS.json` `/rows` | none | 1121 rows | no | none | NON_ACTIONABLE | none — not a suppression |
| `a1-superseded-disposition` | `evidence/a1/SARIF.json` `/runs/2/results/210` | exact | 1 | no | none | NON_ACTIONABLE | none — not a suppression |
| `t3-spec-guard-control-fixture` | `evidence/etp-t3/SPECIFICATIONS.json` `/controls/0/exemptions/0` | none | 1 fixture token | fixture reviewer | none | NON_ACTIONABLE | none — control fixture |

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

Codes that fired on a real record, with counts: 8
`SG_REFUSED_TARGET_NOT_IN_POPULATION`, 8 `SG_REFUSED_NO_MEMBER_IDENTITIES`, 8
`SG_REFUSED_NO_EXPIRY`, 8 `SG_REFUSED_STALE_CANDIDATE`, 7
`SG_REFUSED_NO_JUSTIFICATION`, 7 `SG_REFUSED_NO_REVIEWER`, 3
`SG_REFUSED_UNBOUNDED_SCOPE`, 1 `SG_REFUSED_UNRECORDED_REVIEWER`.

The other six codes did not fire on a real record: `SG_REFUSED_SUPPRESSION_AS_ABSENCE`,
`SG_REFUSED_EXPIRED`, `SG_REFUSED_LOGICAL_AS_EXACT`,
`SG_REFUSED_CROSS_ARTEFACT_INHERITANCE`, `SG_REFUSED_INVALIDATED` and
`SG_REFUSED_COUNT_UNBALANCED`. That is a negative result, not a pass: no real record
states an expiry, a logical identity or an artefact binding, so the substitutions those
codes refuse cannot be constructed from the recorded fields. Each is exercised by a
control.

**Invalidation at the base candidate.** `evidence/a6/INVALIDATION.json` evaluates all
seven triggers for all 11 records at candidate
`63dab01cf35a2ea7a643a67a2bf1c6b07608b0f9`, as-of `2026-11-24` (read from
`git rev-parse HEAD` and `git show -s --format=%cs HEAD`). All 8 suppressions become
`INVALIDATED`: `candidate-identity-change` fires (recorded `246e3058…` or `b85c` is not
the base candidate) and `target-absent-from-population` fires (no target identity is in
the A1 population). `tool-identity-change` is `NOT_FIRED` for the two `etp-t4` records
(the recorded `scanner_sha256` equals the current file digest) and `NOT_RUN` for the
other nine, which record no instrument or a different one.
`source-tree-digest-change`, `expiry`, `new-occurrence-at-logical-identity` and
`policy-basis-change` are `NOT_RUN` for every record, with the reason recorded: the tree
digest was not recomputed, no expiry is recorded, no logical identity is recorded and no
policy-basis identity is recorded.

## 5. Controls and measured figures

| quantity | measured |
|---|---|
| suppression-shaped records read | 11 |
| suppressions / not suppressions | 8 / 3 |
| actionable suppressions | 0 |
| refusal codes | 14 |
| controls | 15, covering 14 codes |
| invalidation triggers | 7 |
| invalidation controls | 7, all fired |
| suppressions invalidated at the base candidate | 8 |
| finding population | 4,245 exact identities, 4,066 logical, 24 rules |
| reconciliation | suppressed 0, unsuppressed 4,245, balanced |
| reviewer tokens established | 10 |
| new `unittest` controls | 68 |

The 15 controls are one per refusal code plus a policy-change control:
`suppression-as-absence`, `aggregate-read-as-census`, `no-justification`,
`no-reviewer`, `unrecorded-reviewer`, `no-expiry`, `expired-read-as-active`,
`unbounded-scope`, `logical-as-exact`, `cross-artefact-inheritance`,
`stale-candidate`, `target-absent-from-population`, `invalidated-read-as-active`,
`count-unbalanced` and `policy-change`. The seven invalidation controls are one per
trigger: `candidate-identity-change`, `source-tree-digest-change`,
`tool-identity-change`, `expiry`, `target-absent-from-population`,
`new-occurrence-at-logical-identity` and `policy-basis-change`.

Two semantic positive controls are asserted by tests rather than by a refusal:
`test_a_suppressed_finding_is_still_counted_in_the_population` (the member stays in
`population.exact`, is in `suppressed`, is not in `unsuppressed`, and the counts still
sum to the population) and
`test_a_well_formed_suppression_is_active` (a record with all fields is `ACTIVE`).

## 6. Defects found in existing records

Three observations are recorded; none edits the record that carries the defect, and
each old value is preserved verbatim in `evidence/a6/SUPPRESSIONS.json` under the
record's `recordedFields`.

**6.1 The scanner computes suppression members and the evidence record omits them.**
`forensics/tools/unsafe_obligations.py` `suppressions()` returns `occurrences`, a list
of rows with `path`, `line`, `attribute` and `lints`, and its `validate` mode asserts
`total == len(occurrences)`. The tracked record
`evidence/etp-t4/SAFETY-SITES.json#/suppressions` (SHA-256
`7fb1ef96b7b7b36b9d49ae7283743b51ec9db6170bbde74074a6af0a8856e7da`) carries
`total: 1999`, a 35-entry `by_lint` partition and 550 `test_modules` rows, and no
`occurrences` key.

| field | value |
|---|---|
| old recorded statement | `/suppressions = {total: 1999, by_lint: {35 entries}, test_modules: [550 rows]}`, with no member row; the record's own non-claim is "A suppression is recorded, never adjudicated" |
| new observation | the tool that produced the record computes the member rows and the record does not carry them; the 1,999 suppressed diagnostics cannot be named from the tracked evidence |
| admission | `NON_ACTIONABLE`, refused `SG_REFUSED_NO_MEMBER_IDENTITIES` (and the six other codes in §4); the A5 admission already records the same population as `AGGREGATE_ONLY` with `CA_REFUSED_OMITTED_UNRECORDED` |
| preservation | the record is not edited. The recorded fields are preserved in `evidence/a6/SUPPRESSIONS.json` under `t4-suppressions.recordedFields` (`total`, `byLint`, `summary`, `identity`) and under `t4-test-modules.recordedFields` (`testModules`, `firstModule`, `lastModule`); both are stated in `docs/SUPPRESSION-GOVERNANCE.md` §1. |

This is not a new A0 finding and not a contradiction of F02: F02 recorded the missing
member row; A6 records that the producer computes one, so the population is recoverable
by re-running the scanner and is not part of the tracked evidence today.

**6.2 The spec-guard control fixture records a commit where a time belongs.**
`evidence/etp-t3/SPECIFICATIONS.json#/controls/0/exemptions/0` records
`reviewed: "794a7c549"`.

| field | value |
|---|---|
| old recorded statement | `reviewed: "794a7c549"` |
| new observation | the value is a 9-hex commit token, not an ISO date; `forensics/tools/spec_guard.py` validates only that `justification`, `reviewer` and `reviewed` are non-empty strings, so the field's form is unchecked |
| consequence | none for a real suppression: the entry is a guard control fixture, not an exemption of a real finding. It is recorded as `t3-spec-guard-control-fixture` and classified `control-fixture`, not forced into the refusal table. |
| preservation | `SUPPRESSIONS.json` records the exemption verbatim under `recordedFields.exemption`, and `recordedAt` holds `794a7c549` unchanged. |

**6.3 No reviewer identity is established for any real suppression.**
The reviewer register scans `evidence/**/*.json` for `reviewer` fields. Ten tokens are
established, all role descriptions such as "independent adjudicator (not the author)".
One further token, "ETP-T3 adversarial review", occurs only in the guard's `/controls/`
fixtures and is therefore not established: a fixture proves the guard works, it does not
review a real suppression. The OpenSSH risk acceptance's only reviewer-shaped field is
`classification.decided_by = "decision-maker (campaign principal)"`, which is a role and
is refused with `SG_REFUSED_UNRECORDED_REVIEWER`. No reviewer was invented to fill the
gap, and Article 5 independence remains unestablished for every token.

## 7. Gates actually run

All commands ran inside the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 12 28 0 5 33` (available 33 GiB); `Swap: 45 14 31` |
| new controls | `python3 -m unittest forensics.tools.tests.test_suppression_governance` | `Ran 68 tests in 123.716s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 841 tests in 156.562s`; `OK` (**841 tests, 0 failures, 0 errors, 0 skipped**; 773 before this item; no test removed, none ignored) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 |
| register well-formedness | `python3 -m json.tool evidence/a6/SUPPRESSIONS.json` | exit 0 |
| invalidation well-formedness | `python3 -m json.tool evidence/a6/INVALIDATION.json` | exit 0 |
| controls well-formedness | `python3 -m json.tool evidence/a6/CONTROLS.json` | exit 0 |
| producer | `python3 evidence/a6/build_evidence.py` twice | `records=11 suppressions=8 notSuppressions=3 actionable=0 NON_ACTIONABLE=11`; `population=a1-sarif-results enumerated=4245 suppressed=0 unsuppressed=4245 balance=ok`; `controls=15 invalidationControls=7 reviewerTokens=10`; the three files were byte-identical across the two runs (`cmp` on each) |
| producer identity | `sha256sum evidence/a6/*.json` | `236dc220d651bdb1f8519f189afa3bc9af78db7e28b0bd4f2c21a856694d8e4e` `SUPPRESSIONS.json`; `663d8c35ed37aa52c1866be0c0630c72ca6d0b5460509c06b471aceacadb87cf` `INVALIDATION.json`; `7333adefd4281650f200d3e79a5bbd8953a849c44e491b99522fa7e89fecf7ec` `CONTROLS.json` |
| reconciliation | `python3 forensics/tools/suppression_governance.py reconcile` | exit 1; `population=a1-sarif-results expected=4245 enumerated=4245 suppressed=0 unsuppressed=4245 balance=ok dispositions=ACTIVE=0 EXPIRED=0 INVALIDATED=0 NON_ACTIONABLE=11 PENDING_REVIEW=0 codes=SG_REFUSED_NO_EXPIRY,SG_REFUSED_NO_JUSTIFICATION,SG_REFUSED_NO_MEMBER_IDENTITIES,SG_REFUSED_NO_REVIEWER,SG_REFUSED_STALE_CANDIDATE,SG_REFUSED_TARGET_NOT_IN_POPULATION,SG_REFUSED_UNBOUNDED_SCOPE,SG_REFUSED_UNRECORDED_REVIEWER` |
| admit each record | `python3 forensics/tools/suppression_governance.py admit <id>` | exit 1 for the 8 suppressions (`t4-suppressions`, `t4-test-modules`, the 5 `t3-known-nonconformance-*`, `openssh-risk-acceptance-b85c`), each printing `disposition=NON_ACTIONABLE` and its codes; exit 0 for `t10-closure-exclusions`, `a1-superseded-disposition` and `t3-spec-guard-control-fixture`, each printing `codes=none` with `not a suppression in this model: …` |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/SUPPRESSION-GOVERNANCE.md`, `?? evidence/a6/`, `?? forensics/tools/suppression_governance.py`, `?? forensics/tools/tests/test_suppression_governance.py` |

**Reproducibility.** Re-running the producer at the recorded candidate
(`--candidate <commit> --as-of <date>`, taken from the document's own `currentIdentity`)
reproduces all three files byte-for-byte. A run at a later HEAD evaluates the
suppressions at that candidate and legitimately records different `STALE_CANDIDATE`
reasons. The producer reads every count from the named record (the `etp-t4` total is
cross-checked against `by_lint`, the `test_modules` list and `summary`; the A1
population is cross-checked against the A5 admission's examined count), and it stops
with a refusal rather than writing a count it did not read. The controls are
`test_the_producer_is_deterministic` and `test_the_producer_runs_at_the_current_candidate`.

**An intermittent pre-existing failure, observed with its header.** A whole-suite run
exited `FAILED (failures=1)` with the header
`FAIL: test_json_is_byte_identical_across_two_runs (test_verify.EndToEndControls)`.
That test runs `forensics/tools/verify.py all --json` twice and compares the bytes.
The `memory:24` need records its detail as the live `MemAvailable N GiB` reading
(`forensics/tools/verify.py:759`), so the document changes when the reading crosses a
GiB boundary between the two runs; under the load of the full suite that boundary is
reachable. This matches the text A4 records (`MemAvailable`, `24 GiB floor`). The
re-run exited `OK`, and the final run is `Ran 841 tests in 156.562s`, `OK`. The flaky
test is a pre-existing defect in another item's tool; A6 records it and does not repair
it, and no check was relaxed. One earlier 840-test run failed without its header being
captured, so that occurrence is **not identified** and is not attributed.

## 8. Obligations retained

* **No real suppression is actionable, and the register remains so.** The eight
  suppressions are refused, not repaired. Making one actionable requires a reviewer
  identity, a justification, an expiry, a candidate binding and member identities that
  the record does not carry. That is the next owner's decision, not A6's.
* **The 1,999 lint suppressions have no tracked member row.** The scanner computes
  `occurrences`; the evidence record does not carry them. A6 records the omission and
  does not reconstruct the population.
* **Reviewer identity and independence.** Ten role-description tokens are established;
  none is an independent identity, and Article 5 remains unestablished for every
  suppression.
* **The policy basis is unchecked.** `AX-SUPPRESSION-SCOPE` is `UNCHECKED` in
  `evidence/etp-t4/AXIOMS.json` and `AX-TEST-ONLY` is `PARTIAL`; the register records
  the basis and its status, not a verified policy.
* **The source-tree, expiry, new-occurrence and policy triggers are `NOT_RUN`.**
  Deferred is never passed (Article 3).
* **The finding population is the A1 emission.** The lint suppressions apply to a
  different tool's findings; they are refused because they name no target identity, not
  because the diagnostics are A1 results.

## 9. `NOT_RUN`

* **BOUNDARY.** No caller or dependency-closure audit of the register readers, no
  sanitizer or Miri run (the item is Python only), and no negative-control canary
  outside the tool's own refusal controls.
* **SEAL.** No full forensic regeneration, no compatibility or cryptographic assurance
  against this candidate, and no held-out verification.
* **Independent review.** The author of the document, the tool and the controls is not
  an independent reviewer, and no third party has reviewed the field-to-code mapping.
* **Recomputing the source-tree digest.** The `etp-t4` scanner's tree digest was not
  recomputed, so `source-tree-digest-change` is `NOT_RUN`.
* **The policy-basis identity.** No record states a policy digest, so
  `policy-basis-change` is `NOT_RUN`.
* **New occurrences.** No real suppression records a logical identity, so
  `new-occurrence-at-logical-identity` is `NOT_RUN`.
* **The suppressions' own populations.** The 1,999 lint suppressions, the 122 tokens,
  the 550 test regions and the 15 obligations are not member censuses of findings and
  are not reconstructed.
* **Reviewer independence (Article 5).** The token register establishes that a string
  exists; it does not establish a distinct trust domain.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test` was run.

## 10. Non-claims

Suppression governance is not a safety, compatibility or cryptographic result. It says
what a suppression must establish, not whether the suppressed finding is true. An
`ACTIVE` suppression does not make a finding false, and an `INVALIDATED` suppression
does not make it not exist. `NON_ACTIONABLE` does not say the record is wrong; it says
the record does not establish the fields a governed suppression requires. A recorded
reviewer token is not an independence result. No record read here was edited, and no
refusal code, admission state, identity rule or evidence record was relaxed.
