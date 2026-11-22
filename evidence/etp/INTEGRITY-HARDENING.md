# ETP evidence-integrity hardening

This receipt records a **hardening of the validators**, not a change to any
measurement. Before the change, several validators could admit malformed or
incomplete documents: they established that an explanation existed, not that the
described procedure had run. The rules are now stricter, each change has a
mutation control that constructs the malformed input and asserts the named
refusal, and the committed evidence has been re-read under the stricter rules.

## Source identity

| field | value |
|---|---|
| repository | `openssl-rs` |
| branch | `staging` |
| base candidate `S` (HEAD at start) | `3c43f87af` — `bn: protect secret values from preparation; publish the cache atomically` |
| worktree at start | clean (no tracked or untracked changes; `git status --porcelain` empty) |
| court image | `openssl-rs-court-tools:1` |
| court Python | 3.11.2 |
| court memory cap | container 8 GiB; command environment `OPENSSL_RS_COURT_MEM=6g`, `OPENSSL_RS_COURT_MEMSWAP=6g` |
| host `available` before the runs | 30–32 GiB (guard threshold 24 GiB) |
| evidence commit | the commit that introduces this file; resolve with `git log -1 --format=%H -- evidence/etp/INTEGRITY-HARDENING.md` |

A Git commit cannot contain its own hash, so the evidence commit is named by the
command that resolves it rather than by a fabricated value. The base candidate
above is the source identity every check in this receipt was run against.

## What was too weak, and what is now required

| # | weakness before | requirement now | refusal identifier |
|---|---|---|---|
| 1a | `_excluded` accepted a non-empty `argument` plus a `checkable_by` that was not a placeholder. An exclusion was therefore admitted without showing that any verification ran. | An exclusion needs an **admitted witness** record binding (i) the exact obligation id, (ii) the claim's candidate identity, (iii) the verification procedure, (iv) an independently produced result with its own path, SHA-256 and digest identity, and (v) a reviewer whose declared role and identity differ from the claim author's. Propagate applies the same structural admission, and the CLI re-derives witness result digests before invoking it. | `EG_EXCLUSION_WITNESS_MISSING`, `EG_EXCLUSION_WITNESS_UNBOUND`, `EG_EXCLUSION_WITNESS_CANDIDATE`, `EG_EXCLUSION_WITNESS_SELF_AUTHORED`, `EG_EXCLUSION_WITNESS_RESULT_ABSENT`, `EG_EXCLUSION_WITNESS_DIGEST` (tree re-derivation); `EG_EXCLUSION_UNCHECKABLE` retained |
| 1b | `conjoin`, `invalidate` and `propagate` loaded the document and answered from it without schema or law validation. | Every operation validates with the same schema, cross-field laws and Git-bound digest check as `validate`; an invalid document is refused with the validator's existing rule identifiers and no operation payload is emitted. `contradictions` is gated the same way. | the validator's own identifiers (for example `EG_SELF_DECLARED_POLICY`, `EG_SCHEMA_VIOLATION`) |
| 1c | Any non-empty set of valid identity rows was accepted. | The identity rows must be exactly the preregistered `label × subject` population: warm-up, every measured repetition, the allocation probe, and both signer roles for every cross-verification repetition, each subject exactly once. Missing, duplicated, substituted and extra identities are named. | `PFP_IDENTITY_POPULATION` |
| 1d | The ordering check compared a single aggregate count and did not require unique repetition identifiers. | The realised repetitions must be exactly the declared identifiers, once each; every row must be one candidate/authority pair; the declared ordering property must be balanced and the realised first-subject counts must equal the declared per-repetition sequence. | `PFP_ORDERING_IDENTITY`, `PFP_ORDERING_PAIR`, `PFP_ORDERING_BALANCE` |
| 1e | Two empty `CHECK` transcripts compared equal. | The expected correctness-check population is declared independently by `check_line_count_per_process` in `WORKLOADS.json`; an empty side is refused, and every expected identifier must appear exactly the declared number of times on each side. | `PFP_CHECK_POPULATION` (plus `PFP_CHECK_CONTENT` for byte inequality) |
| 1f | Cross-verification counted twelve rows without requiring the declared set. | The rows must be exactly the declared `(repetition, signer, verifier)` tuples, so a substituted direction, a missing pair, a duplicate or an extra row is refused. | `PFP_CROSS_POPULATION` |
| 1g | Ordinary `json.load`/`json.loads` kept the last duplicate key and accepted `NaN`/`Infinity`. | Claim and result documents are parsed strictly: duplicate object keys and non-finite numbers are refused with the offending JSON pointer. | `EG_JSON_DUPLICATE_KEY`, `EG_JSON_NON_FINITE`, `EG_JSON_MALFORMED`; `PFP_JSON_DUPLICATE_KEY`, `PFP_JSON_NON_FINITE`, `PFP_JSON_MALFORMED` |

The witness schema is closed (`additionalProperties: false`). A witness is not
admissible because a field is non-empty: the obligation id must equal the owning
obligation's id, the candidate must be one of the claim's declared source
identities, the reviewer must differ from the claim author in role or identity,
the result must declare `present: true` with a 64-hex digest and `S`/`E`
identity, and the tree check re-derives that digest. A claim that uses an
exclusion must declare an `author`; otherwise reviewer independence cannot be
established and the witness is refused.

## Mutation controls

Each control constructs the malformed input and asserts the exact refusal
identifier. A control asserting only "an error occurred" would not count.

### Claim algebra (`forensics/tools/tests/test_etp_claims.py`)

| control | malformed input | asserted identifier |
|---|---|---|
| `test_conjoin_still_answers_a_valid_document` | well-formed document (positive) | no refusal; conjunction returned |
| `test_operations_refuse_an_invalid_document` | self-declared acceptance policy, run through `conjoin`, `invalidate`, `propagate` | `EG_SELF_DECLARED_POLICY`; operation payload absent |
| `test_operations_refuse_a_schema_violation` | unknown claim axis, run through all three operations | `EG_SCHEMA_VIOLATION` |
| `test_absent_witness_is_refused` | exclusion with argument and procedure only | `EG_EXCLUSION_WITNESS_MISSING` |
| `test_unbound_obligation_is_refused` | witness names `OBL-OTHER` | `EG_EXCLUSION_WITNESS_UNBOUND` |
| `test_witness_bound_to_another_candidate_is_refused` | witness candidate `b…`, claim candidate `a…` | `EG_EXCLUSION_WITNESS_CANDIDATE` |
| `test_self_authored_witness_is_refused` | reviewer role/identity is the author's | `EG_EXCLUSION_WITNESS_SELF_AUTHORED` |
| `test_absent_witness_result_is_refused` | `result.present = false` | `EG_EXCLUSION_WITNESS_RESULT_ABSENT` |
| `test_witness_result_digest_is_re_derived` | present file, wrong SHA-256 | `EG_EXCLUSION_WITNESS_DIGEST` |
| `test_witness_result_must_be_present_in_the_tree` | result path absent from the repo root | `EG_EXCLUSION_WITNESS_RESULT_ABSENT` |
| `test_exclusion_without_a_witness_does_not_stop_propagation` | old-style exclusion during propagation | refusal is not raised; obligation still propagates |
| `test_exclusion_bound_to_another_candidate_does_not_stop_propagation` | witness for another candidate during propagation | obligation still propagates |
| `test_duplicate_object_key_is_refused_with_path` | `{"claims":[{"id":"A","id":"B"}]}` | `EG_JSON_DUPLICATE_KEY` at `$/claims/0/id` |
| `test_non_finite_number_is_refused_with_path` | `NaN` under `quantification/measure` | `EG_JSON_NON_FINITE` at `$/quantification/measure` |
| `test_infinite_number_is_refused` | `[Infinity]` | `EG_JSON_NON_FINITE` |
| `test_overflowing_number_is_refused` | `1e999` decodes to infinity | `EG_JSON_NON_FINITE` at `$/n` |
| `test_cli_refuses_duplicate_key_with_path` | duplicate top-level key through the CLI | `EG_JSON_DUPLICATE_KEY` at `$/claims` |

### Benchmark reconstruction (`forensics/tools/tests/test_analyse_bench_api.py`)

| control | malformed input | asserted identifier |
|---|---|---|
| `test_well_formed_campaign_is_accepted` | complete small campaign (positive) | no refusal; `results.json` written |
| `test_missing_identity_is_refused` / `test_duplicated_identity_is_refused` / `test_substituted_identity_is_refused` / `test_extra_identity_is_refused` | identity population gap | `PFP_IDENTITY_POPULATION` with `missing=`, `duplicated=`, `substituted=`, `extra=` |
| `test_duplicate_repetition_is_refused` / `test_missing_repetition_is_refused` / `test_substituted_repetition_is_refused` | repetition population gap | `PFP_ORDERING_IDENTITY` |
| `test_repetition_must_be_one_pair` | `candidate, candidate` | `PFP_ORDERING_PAIR` |
| `test_realised_balance_is_checked_per_repetition` / `test_declared_balance_must_be_balanced` | realised or declared balance wrong | `PFP_ORDERING_BALANCE` |
| `test_empty_check_side_is_refused` | both `CHECK` files empty | `PFP_CHECK_POPULATION` with `no CHECK lines` |
| `test_missing_check_identifier_is_refused` / `test_duplicated_check_identifier_is_refused` / `test_extra_check_identifier_is_refused` | check population gap | `PFP_CHECK_POPULATION` |
| `test_missing_cross_direction_is_refused` / `test_duplicated_cross_pair_is_refused` / `test_substituted_cross_direction_is_refused` | cross-verification gap | `PFP_CROSS_POPULATION` |
| `test_cli_refuses_duplicated_identity`, `test_cli_refuses_duplicated_repetition`, `test_cli_refuses_empty_check_side`, `test_cli_refuses_missing_check_identifier`, `test_cli_refuses_substituted_cross_direction` | end-to-end campaign mutations | the corresponding `PFP_*` identifier on stderr with exit status 1 |
| `test_duplicate_key_is_refused_with_path` / `test_non_finite_number_is_refused_with_path` / `test_infinite_number_is_refused` / `test_overflowing_number_is_refused` / `test_valid_document_loads` | strict JSON | `PFP_JSON_DUPLICATE_KEY` / `PFP_JSON_NON_FINITE` with the JSON pointer; valid input loads |
| `test_cli_refuses_duplicate_json_key` / `test_cli_refuses_non_finite_json` | end-to-end JSON mutations | `PFP_JSON_DUPLICATE_KEY` at `$/campaign`; `PFP_JSON_NON_FINITE` at `$/repetitions` |

## Determinism

Both validators produce sorted, fixed-separator output with no timestamp. Two
consecutive runs over the committed evidence were compared byte for byte:

```
python3 forensics/tools/tests/test_etp_claims.py       -> Ran 59 tests ... OK
python3 forensics/tools/tests/test_analyse_bench_api.py -> Ran 34 tests ... OK
python3 forensics/tools/etp_claims.py validate          -> rc=0, valid=true, 0 refusals, 35 claims
analyse_bench_api.py --work <PFP-0> ... --out /tmp/pfp0-a.json
analyse_bench_api.py --work <PFP-0> ... --out /tmp/pfp0-b.json
cmp /tmp/pfp0-a.json /tmp/pfp0-b.json                   -> DETERMINISTIC_SAME
cmp /tmp/pfp0-a.json <PFP-0>/results.json               -> MATCHES_COMMITTED_RESULTS
```

The second comparison is stronger than a determinism check: the hardened
reconstruction of the committed campaign reproduces the committed `results.json`
byte for byte.

## Re-validation against committed evidence

### `evidence/etp/claims.json`

* 35 claims, 0 refusals under the schema, the cross-field laws and the Git-bound
  digest re-derivation (`validate` defaults to the full tree check).
* The committed document contains **no exclusion records** (zero occurrences of
  `"exclusions"`), so the stricter witness rule refuses nothing and **no witness
  was invented** for any of the 90 open obligations.
* No previously accepted claim loses acceptance. The four contradictions, 13
  `PARTIAL` claims and 17 `ESTABLISHED` claims keep their recorded verdicts. The
  distinction that must be stated plainly: **the rules were too weak before, not
  the evidence wrong**. This hardening is a finding about the validator; it is
  not a re-adjudication of any claim's truth.

### PFP-0 campaign

The hardened reconstruction accepts the committed campaign. It derives and
matches exactly:

* **Identity:** 58 process identity rows = warm-up 2 + 15 repetitions × 2
  subjects + allocation probe 2 + 6 cross-verification repetitions × 2 signer
  roles × 2 subjects. No missing, duplicated, substituted or extra row.
* **Ordering:** repetitions `00`–`14` once each; every row one
  candidate/authority pair; 8 candidate-first and 7 authority-first, matching the
  declared balanced sequence.
* **Correctness checks:** each repetition carries nine `CHECK` identifiers, once
  on each side, matching the nine workload ids declared in `WORKLOADS.json`.
* **Cross verification:** exactly the 12 declared tuples — six repetitions ×
  two directions — with `verified=1` and one shared public key.
* **Results and allocations:** the nine declared workload ids once each in every
  `RESULT` and `ALLOC` population.

No previously accepted measurement loses acceptance. One path correction was
needed in the review brief rather than in the evidence: the cross-verification
table is at `evidence/performance-frontier/campaigns/PFP-0/cross-verification.tsv`,
not under `raw/`. The analyser already reads the campaign-root path, and the
committed file is the declared 12-row set.

## What the hardened machinery still cannot establish

* A witness proves that a result **exists at a digest-bound path** and that the
  declared reviewer differs from the declared author. It does not prove that the
  reviewer is organisationally independent, that the reviewer actually reviewed,
  or that the procedure was executed as named. §7 of `AGENTS.md` still applies:
  external review and organisational independence are outside the algebra.
* The claim author is a declared field. A document can declare any distinct role
  and identity; distinctness is enforced, genuine independence is not.
* Exact populations are derived from declarations that already existed: the
  preregistration, the warm-up paragraph, the allocation-probe phase and the
  cross-verification repetition list. The derivation encodes the harness's phase
  label convention (`warmup`, `rep-NN`, `alloc`, `cross-NN-role`). A future
  harness that changes those labels must change the analyser with it; the
  validator refuses the new population rather than guessing.
* Strict JSON rejects ambiguity and non-finite numbers. It does not validate the
  semantic truth, freshness or completeness of the parsed values beyond the
  rules the algebra already states.
* `--no-tree-check` remains an explicit escape for documents whose digests
  cannot be resolved; it is opt-in, and the controls in this receipt use it only
  for synthetic fixtures. With the default, a digest that cannot be re-derived
  is a refusal.
* `build_identity.py`, `emit_shell.py` and PFP-1's `analyse_pfp1.py` are outside
  this change and still parse their generator inputs with `json.loads`. No
  claim or result document is read by them, so the stated finding is closed for
  claim and result documents; the wider repository is not claimed to be strict.
* No Rust build, Miri, sanitizer, cryptographic vector or timing instrument was
  run: the change is Python validator machinery and its evidence is the mutation
  controls above. This receipt does not claim any safety, cryptographic or
  timing property.

## Files changed

| file | change |
|---|---|
| `forensics/tools/etp_claims.py` | strict JSON loading; admitted exclusion witnesses; operation validation before `conjoin`/`invalidate`/`propagate`/`contradictions`; witness owner tracking in propagation |
| `evidence/etp/claim.schema.json` | optional claim `author`; required exclusion `witness` with a closed result and reviewer type |
| `forensics/tools/tests/test_etp_claims.py` | witness, CLI-bypass and strict-JSON mutation controls; propagation controls updated to require a witness |
| `courts/performance-frontier/baseline/analyse_bench_api.py` | exact identity, ordering, check and cross-verification populations; strict JSON; stable `PFP_*` refusal identifiers |
| `forensics/tools/tests/test_analyse_bench_api.py` | unit and end-to-end mutation controls plus a positive campaign reconstruction |
| `docs/ETP-CLAIM-ALGEBRA.md` | refusal table and witness requirement |
| `docs/ETP-TODO.md`, `docs/PERFORMANCE-FRONTIER-TODO.md` | recorded hardening and its evidence commit |
