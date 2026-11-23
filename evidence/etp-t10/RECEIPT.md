# ETP-T10 receipt — closure discipline

Status: implementation + records. This receipt is the evidence-commit record for
ETP-T10. It is **not** a graduation and it promotes no consumer. The rule it
implements makes one existing positive verdict fail; that failure is recorded
here and in the traceability graph, not softened.

## 1. Identity

| field | value |
|---|---|
| branch | `staging` |
| HEAD at start of the batch | `7e70b667f107c0f2f1dd297dfa6f7c285934d3e3` |
| worktree at start | clean |
| evidence identity recorded in the ETP-T10 files | `7e70b667f107c0f2f1dd297dfa6f7c285934d3e3` |
| graph claim-tier identity | `21bea318819a56f641b3aa2f25027216b97a1c4d` (`S`) |
| evidence commit `E` | the orchestrator's commit on top of `7e70b667f` |

The graph is bound to `S`, where the three closure receipts and their procedure
inputs are tracked. The ETP-T10 JSON files record `7e70b667f`, the source HEAD
they were generated from. The two identities name different things and are not
interchangeable.

## 2. Artefacts

| path | sha256 |
|---|---|
| `evidence/etp-t10/EXCLUSIONS.json` | `791c699d3c3f60e5dee0f26563573a988411ad6854a319286b9cc34719e48f90` |
| `evidence/etp-t10/OPAQUE-OPERATIONS.json` | `6f03c642b914c29ce4576bd47b99120cb176f7345a363f4877ee3cb05dbd2cd2` |
| `evidence/etp-t10/AGGREGATES.json` | `c7f31e73b67a1b7fcba1a9b8a6307281387303bdc06ed16d76888407cfc93925` |
| `evidence/etp-t1/TRACEABILITY.json` (regenerated) | `2fc3298fbe142db81acc51048364f78d8902c82a9598739dde132c3457a1a650` |
| `evidence/etp/claim.schema.json` | `8add927ac7e9e5b07eb513932c5151d9d789fd06f42a2636ab3763cee72b8c0c` |
| `docs/CLOSURE-DISCIPLINE.md` | `cf0a0476e7e8a6608a950bb946abbda6cb800b89dcf5dd76d6c71893942852a1` |
| `forensics/tools/closure_discipline.py` | `2362c045e647159aa764c14e58119a510ebcda1c23bef9d8b61a2063fe0b62b6` |
| `forensics/tools/etp_claims.py` | `1ac714e66b2521feedfc9ee05dd7f78b033fd762a1875e18ede3ff02b2719b89` |
| `forensics/tools/etp_t1_seed.py` | `748a06e91177ff5996d0153014487facc4b5afba5a10149ac3a507cb0c0e9297` |
| `forensics/tools/traceability.py` | `cf960ce7bf44338381725450f0b8c4f00733f2b09efa510de15c308e5441d564` |
| `forensics/tools/consumer_closure.py` | `26cc33bd1097275ee0a9f5e2a9474f6386221b3226f004a062f060e5c7cc497f` |
| `forensics/tools/tests/test_closure_discipline.py` | `bc6ce688562f5093197dee6f10d78674d44cc299c7c3b0f3e6b1129f5e947ddd` |

`EXCLUSIONS.json`, `OPAQUE-OPERATIONS.json` and `AGGREGATES.json` are accepted by
`python3 -m json.tool`.

## 3. What the parked work got right

The parked commit `7e70b667f` supplied the core classification and most of it
was kept:

- the five-requirement bar and the four-way disposition (`ARGUMENT`,
  `ASSERTION`, `ADMITTED_LIMITATION`, `NON_CLAIM`) are sound and were kept;
- the four omission categories, the per-row identity/reason/procedure/identity
  binding/result record, the contract requirement (`assumption`, `scope`,
  `falsifier`) and the aggregate refusal are sound and were kept;
- the schema addition is **additive and does not weaken a rule**: `declared_state`
  is an optional property on `aggregate_cell` with a closed enum, and
  `additionalProperties: false` is unchanged on the claim type and on
  `aggregate_cell`;
- `etp_claims.py validate` accepts the committed claim set unchanged (35 claims,
  0 refusals);
- `consumer_closure.closure_discipline_section` imports and runs on a real
  receipt (curl: 219 rows, 3 failing, 12 unscoped opaque rows) without a cycle.

## 4. What the parked work got wrong, and what changed

| defect | correction |
|---|---|
| `etp_t1_seed.py` imported `closure_discipline` but never used it; no closure result reached the graph, so section 1d's projection was absent | the seed now audits each closure at `S`, adds `OBL-CLOSURE-<CONSUMER>-EXCLUSIONS` with `closure_exclusions`, edges it to `IMP-CONSUMER-CLOSURE` and the supported release claims, and declares the class-13 orphans |
| `traceability.py` gained class 13 but no graph carried a class-13 node, so the rule was unreachable | the regenerated graph carries three class-13 obligation orphans and one class-13 claim orphan; four class-13 controls were added |
| the audit read only four omission populations; `precision.residual_sites`, the unrecorded residual remainder, `unclassified_reachable_sites`, `boundary_coverage` and unresolved disposition conflicts were not classified | a fifth category (`unresolved-indirect-sites`) and a coverage group were added; curl gains 40 failing rows (39 unregistered `field`/`materialised`/`ABI_OPEN_METHOD_TABLE` sites plus 249-of-449 unrecorded sites), so the element-7 population is no longer silently outside the audit |
| `_evaluate_bar` classified a row with a reason but no check as `ADMITTED_LIMITATION` | it is now `ASSERTION`; only a row with no edge, no reason and no check is admitted, and an admitted limitation never passes |
| an incomplete target-drop or residual sample was recorded as `complete: false` but not counted | the unrecorded remainder is now a failing row with no edge identity |
| a `retraction` of a sub-claim was counted as a blocked `WITHDRAWN` row | a sub-claim retraction is now `RETRACTED_SUB_CLAIM` history and is not blocking; only a retraction of the aggregate's own verdict is blocking. The `SAFE-COMPATIBLE-openssh-b85c` refusal therefore rests on its `dissent`, not on the retracted label |
| `EG_AGGREGATE_PASS_HIDES_BLOCKED_CELL` could be evaded by omitting every cell state | a positive aggregate with an undeclared cell state is refused (`EG_AGGREGATE_CELL_STATE_UNDECLARED`) |
| `check_closure_exclusions` audited the worktree and not the claim's identity | the audit now resolves the candidate DSO and inventory at the claim's `identity.source.commit` when one is named, and inserts the tools directory on `sys.path` |
| the parked `EXCLUSIONS.json` named commit `87d0868ef` and the parked `OPAQUE-OPERATIONS.json` was not reproducible (61 rows; the current tool merges a literal across DSOs to 55) | both files were regenerated at `7e70b667f`; a fresh build reproduces the committed bytes |
| the positive control `test_graduated_claim_with_complete_closure_is_accepted` depended on a non-closure dependency and failed under the new rule | the fixture now names a closure receipt, and a new control asserts that a graduated claim with no closure receipt is refused. The rule was not weakened |
| the seed did not reproduce the graph: `EV-HAZ-15-DIFFERENTIAL` hashes `evidence/haz-15/observables.json` from the **worktree** while its `bound_commit` does not contain the path, and commit `618f5e6ec` changed that file after the graph was generated | **pre-existing, not introduced by ETP-T10.** Regenerating the graph at the current bytes makes the reproduction test pass. The underlying worktree-read is recorded as a residual: a later edit to that file invalidates the graph's byte reproduction until the node is bound to a commit that contains it |

No exclusion was added and no contract was fabricated to reduce a count.

## 5. Results

| figure | value |
|---|---:|
| exclusion rows | 1121 |
| passing | 377 |
| failing | 744 |
| curl (rows / failing) | 420 / 43 |
| ssh (rows / failing) | 374 / 374 |
| sshd (rows / failing) | 327 / 327 |
| opaque rows / sites | 55 / 472 |
| opaque scoped rows | 24 |
| opaque rows with no contract / sites | 31 / 82 |
| real aggregates audited | 8 |
| aggregates refused | 2 |
| graph nodes / edges / declared orphans | 361 / 475 / 43 |
| class-13 orphans | 4 |

Failure split: 695 rows fail only `checkable_result`; 39 fail `checkable_result`
and `reason`; 10 fail all five (nine analysis limits and one unrecorded
population).

## 6. Verdicts affected

`REL-OPENSSH-B85C` claims `SAFE_COMPATIBLE`. Its ssh and sshd closures fail the
bar (374 and 327 failing rows), so class 13 records
`ORPHAN-13:CLAIM:REL-OPENSSH-B85C` and the verdict is no longer supported by a
clean closure. `REL-CURL-049` is `NOT_ESTABLISHED`, so it is not a positive
claim and class 13 does not add a claim orphan for it; its closure obligation is
still an orphan.

The committed typed claim set has no `SAFE_COMPATIBLE` claim, so the claim
algebra reports 0 refusals. The rule is therefore enforced but not exercised by
the committed set; the controls exercise it.

## 7. Controls and gate

| run | result |
|---|---|
| `closure_discipline.py --self-test` | 7 control groups pass |
| `forensics/tools/tests/test_closure_discipline.py` | 23 tests, 0 failures |
| `forensics/tools/tests/test_etp_claims.py` | 85 tests, 0 failures |
| `forensics/tools/tests/test_traceability.py` | 30 tests, 0 failures |
| `forensics/tools/tests` discovery | 396 tests, 3 failures, all pre-existing and named in §8 |
| `etp_claims.py validate` | 35 claims, 0 refusals, `valid: true` |
| `traceability.py validate` | 361 nodes, 475 edges, 43 declared and reproduced, 0 undeclared, 0 stale |
| `docs_consistency.py` | 20 hand-written claims agree |
| `python3 -m json.tool` on both required records | accepted |

`closure_discipline.py check` exits 1 with:

```
exclusion_rows: 1121
exclusions_failing: 744
exclusions_failing_by_consumer: {curl: 43, ssh: 374, sshd: 327}
aggregate_refusals: [safe-compatible-openssh-b85c, campaign-status]
opaque_unscoped_rows: 31
opaque_unscoped_sites: 82
```

Exit 1 is the refusal of a promotion, not a tool failure. A green exit would
claim that no omission is unresolved, which the records contradict.

## 8. Pre-existing failures

The full discovery reports three failures. None is introduced by this batch:

1. `test_spec_guard.SpecGuardControls.test_committed_registry_passes` —
   `SP_KNOWN_FAILURE_DRIFT: docs/ETP-TODO.md: tokens added
   ['OPENSSL_clear_free', 'guard_ffi'], removed []`. Both tokens are present in
   `HEAD:docs/ETP-TODO.md` before this batch, and the ETP-T10 row does not add a
   token.
2. `test_spec_guard.SpecGuardControls.test_check_output_is_deterministic` — the
   same drift makes `check` exit 1; the determinism assertion fails on the exit
   status, not on differing output.
3. `test_unsafe_obligations.UnsafeObligationControls.test_committed_inventory_and_axioms_validate`
   — `ET4_SOURCE_DRIFT`: the inventory records an older source-tree digest. `src/`
   is untouched by this batch.

## 9. Non-claims

- The audit covers the omission populations the receipts record. It does not
  re-run the closure, rebuild the candidate, or invent per-site identities for
  the 249 unrecorded curl residual sites; those are counted as failing.
- Every passing row establishes that the procedure can be run at the recorded
  identity. It does not establish that it was re-run for this record, that its
  result is correct, or that the operation is safe.
- The residual procedures recompute with the recorded analyser. That is
  reproducible, not independent of the analyser.
- CPU intrinsics, inline assembly and libc syscall wrappers are not separately
  enumerated; the only contract at that layer is the unmodelled-shared-object
  row, and no per-syscall or per-intrinsic contract is claimed.
- No memory-safety, constant-time, cryptographic or functional-compatibility
  result is claimed.
- The ETP-T10 records and the graph are bound to different identities
  (`7e70b667f` and `S = 21bea3188`) and are not interchangeable.

## 10. Reproduction

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=<computed> OPENSSL_RS_COURT_MEMSWAP=<computed> \
  bash docker/openssl-rs-court.sh exec sh -c '
    cd /work &&
    python3 forensics/tools/closure_discipline.py --self-test &&
    python3 forensics/tools/closure_discipline.py emit &&
    python3 forensics/tools/etp_t1_seed.py &&
    python3 forensics/tools/tests/test_closure_discipline.py &&
    python3 forensics/tools/tests/test_etp_claims.py &&
    python3 forensics/tools/tests/test_traceability.py'
```

The memory cap is computed from live availability, never assumed; see
`AGENTS.md` §6.1.
