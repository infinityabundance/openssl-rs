# Closure discipline

Status: ETP-T10 deliverable. This document is normative for the exclusion and
aggregation rules applied to the safe-c33 consumer closures. It records the
bar, the opaque-operation contract requirement, the aggregation rule, the
measured counts and the non-claims. It is bound to the records produced by
`forensics/tools/closure_discipline.py`; it is not a claim that any consumer is
safe or graduated.

The item is **not** a licence to close a gap by adding an exclusion. An
exclusion that cannot be independently checked is recorded as failing and stays
failing. A `SAFE_COMPATIBLE` verdict that depends on such a closure fails; a
verdict that previously passed and now fails is recorded as failing rather than
softened.

## 1. What is audited

`forensics/tools/consumer_closure.py` measures a reachable set for each consumer
and records the omissions it admits. `forensics/tools/closure_discipline.py`
audits those omissions and the operations the closure cannot see into. Five
omission populations are read from each receipt:

| category | receipt source | what it is |
|---|---|---|
| `production-operation-exclusions` | `closure_scope.excluded_from_upper_bound` | a production operation excluded from the conservative upper bound |
| `documented-enrolment-exclusions` | `documented_enrollment.excluded` | a documented operation that no longer exists at the recorded identity |
| `indirect-target-drops` | `edge_provenance.records_sample[].exclusions` | an indirect site whose candidate target is dropped |
| `unresolved-indirect-sites` | `precision.residual_sites` and the coverage counts | a reachable indirect dispatch that the analysis leaves unresolved or only set-bounded |
| `analysis-limit-omissions` | `graph.limits` | a global limitation of the analysis (inlining, residual may-bound, input completeness) |

A target-drop population is complete only when the number of per-site records
equals the number the receipt declares in `edge_provenance.exclusion_reasons`.
An incomplete sample produces an extra failing row for the unrecorded remainder;
the remainder is never dropped from the denominator. The same rule applies to
`precision.residual_sites`: when the per-site list is shorter than
`precision.totals.reachable_unresolved_sites`, the missing sites are counted as
failing because they have no recorded identity. The audit also records, as
failing rows, a non-empty `precision.unclassified_reachable_sites`,
`boundary_coverage.reachable_files_without_receipt`, and a non-zero
`disposition_conflicts.unresolved_obligation_count` or `unresolved_edge_count`.

The audit reads the populations the receipts record. It does not re-run the
closure, rebuild the candidate, or enumerate operations the receipt does not
record; §8 states what that omits.

## 2. The exclusion bar

An exclusion passes only when all five requirements hold. A row missing any
requirement is counted as failing; no row is removed to make a closure look
complete.

| requirement | meaning |
|---|---|
| `edge_identity` | the exact omitted edge is named: a consumer import, a symbol, an indirect site plus its dropped target, or a `file:line:kind` operation identity. A count is not an identity. |
| `reason` | the argument states why the omission cannot affect the claim. A partial-resolution marker such as `base-slot-partial` is not a reason. |
| `procedure` | a reproducible procedure a third party can run. "Would be checked" is not a procedure. |
| `identity_binding` | the procedure is bound to the candidate identity the closure claims (install prefix, DSO digests, source commit, inventory path), so it cannot be satisfied by a different build. |
| `checkable_result` | every input the procedure needs is present at the recorded identity, and the receipt records the observed result. An unavailable input makes the argument an assertion. |

Each row carries a disposition:

- `ARGUMENT` — all five requirements hold; the exclusion is independently checkable.
- `ASSERTION` — an edge is named but at least one requirement fails.
- `ADMITTED_LIMITATION` — a global limitation with no edge, reason or procedure.
- `NON_CLAIM` — a limitation that is not an exclusion at all and is not counted.

The distinction matters: a passing row establishes that the procedure *can be
run* against the recorded identity. It does not establish that the procedure was
re-run for this record.

## 3. Measured classification

At candidate `7e70b667f`, over the three tracked consumer closures
(`evidence/closure-curl-049.json`, `evidence/closure-ssh-b85c.json`,
`evidence/closure-sshd-b85c.json`):

| category | rows | passing | failing |
|---|---:|---:|---:|
| production-operation-exclusions | 12 | 4 | 8 |
| documented-enrolment-exclusions | 111 | 37 | 74 |
| indirect-target-drops | 484 | 175 | 309 |
| unresolved-indirect-sites | 505 | 161 | 344 |
| analysis-limit-omissions | 9 | 0 | 9 |
| **total** | **1121** | **377** | **744** |

Per consumer:

| consumer | rows | passing | failing |
|---|---:|---:|---:|
| curl | 420 | 377 | 43 |
| ssh | 374 | 0 | 374 |
| sshd | 327 | 0 | 327 |

The failures split by missing requirement:

| missing requirements | rows | cause |
|---|---:|---|
| `checkable_result` only | 695 | the argument is structurally complete, but the recorded candidate DSO or inventory is not present at the recorded identity |
| `checkable_result`, `reason` | 39 | an `ABI_OPEN_METHOD_TABLE`, `field` or `materialised` site has no contract and no exclusion reason |
| all five | 10 | nine global analysis limits plus one unsampled population |

Two findings follow directly and neither is softened:

1. **The OpenSSH closures cannot be checked at the current identity.** The ssh
   and sshd receipts name candidate DSO `06b5f338…` and inventory
   `court/freeze-b85/census-b85.json`. At `7e70b667f` the tracked
   `artifacts/phase2/install/lib/libcrypto.so.3` is the curl candidate
   `fd25cc9e…`, and the census path is untracked. Every ssh/sshd argument that
   depends on those inputs therefore fails `checkable_result`, even though the
   argument names its edge, reason and procedure.
2. **curl's element-7 population is not fully recorded.** The curl receipt
   records `reachable_unresolved_sites = 449` but only 200 per-site records. The
   remaining 249 have no recorded identity, so no exclusion argument can be
   checked for them. Of the 200 recorded sites, 39 are `field`,
   `materialised` or `ABI_OPEN_METHOD_TABLE` sites with no contract and no
   reason.

The 3 analysis-limit failures per consumer are admitted limitations, not
excluded edges: inlining, the residual may-bound and analysis-input
completeness. They fail because no edge, reason or procedure can be supplied for
a global limitation; they are recorded, not waived.

## 4. Opaque operations

An operation the closure cannot see into is scoped only when its contract states
three things:

| requirement | meaning |
|---|---|
| `assumption` | what the operation is assumed to do |
| `scope` | the scope of the assumption |
| `falsifier` | what would falsify it |

The contract registry is `consumer_closure.ABI_CONTRACTS`. A registry entry is
scoped when it supplies `contract` (the assumption), `covers` (the scope) and
`does_not_cover` (the conditions under which the assumption does not apply,
which is what falsifies it). The audit records a registry entry as scoped only
when all three are present and non-empty.

At `7e70b667f`, the audit records 55 operation rows covering 472 sites:

| status | rows | sites |
|---|---:|---:|
| scoped by the contract registry | 24 | 390 |
| **no contract** | **31** | **82** |

The 31 rows without a contract are:

| kind | rows | what has no contract |
|---|---:|---|
| `dlsym-literal-not-covered` | 18 | `CRYPTO_free`, `OPENSSL_init_crypto`, `__pthread_get_minstack`, `conf_ssl_get`, `conf_ssl_get_cmd`, `conf_ssl_name_find` (six literals in each of three closures) |
| `dynamic-name-lookup` | 6 | `DSO_bind_func`, `DSO_convert_filename` (two in each of three closures) |
| `unmodelled-shared-object` | 5 | `libz.so.1` and `libc.so.6` (curl), `libz.so.1` and `libc.so.6` (ssh), `libc.so.6` (sshd) |
| `candidate-contract-without-witness` | 1 | one `ABI_CONTRACT_PROVIDER` call site in curl has no per-call-site witness |
| `abi-class-without-contract` | 1 | `ABI_OPEN_METHOD_TABLE`, 18 sites in curl |

An operation listed here is not thereby unsafe. It is an admission that the
closure cannot see into it under a documented interface. No contract was added
to remove a row.

## 5. Aggregation

A summary may not be stronger than its members. An aggregate that reports an
overall pass while containing a blocked, unresolved or not-established row is
refused. The refusal does not edit the aggregate; it records that the aggregate
cannot be cited as a pass.

Two mechanisms enforce the rule:

- `forensics/tools/closure_discipline.py` audits eight real aggregates and emits
  `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW` when a pass contains a blocked row.
- `forensics/tools/etp_claims.py` refuses a positive aggregate claim whose
  `aggregate_cells` contains a cell declaring a blocked `declared_state`
  (`EG_AGGREGATE_PASS_HIDES_BLOCKED_CELL`), and refuses a positive aggregate
  whose cells omit the state entirely (`EG_AGGREGATE_CELL_STATE_UNDECLARED`).

### Demonstration on real aggregates

| aggregate | reported state | blocked rows | result |
|---|---|---|---|
| `evidence/SAFE-COMPATIBLE-openssh-b85c.json` | `SAFE_COMPATIBLE` (pass) | `dissent` (`NOT_ESTABLISHED`) | refused |
| `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` | 1/33 graduates (pass) | three b8x adjudications `NOT ESTABLISHED`, `boundary_gate` and `seal_gate` blocked | refused |
| `evidence/FREEZE-b85c.json` | `safe_compatible: false` (fail) | eleven `not_run` rows, seven `outstanding` rows | not refused; blocked rows stay visible |

The primary demonstration is `evidence/SAFE-COMPATIBLE-openssh-b85c.json`. It
reports `verdict.value = SAFE_COMPATIBLE` while carrying a `dissent` object that
records an independent adjudicator's `NOT ESTABLISHED`. The audit refuses the
aggregate: a pass that contains a not-established adjudication is not a pass.
`FREEZE-b85c.json` is the positive control in the other direction: it reports
failure and keeps its blocked rows visible, so no refusal is needed. A
`retraction` whose `withdrawn_claim` is a sub-claim (not the aggregate's own
verdict) is recorded as `RETRACTED_SUB_CLAIM` history and is not counted as a
blocked row; only a retraction of the aggregate's own verdict is blocking.

## 6. Binding to the graph and the algebra

Closure results are nodes and edges in `evidence/etp-t1/TRACEABILITY.json`. Each
consumer closure produces an obligation node `OBL-CLOSURE-<CONSUMER>-EXCLUSIONS`
carrying

```
closure_exclusions = {rows, failing_rows, category, failing_ids}
```

with a `raises` edge from `IMP-CONSUMER-CLOSURE` and `constrains` edges to the
release claims the closure supports. `failing_ids` enumerates every omitted edge
that fails the bar, so no omitted edge is dropped at the projection.

`forensics/tools/traceability.py` class 13 makes the omission an orphan:

- `ORPHAN-13:<obligation>` when an obligation's `closure_exclusions.failing_rows`
  is positive;
- `ORPHAN-13:CLAIM:<claim>` when a positive release claim is constrained by such
  an obligation.

At `7e70b667f` the graph is 361 nodes, 475 edges and 43 declared orphans, of
which four are class 13:

```
ORPHAN-13:OBL-CLOSURE-CURL-EXCLUSIONS
ORPHAN-13:OBL-CLOSURE-SSH-EXCLUSIONS
ORPHAN-13:OBL-CLOSURE-SSHD-EXCLUSIONS
ORPHAN-13:CLAIM:REL-OPENSSH-B85C
```

**Existing verdict that now fails.** `REL-OPENSSH-B85C` claims
`SAFE_COMPATIBLE`. Its closure is the ssh and sshd pair, which fails the bar
(374 and 327 failing rows respectively). Under the rule the verdict is refused:
`ORPHAN-13:CLAIM:REL-OPENSSH-B85C` is recorded and the release claim is no longer
supported by a clean closure. The rule was not softened to keep the previous
verdict.

The claim algebra half is `EG_SAFE_COMPATIBLE_CLOSURE_UNBOUND` (a graduated
verdict names no auditable closure receipt) and
`EG_SAFE_COMPATIBLE_EXCLUSION_FAILS_BAR` (the named receipt has a failing
exclusion). The committed `evidence/etp/claims.json` contains no
`SAFE_COMPATIBLE` claim, so `etp_claims.py validate` still reports 35 claims and
zero refusals; the rule is exercised by controls rather than by the committed
set.

## 7. Controls and determinism

All controls are standard-library `unittest` inside the court.

| control | what it proves |
|---|---|
| `forensics/tools/tests/test_closure_discipline.py` (23 tests) | each of the five bar requirements is load-bearing; a limitation is admitted but never passes; an unsampled drop is counted; a contract is scoped only with assumption, scope and falsifier; the real `SAFE-COMPATIBLE-openssh-b85c` pass is refused and `FREEZE-b85c` is not; a sub-claim retraction is not a blocked row; two builds are byte-identical; the committed evidence matches a fresh build at the commit it names |
| `closure_discipline.py --self-test` | seven control groups, including per-requirement bar checks, opaque-operation kinds, aggregate refusal and determinism |
| `forensics/tools/tests/test_etp_claims.py` (85 tests) | the committed claim set validates; a positive aggregate hiding a blocked cell is refused; an undeclared cell state is refused; a non-positive aggregate may keep a blocked cell visible; a graduated claim with no closure receipt or with a failing exclusion is refused |
| `forensics/tools/tests/test_traceability.py` (30 tests) | the graph validates with 43 declared orphans and zero undeclared or stale; a missing class-13 declaration is refused; a clean exclusion makes its declaration stale; more failing rows than rows is a structural refusal; the seed reproduces the graph byte for byte |

Determinism: `build_documents` is byte-stable over two runs, `audit_aggregates`
is stable, and the committed `EXCLUSIONS.json` and `OPAQUE-OPERATIONS.json` match
a fresh build at the commit recorded in their `identity` block.

## 8. Non-claims and residuals

- The audit covers the populations the receipts record. It does not enumerate
  operations the receipt does not record. The 249 unrecorded curl residual sites
  are counted as failing, not inventoried.
- The residual/lot procedures recompute with the recorded analyser
  (`consumer_closure.py`). That is reproducible but not independent of the
  analyser; an independent reimplementation is not claimed.
- A passing row establishes that the procedure can be run at the recorded
  identity. It does not establish that it was re-run, that its result is correct,
  or that the external implementation is safe.
- External provider modules, unmodelled shared objects, `dlsym` literals and
  dynamic name lookups are listed; where no contract exists the row says so. No
  contract was fabricated to reduce the list.
- CPU intrinsics, inline assembly and libc syscall wrappers are not separately
  enumerated by the closure. The boundary contract for an unmodelled shared
  object (`libc.so.6`, `libz.so.1`) is the only coverage at that layer; no
  per-syscall or per-intrinsic contract is claimed.
- The audit does not establish memory safety, constant-time behaviour,
  cryptographic correctness or functional compatibility. It is a record of
  omission discipline.
- The graph projection records the omission counts at `S = 21bea3188`, the
  graph's claim tier. The ETP-T10 evidence files record candidate `7e70b667f`.
  The two identities are named separately and are not interchangeable.

## 9. Reproduction

Inside the court (`docker/openssl-rs-court.sh`, Python 3.11):

```
python3 forensics/tools/closure_discipline.py --self-test
python3 forensics/tools/closure_discipline.py check
python3 forensics/tools/closure_discipline.py emit
python3 forensics/tools/etp_t1_seed.py
python3 forensics/tools/tests/test_closure_discipline.py
python3 forensics/tools/tests/test_etp_claims.py
python3 forensics/tools/tests/test_traceability.py
python3 -m json.tool evidence/etp-t10/EXCLUSIONS.json >/dev/null
python3 -m json.tool evidence/etp-t10/OPAQUE-OPERATIONS.json >/dev/null
```

`check` exits 1 while any exclusion fails or any aggregate is refused. That exit
status is the refusal of a promotion, not a defect in the tool; `emit` records
the same facts in `EXCLUSIONS.json`, `OPAQUE-OPERATIONS.json` and
`AGGREGATES.json`.
