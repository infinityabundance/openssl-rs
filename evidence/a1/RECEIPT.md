# A1 receipt — SARIF 2.1.0 profile and deterministic adapter

Status: **BATCH-level evidence for item A1 of `docs/ETP-TODO.md` §E.** No claim
about memory safety, cryptographic correctness or compatibility is made here; the
axes are fidelity of a projection and honesty about what the projection does not
contain.

Source identity at the start of the batch: `staging` at
`33ace9aff84b78fdf12d8ebe859719316f62ee6c`, worktree clean. This batch adds four
paths and does not commit; the orchestrator commits. The emission describes the
native records by their own bytes, so it is bound to those records rather than to
the commit that carries this receipt.

## 1. What was built

| artefact | path | SHA-256 |
|---|---|---|
| profile (normative) | `docs/SARIF-PROFILE.md` | `330a0063af5d799ab8648e20581d3aa42b8cbf32d4bfda59bcacf443257180b4` |
| adapter | `forensics/tools/sarif_adapter.py` | `35614b905d18bea2090fcac9e8c86ddee08b470fd7ad0ccbca189d4a54929d5b` |
| controls (26 tests) | `forensics/tools/tests/test_sarif_adapter.py` | `fa2f37768fde021dab745533ecca1bd1bf7f754e721a48ab62133bbedfa761b6` |
| emission | `evidence/a1/SARIF.json` | `5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852` |

The emission records the adapter digest it was produced by
(`runs[*].properties.a1.adapter.sha256 = 35614b90…`), which equals the tracked
adapter's digest. A change to the adapter therefore changes the emission's own
identity record; the file must be regenerated when the adapter changes.

## 2. Inputs, candidate identities and populations

Six native records, one SARIF run each, ordered by record path. Every value below
is read from the record and copied verbatim; nothing is inferred.

| run | record SHA-256 | candidate identity | native population | projected |
|---|---|---|---|---|
| `evidence/b85c-adjudication.json` | `24e11717aa72bf0c39425987d826df3cc59da0c4d05e4d280dc4ab99a9f4ab5d` | `evidence_source_head 17042ccf2…`, `head_at_adjudication bfa39a6c3`, `src_content_sha256 bc6815c2…`, `freeze_sha256 b08131b1…` | 8 refutations, 7 mechanisms, 5 prose items | 17 |
| `evidence/b85c-row-reconciliation.json` | `a684b6af66220dcc6741b35b6e45f50f23cea5f3e3a888aee4f5f0c9d963d7c4` | `source_candidate 17042ccf2…`, `head_at_review fc1a1e8df` | 3 rows, 1 limits block | 4 |
| `evidence/closure-curl-049.json` | `b72193072780e9a425e7e93be8c0c15849d06c758b9e71f226cafb4992388c62` | `repository_head 17e45eec1…`, `libcrypto.so.3 fd25cc9e…`, `libssl.so.3 648f8cae…` | 7 obligations, 0 refusals, 200-of-449 residual sites | 211 |
| `evidence/etp-t4/SAFETY-SITES.json` | `7fb1ef96b7b7b36b9d49ae7283743b51ec9db6170bbde74074a6af0a8856e7da` | `commit 246e30580…`, `source_tree_sha256 ef8678c5…`, `scanner_sha256 443634a3…` | 62 297 sites, 2 916 vacuity findings, 1 036 contract-absent rows, 1 999 suppressions | 3 953 |
| `evidence/etp-t7/SECRETS.json` | `b6f30fa86e2767efc9eb861faedbf099749a4b1288c7d2705ed2f29e01cf67a1` | `commit 0eddfe839…` | 51 entries in 5 classes | 51 |
| `evidence/timing-bn-findings.json` | `7289fbce2dabe40be92538c916736dba7c4d5250c1fae6e12767580daad8696c` | `source_head 18d12e1d5…`, `libcrypto_sha256 fd25cc9e…`, `build_id 592a81d4…` | 2 primitives, 7 not-run analyses | 9 |

The adjudication record digest `24e11717…` agrees with the digest ETP-T15 records
for the unchanged b85c adjudication (the ETP-T15 row in `docs/ETP-TODO.md`), which
is an independent check that the projected bytes are the adjudicated bytes.

The closure's `install_prefix` is deliberately not emitted: it is a build-layout
path and Appendix F §F.4 forbids machine-specific path leakage in a deterministic
log. The digests are emitted instead.

## 3. Emission

4 245 results over 6 runs, 24 rules. 13 651 450 bytes.

| run | results | record-level | line regions | binary regions | exact collisions |
|---|---|---|---|---|---|
| b85c-adjudication | 17 | 17 | 0 | 0 | 0 |
| b85c-row-reconciliation | 4 | 4 | 0 | 0 | 0 |
| closure-curl-049 | 211 | 3 | 8 | 200 | 0 |
| SAFETY-SITES | 3 953 | 1 | 3 952 | 0 | 0 |
| SECRETS | 51 | 0 | 51 | 0 | 0 |
| timing-bn-findings | 9 | 7 | 0 | 2 | 0 |

| rule | count | level (dominant) |
|---|---|---|
| `A1-ADJUDICATION-CROSS-CUTTING` | 1 | error |
| `A1-ADJUDICATION-MECHANISM` | 7 | error (5) / note (2) |
| `A1-ADJUDICATION-REFUTATION` | 8 | error |
| `A1-ADJUDICATION-VERDICT` | 1 | error |
| `A1-RECONCILIATION-LIMIT` | 1 | warning |
| `A1-RECONCILIATION-ROW` | 3 | note |
| `A1-CLOSURE-VERDICT` | 1 | none (informational) |
| `A1-ELEMENT7-PREDICATE` | 1 | error |
| `A1-ISA-BINARY-UNRESOLVED` | 200 | warning |
| `A1-ISA-POPULATION-TRUNCATED` | 1 | warning |
| `A1-OBLIGATION-DISCHARGED` | 7 | none (informational) |
| `A1-OBLIGATION-DISPOSITION-SUPERSEDED` | 1 | note |
| `A1-UNSAFE-CONTRACT-ABSENT` | 1 036 | warning |
| `A1-UNSAFE-OBLIGATION-DELEGATED` | 2 391 | note |
| `A1-UNSAFE-OBLIGATION-UNESTABLISHED` | 36 | error |
| `A1-UNSAFE-OBLIGATION-VACUOUS` | 489 | warning |
| `A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT` | 1 | warning |
| `A1-SECRET-CLASSIFICATION-RECORDED` | 7 | note |
| `A1-SECRET-CLEANSING-UNMET` | 12 | error |
| `A1-SECRET-CONTROL-NO-EVIDENCE` | 6 | warning |
| `A1-SECRET-EVIDENCE-CONTRACT-ONLY` | 20 | note |
| `A1-SECRET-LEAKAGE-REPORTED` | 6 | error |
| `A1-TIMING-LEAKAGE-DETECTED` | 2 | error |
| `A1-TIMING-NOT-RUN` | 7 | warning |

Levels: **72 error / 1 741 warning / 2 424 note / 8 none**. Kinds: 4 237 `fail`,
8 `informational` (SARIF §3.27.9 requires `kind = "fail"` whenever `level !=
"none"`).

How unresolved, blocked, not-run and superseded findings appear:

- the one superseded disposition (`P25-ENGINE-CB-000` at
  `obligations[2].disposition_conflicts[0]`) is a result of its own at `level =
  note`, with `superseded: true`, the keyword and the receipt that superseded it,
  verbatim. It does not replace the DISCHARGED obligation result beside it;
- `NOT_ESTABLISHED` verdict, five mechanisms, the cross-cutting block and eight
  refutations are `level = error`;
- seven named not-run timing analyses are `level = warning` results built from the
  record's `not_run` list;
- the 200-of-449 residual list is emitted in full as 200 results, and the bound
  (`sample_size 200`, `population_size 449`, `omitted_members 249`,
  `omitted_members_recorded false`) is a separate `warning` result. The list is
  never presented as a census;
- 1 999 suppressions with no member rows appear as one `warning` result whose
  limitation property says the record holds no member location.

## 4. The six required controls

Observed in `forensics/tools/tests/test_sarif_adapter.py`; each control constructs
its own fixture so that it cannot pass because the repository happens to contain
the shape.

| # | control | test | observed |
|---|---|---|---|
| 1 | a superseded finding appears and is marked | `test_superseded_row_is_emitted_and_marked` (fixture) and `test_superseded_real_row_is_present` (real record) | result present, `level = note`, `properties.a1.superseded = true`, native `keyword = BLOCKED` carried verbatim, message says "superseded"; the real emission contains exactly one such result and the discharged obligation beside it |
| 2 | a binary finding with no line information is emitted with a symbol region and no fabricated line | `test_binary_finding_has_no_fabricated_line`, `test_real_binary_findings_never_claim_a_line` | `region` holds `byteOffset` only; `address.absoluteAddress` is the function offset with `kind = "function"`; no `startLine`/`endLine`/`startColumn` anywhere in the result or its `relatedLocations`; `lineInfoAvailable = false`; every location in the run asserted line-free |
| 3 | two occurrences in different artefacts that share a rule have distinct exact identities and are not interchangeable | `test_same_rule_in_different_artifacts_not_interchangeable` | same `ruleId`, equal `a1Logical/v1`, different `a1Exact/v1`, different artifact URIs, `fingerprints_interchangeable(...) == False`, both results emitted |
| 4 | an unchanged finding across runs keeps its logical identity | `test_unchanged_finding_keeps_logical_identity` | two builds produce identical fingerprint objects |
| 5 | a changed location changes the exact identity and not the logical identity | `test_changed_location_changes_exact_not_logical` | moving `src/a.rs:10` to `:11` leaves `a1Logical/v1` equal and `a1Exact/v1` different; the untouched entries are unchanged |
| 6 | a native record whose candidate identity is absent refuses the run rather than emitting unattributed results | `test_missing_candidate_identity_refuses_emission`, `test_missing_candidate_block_refuses_emission`, `test_cli_refusal_writes_no_output` | `Refusal` with `SARIF_REFUSED_MISSING_CANDIDATE_IDENTITY`; the CLI exits 2, prints the code and writes no output file |

Additional controls: population mismatch (`summary.contract_absent` versus decoded
rows; truncation bound versus list length) refused with
`SARIF_REFUSED_POPULATION_MISMATCH`; a binary site whose DSO has no recorded digest
refused with `SARIF_REFUSED_MISSING_ARTIFACT_DIGEST`; an unknown native status
refused with `SARIF_REFUSED_UNSUPPORTED_NATIVE_SHAPE`; an exact-identity collision
counted and both results kept (`fingerprintCollisions = 1`, no merge) in
`test_colliding_exact_identities_are_counted_not_merged`.

## 5. Determinism

Two independent CLI runs over the same inputs produced byte-identical files
(`cmp`), and a third run after the profile document was edited produced the same
bytes. Verified in `test_determinism_is_byte_identical` and by hand:

```
python3 forensics/tools/sarif_adapter.py --repo-root . --out evidence/a1/SARIF.json
python3 forensics/tools/sarif_adapter.py --repo-root . --out /tmp/sarif-check.json
cmp evidence/a1/SARIF.json /tmp/sarif-check.json      # identical
sha256sum evidence/a1/SARIF.json                      # 5c0cfee6…
```

Determinism rests on: no time, machine, account, process, working directory,
environment or absolute path; `json.dumps(sort_keys=True, indent=2)`; runs ordered
by record path; results ordered by `(ruleId, a1Exact, a1Logical, record, locator,
message)`; rules by id; artifacts by URI; projection and collision lists sorted.

## 6. Validation actually run

| check | command | result |
|---|---|---|
| JSON well-formedness | `python3 -m json.tool evidence/a1/SARIF.json` | PASS |
| structural profile validation | `validate_emission` invoked by the adapter on every build | PASS (the emission was written, so it was accepted) |
| controls | `python3 -m unittest discover -s forensics/tools/tests -p test_sarif_adapter.py` | 26 tests, 0 failures, 0 errors |
| determinism | second emission + `cmp` | byte-identical |
| document consistency | `python3 forensics/tools/docs_consistency.py` | PASS (20 claims agree; constitution wired) |

## 7. The four A0 defect classes, and what this emission does instead

`docs/EVIDENCE-AUDIT.md` names four classes A1 must not reproduce. Each is
addressed by a mechanism, not by prose:

| A0 class | instance inherited by A1 | what the emission does |
|---|---|---|
| truncation (F01, F02) | the 200-of-449 residual list; 1 999 suppressions without member rows | the 200 rows are emitted; the bound result carries sample, population, omitted count, `omitted_members_recorded false` and the native selection rule; the suppression aggregate is emitted with `membersRecorded: false`. Neither is a rounded-up summary. |
| silent suppression (F05, F09) | superseded dispositions; ledger rows read as satisfied | superseded rows are emitted and marked; refutation 4 of the adjudication (`0 BLOCKED is receipt coverage, not adjudication`) is emitted verbatim; nothing is suppressed, and `result.suppressions` is forbidden. |
| summary without reconstruction (F10, F11) | curl `verdict.state = ACCEPTED` beside `predicate_element_7.status = FAIL` | the verdict and the predicate are two results of two rules; neither is folded into the other. Every result carries its record digest and JSON locator; every run declares its native population and projected counts. |
| wrong-candidate application (F15, F16) | six records at five distinct source identities | one run per record, each with its own candidate block; every result repeats the candidate; a missing candidate refuses the whole file. |

## 8. What is not established

- **OASIS JSON-Schema validation is NOT_RUN.** No JSON-Schema validator exists in
  the Python standard library, and the profile adds no dependency. The emission is
  checked by `validate_emission` (a structural check written alongside the
  adapter), by `json.tool`, and by the controls; none of these is the OASIS schema.
  Conformance Clauses 1 and 2 are claimed on that basis; Clauses 3–5 are
  explicitly not claimed.
- **A2 (lossless preservation) is not implemented.** The emission names the native
  record, its digest and the locator; it does not preserve raw tool output,
  arguments, timeouts or unsupported operations. `run.properties.a1.projection`
  names what was projected and what was not, with counts, but reconciliation of the
  native and exported populations is A2's.
- **A5 (completeness admission) is not implemented.** No run states a population is
  complete. The `notProjected` blocks are declarations of scope, not a completeness
  result; an absent population is not an empty one.
- **A6 (suppression governance) is not implemented.** A1 never suppresses and never
  emits `result.suppressions`; the aggregate-without-members result is the closest
  it comes, and it is a limitation, not a governance record.
- **A3/A4 remain the project-wide identity and location items.** The profile defines
  the scheme this emission uses; it does not replace the cross-artefact model (A3)
  or the full Rust/FFI/binary fidelity review (A4). No macro-expanded or
  monomorphised finding occurs in this emission, and the profile states the class
  rule without an instance.
- **Fingerprint collision behaviour was exercised on a fixture, not on the real
  data.** The real emission has zero exact-identity collisions; the control proves
  the collision path counts and keeps both results when one is constructed.
- **The emission is not evidence about the code.** It is an index into native
  records at the stated identity. A consumer that claims a finding must read the
  record at the locator and re-derive the digest.

## 9. Environment and cost

`free -g` at the start reported `available = 15` GiB. The §6.1 cap is
`min(8, 15 − 16) = −1` GiB, below the 2 GiB floor, so no new court was started. An
already-running capped container (`openssl-rs-court`, 6 GiB memory and swap, 8
CPUs) was used for every command in this batch. No compile, link, test binary or
Rust toolchain ran; the work is Python 3.11 standard library and JSON. One heavy
command ran at a time.

`forensics/tools/check_evidence_portability.py` reports a pre-existing failure in
`gen_bn_dh.py` that is unrelated to this batch and was not repaired here.

## 10. Non-claims

A SARIF result is not a vulnerability, a memory-safety result, a timing result or a
compatibility result. A clean or complete-looking log is not an absence of defects.
`level` is a native disposition class, not a probability. A fingerprint authorises
no reuse across artefacts or candidates. A covered obligation is receipt coverage,
not a re-audit. The file is not signed, attested, timestamped or
transparency-logged. Conformance to a format is not evidence of correctness.
