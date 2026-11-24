# A2 receipt — lossless evidence preservation and population reconciliation

Status: **BATCH-level evidence for item A2 of `docs/ETP-TODO.md` §E.** The axes
are preservation of what a finding came from and mechanical reconciliation of a
native population against an exported one. No claim about memory safety,
cryptographic correctness or compatibility is made here.

Source identity at the start of the batch: `staging` at
`9c3af068a374a3a4e686139bdbc89ce79d123e3f`, worktree clean (`git status
--porcelain` empty). This batch adds new paths and modifies
`docs/ETP-TODO.md`; it does not commit. The orchestrator commits.

`free -g` at the start: `total 45, used 37, free 4, buff/cache 7, available 8`,
swap `45 used, 0 free`. The §6.1 cap is `min(8, 8 − 16) = −8 GiB`, below the 2 GiB
floor, so no new court was started. Every command ran in the already-running
capped container `openssl-rs-court`
(`openssl-rs-court-tools:1`, `Memory 6 GiB`, `MemorySwap 6 GiB`, 8 CPUs),
checked with `docker inspect` and `/proc/pressure/io` (`some avg10=0.00`) before
use. No compile, link, test binary or Rust toolchain ran; the work is Python
3.11.2 standard library. One heavy command ran at a time.

## 1. What was built

| artefact | path | SHA-256 |
|---|---|---|
| normative document | `docs/EVIDENCE-PRESERVATION.md` | `bcf8a8c36258dfdcfa4c06c3f73fe37d6369be6a6e179d2138b05cdf1166e2e1` |
| tool | `forensics/tools/evidence_preservation.py` | `199dd2053d2fdc514eceef81228c869768a1191995146ac43991556796e22086` |
| controls (25 tests) | `forensics/tools/tests/test_evidence_preservation.py` | `1eb4e0555808458a28e2de144690ec2b605c32b79158affd4635a2e9a83adef7` |
| preservation record | `evidence/a2/PRESERVATION.json` | `e505d926fcf3eb60e610e7bd8c2835ddc152630f1a4bdd3c1ff351c2e0c19343` |
| reconciliation record | `evidence/a2/RECONCILIATION.json` | `c5147d2553df3244ada9f6e61a2cbea94933096a7b41669c57a5783450b4510e` |
| content-addressed store | `evidence/a2/raw/sha256/<digest>` (6 entries) | each entry hashes to its own name |

The documents record the producing tool's path and digest
(`tool.sha256 = 199dd205…`), so a change to the tool changes both records'
identity and `verify` refuses a document produced by a different tool.

## 2. The preserved field set and what is content-addressed

Per source, `PRESERVATION.json` records: the exact bytes' SHA-256, byte length,
`preservation:sha256:<hex>` address and store path; the invocation (kind, text,
locators, whether an exact argument vector is recorded, and the limitation); the
instrument identity (path, version, digest, `identity_complete`, and the
instrument register where one exists); the candidate block verbatim; the
production time or an explicit statement that none is recorded; every
population block with its declared count, the locators that declare it and the
enumerated count; every bound with its population, sample, omitted count,
`members_recorded`, selection rule and **what was not examined**; every
unsupported operation, exclusion, not-run analysis, ignored-test count and
unused instrument; the record's non-claims verbatim; and the certification
state with the field families searched.

Content-addressed: the six native records, byte-identically, under
`evidence/a2/raw/sha256/`. Total **29,376,465 bytes** — `SAFETY-SITES.json`
15,629,485, `closure-curl-049.json` 13,655,604, `SECRETS.json` 41,004,
`timing-bn-findings.json` 24,289, `b85c-adjudication.json` 13,552,
`b85c-row-reconciliation.json` 12,531. Each store entry's digest equals the
digest A1 records for that run (`sha256sum` over the store in §8).

The store does not hold the untracked court outputs (the `--edge-records` JSONL
sidecar and instrument binaries). The closure record names that sidecar as the
place the 249 omitted members are written; `git ls-files` shows no such file
tracked. The bound is therefore preserved with `members_recorded: false` and the
omitted members are counted, not recovered.

## 3. The six A1 sources: identity and certification

| run | record | instrument | invocation | certified |
|---|---|---|---|---|
| 0 | `evidence/b85c-adjudication.json` | none recorded | none recorded | **no** — `PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT` |
| 1 | `evidence/b85c-row-reconciliation.json` | none recorded | none recorded | **no** — same code |
| 2 | `evidence/closure-curl-049.json` | `consumer_closure.py` v6, `141b8a0f…` | procedure, `exact_arguments: false` | yes |
| 3 | `evidence/etp-t4/SAFETY-SITES.json` | `unsafe_obligations.py`, `443634a3…` | `python3 forensics/tools/unsafe_obligations.py inventory` | yes |
| 4 | `evidence/etp-t7/SECRETS.json` | none recorded | none recorded | **no** — same code |
| 5 | `evidence/timing-bn-findings.json` | instrument register (valgrind, dudect, clang, binutils, binsec, court image/caps) | four harness invocations | yes |

Three certified, three refused. The three refusals cover 72 emitted results
(17 + 4 + 51). The refusal note names where the record mentions the producer in
prose without recording it as a structured field; prose is not treated as an
identity because it cannot be re-derived.

## 4. The three reconciliations

Native population is the record's declared count; exported population is the
members A1 emitted, matched by the locator each result carries; the difference
is named in both directions. 4 245 results over 6 runs, all reconciled
(`results_reconciled = results = 4245`), 96 537 native members enumerated, 4 242
exported members matched, **0 unaccounted, 0 fabricated**.

### 4.1 curl closure (`run 2`, certified)

| block | declared | enumerated | exported members | results | unidentified | coverage |
|---|---|---|---|---|---|---|
| obligations | 7 | 7 | 7 | 8 (1 attached disposition conflict) | 0 | `CENSUS` |
| residual sites | **449** | **200** | **200** | 201 (200 + 1 bound) | **249** | `TRUNCATED_BOUNDED` |
| verdict | 1 | 1 | 1 | 1 | 0 | `RECORD_CONDITION` |
| element-7 predicate | 1 | 1 | 1 | 1 | 0 | `RECORD_CONDITION` |
| refusals | 0 | 0 | 0 | 0 | 0 | `CENSUS` |

Difference: `native_members_outside_export = 249`,
`export_members_absent_from_native = 0`. Run `covers_population: false`,
`coverage.claim: REFUSED`. The preserved bound states
`sample 200 / population 449 / omitted 249 / members_recorded false` with the
selection rule and the statement that the omitted members are written to the
sidecar and are not identified. The export shows 200 emitted and 249 omitted; a
claim that it covers the population raises
`PRESERVATION_REFUSED_COVERAGE_CLAIM`.

### 4.2 safety sites (`run 3`, certified)

| block | declared | enumerated | exported members | results | coverage |
|---|---|---|---|---|---|
| contract-absent sites | 1 036 | 1 036 | 1 036 | 1 036 | `CENSUS` |
| vacuity findings | 2 916 | 2 916 | 2 916 | 2 916 | `CENSUS` |
| suppressions | **1 999** | **0** | 0 | 1 aggregate | `AGGREGATE_ONLY` |
| site census | 62 297 | 62 297 | 0 | 0 | `CENSUS_DECLARED_NOT_PROJECTED` |
| operations | 767 | 767 | 0 | 0 | `DECLARED_SCOPE` |
| contracts | 29 223 | 29 223 | 0 | 0 | `DECLARED_SCOPE` |
| ignored tests | 54 | 0 | 0 | 0 | `DECLARED_SCOPE` |

Both finding populations are censuses; the per-lint suppression partition sums
to 1 999 but no member row exists, so the run reports
`declared_populations_without_member_rows: [{suppressions, 1999}]`,
`declared_scope_members_not_emitted = 92 341`, and
`covers_population: false` with `claim: REFUSED`. Native minus export is 0
finding members; the 1 999 suppressions are a population the export cannot
cover, not a member gap. Suppression governance is A6's.

### 4.3 timing (`run 5`, certified)

| block | declared | enumerated | exported members | results | coverage |
|---|---|---|---|---|---|
| primitives | 2 | 2 | 2 | 2 | `CENSUS` |
| not-run analyses | 7 | 7 | 7 | 7 | `CENSUS` |

Difference: 0 in both directions. `covers_population: true`,
`claim: ADMITTED`. The resource bound (`instruments.court_caps`) states what was
not examined and names the seven analyses in `not_run`.

The three uncertified runs are reconciled on the same terms and all report 0 in
both directions (secret register 51/51; adjudication 7 mechanisms + 8
refutations + 2 conditions; row reconciliation 3 + 1). Their coverage is
admitted and their certification is refused; the two answers are independent.

## 5. Refusals and their controls

Fifteen refusal codes, each with a control in
`forensics/tools/tests/test_evidence_preservation.py` (table in
`docs/EVIDENCE-PRESERVATION.md` §7). Observed:

| condition | control | observed |
|---|---|---|
| store entry absent | `test_verify_refuses_missing_raw_bytes` | `PRESERVATION_REFUSED_RAW_BYTES_ABSENT` |
| store entry corrupt | `test_verify_refuses_corrupt_raw_bytes` | `PRESERVATION_REFUSED_DIGEST_MISMATCH` |
| record changed, old digest reused | `test_verify_refuses_changed_bytes_with_old_export_digest` | `PRESERVATION_REFUSED_STALE_REEXPORT_DIGEST` |
| record changed, new digest exported | `test_verify_refuses_changed_bytes_with_new_export_digest` | `PRESERVATION_REFUSED_MANIFEST_STALE` |
| population disagrees, no bound | `test_capture_refuses_population_mismatch_without_bound` | `PRESERVATION_REFUSED_POPULATION_MISMATCH` |
| one block's own declared sources disagree | `test_capture_refuses_declared_population_disagreement` | `PRESERVATION_REFUSED_POPULATION_MISMATCH` |
| export re-scopes a declared omission | `test_reconcile_refuses_a_rescoped_declared_omission` | `PRESERVATION_REFUSED_POPULATION_MISMATCH` |
| no invocation and no instrument identity | `test_verify_refuses_missing_invocation_and_instrument` | `PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT` |
| bound without "what was not examined" | `test_bound_without_statement_of_what_was_not_examined_is_refused` | `PRESERVATION_REFUSED_BOUND_UNEXPLAINED` |
| native member neither emitted nor omitted | `test_reconcile_refuses_unaccounted_member` | `PRESERVATION_REFUSED_EXPORT_UNACCOUNTED` |
| export member absent from the record | `test_reconcile_refuses_fabricated_member` | `PRESERVATION_REFUSED_EXPORT_FABRICATED` |
| emitted result matches no block | `test_reconcile_refuses_unrouted_result` | `PRESERVATION_REFUSED_UNROUTED_RESULT` |
| different producing tool | `test_verify_refuses_a_different_producing_tool` | `PRESERVATION_REFUSED_TOOL_IDENTITY` |
| coverage claim on a non-census | `test_truncated_population_is_bounded_not_a_census` | `PRESERVATION_REFUSED_COVERAGE_CLAIM` |
| native record absent or invalid JSON | test_capture_refuses_an_unreadable_native_record, test_capture_refuses_invalid_json | PRESERVATION_REFUSED_RECORD_UNREADABLE |

The two "missing instrument" and "missing invocation" codes are constructed in
`certification()` and are exercised by the real-data control: the three
uncertified records carry neither.

`verify` over the real records exits **2** and refuses, naming all three:

```
PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT: 3 source(s) cannot be
certified: evidence/b85c-adjudication.json, evidence/b85c-row-reconciliation.json,
evidence/etp-t7/SECRETS.json
```

`verify --reconciliation` first re-derives the reconciliation's own three
addresses (preservation document, export bytes, tool digest) and only then
reports certification, so a stale reconciliation is named before a
certification refusal.

## 6. Boundary with A5 and A6

* **A5** owns completeness admission. A2 records expected versus enumerated
  population, skips, not-run analyses, ignored tests and truncations with their
  counts and bounds, refuses a coverage claim beyond what it can establish, and
  marks an aggregate-only population as never covered. A2 does not decide
  whether a truncation policy, a scope exclusion or an absent population is
  acceptable; no field answers that question.
* **A6** owns suppression governance. A2 preserves the suppression total, its
  per-lint partition and the statement that no member row exists, refuses
  coverage of that population, and records nothing else. No suppression
  justification, reviewer, independence, expiry or consequence is recorded here.

## 7. Determinism

Two captures and two reconciliations over the same bytes are byte-identical,
including a second capture that finds the store already populated:

```
python3 forensics/tools/evidence_preservation.py capture --out /tmp/p2.json
cmp evidence/a2/PRESERVATION.json /tmp/p2.json      # identical
python3 forensics/tools/evidence_preservation.py reconcile --out /tmp/r2.json
cmp evidence/a2/RECONCILIATION.json /tmp/r2.json    # identical
```

No clock, machine, account, process, working directory or absolute path enters
either document; production times are copied from the records; members are
ordered lexicographically; the store's written/existing settlement is not
recorded.

## 8. Validation actually run

| check | command | result |
|---|---|---|
| controls | `python3 -m unittest discover -s forensics/tools/tests -p test_evidence_preservation.py` | **25 tests, 0 failures, 0 errors** |
| JSON well-formedness (preservation) | `python3 -m json.tool evidence/a2/PRESERVATION.json` | PASS |
| JSON well-formedness (reconciliation) | `python3 -m json.tool evidence/a2/RECONCILIATION.json` | PASS |
| store integrity | `sha256sum evidence/a2/raw/sha256/*` | each entry equals its name |
| addresses re-derived | `verify --reconciliation evidence/a2/RECONCILIATION.json` | reconciliation verified, then certification refused (exit 2, three codes) |
| determinism | second capture and reconciliation + `cmp` | byte-identical |
| first-person text | first-person pronoun scan over the new document, tool, tests and both JSON records | no first-person prose; the only naive-scan match is the compiler include flag inside a compile line preserved verbatim from timing-bn-findings.json, and a Roman-numeral heading that pre-dates this batch in docs/ETP-TODO.md |

The export reconciled is unchanged A1 evidence:
`evidence/a1/SARIF.json`, SHA-256
`5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852`, 6 runs,
4 245 results. No A1, A0, `src/` or `docker/` file was modified.

## 9. What is not established

* Whether the 249 omitted residual sites are a prefix, a sample or the full
  contract-bounded subclass. `NOT_RUN`: it needs the untracked `--edge-records`
  sidecar or a re-run of `consumer_closure.py`. A0 recorded the same limit.
* The content of the untracked sidecar and of other court working directories.
  Not preserved; stated in `docs/EVIDENCE-PRESERVATION.md` §3.
* Whether the three uncertified records were produced by the tools their prose
  names. `NOT_RUN`: no structured identity exists to re-derive.
* Whether the blocks A2 models are the only populations in each record. The
  model is explicit per record in the tool's descriptor registry; a population
  the registry does not name is outside the reconciliation, and the omission
  would be a defect in the model, not a pass.
* Independent review (AGENTS.md §15), BOUNDARY and SEAL evidence. `NOT_RUN`.
* Any cryptographic, timing or compatibility consequence. Outside these axes.

## 10. Non-claims

Preservation is not completeness, correctness or honesty. A matched member is a
member that is present, not one that is justified or current. Coverage states
that the export is a census of the modelled blocks, not that the model is
exhaustive. The store is content-addressed, not signed, attested or
timestamped. The instrument identity recorded is the one the record states.
Reconciliation does not re-audit any receipt.
