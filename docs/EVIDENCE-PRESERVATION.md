# Lossless evidence preservation and population reconciliation (A2)

Status: **normative for item A2 of `docs/ETP-TODO.md` §E.** The tool that
implements it is `forensics/tools/evidence_preservation.py`; the batch evidence
is `evidence/a2/RECEIPT.md`, `evidence/a2/PRESERVATION.json` and
`evidence/a2/RECONCILIATION.json`. Nothing in this document is a claim about
memory safety, cryptographic correctness or compatibility. The axes here are
preservation of what a finding came from, and the mechanical reconciliation of a
native population against the population an export emitted.

## 1. What A2 governs

The exports in scope are the six runs of `evidence/a1/SARIF.json`, each
projecting one native record:

| run | native record |
|---|---|
| 0 | `evidence/b85c-adjudication.json` |
| 1 | `evidence/b85c-row-reconciliation.json` |
| 2 | `evidence/closure-curl-049.json` |
| 3 | `evidence/etp-t4/SAFETY-SITES.json` |
| 4 | `evidence/etp-t7/SECRETS.json` |
| 5 | `evidence/timing-bn-findings.json` |

A1's emission already carries, per result, the native record path, its SHA-256
and a JSON locator. A2 supplies what A1 explicitly declined to own: the
preserved bytes themselves, the invocation, the instrument identity, the
declared and the enumerated population with its remainders, the bounds and their
unexamined remainder, and the reconciliation between the two populations. A1's
emission is **not modified**; A2 binds to it through the record digests A1
already records and re-derives them.

## 2. What is preserved per finding source

Every field below is written into `evidence/a2/PRESERVATION.json` for each of
the six sources. Values copied from the record are copied verbatim and are
attributed to the locator they were read from.

| field | content | source |
|---|---|---|
| `raw.sha256` | SHA-256 of the exact bytes read | computed |
| `raw.byte_length` | length of those bytes | computed |
| `raw.address` | `preservation:sha256:<hex>` | computed |
| `raw.preserved_path` | the store entry holding those bytes | computed |
| `invocation` | the recorded command, harness, compile line or procedure; whether an exact argument vector is recorded; the locators read; the limitation where only a procedure is named | record |
| `instrument` | the producer's path, version and digest, or the instrument register, with `identity_complete` | record |
| `candidate` | the candidate identity block, verbatim | record |
| `produced` | the field and value that state when the record was produced, or an explicit statement that no generation time is recorded | record |
| `populations[]` | each block's declared count, the locators that declare it, the enumerated count and the member selector | record + computed |
| `bounds[]` | kind, population, sample, omitted, whether omitted members are recorded, the selection rule, and **what was not examined** | record |
| `unsupported_operations[]` | exclusions, not-run analyses, the scanner's granularity and heuristic flag, ignored tests, instruments declared unused | record |
| `non_claims` | the record's own non-claims, verbatim | record |
| `certification` | `certified`, the refusal code when not, and the field families searched | computed |
| `export` | the SARIF run index and the record digest that run cites | A1 |

*An unsupported operation, a timeout or a bound is recorded, never omitted.* A
source with no bound records `bounds: []`; the absence is a fact about the
record, not an invitation to assume completeness.

### What counts as an invocation and as an instrument identity

Both are read from **structured fields only**. A producer named in prose is not
treated as an instrument identity, because prose is not mechanically
re-derivable and cannot be re-checked after the record changes.

* An invocation is recorded when a structured field names a command, harness,
  compile line or procedure. `exact_arguments` distinguishes an argument vector
  or command string from a procedure description.
* An instrument identity is recorded when a structured field names a producer
  with a digest or a version. A name with a digest is accepted for a record that
  carries no version, and the limitation is recorded.

Three sources meet both requirements and are certified: the closure record
(`tool.path`, `tool.version`, `tool.sha256`), the safety-site record
(`identity.scanner`, `identity.scanner_sha256`, `identity.settling_method`), and
the timing record (the instrument register and four harness invocations). Three
do not: the adjudication record, the reviewer row reconciliation and the secret
register carry no structured producer identity and no structured invocation.
They are preserved in full and **refused certification** with
`PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT`, and the note names
where prose mentions the producer without recording it as a field. A1 emitted
72 results from those three records; that is the population the refusal
concerns.

## 3. The content address

```
address := "preservation:sha256:" hex(SHA-256(bytes))
store   := evidence/a2/raw/sha256/<hex>
```

* The store entry is the **exact bytes that were read**, byte-identical to the
  native record at capture time. It is a copy, not a link: a later edit to the
  record does not change what the address resolves to.
* `write_store` is idempotent. An existing entry is re-hashed and must equal the
  address; a corrupt entry is refused, never overwritten silently.
* `verify` re-reads the store entry, re-derives the digest, and separately
  re-derives the digest of the live record. Three outcomes follow: the three
  agree (verified); the export cites a digest that is not the record's (refused
  as a mismatch); the record changed after capture (refused as stale).
* The tool's own path and digest are recorded in both documents
  (`tool.path`, `tool.sha256`). A document produced by a different version of
  the tool refuses to verify.

Cost is stated rather than hidden: the six records total **29,376,465 bytes**,
of which `SAFETY-SITES.json` is 15,629,485 and `closure-curl-049.json` is
13,655,604. The duplication is the price of an address that resolves without
the mutable path. A git-blob address would be cheaper and would not survive an
uncommitted edit, so it is not used.

**What is not addressed.** The store holds records, not the working directories
that produced them. Untracked court outputs (the `--edge-records` JSONL sidecar
named by the closure record, instrument binaries, stored logs) are outside it.
The closure record states that the 249 members omitted from
`precision.residual_sites` are written to that sidecar; the sidecar is not
tracked by `git ls-files` and is not preserved here. The record's
`omitted_members_recorded: false` is therefore matched by a reconciliation that
names the omission as a count and refuses coverage — never by a claim that the
members are recoverable.

## 4. Populations

A **population block** is a named set of finding-bearing members inside one
native record. Six roles exist, and only the first two can be covered:

| role | meaning | may be covered |
|---|---|---|
| `finding` | members are findings; the export is expected to project them | yes, when it is a census |
| `record_condition` | a single record-level verdict, predicate or limit | yes, when emitted |
| `census` | a full enumeration that is not a finding population (e.g. 62 297 lexical sites); the export declares it not projected | no |
| `aggregate_only` | a count with no member rows at all (e.g. 1 999 suppressions by lint) | **never** |
| `declared_scope` | a block the record counts and the export declares outside its projection, with a reason | no |

`declared` is the count the record states, and every source that states it is
recorded; a block whose own sources disagree with each other is refused at
capture. `enumerated` is the number of members the tool derives from the same
bytes through a documented selector, independently of the export. A member's
identity is its locator into the native record; the export's member is the
locator it carries at `properties.a1.native.locator`. A nested locator (e.g.
`obligations[2].disposition_conflicts[0]`) attaches to its enclosing member and
is counted as an attached result, not as an extra member; a result at a bound
locator (e.g. `precision.residual_sites_bound`) is an aggregate statement about
the block, not a member.

| record | blocks (declared / enumerated) |
|---|---|
| curl closure | obligations 7/7, residual sites 449/200 (**bound**), verdict 1/1, predicate 1/1, refusals 0/0 |
| safety sites | contract-absent 1036/1036, vacuity findings 2916/2916, suppressions 1999/**0** (**aggregate only**), site census 62297/62297, operations 767/767, contracts 29223/29223, ignored tests 54/**0** |
| timing | primitives 2/2, not-run 7/7 |
| secret register | entries 51/51 |
| b85c adjudication | mechanisms 7/7, cross-cutting 1/1, refutations 8/8, verdict 1/1, `item1..item5` 5/5, non-claims 3/0 |
| b85c row reconciliation | rows 3/3, limits 1/1, narrative 3/3 |

## 5. Reconciliation rules

For each export run the tool answers, mechanically: does the exported population
equal the native population, and if not, exactly which members are missing in
each direction?

1. **Route.** Every emitted result is assigned to exactly one block by its
   locator prefix; a result that routes nowhere is refused
   (`PRESERVATION_REFUSED_UNROUTED_RESULT`), because the membership question
   cannot be answered for it. The emitted rule counts must also equal the run's
   own `projection.projected`; a disagreement is a population mismatch.
2. **Match.** An emitted locator resolves to a member by exact match or by the
   longest enclosing member prefix. A locator that resolves to no member is
   **fabricated** and refused (`PRESERVATION_REFUSED_EXPORT_FABRICATED`).
3. **Two directions.** For each block the report states
   `declared`, `enumerated`, `exported_members`, `exported_results`,
   `attached_results`, `aggregate_results`, `members_not_enumerated`,
   `unidentified`, `unaccounted`, `fabricated`. At run level,
   `difference.native_members_outside_export` counts unidentified plus
   unaccounted finding members, and `difference.export_members_absent_from_native`
   counts fabricated members. Both are 0 together only for a census.
4. **Native member neither emitted nor declared.** `unaccounted`, refused
   (`PRESERVATION_REFUSED_EXPORT_UNACCOUNTED`). The refusal names the members.
5. **Counted but not listed.** `unidentified`. With a declared bound that names
   what was not examined, the block is `TRUNCATED_BOUNDED` and the run still
   refuses coverage. Without such a bound it is a population mismatch, refused
   at capture and at verification.
6. **Aggregate without members.** An `aggregate_only` block is never covered.
   The run reports `declared_populations_without_member_rows` and refuses
   coverage even when every finding block is a census.
7. **Declared scope.** A `census` or `declared_scope` block is reported as
   `declared_scope_members_not_emitted`; the export's own omission declaration
   for that block is compared with the native count. A declaration that
   re-scopes the population (a different count with no bound) is a population
   mismatch, refused.
8. **Coverage.** `coverage.covers_population` is true only when every `finding`
   block is a census of its declared population, every `record_condition` is
   emitted, and no `aggregate_only` block declares members. Otherwise
   `coverage.claim` is `REFUSED`, with a reason, and
   `assert_covers_population()` raises
   `PRESERVATION_REFUSED_COVERAGE_CLAIM` for any caller that asserts otherwise.

A run can be covered and uncertified (the population is fully emitted but the
record carries no producer identity), uncertified and uncovered, or covered and
certified. Coverage and certification are separate questions and are reported
separately.

## 6. The worked example: 200 of 449

`evidence/closure-curl-049.json` declares 449 reachable unresolved sites
(`precision.residual_sites_bound.population_size`, agreeing with
`precision.totals.reachable_unresolved_sites`) and embeds 200 rows in
`precision.residual_sites`. A0 recorded this as `F01`.

The reconciliation reports, for the `residual_sites` block:

| quantity | value |
|---|---|
| declared (native population) | 449 |
| enumerated (members in the record) | 200 |
| exported members (`A1-ISA-BINARY-UNRESOLVED`) | 200 |
| exported results in the block | 201 (200 members + 1 bound statement) |
| aggregate results (`A1-ISA-POPULATION-TRUNCATED`) | 1 |
| members not enumerated | 249 |
| unidentified | **249** |
| unaccounted | 0 |
| fabricated | 0 |
| coverage | `TRUNCATED_BOUNDED` |
| run `covers_population` | **false** |
| run `coverage.claim` | **REFUSED** |

The preserved bound records `sample 200 / population 449 / omitted 249`,
`members_recorded: false`, the selection rule, and the statement of what was not
examined. The export shows 200 emitted and 249 omitted; the reconciliation
refuses a claim that the export covers the population, and
`assert_covers_population()` on this run raises. The control
`test_truncated_population_is_bounded_not_a_census` constructs the same shape in
a fixture and asserts each figure.

## 7. Refusals

| code | condition | control |
|---|---|---|
| `PRESERVATION_REFUSED_RAW_BYTES_ABSENT` | the store entry for a record is missing | `test_verify_refuses_missing_raw_bytes` |
| `PRESERVATION_REFUSED_DIGEST_MISMATCH` | preserved bytes, live bytes or an export digest disagree with the address | `test_verify_refuses_corrupt_raw_bytes`, `test_check_reconciliation_refuses_a_reused_digest` |
| `PRESERVATION_REFUSED_STALE_REEXPORT_DIGEST` | the record changed after capture and the export still cites the preserved digest | `test_verify_refuses_changed_bytes_with_old_export_digest` |
| `PRESERVATION_REFUSED_MANIFEST_STALE` | the record changed after capture and the export cites the new digest | `test_verify_refuses_changed_bytes_with_new_export_digest` |
| `PRESERVATION_REFUSED_POPULATION_MISMATCH` | a population disagrees with the members listed, or with another source of the same count, or with the export's own omission declaration, and no bound reconciles it | `test_capture_refuses_population_mismatch_without_bound`, `test_capture_refuses_declared_population_disagreement`, `test_reconcile_refuses_a_rescoped_declared_omission` |
| `PRESERVATION_REFUSED_MISSING_INVOCATION_AND_INSTRUMENT` | no structured invocation and no structured instrument identity | `test_verify_refuses_missing_invocation_and_instrument` |
| `PRESERVATION_REFUSED_MISSING_INSTRUMENT_IDENTITY` | an invocation is recorded, no producer identity is | by construction in `certification()` |
| `PRESERVATION_REFUSED_MISSING_INVOCATION` | a producer identity is recorded, no invocation is | by construction in `certification()` |
| `PRESERVATION_REFUSED_BOUND_UNEXPLAINED` | a bound is declared without a statement of what was not examined | `test_bound_without_statement_of_what_was_not_examined_is_refused` |
| `PRESERVATION_REFUSED_EXPORT_UNACCOUNTED` | a native member is neither emitted nor declared omitted | `test_reconcile_refuses_unaccounted_member` |
| `PRESERVATION_REFUSED_EXPORT_FABRICATED` | the export emits a member the record does not contain | `test_reconcile_refuses_fabricated_member` |
| `PRESERVATION_REFUSED_UNROUTED_RESULT` | an emitted result matches no block | `test_reconcile_refuses_unrouted_result` |
| `PRESERVATION_REFUSED_TOOL_IDENTITY` | the document was produced by a different version of the tool | `test_verify_refuses_a_different_producing_tool` |
| `PRESERVATION_REFUSED_COVERAGE_CLAIM` | a caller asserts coverage the reconciliation refused | `test_truncated_population_is_bounded_not_a_census` |
| `PRESERVATION_REFUSED_RECORD_UNREADABLE` | a native record is absent or is not valid JSON | `test_capture_refuses_an_unreadable_native_record`, `test_capture_refuses_invalid_json` |

Every refusal is an exception with a stable code, a non-zero exit from the CLI,
and no output file written. None of them warns and continues.

## 8. What the six A1 sources show

| run | instrument + invocation | certified | finding population | coverage | difference |
|---|---|---|---|---|---|
| curl closure | tool path/version/digest; procedure with `exact_arguments: false` | yes | 7 obligations + 200-of-449 sites | **REFUSED** | 249 unidentified |
| safety sites | scanner path + digest; command string | yes | 1 036 contract-absent, 2 916 vacuity findings, all emitted | **REFUSED** | 1 999 suppressions with no member rows; 92 341 declared-scope members not emitted |
| timing | instrument register + four harness invocations | yes | 2 primitives + 7 not-run analyses, all emitted | ADMITTED | 0 |
| secret register | none recorded | **no** | 51 entries, all emitted | ADMITTED | 0 |
| b85c adjudication | none recorded | **no** | 7 mechanisms + 8 refutations + 2 conditions, all emitted | ADMITTED | 8 declared-scope members not emitted |
| b85c row reconciliation | none recorded | **no** | 3 rows + 1 limit, all emitted | ADMITTED | 3 narrative members not emitted |

Totals: 4 245 emitted results over 6 runs, 4 245 reconciled, 96 537 native
members enumerated, 4 242 exported members matched, 0 unaccounted, 0
fabricated, 249 unidentified, 2 coverage claims refused, 3 runs certified and 3
refused.

## 9. Boundary with A5 and A6

**A5 owns completeness admission.** A2 records the facts A5 judges and stops
there:

* the expected population (the record's declared counts) and the examined
  population (the enumerated members) are recorded side by side;
* a skip, a not-run analysis, an ignored test and a truncation appear as their
  own records, with counts and, where the record supplies it, members;
* A2 refuses a claim that an export covers a population it does not cover, and
  marks an aggregate-only population as never covered;
* A2 does **not** decide whether a declared truncation policy is acceptable,
  whether an absent population may be read as empty, whether an exit code
  implies completeness, or whether a scope exclusion is justified. Those are
  A5's, and A2 emits no field that answers them.

**A6 owns suppression governance.** A2 preserves the suppression aggregate with
its total, its per-lint partition and the statement that no member row exists;
it refuses coverage of that population and records nothing else about it. A2
does not record a justification, scope, reviewer, independence, expiry or
consequence for any suppression, and it emits no suppression disposition. A
suppressed finding is not represented here at all, because A1 emits no
suppressions and A2 preserves what A1 projected.

## 10. Determinism

Neither document contains a clock, machine, account, process, working directory
or absolute path. Production times are copied from the records. Members are
ordered lexicographically; the settlement of the store does not enter the
documents; JSON is written with sorted keys and a fixed indent. Two captures and
two reconciliations over the same bytes are byte-identical (`cmp`), including a
second capture that finds the store already populated. The controls
`test_capture_is_deterministic` and `test_capture_preserves_bytes_and_digest`
hold this; the receipt records the commands.

## 11. Non-claims

* **Preservation is not completeness.** A preserved record can still describe an
  incomplete population. A5 owns that judgement.
* **Preservation is not correctness.** Preserved bytes can encode a wrong
  result, a stale candidate or a contradicted verdict. A2 re-derives digests,
  not conclusions.
* **Reconciliation is not verification of the finding.** A matched member is a
  member that is present, not one that is justified, current or correct.
* **Coverage is not a promotion.** `covers_population: true` states that the
  export is a census of the populations this item modelled; it does not state
  that the model's blocks are the only populations in the record.
* **The store is not a notary.** Bytes are content-addressed, not signed,
  timestamped or transparency-logged.
* **The instrument identity recorded is the one the record states.** A2 does not
  execute the instrument, re-hash the producer binary, or establish that the
  record was produced by the tool it names.

## 12. What is not established

| item | state |
|---|---|
| whether the 249 omitted residual sites are a prefix, a sample or the full contract-bounded subclass | `NOT_RUN`: determining it requires the untracked `--edge-records` sidecar or a re-run of `consumer_closure.py`; A0 recorded the same limit |
| the content of the untracked sidecar and of other court working directories | not preserved; stated in §3 |
| whether the three uncertified records were produced by the tools their prose names | `NOT_RUN`: no structured identity exists to re-derive |
| BOUNDARY and SEAL level evidence | `NOT_RUN`; this batch carries FAST/BATCH controls |
| independent review of this item | `NOT_RUN`; the author is not the sole authority for its claims under §15 |
| cryptographic, timing or compatibility consequences of any preserved record | outside this item's axes |

## 13. The reconciliation's own address

`evidence/a2/RECONCILIATION.json` records the SHA-256 of
`evidence/a2/PRESERVATION.json` (content-addressed over the canonical document),
the SHA-256 of the export it reconciles, and the tool digest that produced it.
`verify --reconciliation` re-derives all three and refuses a reconciliation
whose named bytes no longer resolve. The binding runs in one direction — A1's
export names each native record and its digest, and A2's reconciliation names
the export — because A2 does not modify another item's evidence. A reverse
pointer in the export would be A3/A4 work and is not claimed here.
