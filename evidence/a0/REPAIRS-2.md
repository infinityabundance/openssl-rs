# A0 evidence-audit repairs, second batch — F01, F06, F10

Item: A0 of `docs/ETP-TODO.md` (findings only; this record holds the repairs).
Date: 2026-11-23.
Base: branch `staging`, HEAD `2d31a23fb25f52ab4c443212d34cd05ded715185`, clean
worktree at the start.
Commit identity: **`TO_BE_FILLED_BY_ORCHESTRATOR`** (this record and the source
changes are returned uncommitted; the orchestrator commits and records the hash).

This batch repairs three of the eighteen findings in
`evidence/a0/FINDINGS.json`: `A0-F01` (a sampled list presented as the
population), `A0-F06` (a stale full-gate transcript) and `A0-F10` (a status row
that overstates the cohort). The findings themselves are left in place in
`docs/EVIDENCE-AUDIT.md` and `evidence/a0/FINDINGS.json`; §2.5 of the audit
gains three repair rows beside them.

The first batch — `A0-F15` and `A0-F16` — is recorded in
`evidence/a0/REPAIRS.md`. That record states that the `STATUS.md` finding it
numbers `F10` "is left open"; that statement was true of that batch. It is
superseded here for the `STATUS.md` row, and `REPAIRS.md` is not edited.

---

## 1. A0-F01 — a sampled list presented as the population

### What the record said

`evidence/closure-curl-049.json` carried 200 rows in `precision.residual_sites`
beside `precision.totals.reachable_unresolved_sites = 449`
(`reachable_target_bounded_unresolved_sites = 219`,
`reachable_contract_bounded_sites = 158`,
`reachable_closed_target_set_sites = 72`; the three sum to 449). No field named a
limit, a sample size, a selection rule or a truncation flag. A reader who counted
the rows concluded 200 unresolved sites and that the rest were closed; the
record's own blocking predicate (`predicate_element_7`, `FAIL`) is the 449.

### What the record now says

`precision.residual_sites_bound` is added immediately after the list, and the
list itself is unchanged:

| field | value |
|---|---|
| `schema` | `openssl-rs/campaign/safe-c33/residual-site-bound/v1` |
| `record` | `precision.residual_sites` |
| `status` | `TRUNCATED_BOUNDED` |
| `sample_size` | 200 |
| `population_size` | 449 |
| `omitted_members` | 249 |
| `bound` | the list is a prefix of the population, not a census; the cap is named in `selection_rule` |
| `omitted_members_recorded` | `false` — the 249 omitted members are written to the `--edge-records` JSONL sidecar, not identified here |
| `selection_rule.rule` | the population is sorted by (dso name, function start address, call-site address) and the first 200 members are embedded; the sort order is the whole selection |
| `selection_rule.locator` | `forensics/tools/consumer_closure.py`: `RESIDUAL_SITE_RECORD_LIMIT` |
| `selection_rule.rerunnable` | `true` |
| `selection_rule.requires` | the candidate DSOs named in `candidate_identity` and the closure engine; `--element7-only` prints the whole population without writing a receipt |

The 200 rows are not added to, removed, reordered or rewritten, so the record's
per-site evidence is exactly what it was. The verdict, `predicate_element_7`
(`FAIL`, 449 reachable / 219 target-bounded) and `refusals` are untouched: the
repair states the bound and closes nothing.

### The selection rule: answered, not `UNKNOWN`

The rule is mechanical and was read from the generator, not inferred. The
generator sorts the reachable unresolved population
(`reachable_residual_sites.sort(key=(dso, function start, site address))`) and
serialises `closure["reachable_residual_sites"][:200]`. Two independent checks
agree with that reading on the recorded bytes:

- the 200 recorded rows are strictly increasing under that exact sort key
  (`(dso, function, call_site)`), so the list is a prefix of a sorted population
  and not an arbitrary or representative selection;
- the 200 rows carry 200 distinct call sites, so nothing was deduplicated to
  reach the cap.

The literal `200` was the defect's mechanism as well as its size: the generator's
`--max-record-sample` argument bound a different list (the edge-record sidecar
sample, default 500) while this list used a hardcoded slice. The cap is now the
named constant `RESIDUAL_SITE_RECORD_LIMIT`, used both by the slice and by
`residual_sites_bound(...)`, so the stated cap and the applied cap cannot drift.

### The re-run: attempted, did not confirm the population

`consumer_closure.py --element7-only` recomputes the graph, the precision
resolver and the reachability closure and prints the whole population without
writing a receipt, so the count can be re-derived from the recorded identity
(curl 8.10.1 `libcurl.so.4.8.0` `7dfe9b54…`, install `libcrypto.so.3`
`fd25cc9e…` / `libssl.so.3` `648f8cae…`, all present at the recorded paths).
Two bounded attempts were made in the court:

| attempt | bound | result |
|---|---|---|
| 1 | `timeout 1500` (25 min) | exit 124, timeout, no output |
| 2 | `timeout 5400` (90 min) inside the 6 GiB court cgroup | exit 137, SIGKILL; the cgroup records `oom 1`, `oom_kill 1`, `memory.peak` = `memory.max` = 6442450944 |

The run did not fit the court's 6 GiB cap. It was not retried at the same size
(`AGENTS.md` §6.1 rule 5). Consequence, stated plainly:

- **confirmed by re-running the rule**: the sample size (200) and its position
  as the population's sorted prefix;
- **`NOT_RUN`**: the whole-population re-derivation. The population totals
  (449 / 219 / 158 / 72) are the generating run's own recorded totals, and the
  identities of the 249 omitted members are not recorded in the receipt. The
  `TRUNCATED_BOUNDED` status therefore means "the bound is declared", not "the
  population was re-derived at this repair".

### The checker: the shape is now refused

`forensics/tools/closure_discipline.py` is the validator that reads these
records, and it now refuses the shape rather than only the shortfall:

- `residual_sample_bound(receipt)` returns a refusal when
  `len(precision.residual_sites) < precision.totals.reachable_unresolved_sites`
  and `precision.residual_sites_bound` is absent
  (`CD_RESIDUAL_SAMPLE_UNBOUNDED`), when the declared numbers disagree with the
  record's own list and totals (`CD_RESIDUAL_SAMPLE_MISMATCH`), and when no
  selection rule is stated, or `UNKNOWN` is stated with no method that would
  establish it (`CD_RESIDUAL_SAMPLE_RULE_MISSING`). A complete list needs no
  bound.
- `closure_discipline.py audit --receipt …` prints each refusal on stderr and
  exits 1; `check` reports `sample_bound_status_by_consumer` and
  `sample_bound_refusals` and includes them in its exit condition.
- `consumer_closure.py` emits `residual_sites_bound` with every receipt, so a
  regenerated receipt cannot lose the block.

The refusal does not close the 249 omitted members: the pre-existing failing row
for the unrecorded remainder (`_coverage_rows`) still fires, and the existing
`predicate_element_7` verdict is unchanged. Declaring a bound is not resolving
an omission.

Controls: ten tests in `forensics/tools/tests/test_closure_discipline.py`
(`ResidualSampleBoundControls`), covering the absent bound, a declared bound
accepted, a complete list needing none, a bound whose population disagrees with
the record, a bound declaring `COMPLETE` on a truncated list, a bound with no
selection rule, `UNKNOWN` without and with the method that would establish it, a
record with no population, the command-line refusal, and the committed curl
record's own declared bound.

### Identity consequence

Adding fields changes the record's bytes, and one tracked record asserts the
closure's digest as *live* evidence: `evidence/etp-t6/CLAIM-MATRIX.json`
(`BA-CLM-007`) recorded `6aedaa4e…`; `binary_assurance.check_documents`
re-derives the file and refused the mismatch. That citation was updated to
`b72193072780e9a425e7e93be8c0c15849d06c758b9e71f226cafb4992388c62`
(the digest of this file as patched), which is the only permitted edit of another
item's record here: it is a citation that names the repaired record. The claim's
substance — 644 files reached, 7/7 reachable production obligations discharged,
`safe_compatible` false — is unchanged, and the superseded digest is preserved
above.

**Retained obligation.** `evidence/etp-t10/EXCLUSIONS.json` records
`consumers.curl.receipt_sha256 = 6aedaa4e…` as the identity ETP-T10 audited at
commit `7e70b667f`, and `verify.py`'s `consumer-curl` guard compares that value
with the live file. It therefore now reports the mismatch:

```
the closure receipt evidence/closure-curl-049.json has digest <new>, but the
identity ETP-T10 audited is 6aedaa4e…
```

That report is true and is the freshness signal working, not a passing result.
It cannot be discharged before the repair is committed, because the record
stores a Git blob digest at a commit:

```
python3 forensics/tools/closure_discipline.py emit --commit <commit containing this repair>
```

until which the `consumer-curl` verification step is red. Other records that
cite the old digest (`evidence/etp5/probes/p6*.json`,
`evidence/element7-curl-049-triage.json`, `evidence/etp-t12/RUN.json`, the
traces under `evidence/etp-t1/` and the two `etp-t15` history copies) are
records of runs at their own identities and are not rewritten.

---

## 2. A0-F06 — a stale full-gate transcript

### What the record said

`evidence/etp7/RECEIPT.md` recorded, verbatim and in the present tense, a gate run
at `8a697aa7e` that exited 1 with four `RG_CLAIM_CONTRADICTED` refusals
(`ETP0-CLM-004`, `-005`, `-030`, `-032`), a conjoin verdict of `CONTRADICTED`,
33 blocked members and 42 open obligations, plus a §5 table of the same run. No
field bound the transcript to the claim-set bytes it read. The live claim set
conjoins to `SUPERSEDED` with 37 open obligations, and `docs/ETP-TODO.md`'s ETP-7
row asserted the four-refusal result in the present tense.

### What the record now says

- A `Record status` paragraph names the two identities and says which sections
  are history.
- §3 keeps its command and its output bytes **unedited**, under a heading note
  that it is the run at `8a697aa7e` and is superseded.
- §5 keeps its table **unedited**, under a note that it is the run at
  `8a697aa7e`, at which the claim set conjoined to `CONTRADICTED` with 42 open
  obligations.
- A new §9 records, verbatim, the run at `2d31a23fb`: the gate output, the
  claim-set digest it read, `etp_claims.py validate` and `conjoin`, and the
  candidate identity.

| field | §3 (history, `8a697aa7e`) | §9 (current, `2d31a23fb`) |
|---|---|---|
| claim conjunction | `CONTRADICTED` | `SUPERSEDED` |
| blocked members | 33 | 33 |
| open obligations | 42 | 37 |
| refused items | 5 (4 `RG_CLAIM_CONTRADICTED`, 1 `RG_PACKAGE_MISSING`) | 31 (19 `RG_CLAIM_UNCERTIFIABLE_EVIDENCE`, 11 `RG_CLAIM_HISTORICAL_EVIDENCE`, 1 `RG_PACKAGE_MISSING`) |
| claim set read | `S = 9372bb28b`, digest not recorded | `S = 9372bb28b`, `evidence/etp/claims.json` digest recorded |

The move from `CONTRADICTED` to `SUPERSEDED` is **not** a resolution and this
repair does not present it as one. The four contradictions were reclassified by
ETP-T15 (`-004`, `-005`, `-032` to `SUPERSEDED`, `-030` to `RISK_ACCEPTED`) and
the five obligations that closed carry `settled_by`; the gate now refuses the
same candidate for a different and larger set of reasons — 30 refusals about the
identity of the evidence the claims cite, against 4 about contradicted verdicts.
The refusal count rose from 5 to 31. No claim was promoted, and neither run is a
pass.

### The citations, repaired the same way

- `docs/ETP-TODO.md`, ETP-7 row: an `A0-F06` clause records the live
  conjunction, obligation count and refusal split, states that the earlier
  sentence describes `8a697aa7e` and is history, and notes that the refusals did
  not fall. The earlier text is kept in place.
- `docs/RELEASE_GATES.md`: the paragraph that said the gate "refuses, because the
  committed claim set conjoins to `CONTRADICTED`" now states the historical run
  and the live one, names both identities, and says neither is a pass.
- `forensics/tools/independence.py`'s `RCP-ETP7` entry and
  `evidence/etp-t9/RECEIPT.md`'s line for the receipt are records at their own
  identities and were left unchanged; the ETP-9 lineage reads the receipt at
  `8a697aa7e`, which remains true.

### The checker: the shape is **not** refused

No checker refuses this shape. `release_gate.py` reads the claim set and the
package but never a recorded transcript, `docs_consistency.py` does not read
`evidence/etp7/RECEIPT.md`, and nothing binds a receipt's quoted gate output to
the claim-set digest that produced it. What it would take, concretely: a gate or
documentation rule that a recorded release-gate transcript carries (a) the
candidate commit, (b) the claim-set path and digest it read, and (c) the
conjunction verdict it observed, and that refuses (`RG_TRANSCRIPT_SUPERSEDED` or
equivalent) when the recorded digest no longer matches the tracked claim set
while the transcript is presented as current. Without that rule the defect is
repaired in the records and remains possible in the machinery; it is recorded
here rather than claimed closed.

---

## 3. A0-F10 — a status row that overstates the cohort

### What the record said

`forensics/STATUS.md` (line 541) carried one row:

```
| current | 207 | 33/33 at `L7-functional` | `forensics/downstream/runtime-functional-atlas.json` (`body.counts.by_subject`, `body.runs`) |
```

The cited fields do not support 33 families at one identity. They yield 66 cohort
rows, of which 54 carry `reused_from_candidate_identity` (27 families) and 12 do
not (6 families: curl, haproxy, monit, openssh, pure-ftpd, redis); the marker
names `26ba36ff…` while the atlas candidate is `1c03ec0a…`, and
`body.evidence_reuse.candidate_identity_match` is `false`.

### What the record now says

`forensics/STATUS.md` is generated by `forensics/tools/render_status.py`, so the
repair is in the generator; a hand edit would have been undone by the next
render. `_runtime_functional()` now partitions the cohort from the per-row
marker, and the rendered table separates the population:

| row | cohort cell |
|---|---|
| current (mixed identity) | `33/33 at L7-functional`, of which `6/33` measured at the atlas candidate and `27/33` carried forward |
| of which measured at the atlas candidate `1c03ec0a…` | `6/33`, 6 candidate rows with no `reused_from_candidate_identity` |
| of which carried forward from `26ba36ff…` | `27/33`, 27 candidate rows carrying the marker; source `body.evidence_reuse` (`candidate_identity_match: false`, mode `committed-rows-carried-forward`) |
| previous rendering (historical, superseded 2026-11-23 by the A0-F10 repair) | `33/33 at L7-functional` — the previous text verbatim |

A paragraph above the table states that a carried-forward row is a record, not a
measurement at the atlas candidate, and that the split is read from
`body.runs`, never from an aggregate. The superseding sentence the renderer
already emitted for the Phase-25 ledger's frozen downstream finding now also
names the mixture (6 measured at `1c03ec0a…`, 27 carried forward from
`26ba36ff…`, `candidate_identity_match` false), so the ledger section that
states the same `33/33` carries the qualifier beside it. The ledger artefact
(`forensics/phase25-obligations.json`) is not edited.

History: the previous cell text is preserved verbatim in the table as the
labelled historical row, with the reason it was superseded and a pointer to this
record. The 223-run frozen row above it keeps its own `historical, superseded`
label.

### The checker: the shape is **not** refused

`docs_consistency.py` does not read `forensics/STATUS.md`, and no other checker
compares a rendered cohort figure with the per-row identity partition. The
renderer can no longer emit the unpartitioned row — the partition is computed
whenever any carried-forward family is present — which makes the specific defect
unrepeatable by regeneration, but a later hand edit or a new renderer path could
reintroduce it. What it would take: a `docs_consistency.py` rule that any line
in a generated status document reporting an `N/N at L7-functional` cohort total
must also name the measured-at-candidate count and the carried-forward
population; the check is cheap because `render_status.py` already computes both
values. Recorded as the gap rather than claimed closed.

---

## 4. Common properties

- **History preserved.** No recorded result is rewritten: the §3 transcript, the
  §5 table, the 200 residual rows, the closure verdict and the `33/33` cell text
  are all preserved, superseded and labelled. The one value changed in another
  item's record (`CLAIM-MATRIX` `BA-CLM-007` evidence digest) is a live citation
  of the repaired record, and its previous value is preserved in §1 above.
- **No promotion.** F01 leaves `predicate_element_7` `FAIL` and the 249 omitted
  members unclosed. F06 records a larger refusal set (31 against 5) and states
  that the reclassification is not a resolution. F10 lowers the cohort figure at
  the recorded candidate from 33 to 6, with 27 explicitly carried forward.
- **Deferred is not pass.** The population re-derivation is `NOT_RUN` (the run
  did not fit the court's memory cap); the `consumer-curl` verification step is
  red until the ETP-T10 evidence is re-emitted at the repair commit; the two
  missing checker rules are recorded as gaps, not as repaired.

## 5. Gates

Run in the court (`openssl-rs-court-tools:1`, existing container, 6 GiB cgroup
cap) with `python3` 3.11; nothing compiled on the host and no Rust build was
run (no `src/` change). The test count is the same `unittest discover` command
before and after the change, and the name diff is ten added tests in
`ResidualSampleBoundControls` with nothing removed, skipped or converted to an
expected failure.

| gate | before | after |
|---|---|---|
| `python3 -m unittest discover -s forensics/tools/tests` | 535 tests, OK | 545 tests, OK (10 added, 0 removed, 0 skipped, 0 expected failures) |
| `etp_claims.py validate` | 35 claims, 0 refusals | 35 claims, 0 refusals |
| `etp_claims.py conjoin` | `SUPERSEDED`, 33 blocked, 37 obligations | `SUPERSEDED`, 33 blocked, 37 obligations |
| `release_gate.py --self-test` | 21 cases ok | 21 cases ok |
| `docs_consistency.py` | exit 0, 20 claims agree | exit 0, 20 claims agree |
| `release_gate.py` (no `--package`) | exit 1, 5 refusals | exit 1, 31 refusals (transcript: `evidence/etp7/RECEIPT.md` §9) |

A confirmation run after the last prose edit reproduces the §9 transcript byte
for byte except for the uncommitted-path count, which is 12 in both runs.
| `closure_discipline.py --self-test` | 7 control groups passed | 7 control groups passed |
| `binary_assurance.check_documents` (via `test_binary_assurance`) | no refusals | no refusals (the `BA-CLM-007` digest re-recorded) |

## 6. Non-claims

- Declaring a sample bound does not close the 249 omitted residual sites and does
  not change the element-7 predicate.
- Recording the live gate output does not resolve a contradiction and does not
  make the claim set releasable: the gate refuses 31 items at this candidate.
- The cohort partition is a property of the atlas rows, not of the workloads: 27
  families carry a recorded result produced at a superseded candidate, and no
  re-measurement is claimed.
- Neither `verify.py consumer-curl` nor the two missing checker rules are
  repaired here; both are named above with the command or rule that would close
  them.
