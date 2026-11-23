# Evidence and Trust-Surface Audit

Status: **A0 of `docs/ETP-TODO.md` (ETP Addendum A)**. Findings only: this
document repairs nothing. The machine records are `evidence/a0/INVENTORY.json`
and `evidence/a0/FINDINGS.json`.

Candidate: `staging` at `e0b727d067b00da65ff66f329a36c725bc2658e5`, clean
worktree, 14,241 tracked files. Every count below was recomputed from that tree;
where a receipt and the artefact disagree, the disagreement is the finding.

The question this audit answers is not "how much evidence exists" but **where a
reader can be misled**. A record may be honest in prose and misleading in its
fields, and that is the failure mode that matters when an external reader, a
SARIF consumer or a later item reads the machine record alone.

---

## 1. Inventory

### 1.1 What exists, at a glance

| measure | count |
|---|---|
| tracked files / tracked `.json` / tracked `.md` | 14,241 / 3,131 / 225 |
| distinct `schema` identifiers | 528 |
| evidence JSON files / of which without a `schema` key | 352 / 8 |
| forensics JSON without a `schema` key | 214 |
| claims / open obligations / discharged obligations | 35 / 37 / 5 |
| interop receipts / manifests | 14 / 3 |
| freshness artefacts / dependency edges / exclusions | 331 / 5,183 / 228 |
| traceability nodes / edges / declared orphans | 361 / 475 / 43 |
| hazards / FMEA rows / STPA UCAs / attack graphs | 20 / 30 / 12 / 7 |
| unsafe sites / operation rows | 62,297 / 767 |
| closure-discipline rows / opaque-operation rows | 1,121 / 55 |
| scheduling change sets / requirements | 6 / 78 |
| audited aggregates / refused aggregates | 8 / 2 |
| instruments | 11 |
| constitution articles / without a release-gate item | 11 / 4 |
| atlas runs / specimens / recipes / reused families | 2,000 / 226 / 307 / 301 |
| external-package inputs / refusals | 1,633 / 5 |

### 1.2 The artefact table

Each row states the format and version, the producer, the consumer, whether the
record is machine-readable, whether it carries a candidate identity, and whether
its population can be reconstructed from tracked content. Full detail is in
`INVENTORY.json`; identifiers `A0-INV-nn` are shared.

| id | artefact | schema / version | producer | consumer | identity | reconstructable |
|---|---|---|---|---|---|---|
| 01 | `evidence/etp/claims.json` | `openssl-rs/etp/claims/v1` | ETP-1 conversion; `etp_claims.py` | `etp_claims.py`, `release_gate.py` gate-2, `freshness.py` | `source_identity.commit=9372bb28b`, per-evidence SHA-256 | partial (F15) |
| 02 | `evidence/etp/claim.schema.json` | JSON Schema 2020-12 | hand-written | `etp_claims.py` | n/a (definition) | yes |
| 03 | `evidence/etp0/{CLAIMS,TRUST-GAPS}.json` | unversioned | ETP-0 | claim set `derived_from` | prose in receipt | yes, as history |
| 04 | `evidence/etp-t1/TRACEABILITY.json` | `openssl-rs/etp/traceability/1` | `etp_t1_seed.py` | `traceability.py`, `hazard_register.py` | `identity.commit=21bea3188`; per-node `bound_commit` + digest | yes, byte-for-byte seed |
| 05 | `evidence/etp-t2/HAZARDS.json` | `openssl-rs/etp/hazards/1` | analysis; `hazard_register.py` | `hazard_register.py`, T1 projection | `analysis_candidate=6da02233f` | yes from register; aggregates only in receipt (F05) |
| 06 | `evidence/etp-t4/SAFETY-SITES.json` | `openssl-rs/etp/unsafe-sites/1` | `unsafe_obligations.py`, declared heuristic | T1 projection, `unknown_obligations_v1l.py` | `commit=246e30580`, `scanner_sha256` | partial (F02) |
| 07 | `evidence/etp-t4/{AXIOMS,VACUITY}.json` | `openssl-rs/etp/axioms/1`; VACUITY unversioned | ETP-T4 | T1 projection | via T1 digest | yes |
| 08 | `evidence/etp3/instruments.json` | `openssl-rs/instrument-qualification/1` | register; `instrument_qualify.py` | gate-4, `verify.py instruments` | per-instrument version + control binding | yes, 9 executable / 2 RECORDED |
| 09 | `courts/phase18/interop/RECEIPT-*.json` (14) | `interop-{pin-receipt/1,cell-receipt/1,matrix-receipt/3}` | `cell.sh`, `manifest.py`, `publish_logs.py`, `verify_pins.py` | `check_receipts.py`, gate-3 | per-cell log SHA-256; no DSO digest at matrix level | yes for counts/logs; binary identity prose-only (F07) |
| 10 | `courts/phase18/interop/MANIFEST*.json` (3) | value fields, no `schema` key | `manifest.py`, pin verifier | `check_receipts.py` R4/R5 | source and DSO digests in O11 | yes |
| 11 | `evidence/closure-curl-049.json`, `evidence/closure-ssh-b85c.json`, `evidence/closure-sshd-b85c.json` | `consumer-closure/v2` | `consumer_closure.py` | `closure_discipline.py`, aggregate audit | source/candidate/artifact/ledger identity | partial (F01, F11) |
| 12 | `evidence/etp-t10/{EXCLUSIONS,OPAQUE-OPERATIONS,AGGREGATES}.json` | declared by tool | `closure_discipline.py` | `verify.py closure` | `AGGREGATES.identity.commit=7e70b667f` | rows yes; 3/8 digests stale (F13) |
| 13 | `evidence/etp-t9/DEPENDENCIES.json` | `openssl-rs/etp/freshness-dependencies/1` | `freshness.py record` | `freshness.py check`, gate-2b | `recorded_at_commit=26c127262` | yes |
| 14 | `evidence/etp-t11/{TIERS,RUNS,CACHE,CHANGE-SETS}.json` | `etp/scheduling-*/1` | `scheduling.py` | `verify.py scheduling` | per-set base/head; five-field admission | TIERS yes (F09 in RUNS) |
| 15 | `evidence/etp-t14/ARTICLES.json` | `openssl-rs/etp-t14/articles/1` | ETP-T14; `earned_trust.py` | `earned_trust.py`, `docs_consistency.py` | `source_candidate=1e068243d` | partial (F08) |
| 16 | `evidence/etp-t8/{ROLES,ASSIGNMENTS}.json` | `etp-t8/roles/1`, `etp-t8/assignments/1` | ETP-T8; `independence.py` | `independence.py`, `verify.py` | `source_identity` | yes |
| 17 | `evidence/etp-t6/{TCB,CLAIM-MATRIX}.json` | `etp-t6/tcb/1`, `etp-t6/claim-matrix/1` | ETP-T6; `binary_assurance.py` | `binary_assurance.py` | `candidate.commit=c28ac7bb94` (pending-commit status) | yes |
| 18 | `evidence/etp-t13/{FORMATS,DIGESTS,IDENTITY-SYSTEMS,ARCHIVAL}.json` | `etp-t13/*/1` | ETP-T13 | `preservation.py` | candidate `0eecec734`, object format `sha1` | yes |
| 19 | `evidence/etp-t15/{RECONCILIATION.json,history/}` | `etp-t15/reconciliation/1` | ETP-T15 | claim settlements, campaign history | `source_identity`; before/after digests | yes |
| 20 | `evidence/etp6/{MANIFEST.json,verify.sh}` | declared by builder | `etp6_package.py` | `etp6_verify.py`, gate-5 | `candidate.commit=98c7b5d29` | partial (F03, F18) |
| 21 | `forensics/downstream/runtime-functional-atlas.json` | `atlas/downstream-runtime-functional-atlas/v1` | `downstream_runtime.py` | `render_atlas.py`, `STATUS.md`, phase ledgers | `body.candidate_identity`; per-row `reused_from_candidate_identity` plus body-level `evidence_reuse` | partial (F04, F10) |
| 22 | `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` | `safe-c33/campaign-status/v1` | campaign ledger | aggregate audit, claim set, `STATUS.md` | `source_head` + history block | partial (inherits F04) |
| 23 | `forensics/phase*-obligations.json` (23) | `atlas/phaseNN-obligations/v1` | `phaseNN_obligations.py` | `phase_state.py`, seals | authority + generator + input digests | yes |
| 24 | `forensics/tools/release_gate.py` + `evidence/etp7/RECEIPT.md` + `evidence/etp-t12/RUN.json` | tool JSON; receipt is prose | `release_gate.py` | release procedure | resolves `--candidate`; package unbound (F16) | partial (F06) |
| 25 | `docs/*.md` (97) + `forensics/STATUS.md` | prose | hand-written / rendered | human readers, `docs_consistency.py` | rarely; prose commit at best | partial (F10, F12) |

### 1.3 Formats that are absent

The Addendum-A premise is that the project can emit and consume interoperable
security evidence. It cannot yet, and the inventory should say so plainly rather
than imply a gap in conversion.

- **SARIF** — no `.sarif` file exists, no writer, no reader, no profile. Grep for
  `sarif` in tracked JSON, Python and Markdown matches only the two queue
  documents that request it. SARIF 2.1.0 and Errata 01 are both absent.
- **DSSE**, **in-toto Statement**, **SLSA provenance**, **Sigstore bundle /
  Rekor entry / C2SP tlog**, **RFC 3161 timestamp**, **TUF metadata** — absent.
  They appear only as requirements in `docs/ETP-TODO.md` §E, `docs/ETP-ADDENDUM-B.md`
  and the research documents.
- **SBOM** (SPDX or CycloneDX) — absent; no generator in `forensics/tools/`.

The evidence formats that do exist are project-local JSON with versioned
`schema` identifiers, Markdown receipts, JSON Lines for the downstream corpus,
and SHA-256 input manifests. `evidence/etp-t13/FORMATS.json` lists ten admitted
formats and none of the above; the registry is correct and the absence is not
hidden.

---

## 2. Findings by class

Eighteen findings: four truncation, five silent suppression, five
summary-without-reconstruction, four wrong-candidate application. Identifiers
are shared with `FINDINGS.json`.

### 2.1 Truncation

| id | artefact | locator | what is reported | what is true |
|---|---|---|---|---|
| **F01** | `evidence/closure-curl-049.json` | `precision.residual_sites`; `precision.totals` | 200 per-site residual rows | 449 reachable unresolved, 219 target-bounded; no limit field |
| **F02** | `evidence/etp-t4/SAFETY-SITES.json` | `suppressions` | total 1,999 plus a per-lint map | no member row for any suppression |
| **F03** | `evidence/etp6/MANIFEST.json` | `selection.paths` (56), `input_count=1633` | 1,633 verified inputs | no denominator; `evidence/etp-t*`, `etp6`, `etp7`, `closure-*` and the atlases are outside the selection |
| **F04** | `forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json` | `consumers.l7_functional`, `consumers.l7_families` | 33 families at L7 | 66 L7 rows: 54 carry `reused_from_candidate_identity` (27 families), 12 do not (6 families: curl, haproxy, monit, openssh, pure-ftpd, redis — the six `runtime-observed measured consumer(s)` at `STATUS.md:522`) |

**F01 is the clearest case.** The record's own totals name 449 reachable
unresolved sites and 219 target-bounded ones. The per-site list stops at exactly
200 and says nothing about being a subset. `docs/CLOSURE-DISCIPLINE.md` requires
an incomplete residual sample to add a failing row for the remainder; the
closure record carries neither the bound nor the failing row. The defect has been recorded in
prose (ETP-T10, and the queue row at `docs/ETP-TODO.md:128`), which is exactly
the pattern A2 exists to end.

**F02 is where suppression governance will begin.** A6 cannot govern a
suppression it cannot locate. The same indexed-table encoding used for `sites`
and `operations` would carry the member rows; the aggregate-only encoding is a
choice, not a limit.

**F03 and F04 are different shapes of the same mistake**: a count that omits the
identity of its members. In F03 the complement is a set of evidence families
missing from the external package; in F04 it is 27 of the 33 cohort families,
carried forward from `26ba36ff…` and counted beside the 6 measured at
`1c03ec0a…`. F04 is not a missing mechanism: `downstream_runtime.py` writes
the `reused_from_candidate_identity` marker and the partition can be recomputed.
The defect is that the aggregate and the status row do not use it.

### 2.2 Silent suppression

| id | artefact | locator | suppressed between |
|---|---|---|---|
| **F05** | `evidence/etp-t2/HAZARDS.json` | `hazards[].barrier.state` | register and its receipt / queue row |
| **F06** | `evidence/etp7/RECEIPT.md` | lines 108-156, 216, 224 | recorded gate run and the live claim set |
| **F07** | `courts/phase18/interop/RECEIPT-o7.json` | line 7 `supersedes`, `cells.BB.log_sha256` | aggregate, cell receipts, queue row |
| **F08** | `evidence/etp-t14/ARTICLES.json` | `articles[ET14-A09]` | machine record and `docs/EARNED-TRUST.md:281-288` |
| **F09** | `evidence/etp-t11/RUNS.json` | `runs[].status` | declaration layer and `TIERS.json` admission |

**F05** is a state transition that exists only in file order. `HAZARDS.json` was
last written after the receipt was generated, and two hazards moved from
`BARRIER_ABSENT` to `CLAIMED_NO_EVIDENCE`. The register records no transition;
the receipt records the earlier state; the queue row narrates four states across
appended updates and never lands on the live counts. The current state can be
obtained only by recomputing it; the receipt yields the earlier state and the
queue row yields none of the intermediate ones.

**F06** is the most consequential suppression because it sits on the release
path. The only verbatim full-gate transcript in the tree refuses four
contradicted claims; the current claim set contains none, and `conjoin` returns
`SUPERSEDED` with 37 open obligations against the recorded 42. The five
obligations that moved to `DISCHARGED` carry `settled_by` text and evidence
references, so the change is documented at the obligation level — but the gate
receipt was never regenerated and no field binds it to the claim-set bytes it
read. The queue row still uses the present tense.

**F07** is two records disagreeing about the same run. The aggregate says it
supersedes `the three per-cell receipts marked withdrawn`; all four cells read
`withdrawn: false`. The aggregate's BB log digest is not the BB cell's. The gate
item that owns this check reports zero problems because each receipt validates
in isolation: R4 reads only `result.log_sha256`, a field the matrix receipt does
not have.

**F08** is the constitution's own machine record. `docs/EARNED-TRUST.md` says in
terms that the "not a probability" half of Article 9 has no mechanical
enforcement. `ARTICLES.json` has no field able to express a half-enforced
article: it lists two rules and `declared_none: false`. A machine consumer of
the record therefore reads Article 9 as enforced. `docs_consistency.py` refuses
an article with no enforcement and no declaration of that, which is the right
rule for a fully unenforced article and does not cover a partial one.

**F09** is a vocabulary collision. Six `RUNS.json` entries say `SATISFIED` with
`identity: null`; the notes say no source tree, tool digest, configuration,
target or population was recorded. `TIERS.json` refuses those same declarations
and reports 0 SATISFIED. Both files are honest in context; the field name is
not. An exporter that read `RUNS.json` would emit six satisfied results that the
policy resolved to refused.

### 2.3 Summary without reconstruction

| id | artefact | locator | the summary | why it cannot be recomputed |
|---|---|---|---|---|
| **F10** | `forensics/STATUS.md` | line 541 | `current … 33/33 at L7-functional` | the cited fields yield 27 carried-forward families and 6 measured at the atlas candidate; the row states neither |
| **F11** | `evidence/closure-curl-049.json` | `verdict` vs `precision.predicate_element_7` | `ACCEPTED`, `no refusal condition fired` | the blocking predicate is FAIL in a separate block |
| **F12** | `docs/ETP-TODO.md` | lines 119-120 | 325 nodes / 403 edges / 21 orphans; barrier and FMEA counts | live graph is 361/475/43; live register is 18/2/0 and 23/7/0 |
| **F13** | `evidence/etp-t10/AGGREGATES.json` | per-aggregate `sha256`, `reported_state_source` | PASS classification over eight documents | three of eight digests do not match live bytes; for b85c the field read no longer exists |
| **F14** | `evidence/etp6/MANIFEST.json`, `docs/EXTERNAL-REPRODUCTION.md:174-175` | `court_tmp_reference_audit` vs prose | 7,425 occurrences in 549 files | the document says 7,399 in 546 `at this HEAD`, which names no commit |

**F10 is the strongest.** The status table names exactly the two atlas fields a
reader should recompute from, and those fields do support the recomputation:
66 L7 rows for the cohort, 54 marked as carried forward from `26ba36ff…`, 12
unmarked and therefore measured at the atlas candidate `1c03ec0a…`. The result
is 6 of 33 families at the recorded candidate, not 33. The table labels the
older 223-run row "historical, superseded" and the mixed 207-run row "current",
with the qualifier neither stated nor filtered.

**F11 is a verdict split across blocks.** `verdict.state` is `ACCEPTED`,
`refusals` is empty, and the reason is `no refusal condition fired`; the element-7
predicate that keeps curl from graduation is `FAIL` in `precision`. The aggregate
audit reads the precision block and reports FAIL, so the machinery is right, but
the document's own verdict is not.

**F12 and F14 are unreconstructable by construction**: a stale snapshot and a
prose `at this HEAD`. Both are cheap to repair by citing a generated table or a
commit, and both are invisible to `docs_consistency.py` today.

**F13 is the audit auditing itself.** The aggregate record is substantively
right about b85c and `CAMPAIGN-STATUS.json`; what it cannot show is that it read
the bytes it claims to have read. Three of its eight recorded digests are stale,
and for the b85c record the field it named (`verdict.value`) was removed by the
ETP-T15 reclassification.

### 2.4 Wrong-candidate application

| id | artefact | locator | identity used | identity claimed or implied |
|---|---|---|---|---|
| **F15** | `evidence/etp/claims.json` | `ETP0-CLM-032` `OBL-GAP-005` and `EV-01.sha256` | S bytes `abb8a6cb…` (`safe_compatible: 1`) | `settled_by` asserts the live 0/33 state |
| **F16** | `forensics/tools/release_gate.py` | `check_package` lines 530-574 | any package's own `verify.sh` | the gate's `--candidate` |
| **F17** | `evidence/etp2/reproducibility.json` | `candidate.commit`, `deferred_gates` | `head_at_start=e9d492b0d` | a committed candidate identity |
| **F18** | `evidence/etp6/MANIFEST.json` | `candidate.commit=98c7b5d29` | another commit's inputs | the candidate under audit |

**F15 is the ranking's first finding.** `OBL-GAP-005` is `DISCHARGED` and its
`settled_by` text says `CAMPAIGN-STATUS.json now records 0/33 section 7`. The
evidence entry in the same claim records `sha256 abb8a6cb…` with
`digest_identity: S`. Hashing the Git blob at `S=9372bb28b` gives `abb8a6cb…`,
and that blob says `consumers.safe_compatible: 1`. The live file says 0. The
digest is honest for S, which is why the validator accepts it; the settlement is
honest for the live tree, which is why the verdict reads as corrected. The two
are different identities, and the record does not distinguish them.

**F16 is the release tool's own hole.** `check_package` verifies that the
package's verifier passes; it never compares `MANIFEST.json candidate.commit`
with the `--candidate` the gate resolved. A package from `98c7b5d29` satisfies
gate-5 for a release at `e0b727d06`. The gate's docstring disclaims truth,
representativeness and independence; it does not disclaim, and does not check,
identity. This is the defect the release policy exists to refuse, in the tool
that enforces the policy.

**F17 and F18 are instances of the same pattern in two places**: a record whose
identity field is null or names another commit. `reproducibility.json` has
`candidate.commit: null` and `post_commit_rebuild_of_S_prime: NOT_RUN`; the
tracked package manifest is at `98c7b5d29` and `verify manifest` records 56 hard
refusals at this candidate (`evidence/etp-t12/RECEIPT.md:96`).

---

## 3. Ranked by consequence

Not by count. The order answers one question: if an external reader trusted this
artefact and nothing else, what would that reader wrongly conclude?

1. **`A0-F15` — a discharged obligation whose evidence digest resolves to the
   opposite value.** The reader who trusts `settled_by` concludes a contradiction
   was resolved on evidence that does not show it; the reader who re-derives the
   digest concludes the claim set is internally unsound. Both are wrong. The
   defect sits in the record that adjudicates every other claim, and it is the
   pattern ETP-T15 exists to prevent, one level below the reconciliation.
2. **`A0-F01` — 200 of 449 residual sites with no bound.** The reader counts 200,
   sees that the rows present are contract-bounded, and concludes the curl
   element-7 blocker is nearly closed. The record's own total says 449 with 219
   target-bounded, which is the population that keeps element 7 `FAIL` and the
   curl graduation open. A C1–C5 reader is the most likely victim.
3. **`A0-F06` — the only recorded full-gate run no longer reproduces.** The
   reader concludes the gate still refuses four contradictions at this tree, or
   that reclassifying claims removed the refusals without resolution. Neither is
   what the current gate produces, and no record binds the transcript to the
   claim-set bytes it read. Release admissibility is decided here.

The next tier, in order: `F05` (hazard states that exist only in file order),
`F10` (the `current` 33/33 row), `F16` (the gate's package item), `F04` (the
unpartitionable L7 population), `F11` (the split curl verdict).

---

## 4. What is already sound

The audit is not a blanket condemnation, and several mechanisms are the model
the repairs should follow.

- **`evidence/etp6/MANIFEST.json` inputs and refusals.** 1,633 path/digest pairs,
  a 56-path `git archive` selection, five named refusals with consequences. The
  mutation controls show a missing or one-byte-changed input failing with both
  hashes named. Its defect (F03) is the missing denominator, not the digests.
- **Freshness (`DEPENDENCIES.json`, `freshness.py`).** Population, identity,
  edges and exclusions are derived, not declared; 228 exclusions are named, 189
  by an explicit 512 KiB bound; an unresolved dependency is never `UNAFFECTED`;
  carry-forward must be an explicit `HISTORY` declaration. This is the right
  shape for a bounded population.
- **Traceability (`TRACEABILITY.json`).** Per-node `bound_commit` and digest,
  43 orphans declared by class with reasons, byte-for-byte seed reproduction,
  and a hazard-register projection digest that matches the live register.
- **Claim evidence digests.** All 81 reconstruct: 80 re-derive from the Git blob
  at S, and the 81st is the withdrawn O7 revision tagged
  `digest_identity: historical`, which re-derives from the commit `cc2e5fa32`
  named in its note (`2ee7ee4d…`). The withdrawn bytes are preserved history,
  not absent evidence.
- **Instrument qualification.** Eleven instruments with intended use, failure
  modes, soundness limits and paired controls; nine re-run, two `RECORDED` and
  bound to a tracked runner digest; a `RECORDED` control presented as a pass is
  refused by gate-4.
- **O11 interop manifests.** Every count derived from a named log under stated
  rules, with the log digest and byte length recorded and recomputed by R4/R5.
  The parser refuses to guess when the harness invents a third skip spelling.
- **Scheduling admission (`TIERS.json`).** 0 satisfied, 19 refused, 59 not run,
  and every refusal names the missing identity fields. `A0-F09` is a defect in
  the declaration file beside it, not in this aggregate.
- **Closure-discipline aggregates and exclusions.** Eight aggregates audited
  against their own blocked rows; two refused with
  `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`; 1,121 exclusion rows never dropped, and
  an incomplete sample adds a failing row for the remainder.
- **ETP-T15 reconciliation and history.** Six pre-reconciliation documents
  preserved with digests, the graduation's original bytes kept, the dissent
  unchanged, the 1/33 counter retained in a history block. A correction
  preserves what was believed.
- **`docs/RELEASE_GATES.md` §10.** The article-to-gate mapping names the four
  uncovered articles (5, 6, 7, 9) and states that the gate evidences nothing for
  them. A reader cannot mistake gate coverage for constitution coverage.
- **Independence records.** All 50 assignments reported as same-party
  adjudication with zero external trust domains, and the b85c independence claim
  refused on four named grounds. The adverse result is the headline.

---

## 5. What this audit cannot determine

Stated so the record is not read as more than it is.

- Whether the 200 `residual_sites` rows are a prefix, a sample or the full
  contract-bounded subclass of the 449. Determining it requires re-running
  `consumer_closure.py`; A0 did not.
- The validity of the 27 cohort families carried forward at `26ba36ff…` (301
  families across the full atlas); the prior run record is not in the tree.
- The freshness of the 228 artefacts excluded by the 512 KiB bound, including
  `artifacts/phase24/COURTS.json` and five phase-25 records.
- Whether HAZ-15 and HAZ-16 changed barrier state deliberately. Only file order
  (register 22:44, receipt 10:30) and the queue narrative show it; the register
  has no transition field.
- The current release-gate output against the preserved pre-reconciliation claim
  set. A0 did not execute `release_gate.py`.
- External independence or external reproduction. No external reviewer or
  reproducer identity exists; ETP-6 remains `EXTERNAL_REVIEW_PENDING`.
- The 549 tracked files that cite `court/tmp` and the untracked outputs they
  name. That is the ETP-0 finding, not re-measured here.
- SARIF conformance, because no SARIF artefact, writer, reader or profile exists.
  The format is absent, not non-conforming.
- The correctness of the 62,297-site heuristic census. The scanner is lexical,
  the source tree changed after the scan, and A0 did not re-run it.

---

## 6. What the later Addendum-A items must build on

| item | findings it inherits | what it must therefore carry |
|---|---|---|
| **A1** SARIF profile and adapter | F01, F02, F09, F11 | a lossless finding model first; an adapter over a 200-of-449 list or a `SATISFIED` declaration would re-truncate |
| **A2** lossless preservation | F01, F02, F03, F05, F06, F12, F13, F17, F18 | original output, arguments, instrument identity, candidate identity, population and remainders in one record |
| **A3** identity model | F04, F10, F15, F16 | rule / logical-finding / exact-occurrence identity, never reused across artefacts, with a per-row join key |
| **A5** completeness and execution admission | F03, F07, F09, F11 | expected versus examined population; an absent population is not an empty population; exit code is not completeness |
| **A6** suppression governance | F02, F05, F07, F08 | a suppressed or reclassified finding remains a finding, with justification, scope, reviewer, independence and expiry |
| **A17** omission resistance | F03, F18 | the pre-registered expected manifest already specified; this audit supplies two concrete instances |
| **A20** deterministic policy engine | F06, F16 | one admission decision over explicit obligations, with the candidate identity of every input |
| **A21** verification-summary attestations | F06, F09, F10, F11, F12 | a summary references the evidence for reconstruction and never replaces it |

The repeated shape across all four classes is the same: **a record states a
conclusion at a level where its members or its identity are not present.** The
existing machinery already refuses that shape in four places — freshness
(`FR_IDENTITY_UNKNOWN`), closure discipline (`CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`),
the claim algebra (`EG_AGGREGATE_UNBOUND`, `EG_EVIDENCE_DIGESTS_MISMATCH`) and
scheduling (`REFUSED` on an incomplete identity). The findings above are the
places where the population, the identity or the remainder is outside the reach
of those rules.
