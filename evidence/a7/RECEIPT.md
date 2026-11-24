# A7 receipt — baseline disposition

## 1. Identity of this batch

| field | value |
|---|---|
| item | A7 (baselines and honest regression tracking: distinguish root-cause elimination from tool-stopped-reporting; no artificial monotonicity) |
| branch | `staging` |
| HEAD at the start | `1efd02cbd` (`verify: make the determinism control about deterministic inputs`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 19 23 0 4 26` (total 45, used 19, free 23, available **26** GiB); `Swap: 45 24 21` |
| derived court cap | `min(8g, 26 − 16) = 8g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no build; no `src/`, `docker/` or another item's evidence modified |

The derived cap was 8 GiB and the running container's cap is 6 GiB, below it.
The container was reused rather than restarted, because one court already held
the memory budget and restarting it would not lower the cap. Every gate is
Python only; no Rust build was required.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `docs/BASELINE-DISPOSITION.md` | 370 | normative document: the problem; the baseline contract; the 10 dispositions and what each licenses; the five-condition `RESOLVED` rule; all 11 refusal codes with the wrong conclusion each prevents; the real baselines and deltas with verdicts; the one defect preserved; the controls and measured figures; non-claims; `NOT_RUN` |
| `forensics/tools/baseline.py` | 2,824 | the model and checker: the baseline record, the candidate/tool/scope/member identities, the 10 dispositions, the 11 codes, `delta`, `admit`, `explain`, the real-record readers, the real baseline and delta builders, the controls, and the `delta` / `explain` / `admit` command line |
| `forensics/tools/tests/test_baseline.py` | 729 | 52 controls: one per refusal code, one per disposition, each condition of the five-condition rule individually violated and refused, every before-member retained, producer determinism, the committed records matching a fresh build, CLI exit codes with printed codes, and document synchronisation |
| `evidence/a7/build_evidence.py` | 236 | deterministic producer of the three JSON records; reads every identity and count from its record, asserts the design expectations and writes no count it did not read |
| `evidence/a7/BASELINES.json` | 3,852,253 bytes | 16 baselines with candidate, tool, scope and A5 state, member or aggregate status, suppressions, time and record+locator; 3 records named as not baselines |
| `evidence/a7/DELTA.json` | 2,344,890 bytes | 4 real deltas over 4,596 records with per-identity dispositions and counts; 7 `NO_BASELINE` entries |
| `evidence/a7/CONTROLS.json` | 2,369 bytes | 11 controls, one per refusal code |
| `evidence/a7/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A7 row only; no other row was touched. No existing
record was edited; the one defect found is preserved with its old and new values
in §6.

## 3. The rule

> A finding that is absent from a later report is not thereby resolved. A delta
> between two baselines must say *why* the member is absent, and only one class of
> reason is a resolution.

A baseline is a finding population bound to a candidate identity: the candidate
(commit, branch and the identity of what it was taken over), the tool identity and
digest, the scope and its A5 completeness state, the exact and logical member
identities (or an explicit aggregate with no members), the A6 suppressions that
touch the scope, the time and the tracked record plus locator. `delta` returns one
disposition per before-member and never deletes an absent member. `RESOLVED`
requires all five conditions: a `COMPLETE` later population, an unchanged recorded
tool, an absent identity, no exclusion or suppression, and a candidate recorded on
both sides where the later side is the one being claimed. Every weaker reason has
its own code.

## 4. The real baselines and deltas

`evidence/a7/BASELINES.json` records 16 baselines: 10 enumerate their members and
6 are aggregates. The enumerated baselines carry **9,274** member identities; the
aggregate baselines carry **65,934** declared counts. The A1 artefact records six
per-run candidates and is marked mixed, not relabelled. Three records are named
as not baselines: the campaign status record, the evidence-receipt file manifests
and the Phase-1 reconciliation baseline.

| baseline | candidate | tool | scope / A5 state | members |
|---|---|---|---|---|
| `a1-sarif-results` | six per-run, mixed | `sarif_adapter.py` `35614b90…` | `a1-sarif-results` / `COMPLETE` | 4,245 |
| `a1-fingerprints-model` | the same six, mixed | `finding_identity.py` | the same scope / `COMPLETE` | 4,245 |
| `etp-claims-before` | `9372bb28b…` | not recorded | `etp-claims` / `COMPLETE` | 35 |
| `etp-claims-after` | `9372bb28b…` (stale) | `apply_claims.py` | the same scope / `COMPLETE` | 35 |
| `closure-ssh-b50-baseline` | `84f624012…`, DSO `e7cbb9ee…` | `consumer_closure.py` | `closure-ssh-b50-obligations` / `COMPLETE` (not A5-registered) | 312 |
| `closure-ssh-b50-applied` | the same | the same | the same scope / `COMPLETE` | 312 |
| `haz15-prefix` | DSO `c816b3d1…` | not recorded | `haz15-padding-observations` / `UNKNOWN` | 2 |
| `haz15-postfix` | DSO `5761b715…` | not recorded | the same scope / `UNKNOWN` | 2 |
| `haz16-classification` | `5d38094cc…` | not recorded | `haz16-ffi-mutation-classification` / `COMPLETE` | 79 |
| `t4-unsafe-sites` | `246e3058…` | `unsafe_obligations.py` | `t4-unsafe-sites` / `COMPLETE` | aggregate 62,297 |
| `t4-suppressions` | `246e3058…` | `unsafe_obligations.py` | `t4-suppressions` / `AGGREGATE_ONLY` | aggregate 1,999 |
| `t4-ignored-tests` | `246e3058…` | `unsafe_obligations.py` | `t4-ignored-tests` / `COMPLETE` | aggregate 54 |
| `t10-closure-exclusions` | `7e70b667…` | not recorded | `t10-closure-exclusions` / `COMPLETE` | aggregate 1,121 |
| `curl-residual-sites` | `17e45eec…`, DSO `fd25cc9e…` | `consumer_closure.py` | `curl-residual-sites` / `TRUNCATED_BOUNDED` | aggregate 200 of 449 |
| `curl-obligations` | `17e45eec…`, DSO `fd25cc9e…` | `consumer_closure.py` | `curl-production-obligations` / `COMPLETE` | 7 |
| `a3-logical-collisions` | the six A1 runs, mixed | `finding_identity.py` | `a1-logical-collision-members` / `COMPLETE` | aggregate 263 (84 groups) |

Four real deltas can be computed. Together they hold **4,596** records: **4,577
`STILL_PRESENT`, 15 `MOVED`, 2 `NEW`, 2 `UNSCANNED_ABSENT` and 0 `RESOLVED`**.
One delta is admitted and three are refused.

| delta | dispositions | codes | verdict |
|---|---|---|---|
| `a3-fingerprint-migration` | `STILL_PRESENT=4245` | none | admitted: the tool changed and every exact identity was reproduced; no absence is claimed |
| `claims-reconciliation` | `STILL_PRESENT=31`, `MOVED=4` | `BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED`, `BL_REFUSED_TOOL_CHANGE` | refused: the four historical `CONTRADICTED` claims were reclassified at the same recorded candidate |
| `closure-ssh-b50-status` | `STILL_PRESENT=301`, `MOVED=11` | `BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED` | refused: eleven obligations changed status at the same candidate |
| `haz15-padding-observation` | `UNSCANNED_ABSENT=2`, `NEW=2` | `BL_REFUSED_PARTIAL_SCAN`, `BL_REFUSED_TOOL_CHANGE` | refused: the sign/buffer/queue findings are absent, but the later population is `UNKNOWN` and the harness identity is unrecorded; the length finding appears |

**No real delta reaches `RESOLVED`.** That is a negative result, not a pass. The
one repair that looks like a resolution (HAZ-15) is refused because the later
observation population was never admitted complete and the harness identity was
never recorded. The producer asserts `real_resolutions == 0`; a later real
resolution stops the producer until the document is revised.

Seven areas have a baseline but no second population at a second identity:
`a1-sarif-results`, `t4-unsafe-sites`, `t10-closure-exclusions`,
`curl-residual-sites`, `haz16-classification`, `a3-logical-collisions` and
`phase1-baseline-20261120`. Each is recorded as `NO_BASELINE` with the reason; none
was synthesised.

## 5. Controls and measured figures

`evidence/a7/CONTROLS.json` records 11 controls over the 11 codes, one per code,
each built in memory from the real claim member identities.

| control | code | asserted disposition |
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

Measured quantities:

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
| new `unittest` controls | 52 |

The other seven codes did not fire on a real delta: no real delta has a later
aggregate, an unrecorded side, a shrunk expected count, an exclusion, a
suppression or an unstable identity that would trigger them. Each is exercised by
its control. That is a negative result, not a pass.

## 6. Defect found in an existing record

One defect is recorded; the record is not edited. Because the two populations are
both bound to the same recorded source commit, the four disappearing
contradictions cannot be read as resolutions.

**6.1 The claim record's source commit did not advance with its bytes.**
`evidence/etp/claims.json` and its preserved before-reconciliation copy
`evidence/etp-t15/history/claims.before-reconciliation.json` both record
`source_identity.commit = 9372bb28b2fbe2f71cf2aa2ab501414d45e87d42`, although
their verdicts differ and the live bytes were edited after the reconciliation.

| field | old value (preserved history copy) | new value (live record) |
|---|---|---|
| file SHA-256 | `65d8105b744c80ae01e76af8bf3370c478ab116c7fc9b0f16f63eea5d5c579de` | `2968ffd6976f19bd701c58636b51cceed192e42c928dd2116217449a7b85a1bb` |
| `source_identity.commit` | `9372bb28b…` | `9372bb28b…` (unchanged) |
| verdicts | 17 `ESTABLISHED`, 13 `PARTIAL`, 4 `CONTRADICTED`, 1 `SUPERSEDED` | 17 `ESTABLISHED`, 13 `PARTIAL`, 4 `SUPERSEDED`, 1 `RISK_ACCEPTED` |
| the four | `ETP0-CLM-004`, `-005`, `-030`, `-032` read `CONTRADICTED` | the same four read `SUPERSEDED`, `SUPERSEDED`, `RISK_ACCEPTED`, `SUPERSEDED` |

`evidence/etp-t15/RECONCILIATION.json` names `base_commit = 576e26d2d…`, and the
live file changed at `e0b727d06` and again at `2d31a23fb`; the record's own
candidate field did not advance. The old file remains tracked and unedited. The
baseline records the same candidate token on both sides and marks the later one
stale in its note; the delta therefore refuses
`BL_REFUSED_ABSENCE_AS_RESOLUTION`, `BL_REFUSED_MOVED_AS_RESOLVED` and
`BL_REFUSED_TOOL_CHANGE` and classifies the four as `MOVED`, not `RESOLVED`.
Repairing the record is a separate decision for its owner; this item preserves the
old and new values.

## 7. Gates actually run

All commands ran inside the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 19 23 0 4 26` (available 26 GiB); `Swap: 45 24 21` |
| new controls | `python3 -m unittest forensics.tools.tests.test_baseline -v` | `Ran 52 tests in 7.815s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 911 tests in 172.882s`; `OK` (**911 tests, 0 failures, 0 errors, 0 skipped**; 859 before this item; no test removed, none ignored) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool evidence/a7/BASELINES.json` | exit 0 |
| | `python3 -m json.tool evidence/a7/DELTA.json` | exit 0 |
| | `python3 -m json.tool evidence/a7/CONTROLS.json` | exit 0 |
| producer, two runs | `python3 evidence/a7/build_evidence.py --out /tmp/a7a` twice | `baselines=16 enumerated=10 aggregate=6 members=75208 notBaselines=3`; `deltas=4 admitted=1 refused=3 records=4596 MOVED=15 NEW=2 STILL_PRESENT=4577 UNSCANNED_ABSENT=2 noBaseline=7`; `codes=BL_REFUSED_ABSENCE_AS_RESOLUTION,BL_REFUSED_MOVED_AS_RESOLVED,BL_REFUSED_PARTIAL_SCAN,BL_REFUSED_TOOL_CHANGE`; `controls=11 codesCovered=11` |
| producer byte-identity | `cmp /tmp/a7a/<name> /tmp/a7b/<name>` | `byte-identical BASELINES.json`, `byte-identical DELTA.json`, `byte-identical CONTROLS.json` |
| committed bytes | `sha256sum evidence/a7/*.json` | `f2d6e37928a6fd05fa295a06cb54bd64a495336ab0af0a66403bcdbfbb0fe188` `BASELINES.json`; `c676780ccde5bfdfb53f9aa3410be7c3feb6466cce3f904efab5f632b5d9dbb2` `DELTA.json`; `ae80106059df8cdf703116850869ede86e9713a43a08d919f91f49794c7a03e2` `CONTROLS.json` |
| delta CLI | `python3 forensics/tools/baseline.py delta` | exit 1; the four lines above, with `admitted=yes` for `a3-fingerprint-migration` and `admitted=no` for the other three |
| admit CLI | `python3 forensics/tools/baseline.py admit <delta>` | exit 0 and `admitted=yes` for `a3-fingerprint-migration`; exit 1 and `admitted=no` with the printed codes for the three refused deltas; exit 2 and `BL_REFUSED_NO_BASELINE` for an unknown id |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/BASELINE-DISPOSITION.md`, `?? evidence/a7/`, `?? forensics/tools/baseline.py`, `?? forensics/tools/tests/test_baseline.py` |

**Reproducibility.** The producer reads every identity and count from its record
(the A1 result count from `/runs`, the claim count from `/claims`, the closure
obligation count from `/obligations`, the HAZ-15 booleans from
`/finding_prefix` and `/finding_postfix`, the HAZ-16 row count from `/rows`, the
T4 and T10 counts from their native keys, the curl bound from
`/precision/residual_sites_bound`, the A3 collision counts from `/recorded`) and
cross-checks the A1 result count against its fingerprint sets. It asserts the
design expectations and stops with a refusal rather than writing a count it did
not read. Two runs at one source identity are byte-identical, and the committed
bytes match a fresh build (`test_the_producer_is_deterministic`,
`test_the_committed_records_match_a_fresh_build`).

## 8. Obligations retained

* **No real delta reaches `RESOLVED`.** The four contradictions are still claims;
  the eleven obligations are still in the closure population; the HAZ-15
  sign/buffer/queue findings are absent only inside a population not admitted
  complete. The model records the movements and refuses the resolutions.
* **The claim record's stale candidate identity.** The live record still states
  `9372bb28b…` while its bytes were reconciled later. The baseline preserves both
  files and treats the later candidate as stale; the record itself is not
  repaired.
* **The claims producer's historical identity.** The before-reconciliation record
  names no producer. The tool identity is recorded as unrecorded, which is why
  `BL_REFUSED_TOOL_CHANGE` fires; it was not guessed.
* **The HAZ-15 observation population.** The record names four cases and 24 rows
  but states no expected observation population and records no harness identity.
  The baseline records `UNKNOWN` and refuses `RESOLVED`; it does not infer
  completeness from the row list.
* **The HAZ-16 after population.** The three repairs are a mechanism description
  with a test and a revert control, not a second 79-row classification. No delta
  was computed.
* **The seven `NO_BASELINE` areas.** A later scan that closes one must be bound to
  its own candidate and tool before a delta exists.
* **The closure pair's own admission.** The baseline records the two closure
  records as `COMPLETE` over their stated 312 obligations but does not audit the
  closure engine's admission; that is the closure discipline's subject.
* **The five-condition conservative limitation.** A later population complete
  over a smaller expected count is `POPULATION_SHRUNK_ABSENT`, even when the
  shrink follows from a legitimate fix, because the recorded fields do not
  distinguish the two.

## 9. `NOT_RUN`

* **BOUNDARY.** No caller or dependency-closure audit of the baseline readers, no
  sanitizer or Miri run (the item is Python only), and no negative-control canary
  outside the tool's own refusal controls.
* **SEAL.** No full forensic regeneration, no compatibility or cryptographic
  assurance against this candidate, and no held-out verification.
* **Independent review.** The author of the document, the tool and the controls is
  not an independent reviewer, and no third party has reviewed the
  disposition-to-code mapping.
* **The seven `NO_BASELINE` areas.** No second population exists at a second
  identity; none was synthesised.
* **The HAZ-16 after population.** The classification was not re-run, so there is
  no second enumerated population.
* **A real `RESOLVED`.** None exists in this tree. The positive path is the
  in-memory control `test_the_positive_path_reaches_resolved`, not a real delta.
* **The claims record's later candidate.** The claims record itself does not
  record it; the reconciliation record names `576e26d2d…`, and the live bytes
  changed at `e0b727d06` and `2d31a23fb`. The baseline records the stale identity
  rather than repairing it.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test` was
  run.

## 10. Non-claims

Baseline disposition is not a safety, compatibility or cryptographic result. A
resolution is not a safety proof, and a baseline is not a census of the tree.
`RESOLVED` is scoped to the population examined; `STILL_PRESENT` does not say a
finding is open; `NEW` does not say it is a new defect; `MOVED` does not say it is
fixed; `UNKNOWN` is not a pass. An aggregate is not a census, and a `NO_BASELINE`
area is not a clean area. The A1 artefact's six per-run candidates are not one
candidate. No record read here was edited, and no refusal code, disposition or
admission state was relaxed.

## 11. Correction appended: the source identity was a moving value

**A8 found this, not A7.** A8's whole-tools run reported `Ran 939 tests` and
`FAILED (failures=1)`:

```
FAIL: test_the_committed_records_match_a_fresh_build (test_baseline.ProducerTests)
```

### 11.1 The old value and the cause

The three records stated

```json
"sourceIdentity": {
  "asOf": "2026-11-24",
  "branch": "staging",
  "commit": "1efd02cbd1401c4cffb854b906c021915df94386"
}
```

`1efd02cbd…` was the live `HEAD` at the moment the producer ran: the measured
source candidate `S`. The record is carried by the evidence commit `E`
(`9f79f5066` at A8's run, and later). The producer read the token with
`git rev-parse HEAD`, so rebuilding at `E` necessarily recorded `E`'s token and
the committed bytes could never be reproduced at the commit that carries them.
This is the two-identity confusion Article 22 exists to prevent: `S` (what was
measured) was conflated with `E` (where the receipt lives). The defect was in
`baseline.py`'s `source_identity()` and in the producer, not in any baseline
member, count or disposition.

### 11.2 The new contract

The source identity is now an explicit input, and the record names the bytes it
measured:

```json
"sourceIdentity": {
  "asOf": "2026-11-24",
  "commit": "1efd02cbd1401c4cffb854b906c021915df94386",
  "inputs": [ { "path": "evidence/a1/SARIF.json", "sha256": "5c0cfee6…" }, … ]
}
```

* `commit` is supplied. `build_evidence.py --source-commit <token>` is the
  explicit argument; when it is absent and a record exists, the default is the
  value the record states, never a live reading. `asOf` is derived from that
  commit, so it is stable across checkouts. `branch` was removed: it is worktree
  state, not a property of the measured source, and it made the record depend on
  how a verifier checked it out.
* `inputs` is the audit of every file the producer read while composing the
  evidence set: **16 files**, each by repo-relative path and full-length
  SHA-256. The audit covers both `_read_json` and every direct `digest_file`
  call, so scanner records and the producer scripts the record names are not
  missed.
* `verify_input_digests` refuses with
  **`BL_REFUSED_INPUT_DIGEST_MISMATCH`** when a recorded input hashes to a
  different digest, when a recorded input is no longer read, or when a new input
  is read that the record does not name. A record with no inventory is the
  bootstrap run that establishes one; every later run is verified. This is the
  property that would have caught the stale identity, so it is enforced, not
  documented.

The verifier test now runs the producer **at `HEAD`, with the identity the
record states**, as an external verifier would:
`--source-commit 1efd02cbd1401c4cffb854b906c021915df94386`. It no longer depends
on the worktree being at `S`, and it is not skipped on a later or dirty worktree.

### 11.3 Regenerated records

All three records were regenerated at `HEAD` with the recorded `S` identity.
Their measured content is **identical except for `sourceIdentity`** (verified by
parsing both sides and comparing every other field), and all three are
byte-identical under both the default run and the explicit-argument run.

| record | old SHA-256 | new SHA-256 |
|---|---|---|
| `BASELINES.json` | `f2d6e37928a6fd05fa295a06cb54bd64a495336ab0af0a66403bcdbfbb0fe188` | `2a5a3f863c1ddf7775d0f524e7b36feb9f01a22a6c6569eff1d3c93081ae1cab` |
| `DELTA.json` | `c676780ccde5bfdfb53f9aa3410be7c3feb6466cce3f904efab5f632b5d9dbb2` | `0444a879bf4a0ddf5c50cffba7f51a5834b0fc4a1702d5190815de1f4470c8cf` |
| `CONTROLS.json` | `ae80106059df8cdf703116850869ede86e9713a43a08d919f91f49794c7a03e2` | `0b5f7a0473e9e84aeec37e0aff17452ac5fad73e2d2fc270a633aea1d886f771` |

No baseline member, delta record, disposition, count or control changed:
`BASELINES.json` remains 16 baselines (10 enumerated, 6 aggregate, 75,208
declared members/counts), `DELTA.json` remains 4 deltas over 4,596 records with
4,577 `STILL_PRESENT`, 15 `MOVED`, 2 `NEW`, 2 `UNSCANNED_ABSENT` and 0
`RESOLVED`, and `CONTROLS.json` remains 11 controls over the 11 delta codes. The
new code is a producer-level record refusal, deliberately not added to the
delta-code registry (`REFUSALS`) or to the document's 11-code table.

### 11.4 Preservation

Sections 1–10 above are unchanged, including the old identity in §1 and the
reproduction claim in §7. This section is appended so the record shows what was
believed, what was measured, and why the identity representation changed.
`docs/BASELINE-DISPOSITION.md` was inspected: its §11 sentence states only that
re-running at one source identity reproduces the bytes, which remains true under
the new contract (the identity is now supplied rather than read). It contains no
statement about the `sourceIdentity` fields that is now wrong, so it was left
unedited. No `src/`, `docker/`, `AGENTS.md` or A8 file was touched.
