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

## 12. Correction appended: the exact identity was checkout-location dependent

**A batch triage note reported this baseline as a stale record left behind by the
A3 identity model. The measurement says otherwise.** `forensics/tools/finding_identity.py`
is byte-identical between the recorded source commit `1efd02cbd…` and the tree that
regenerated the record (`29e9ac46bd049392b20decb8518e64a77c31d50cbbe29dd2df72f19e7f9718b6`), `evidence/haz-16/CLASSIFICATION.json` is
byte-identical to the recorded input digest
(`85942983564b19d4161425677ce47eee9500cf6a59ed5e1abf8adeb1cf43f34d`), and all 79 `logical` and `rule` member identities are
unchanged. The recorded `exact` identities were not produced by a different A3
model.

### 12.1 What moved and why

`read_haz16_members` built its A3 binding as
`fi.Binding(uri=Path(path).as_posix(), digest=sha256, digest_scope="record")`.
`path` is absolute, so the binding URI was
`/work/evidence/haz-16/CLASSIFICATION.json` in the court that produced the
record. The exact fingerprint hashes the binding URI (section 3 of
`docs/FINDING-IDENTITY.md`), so the same record bytes produced different exact
identities when the tree was checked out anywhere else. Recomputing row 0 with
`uri=/work/evidence/haz-16/CLASSIFICATION.json` reproduces the superseded
`9ef25179c5d41307e5ec76de6265b5574f286c5aaf34e408b9502769cadff3be` exactly; `uri=evidence/haz-16/CLASSIFICATION.json`
reproduces the regenerated `fbd123adb6d3d71bf2712ac57fec6de9a623f7072e6dc5e48a6eb3e0f45255ce`. The logical and rule
fingerprints do not hash the binding, which is why they did not move.

This was a producer defect, not a stale A7 record and not a change in the identity
model: an exact identity must be a property of the record's bytes, and it was
instead a property of the build machine's mount point.

### 12.2 The repair

`read_haz16_members` now takes the repository-relative artefact name
(`evidence/haz-16/CLASSIFICATION.json`) and hashes that. `forensics/tools/finding_identity.py`
is untouched. The three A7 documents were regenerated with the producer's explicit
identity:

```
python3 evidence/a7/build_evidence.py --source-commit 1efd02cbd1401c4cffb854b906c021915df94386
```

`BASELINES.json` changed only in the 79 HAZ-16 `exact` fields; no member label,
logical identity, rule identity, count, scope, disposition or control changed.
`DELTA.json` and `CONTROLS.json` are byte-identical. `test_baseline` is green on the
host and in the court at `/work` (57 tests each), which is the property the
absolute path had broken.

### 12.3 Regenerated records

| record | superseded SHA-256 | regenerated SHA-256 |
|---|---|---|
| `BASELINES.json` | `2a5a3f863c1ddf7775d0f524e7b36feb9f01a22a6c6569eff1d3c93081ae1cab` | `a57a2766046ff4123e39bce62b3baa75fde758790aac09520657550f76986ca5` |
| `DELTA.json` | `0444a879bf4a0ddf5c50cffba7f51a5834b0fc4a1702d5190815de1f4470c8cf` | `0444a879bf4a0ddf5c50cffba7f51a5834b0fc4a1702d5190815de1f4470c8cf` |
| `CONTROLS.json` | `0b5f7a0473e9e84aeec37e0aff17452ac5fad73e2d2fc270a633aea1d886f771` | `0b5f7a0473e9e84aeec37e0aff17452ac5fad73e2d2fc270a633aea1d886f771` |

`DELTA.json` and `CONTROLS.json` are unchanged. The superseded `BASELINES.json` is
the tracked blob at `HEAD` before this correction; it remains in Git history and is
not rewritten.

### 12.4 The superseded binding

| field | superseded | regenerated |
|---|---|---|
| binding URI | `/work/evidence/haz-16/CLASSIFICATION.json` | `evidence/haz-16/CLASSIFICATION.json` |
| source commit | `1efd02cbd1401c4cffb854b906c021915df94386` | `1efd02cbd1401c4cffb854b906c021915df94386` (unchanged) |
| record digest | `85942983564b19d4161425677ce47eee9500cf6a59ed5e1abf8adeb1cf43f34d` | `85942983564b19d4161425677ce47eee9500cf6a59ed5e1abf8adeb1cf43f34d` (unchanged) |
| moved `exact` | 79 | — |
| moved `logical` | 0 | — |
| moved `rule` | 0 | — |

### 12.5 Superseded member values

| index | label | superseded `exact` | regenerated `exact` |
|---|---|---|---|
| 0 | `src/bn/bignum.rs:BN_bin2bn:FAILURE_ATOMIC` | `9ef25179c5d41307e5ec76de6265b5574f286c5aaf34e408b9502769cadff3be` | `fbd123adb6d3d71bf2712ac57fec6de9a623f7072e6dc5e48a6eb3e0f45255ce` |
| 1 | `src/bn/bignum.rs:BN_bn2bin:FAILURE_ATOMIC` | `a91334590fb02a6e5e9477dafe35c73b1a61bd550db7d430a7da0f0716e7b25b` | `2c8a37a93ea9c2a5db24ddc48df8f6d989bdb86765317a07fc2105ee6dd0166a` |
| 2 | `src/bn/bignum.rs:BN_bn2mpi:FAILURE_ATOMIC` | `088fd2bcdcfd96609acdd708f925ad2a710b309f81a999a079d71edcfb337a93` | `3cde8a85fed5a5d4a9c714f649cbc595af99a4ec2eb120bfbdd2bab2f8fdbd1e` |
| 3 | `src/bn/bignum.rs:BN_clear:FAILURE_ATOMIC` | `52d95a70e9b860f127768a79ab848f42db23723add6487a77f7e4b855d357b92` | `a7fc4c29347db16c0374d0f2724c27b2119b488f2d75952d6f81276b31fc0018` |
| 4 | `src/bn/bignum.rs:BN_clear_bit:FAILURE_ATOMIC` | `cad741b6e68df6b212425e2d6b42ae4216d0c2ac195462739789d5d0dd2d8419` | `894ee91a4f1d667ab74d5c23746b69c4d80897650ef32a7a469ef4bd08732d07` |
| 5 | `src/bn/bignum.rs:BN_clear_free:FAILURE_ATOMIC` | `623d90afda6db5abcaa6fb6c380b74f11c0a221f21f4f97b6d69454dbf169884` | `94b43cfb90503418e828ab2050ee4f672b254be8d85d3de451e64f6cd0f341c8` |
| 6 | `src/bn/bignum.rs:BN_consttime_swap:FAILURE_ATOMIC` | `47eb04199230a989f49a5f5637add5e2e5d7faab2035f2a1999cb179b81e05b8` | `c477d2d03e1ae950173d74200941dafbba52dc2200596fa866e071b72e9b1559` |
| 7 | `src/bn/bignum.rs:BN_copy:FAILURE_ATOMIC` | `17e0cbbe601c29f097947f698777d63ce602448c59a9c551c4f184b2ec353e7b` | `655349dd03b16631d8d8c88c02850bbae5e4ed26138098f03cb76e1873caeb0c` |
| 8 | `src/bn/bignum.rs:BN_free:FAILURE_ATOMIC` | `c638c88a3a0e2cc7ceb9637fc8a3d189e0901188db0a95d9133087669f38f551` | `f9045fd0938226c7deaf4c7b3e153e1a7a0b4b3e29ea4bf05dbefb702ffa1b97` |
| 9 | `src/bn/bignum.rs:BN_lebin2bn:FAILURE_ATOMIC` | `4a2c159d462c0d8b58c899cc0e32329e8543bade3a2818dfc16c09f9322eb959` | `897e0494ff848ca620364b708fddedd424b44a99efe7fcdc7bf704b85675b7bf` |
| 10 | `src/bn/bignum.rs:BN_mpi2bn:FAILURE_ATOMIC` | `742f3e3e195291daffac7d9abd9f013bc19dde1b3cd11ffec6160eb87377cb11` | `20c309ab0b0146723a335bf742d5dc31897dd70ecc85b0454adfe4f95e75f9b2` |
| 11 | `src/bn/bignum.rs:BN_secure_new:FAILURE_ATOMIC` | `9a0c663925500d869ac8155b0aa618eb28f30552718a5293f93ef9cc60b3f60b` | `06f7a66e15f76a87e7e65da82ed16a261dc3ad2c203ee6cee90e14785dbfb1ef` |
| 12 | `src/bn/bignum.rs:BN_set_bit:FAILURE_ATOMIC` | `505c43ad082aca31884c576999834186264909bdda2ca41c156347c80aa2e783` | `79149498c526b3552f6cda54e3a03d249eba0df80c23b2deaa1298a60bfdaac5` |
| 13 | `src/bn/bignum.rs:BN_set_flags:FAILURE_ATOMIC` | `7c1fd0e85f3d4dbedcdf327a19626a93ea4ee3ece28be0d1c90ed8ffa2107639` | `396e6dc8ec2e9e345e771ea84fbfa89e348a8f9eeaa386f9b9cefffaa0b49d4a` |
| 14 | `src/bn/bignum.rs:BN_set_negative:FAILURE_ATOMIC` | `911dc876057294c59e2cf1d6308cbacfb767d8d727e1aac09346bbba76f748f7` | `817af694a2deab973de7dc3f2791c56332376b0e78cd2322e748b0149d85df48` |
| 15 | `src/bn/bignum.rs:BN_set_word:FAILURE_ATOMIC` | `652fdfd6ab4df55ebbc51e6848fdda952d59712ddf5121339f2bb55a664e416c` | `e21ae697b00a89fd1462ab448ad77334c0298df095c482e971d708909a037f0a` |
| 16 | `src/bn/bignum.rs:BN_swap:FAILURE_ATOMIC` | `99b397ee253bd3325e19388de872726c6ccb9ea00b19cb3c37cf949a2bde7a54` | `aab861450ede8e073bf78a834b2a5fd5932426b69ba1f241ae8a4f255df47a3a` |
| 17 | `src/bn/bignum.rs:BN_with_flags:FAILURE_ATOMIC` | `40a80346a9dd003a3f92130aaeb3dec8454173f73f11268fcf7f775bc15cd5c2` | `5086c7df685014c941e3e2f49f2bc2f583d89e27f33b7a93542f25ffab4009b0` |
| 18 | `src/bn/blinding.rs:BN_BLINDING_convert_ex:FAILURE_ATOMIC` | `99f4a67756a25a257060c2c8a5b1606259ef9e39a5ec5b7b62962d68d65d266a` | `badea26e527def1007b9fe890cb969838836c00050b23b5b389cd28140c1e9cc` |
| 19 | `src/bn/blinding.rs:BN_BLINDING_create_param:FAILURE_ATOMIC` | `b8c552e70eb7c9401cfd2de71d88b3e545d9f706ea7a63927bd44e6c06021f95` | `2add18c40a32e771e05facc29a6dd844270a172d6444316eb14ac68047758dc8` |
| 20 | `src/bn/blinding.rs:BN_BLINDING_free:FAILURE_ATOMIC` | `cee78dc1db21bc77f4e946939c798f032abf67a00bff394088151abe560b2ee7` | `48556e94b675f9a6ccfcce3e9d6bb4a9a2d417b2f2648aeb03a66ae7745dc342` |
| 21 | `src/bn/blinding.rs:BN_BLINDING_invert_ex:FAILURE_ATOMIC` | `85c3638183ba159c6fe74d9db5c84cd1ecaaf1f9739905e7e10bc492d99c4a18` | `34507dd7e333d9c7bc1e6156326865136149ee64ba5cd5de445ead470da5d11f` |
| 22 | `src/bn/blinding.rs:BN_BLINDING_new:FAILURE_ATOMIC` | `7620aad20b0b15bbf81a978c353c9bf2693484434f8b9fb2bfa61463bd893984` | `b9757532e4ace9f23717191d5170bfb96e7b925f2ccf31d7828c1518f6fd5f99` |
| 23 | `src/bn/blinding.rs:BN_BLINDING_update:FAILURE_ATOMIC` | `0c679c712e590d9dc630e3734abc14c18a2f2516ce3e7ba19b6a30ecda7e706b` | `8b0bd74ec5fd42a2442d2397b92d942c4e453bd57659ff3d30234ce4c214204f` |
| 24 | `src/bn/ctx.rs:BN_CTX_free:FAILURE_ATOMIC` | `3d87a8346d7032775f859f2f42aeab0479cee210e07ba319c2c8b1d57e0f4148` | `55585f15a40b864d41e5f37f385f81fecd240868fd00741fcc08cd507e2ee951` |
| 25 | `src/bn/ctx.rs:BN_CTX_get:FAILURE_ATOMIC` | `99f9ae2a19e570f04b2e233bdc69354eac834f99518f9dc929a43a06085e1b41` | `080d8719a6534b69deed98330ec65ae2ac9d71b137f31f891597ab0050dec2d3` |
| 26 | `src/bn/ctx.rs:BN_CTX_start:FAILURE_ATOMIC` | `b2e897ea7d3fb7df60cbed26d92100d7b05bbc2319b644ef2391759d85df0e9f` | `0e18a54494b882b2402a0187212e47657185eadde69c45ecf1a43a3f0fe113b6` |
| 27 | `src/bn/ctx.rs:BN_GENCB_free:FAILURE_ATOMIC` | `684cfe53e88692eeac5630a38b84d7b140d5d0b27f439b3e10f898f28d4c2df0` | `ae38d14f01220bc3730530993ac82a122212403588640bc26c8cfcacf934b910` |
| 28 | `src/bn/ctx.rs:BN_GENCB_new:FAILURE_ATOMIC` | `827ff8ab5dab5cef47d76b843fc724ee06cb6c721a346d0ed645399aae75e42f` | `f140b60dcf25750f4ecad2bb66b05b4dff5b2d1502ee59e14d88d6cca63a8ea5` |
| 29 | `src/runtime/bio/iolib.rs:BIO_callback_ctrl:FAILURE_ATOMIC` | `3d9994a2ba5ad7afef475848e374fbfc5b965fc0e25c63595d4b635249ebe194` | `a23f75b694b204d738a42faf9bbaa73bdb4c0e27e9b810c90235334e897e4799` |
| 30 | `src/runtime/bio/iolib.rs:BIO_ctrl:FAILURE_ATOMIC` | `8567e230e672937034e50fceb91118a05b7751afaa049c50d37d5b6ade8f1d6d` | `0247b37313f9055a69c27a548f32a164569590e90ba9f999eb50341f06275e95` |
| 31 | `src/runtime/bio/iolib.rs:BIO_do_connect_retry:FAILURE_ATOMIC` | `646957b4abb33c488a6660789aa556276302f2ea6f663f17fc5c90e6331ae380` | `ebfe67a47d7288d88d6ea5d32f91246af860311ff06e024e3dacce853b50989c` |
| 32 | `src/runtime/bio/iolib.rs:BIO_get_line:FAILURE_ATOMIC` | `191c89725127be600f52ce4d263cb0aef39bf77a58b60adeba8a9c9ad46e7384` | `df48443952de87e25b4bc1a98babec6cee2d87cc2d2efa4b5d618c4d090bdd2f` |
| 33 | `src/runtime/bio/iolib.rs:BIO_gets:FAILURE_ATOMIC` | `9077bb87c55de87ceaea01dd708930e1de2b6a6cab105a276ded9738c763be64` | `6a13f673c7a9210cce68f7cc856c17a44a3e79ee89e5d5f1a11190f5618f7023` |
| 34 | `src/runtime/bio/iolib.rs:BIO_puts:FAILURE_ATOMIC` | `c032453c3b6315b122e1399154bd9c6e930863a68e2c98fb24bb2c5c34629987` | `b19b974b2b8f007cfff3a361050cf47a376342f278299ad1e0b91509d580978f` |
| 35 | `src/runtime/bio/iolib.rs:BIO_recvmmsg:FAILURE_ATOMIC` | `5e7a7e29fac4d12927cf78abfe42b47f60f77be4cc7b0c18175b612a19f6599b` | `62cb417b35cd464ac52379a29133798108c11cba11703c84f7b02aab881570cf` |
| 36 | `src/runtime/bio/iolib.rs:BIO_sendmmsg:FAILURE_ATOMIC` | `a584bb73a66acc7a5dbb96fd990fd68a1f787c7f6f8ae80bc537d389b38f9fcd` | `163e9eeff4fbccbae6132cb55a8111b54c02f4036fc89afd4003f7f60774c458` |
| 37 | `src/runtime/bio/mod.rs:BIO_dup_chain:ROLLBACK` | `7bf5018f2e98177451d2c331057de19da43cbed34e498f953698968e305ee925` | `f8c352eb9e9db900018e2afb403ab99c635837ba7dc79b5ade148d9c3f40c662` |
| 38 | `src/runtime/bio/mod.rs:BIO_find_type:FAILURE_ATOMIC` | `b21ed88bfc0696958da5ca9b957aacb8bde14d9695633825fb90bae9a613419a` | `409759a917c856305e92be1edaf97bc8e12c6e954ac2521c6ac0552f449cc1ba` |
| 39 | `src/runtime/bio/mod.rs:BIO_free:POISONED` | `3863353ee9c1d23fb31876fcc4888b69e5fd93c35fdbee157275fad34ca5e3a8` | `a8bf3f507b2a825280becbb728404344d35d5830c019ddb859f5b515129f66f8` |
| 40 | `src/runtime/bio/mod.rs:BIO_free_all:FAILURE_ATOMIC` | `e10f3b037a4955e99c2c0df1b8b575801b95767439515f7794fa781038d513a8` | `0ccc8b519c4e461a95e0ede5b598a249b4d83c0654b5817a4cc73d1f2376db29` |
| 41 | `src/runtime/bio/mod.rs:BIO_get_retry_BIO:FAILURE_ATOMIC` | `8fcf5067ce0fc4a8ca1fc01636420f8e021fd54f63c6c580714e642e4a189fc3` | `6546eb949a9e0bcc33c9e46d5116049d16a63a077b97e2859898335459016d36` |
| 42 | `src/runtime/bio/mod.rs:BIO_new_ex:FAILURE_ATOMIC` | `c9fec820025c58597d25adb2ea71cdd3c736142b8d5a556942908cf877cbcabb` | `0758e177e3a80196ba9b73749a23e69451c7a0227d33b4475769e34ab0bbe3db` |
| 43 | `src/runtime/bio/mod.rs:BIO_push:FAILURE_ATOMIC` | `3edd5f7f2bf1e8e595170df51fa94ab936ca32dde8b73bf195940104b4735f0f` | `b2d1a54c69f72614d6aa52408643be74ded5b0fb21ecd755e9823dd8c58acd9d` |
| 44 | `src/runtime/bio/mod.rs:BIO_up_ref:FAILURE_ATOMIC` | `643232e7a4f7d406c7f5d505e2802168f86b43dbda4c30bceff7785aa89d5f20` | `03fd1e788473bfc339143b6ba691c0db858c7c352ec77c85d0ca28bb7a33760c` |
| 45 | `src/runtime/bio/mod.rs:BIO_vfree:FAILURE_ATOMIC` | `ab9954b923fb9a8c412a5cdc4ff97b5c678b39e6b2f33f6f3d5fea8714d1d1d3` | `053bee2809facce34e71d1aaaab523288a9f231ad96b3ced1089cd94effac136` |
| 46 | `src/runtime/ex_data.rs:CRYPTO_dup_ex_data:PARTIAL_EXPOSED` | `aa904d7484c2e291ffb9c049f357e7467b829ae5dbfe4837dca0864584a8fdfb` | `0b5b053bc5ae3fa48f9c47a0b23a143917e6e811f3636fce6f4c067fd52c283b` |
| 47 | `src/runtime/ex_data.rs:CRYPTO_free_ex_data:PARTIAL_EXPOSED` | `85737dc7ec7b15e42f87b4232bc906e1fed706e770963a3b861c875471a3b457` | `d0266e38218bb55ae985b4a1a304a052132e8c98aed78fe6c25259c9c7430dc7` |
| 48 | `src/runtime/ex_data.rs:CRYPTO_get_ex_data:FAILURE_ATOMIC` | `a89f1d000e1a6845ab8139f3bb2e480c12a772b9a5d51cbe360a299eac4fdb04` | `0845c210aee3363b950b1f3dcd48f6c684bccf86a8889e36615ec37b3fae24fe` |
| 49 | `src/runtime/ex_data.rs:CRYPTO_get_ex_new_index:FAILURE_ATOMIC` | `e93ca9f10f7e0a0f111f8f992f306dfeb3fd4fd1d0901af1bc9ccfcbd1280f94` | `7b75d7a26f4f809cc4d178d83ac0a66fd1ef062bb7e17c466106470b412aaae7` |
| 50 | `src/runtime/ex_data.rs:CRYPTO_new_ex_data:PARTIAL_EXPOSED` | `b27a97b6df94922585fd61f2840f95ea1482282b58c825de6ea49ab4b2db3b05` | `dbc427b96098cb4f83fdc4042a3b33ead892ed00f49c045c31ee735fb318d200` |
| 51 | `src/runtime/ex_data.rs:CRYPTO_set_ex_data:FAILURE_ATOMIC` | `48667942a29951c4cda140727bf6996b3fcfd90d370b22731c57c3faff08080b` | `4e5b412a6be31f903e4ac365bc77694a8c10f5d029fc9040ddd0091813ee436e` |
| 52 | `src/runtime/lhash.rs:OPENSSL_LH_delete:FAILURE_ATOMIC` | `12ac4df4708836ab0d74e00a8853e1ac6296446b79015997c2d19d59326b304f` | `f9e136585eb2714f2fdddc7bc1bdf961099b4fd3a2630b5fdcae48cdbf143e08` |
| 53 | `src/runtime/lhash.rs:OPENSSL_LH_flush:FAILURE_ATOMIC` | `952e9f9ead1d4bc38ecf0c48e2a8565e9fe20abe391042b84b98c50011d7fb42` | `4eb245750baadd86489f0b0879bdc42e4032f730a2a02a3470d1e1b5690bc3aa` |
| 54 | `src/runtime/lhash.rs:OPENSSL_LH_free:FAILURE_ATOMIC` | `1efb8c5e7be898c4ee1671a114ad47121aafc15eff93ca2ba81572527616f2fc` | `71684659ea8e81fe96a6b1f3c34d9e459c7d54ee9a31bb54daa738d2899a4828` |
| 55 | `src/runtime/lhash.rs:OPENSSL_LH_insert:FAILURE_ATOMIC` | `8e88cffcbe2de108e27102b704baacab54ef6711af0e8a62fd93cc3c198cf345` | `f59e9f797c914693ab7dc55df87d2919a9d44de2294f70ea42a173c5fb352bb8` |
| 56 | `src/runtime/obj.rs:OBJ_NAME_add:FAILURE_ATOMIC` | `fac16f156fdc7c3122bcd019190387053fd561f477856f5e6c234dc94d9b2894` | `6792bcb677795909b3811ef28159dd73ffc8bb5e831316057fdc4294bc1447c6` |
| 57 | `src/runtime/obj.rs:OBJ_NAME_cleanup:FAILURE_ATOMIC` | `d1a2d3b138b769478843d4cd038361d0513d965f27a2693f449a722c41d4d00c` | `fa795a34d9179d1be3911590aad217bc722f1c48448c8365468417832f28f7ee` |
| 58 | `src/runtime/obj.rs:OBJ_NAME_new_index:FAILURE_ATOMIC` | `a8bea24e488c7936c87b20f100856e09157f7d5693da48499dbecce0584eea83` | `189c0d25987c8fbfdbccd478ff07604a2114cc065d6848eae0043f409496b7fc` |
| 59 | `src/runtime/obj.rs:OBJ_NAME_remove:FAILURE_ATOMIC` | `a0ffb4d4ad311059154012896ea4a16c86ac3b88b543f93d10f168a0be2d5fd7` | `7f8923bbad550814e8ac15c403baf9949c908c6241ab38b0c7052c122f273e2b` |
| 60 | `src/runtime/obj.rs:OBJ_add_object:FAILURE_ATOMIC` | `d81da17a3b57783bb74b7e514ff1a667dd4b17676ae90ec12f410464bde2f45a` | `5e85d867f0402b0932e6e855d2c8b654d5fa8a18ad4dfd77ff8e37ae0d80d828` |
| 61 | `src/runtime/obj.rs:OBJ_add_sigid:FAILURE_ATOMIC` | `b76289574aa8e41a2b47e7471071ab984fa68dc30dcfc316b48cbafd9f0e6d33` | `817a23e169968e409c7c2c1b6f5591291f5e85d3446a22fcc6f187fdc057a9b7` |
| 62 | `src/runtime/obj.rs:OBJ_create:FAILURE_ATOMIC` | `458318445606018644dd3e363adf5b50c3335e67b3061decc6b89f7e4ddca659` | `7b1dd330c8a07cc62dd1d3801178c37028a2729e1c2f2cf11152a30de6e82975` |
| 63 | `src/runtime/obj.rs:OBJ_get0_data:FAILURE_ATOMIC` | `118126501faaeab96712cbcae1756afe3b21113bba72201589bda12292673438` | `d5458541659aa0056c646d7997de7c90dc9d3ed0b1612d39ebee0f69ac394a6e` |
| 64 | `src/runtime/obj.rs:OBJ_length:FAILURE_ATOMIC` | `cbc9450eb27d0a002be0476cf637d8a4c1a7fa2dc64d6047ab73abf65347f553` | `540ba1b43b8d086000515912b1d01ae6bb766f2b170e2db77388911202c2da60` |
| 65 | `src/runtime/obj.rs:OBJ_nid2ln:FAILURE_ATOMIC` | `c2dc0cc01f6de6f537c87881fcb2be8c3ee65497474c032a8c13eff47369bc1e` | `f19a4c64bc0e05ec9a105f6e8302ccf4947277d53a563f85bd8e610852bab68d` |
| 66 | `src/runtime/obj.rs:OBJ_nid2obj:FAILURE_ATOMIC` | `20d2d5509a4af849312ebdf8874645ed11c2b7933197f73e6d8e3505fabc45fe` | `2539c31fe8abf65e4c709cd2bf3b1a8039b5dfe4ee4b0a649e882e6026b642ac` |
| 67 | `src/runtime/obj.rs:OBJ_nid2sn:FAILURE_ATOMIC` | `d280e157b86e1b238467458ca9ca9b634072bbab4398aa3386627699c94f3aa2` | `b5ba54ce362a5fad36d60aa7fef9505e7b8ca949e54a2bd6936a9f3f723fdcbc` |
| 68 | `src/runtime/obj.rs:OBJ_sigid_free:FAILURE_ATOMIC` | `d1fcadc36cc1960510e2e375462a0a8f08d12906c66801df36549de64a4e41db` | `acde4b0a85623eda0de08a83c57daa1535aea06defd8d72309e20c18fa95033e` |
| 69 | `src/runtime/obj.rs:OBJ_txt2nid:FAILURE_ATOMIC` | `5b24fedb8c8887fb66e0f290e21392c3dfaa9052e7055d2061a53d2ac4398395` | `24e152b8724ab547ebd05884a002ce29e4f33f89a307b6acf6734925d8b64a95` |
| 70 | `src/runtime/obj.rs:OBJ_txt2obj:FAILURE_ATOMIC` | `dece5358a9c390c0cf7c45b9fa673ce26f3c2e5878977c36c371985a237ab3b2` | `6b53f5abb648639dee895d147dc39636b02d0d95c0bd6eb26c9fe96331d7a9ca` |
| 71 | `src/runtime/stack.rs:OPENSSL_sk_deep_copy:ROLLBACK` | `4cc8ece7d5c505621c27b529a0d284e4a5e13a635b1913b0ff8ddf6a7d6983f0` | `905f794555cd3886010628aa8e566ad17b36c8f0a969f0a785b0e276bbfde35e` |
| 72 | `src/runtime/stack.rs:OPENSSL_sk_free:FAILURE_ATOMIC` | `3d13fa7a667f61e6c976e5393341324a11f413a35c460fa2efcfcc11f46ab119` | `6062376eb145b007affc7fb871841731c6f91108623207fe5f8c7105963aac64` |
| 73 | `src/runtime/stack.rs:OPENSSL_sk_insert:FAILURE_ATOMIC` | `aa30dc0744c53ed8434b8c06f2463ba715612f7d88065d31a18e32676afd4e49` | `656567864cf0d6fdd7a74cc56590d7e6713a757456489529fb22cfb5a04724fe` |
| 74 | `src/runtime/stack.rs:OPENSSL_sk_new_reserve:FAILURE_ATOMIC` | `caf85932ec65d9cad50396a04b680a04271ac4ba02035d6563ed67ff4cd0d84d` | `c836f832074edf683f1ab778ca1a6ce864c29b1e777447a93497d0c52fce68cc` |
| 75 | `src/runtime/stack.rs:OPENSSL_sk_pop_free:ROLLBACK` | `59578bdaf635a52bb60d083e1e1ba7e645ff751a138ae9d3a2b78c5244c3f746` | `17b474d75583ba4293b8a2110ee45d2de06fc545459a775af691d92132d8183f` |
| 76 | `src/runtime/stack.rs:OPENSSL_sk_reserve:FAILURE_ATOMIC` | `f8b66779039e71f3bb61f1854bfd05b28eb1aec1ef2416a70cef4d17faf8a7e5` | `b40effe30272f80eb464e5cd61f9a478e591c1b47269d1f09a2e893f1d66d5a7` |
| 77 | `src/runtime/stack.rs:OPENSSL_sk_set:FAILURE_ATOMIC` | `064e1921e35bc93ca4abbb0fdad8efdf6457cb7a5b2f47b7865247a96ab1a551` | `f77cf25275ec5c1ef4e41f4fbb22ab14967bcce74380873e09e85a71b8eb3b9b` |
| 78 | `src/runtime/stack.rs:OPENSSL_sk_zero:FAILURE_ATOMIC` | `37d4c48cd367406e197b5e7def6d5fa5b983527b327d1ccbc52afefb03e77b1f` | `6d8e5484e501fa5dfa91e9ed75970e110ac944f4a4f2dc9fd85c14942dd2e492` |

### 12.6 Preservation

Sections 1-11 above are unchanged. The superseded exact identities and the binding
that produced them are preserved in section 12.5 so the record shows what was
believed and what was measured. No `src/`, `docker/` or `AGENTS.md` file was
touched, and no A3 model file was changed.
