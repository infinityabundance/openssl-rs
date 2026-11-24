# A9 receipt — in-toto Statement v1 attestations

## 1. Identity of this batch

| field | value |
|---|---|
| item | A9 (in-toto Statement v1 typed attestations; SLSA provenance predicate only for genuine SLSA statements; versioned project predicate types for everything else) |
| branch | `staging` |
| HEAD at the start | `f1c5047a5` (`a7: bind the measured inputs, not the commit that carries the record`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 20 19 0 5 24` (total 45, used 20, free 19, available **24** GiB); `Swap: 45 26 18` |
| derived court cap | `min(8g, 24 − 16) = 8g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/` or another item's tool/evidence modified |

The derived cap was 8 GiB and the running container's cap is 6 GiB, below it.
The container was reused rather than restarted, exactly as A7 and A8 did: one
court already holds the memory budget, and restarting it would not lower the cap.
Every gate is Python-only. `free -g` after the work read
`Mem: 45 22 18 0 5 23` (available 23 GiB).

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/INTOTO-STATEMENTS.md` | 343 lines | normative document: the problem; the three mandatory parts; the subject rule; the five-type predicate registry; the no-upgrade rule with each refused upgrade named; all 12 refusal codes and the wrong conclusion each prevents; the four real statements; the seven records that cannot be attested; the 17 controls; the A10 boundary; non-claims; `NOT_RUN`; reproduction |
| `forensics/tools/intoto.py` | 1,911 lines | the statement model: subject recomputation, the registry, the predicate builders for A5/A6/A7/instruments/SARIF, `encode`/`decode` with the canonical-form check, `verify_statement`, the 12 codes, the 17 controls and the `emit`/`verify`/`subjects` command line |
| `forensics/tools/tests/test_intoto.py` | 745 lines | 59 controls: the subject rule, the registry, each no-upgrade individually, canonical round trip, one-byte mutation, verification recomputation, the real statements and index, producer determinism and committed-bytes match, the absent-record refusal, CLI exit codes with printed codes, and document synchronisation |
| `evidence/a9/build_evidence.py` | 437 lines | deterministic producer of the four statements, the index and the controls; reads every digest and value from the record and stops on an absent record |
| `evidence/a9/STATEMENTS/a1-sarif.json` | 549 bytes | the A1 SARIF statement (`d53bc4eb…`) |
| `evidence/a9/STATEMENTS/a5-admission.json` | 528 bytes | the A5 admission statement (`d17bb4c9…`) |
| `evidence/a9/STATEMENTS/a7-delta.json` | 672 bytes | the A7 delta statement (`d4dfa5a3…`) |
| `evidence/a9/STATEMENTS/a8-shard-000.json` | 714 bytes | the A8 shard statement (`ea67963a…`) |
| `evidence/a9/STATEMENTS.json` | 7,345 bytes | the index: subject, digest, predicate type, record, asserted state vs record state, the seven refusals, and the audited source inputs (`4ef85aae…`) |
| `evidence/a9/CONTROLS.json` | 11,585 bytes | 17 controls over the 12 codes, the registry and the code table (`5886e4dd…`) |
| `evidence/a9/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A9 row only; no other row was touched. No
existing record was edited, because no existing record was defective (§6). No
`src/`, `docker/`, `AGENTS.md` or another item's tool or evidence was modified.

## 3. The rule

> A statement must not be able to assert more than the records behind it admit,
> and must not name an artefact it has not hashed.

The subject digest is a content digest of the exact bytes, computed by reading
them and recomputed at verification; a caller-supplied digest, a Git object id,
a short token and a non-hex value are refused. The predicate is built from the
record's own admitted values and re-checked against a fresh reading of that
record. A stronger admission state, a resolution the delta does not record, a
member census over an aggregate, a verified instrument that is only `RECORDED`,
an expiry-free suppression and an evidence identity with no digest are each
refused with a stable code.

The commit token in `STATEMENTS.json` is an audit of when the inputs were
measured, never a subject digest. This is the `evidence/a7/RECEIPT.md` §11
two-identity contract applied to the envelope: the digest names the bytes, not
the commit that carries them.

## 4. The real statements

All four subject digests were recomputed from the bytes at build time, and each
predicate was verified against a fresh reading of its record before the statement
was written.

| statement | subject | subject SHA-256 | predicate type | source record | asserted = record |
|---|---|---|---|---|---|
| `STATEMENTS/a1-sarif.json` | `evidence/a1/SARIF.json` | `5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852` | `.../sarif-emission/v1` | the SARIF log itself | 6 runs, 4,245 results, `subset: false` |
| `STATEMENTS/a5-admission.json` | `evidence/a5/ADMISSION.json` | `d4871ec97ae3a27b8ec820896e292429e44b4db4d11d2671a69b9dc0230ddc0a` | `.../population/v1` | `evidence/a5/ADMISSION.json#/populations/a1-sarif-results` | `COMPLETE`, 4,245 examined, 0 omitted, `membersRecorded: true` |
| `STATEMENTS/a7-delta.json` | `evidence/a7/DELTA.json` | `0444a879bf4a0ddf5c50cffba7f51a5834b0fc4a1702d5190815de1f4470c8cf` | `.../baseline-delta/v1` | `evidence/a7/DELTA.json#/deltas/a3-fingerprint-migration` | 4,245 records, 4,245 `STILL_PRESENT`, **0 `RESOLVED`**, admitted, no codes |
| `STATEMENTS/a8-shard-000.json` | `evidence/a8/SHARD-000.sarif` | `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed` | `.../sarif-emission/v1` | the shard itself | 6 runs, 4,245 results, `subset: true`, `parentResultCount: 4245`, shard 0 of 1 |

What the statements do **not** assert: finding truth, severity, reachability or
currency; a census of the tree; that a delta is a fix; that one shard is the
export; that a `COMPLETE` population is the whole code base. The A7 statement
exists precisely because the delta is admitted with **zero** resolutions — the
statement says 0, not "clean".

### 4.1 The records that cannot be attested

Seven attempts are made by the producer on the real records; each code is read
from the tool and recorded in `STATEMENTS.json#/notAttested`.

| record | selection | attempted | code |
|---|---|---|---|
| `evidence/a5/ADMISSION.json` | `t4-suppressions` | a census over an aggregate whose declaration is refused (`CA_REFUSED_OMITTED_UNRECORDED`) | `IT_REFUSED_RECORD_INADMISSIBLE` |
| `evidence/a5/ADMISSION.json` | `t11-satisfied-runs` | a census over an aggregate whose declaration is refused (`CA_REFUSED_MEMBER_UNIDENTIFIED`) | `IT_REFUSED_RECORD_INADMISSIBLE` |
| `evidence/a5/ADMISSION.json` | `o11-interop-scripts` | a completeness claim over the HAZ-15 population admitted `UNKNOWN` | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/a5/ADMISSION.json` | `curl-residual-sites` | `COMPLETE` over a `TRUNCATED_BOUNDED` population (200 examined, 249 omitted) | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/a7/DELTA.json` | `a3-fingerprint-migration` | one `RESOLVED` over a delta with zero | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/etp3/instruments.json` | `timecop-supercop` | a verified claim over a `RECORDED`-only control | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/a6/SUPPRESSIONS.json` | `t4-suppressions` | an `ACTIVE` suppression with no expiry (the record is `NON_ACTIONABLE`) | `IT_REFUSED_CLAIM_UPGRADE` |

That is the honest result: an aggregate cannot support a member census, HAZ-15 is
`UNKNOWN`, the curl population is bounded at 200 of 449, the delta has no
resolution, a `RECORDED` control is not a verification, and no suppression in the
tree is active.

## 5. Controls and measured figures

`evidence/a9/CONTROLS.json` records 17 controls over the 12 codes: one per code
and one per distinct upgrade. Each mutates a real record's values in memory and
asserts its named code fires.

| control | code |
|---|---|
| `missing-subject` | `IT_REFUSED_MISSING_SUBJECT` |
| `absent-file` | `IT_REFUSED_SUBJECT_ABSENT` |
| `git-object-id` | `IT_REFUSED_SUBJECT_DIGEST_FORM` |
| `digest-mismatch` | `IT_REFUSED_SUBJECT_DIGEST_MISMATCH` |
| `duplicate-subject` | `IT_REFUSED_DUPLICATE_SUBJECT` |
| `wrong-type` | `IT_REFUSED_TYPE` |
| `unknown-predicate-type` | `IT_REFUSED_PREDICATE_TYPE` |
| `missing-predicate-field` | `IT_REFUSED_PREDICATE_FIELD` |
| `complete-over-truncated` | `IT_REFUSED_CLAIM_UPGRADE` |
| `resolved-over-none` | `IT_REFUSED_CLAIM_UPGRADE` |
| `census-over-aggregate` | `IT_REFUSED_CLAIM_UPGRADE` |
| `verified-over-recorded` | `IT_REFUSED_CLAIM_UPGRADE` |
| `expiry-free-suppression` | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence-without-digest` | `IT_REFUSED_CLAIM_UPGRADE` |
| `absent-record` | `IT_REFUSED_RECORD_ABSENT` |
| `inadmissible-record` | `IT_REFUSED_RECORD_INADMISSIBLE` |
| `mutated-statement` | `IT_REFUSED_STATEMENT_MUTATED` |

| quantity | measured |
|---|---|
| statements / subjects | 4 / 4 |
| predicate types registered / used | 5 / 3 |
| refusal codes | 12 |
| controls | 17 (one per code, one per distinct upgrade) |
| records that cannot be attested | 7 |
| codes that fired on real records | 2, in the producer's seven refused attempts: `IT_REFUSED_CLAIM_UPGRADE` (5) and `IT_REFUSED_RECORD_INADMISSIBLE` (2) |
| `IT_REFUSED_RECORD_ABSENT` on a real record | none; it fires in the producer's absent-record test with a temporary repo root |
| A5 populations re-derived | 16, 0 disagreements with `ADMISSION.json` |
| A7 `RESOLVED` in the attested delta | 0 |
| A8 shard | 1 of 1, `subset: true`, parent 4,245 |
| A6 actionable suppressions | 0 of 8 |
| new `unittest` controls | 59 |

`IT_REFUSED_RECORD_ABSENT`, `IT_REFUSED_TYPE`, `IT_REFUSED_MISSING_SUBJECT`,
`IT_REFUSED_SUBJECT_ABSENT`, `IT_REFUSED_SUBJECT_DIGEST_FORM`,
`IT_REFUSED_SUBJECT_DIGEST_MISMATCH`, `IT_REFUSED_DUPLICATE_SUBJECT`,
`IT_REFUSED_PREDICATE_TYPE`, `IT_REFUSED_PREDICATE_FIELD` and
`IT_REFUSED_STATEMENT_MUTATED` did not fire on a real record; the absent-record
code fires only in the producer's absent-record test. Each is exercised by its
control. That is a negative result, not a pass.

## 6. Defects found in existing records

**No defect was found in an existing record, and no existing record was edited.**
The checks that would have found one were run:

* **A5.** All 16 populations were re-derived with `completeness.build_populations`
  and `admit`; every recorded `(state, refusal)` pair matched (0 mismatches). The
  five refused declarations are refused in the record itself, not hidden.
* **A7.** The attested delta's counts sum to 4,245, its `admitted` flag is true
  and its code list is empty; the refused `claims-reconciliation` delta is
  `admitted: false` with three codes. Both are consistent, so `IT_REFUSED_RECORD_INADMISSIBLE`
  would not have been a way to avoid their content.
* **A8.** The shard's own `properties.shard` states 4,245 results and its six runs
  hold 4,245 results; `parentResultCount` is 4,245. The property agrees with the
  log.
* **A6.** `totals.actionable` is 0 and all 8 suppressions are `NON_ACTIONABLE`;
  the per-record admissions carry the matching refusal codes. The absence of an
  active suppression is consistent with the record.
* **Instruments.** `timecop-supercop` and `tsc-smi-fallbacks` are `RECORDED`;
  the other nine controls are `PASS`. The statuses are internally consistent.

Two negative results are recorded rather than repaired, because there is nothing
to repair: **all four A7 deltas have `RESOLVED = 0`**, and **A6 has zero active
suppressions**. A statement that said otherwise would be refused (§4.1).

History is preserved in the ordinary sense: no record was rewritten, so no old
and new value exists to report. The one tracked file modified is
`docs/ETP-TODO.md`, whose A9 row was replaced as the item requires; no other row
was touched.

## 7. Gates actually run

All commands ran inside the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 20 19 0 5 24` (available 24 GiB); `Swap: 45 26 18` |
| new controls | `python3 -m unittest forensics.tools.tests.test_intoto` | `Ran 59 tests in 18.750s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1003 tests in 206.195s`; `OK` (**944 before + 59 new = 1003, 0 failures, 0 errors**; no test removed, none newly ignored or skipped). After the documentation-only edit that added the `POPULATIONS.json` limitation, the 7 document-synchronisation tests re-ran: `Ran 7 tests in 1.408s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `STATEMENTS.json`, `CONTROLS.json` and the four statements | exit 0 each |
| producer, two runs | `python3 evidence/a9/build_evidence.py --out /tmp/a9a --source-commit f1c5047a5` and the same to `/tmp/a9b` | `statements=4 subjects=4 predicateTypes=3 notAttested=7 controls=17 codes=12 commit=f1c5047a5` |
| producer byte-identity | `cmp /tmp/a9a/<name> /tmp/a9b/<name>` and against `evidence/a9/<name>` | `byte-identical` for all six files |
| statement digest identity | `sha256sum /tmp/a9a/STATEMENTS/*.json` | `d53bc4eb66f71bab7227fb9e590d151287a1d64b4446f8dd84b94ca8fef26329`, `d17bb4c990893dc61ee06687a78b6c1b9a91b772e9dbefe233d1fa8b6c21e45f`, `d4dfa5a3b374ffc4382964dcac61e8a785cfe7f833cbe5c7731a210c0fe7fba8`, `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582` — identical to the committed bytes |
| statement verification | `python3 forensics/tools/intoto.py verify evidence/a9/STATEMENTS/*.json` | four times `verify: code=IT_OK …`; exit 0 each. The codes that fire on real records are the seven `notAttested` entries (§4.1): 2 × `IT_REFUSED_RECORD_INADMISSIBLE`, 5 × `IT_REFUSED_CLAIM_UPGRADE` |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/INTOTO-STATEMENTS.md`, `?? evidence/a9/`, `?? forensics/tools/intoto.py`, `?? forensics/tools/tests/test_intoto.py` |

**Reproducibility.** The producer reads every digest and predicate value from the
named record through `forensics/tools/intoto.py`; nothing is typed in
`build_evidence.py`. The source identity is supplied (`--source-commit`), and
when it is absent the default is the value `STATEMENTS.json` records, never a
live `HEAD`. The seven audit inputs are hashed in the index. Two runs are
byte-identical, and the committed files match a fresh build
(`test_the_producer_is_deterministic`,
`test_the_committed_files_match_a_fresh_build`,
`test_the_source_identity_is_supplied_not_read_live`).

## 8. Obligations retained

* **One population is attested, not sixteen.** The A5 statement reports
  `a1-sarif-results` at `COMPLETE`. The two refused aggregates, the `UNKNOWN`
  HAZ-15 population, the bounded curl population and the other admitted
  populations are not attested; the admission record remains their statement.
* **Instrument qualification is registered and controlled, not emitted.** The
  registry and all 17 controls exercise `.../instrument-qualification/v1`, but no
  real instrument statement is emitted. The two `RECORDED` controls cannot be
  called verified, and a statement of a `RECORDED` status alone would add an
  envelope without adding evidence.
* **One delta is attested.** `a3-fingerprint-migration` is admitted and states
  zero resolutions. The three refused deltas are not attested; their refusal is
  in `DELTA.json`.
* **The A8 statement is about the shard, not the export.** It records
  `subset: true` and the parent count; the union and the manifest remain A8's.
* **The A1 statement is about the log's shape.** It does not assert finding
  truth, severity, reachability or currency.
* **The A5 re-derivation depends on `POPULATIONS.json`.** The admission record is
  re-derived from the declaration and all 16 populations matched. If that
  declaration is absent, the recorded admission is trusted as-is; that fallback
  is stated in the document rather than hidden.
* **The input audit is direct reads.** `sourceIdentity.inputs` names the seven
  files this item reads. A5's transitive reads are the ones `POPULATIONS.json`
  names and are audited by A5, not duplicated here.
* **No active suppression exists to attest.** Every A6 suppression is
  `NON_ACTIONABLE`; the suppression predicate is exercised only by controls.
* **The standard-library parser.** `decode` refuses non-canonical bytes but does
  not implement A11's duplicate-key, encoding, size or algorithm-downgrade rules.
* **No independent reviewer.** The author of the tool, the document and the
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## 9. `NOT_RUN`

* **BOUNDARY.** No caller or dependency-closure audit of the record readers, no
  independent review of the predicate-to-record comparisons, and no negative
  control outside the tool's own 17 controls.
* **SEAL.** No full forensic regeneration, no downstream replay and no release
  candidate assurance.
* **DSSE and PAE.** A10's envelope and pre-authentication encoding; no envelope
  is built or parsed.
* **Signatures and trust.** A12 verification, A14 role authorisation, A15
  thresholds, A16 Sigstore and A17 transparency/omission resistance.
* **Parser hardening.** A11.
* **JSON-Schema validation** of the statement against the in-toto schema. The
  structural checks, `json.tool` and `verify_statement` ran instead.
* **A genuine SLSA statement.** None exists in the tree and none was fabricated.
* **A multi-subject statement on a real record.** The tool refuses duplicate
  names and accepts several subjects, but every real statement has one subject.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test`
  was run.

## 10. Non-claims

A statement is not a signature, not a proof, not a verification and not
admission. It is evidence that the named bytes hash to the subject and that the
named record admits the carried predicate. `COMPLETE` is complete over the
declared population, not over the tree; `subset: true` is a subset, not a census;
`admitted: true` on a delta is not a fix; `0 RESOLVED` is a result, not a clean
bill. `RECORDED` is not `PASS`, an aggregate is not a census, `UNKNOWN` is not a
pass, and an expiry-free suppression is not in force. The source commit in the
index is an audit, not a subject digest. No refusal code, admission state or
record was relaxed to make a statement possible.

## 11. Boundary with A10

This item emits the bare in-toto Statement v1 and nothing above it. The DSSE
envelope, the exact PAE over the received bytes and the `keyid` hint are A10's;
signature verification and the trust root are A12's; role, threshold, bundle and
transparency rules are A14–A17's. A bare statement is not a signed attestation,
and this item does not pre-empt A10: it emits no envelope, no PAE and no
signature, and it refuses a document whose `_type` is a DSSE envelope or an older
statement type (`IT_REFUSED_TYPE`, control `wrong-type`).
