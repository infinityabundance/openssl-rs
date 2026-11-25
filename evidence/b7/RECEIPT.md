# B7 receipt — the invariants in a small model, and the gap beside the result

## 1. Identity of this batch

| field | value |
|---|---|
| item | B7 (`docs/ETP-ADDENDUM-B.md` §B.23, §B.30): verify the transparency-policy invariants in a small model; qualify the verification tools and preserve their assumptions |
| status | **`PARTIAL`** — eight of §B.23's twelve clauses are checked in a finite model with an exhaustive enumeration, eight canaries and a 219-sequence differential; five clauses are `NOT_MODELLED` with reasons, and §B.23's crash-recovery/retry/partial-write/concurrency requirement is not met |
| branch | `staging` |
| HEAD at the start | `554acc9d0` (`b6: withdrawal is not erasure, and replay is not current`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 39 5 0 1 6` (available **6** GiB); `Swap: 45 45 0` |
| `free -g` before the whole-suite gate | `Mem: 45 41 4 0 0 4` (available **4** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, `HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944` (6 GiB), repository bind-mounted at `/work`; **reused, not restarted** |
| interpreter | CPython 3.11.2 in the court |
| heavy commands | one at a time; no Rust build |

Available memory was below the 24 GiB floor `AGENTS.md` §6.1 sets before a build.
No build was needed or attempted: every gate is Python. The derived cap
`min(8g, available − 16g)` is negative, below the 2 GiB floor, so **no new court
was started**; the existing 6 GiB court was reused and every command ran inside
it. `docker/` was not modified and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/transparency_model.py` | 2,362 | the model (state, fourteen-operation alphabet, step function, checker), the exhaustive enumeration, the eight canaries, the differential driver, the refinement builder, nine stable refusal codes plus `BM_OK`, and the `model`/`enumerate`/`differential`/`refinement`/`controls` CLI |
| `forensics/tools/tests/test_transparency_model.py` | 631 | 57 controls: one per refusal code, the bound, the canary, each invariant's individual violation replayed, the `NOT_RUN` labelling, determinism, CLI exit codes, document synchronisation |
| `docs/TRANSPARENCY-FORMAL-ASSURANCE.md` | 452 | the normative document: the problem, the model and alphabet, the bound, each invariant with clause/operations/assumption, the differential and its `NOT_RUN`, the refinement gap, the canary, the refusal table, non-claims, `NOT_RUN` |
| `evidence/b7/build_evidence.py` | 186 | the deterministic producer of the five records; `--out` for two-run comparison, `--check` against the committed bytes |
| `evidence/b7/MODEL.json` | 332 | the state fields, fourteen operations, bound 5, eight invariants with verbatim §B.23 clauses, twelve clause rows (seven modelled, five `NOT_MODELLED`), six assumptions, the canary map, and a canonical digest |
| `evidence/b7/ENUMERATION.json` | 326 | 579,195 sequences, 1,871 states, 555 expanded, 7,770 transitions, depth 5, 0 violations, per-invariant results and eight canaries with replayable witnesses |
| `evidence/b7/DIFFERENTIAL.json` | 10,305 | 219 sequences, 219 compared, 219 agreed, 0 disagreements, 0 `NOT_RUN`, every row's accept vector and resulting state for both sides |
| `evidence/b7/REFINEMENT.json` | 269 | eight `MODEL_AND_MATCHED` statuses, five `NOT_MODELLED` clauses, six gaps with sources, six `NOT_RUN` items, four limits |
| `evidence/b7/CONTROLS.json` | 89 | ten `controlOnly` rows, one per refusal code plus a positive, each with its observed code |
| `docs/ETP-TODO.md` | 1 row | the B7 row changed from `TODO` to `PARTIAL` at base `554acc9d0`; no other row touched |
| `evidence/b7/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `MODEL.json` | `a1cbbc4754a2d693af6b18b000578243aa06519b0d899b59ab49c613bc3bf0fc` |
| `ENUMERATION.json` | `5cf7ae5f57c6bf9dfcf842ed8ccf922f432c16773a912953c1507938a8b91b06` |
| `DIFFERENTIAL.json` | `a195838c23889958cc4fe147e832b7f66e4d3f4b83fc382e35ae1670e91b3c1f` |
| `REFINEMENT.json` | `b14efed9b6201705839da3f700619e42108d4bb84ab3cd18400bd1bd534df12d` |
| `CONTROLS.json` | `c8f20d401b0de77e0d669a4e81087e639415f27eca669521cd53858c09699df3` |

`MODEL.json`'s own canonical digest is
`b53474c708c9c589daadcc998ef3c4ec81514f718b1035164d1880d9a940cc24`; the
producer recomputes it and refuses a mismatch.

## 3. The model, the enumeration and the differential

### 3.1 The model

The state is `(origin, leaves, issued, accepted, version, versionFloor, verdict,
correctedAt, lastUseVersion, published, witnessLabels, witnessDomains, quorum)`.
A leaf is its bytes; `accepted` records each checkpoint with the leaf sequence it
commits, which is the model's stand-in for the tiles a verifier would read. The
step function is total and **failure-atomic**: a refused operation returns the
same state. The alphabet is fourteen operations: append either of two leaf kinds,
issue a checkpoint, observe head/stale/split/unsigned/foreign, correct a subject,
use the claim, publish a public or private member, and admit a distinct witness
domain or an alias of one.

The model does not import the implementation. `root_of`, the step function and
the checker are implemented from the model text; the real modules are imported
inside the driver constructor. `test_the_model_does_not_import_an_implementation`
checks the functions' globals and `test_the_model_source_has_no_top_level_import`
parses the module's AST.

### 3.2 The eight invariants

| id | clause (§B.23, verbatim) | operations | assumption | result |
|---|---|---|---|---|
| `BM-I1` | an unauthenticated checkpoint cannot authorise an accepted tree root; | issue, observe×5 | signatures unforgeable over the exact bytes | 0 violations; differential matched |
| `BM-I2` | a smaller checkpoint cannot silently roll back accepted state; | observe head/stale/split | size is the committed leaf length | 0; matched |
| `BM-I3` | equal-size conflicting authenticated roots produce an incident; | observe head/stale/split | origins atomic; one producer | 0; matched |
| `BM-I4` | a false inclusion proof cannot satisfy inclusion verification; | append×2, issue, observe×3, use | leaf bytes atomic; RFC 6962 in the model | 0; matched |
| `BM-I5` | a revoked claim cannot satisfy a sufficiently fresh current-state policy; | correct, use, issue, observe head | a correction is a new version | 0; matched |
| `BM-I6` | duplicate witness credentials cannot satisfy independence thresholds; | witness distinct/alias | a domain is its establishment record | 0; matched |
| `BM-I7` | a smaller checkpoint cannot silently roll back accepted state; (B6 version) | correct, use | the version is the covered-event count | 0; matched |
| `BM-I8` | a publication failure cannot masquerade as transparent acceptance. | publish public/private | the B4 policy; a class is atomic | 0; matched |

The five clauses the model does not express — unrelated DSSE entry, unrelated
shard, omitted campaign activity, missing timestamp, unavailable evidence — are
recorded as `NOT_MODELLED` with a reason, not dropped. `MODEL.json` records all
twelve bullets verbatim as clause rows; seven are modelled (the rollback bullet
grounds both `BM-I2` and `BM-I7`) and five are not.

### 3.3 The bound and the counts

The bound is **5 operations** over **14**, so the sequence space is
`14^0 + … + 14^5 = 579,195`. The enumeration explores the **reachable state
graph**: 1,871 states, 555 expanded, 7,770 transitions, maximum depth 5, **0
violations**. Because the state is complete and the step deterministic, every
sequence up to the bound maps to a path in the explored graph, so no sequence's
outcome is missed. The record reports the sequence space and the executed edges
separately so neither is mistaken for the other.

### 3.4 The differential and its `NOT_RUN`

The default set is every length-1 and length-2 sequence over the fourteen
operations (14 + 196 = 210) plus nine curated sequences: one per invariant and
one growth sequence over an accepted head (9) = **219**. All 219 agree on the
accept/reject vector and the resulting state: accepted
sizes, roots, version, verdict, published set, witness quorum and last-use
version. The driver uses `tlog` and `monitor` for append/issue/observe,
`corrections` for correct/use, `publication` for publish and `thresholds` for the
witness count.

**0 sequences are `NOT_RUN`.** No modelled operation needs a service: the driver
builds a local fixture log, a local checkpoint store, a local correction log and
a local classification query. The labelling mechanism is exercised rather than
assumed: `differential(..., force_not_run={0: reason})` records a labelled
`NOT_RUN` row excluded from `compared` (control `not-run-labelled`), and a
matched status with no executed sequence is refused with
`BM_REFUSED_NOT_RUN_AS_VERIFIED` (control `not-run-counted`). The
service-dependent claims the model does not express are in §8.

### 3.5 The canary

Eight deliberately broken models, one per invariant, each caught by the same
checker, each with a replayable sequence:

| broken model | target | first witness | violations |
|---|---|---|---:|
| `unsigned-accepted` | `BM-I1` | `["issue_checkpoint","observe_unsigned"]` | 571 |
| `rollback-accepted` | `BM-I2` | `["issue_checkpoint","append_claim","issue_checkpoint","observe_head","observe_stale"]` | 4 |
| `split-accepted` | `BM-I3` | `["issue_checkpoint","observe_head","observe_split"]` | 452 |
| `root-ignored` | `BM-I4` | `["issue_checkpoint","observe_head"]` | 953 |
| `withdrawn-current` | `BM-I5` | `["correct_subject","use_claim"]` | 123 |
| `witness-labels` | `BM-I6` | `["witness_distinct","witness_alias"]` | 193 |
| `version-decrease` | `BM-I7` | `["correct_subject"]` | 678 |
| `publish-private` | `BM-I8` | `["publish_private"]` | 1,349 |

The test `test_each_invariant_is_individually_violated_and_caught` replays each
witness through the broken step and re-checks the state, so the canary is not
just a recorded flag.

## 4. Controls

`evidence/b7/CONTROLS.json`: **10 `controlOnly` rows, 10 fired** — one per stable
refusal code plus a positive row for the `NOT_RUN` labelling.

| control | wrong behaviour | code observed |
|---|---|---|
| `rollback-accepted-invariant-violated` | a broken model reaches a violation | `BM_REFUSED_INVARIANT_VIOLATED` |
| `alphabet-short` | the alphabet drops `witness_alias` | `BM_REFUSED_MODEL_INCOMPLETE` |
| `fabricated-clause` | `BM-I1`'s clause is not a §B.23 sentence | `BM_REFUSED_INVARIANT_UNSOURCED` |
| `limit-below-bound` | a limit of 4 for bound 5 | `BM_REFUSED_ENUMERATION_TRUNCATED` |
| `canary-not-detected` | every canary row rewritten to false | `BM_REFUSED_CANARY_NOT_DETECTED` |
| `gap-without-source` | `BM-G1`'s source is erased | `BM_REFUSED_REFINEMENT_UNSTATED` |
| `driver-differs` | an implementation accept vector is inverted | `BM_REFUSED_DIFFERENTIAL_DISAGREEMENT` |
| `not-run-counted` | matched statuses against a forced-`NOT_RUN` differential | `BM_REFUSED_NOT_RUN_AS_VERIFIED` |
| `not-run-labelled` | a positive: the forced row carries its reason and is excluded | `BM_OK` |
| `bound-above-maximum` | a bound of 9 against a maximum of 8 | `BM_REFUSED_USAGE` |

Every control mutates an in-memory record; none mutates a tracked file.

## 5. Defects found

### 5.1 The refinement record's source was erased by a control (repaired here)

`build_refinement` copied `REFINEMENT_GAPS` with `list(...)`, a shallow copy, so
the control `gap-without-source` mutated the **module-global** gap dictionary.
The producer writes the refinement before it runs the controls, but the written
record shares those dictionaries, so `REFINEMENT.json` recorded
`"source": ""` for `BM-G1` while the earlier validation had passed. Old:
`list(REFINEMENT_GAPS)` and a shared dict. New: `[dict(gap) for gap in
REFINEMENT_GAPS]`, a per-record copy. The record was rebuilt and the test
`test_the_producer_is_byte_identical_and_reproduces_the_records` now guards it.
This is a defect in this item's own machinery and is preserved rather than
quietly fixed.

### 5.2 The canary witness was one operation, not a sequence (repaired here)

The first enumeration recorded `sequence: [operation]` for a violation, which is
not a replayable witness: the state that triggers the violation may need four
prior operations. Old: the last operation only. New: the breadth-first search
tracks a representative path per state and records the **whole** sequence; the
test replays it.

### 5.3 The `not-run-counted` control was vacuous at first (repaired here)

The first version built the refinement *from* the forced differential, so the
statuses became `MODEL_ONLY` and the matched-status branch never ran; the control
observed no refusal. Old: refinement from the forced differential. New: the
refinement is built from the unforced differential and validated against the
forced one, so a matched status with no executed sequence is refused.

### 5.4 The transition count assumed the whole frontier is expanded (repaired here)

The first test asserted `transitions == states × 14`. The depth-5 frontier is
reached but not expanded, so the count is `statesExpanded × 14`. Old: an
over-large expected value; the record now carries `statesExpanded` (555) and the
test binds to it. The state and transition counts did not change.

### 5.5 The last §B.23 bullet ends with a full stop (caught by the tool)

`BM-I8`'s clause was first copied with a semicolon because the other eleven
bullets end that way. `validate_model` refused the producer's first run with
`BM_REFUSED_INVARIANT_UNSOURCED`. The clause was corrected to the verbatim text;
the authority was not edited and the check was not relaxed.

### 5.6 No defect in another item's records was found

`docs_consistency.py` exits 0 with 20 hand-written claims and the constitution
wired; `spec_guard.py check` reports 10 registered specifications, 5 recorded
known nonconformances, 0 unclassified and 0 unjustified exemptions; the whole
2,434-test tools discovery is `OK`. No other item's tool, record or evidence was
modified: the write scope was `docs/TRANSPARENCY-FORMAL-ASSURANCE.md`,
`docs/ETP-TODO.md`, `forensics/tools/transparency_model.py`,
`forensics/tools/tests/test_transparency_model.py` and `evidence/b7/`.

## 6. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before the work `Mem: 45 39 5 0 1 6` (available **6** GiB); before the suite `Mem: 45 41 4 0 0 4` (available **4** GiB); `Swap: 45 45 0` |
| 1. court and cap | `docker inspect openssl-rs-court` | `mem=6442450944 memswap=6442450944 status=running` (6 GiB), `/work` bind-mounted; reused, no new court, no build |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | final tree: `Ran 2434 tests in 488.540s`; `OK` (two earlier runs over the same code, before the last record regeneration, were `Ran 2434 tests in 491.006s` and `Ran 2434 tests in 490.717s`, both `OK`). The **2,377 pre-existing tests are present** (2,377 + 57 = 2,434), none removed, none skipped, none newly ignored |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on every created JSON | `MODEL.json ok`, `ENUMERATION.json ok`, `DIFFERENTIAL.json ok`, `REFINEMENT.json ok`, `CONTROLS.json ok` |
| 5. producer, twice | `python3 evidence/b7/build_evidence.py` twice, then `diff` of every produced file's SHA-256 | `BYTE-IDENTICAL-RUNS`; run 2: `code=BM_OK b7: bound=5 alphabet=14 sequences=579195 states=1871 violations=0 canaries=8 canariesDetected=true compared=219 agreed=219 notRun=0 matched=8/8 controls=10 codes=10` |
| 5. producer check | `python3 evidence/b7/build_evidence.py --check` | `code=BM_OK b7: check ok files=5 bound=5 states=1871`; `CHECK_EXIT=0` |
| 6. enumerate | `python3 forensics/tools/transparency_model.py enumerate` | `code=BM_OK bound=5 sequences=579195 states=1871 transitions=7770 violations=0 canaries=8 allDetected=true`; `ENUM_EXIT=0`; each `bm: invariant BM-I1..BM-I8 checked=1871 violations=0` |
| 6. differential | `python3 forensics/tools/transparency_model.py differential` | `code=BM_OK sequences=219 compared=219 agreed=219 disagreements=0 notRun=0`; `DIFF_EXIT=0` |
| 6. controls | `python3 forensics/tools/transparency_model.py controls` | `code=BM_OK controls=10 codes=10`; every `bm: control … observed=…` matches its expected code |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/TRANSPARENCY-FORMAL-ASSURANCE.md`; `?? evidence/b7/`; `?? forensics/tools/tests/test_transparency_model.py`; `?? forensics/tools/transparency_model.py` — nothing else |

The full discovery ran on the final code, document and record tree. Only the
prose of this receipt was written afterwards; no test reads it. B7's 57 controls
pass.

## 7. Obligations retained

* **Five §B.23 clauses are not modelled.** DSSE entry binding, shard
  consistency, campaign omission, timestamp evidence and reconstruction
  requirements are `NOT_MODELLED` with reasons; the item does not claim them.
* **§B.23's crash-recovery requirement is not met.** Crash recovery, persistent
  witness state, retries, partial writes, concurrent publication and shard
  transitions are not modelled. `BM-G4` records this as a gap, not a success.
* **A model theorem is not a proof about the binary or the service.** No TLA+,
  Coq, Lean or Kani proof, and no refinement edge to the compiled code (Article
  7). The checker is a Python predicate over a finite state.
* **The enumeration is finite and sequence-bounded.** Five operations over
  fourteen; a reachable state graph, not every sequence executed.
* **The model, the checker and the driver share an author.** Agreement is a
  shared reading, not independent verification (Article 5); no external party
  ran either side.
* **The differential is local.** Fixture logs and local modules; the observation
  instants are records, not trusted time; the checkpoint signature is a
  test-only HMAC-SHA256 key.
* **The first split view is not detected.** A monitor seeing only a forked head
  first has nothing to compare with; the model represents that acceptance and
  refuses the later conflicting head. This is a property of the monitor, stated
  in the document, not a claim of equivocation detection.
* **The nine refusal codes are exercised by controls, not by a real adversarial
  service.** A refusal that fires proves the check works.

## 8. `NOT_RUN`

* An admitted public transparency log, its key, client and inclusion (B0/B1
  record a fixture; no service exists here).
* A witness cosignature admitted from an independent operator (B5 records 0
  witnesses).
* A trusted RFC 3161 timestamp (B2 records no authority in this venue).
* Crash recovery, retries, partial writes and concurrent publication.
* A machine-checked proof (TLA+, Coq, Lean, Kani) and a source-to-binary
  refinement edge.
* An independent reviewer or a distinct trust domain.
* `BOUNDARY`, `SEAL` and the Rust suite: no Rust source was modified, so no
  `cargo` command ran.

## 9. Forward-freeze member and worktree

The A17 forward-freeze member `b7-receipt` (`evidence/b7/RECEIPT.md`, predicate
"a receipt records the model, assumptions and refinement gap") is **satisfied**:
this receipt and the five records name the state and alphabet, the bound, the
eight invariants with their sources and assumptions, the enumeration counts, the
canaries, the differential and its `NOT_RUN`, and the six refinement gaps with
their documents. The freeze itself was not closed, and A20's
`A17.forward-freeze-closed` obligation is unaffected.

Worktree after this batch: `M docs/ETP-TODO.md`;
`?? docs/TRANSPARENCY-FORMAL-ASSURANCE.md`; `?? evidence/b7/`;
`?? forensics/tools/tests/test_transparency_model.py`;
`?? forensics/tools/transparency_model.py`. Nothing else. This subagent did not
commit and did not push.

**Why `PARTIAL`:** eight of the twelve clauses are checked, but five are not
modelled; §B.23's crash-recovery/retry/partial-write/concurrency requirement is
not met; the enumeration is finite; there is no machine-checked theorem or
refinement edge; the differential uses local fixtures and a test-only key; and no
independent review exists.
