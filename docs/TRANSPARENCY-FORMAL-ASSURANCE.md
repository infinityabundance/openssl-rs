# Transparency formal assurance — the invariants in a small model, and the gap

Status: normative for B7 of `docs/ETP-TODO.md`.
Authority: `docs/ETP-ADDENDUM-B.md` §B.23 (the invariants), §B.30 (B7).
Type: `openssl-rs/b7/model/1` (the model), `openssl-rs/b7/enumeration/1`,
`openssl-rs/b7/differential/1`, `openssl-rs/b7/refinement/1`,
`openssl-rs/b7/controls/1` (the records).
Implementation: `forensics/tools/transparency_model.py`.
Records: `evidence/b7/{MODEL,ENUMERATION,DIFFERENTIAL,REFINEMENT,CONTROLS}.json`,
produced by `evidence/b7/build_evidence.py`.
Tests: `forensics/tools/tests/test_transparency_model.py`.

This document defines the transparency-policy invariants as a finite model,
states the bound of the enumeration, records the abstraction each invariant
assumes, drives the same small sequences through the real modules, and states
exactly what the result does and does not establish. It is not a proof about the
binary, and it says so beside the result.

---

## 1. The problem

§B.23 states twelve transparency-policy invariants in prose. A sentence such as
"an unauthenticated checkpoint cannot authorise an accepted tree root" is a
requirement; it is not a checked property. Nothing about the sentence prevents
the implementation from accepting an unsigned checkpoint, and no amount of
reading the implementation can find that defect, because a rule read out of the
code inherits whatever the code does (Earned Trust Article 6).

Two weaker substitutes are tempting and both are refused here. Enumerating a
handful of examples is a smoke test, not a result: an agreement over the cases
the author thought of is exactly what a defect evades. Enumerating a *model* and
reporting "verified" is worse, because it invites the reader to hear "the
service is verified" (Article 7). §B.23 makes the requirement precise: the
abstract model must stay small and independently reviewable, and a verified
abstract state machine is **not** a verified implementation without a refinement
relationship.

This item therefore does the honest middle thing:

1. the twelve clauses are taken **verbatim** from §B.23 and recorded against an
   identifier; a clause not found in the authority is refused;
2. eight of them are expressed in a finite state with fourteen operations and a
   step function that either changes the state or refuses with the state
   unchanged;
3. a checker flags every invariant on every reachable state, and the reachable
   state graph is enumerated exhaustively to a declared sequence bound;
4. the same small sequences are driven through the real modules (`tlog`,
   `monitor`, `corrections`, `thresholds`, `publication`), comparing the
   accept/reject vector and the resulting state;
5. every result is written beside its bound, its assumptions and its `NOT_RUN`
   list, including the fact that the model and the implementation share an
   author.

The four clauses the model does not express are recorded as `NOT_MODELLED` with
a reason, not dropped: three of §B.23's twelve would need a service, a timestamp
authority or an archive, and one would need DSSE parsing, which the model
deliberately does not have.

## 2. The model and its alphabet

The state is finite and recorded in `evidence/b7/MODEL.json`:

```
(origin, leaves, issued, accepted, version, versionFloor, verdict,
 correctedAt, lastUseVersion, published, witnessLabels, witnessDomains, quorum)
```

`origin` is one atomic label. `leaves` is an append-only sequence of opaque leaf
strings; a leaf is its bytes. `issued` is the first and last checkpoint the log
signed. `accepted` is the sequence of accepted checkpoints, each with the leaf
sequence it commits to — the model's stand-in for the tiles an RFC 6962 verifier
would read. `version`/`versionFloor` are the current-state counters;
`verdict`/`correctedAt`/`lastUseVersion` are the subject's current state;
`published` is the set of published members; `witnessLabels`/`witnessDomains`/
`quorum` are the witness counts.

The initial state has one leaf (`claim-0`), version 1, the subject `ACTIVE`, no
issued or accepted checkpoint, nothing published and no witness. The leaf
`claim-0` is the subject under test; its position is used by `BM-I5`.

**The alphabet** is fourteen operations (`MODEL.json` records the same list):

| operation | effect |
|---|---|
| `append_claim` / `append_other` | append one of two leaf kinds; the log grows |
| `issue_checkpoint` | sign a checkpoint over the current leaves; record it as issued |
| `observe_head` | observe the latest issued checkpoint |
| `observe_stale` | observe the earliest issued checkpoint (a stale replay) |
| `observe_split` | observe an equivocating head at the same size with a forked committed leaf list |
| `observe_unsigned` | observe the latest issued checkpoint with no signature |
| `observe_foreign` | observe the latest checkpoint under a foreign origin |
| `correct_subject` | record a correction: the version advances and the subject is `CORRECTED` |
| `use_claim` | present the subject as a current claim |
| `publish_public` / `publish_private` | publish a classified-public or a private member |
| `witness_distinct` / `witness_alias` | admit a witness in a new domain, or a second label of an existing domain |

**The step function is total and failure-atomic.** For every state and operation
it returns a state and a disposition; a refused operation returns the *same*
state. The dispositions are the model's own vocabulary, kept separate from the
tool's refusal codes:

| disposition | meaning |
|---|---|
| `BM_STEP_OK` | the operation took effect |
| `BM_STEP_NO_NOTE` | there is no issued checkpoint to observe |
| `BM_STEP_UNSIGNED` | the observed checkpoint carries no signature |
| `BM_STEP_FOREIGN` | the observed checkpoint names another origin |
| `BM_STEP_FALSE_PROOF` | the checkpoint's root is not the root over its committed leaves |
| `BM_STEP_SPLIT` | a second root at an already-accepted size |
| `BM_STEP_ROLLBACK` | the checkpoint is smaller than the largest accepted size |
| `BM_STEP_INCONSISTENT` | the checkpoint does not extend the accepted committed prefix |
| `BM_STEP_CORRECTED` | a present-tense use after the subject was corrected |
| `BM_STEP_PRIVATE` | the member is not classified public |
| `BM_STEP_NOTHING_TO_ALIAS` | there is no established domain to alias |

The split-view operation needs one word of explanation. The model is honest about
what a monitor can and cannot see. `observe_split` offers a *validly signed*
checkpoint at the same size whose committed leaf list differs from the log's
own. If this is the first observation, the monitor accepts it — it has nothing
to compare with. If a root at that size was already accepted, it is an incident
and the observation is refused. The model represents both cases and never
pretends the first one was detected.

## 3. The enumeration bound

The bound is **5 operations** over an alphabet of **14**. The sequence space is

```
14^0 + 14^1 + 14^2 + 14^3 + 14^4 + 14^5 = 579,195
```

The enumeration is a breadth-first exploration of the **reachable state graph**,
not 579,195 independent runs. Because the state is complete (it records every
effect an operation can have) and the step is deterministic, every sequence up
to the bound maps to a path in the explored graph, so no sequence's outcome is
missed. The enumeration executes each distinct (state, operation) edge once:
**1,871 states**, **7,770 transitions**, maximum depth **5**. The record reports
both the combinatorial sequence space and the executed edges, so neither number
can be mistaken for the other.

The bound is a declared choice, not a bound derived from the implementation. A
sequence longer than five operations, or an alphabet larger than fourteen
operations, is outside the result. This is `BM-G5` in §6.

## 4. The invariants

Each invariant names the clause it refines (verbatim from §B.23), the operations
that constrain it, the abstraction it assumes, and what the checker tests.
`MODEL.json` records the same objects; `ENUMERATION.json` reports zero violations
for each.

### 4.1 `BM-I1` — no checkpoint is accepted without a signature

**Clause (§B.23).** "an unauthenticated checkpoint cannot authorise an accepted
tree root;"

**Operations.** `issue_checkpoint`, `observe_head`, `observe_stale`,
`observe_split`, `observe_unsigned`, `observe_foreign`.

**Assumption.** Signatures are unforgeable and cover the exact note bytes. The
model represents "verified" as a boolean supplied by a signer/verifier pair it
does not implement.

**Check.** No accepted checkpoint has `signed == false`. The unsigned operation
is refused with `BM_STEP_UNSIGNED` and leaves the state unchanged.

### 4.2 `BM-I2` — an accepted tree size never decreases

**Clause (§B.23).** "a smaller checkpoint cannot silently roll back accepted
state;"

**Operations.** `observe_head`, `observe_stale`, `observe_split`.

**Assumption.** A checkpoint's tree size is the length of the leaf sequence it
commits; leaf bytes are atomic.

**Check.** The accepted sizes are non-decreasing. A checkpoint smaller than the
largest accepted size is refused with `BM_STEP_ROLLBACK`.

### 4.3 `BM-I3` — one root per (origin, size)

**Clause (§B.23).** "equal-size conflicting authenticated roots produce an
incident;"

**Operations.** `observe_head`, `observe_stale`, `observe_split`.

**Assumption.** Origins are atomic labels; the log is the only producer of its
own checkpoints, and equivocation is the only source of two roots at one size.

**Check.** No `(origin, size)` key maps to two accepted roots. A second
authenticated root at an accepted size is refused with `BM_STEP_SPLIT`.

### 4.4 `BM-I4` — persistence, and no false inclusion proof

**Clause (§B.23).** "a false inclusion proof cannot satisfy inclusion
verification;"

**Operations.** `append_claim`, `append_other`, `issue_checkpoint`,
`observe_head`, `observe_stale`, `observe_split`, `use_claim`.

**Assumption.** Leaf bytes are atomic; the RFC 6962 hash geometry is part of the
model, not imported from `tlog`.

**Check.** Three things. Every accepted checkpoint's root is the RFC 6962 root
over the leaf sequence it commits. A leaf committed at size *n* is committed at
the same index by every later accepted checkpoint (prefix persistence). The
model's inclusion verifier accepts the true path for index `0` and for the last
index, and rejects a path whose last sibling is mutated — a false proof does not
verify. The root-soundness half also catches a checkpoint whose root was never
the root over its leaves (`BM_STEP_FALSE_PROOF`).

### 4.5 `BM-I5` — a withdrawn or corrected claim is never current

**Clause (§B.23).** "a revoked claim cannot satisfy a sufficiently fresh
current-state policy;"

**Operations.** `correct_subject`, `use_claim`, `issue_checkpoint`,
`observe_head`.

**Assumption.** The corrected value is a new state version; the claim leaf's
position is atomic.

**Check.** After a correction, no present-tense use is accepted at that version
or any later version (`BM_STEP_CORRECTED`), and the claim leaf is still at index
`0`, committed at index `0` by every honest accepted checkpoint and still
verifying there. The original inclusion is not erased by the correction.

### 4.6 `BM-I6` — a quorum counts distinct operator domains, not labels

**Clause (§B.23).** "duplicate witness credentials cannot satisfy independence
thresholds;"

**Operations.** `witness_distinct`, `witness_alias`.

**Assumption.** A domain is identified by its establishment record
`(path, sha256)`, not by its label.

**Check.** The quorum equals the number of distinct domains and never exceeds
the number of labels. An alias adds a label and does not raise the quorum.

### 4.7 `BM-I7` — a current-state version never decreases

**Clause (§B.23).** "a smaller checkpoint cannot silently roll back accepted
state;", applied to the B6 current-state version
(`docs/ARCHIVAL-REVOCATION.md` §3–§4).

**Operations.** `correct_subject`, `use_claim`.

**Assumption.** The B6 current-state version is the number of covered correction
events.

**Check.** `version >= versionFloor`; a correction advances the version and no
operation lowers it below the highest version reached.

### 4.8 `BM-I8` — a published bundle contains only classified public members

**Clause (§B.23).** "a publication failure cannot masquerade as transparent
acceptance."

**Operations.** `publish_public`, `publish_private`.

**Assumption.** The classification policy is the B4 policy and a member's class
is atomic.

**Check.** Every published path is classified public. Publishing a private
member is refused with `BM_STEP_PRIVATE`, not recorded.

### 4.9 The clauses the model does not express

Five of §B.23's twelve clauses have no representation in this state. They are
recorded as `NOT_MODELLED` with a reason in `REFINEMENT.json`, not omitted:

| clause | why not modelled |
|---|---|
| an unrelated log entry cannot authenticate a DSSE statement; | leaves are opaque bytes; DSSE and the A9/A10 binding are outside the model |
| unrelated log shards cannot satisfy a same-tree consistency obligation; | one origin, no shard transitions; B5 owns the shard controls |
| an omitted required campaign activity cannot permit promotion; | campaign machinery (A19, B3) has no representation here |
| missing timestamp evidence cannot satisfy a timestamp-dependent claim; | no trusted-time authority; B2 records none in this venue |
| unavailable evidence cannot satisfy reconstruction requirements; | archival reconstruction is B6's archive reader; the model has no IO |

## 5. The differential

`differential(sequences)` drives the model and the real modules over the same
sequences and compares the accept/reject vector and the resulting state
(accepted sizes, roots, version, verdict, published set, witness quorum,
last-use version). The default set is every sequence of length 1 and 2 over the
fourteen operations (**210**) plus nine curated sequences: one per invariant and
one growth sequence over an accepted head, of length 3–5 (**9**), so **219**
sequences. All 219 agree; the record is
`evidence/b7/DIFFERENTIAL.json`.

Each operation is driven by the module that owns it:

| operation | real module |
|---|---|
| `append_*`, `issue_checkpoint`, `observe_*` | `forensics/tools/tlog.py` and `forensics/tools/monitor.py` |
| `correct_subject`, `use_claim` | `forensics/tools/corrections.py` |
| `publish_*` | `forensics/tools/publication.py` |
| `witness_*` | `forensics/tools/thresholds.py` |

The model does not import these. They are imported **inside** the driver
constructor, after the model has decided; the structural test
`test_the_model_does_not_import_an_implementation` refuses a model function whose
globals resolve one of them, and
`test_the_model_source_has_no_top_level_import` refuses a top-level import.

**`NOT_RUN` cases.** No modelled operation requires a service: the driver builds a
local fixture log, a local checkpoint store, a local correction log and a local
classification query. The default differential therefore has **0 `NOT_RUN`
sequences**, and says so (`notRunCount: 0`). The labelling mechanism is not left
untested: the control `not-run-labelled` forces one sequence to `NOT_RUN` with a
reason and confirms it is excluded from `compared`, and the control
`not-run-counted` confirms that a matched status with no executed sequence is
refused with `BM_REFUSED_NOT_RUN_AS_VERIFIED`. The service-dependent claims the
model does not express are listed in §8.

A disagreement is a counterexample: the record carries both accept/reject
vectors and both resulting states, the tool exits 1 with
`BM_REFUSED_DIFFERENTIAL_DISAGREEMENT`, and the model is **not** edited to match
the code.

## 6. The refinement gap

`REFINEMENT.json` states, per invariant, whether it was checked in the model
only, in the model and matched by the implementation on the enumerated
sequences, or not matched. All eight modelled invariants are
`MODEL_AND_MATCHED`: the checker reports no violation and the named sequences
agree with the real modules. The five unmodelled clauses are `NOT_MODELLED`.

The gaps are stated, each with the clause or document that establishes the
assumption:

| gap | assumption | source | consequence |
|---|---|---|---|
| `BM-G1` DER and signature cryptography are assumed unforgeable | the `signed` flag is an oracle; the note bytes are the signed bytes | §B.23 (unauthenticated checkpoint); `docs/LOCAL-TRANSPARENCY.md` | no claim about signature verification, key binding or DER parsing; the differential uses a test-only HMAC-SHA256 key |
| `BM-G2` time is the recorded instant, not a clock | each observation carries a monotonically increasing recorded instant | `docs/TRANSPARENCY-MONITORING.md` §5; `evidence/b5/RECEIPT.md` | backdating is a comparison of records; trusted time, clock skew and RFC 3161 are `NOT_RUN` |
| `BM-G3` the model's leaves are opaque bytes | a leaf is its bytes; no parsing, DSSE payload or tile structure | §B.23 (model paragraph); `docs/ARCHIVAL-REVOCATION.md` §2 | five §B.23 clauses are `NOT_MODELLED` |
| `BM-G4` the model does not model process failure, IO or concurrency | an operation takes effect atomically or is refused with the state unchanged | §B.23 (the crash-recovery and partial-write sentence) | the B.23 requirement to model crash recovery, retries, partial writes and concurrency is **not met**; those properties are `NOT_RUN` |
| `BM-G5` the enumeration is finite and sequence-bounded | bound 5; the state graph is explored, not every sequence executed | §B.23 (bounded model checkers; the model stays small) | no claim beyond the bound or beyond fourteen operations |
| `BM-G6` the model, the checker and the driver share an author | the model is written from §B.23 and the B4/B5/B6 documents, not from the modules | `docs/EARNED-TRUST.md` Article 5; §B.23 (a verified abstract state machine is not a verified implementation) | agreement is a shared reading; a model theorem is not a proof about the binary (Article 7) |

`BM-G4` is the gap a reader should weigh first: §B.23 explicitly requires crash
recovery, persistent witness state, retries, partial writes, concurrent
publication and shard transitions to be modelled, and this model does not model
them. It is recorded as a gap rather than softened into a success.

## 7. The canary

A check that cannot fail is not a check. `ENUMERATION.json` records **eight
deliberately broken models**, one per invariant, each caught by the same checker:

| broken model | wrong behaviour | caught as |
|---|---|---|
| `unsigned-accepted` | accept an unsigned checkpoint | `BM-I1` |
| `rollback-accepted` | accept a checkpoint smaller than the largest accepted | `BM-I2` |
| `split-accepted` | accept a second root at an accepted size | `BM-I3` |
| `root-ignored` | accept a root that is not the root over its leaves | `BM-I4` |
| `withdrawn-current` | accept a use after the correction | `BM-I5` |
| `witness-labels` | count labels instead of domains | `BM-I6` |
| `version-decrease` | lower the state version | `BM-I7` |
| `publish-private` | publish a private member | `BM-I8` |

Each row records the target invariant, the number of violations, and a concrete
sequence that reaches the first one. The control `canary-not-detected` rewrites
every row to `detected = false` and confirms the tool refuses with
`BM_REFUSED_CANARY_NOT_DETECTED`. The tests
`test_each_invariant_is_individually_violated_and_caught` (one case per
invariant) and `test_the_canary_is_detected` are the enforced checks.

## 8. The refusal table

Every code is stable, documented here, exercised by one control in
`evidence/b7/CONTROLS.json`, and named by a test.

| code | condition | prevents | enforced by |
|---|---|---|---|
| `BM_REFUSED_INVARIANT_VIOLATED` | a reachable state violates a stated invariant | a violation recorded as a pass | `test_refused_invariant_violated` |
| `BM_REFUSED_MODEL_INCOMPLETE` | a state field, operation, alphabet member or required invariant field is missing | a partial model presented as the model | `test_refused_model_incomplete` |
| `BM_REFUSED_INVARIANT_UNSOURCED` | an invariant's clause is not a verbatim §B.23 bullet | a fabricated clause presented as an authority requirement | `test_refused_invariant_unsourced` |
| `BM_REFUSED_ENUMERATION_TRUNCATED` | the run stops below the declared bound, or its sequence space is not the declared alphabet's | a truncated run reported at the bound | `test_refused_enumeration_truncated` |
| `BM_REFUSED_CANARY_NOT_DETECTED` | a broken model does not violate the invariant it targets | a canary that cannot fail | `test_refused_canary_not_detected` |
| `BM_REFUSED_REFINEMENT_UNSTATED` | a status, a gap or a gap's source is unstated or contradictory | a gap claimed as closed by silence | `test_refused_refinement_unstated` |
| `BM_REFUSED_DIFFERENTIAL_DISAGREEMENT` | the model and the real modules differ on a sequence both ran | a defect repaired by editing the model | `test_refused_differential_disagreement` |
| `BM_REFUSED_NOT_RUN_AS_VERIFIED` | a `NOT_RUN` row is counted as compared, or a matched status has no executed sequence | deferred work counted as verified | `test_refused_not_run_as_verified` |
| `BM_REFUSED_USAGE` | the command line is used incorrectly, or the bound exceeds its maximum | an undefined invocation treated as a result | `test_usage_exits_two_with_a_code` |

## 9. What this establishes, and what it does not

**Established.** Over the reachable state graph to bound 5 on a fourteen-operation
alphabet (1,871 states, 7,770 transitions), the eight modelled invariants hold on
every state; eight deliberately broken models are each caught on the invariant
they target; and the model and the local real modules agree on the accept/reject
vector and the resulting state for all 219 enumerated sequences.

**Not established — stated plainly.**

* **A model theorem is not a proof about the binary or the service.** There is no
  TLA+, Coq, Lean or Kani proof, and no refinement edge from this state machine
  to the compiled code (Article 7). The checker is a Python predicate.
* **The enumeration is finite.** Five operations over fourteen, and a reachable
  state graph, not every sequence executed. Nothing here proves the invariants
  for a longer sequence.
* **The model and the implementation share an author.** Agreement is evidence of
  a shared reading, not independent verification; no external party wrote either
  side (Article 5).
* **Five §B.23 clauses are not modelled.** DSSE entry binding, shard consistency,
  campaign omission, timestamp evidence and reconstruction requirements are
  `NOT_MODELLED` with reasons, and the model does not claim them.
* **Crash recovery, retries, partial writes and concurrency are not modelled**,
  although §B.23 requires them to be. This is a gap, not a success.
* **The differential is local.** It drives fixture logs and local modules; the
  observation instants are records, not trusted time; the signature is a
  test-only HMAC.

## 10. `NOT_RUN`

* An admitted public transparency log, its key, client and inclusion
  (B0/B1 record a fixture; no service exists in this venue).
* A witness cosignature admitted from an independent operator (B5 records 0
  witnesses).
* A trusted RFC 3161 timestamp for an observation, a state or a publication (B2
  records no authority).
* Crash recovery, retries, partial writes and concurrent publication.
* A machine-checked proof and a source-to-binary refinement edge.
* An independent reviewer or a distinct trust domain.
* A `BOUNDARY` audit, a `SEAL`, and the Rust test suite — no Rust source was
  modified by this item.

## 11. Reproducing the result

```
python3 forensics/tools/transparency_model.py enumerate
python3 forensics/tools/transparency_model.py differential
python3 forensics/tools/transparency_model.py refinement
python3 forensics/tools/transparency_model.py controls
python3 evidence/b7/build_evidence.py
python3 -m unittest discover -s forensics/tools/tests
```

The producer is deterministic: two runs, and `--check` against the committed
records, reproduce the same bytes. The expected summary is

```
code=BM_OK b7: bound=5 alphabet=14 sequences=579195 states=1871 violations=0 canaries=8 canariesDetected=true compared=219 agreed=219 notRun=0 matched=8/8 controls=10 codes=10
```

The tests in `forensics/tools/tests/test_transparency_model.py` enforce every
statement above: one control per refusal code, the enumeration's declared
bound, the canary, each invariant's individual violation in a fixture, the
`NOT_RUN` labelling, determinism, the CLI exit codes, and this document's
synchronisation with the records.
