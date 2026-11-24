# A27 receipt — one real finding through the whole chain, and where it stops

## 1. Identity of this batch

| field | value |
|---|---|
| item | A27 (vertical slice: one real artefact through finding identity, location, population, suppression, delta, export, statement, envelope, verification, authorisation, threshold, bundle, key lifecycle, correction, omission, policy and summary; then the deliberately corrupted counterpart) |
| branch | `staging` |
| HEAD at the start | `e3bed067cf9a28786952152fb2e55883c6405a22` (`a26: measure the cost, state the machine, and never skip to save it`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 31 7 0 7 13` (available **13** GiB); `Swap: 45 43 2` |
| `free -g` before the final suite | `Mem: 45 33 5 0 7 12` (available **12** GiB); `Swap: 45 42 2` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `HostConfig.MemorySwap` both `6442450944`; cgroup `memory.max` `6442450944`), CPU quota **8 cores** (`cpu.max = 800000 100000`), repository at `/work`; reused, not restarted |
| interpreter in the court | CPython **3.11.2** |
| peak court memory observed | 114.2 MiB of 6 GiB |
| heavy commands | one at a time; no Rust build |

Available memory was 13 GiB before the work and 12 GiB before the final suite,
below the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed:
every gate is Python, the derived cap would be below the 2 GiB floor, and **no new
court was started**. The already-running 6 GiB court was reused and every gate ran
inside it.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/vertical_slice.py` | 2,107 | the implementation: the chain declaration, `bind_artefact`, `run`, `run_chain`, `validate_trace`, `check_stop_binding`, `first_stop`, `policy_counterfactual`, `build_slice`, `build_stops`, `build_controls`; CLI `run`, `trace`, `stop`, exit 0/1/2, always printing the code; 10 stable refusal/stop codes |
| `forensics/tools/tests/test_vertical_slice.py` | 499 | 51 controls: one per refusal code, the digest chain both ways, the skipped stage, every stage after the stop, the real stop, the policy counterfactual, determinism, the command line, document synchronisation |
| `docs/VERTICAL-SLICE.md` | 397 | the normative document: why a slice exists, the artefact, the chain and each contract, the digest rule, the status vocabulary, the real trace, the stop, the stages not reached, the controls, the refusal table, what it does and does not establish, `NOT_RUN` |
| `evidence/a27/build_evidence.py` | 146 | the deterministic producer: runs the chain against the committed records, validates the stop and the controls, writes the three records, exits nonzero on any disagreement |
| `evidence/a27/SLICE.json` | 1,050 | the artefact, the chain, the full digest-chained trace, the stop and the policy counterfactual |
| `evidence/a27/STOPS.json` | 106 | the stop with its establishing record, and every stage after it `NOT_REACHED` with the reason |
| `evidence/a27/CONTROLS.json` | 170 | 9 `controlOnly` rows (one per refusal code, including the invocation code) and 3 positive rows |
| `docs/ETP-TODO.md` | 1 row | the A27 row replaced from `TODO`; no other row touched |
| `evidence/a27/RECEIPT.md` | this file | the receipt |

Content digests (SHA-256, full):

| file | sha256 |
|---|---|
| `vertical_slice.py` | `46da8ddaa7c2410643ec34fa9ed651f2da0f56e9d1bde629d3d29a01733751ac` |
| `test_vertical_slice.py` | `a379626889a300761a07830dea6512910ca51fabe5b8db092de47a66238dea65` |
| `VERTICAL-SLICE.md` | `5585d4d8c808275bea57c5bdbfd61dbd1df2ea6d370ed74d23f42ffb0647e36c` |
| `build_evidence.py` | `6271e7a88d5aff90bf864db961d17d13d037f5d751f5bf68333025194f834f8e` |
| `SLICE.json` | `10c3b1965372d6ff26460f3f7e69cc358d3e9ee56b5413de6bed4a17abdc000c` |
| `STOPS.json` | `4083b770ec2d890b156fe1c4fd9d959020ceb6a95ccf4f4c257d5bf65568bd85` |
| `CONTROLS.json` | `4c10a9637d6c8bb7b8599bcd36dba112c053c35772442fbfc55b1bd7a0fa7359` |

`SLICE.json`, `STOPS.json` and `CONTROLS.json` name the producer and the tool by
digest, so an edit to either invalidates them until the producer is re-run.
`STOPS.json` and `CONTROLS.json` also name the `SLICE.json` digest they describe.

## 3. The artefact and why it was chosen

The slice starts from the A1 result `a1-run3-result-2390`: `evidence/a1/SARIF.json`
(SHA-256 `5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852`),
run 3, result index 2390. It is the finding
`A1-UNSAFE-OBLIGATION-DELEGATED` at `md32.rs:118`, symbol `update`:

| field | value |
|---|---|
| exact identity | `9387bcba07a02821e3b0190b1a414ab266de6b50c16bf788faf34e70218898b1` |
| logical identity | `d423fed03da544cf95e80d07dd9db33156bfa030fda634bf2fa025e5211513e3` |
| rule identity | `a85943c7f0f99e379153074145963b9a1a994f3815bf479e55cd40575659cdf2` |
| binding | `md32.rs`, scope `source-tree`, digest `ef8678c53feb9ec59e8cc61c6a0b636ae59aeb01b6dbe482ebc463932ae2ed1d` |
| recorded region | line 118; no column, no extent |
| native locator | `vacuity.findings[65]` in `evidence/etp-t4/SAFETY-SITES.json` (`7fb1ef96…`) |
| candidate | `246e30580f909c047eeb04a93a06f9bd05dc65f3` |
| A4 instance | `L3-md32-update` (provenance row 13997; joined by path, line and symbol) |
| population | `a1-sarif-results`, `COMPLETE`, 4245 examined, 0 omitted, 4245 distinct |
| shard membership | `evidence/a8/SHARD-000.sarif`, run 3, result index 2390 |

It was chosen because it is the only kind of artefact that satisfies all four
preconditions the item requires, and each is **re-derived before the chain
starts**:

1. the recorded fingerprints are recomputed from the recorded rule, key, binding
   and region (not copied);
2. the A4 instance's provenance row names the same path, line and symbol;
3. the containing population is admitted `COMPLETE` with identified members, and
   the member is present in the cited record;
4. the shard contains the same exact identity at the same run and result index.

An artefact that fails any of them is `VS_REFUSED_ARTEFACT_UNBOUND`. The slice
does **not** switch to a different artefact: a slice that picks the artefact that
works demonstrates nothing.

## 4. The chain and the trace

Seventeen stages are declared, in the order the item states. Nine were traversed:
eight `PASS` and one `STOP`. Eight are `NOT_REACHED` with the reason. Zero
refused. Zero validation codes.

| stage | item | status | inputDigest | outputDigest |
|---|---|---|---|---|
| A3 | finding identity | PASS | `43861048faad6c87` | `11d5a576c51f9999` |
| A4 | location fidelity | PASS | `11d5a576c51f9999` | `18414f7d1cc5cc84` |
| A5 | population admission | PASS | `18414f7d1cc5cc84` | `8640c9a13a98e804` |
| A6 | suppression disposition | PASS | `8640c9a13a98e804` | `a9be1da7de07cf00` |
| A7 | baseline delta | PASS | `a9be1da7de07cf00` | `ec18d9220518a0a6` |
| A8 | export shard and union | PASS | `ec18d9220518a0a6` | `b16d376ae0b2fa54` |
| A9 | in-toto statement | PASS | `b16d376ae0b2fa54` | `ea67963abf16e9b1` |
| A10 | DSSE envelope | PASS | `ea67963abf16e9b1` | `5bf418cc5b014d98` |
| A12 | independent verification | STOP | `5bf418cc5b014d98` | `b857ff11c7506237` |
| A14 | authorisation | NOT_REACHED | `b857ff11c7506237` | — |
| A15 | threshold | NOT_REACHED | `b857ff11c7506237` | — |
| A16 | Sigstore bundle | NOT_REACHED | `b857ff11c7506237` | — |
| A18 | key lifecycle | NOT_REACHED | `b857ff11c7506237` | — |
| A19 | correction status | NOT_REACHED | `b857ff11c7506237` | — |
| A17 | omission closure | NOT_REACHED | `b857ff11c7506237` | — |
| A20 | policy | NOT_REACHED | `b857ff11c7506237` | — |
| A21 | summary | NOT_REACHED | `b857ff11c7506237` | — |

The trace uses three kinds of digest, and the document says which is which:

* **projection digests** at A3–A7 and A12: the SHA-256 of a canonical JSON payload
  built from the record's own row for this artefact, embedding the digest it
  consumed;
* **artefact digests** at A8–A10: the shard
  `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed`, the
  statement `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582`
  and the envelope `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9`;
* the **binding digest** `43861048faad6c87657982fa554b2315af8569e9324532e36eed7575247efd35`
  that A3 consumes.

A9, A10 and A12 do not take the previous stage's word for it: A9 requires
`record.sha256` to be the shard digest, A10 requires `payloadSha256` to be the
statement digest, and A12 requires `envelopeSha256` to be the envelope digest. A10
also recomputes the PAE to
`9e08bc6c908d7964aa05af48a8e81c7806b6835febc31e9ecf022cb9c622280f`.

## 5. The stop at A12 and what it means

A12 records **`SELF_ISSUED`** for this envelope, `independentlyVerified: false`,
and three codes: `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT` and
`IV_REFUSED_SELF_ISSUED`. The aggregate is **0 of 4 envelopes independently
verified, 4 self-issued**, and the A10 test-only HMAC key is symmetric, inside the
candidate tree, and records a self-issued independence basis.

The stop code is `VS_STOP_NO_INDEPENDENT_VERIFICATION`. It is established by

| field | value |
|---|---|
| record | `evidence/a12/VERIFICATION.json` |
| sha256 | `7cbdcdae7d7c5636c26b3a9f6141e6a0e345e6c8a281c926fc4b411f68991a48` |
| locator | `/verifications[name=a8-shard-000]` |
| observed | outcome `SELF_ISSUED`; 0 of 4 independently verified; the three codes above |

**The policy would deny.** The committed A20 decision is **`DENY`**
(`evidence/a20/DECISION.json`, SHA-256 `7f5a3cb8…`), with five unmet required
obligations including `A12.independent-attestation` (`state: UNMET`,
`observed.count: 0`, detail "0 qualifying member(s), at least 1 required"), and
`policy.default: deny`. The slice additionally checks that all eight obligation
`recordSha256` values are the current source records
(`sourceRecordsMatchCurrentTree: true`, no mismatches) and that the decision names
the same A12 digest the stop is established by. It is labelled
`evaluatedByThisSlice: false`: it is the A20 record's own decision at its own
candidate, not a re-evaluation at this base commit.

**Why the chain stops rather than degrading.** Every later stage consumes an
independent verification. Substituting a self-issued signature for an independent
one is the exact defect A12 exists to prevent, so the slice records the stop and
marks the rest `NOT_REACHED`. It does not promote, and it does not summarise a
denial as a result.

## 6. The deliberately corrupted counterpart

`evidence/a27/CONTROLS.json` holds nine `controlOnly` rows, one per refusal code
(including the invocation code), and three positive rows. Each mutates an
in-memory trace, an in-memory record, the artefact declaration or the invocation
and asserts the exact code that fires; no row changes a committed record.

| control | code observed |
|---|---|
| `trace-broken` | `VS_REFUSED_TRACE_BROKEN` |
| `stage-skipped` | `VS_REFUSED_STAGE_SKIPPED` |
| `output-missing` | `VS_REFUSED_OUTPUT_MISSING` |
| `stage-overclaim` | `VS_REFUSED_STAGE_OVERCLAIM` |
| `admit-without-root` | `VS_REFUSED_ADMIT_WITHOUT_ROOT` |
| `summary-as-evidence` | `VS_REFUSED_SUMMARY_AS_EVIDENCE` |
| `stop-unrecorded` | `VS_REFUSED_STOP_NOT_RECORDED` |
| `artefact-unbound` | `VS_REFUSED_ARTEFACT_UNBOUND` |
| `malformed-invocation` | `VS_REFUSED_USAGE` |

`coversEveryCode` is true, `codesMissing` is empty and `failing` is empty. The
positive rows assert that the real trace validates with no code, that the real
stop is bound to its record, and that the real trace has no omission. A control
proves the refusal fires; it is not evidence that a stage is correct.

## 7. Defects found

**Existing records:** **none contradicted by this item.** Every source digest the
slice cites is the current file's digest, the A20 decision's eight source digests
all match, and the A17 forward freeze declares `evidence/a27/RECEIPT.md` as
`a27-receipt`. No check was relaxed and no other item's record was modified.

**One seam that would invalidate another item's record if handled carelessly.**
A19 derives its dependent population by scanning documents for superseded
tokens. A new document that reproduces such a token becomes a dependent, and the
committed A19 propagation record (14 dependents) becomes stale. The generator is
deterministic and the record is another item's evidence, so this item did not
regenerate it; instead `docs/VERTICAL-SLICE.md` §8 cites the correction (subject
`A4/L3-md32-update/byteLength`, accepted extent `0x165`) **without reproducing the
superseded token**, and A19 stays at 14 dependents. Owning item: **A19** (with
A17 for the freeze/regeneration policy). If a future document must quote the
token, A19 must regenerate its records in the same change.

**Seams between stages found by the traversal** (recorded, not repaired here; the
owning item is named):

* **A4/A1:** the A4 instance locates the site's machine-code instantiation, while
  the finding's location is a source line. The join is path, line and symbol, not
  identity; the slice records it as such and adds no precision.
* **A5/A6:** the finding's population is the A1 emission; the record the finding
  cites as provenance also carries the suppression population `t4-suppressions`,
  which A5 admits only `AGGREGATE_ONLY` (`CA_REFUSED_OMITTED_UNRECORDED`). One
  artefact, two populations, only one of them containing the member.
* **A6:** the suppression register is recorded at the finding's candidate, but its
  admissions were evaluated against a later candidate and every candidate-bound
  record is refused stale. Zero records are actionable; zero members are disposed.
* **A7:** the `a1-sarif-results → a1-fingerprints-model` delta compares the
  pre-extraction SARIF projection with the generalised identity model **over the
  same emission**. `STILL_PRESENT` is an identity-model agreement, not a
  code-change baseline, and A7's own `noBaseline` entry says no second population
  exists for the area. A reader who takes the delta for a baseline would
  overclaim.
* **A8/A9:** the digest link is exact but the granularity changes. A8 is the last
  per-member stage; A9's statement is about the shard, and this member's identity
  survives only inside the shard's bytes.
* **A12:** the aggregate and the per-envelope outcome agree (0 of 4). The slice
  checks that agreement, because an aggregate that disagrees with its entries is
  the summary-without-reconstruction defect at the verification layer.
* **A19:** the correction about this very A4 instance is preserved and
  **unauthenticated** (`SELF_ISSUED`); the A4 value the slice consumed is the
  accepted one, and the slice cannot be read as authenticating it.
* **A17:** the forward freeze is `OPEN`. Producing the declared `a27-receipt`
  member satisfies the member predicate; it does not close the freeze, and the
  A17 record is not moved.

**Development defects in this item's own machinery** (recorded because a control
that passes for the wrong reason is the defect this item exists to catch):

* The first `stage-overclaim` control read `validate_trace`'s return value, which
  is empty for a trace that is merely `REFUSED`, so the control reported no code
  and did not fire. The control now reads the refusing stage's own codes; the
  refusal was not changed.
* The first document-synchronisation test unpacked two fields from a three-group
  regular expression and raised `ValueError`. The test now unpacks the enforced-by
  cell; the document format was not weakened.
* The first committed-controls comparison left the producer-injected `slice` key
  in the committed document and therefore never compared equal. The comparison now
  removes producer-added keys; the record was not edited.
* The first export stage referred to a population-size key the artefact does not
  carry. It now uses the manifest's parent result count and requires the union's
  distinct count to equal it and the shard result count, which is the stronger
  check.
* The first stop line printed `independent=False`; it now prints `0/4`, because
  the number the item exists to report must be the number a reader sees.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | `Mem: 45 31 7 0 7 13` (available 13 GiB) before the work; `Mem: 45 33 5 0 7 12` (available 12 GiB) before the final suite; `Swap: 45 42 2` |
| 1. court and cap | `docker inspect openssl-rs-court`; cgroup | `6442450944 6442450944 8000000000 running`; `memory.max 6442450944`; `cpu.max 800000 100000`; CPython 3.11.2; peak 114.2 MiB of 6 GiB |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1937 tests in 438.876s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,886 pre-existing tests are present (1,886 + 51), none removed, none ignored, no skips reported |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on `SLICE.json`, `STOPS.json`, `CONTROLS.json` | all three: `json.tool ok` |
| 5. producer, twice | `python3 evidence/a27/build_evidence.py` twice in the court | both: `a27: artefact=a1-run3-result-2390 exact=9387bcba07a0 stages=17 passed=8 stopped=1 notReached=8 stop=A12 code=VS_STOP_NO_INDEPENDENT_VERIFICATION policy=DENY controls=9/9 codes=NONE`; `diff` of the three file digests before vs run 1 and run 1 vs run 2: `BYTE-IDENTICAL`; the committed files are the same bytes |
| 6. run | `python3 forensics/tools/vertical_slice.py run` | 8 × `status=PASS`, `stage=A12 status=STOP … codes=IV_REFUSED_SYMMETRIC,IV_REFUSED_CANDIDATE_TRUST_ROOT,IV_REFUSED_SELF_ISSUED,VS_STOP_NO_INDEPENDENT_VERIFICATION`, 8 × `status=NOT_REACHED`, `stop=A12 code=VS_STOP_NO_INDEPENDENT_VERIFICATION outcome=SELF_ISSUED independent=0/4`, `codes=NONE`, `RUN_EXIT=0` |
| 6. stop | `python3 forensics/tools/vertical_slice.py stop` | `stop=A12 code=VS_STOP_NO_INDEPENDENT_VERIFICATION outcome=SELF_ISSUED record=evidence/a12/VERIFICATION.json sha256=7cbdcdae… locator=/verifications[name=a8-shard-000]`; `not_reached=A14…A21 after=A12 code=VS_STOP_NO_INDEPENDENT_VERIFICATION reason=the chain stopped at A12 (VS_STOP_NO_INDEPENDENT_VERIFICATION); A14 was not executed` (and the same for each); `codes=NONE`, `STOP_EXIT=0` |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; exit 0 |
| 8. worktree | `git --no-pager status --porcelain` | see below |

Gate 5's byte identity is of the *record*: the trace is a function of the
committed records, so two producer runs reproduce the same bytes. The producer
stamps its own digest and the tool's, so an edit to either is visible until the
producer is re-run (`test_the_producer_stamp_is_current`).

After gate 2 ran, the A27 row in `docs/ETP-TODO.md` was replaced from `TODO` and
this receipt was written. Both are documentation/evidence edits; the only pinned
consumer of `docs/ETP-TODO.md` is `spec_guard.py`, and `spec_guard.py check` and
`docs_consistency.py` were re-run after the edit and pass (gate 7 and gate 3
above). The A27 row contains no source-tree path and no implementation identifier in a
code span, so the pinned nonconformance token set did not change. No measured
command, record or test input changed.

## 9. Obligations retained

* **A connected chain is not a true chain.** The slice establishes that the
  stages consume each other's digests; it does not establish that any stage's
  claim is true (Article 1).
* **`SELF_ISSUED` is not a pass.** Zero of four envelopes are independently
  verified. That is the result, not a defect to be repaired by relabelling it.
* **The policy counterfactual is a read, not a re-evaluation.** It is the A20
  record's decision at the A20 record's candidate; `evaluatedByThisSlice` is false.
* **Post-stop records belong to their items.** A14–A21 are recorded by their own
  items at their own candidates; the slice did not execute or consume them.
* **The artefact is one member of a mixed-candidate population.** Nothing here is
  a census, and `COMPLETE` is about the record-set, not the tree.
* **The tool implements no post-A12 consumer.** A chain that does not stop at A12
  refuses with `VS_REFUSED_OUTPUT_MISSING` rather than fabricating one.
* **The receipt member does not close the freeze.** The A17 forward freeze remains
  `OPEN`; A17 owns closing it.
* **The digest kinds are not interchangeable.** A projection digest proves the
  projection, an artefact digest proves the bytes; the document keeps them apart.

## 10. `NOT_RUN`

* A real external trust root, a production signature primitive, and any party in
  a distinct trust domain — the reason the chain stops at A12.
* Per-artefact consumers for A14, A15, A16, A18, A19, A17, A20 and A21.
* A live re-evaluation of the A20 policy at this base commit.
* Independent cryptographic verification inside this tool; A12's check 7 records
  the signature check, and the slice consumes that record.
* A multi-shard export (the A8 export is one shard under the 5,000-result limit).
* A second artefact, a second candidate, and any census claim.
* Independent review, BOUNDARY and SEAL evidence, and the Rust test suite (no
  source file was modified by this item).

## 11. The forward-freeze member

`evidence/a17/FREEZE-forward.json` declares `a27-receipt`
(`path: evidence/a27/RECEIPT.md`, `phase: A27`, `required: true`, predicate: "a
receipt records the item's result, gates and `NOT_RUN` obligations"). This file is
that member: it records the result, the gates with their output, and the `NOT_RUN`
obligations. The member predicate is satisfied. The freeze itself remains `OPEN`
and is not moved by a member landing; A17 closes it at its own record.
