# Vertical slice — one real finding, every stage, and where the chain stops

> **A per-stage test proves that a stage refuses one wrong conclusion. It does
> not prove that the next stage consumes what the stage produced.** A vertical
> slice traverses one real artefact through the whole chain and records, at every
> stage, the digest it consumed, the digest it produced, its status and its code.
> A recorded stop is a valid completion of the *slice*; it is never a pass of the
> release.

The item is A27 in `docs/ETP-TODO.md`. The implementation is
`forensics/tools/vertical_slice.py`; the controls are
`forensics/tools/tests/test_vertical_slice.py`; the records are
`evidence/a27/SLICE.json`, `evidence/a27/STOPS.json` and
`evidence/a27/CONTROLS.json`, written deterministically by
`evidence/a27/build_evidence.py`.

## 1. What a vertical slice is for

Each item in the chain has a suite that exercises its own refusals. Those suites
are necessary and they are not sufficient, because every one of them can pass
while the *seam* between two stages is missing:

* an identity that is recorded but not derivable from the recorded fields;
* a location record that locates a different site than the finding it is joined to;
* a population whose admission is stronger than the membership it can enumerate;
* a suppression register whose candidate is not the finding's candidate;
* a delta that compares two projections of one emission and calls it a baseline;
* a statement that frames a shard nobody produced;
* an envelope that frames a statement the verifier never saw;
* a verification record the aggregate does not summarise;
* a policy evaluated over records that are not the ones the slice traversed.

A stage test sees one side of the seam. The slice sees both sides and refuses a
trace whose digests do not meet. This is the property that `test_digest_chain_links_every_consecutive_pair_forward`,
`test_digest_chain_links_every_consecutive_pair_backward` and
`test_digest_chain_is_not_coincidental` establish, and the code that fires when
the property fails is `VS_REFUSED_TRACE_BROKEN`.

## 2. The artefact and why this one

The slice starts from one **A1 SARIF result** — artefact `a1-run3-result-2390`:
run 3, result index 2390, of `evidence/a1/SARIF.json` (SHA-256 `5c0cfee6…`). It is
the finding `A1-UNSAFE-OBLIGATION-DELEGATED` at `md32.rs:118`, symbol `update`,
with:

| field | value |
|---|---|
| exact occurrence identity (`a1Exact/v1`) | `9387bcba07a02821e3b0190b1a414ab266de6b50c16bf788faf34e70218898b1` |
| logical identity (`a1Logical/v1`) | `d423fed03da544cf95e80d07dd9db33156bfa030fda634bf2fa025e5211513e3` |
| rule identity (`a1Rule/v1`) | `a85943c7f0f99e379153074145963b9a1a994f3815bf479e55cd40575659cdf2` |
| subject binding | `md32.rs`, scope `source-tree`, digest `ef8678c5…` |
| recorded region | line 118, no column, no extent |
| native locator | `vacuity.findings[65]` in `evidence/etp-t4/SAFETY-SITES.json` |
| candidate | `246e3058…` (the scanner identity recorded on the result) |

It was chosen because it is the only kind of artefact that satisfies all four
preconditions, and each precondition is checked before the chain starts:

1. **a recorded exact identity** — and the identity model *derives* the recorded
   fingerprints from the recorded fields;
2. **a recorded location** — the A4 instance `L3-md32-update` (`evidence/a4/INSTANCES.json`)
   locates the same path, line and symbol through its provenance row 13997;
3. **a containing population** — `a1-sarif-results`, admitted `COMPLETE` in
   `evidence/a5/ADMISSION.json` with 4245 identified members;
4. **a shard membership** — the same run and result index in
   `evidence/a8/SHARD-000.sarif`.

An artefact that fails any one of them is `VS_REFUSED_ARTEFACT_UNBOUND`, and the
slice **does not switch to a different artefact**. That is the difference between
a slice and a demonstration: a demonstration picks the artefact that works.

The A4 instance is about the site's **machine-code** instantiation (the mangled
symbol and its 357-byte extent in `libcrypto.so.3`), while the finding's own
location is the **source** line. The two are joined by path, line and symbol, not
by identity. The slice records that seam at A4 and adds no source precision.

## 3. The chain and each stage's contract

The chain is declared in `vertical_slice.py` and reproduced in `SLICE.json`. Each
stage names the tool it invokes or the record it reads, what it consumes, what it
produces, and the one contract it enforces.

| Stage | Item | Tool | Reads | Consumes → produces | Contract |
|---|---|---|---|---|---|
| `A3` | finding identity | `forensics/tools/finding_identity.py` | `evidence/a1/SARIF.json` | the artefact binding → the identity record | the recorded fingerprints are recomputed from the recorded fields |
| `A4` | location fidelity | `forensics/tools/location_fidelity.py` | `evidence/a4/INSTANCES.json`, `evidence/etp-t4/SAFETY-SITES.json` | A3 output → the location rule and its limitations | the instance locates the same path, line and symbol; no precision is added |
| `A5` | population admission | `forensics/tools/completeness.py` | `evidence/a5/POPULATIONS.json`, `evidence/a5/ADMISSION.json`, `evidence/a1/SARIF.json` | A4 output → the admission state and the member's presence | the population is admitted at the state its facts support and the member is present |
| `A6` | suppression disposition | `forensics/tools/suppression_governance.py` | `evidence/a6/SUPPRESSIONS.json` | A5 output → the disposition of this finding | only an actionable record naming this identity disposes of it |
| `A7` | baseline delta | `forensics/tools/baseline.py` | `evidence/a7/DELTA.json`, `evidence/a7/BASELINES.json` | A6 output → the per-identity disposition and what the delta compares | the disposition is the one recorded and no resolution is claimed |
| `A8` | export shard and union | `forensics/tools/code_scanning_export.py` | `evidence/a8/MANIFEST.json`, `evidence/a8/SHARD-000.sarif` | A7 output → the shard digest and the member's coordinates | the shard is a subset whose union equals the parent and the member is present |
| `A9` | in-toto statement | `forensics/tools/intoto.py` | `evidence/a9/STATEMENTS.json`, `evidence/a9/STATEMENTS/a8-shard-000.json` | the shard digest → the statement digest | the statement names the shard at its byte digest and asserts no more than it records |
| `A10` | DSSE envelope | `forensics/tools/dsse.py` | `evidence/a10/ENVELOPES.json`, `evidence/a10/ENVELOPES/a8-shard-000.json` | the statement digest → the envelope digest | the payload is the statement's bytes and the PAE is recomputed from them |
| `A12` | independent verification | `forensics/tools/independent_verify.py` | `evidence/a12/VERIFICATION.json` | the envelope digest → the verification outcome | the outcome is the one recorded for this envelope and the aggregate agrees with it |
| `A14` | authorisation | `forensics/tools/authorisation.py` | `evidence/a14/AUTHORISATION.json` | an independent verification → a role decision | no per-artefact action consumes this member; not implemented here |
| `A15` | threshold | `forensics/tools/thresholds.py` | `evidence/a15/EVALUATION.json` | the A14 decision → a domain threshold | not implemented here |
| `A16` | Sigstore bundle | `forensics/tools/sigstore_bundle.py` | `evidence/a16/INVENTORY.json` | the A15 evaluation → an offline bundle validation | not implemented here |
| `A18` | key lifecycle | `forensics/tools/key_lifecycle.py` | `evidence/a18/INVENTORY.json` | the A16 validation → a survivability evaluation | not implemented here |
| `A19` | correction status | `forensics/tools/corrections.py` | `evidence/a19/PROPAGATION.json` | the A18 evaluation → the correction status | not implemented here |
| `A17` | omission closure | `forensics/tools/omission.py` | `evidence/a17/STATUS.json`, `evidence/a17/FREEZE-forward.json` | the A19 status → the omission closure | not implemented here |
| `A20` | policy | `forensics/tools/policy_engine.py` | `evidence/a20/POLICY.json`, `evidence/a20/DECISION.json` | the A17 closure → the policy decision | not implemented here |
| `A21` | summary | `forensics/tools/verification_summary.py` | `evidence/a21/SUMMARY.json` | the A20 decision → a summary | not implemented here; a summary is never another stage's evidence |

The eight stages after A12 are declared because the chain has them. They are not
implemented **as per-artefact consumers** here, and the slice says so rather than
pretending they ran. A chain that does not stop at A12 therefore refuses with
`VS_REFUSED_OUTPUT_MISSING`, not with a fabricated continuation.

## 4. The digest-chaining rule

Every stage produces a digest and every stage consumes one. There are three kinds
of digest in the trace, and the difference matters:

1. **A projection digest** (A3–A7, and A12's result). The stage's payload is a
   canonical JSON object built from the record's own row for this artefact; the
   digest is the SHA-256 of
   `json.dumps(payload, sort_keys=True, separators=(",", ":"))`. The payload
   embeds the digest it consumed, so the projection chain is a hash chain: an
   edit to any earlier payload changes every later digest.
2. **An artefact digest** (A8, A9, A10). The shard is `b16d376a…`, the statement
   is `ea67963a…` and the envelope is `5bf418cc…`, and each is the SHA-256 of the
   bytes on disk. Here the link is not reconstructed by this tool: A9's record
   *names* the shard digest, A10's record names the statement digest, and A12's
   record names the envelope digest. The tool checks the record's own field
   against the previous stage's output.
3. **The binding digest** (the chain's first input). It is the SHA-256 of the
   artefact binding — identity, binding, region, population and shard membership
   — and it is what A3 consumes.

The rule is one sentence: **stage N's `outputDigest` is stage N+1's
`inputDigest`**, and a break is `VS_REFUSED_TRACE_BROKEN` — never a warning and
never a retry. The `trace-broken` control replaces one output and the `A5`-input
control replaces one input; both fire the code
(`test_a_broken_output_digest_is_detected`, `test_a_broken_input_digest_is_detected`).

A stage that is not reached is `NOT_REACHED`, carries the terminal stage's output
digest as its own `inputDigest`, produces no `outputDigest`, and states why. It is
never omitted: `test_no_stage_is_omitted` asserts that the trace's stage list is
the declared list, and `VS_REFUSED_STAGE_SKIPPED` fires when a stage is missing
or the observed order differs from the declaration.

## 5. The status vocabulary

| Status | Meaning |
|---|---|
| `PASS` | the stage consumed the previous digest, produced its own, and its assertion is no stronger than its record |
| `STOP` | the stage produced its outcome and the chain must not continue; the stop carries the record that establishes it |
| `REFUSED` | the stage refused its input or found its record too weak; the chain cannot continue |
| `NOT_REACHED` | an earlier `STOP` or `REFUSED` prevented execution; the reason is recorded |

A `STOP` is not a `PASS`. `SELF_ISSUED` is a verification *outcome*, not a
verification success, and the stop code that carries it is
`VS_STOP_NO_INDEPENDENT_VERIFICATION` (`test_the_real_trace_stops_at_a12_with_self_issued`).
A `REFUSED` stage exits the CLI with status 1; a recorded `STOP` exits 0 because
the slice completed. `VS_REFUSED_STOP_NOT_RECORDED` fires when a `STOP` has no
record, no digest or no locator (`test_a_stop_with_no_record_is_refused`,
`test_the_stop_record_digest_must_match_the_file`).

## 6. The real artefact and the full trace

Both producer runs and the committed records are byte-identical. Digests are
shown truncated to 16 hex characters here; the full values are in
`evidence/a27/SLICE.json`.

| Stage | Status | inputDigest | outputDigest | Codes |
|---|---|---|---|---|
| A3 | PASS | `43861048faad6c87` | `11d5a576c51f9999` | NONE |
| A4 | PASS | `11d5a576c51f9999` | `18414f7d1cc5cc84` | NONE |
| A5 | PASS | `18414f7d1cc5cc84` | `8640c9a13a98e804` | NONE |
| A6 | PASS | `8640c9a13a98e804` | `a9be1da7de07cf00` | NONE |
| A7 | PASS | `a9be1da7de07cf00` | `ec18d9220518a0a6` | NONE |
| A8 | PASS | `ec18d9220518a0a6` | `b16d376ae0b2fa54` | NONE |
| A9 | PASS | `b16d376ae0b2fa54` | `ea67963abf16e9b1` | NONE |
| A10 | PASS | `ea67963abf16e9b1` | `5bf418cc5b014d98` | NONE |
| A12 | STOP | `5bf418cc5b014d98` | `b857ff11c7506237` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED`, `VS_STOP_NO_INDEPENDENT_VERIFICATION` |
| A14 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A15 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A16 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A18 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A19 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A17 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A20 | NOT_REACHED | `b857ff11c7506237` | — | — |
| A21 | NOT_REACHED | `b857ff11c7506237` | — | — |

**Counts: 17 stages declared, 8 `PASS`, 1 `STOP`, 0 `REFUSED`, 8 `NOT_REACHED`,
0 validation codes.** The four artefact digests, in full:

* shard `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed`
  (the member is at run 3, result index 2390, the same coordinates as the parent);
* statement `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582`;
* envelope `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9`;
* PAE (recomputed at A10) `9e08bc6c908d7964aa05af48a8e81c7806b6835febc31e9ecf022cb9c622280f`.

What the intermediate stages actually found, in one line each:

* **A3** derives all three fingerprints from the recorded rule, key, binding and
  region and re-hashes the finding's provenance record
  (`evidence/etp-t4/SAFETY-SITES.json`, `7fb1ef96…`).
* **A4** joins the instance to the finding by path, line and symbol, re-hashes the
  provenance record, and states the line-only source rule and the
  function-offset-and-extent machine-code rule without adding precision.
* **A5** admits `a1-sarif-results` `COMPLETE` with 4245 examined, 0 omitted and
  4245 distinct members, and derives the membership from the cited record rather
  than trusting a count. It also records that the same provenance record carries
  `t4-suppressions`, which A5 admits only `AGGREGATE_ONLY` with
  `CA_REFUSED_OMITTED_UNRECORDED`.
* **A6** finds no actionable suppression naming this identity; the register's 11
  records are all `NON_ACTIONABLE`, 0 members are disposed, and the register was
  admitted at a later evaluation candidate, so every candidate-bound record is
  refused stale.
* **A7** records `STILL_PRESENT` with `RESOLVED: 0`, and states that the delta
  compares the pre-extraction SARIF projection with the generalised identity model
  **over the same emission**. A7's own `noBaseline` entry says no second
  population for this area exists.
* **A8** locates the member in the single shard, re-hashes the shard, and checks
  that the union equals the parent exactly once (`missing: 0`, `duplicates: 0`).
* **A9** checks that the statement names the shard at the shard's byte digest,
  that the statement file's bytes hash to the index's digest, and that the
  statement's asserted state equals its record state.
* **A10** re-decodes the payload, re-hashes it to the statement digest, and
  recomputes the PAE to the recorded `9e08bc6c…`.

## 7. The stop at A12 and what it means

A12 records `SELF_ISSUED` for this envelope, `independentlyVerified: false`, and
three codes: `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT` and
`IV_REFUSED_SELF_ISSUED`. The root is a test-only HMAC-SHA256 key whose seed is
recorded inside the candidate tree, whose trust domain is `same-party`, and whose
`symmetric` and `selfIssued` fields are both true. The verifier holds the signer's
secret, so it could have produced the signature; nothing outside the producing
party vouched for these bytes.

The aggregate agrees: **0 of 4 envelopes independently verified**, 4
`SELF_ISSUED`. The stage stops with `VS_STOP_NO_INDEPENDENT_VERIFICATION`, and the
stop is established by

* record `evidence/a12/VERIFICATION.json`,
* SHA-256 `7cbdcdae7d7c5636c26b3a9f6141e6a0e345e6c8a281c926fc4b411f68991a48`,
* locator `/verifications[name=a8-shard-000]`,
* observed `SELF_ISSUED`, 0 of 4 independently verified.

**Why the slice stops and does not degrade.** Every later stage consumes an
independent verification. There is none, so authorisation has no verified
signature, the threshold has no distinct domain, the bundle inventory is empty,
the key inventory is one key with no second root, and the policy cannot admit.
Continuing would mean substituting a self-issued signature for an independent
one, which is the defect A12 exists to prevent. A14's own record refuses the
release action and A15's evaluation is `UNREACHABLE`; the slice does not need
those records to know the chain has no next stage, and it does not use them.

**The policy would deny.** The committed A20 decision is `DENY`, with five unmet
required obligations including `A12.independent-attestation`
(`state: UNMET`, `observed.count: 0`, "0 qualifying member(s), at least 1
required"), and `policy.default: deny`. The slice reads that record (SHA-256
`f4aebf28…`), verifies that every obligation's `recordSha256` is the digest of
the current source record (`sourceRecordsMatchCurrentTree: true`, no mismatches),
and verifies that the decision names the same `evidence/a12/VERIFICATION.json`
digest the slice's stop is established by. The counterfactual is labelled
`evaluatedByThisSlice: false`: this is the A20 record's own decision at the
record's own candidate (`f34e429f…`), not a re-evaluation at this base commit.
`test_the_policy_would_deny`, `test_the_policy_names_the_same_source_records` and
`test_the_policy_attestation_is_unmet_at_zero` assert it.

This is the point of the slice. The chain is connected through nine stages, the
digests meet at every seam, and the chain ends at an exact stage with an exact
code and an exact record. A release is denied — not because a summary says so,
but because the stage that would have to supply the independent root supplies
zero of them.

## 8. The stages not reached, and why

Each row names what the stage would consume and **what that item's own committed
record says**. Those outcomes are recorded by the owning item, at its own
candidate; the slice did not execute them and does not consume them.

| Stage | Item | Record | Recorded by that item | Why not reached |
|---|---|---|---|---|
| A14 | authorisation | `evidence/a14/AUTHORISATION.json` | the `release` action is `REFUSED`; no external reproducer is named | there is no independent verification to authorise |
| A15 | threshold | `evidence/a15/EVALUATION.json` | `release` is `UNREACHABLE` with `TH_REFUSED_THRESHOLD_UNREACHABLE` | there is no distinct external domain |
| A16 | Sigstore bundle | `evidence/a16/INVENTORY.json` | 0 bundles, 0 certificates, 0 certificate files | the chain produced a DSSE envelope, not a Sigstore bundle |
| A18 | key lifecycle | `evidence/a18/INVENTORY.json` | one key, 0 repositories, 0 metadata versions, `detectable: false` | there is no bundle to evaluate |
| A19 | correction status | `evidence/a19/PROPAGATION.json` | 11 corrections, 14 dependents invalidated, 0 valid; none authenticated | there is no key-lifecycle evaluation to correct |
| A17 | omission closure | `evidence/a17/STATUS.json` | the forward freeze is `OPEN`, 20 members declared | the forward freeze is not closed until A17 closes it |
| A20 | policy | `evidence/a20/DECISION.json` | `DENY`, 5 unmet required obligations | the record was evaluated at its own candidate, not on this chain |
| A21 | summary | `evidence/a21/SUMMARY.json` | `DENY` reconstructed from nine records; `replacesEvidence: false` | there is no per-artefact policy decision to summarise |

Two of those records concern this artefact directly and are worth naming, because
they are exactly the seams a per-stage test cannot see:

* A19 records a correction whose subject is **`A4/L3-md32-update/byteLength`**:
  a decimal reading of the `nm` size field was mistaken for a hexadecimal one, and
  the accepted extent is `0x165` (357). The superseded value is preserved in
  `evidence/a19/EVENTS.json` and is deliberately not reproduced in this document,
  so this document does not become a citation of the superseded record. The A4
  record the slice consumed already carries 357, so the correction is applied —
  but A19 also records that the correction is **prose-only and unauthenticated**
  (`SELF_ISSUED`). The slice's A4 output is therefore honest about the value and
  cannot be read as authenticating it.
* A17's forward freeze declares the A27 receipt as a required member. Producing
  this receipt satisfies the member predicate
  (`evidence/a27/RECEIPT.md`); it does not close the freeze, which remains `OPEN`
  until A17 closes it at its own record. A produced member is not a closed freeze.

## 9. The controls

`evidence/a27/CONTROLS.json` holds nine `controlOnly` rows — one per refusal code,
including the invocation code — and three positive rows. Each row mutates an
in-memory trace, an in-memory record, the artefact declaration or the invocation,
and asserts the exact code that fires. No row changes a committed record
(`test_the_controls_do_not_change_the_committed_records`).

| Control | Code it must fire | What is mutated |
|---|---|---|
| `trace-broken` | `VS_REFUSED_TRACE_BROKEN` | A7's output digest, so A8's input no longer equals it |
| `stage-skipped` | `VS_REFUSED_STAGE_SKIPPED` | A6 removed from the trace |
| `output-missing` | `VS_REFUSED_OUTPUT_MISSING` | A9 reports `PASS` with no output digest |
| `stage-overclaim` | `VS_REFUSED_STAGE_OVERCLAIM` | A9 asserts one more result than its record state |
| `admit-without-root` | `VS_REFUSED_ADMIT_WITHOUT_ROOT` | the trace is completed to A20 with `ADMIT` while A12 records 0 independent verifications |
| `summary-as-evidence` | `VS_REFUSED_SUMMARY_AS_EVIDENCE` | A12 cites the A21 summary as the record it verified |
| `stop-unrecorded` | `VS_REFUSED_STOP_NOT_RECORDED` | A12 is a `STOP` with no establishing record |
| `artefact-unbound` | `VS_REFUSED_ARTEFACT_UNBOUND` | the declared exact identity is a digest no result carries |
| `malformed-invocation` | `VS_REFUSED_USAGE` | the command line names no known command |

The positive rows assert that the real trace validates with no code
(`real-trace-validates`), that the real stop is bound to its record
(`real-stop-is-recorded`), and that the real trace has no omission
(`real-chain-has-no-omission`). A control proves that the refusal fires; it is
not evidence that a stage is correct.

## 10. The refusal table

A refusal is stable: a document, a receipt and a test cite it verbatim. The stop
code is listed after the refusals because it is **not** a refusal.

| Code | Condition | Enforced by |
|---|---|---|
| `VS_REFUSED_TRACE_BROKEN` | stage N's output digest is not stage N+1's input digest, or a stage is reached after a terminal stage | `test_digest_chain_links_every_consecutive_pair_forward`, `test_a_broken_output_digest_is_detected`, and the `trace-broken` control |
| `VS_REFUSED_STAGE_SKIPPED` | a declared stage is missing from the trace, out of order, or `NOT_REACHED` before any terminal stage | `test_a_skipped_stage_is_detected`, `test_no_stage_is_omitted`, and the `stage-skipped` control |
| `VS_REFUSED_OUTPUT_MISSING` | a `PASS`/`STOP` stage produces no digest, or a record a stage must consume is absent, or a post-A12 stage has no consumer contract | `test_a_stage_before_the_stop_has_an_output_and_a_later_stage_does_not` and the `output-missing` control |
| `VS_REFUSED_ARTEFACT_UNBOUND` | the artefact lacks a recorded identity, location, containing population or shard membership, or its fingerprints are not derivable | the `artefact-unbound` control and `test_the_artefact_identity_is_recomputed_not_copied` |
| `VS_REFUSED_STAGE_OVERCLAIM` | a stage reports a stronger state than its source record, an asserted value the record does not carry, or an aggregate that disagrees with its entries | `test_each_control_fires_its_own_code` and the `stage-overclaim` control |
| `VS_REFUSED_ADMIT_WITHOUT_ROOT` | the trace reaches `ADMIT`/`AUTHORISED`/`MET` while independent verification is zero | `test_the_slice_does_not_claim_a_release_pass` and the `admit-without-root` control |
| `VS_REFUSED_SUMMARY_AS_EVIDENCE` | a stage other than A21 reads an A21 summary in place of the record it must consume | the `summary-as-evidence` control and `test_the_document_states_what_is_not_run` |
| `VS_REFUSED_STOP_NOT_RECORDED` | a `STOP` carries no establishing record, digest or locator, or its digest is not the file's | `test_a_stop_with_no_record_is_refused`, `test_the_stop_record_digest_must_match_the_file` |
| `VS_REFUSED_USAGE` | the command line names no known command or an unknown option | `test_a_malformed_invocation_exits_two_and_prints_the_code` and the `malformed-invocation` control |
| `VS_STOP_NO_INDEPENDENT_VERIFICATION` | the verified envelope has no independent root: the stop code, not a refusal | `test_the_real_trace_stops_at_a12_with_self_issued` |

## 11. What the slice establishes, and what it does not

It **establishes**:

* that one real artefact has an identity, a location, a population and a shard,
  and that each of the four was re-derived rather than asserted;
* that the seventeen stages are declared, that nine were traversed, and that no
  stage was omitted (`test_no_stage_is_omitted`);
* that the digests meet at every seam, in both directions
  (`test_digest_chain_links_every_consecutive_pair_forward`,
  `test_digest_chain_links_every_consecutive_pair_backward`);
* that the chain stops at **A12**, with outcome `SELF_ISSUED` and 0 of 4
  independently verified, and that the stop is established by a named record at a
  named digest and locator (`test_the_real_trace_stops_at_a12_with_self_issued`,
  `test_the_stop_is_bound_to_its_record`);
* that every stage after the stop is `NOT_REACHED` with a reason
  (`test_every_stage_after_the_stop_has_a_reason`);
* that the committed policy record says `DENY` and names the same source records
  (`test_the_policy_would_deny`, `test_the_policy_names_the_same_source_records`).

It **does not establish**:

* that any stage's claim is true. A recomputed fingerprint proves derivation, not
  that the finding is real, reachable, severe or current; a frame proves framing,
  not authenticity (Earned Trust Article 1).
* that the release is verified. Zero envelopes are independently verified; the
  `SELF_ISSUED` outcome is not a pass, and no relabelling changes that.
* that the post-stop records are consumed. Their outcomes are their own items'
  records at their own candidates; the slice did not execute them.
* that the policy was re-evaluated at this base commit. `evaluatedByThisSlice` is
  false, and the record's candidate differs from the slice's base commit.
* that the population is a census. The artefact is one member of a
  mixed-candidate population, and A5's `COMPLETE` is about the record-set, not
  the tree it was drawn from.
* any graduation. A recorded stop at A12 is `NOT_RUN` as a release, and nothing
  here changes any `OWNERSHIP_RECONSTRUCTED`, `SAFETY_DISCHARGED` or
  `SAFE_COMPATIBLE` state (Article 3: deferred is never pass).

## 12. `NOT_RUN`

* a real external trust root, a production signature primitive, and any party in
  a distinct trust domain — the reason the chain stops at A12;
* per-artefact consumers for A14, A15, A16, A18, A19, A17, A20 and A21 — the
  slice declares them and refuses to fabricate them;
* a live re-evaluation of the A20 policy at this base commit;
* independent cryptographic verification of the HMAC signature inside this tool —
  A12's check 7 records it, and the slice consumes that record;
* a multi-shard export (the A8 export is one shard under the 5,000-result limit);
* a second artefact, a second candidate, and any census claim;
* independent review, BOUNDARY and SEAL evidence, and the Rust test suite — no
  `src/` file was modified by this item.
