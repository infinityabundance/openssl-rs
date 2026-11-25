# A21 receipt — a summary that cannot outlive its evidence

## 1. Identity of this batch

| field | value |
|---|---|
| item | A21 (verification-summary attestations after policy evaluation; a summary never replaces the evidence for independent reconstruction) |
| branch | `staging` |
| HEAD at the start | `ad49d33f2a…` (`a20: a conjunction of obligations, denied by default`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 29 11 0 5 16` (total 45, used 29, free 11, available **16** GiB); `Swap: 45 37 8` |
| `free -g` before the suite | `Mem: 45 30 10 0 5 15` (available **15** GiB); `Swap: 45 37 8` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), repository at `/work`, Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool or evidence modified |

The machine had 16 GiB available, below the 24 GiB floor `AGENTS.md` §6.1 sets
before a build. No build was needed or run: every gate is Python-only. The derived
cap would have been `min(8, 16 - 16) = 0`, below the 2 GiB floor, so **no new
court was started**; the already-running court has a hard 6 GiB cap and was
reused, as A7–A20 did. Every command that reads or runs the tree ran inside it.
No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/verification_summary.py` | 1,655 lines | the summary model, the recount, reconstruction through A20's own obligation mapping, the 12 refusal codes, the statement/envelope and `SELF_ISSUED` label, the consumer contract, 12 controls and the CLI |
| `forensics/tools/tests/test_verification_summary.py` | 523 lines | 42 controls: one per refusal code, recounting from a deliberately inconsistent decision, every source-digest failure, the coverage gap in both directions, decision upgrade, overclaim, the real summary and reconstruction, determinism, CLI exit codes and printed codes, document synchronisation |
| `docs/VERIFICATION-SUMMARIES.md` | 309 lines | the normative document: the problem, the summary and reconstruction contracts, the recount rule, the marker and consumer duty, the signature boundary and A12 caveat, the real summary, the controls, all 12 codes, the non-claims and `NOT_RUN` |
| `evidence/a21/build_evidence.py` | 107 lines | deterministic producer of the four records; it verifies the envelope and the reconstruction before writing |
| `evidence/a21/SUMMARY.json` | record | the real summary: `DENY`, 8 obligations, 3 `MET`, 5 `UNMET`, 9 cited records, `replacesEvidence: false` |
| `evidence/a21/SUMMARY.envelope.json` | record | the DSSE envelope over the Statement v1 whose subject is A20's decision record |
| `evidence/a21/RECONSTRUCTION.json` | record | the output of `reconstruct`: per-obligation summary/decision/recomputed states, the recount, and `equal: true` |
| `evidence/a21/CONTROLS.json` | record | 12 `control-only` fixtures, one per code |
| `docs/ETP-TODO.md` | 1 row | the A21 row replaced from `TODO` to `DONE`; no other row touched |
| `evidence/a21/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `SUMMARY.json` | `f1321b52aa0db4b2d5b66d471ede2b31a2984c17f60c17defc8d62356fc49061` |
| `SUMMARY.envelope.json` | `f02f098a0e2dfa4728146eb419144a902a4f41fb13a96a44f6cc9303218eefdd` |
| `RECONSTRUCTION.json` | `9641a4c8c7f1566d54047d4cbb38a3ff683b68eb86493012fcfc0184b0bb7cea` |
| `CONTROLS.json` | `9939b551344a9b545ca6542107fd42a305db2cdb6b0e495e4f3acc57fc1bc44d` |

The tool's digest is
`8995427317b04be3875dfe1306a687789e12462fbc7dbc14bd85991c90f19470`.

## 3. The rule

> A summary is produced after policy evaluation and condenses a decision. Every
> count in it is recounted from its obligation list and derivable from the cited
> sources; every source is cited by digest; and a consumer that cites the summary
> in place of the sources is refused. The summary may not assert anything the
> decision does not contain.

A summary that is not reconstructible will drift from its evidence and then
outlive it, because it is shorter, easier to quote and often signed. A21 binds
the summary to the exact bytes it read, to the decision record by digest, and to
the policy's own mapping — and refuses the three conventions that let it drift: a
copied count, an unidentified source, and a consumer that stops re-reading.

## 4. The real summary and its reconstruction

`reconstruct evidence/a21/SUMMARY.json` prints:

```
reconstruct: code=AS_OK decision=DENY obligations=8 met=3 unmet=5 unknown=0 notApplicable=0 equal=true summaryDigest=f1321b52aa0db4b2
reconstruct: unmet = A06.suppression-member-identities,A12.independent-attestation,A14.release-authorised,A15.release-threshold-met,A17.forward-freeze-closed
```

| obligation | state | source |
|---|---|---|
| `A05.populations-admitted` | `MET` | `evidence/a5/ADMISSION.json` |
| `A06.suppression-member-identities` | **`UNMET`** | `evidence/a6/SUPPRESSIONS.json` |
| `A07.delta-resolution-conditions` | `MET` | `evidence/a7/DELTA.json` |
| `A12.independent-attestation` | **`UNMET`** | `evidence/a12/VERIFICATION.json` |
| `A14.release-authorised` | **`UNMET`** | `evidence/a14/AUTHORISATION.json` |
| `A15.release-threshold-met` | **`UNMET`** | `evidence/a15/EVALUATION.json` |
| `A17.forward-freeze-closed` | **`UNMET`** | `evidence/a17/STATUS.json`, corroborated by `evidence/a17/FREEZE-forward.json` |
| `A19.retraction-propagated` | `MET` | `evidence/a19/PROPAGATION.json` |

The decision digest is `7f5a3cb88972ecfe7506173ee25125b9be513f74c7ccf6ed801fe73076f40495`,
the SHA-256 of `evidence/a20/DECISION.json`'s bytes and of its canonical form.
Nine records are cited: the eight primary sources and the A17 corroborating
record. The reconstruction reads the policy from `evidence/a20/POLICY.json`,
checks its canonical digest against the decision's `policyDigest`
(`a3fcce8f…`), and recomputes every obligation with
`policy_engine._evaluate_obligation` over the verified bytes. Every summary state,
decision state and recomputed state agree; the recomputed counts equal the
summary's; `equal` is `true`.

`verify` prints:

```
verify: code=AS_OK label=SELF_ISSUED keyid=test-only:hmac-sha256:8e10a5a15d233d54 decision=DENY met=3 unmet=5 unknown=0 notApplicable=0 equal=true summaryDigest=f1321b52aa0db4b2 decisionDigest=7f5a3cb88972ecfe
```

No refusal code fires on the real records.

## 5. The controls

`CONTROLS.json` holds **12** `control-only` fixtures, one per refusal code. Each
records the code it establishes and the codes observed; the producer refuses to
emit a fixture that does not establish its code, and refuses a missing code.

| control | code |
|---|---|
| `consumer-cites-summary` | `AS_REFUSED_SUMMARY_AS_EVIDENCE` |
| `counts-disagree-with-list` | `AS_REFUSED_COUNTS_MISMATCH` |
| `source-removed` | `AS_REFUSED_EVIDENCE_ABSENT` |
| `source-bytes-changed` | `AS_REFUSED_SOURCE_DIGEST_MISMATCH` |
| `obligation-without-digest` | `AS_REFUSED_NO_SOURCE_DIGEST` |
| `obligation-removed` | `AS_REFUSED_COVERAGE_GAP` |
| `obligation-duplicated` | `AS_REFUSED_DUPLICATE_OBLIGATION` |
| `decision-upgraded` | `AS_REFUSED_DECISION_UPGRADED` |
| `obligation-added` | `AS_REFUSED_OVERCLAIM` |
| `no-source-manifest` | `AS_REFUSED_NON_RECONSTRUCTIBLE` |
| `summary-unsigned` | `AS_REFUSED_SUMMARY_UNSIGNED` |
| `signed-summary-mutated` | `AS_REFUSED_SUMMARY_MUTATED` |

The tests additionally change the **corroborating** A17 record, the decision
record and the policy in a temporary mirror of the real tree, and exercise the
coverage gap in both directions. A control is not evidence about any tracked
record; it is evidence that the refusal fires when the named wrong conclusion is
presented.

## 6. Defects found

**None in an existing record.** No gate rejected an existing record because of
this item. The real decision is `DENY` on its own five unmet obligations, and the
summary reports exactly that; no check was relaxed and no expected state was
changed.

Development corrections, before any record was produced:

* **The first `verify` compared the envelope payload with the summary bytes.** The
  payload is the Statement, not the summary, so every real verification was
  refused `AS_REFUSED_SUMMARY_MUTATED`. Old: `verify` exited 1 on the real
  envelope. New: the summary file must be the canonical summary form and the
  statement's predicate must carry exactly that summary; `verify` exits 0.
* **The first `reconstruct` read a corroboration source as `source.record`.** The
  policy spells a corroborating source at the top level while the decision nests
  it under `source`, so the real A17 corroboration resolved to `None`. Old: every
  real reconstruction refused `AS_REFUSED_EVIDENCE_ABSENT` with `source None`.
  New: both forms are read, and the nine cited records reconstruct.
* **`_decision_sources` was written and never called.** Old: dead code.
  New: removed.
* **A test rewrote the decision's totals in memory without rewriting the record.**
  Old: the test observed `AS_REFUSED_SOURCE_DIGEST_MISMATCH` (the summary was no
  longer about the file). New: the record is rewritten and the test observes
  `AS_REFUSED_COUNTS_MISMATCH`, which is the check it means to exercise. This is
  a test correction, not a product defect.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 29 11 0 5 16` (available 16 GiB); `Swap: 45 37 8` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1606 tests in 240.017s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,564 pre-existing tests are present (1,564 + 42 verification-summary = 1,606), none removed, none ignored |
| focused A21 controls | `python3 -m unittest forensics.tools.tests.test_verification_summary` | `Ran 42 tests in 0.375s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on the four records | `json.tool ok evidence/a21/SUMMARY.json`, `SUMMARY.envelope.json`, `RECONSTRUCTION.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a21/build_evidence.py` and `--out /tmp/a21b` | `a21: decision=DENY obligations=8 met=3 unmet=5 unknown=0 notApplicable=0 sources=9 topLevel=summary replacesEvidence=false decisionDigest=7f5a3cb88972ecfe summaryDigest=f1321b52aa0db4b2 label=SELF_ISSUED keyid=test-only:hmac-sha256:8e10a5a15d233d54 controls=12 codesCovered=12/12 commit=ad49d33f2` twice; `a21: unmet = A06…,A12…,A14…,A15…,A17…` |
| producer byte-identity | `cmp` of each name, run1 vs run2 vs committed | `identical SUMMARY.json`, `SUMMARY.envelope.json`, `RECONSTRUCTION.json`, `CONTROLS.json` |
| CLI, summarise | `python3 forensics/tools/verification_summary.py summarise` | `summary: code=AS_OK decision=DENY obligations=8 met=3 unmet=5 unknown=0 notApplicable=0 sources=9 decisionDigest=7f5a3cb88972ecfe summaryDigest=f1321b52aa0db4b2 replacesEvidence=false`; exit 0 |
| CLI, reconstruct | `python3 forensics/tools/verification_summary.py reconstruct evidence/a21/SUMMARY.json` | `reconstruct: code=AS_OK decision=DENY obligations=8 met=3 unmet=5 unknown=0 notApplicable=0 equal=true summaryDigest=f1321b52aa0db4b2`; exit 0 |
| CLI, verify | `python3 forensics/tools/verification_summary.py verify evidence/a21/SUMMARY.json evidence/a21/SUMMARY.envelope.json` | `verify: code=AS_OK label=SELF_ISSUED keyid=test-only:hmac-sha256:8e10a5a15d233d54 decision=DENY met=3 unmet=5 unknown=0 notApplicable=0 equal=true summaryDigest=f1321b52aa0db4b2 decisionDigest=7f5a3cb88972ecfe`; exit 0 |
| CLI, refusal | `python3 -m unittest …test_a_refused_reconstruction_exits_one_and_prints_the_code` | exit 1 with `AS_REFUSED_COUNTS_MISMATCH` printed |
| CLI, usage | `python3 forensics/tools/verification_summary.py reconstruct evidence/a21/absent.json` | exit 2 with `AS_USAGE` printed |
| worktree | `git --no-pager status --porcelain` | see §10 |

## 8. Obligations retained

* **The signature is not authentication.** A10's test-only HMAC-SHA256 key is
  derived from a fixed public seed. The envelope proves the summary's bytes are
  unchanged since signing; A12 records it `SELF_ISSUED`, and no external root
  exists.
* **Digest binding is not commit binding.** A checkout that rewrites the decision
  and its sources consistently defeats the digests. An external anchor is
  A12/A16's subject.
* **Reconstruction re-derives the decision, not the producing tools.** Whether
  each source record was produced by its declared tool, and whether its result is
  correct, is A2's and the owning item's question.
* **A9's predicate registry is closed.** `intoto.decode` cannot validate the A21
  predicate type, and another item's tool was not edited. A9's subject
  constructor and verifier are reused; the predicate is validated here against
  the same Statement v1 shape. Registration remains open.
* **The policy path is a fixed default.** `reconstruct` reads
  `evidence/a20/POLICY.json` and checks its canonical digest against the
  decision's `policyDigest`; a decision about a policy at another path needs that
  path passed explicitly. The digest check, not the path, is the binding.
* **A21 is downstream of A20.** If A20's decision is regenerated, this summary
  goes stale; `test_the_real_summary_is_the_live_summary` and
  `test_the_committed_reconstruction_is_the_live_reconstruction` name
  `python3 evidence/a21/build_evidence.py` as the repair. Adding A21's records
  did not change any record A20 cites.
* **The summary inherits A20's semantics.** A summary of a `DENY` is not a
  judgement that the five unmet obligations are the only defects; it reproduces
  the recorded mapping.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## 9. `NOT_RUN`

* An independent signer, a production key, a key ceremony or a trust root: none
  exists (A12/A14/A16).
* An external timestamp or transparency-log inclusion of the summary envelope:
  A16's subject, not run here.
* A9 registry registration of the A21 predicate type: retained (§8).
* Reconstruction over any action other than the recorded `release` decision: the
  other A14 actions are not evaluated.
* A downstream consumer in another repository citing this summary: `consume` and
  its control exercise the contract, not an external party.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite: no Rust
  source was modified, so no rebuild and no `cargo test` is claimed.

## 10. Forward-freeze member and worktree

`evidence/a17/FREEZE-forward.json` declares **one** A21 member:

* **satisfied:** `a21-receipt` — `evidence/a21/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

Still open under the same freeze (**16** members, not this item's work):
`a22-receipt` … `a27-receipt` (6 remaining, A22–A27), `b0-registry`,
`b0-service-configuration`, and `b1-receipt` … `b8-receipt` (8). The
`a18-receipt`, `a19-receipt`, `a20-receipt` and `a21-receipt` members are
produced. The freeze remains `state: OPEN`; it was not amended and not closed,
and this receipt does not claim any of those members.

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
?? docs/VERIFICATION-SUMMARIES.md
?? evidence/a21/
?? forensics/tools/tests/test_verification_summary.py
?? forensics/tools/verification_summary.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row (A21),
and `git diff --stat` reports one insertion and one deletion for that file.

## 11. Correction (2026-11-25): rebind the summary to the A20 decision at C9

**Cause.** A20 was regenerated at `4390c0f3` (C9) because A19's
`evidence/a19/PROPAGATION.json` moved at C8. That re-freeze moved the decision
digest from `7f5a3cb8…` to `f4aebf28…` and the A19 propagation source digest from
`982054f9…` to `892be6ef…`. The summary, its envelope and the reconstruction were
re-derived by `evidence/a21/build_evidence.py`, not hand-edited.

**Old and new.**

| field | old | new |
|---|---|---|
| `SUMMARY.decisionDigest` | `7f5a3cb88972ecfe7506173ee25125b9be513f74c7ccf6ed801fe73076f40495` | `f4aebf28f8e79f0a50704df4f39e9332d670433055d007936c4588af91b3044e` |
| `SUMMARY.obligations[A19.retraction-propagated].sourceDigest` | `982054f9fb76777e6672137006c0b9388bc0d8c0245eda5638859cdd3d6d78f3` | `892be6ef2d394e7724f29563cb993778d844f90349c6325a0f195279e5003278` |
| `SUMMARY.reconstructedFrom[evidence/a19/PROPAGATION.json]` | `982054f9…` | `892be6ef…` |
| `SUMMARY.json` | `f1321b52aa0db4b2d5b66d471ede2b31a2984c17f60c17defc8d62356fc49061` | `e1d3c8a9bb490901ca85533466d73437081fbef9b7aa2194ee2f80c8229b068f` |
| `SUMMARY.envelope.json` | `f02f098a0e2dfa4728146eb419144a902a4f41fb13a96a44f6cc9303218eefdd` | `859adf379105794b801b739f37af669f13254872b3799169659057b0c48516b7` |
| `RECONSTRUCTION.json` | `9641a4c8c7f1566d54047d4cbb38a3ff683b68eb86493012fcfc0184b0bb7cea` | `9b74d0bf43a8a7eeb6d4f05f587f1d1613a7fe0f2647e0a909f267760f424197` |
| `CONTROLS.json` | `9939b551…` | byte-identical |

**Outcome unchanged.** The decision is still `DENY`, with 8 obligations,
`met=3 unmet=5 unknown=0 notApplicable=0` and the same unmet set (`A06`, `A12`,
`A14`, `A15`, `A17`). Every obligation's state is identical; only the digest
bindings above moved. The envelope was re-derived by the same A10 test-only
HMAC-SHA256 signer (`test-only:hmac-sha256:8e10a5a15d233d54`); no new key and no
new signer.

**History.** The digests in §4 and the decision digest `7f5a3cb8…` remain this
batch's original values; §11 supersedes them by naming both values rather than
overwriting the history.

**Gates.** `python3 evidence/a21/build_evidence.py` reproduces the committed
bytes and prints `decision=DENY ... decisionDigest=f4aebf28f8e79f0a`;
`test_verification_summary` is 42/42 OK.

**Downstream.** `docs/VERIFICATION-SUMMARIES.md` and `docs/VERTICAL-SLICE.md`
quoted the old decision digest and were updated to the new one; A16 and A11's
frozen populations still name it, and are the remaining links.
