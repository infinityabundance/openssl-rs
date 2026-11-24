# A20 receipt — a deterministic policy engine

## 1. Identity of this batch

| field | value |
|---|---|
| item | A20 (deterministic policy engine: conjunction of obligations, not a score; denial-by-default; a candidate may not choose a permissive policy for itself) |
| branch | `staging` |
| HEAD at the start | `58aeb2ee01000638cc545e4cad7c9ec3b5ff9672` (`a17: record the freeze-time state, and keep the live view live`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 28 12 0 5 17` (total 45, used 28, free 12, available **17** GiB); `Swap: 45 37 8` |
| `free -g` at the end | `Mem: 45 29 11 0 5 16` (available **16** GiB); `Swap: 45 37 8` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool or evidence modified |

The machine had 17 GiB available, below the 24 GiB floor AGENTS.md §6.1 sets
before a build. No build was needed or run: every gate is Python-only. The
derived cap would have been `min(8, 17 - 16) = 1 GiB`, below the 2 GiB floor, so
**no new court was started**; the already-running court has a hard 6 GiB cap and
was reused, as A7–A19 did. Every command that reads or runs the tree ran inside
it. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/policy_engine.py` | 1,954 lines | the policy, pin, predicate and decision model, the 16 refusal codes, strict record reading, the two-run determinism check, the controls and the CLI |
| `forensics/tools/tests/test_policy_engine.py` | 530 lines | 40 controls: one per refusal code, conjunction with each obligation individually unmet, `UNKNOWN` never `MET`, an absent source, determinism in one process and two, canonical order in both forms, the real `DENY`, the synthetic `ADMIT`, the CLI and document synchronisation |
| `docs/POLICY-ENGINE.md` | 464 lines | the normative document: the problem, the rule, the policy and pin contract, the order and determinism, the real policy and decision, the controls, all 16 codes, the residuals and `NOT_RUN` |
| `evidence/a20/build_evidence.py` | 350 lines | deterministic producer of the four records |
| `evidence/a20/POLICY.json` | record | the real policy: eight obligations, `default: "deny"`, `scores: false` |
| `evidence/a20/POLICY-PIN.json` | record | the pin: digest, pinning role and identity, candidate |
| `evidence/a20/DECISION.json` | record | `DENY`, five unmet obligations, no code, no timestamp |
| `evidence/a20/CONTROLS.json` | record | 19 `control-only` fixtures: 16 codes (with a second score and a second order control), one positive |
| `forensics/tools/release_gate.py` | +125 lines, 1 replaced | item 9 `check_policy`, its constants, docstring entry, CLI arguments and four self-test cases; items 1–8 unchanged |
| `forensics/tools/tests/test_release_gate.py` | +42 lines | four gate controls for item 9 |
| `docs/ETP-TODO.md` | 1 row | the A20 row replaced from `TODO` to `DONE`; no other row touched |
| `evidence/a20/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `POLICY.json` | `2575ca0edc5d861baee9668ca647fc04addd06508ec0ad31bfed925ccb0ce15c` |
| `POLICY-PIN.json` | `4dead25e470149e3e22f09e3a2e1e786eabfb4d8ff8f6237fce1b8fe8b4c5553` |
| `DECISION.json` | `7f5a3cb88972ecfe7506173ee25125b9be513f74c7ccf6ed801fe73076f40495` |
| `CONTROLS.json` | `e310ea2b0789d23b0c7d5849e2751e74bdf04b590725059e62a74360c3fd3ef5` |

The engine's own digest is
`f4dcdf2e86317be3eb1fc40860912098ea3599fb460b5716ad38e5ec01ccbbf4`.

## 3. The rule

> A policy is a conjunction of obligations, never a score. The decision is
> `ADMIT` only when every required obligation is `MET`. The default is deny. An
> obligation whose record is absent is `UNKNOWN` and the decision is `DENY`; it is
> never skipped. `UNKNOWN` is never `MET`. The policy is pinned separately, and a
> candidate may not choose the policy that judges it.

A score hides which obligation failed. An unevaluated obligation becomes a pass.
A candidate-chosen policy makes every other obligation meaningless. A20 removes
all three: the decision names each obligation and its state, an unevaluable
obligation is a named `UNKNOWN`, and the pin plus the candidate-producer check
refuse a self-selected policy.

## 4. The policy and the pin

`POLICY.json` is version 1 of `release-policy`, digest
`a3fcce8f195216c714f7d7cca228ee4cbca001d986b8104b6d168ee9152afacf`. Its eight
obligations are declared in ascending id order and each names the record it
reads:

| obligation | source | predicate |
|---|---|---|
| `A05.populations-admitted` | `evidence/a5/ADMISSION.json#/populations` | every state in the A5 vocabulary; no refused declaration keeps the state it declared |
| `A06.suppression-member-identities` | `evidence/a6/SUPPRESSIONS.json#/records` | no record classified `suppression`, declaring `ACTIVE`, with no member identities |
| `A07.delta-resolution-conditions` | `evidence/a7/DELTA.json#/deltas` | no refused delta records `RESOLVED`; no delta with a code records `RESOLVED` |
| `A12.independent-attestation` | `evidence/a12/VERIFICATION.json#/verifications` | at least one `independentlyVerified` |
| `A14.release-authorised` | `evidence/a14/AUTHORISATION.json#/actions/release` | `recorded.outcome` is `AUTHORISED` |
| `A15.release-threshold-met` | `evidence/a15/EVALUATION.json#/evaluations/release` | `outcome` is `MET` |
| `A17.forward-freeze-closed` | `evidence/a17/STATUS.json#/forwardFreeze`, corroborated by `evidence/a17/FREEZE-forward.json` | `state` is `CLOSED`, `closed` is true, both records agree |
| `A19.retraction-propagated` | `evidence/a19/PROPAGATION.json#/events` | no `retract` event has a `VALID` dependent |

The producer that established the policy is recorded as
`{role: maintainer, identity: P-PRINCIPAL}` with `independentOfCandidate: false`;
A14 records `P-CAMPAIGN` as the candidate's producer, read from
`evidence/a14/AUTHORISATION.json#/actions/release/context/evidenceProducer`.

`POLICY-PIN.json` records `policyDigest`, `pinnedAt` (`2026-11-24`), `pinnedBy`
(`{role: maintainer, identity: P-PRINCIPAL}`) and the candidate. Both identity
tokens are the project's undeclared tokens: A14 maps both to the same undeclared
party, so the pin establishes **digest binding and token inequality, not party
independence**. That is a retained obligation, not a claim (§9).

## 5. The real decision

`python3 forensics/tools/policy_engine.py evaluate` prints:

```
decision: DENY codes=NONE obligations=8 required=8 met=3 unmet=5 unknown=0 notApplicable=0
```

| obligation | state | what the record says |
|---|---|---|
| `A05.populations-admitted` | `MET` | 16 populations, every state in the vocabulary, 0 refused declarations keeping their declared state |
| `A06.suppression-member-identities` | **`UNMET`** | 8 of 11 records declare an `ACTIVE` suppression and record no member identity |
| `A07.delta-resolution-conditions` | `MET` | 4 deltas, 0 `RESOLVED` dispositions, 0 refused delta recording one |
| `A12.independent-attestation` | **`UNMET`** | 0 of 4 envelopes are `INDEPENDENTLY_VERIFIED`; all 4 are `SELF_ISSUED` |
| `A14.release-authorised` | **`UNMET`** | the recorded `release` outcome is `REFUSED` |
| `A15.release-threshold-met` | **`UNMET`** | the `release` threshold outcome is `UNREACHABLE` |
| `A17.forward-freeze-closed` | **`UNMET`** | `state` is `OPEN`, `closed` is `false`; the freeze record also says `OPEN` |
| `A19.retraction-propagated` | `MET` | 11 events including 5 retractions, 0 `VALID` dependents |

**No refusal code fires.** Every source record was present, readable, strict JSON,
its locator resolved and its declared producing tool exists, so the denial is
carried by the five unmet obligations and nothing else. This is the honest
expected result: `0` independently verified attestations, `0` authorised release
actions, `0` met thresholds, `0` bundles and `0` key repositories, and an `OPEN`
forward freeze. It is recorded, not tuned away: no obligation was softened and
no expected state was changed to reach a different answer.

## 6. The controls

`CONTROLS.json` holds **19** `control-only` fixtures: one per refusal code (16),
a second score control and a second order control
(`weighted-obligation`, `decision-order`) and one positive.
Each records the code it establishes and the codes observed; the producer refuses
to emit a fixture that does not establish its code, and refuses a missing code.

The required wrong conclusions are covered: a score policy and a weighted
obligation (`score-policy`, `weighted-obligation`), a default-allow policy
(`default-allow`), an unevaluated obligation treated as a pass
(`unevaluated-as-pass`), an amended policy against its pin (`policy-amended`), a
candidate-supplied policy (`policy-from-candidate`), a self-waiver
(`self-waiver`), a duplicate obligation (`duplicate-obligation`), a reordered
decision (`decision-order`), and a contradiction between two sources
(`contradiction`). `weighted-obligation` observes both `PE_REFUSED_SCORE` and
`PE_REFUSED_POLICY_INVALID` (a weight is also an undeclared field); both are
recorded.

**What the positive control establishes.** Two synthetic obligations, both `MET`,
reach `ADMIT` with no code, so the refusals are not vacuous and the engine is not
a machine that always says `DENY`.
**What it does not establish.** That any real obligation is met, that the real
policy is admissible, or that `ADMIT` would be correct for this candidate.

## 7. Defects found

**None in an existing record.** No gate rejected an existing record because of
this item, and the five unmet obligations are the records' own state, not a check
to repair. No check was relaxed.

Development corrections, before any record was produced:

* the first control fixtures read `{"source": {"facts": ...}}` with a `/facts`
  locator, so every synthetic obligation was `UNEVALUATED`; the wrapper was
  removed and the predicates now resolve. Old: all fixtures `UNEVALUATED`. New:
  each establishes its code.
* `control_policy` shared the caller's obligation objects, so the
  `weighted-obligation` fixture added a `weight` that leaked into every later
  fixture. Old: eleven fixtures failed with `PE_REFUSED_SCORE`. New: the policy
  deep-copies its obligations.
* `verify_pin` first compared the candidate's producer with the **pin's own
  candidate block**, which is the same candidate by construction, so the real pin
  was refused as `PE_REFUSED_POLICY_FROM_CANDIDATE`. Old: `verify-pin` exit 1 on
  the real records. New: only the pinning identity is compared with the
  candidate's producer, and `verify-pin` exits 0 with `code=PE_OK`.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 28 12 0 5 17` (available 17 GiB); `Swap: 45 37 8` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1564 tests in 238.457s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,520 pre-existing tests are present (1,520 + 40 policy + 4 gate = 1,564), none removed, none ignored |
| focused A20 controls | `python3 -m unittest forensics.tools.tests.test_policy_engine` | `Ran 40 tests in 0.716s`; `OK` |
| focused gate controls | `python3 -m unittest forensics.tools.tests.test_release_gate` | `Ran 29 tests`; `OK` (25 before this item; 4 new) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on the four records | `json.tool ok` `POLICY.json`, `POLICY-PIN.json`, `DECISION.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a20/build_evidence.py --out /tmp/a20a` and the same to `/tmp/a20b` | `a20: policy=release-policy digest=a3fcce8f195216c7 version=1 default=deny scores=false obligations=8 pin=a3fcce8f195216c7 candidate=58aeb2ee0 decision=DENY codes=NONE met=3 unmet=5 unknown=0 notApplicable=0 controls=19 codesCovered=16/16 positives=1 commit=58aeb2ee0` twice; `a20: unmet = A06.suppression-member-identities,A12.independent-attestation,A14.release-authorised,A15.release-threshold-met,A17.forward-freeze-closed` |
| producer byte-identity | `cmp` of each name, run1 vs run2 vs committed | `identical run1=run2=committed POLICY.json`, `POLICY-PIN.json`, `DECISION.json`, `CONTROLS.json` |
| CLI, evaluate | `python3 forensics/tools/policy_engine.py evaluate` | `decision: DENY codes=NONE obligations=8 required=8 met=3 unmet=5 unknown=0 notApplicable=0`; `unmet: A06...,A12...,A14...,A15...,A17...`; `unknown: NONE`; `notApplicable: NONE`; exit 1 |
| CLI, verify-pin | `python3 forensics/tools/policy_engine.py verify-pin` | `pin-check: code=PE_OK problems=0`; `decision: DENY codes=NONE unmet=A06...,A12...,A14...,A15...,A17...`; exit 0 |
| CLI, verify-decision | `python3 forensics/tools/policy_engine.py verify-decision` | `decision-check: code=PE_OK decision=DENY order=8`; exit 0 |
| CLI, explain | `python3 forensics/tools/policy_engine.py explain A17.forward-freeze-closed` | `obligation: id=A17.forward-freeze-closed state=UNMET required=true codes=NONE`; corroboration `record=evidence/a17/FREEZE-forward.json state=UNMET observed={"expected":"CLOSED","value":"OPEN"}`; exit 1 |
| release gate, before | `python3 forensics/tools/release_gate.py --json` (court) | `verdict REFUSED refusals 33`; `19 RG_CLAIM_UNCERTIFIABLE_EVIDENCE, 11 RG_CLAIM_HISTORICAL_EVIDENCE, 1 RG_PACKAGE_MISSING, 1 RG_AUTHORISATION_REFUSED, 1 RG_THRESHOLD_UNMET`; exit 1 |
| release gate, after | the same command | `verdict REFUSED refusals 34`; the same rows plus `1 RG_POLICY_DENIED`, whose detail is `decision=DENY unmet=A06...,A12...,A14...,A15...,A17... codes=NONE`; items 1–8 unchanged; exit 1 |
| gate self-test | `python3 forensics/tools/release_gate.py --self-test` | `release-gate self-test: ok (29 cases)` (25 before this item) |
| worktree | `git --no-pager status --porcelain` | see §12 |

On the host, outside the court and with valgrind absent, the before-run reports 34
refusals because the instrument check adds `RG_INSTRUMENT` (`IQ_VERSION_COMMAND`);
item 9 adds its row there too. The court figures above are the ones this receipt
claims.

## 9. Obligations retained

* **The pin is not an external anchor.** It is a digest recorded beside the bytes
  it names, in the same tree. A writer who can amend both is not detected. An
  external root is A12's subject.
* **Token inequality is not party inequality.** The engine refuses an equality
  between the pinning/establishing identity and the candidate's producer. A14
  records no declared parties, so the real policy is recorded
  `independentOfCandidate: false` and no independence is claimed. Party-level
  separation is A14/A15's.
* **The policy's author is the project itself.** `P-PRINCIPAL` is an undeclared
  token; the policy is not independently established, and A20 does not claim it
  is.
* **The engine does not re-run the producing tools.** It records each record's
  sha256 and checks that the named tool exists; whether the tool produced the
  record, and whether its result is correct, is A2's and the owning item's.
* **A6's `UNMET` is about declarations.** The eight records declare `ACTIVE`; A6
  admits all eleven as `NON_ACTIONABLE`, so no suppression is in force. The
  obligation reads the declaration, which is the claim under governance.
* **A7 and A19 are `MET` on negative results.** No delta records `RESOLVED` and no
  retraction leaves a `VALID` dependent. That is not a proof that none exists; it
  is what the records state.
* **A17's corroboration is two records, not two parties.**
* **The decision record can go stale.** It binds each source's sha256; a later
  change makes the committed decision stale, and
  `test_the_committed_decision_matches_a_live_evaluation` names
  `python3 evidence/a20/build_evidence.py` as the repair.
* **`docs/RELEASE_GATES.md` §10 is not updated.** Item 9 is not named there,
  exactly as items 7 and 8 were not; the document update is retained.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.
* **The forward freeze is open.** This item satisfies its one declared member;
  the freeze itself is not closed and is not evidence that the other items are
  done.

## 10. `NOT_RUN`

* An `ADMIT` over the real records: no combination of the recorded sources
  reaches it, and none was manufactured.
* An external trust root, a production key, a key ceremony or an independent
  authority: none exists (A12/A14/A16).
* A party-level separation of the policy's author from the candidate's producer:
  A14 declares no parties.
* A gate integration that names item 9 in `docs/RELEASE_GATES.md` §10: retained,
  as for A14's item 7 and A15's item 8.
* A policy over any action other than `release`: the record declares the release
  action; the other five A14 actions are not evaluated here.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite: no Rust
  source was modified, so no rebuild and no `cargo test` is claimed.

## 11. Forward-freeze members

`evidence/a17/FREEZE-forward.json` declares **one** A20 member:

* **satisfied:** `a20-receipt` — `evidence/a20/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

Still open under the same freeze (**17** members, not this item's work):
`a21-receipt` … `a27-receipt` (7 remaining, A21–A27), `b0-registry`,
`b0-service-configuration`, and `b1-receipt` … `b8-receipt` (8). The
`a18-receipt`, `a19-receipt` and `a20-receipt` members are produced. The freeze
remains `state: OPEN`; it was not amended and not closed, and this receipt does
not claim any of those members.

## 12. Worktree

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
 M forensics/tools/release_gate.py
 M forensics/tools/tests/test_release_gate.py
?? docs/POLICY-ENGINE.md
?? evidence/a20/
?? forensics/tools/policy_engine.py
?? forensics/tools/tests/test_policy_engine.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row (A20),
and `git diff --stat` reports one insertion and one deletion for that file; the
gate change is 125 added lines and one replaced docstring line, and its test file
adds 42 lines.
