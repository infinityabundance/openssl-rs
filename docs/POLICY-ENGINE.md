# A deterministic policy engine — conjunction of obligations, denial by default

Status: normative for A20 of `docs/ETP-TODO.md`.
Type: `openssl-rs/a20/policy/1` (policy), `openssl-rs/a20/policy-pin/1` (pin),
`openssl-rs/a20/decision/1` (decision), `openssl-rs/a20/controls/1` (controls).
Implementation: `forensics/tools/policy_engine.py`.
Records: `evidence/a20/{POLICY,POLICY-PIN,DECISION,CONTROLS}.json`, produced by
`evidence/a20/build_evidence.py`.
Tests: `forensics/tools/tests/test_policy_engine.py`.
Release gate: item 9, `check_policy` in `forensics/tools/release_gate.py`.

This document defines the policy record, the pin, the evaluation order, the
refusals and the real decision. It is the normative reference for an item that
asks a policy to decide a release without ever turning a missing evaluation into
a pass.

---

## 1. The problem

Two failure modes make a release policy worthless, and they compound.

**A score hides which obligation failed.** A policy reported as `0.83` does not
say whether the independent verification was absent, the threshold was met by
aliases of one party, or the transparency freeze was still open. A number can be
raised by strengthening an obligation nobody asked about, and it averages a
missing result into a passing one. The ETP claim algebra already refuses a
combined strength for the same reason: a stronger member of a cohort cannot hide
a weaker or blocked member.

**An unevaluated obligation becomes a pass.** A policy whose checker looks up
records by name treats an absent record as "nothing to check". The obligation
disappears, the remaining obligations pass, and the decision reads `ADMIT`.
Nothing in the output distinguishes "the independent verification failed" from
"the independent verification record was not found", because in both cases the
obligation is not in the result.

A third failure mode is specific to a policy that is itself an artefact: the
candidate under test can write the policy that judges it. It can drop an
obligation, waive one for itself, or declare a permissive default, and the
decision is then correct with respect to a policy chosen by the party it decides.

## 2. The rule

### 2.1 Conjunction, not aggregation

A policy is a conjunction. The decision is `ADMIT` only when **every required
obligation is `MET`**. There is no score, no weight, no threshold and no count of
passing obligations that stands in for the decision. One `UNMET` required
obligation is a `DENY`, and the decision names it.

Each obligation's result is one of four states:

| state | meaning | may it satisfy a required obligation? |
|---|---|---|
| `MET` | the record says the obligation holds | yes |
| `UNMET` | the record says it does not hold | no |
| `UNKNOWN` | the record resolves but the result cannot be determined | **no** |
| `NOT_APPLICABLE` | the obligation's applicability condition is false | **no** |

`UNKNOWN` is never `MET`, and `NOT_APPLICABLE` on a required obligation is never
a pass: it fires `PE_REFUSED_OBLIGATION_NOT_APPLICABLE`, because a policy that
may switch a required obligation off has a permissive default by another name.
An obligation declared `required: false` is advisory: it is evaluated and
recorded, it never blocks, and an `UNKNOWN` in it is still a refusal, because an
obligation nobody could evaluate is a machinery defect in either case.

**Enforced by** `forensics/tools/policy_engine.py` — `_evaluate_once` computes
`admit = not problems and all(required is MET)`; test
`test_each_obligation_individually_unmet_denies`,
`test_a_required_inapplicable_obligation_never_passes`.

### 2.2 Denial by default

A policy must declare `default: "deny"`. A policy that declares anything else is
refused with `PE_REFUSED_DEFAULT_ALLOW` and is not evaluated into a decision.
The default is not consulted at run time — the decision is computed from the
obligations — but a policy whose stated default is permissive states that a
missing obligation is admitted, so it is not a policy this engine will apply.

The same applies to the engine's own inputs: an absent record, an unresolvable
locator, an unreadable file, a duplicate JSON key, a non-finite number or an
absent producing tool is a refusal, never a skip. The reader is strict
(`parse_json`), so a duplicate key is `PE_REFUSED_OBLIGATION_UNEVALUATED` rather
than a last-wins collapse.

**Enforced by** `PE_REFUSED_DEFAULT_ALLOW`,
`PE_REFUSED_OBLIGATION_UNEVALUATED`, `PE_REFUSED_OBLIGATION_UNKNOWN`; tests
`test_the_policy_declares_denial_by_default_and_no_score`,
`test_an_absent_source_record_is_unknown_and_denies`.

### 2.3 What the policy may not contain

The policy is a closed record. A field outside the declared set is refused with
`PE_REFUSED_POLICY_INVALID`. A score-shaped key anywhere in the policy —
`score`, `weight`, `threshold`, `confidence`, `rank`, `aggregate`, `composite`,
`grade`, `level_score`, `modality_rank`, `modality_order` — is refused with
`PE_REFUSED_SCORE`, and `scores` must be exactly `false`. An obligation that
carries a `weight` is therefore refused twice, as a score and as an undeclared
field; that is recorded in `CONTROLS.json` rather than smoothed.

**Enforced by** `PE_REFUSED_POLICY_INVALID`, `PE_REFUSED_SCORE`; tests
`test_one_control_per_refusal_code`, `Controls.test_every_control_establishes_its_code`.

## 3. The policy record

```json
{
  "schema": "openssl-rs/a20/policy/1",
  "policyId": "release-policy",
  "version": 1,
  "digest": "<sha256 of the canonical policy without this field>",
  "default": "deny",
  "scores": false,
  "obligations": [ ... ],
  "provenance": { "establishedBy": {"role": ..., "identity": ...},
                  "recordedAt": "YYYY-MM-DD",
                  "independentOfCandidate": false }
}
```

An obligation is:

```json
{
  "id": "A12.independent-attestation",
  "description": "at least one attestation is INDEPENDENTLY_VERIFIED ...",
  "required": true,
  "source": {"tool": "forensics/tools/independent_verify.py",
             "record": "evidence/a12/VERIFICATION.json",
             "locator": "/verifications"},
  "predicate": {"op": "count-at-least", "path": "",
                "where": [{"field": "independentlyVerified", "op": "truthy"}],
                "atLeast": 1}
}
```

Beyond the minimum shape the item defines, the policy carries `provenance`: the
role and identity that established it, the date it was recorded, and whether
that party is independent of the candidate. Without it, "the candidate chose its
own policy" cannot be stated at all.

`source` names three things and each has a use. `record` is read and hashed;
`locator` is an RFC 6901 pointer into it; `tool` is the recorded producer, and
the engine refuses an obligation whose declared producer is absent
(`PE_REFUSED_OBLIGATION_UNEVALUATED`). The engine does not re-run the tool, so
`tool` establishes that a producer was named and exists, not that it produced
these bytes.

The predicate language is closed and declarative: `eq`, `none`, `count-at-least`,
`all-in` and `all`, over member conditions (`eq`, `neq`, `lt`, `lte`, `gt`,
`gte`, `in`, `present`, `absent`, `empty`, `nonempty`, `truthy`, `falsy`,
`eq-field`). A policy cannot carry code, so the engine's behaviour is a function
of its records and its closed vocabulary only.

Two shape rules prevent a silent change of meaning:

* a member field the predicate needs but the record does not state makes the
  condition **undecidable**, and the obligation `UNKNOWN` — it is never read as
  a false condition (`PE_REFUSED_OBLIGATION_UNKNOWN`);
* a population list that resolves to zero members is a pass for `none` (no member
  matches) and is recorded `vacuous: true`; for `all-in` it is `UNKNOWN`,
  because "every population is admitted" over no populations is not a pass.

An obligation may also carry `corroboration`: a second source with its own
predicate for the same fact. The two results must agree; if one is `MET` and the
other `UNMET`, the fact is not established, the obligation is `UNKNOWN` and
`PE_REFUSED_CONTRADICTION` fires. No source is preferred by order, rank or
timestamp.

**Enforced by** `PE_REFUSED_POLICY_INVALID`,
`PE_REFUSED_OBLIGATION_UNKNOWN`, `PE_REFUSED_CONTRADICTION`; tests
`test_unknown_is_never_met`, `test_a_changing_source_is_refused_as_nondeterministic`,
`test_an_unresolvable_locator_is_unevaluated`.

## 4. The pin, and why the candidate may not choose its policy

The policy is recorded in `evidence/a20/POLICY.json`. Its digest is recorded
**separately**, in `evidence/a20/POLICY-PIN.json`:

```json
{
  "schema": "openssl-rs/a20/policy-pin/1",
  "policyId": "release-policy",
  "policyDigest": "<sha256>",
  "policyPath": "evidence/a20/POLICY.json",
  "pinnedAt": "YYYY-MM-DD",
  "pinnedBy": {"role": "maintainer", "identity": "<identity>"},
  "candidate": {"commit": "<commit>", "producedBy": "<identity>"}
}
```

The pin is what makes a policy admissible. The engine refuses:

| wrong conclusion | refusal | condition |
|---|---|---|
| a policy nobody recorded decides a release | `PE_REFUSED_POLICY_UNRECORDED` | no pin; the pin names another id or path; the pin is recorded by a role other than `maintainer` |
| obligations were dropped after the pin | `PE_REFUSED_POLICY_AMENDED` | the policy's current digest differs from `policyDigest` |
| the candidate writes the policy that judges it | `PE_REFUSED_POLICY_FROM_CANDIDATE` | the policy's establishing identity is the candidate's producer, its establishing role is `producer`, or the pin's `pinnedBy` identity is the candidate's producer |
| an unknown candidate reads as "not the candidate's policy" | `PE_REFUSED_CANDIDATE_UNKNOWN` | the candidate commit or its producer is unrecorded, so the previous rule cannot be evaluated |
| the policy exempts the candidate it decides | `PE_REFUSED_SELF_WAIVER` | an obligation's `waivers` names the candidate's producer identity or its commit |

The candidate's producer identity is **read from A14's record**
(`evidence/a14/AUTHORISATION.json#/actions/release/context/evidenceProducer`),
not asserted by the caller: the self-selection rule is then a statement about a
recorded fact. If that record is absent, the engine refuses with
`PE_REFUSED_CANDIDATE_UNKNOWN` rather than comparing against an empty identity.

**What the pin does not establish.** The pin lives in the same tree as the
policy. A party that can amend both can re-pin the amended policy and the engine
will accept it, because a digest recorded beside the bytes it names is not an
external anchor. The engine's rule is exact identity equality between the pinning
and producing identities; A14 records no declared parties, so token inequality is
not party inequality. Both are retained obligations (§10); the external root is
A12's subject and the party-level separation is A14/A15's.

**Enforced by** `PE_REFUSED_POLICY_UNRECORDED`, `PE_REFUSED_POLICY_AMENDED`,
`PE_REFUSED_POLICY_FROM_CANDIDATE`, `PE_REFUSED_CANDIDATE_UNKNOWN`,
`PE_REFUSED_SELF_WAIVER`; tests `test_the_pin_records_the_policy_and_verifies`,
`test_an_amended_policy_is_refused_against_the_pin`,
`test_the_candidate_cannot_supply_the_policy`, `test_self-waiver` control.

## 5. Evaluation: order and determinism

Evaluation is ordered, and the order is part of the contract:

1. the policy's structure, closed field set, schema and self-digest
   (`PE_REFUSED_POLICY_INVALID`);
2. score-shaped keys and `scores` (`PE_REFUSED_SCORE`);
3. `default` (`PE_REFUSED_DEFAULT_ALLOW`);
4. duplicate obligation ids (`PE_REFUSED_DUPLICATE_OBLIGATION`) and the
   canonical order (`PE_REFUSED_ORDER`);
5. the pin: shape (`PE_REFUSED_PIN_INVALID`), then that it records this policy
   and this path (`PE_REFUSED_POLICY_UNRECORDED`), then the digest
   (`PE_REFUSED_POLICY_AMENDED`);
6. the candidate: known (`PE_REFUSED_CANDIDATE_UNKNOWN`), and not the policy's
   establishing or pinning party (`PE_REFUSED_POLICY_FROM_CANDIDATE`);
7. the obligations, in ascending id order, each read from its record with its
   record digest recorded;
8. self-waivers (`PE_REFUSED_SELF_WAIVER`) and contradictions
   (`PE_REFUSED_CONTRADICTION`);
9. the decision, then a second complete evaluation; different canonical bytes
   are `PE_REFUSED_NONDETERMINISTIC`.

The canonical order is **ascending by id**, and the policy must record its
obligations in that order. A policy that lists them otherwise is refused with
`PE_REFUSED_ORDER`, because "the decision's order must be the policy's order" and
"evaluation is in canonical order" cannot both hold for an unsorted policy.
`verify-decision` refuses a decision whose `order`, or whose obligation array,
differs from the policy's canonical order.

Determinism is mechanical: obligations and output arrays are sorted, the
decision contains no timestamp, each obligation records the sha256 of the exact
record bytes it read, and the engine evaluates twice and compares canonical
bytes. Two runs of `policy_engine.py evaluate` over the same records are byte
identical, in one process or two.

**Enforced by** `PE_REFUSED_ORDER`, `PE_REFUSED_NONDETERMINISTIC`,
`PE_REFUSED_DUPLICATE_OBLIGATION`; tests
`test_two_evaluations_are_byte_identical`, `test_two_processes_are_byte_identical`,
`test_a_policy_out_of_canonical_order_is_refused`,
`test_a_reordered_decision_is_refused`,
`test_the_committed_decision_has_the_canonical_order`,
`test_the_decision_contains_no_timestamp`.

## 6. The real policy, its sources and the decision

`evidence/a20/POLICY.json` is version 1 of `release-policy`: eight required
obligations, `default: "deny"`, `scores: false`, digest
`a3fcce8f195216c714f7d7cca228ee4cbca001d986b8104b6d168ee9152afacf`. It was
established in the `maintainer` role at `P-PRINCIPAL` and is **not** recorded as
independent of the candidate (`independentOfCandidate: false`); A14 names
`P-CAMPAIGN` as the producer of the candidate.

| obligation | source record and locator | state | what the record says |
|---|---|---|---|
| `A05.populations-admitted` | `evidence/a5/ADMISSION.json#/populations` | `MET` | 16 populations, every admitted state in the A5 vocabulary, 0 refused declarations keeping the state they declared |
| `A06.suppression-member-identities` | `evidence/a6/SUPPRESSIONS.json#/records` | `UNMET` | 8 of 11 records declare themselves an `ACTIVE` suppression and record no member identity |
| `A07.delta-resolution-conditions` | `evidence/a7/DELTA.json#/deltas` | `MET` | 4 deltas, 0 `RESOLVED` dispositions, 0 refused delta recording one |
| `A12.independent-attestation` | `evidence/a12/VERIFICATION.json#/verifications` | `UNMET` | 0 of 4 envelopes are `INDEPENDENTLY_VERIFIED` (4 `SELF_ISSUED`) |
| `A14.release-authorised` | `evidence/a14/AUTHORISATION.json#/actions/release` | `UNMET` | the recorded `release` outcome is `REFUSED` |
| `A15.release-threshold-met` | `evidence/a15/EVALUATION.json#/evaluations/release` | `UNMET` | the `release` threshold outcome is `UNREACHABLE` |
| `A17.forward-freeze-closed` | `evidence/a17/STATUS.json#/forwardFreeze`, corroborated by `evidence/a17/FREEZE-forward.json` | `UNMET` | the freeze state is `OPEN` and `closed` is `false` in the status record, and `OPEN` in the freeze record; the two agree |
| `A19.retraction-propagated` | `evidence/a19/PROPAGATION.json#/events` | `MET` | 11 events including 5 retractions, 0 dependents left `VALID`, 0 stale |

**The decision is `DENY`.** No refusal code fires: every source was present and
evaluable, so the denial is carried by the five unmet obligations and nothing
else. This is the honest result of the records as they stand, and it is recorded
rather than tuned away. The expected `DENY` would be wrong to hide: the project
has 0 independently verified attestations, 0 authorised release actions, 0 met
thresholds, 0 bundles and 0 key repositories (A12, A14, A15, A16, A18), and an
`OPEN` forward freeze (A17).

`evidence/a20/DECISION.json` records, for each obligation, its state, its source,
the sha256 of the exact record bytes it read, the observed value and the
predicate's explanation, plus `order`, `met`, `unmet`, `unknown`,
`notApplicable`, `codes`, `decision`, and the candidate it was evaluated at. It
contains no timestamp.

**Enforced by** test `test_the_real_decision_is_deny_with_the_expected_unmet_set`
(asserts `DENY` and the exact unmet list) and
`test_the_committed_decision_matches_a_live_evaluation` (a record change makes
the committed decision stale and the test names the regeneration command).

## 7. The controls

`evidence/a20/CONTROLS.json` holds **19** `control-only` fixtures: one per refusal
code (16), a second score control (`weighted-obligation`), a second order control
(`decision-order`), and one positive. A control is synthetic,
built in memory by `policy_engine.controls()`, and is never part of the real
decision. Each record states the code the fixture is meant to establish and the
codes actually observed; the producer refuses to emit a fixture that does not
establish its code.

The required controls are:

| control | shows |
|---|---|
| `score-policy` | a policy declaring `scores: true` is `PE_REFUSED_SCORE` |
| `default-allow` | a policy with `default: "allow"` is `PE_REFUSED_DEFAULT_ALLOW` |
| `unevaluated-as-pass` | an obligation whose record is absent is `UNKNOWN` and the decision `DENY`, never `MET` |
| `policy-amended` | a policy whose digest differs from the pin is `PE_REFUSED_POLICY_AMENDED` |
| `policy-from-candidate` | a policy established by the candidate's producer is `PE_REFUSED_POLICY_FROM_CANDIDATE` |
| `self-waiver` | a policy that waives an obligation for the candidate it decides is `PE_REFUSED_SELF_WAIVER` |
| `duplicate-obligation` | the same id twice is `PE_REFUSED_DUPLICATE_OBLIGATION` |
| `decision-order` | a decision whose obligations are reordered against its policy is `PE_REFUSED_ORDER` |
| `contradiction` | two sources of one fact that disagree are `PE_REFUSED_CONTRADICTION` and the fact is `UNKNOWN` |

The positive control `positive-admit` is a synthetic policy of two obligations,
both `MET`, which reaches `ADMIT` with no code. **What it establishes:** the
decision procedure can admit, so the refusals are not vacuous and the engine is
not a machine that always says `DENY`. **What it does not establish:** that any
real obligation is met, that a real policy is admissible, or that `ADMIT` would
be correct for this candidate. It is a control, not evidence.

**Enforced by** `evidence/a20/build_evidence.py` (refuses a missing code or an
unestablished control) and tests
`test_one_control_per_refusal_code`,
`test_every_control_establishes_its_code`,
`test_the_positive_control_reaches_admit`,
`test_required_named_controls_are_present`.

## 8. Refusals

Every code is stable. `condition` states when it fires; `prevents` states the
wrong conclusion it removes.

| code | condition | prevents | enforced by |
|---|---|---|---|
| `PE_REFUSED_POLICY_INVALID` | not a well-formed policy of the declared schema; an undeclared field; the recorded digest does not match the bytes | reading an arbitrary document as a policy with whatever obligations it happens to contain | `validate_policy`; test `policy-invalid` |
| `PE_REFUSED_PIN_INVALID` | the pin is malformed: no digest, no pinning identity or role, no candidate, an undeclared field | an unreadable pin reading as a pin | `validate_pin`; test `pin-invalid` |
| `PE_REFUSED_POLICY_UNRECORDED` | no pin records this policy; the pin names another id or path; the pinning role may not record a release policy | a policy nobody recorded deciding a release | `test_policy-unrecorded` |
| `PE_REFUSED_POLICY_AMENDED` | the current policy digest differs from the pin | obligations dropped after the pin | `test_an_amended_policy_is_refused_against_the_pin` |
| `PE_REFUSED_POLICY_FROM_CANDIDATE` | the policy's establishing identity or role is the candidate's producer, or the pin was recorded by it | the candidate choosing the policy that decides it | `test_the_candidate_cannot_supply_the_policy` |
| `PE_REFUSED_CANDIDATE_UNKNOWN` | the candidate or its producer is unrecorded so the previous rule cannot be evaluated | an unknown candidate reading as "not its policy" | `resolve_candidate`; test `candidate-unknown` |
| `PE_REFUSED_SCORE` | a score/weight/threshold/aggregation key, or `scores` not false | a number standing in for which obligation failed | `test_score-policy`, `weighted-obligation` |
| `PE_REFUSED_DEFAULT_ALLOW` | `default` is not `deny` | an undeclared obligation admitted by a permissive default | `test_default-allow` |
| `PE_REFUSED_DUPLICATE_OBLIGATION` | two obligations share an id | one result counted twice | `test_duplicate-obligation` |
| `PE_REFUSED_SELF_WAIVER` | an obligation waives itself for the candidate it decides | the policy exempting its own candidate | `test_self-waiver` |
| `PE_REFUSED_OBLIGATION_UNEVALUATED` | the record is absent, unreadable, not strict JSON; the declared tool is absent; the locator does not resolve | an obligation nobody could read being skipped | `test_unevaluated-as-pass` |
| `PE_REFUSED_OBLIGATION_UNKNOWN` | the record resolves but a needed condition is absent or of the wrong shape | an unevaluable obligation read as satisfied | `test_unknown-never-met` |
| `PE_REFUSED_OBLIGATION_NOT_APPLICABLE` | a required obligation's applicability condition is false | a required obligation switched off to avoid evaluating it | `test_required-not-applicable` |
| `PE_REFUSED_CONTRADICTION` | two sources of one fact disagree about whether it holds | one disagreeing record preferred by order, rank or timestamp | `test_contradiction` |
| `PE_REFUSED_ORDER` | the policy's ids are not ascending, or a decision's order differs from the policy's | two decisions compared over different orders; an obligation added or reordered after the decision | `test_policy-order`, `test_decision-order` |
| `PE_REFUSED_NONDETERMINISTIC` | two evaluations of the same policy over the same records differ | a decision reproducible only by accident | `test_nondeterministic` |

## 9. Command line and release-gate integration

```
python3 forensics/tools/policy_engine.py evaluate [--json]
python3 forensics/tools/policy_engine.py explain A12.independent-attestation
python3 forensics/tools/policy_engine.py verify-pin
python3 forensics/tools/policy_engine.py verify-decision
```

Exit status is `0` for `ADMIT` (or a passing check), `1` for `DENY` or a
refusal, `2` for a usage or unreadable-input error. The code and the decision are
always printed; `explain` exits `0` only when the named obligation is `MET`.

The release gate integrates the engine as **item 9**, `check_policy`: a `DENY`
decision is one refusal row, `RG_POLICY_DENIED`, naming every unmet obligation
and every code. Items 1–8 are unchanged. On the A20 candidate the gate goes from
33 to 34 refusals, the extra row being
`RG_POLICY_DENIED a20/release: decision=DENY unmet=A06...,A12...,A14...,A15...,A17... codes=NONE`.

**Enforced by** tests `test_evaluate_prints_the_decision_and_the_code`,
`test_explain_prints_the_obligation_and_exits_one_when_unmet`,
`test_verify_pin_exits_zero_and_prints_the_decision`, and the gate's own
self-test case `denied policy`.

## 10. Residuals retained

* **The pin is not an external anchor.** It is a digest recorded beside the bytes
  it names, in the same tree. A writer who can amend the policy and the pin is
  not detected; that requires a root outside the candidate (A12) and an
  independent party (A14).
* **Token inequality is not party inequality.** The engine compares identities
  and refuses equality; A14 records no declared parties, so `P-PRINCIPAL` and
  `P-CAMPAIGN` are different tokens whose distinctness as parties is not
  established here. The policy is recorded `independentOfCandidate: false` for
  that reason.
* **The engine does not re-run the producing tools.** It records the record
  digest and checks that the named tool exists. Whether the record was produced
  by that tool, and whether the tool's result is correct, is A2's and the
  item's own concern.
* **The predicate language is a closed vocabulary.** An obligation that needs a
  fact the vocabulary cannot express is expressed less precisely or not at all;
  the eight obligations here are all expressible, but a future obligation may
  not be.
* **A6's `UNMET` means the records are refused, not that a suppression is in
  force.** The eight records declare `ACTIVE`; A6 admits all eleven as
  `NON_ACTIONABLE`, so no suppression is actually in force. The obligation reads
  the declaration, which is the claim under governance.
* **A7 and A19 are `MET` on records with no positive instance.** No delta records
  `RESOLVED` and no retraction leaves a valid dependent; those are negative
  results, not proofs that no resolution or stale dependent exists.
* **A17's corroboration is two records of one fact, not two parties.** Both are
  A17's own records; agreement between them does not make the freeze closed.
* **The decision record can go stale.** It binds the sha256 of each record it
  read; a later change to one of those records makes the committed decision
  stale, and `test_the_committed_decision_matches_a_live_evaluation` names the
  regeneration command.

## 11. Non-claims and `NOT_RUN`

Not claimed:

* that the policy is the *right* policy, that its eight obligations are complete,
  or that anything outside them may be ignored for a release;
* that any real obligation is met, that any real attestation is independent, that
  any role is authorised, that any threshold is reachable, or that any freeze is
  closed;
* that `ADMIT` is reachable for this candidate — it is not, on these records;
* that the engine's evaluation is a proof of the facts it reads, or that a record
  is true;
* that the pin, the policy or the controls are independently reviewed.

`NOT_RUN`:

* an `ADMIT` decision over the real records: no combination of the recorded
  sources reaches it, and none was manufactured;
* an external trust root, a real key ceremony or an independent authority
  (A12/A14/A16);
* a party-level separation of the policy's author from the candidate's producer
  (A14/A15);
* a gate integration that names item 9 in `docs/RELEASE_GATES.md` §10 — the
  section is not updated here and that is a retained obligation, as it was for
  A14's item 7 and A15's item 8;
* independent review, a BOUNDARY audit, a SEAL, and the Rust suite: no Rust
  source was modified, so no rebuild and no `cargo test` is claimed.

## 12. Reproducing the check

```
python3 evidence/a20/build_evidence.py            # writes the four records
python3 forensics/tools/policy_engine.py evaluate  # DENY, five unmet, no code
python3 forensics/tools/policy_engine.py verify-pin
python3 forensics/tools/policy_engine.py verify-decision
python3 -m unittest forensics.tools.tests.test_policy_engine
```

`build_evidence.py` writes no timestamp, sorts every array and reproduces the
committed bytes on a second run. A `DENY` is the recorded result and the exit
status of `evaluate` is `1`; that is the decision, not a failure of the tool.
