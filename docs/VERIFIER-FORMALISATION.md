# Verifier formalisation — the written rule, an independent reference, and the gap

Status: normative for A23 of `docs/ETP-TODO.md`.
Type: `openssl-rs/a23/verifier-formalisation-spec/1` (the specification),
`openssl-rs/a23/differential/1`, `openssl-rs/a23/properties/1`,
`openssl-rs/a23/controls/1` (the records).
Implementation: `forensics/tools/verifier_formalisation.py`.
Specification record: `evidence/a23/SPEC.json`.
Records: `evidence/a23/{SPEC,DIFFERENTIAL,PROPERTIES,CONTROLS}.json`, produced by
`evidence/a23/build_evidence.py`.
Tests: `forensics/tools/tests/test_verifier_formalisation.py`.

This document defines the decision rules of the release verifier as a formal
object, explains how an independent reference evaluator is built from it, and
states exactly what the comparison between the reference and the implementation
does and does not establish.

---

## 1. The problem

A specification written by reading the implementation proves nothing. It inherits
whatever the code does: if the code reads `UNKNOWN` as `MET`, the specification
will say that it does, and the "check" will agree with the defect. Earned Trust
Article 6 states the rule directly: **a specification is never a restatement of
the implementation.** A requirement document that names the implementation's
internals is a paraphrase of the artefact it is supposed to constrain.

The second failure is subtler. Suppose the rules are written independently and a
reference evaluator is implemented from them. Comparing the two over a handful of
examples is a smoke test, not a result. An agreement over the examples the author
happened to think of is exactly the evidence a defect evades. The strongest cheap
form of the comparison is **exhaustive enumeration over a domain whose size is
known exactly**, together with invariants that must hold for every input in that
domain.

The third failure is to overclaim the result. A finite enumeration is not a
theorem (Article 7), and a reference by the same author is not independent
verification (Article 5). This item is designed to make those overclaims
impossible to state by accident, because the records carry the domain sizes, the
limits and the `NOT_RUN` list beside the result.

## 2. The rules

The rules are written in `evidence/a23/SPEC.json` as machine-readable objects,
each with a stable identifier, a statement, its grounding in the existing
normative documents, and the reference function and refusals that enforce it.
The text below is the same rule set in prose.

### 2.1 Obligation states and the decision (VF-R1 … VF-R7)

An obligation's recorded state is exactly one of `MET`, `UNMET`, `UNKNOWN`,
`NOT_APPLICABLE` (**VF-R1**). The decision vocabulary is `ADMIT` and `DENY`.

* **VF-R2 (conjunction).** `ADMIT` if and only if the required set is non-empty
  and every required obligation is `MET`. No score, weight, count of passing
  obligations, threshold or aggregation key contributes.
* **VF-R3 (UNKNOWN is a refusal).** If any obligation is `UNKNOWN`, the decision
  is `DENY`, whether or not that obligation is required. `UNKNOWN` is never read
  as `MET` and never as `NOT_APPLICABLE`: an obligation nobody could evaluate is
  a machinery defect in either case.
* **VF-R4 (required-inapplicable denies).** `NOT_APPLICABLE` on a required
  obligation is not a pass, because only `MET` satisfies a required obligation.
  `NOT_APPLICABLE` on a non-required obligation does not decide.
* **VF-R5 (no required obligation denies).** An empty required set is not an
  all-met proof; denial by default.
* **VF-R6 (canonical-order independence).** The decision is a pure function of
  the state vector and the required set. Permuting the vector and its required
  flags together changes no decision; canonical order is for recording.
* **VF-R7 (determinism).** The same vector and required set yield the same
  decision; no clock, random source or ambient state enters.

The decision therefore has a one-line normal form:

```
DENY    if any state is UNKNOWN
DENY    if no obligation is required
ADMIT   iff every required obligation is MET
DENY    otherwise
```

**Enforced by** `VF_REFUSED_DISAGREEMENT` and `VF_REFUSED_UNSPECIFIED_RULE`; tests
`test_decision_differential_small_domain`, `test_decision_differential_real_policy`,
`test_property_determinism`, `test_property_adding_a_met_obligation`,
`test_property_adding_a_required_unmet`, `test_property_unknown_never_admits`,
`test_property_required_inapplicable_denies`,
`test_property_canonical_order_independence`, `test_property_no_numeric_score`.

### 2.2 The threshold over distinct trust domains (VF-R8)

A k-of-n threshold is `MET` if and only if the number of **distinct established
trust domains** among approvals that are *verified*, *role-valid*, *fresh* and
*non-candidate* is at least `k`.

* An approval's `domainId` is a lookup key, not a domain. Two labels whose domain
  records share an establishment record `(path, sha256)` are **one** domain.
* A duplicate approval on one counted domain counts once.
* One identity contributes at most one domain: a later approval by the same
  identity in a different domain is dropped.
* A candidate domain, a self-asserted domain (no establishment record) and an
  unresolved label contribute nothing.

**Enforced by** `VF_REFUSED_DISAGREEMENT` through the threshold comparison;
test `test_threshold_differential`; control `wrong-threshold-ignores-aliases`.

### 2.3 Correction-chain admission (VF-R9)

An event is admissible if and only if every binding rule holds:

| rule | statement | authority refusal |
|---|---|---|
| VF-C1 | a correction's predecessor id names an event in the chain | `CR_REFUSED_PREDECESSOR_MISMATCH` |
| VF-C2 | the recorded predecessor digest is the predecessor's canonical digest | `CR_REFUSED_PREDECESSOR_MISMATCH` |
| VF-C3 | each event has at most one successor | `CR_REFUSED_FORK` |
| VF-C4 | no chain revisits an event; no predecessor points forward | `CR_REFUSED_CYCLE` |
| VF-C5 | a correction's predecessor is about the same subject | `CR_REFUSED_SUBJECT_CHANGED` |
| VF-C6 | a subject has at most one root assertion | `CR_REFUSED_ASSERTION_EXISTS` |
| VF-C7 | a correction's old value is the predecessor's accepted value | `CR_REFUSED_ORIGINAL_MISMATCH` |
| VF-C8 | an assertion does not supersede an event | `CR_REFUSED_EVENT_INVALID` |

The original is never modified: a correction is a new, bound event.

**Enforced by** `VF_REFUSED_DISAGREEMENT` through the `correction` comparison;
test `test_correction_differential`; control `wrong-chain-ignores-digest`.

## 3. The independent reference

`forensics/tools/verifier_formalisation.py` implements three reference
evaluators from the text above and `SPEC.json` alone:

* `reference_decide(states, required)`;
* `reference_threshold_count(approvals, inventory)`;
* `reference_chain_admissible(chain)`.

**No-import rule.** The reference functions do not import — and their
`__globals__` do not contain — `policy_engine`, `thresholds` or `corrections`.
The implementation adapters import those modules *inside the adapter functions*,
after the reference has decided. `assert_reference_independent` checks both the
function's globals and its source text, and refuses with
`VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION` when either names an
implementation. The control `reference-imports-implementation` builds a stub
whose globals resolve `policy_engine` and confirms the check fires; the test
`test_reference_does_not_import_an_implementation` is the structural guard.

The reference reads the decision vocabulary, the satisfying state and the
minimum required count from `SPEC.json`, so the specification and the reference
cannot drift apart silently: a missing or edited specification is refused with
`VF_REFUSED_SPEC_ABSENT` by its recorded digest.

## 4. The domains, and their exact sizes

| domain | object | size | exhaustive? |
|---|---|---:|---|
| `decision-small` | the decision function over `n = 0..3` obligations, every state vector and every required mask | **585** | yes |
| `decision-policy` | the decision function over the real policy's shape: 8 obligations, all required | **65,536** = `4**8` | yes |
| `threshold` | multisets of 0..4 approvals over 12 archetypes, `k = 1..min(3, available)`, two inventories | **9,100** | declared finite model |
| `correction` | chains of length 0..3 over two subjects, earlier-only predecessors, intact/bad digests, preserved/modified originals, plus 3 cycle witnesses | **386** | declared finite model |

The counts add up to **75,607** comparisons. The `decision-policy` domain is not
a sample: an eight-obligation decision function has exactly `4**8 = 65,536`
inputs, so the differential over it is the *whole* input space of that function.
The `decision-small` domain multiplies state vectors by masks:
`1 + 8 + 64 + 512 = 585`. The threshold domain is
`1,820 multisets × (3 + 2) k values = 9,100`. The correction domain is
`1 + 2 + 20 + 360 = 383` chains plus 3 cycle witnesses.

## 5. The invariants

`properties(3)` checks seven invariants over 512 cases (64 vectors × 8 required
masks), on **both** the implementation and the reference:

| id | invariant |
|---|---|
| VF-P1 | determinism: the same vector twice returns the same decision |
| VF-P2 | adding a `MET` obligation to an admitting vector still admits |
| VF-P3 | adding a required `UNMET` obligation to any vector denies |
| VF-P4 | `UNKNOWN` never admits, whether or not the obligation is required |
| VF-P5 | `NOT_APPLICABLE` on a required obligation denies |
| VF-P6 | permuting the vector and its required flags together changes no decision |
| VF-P7 | with no obligation in `UNKNOWN`, a non-required obligation in `MET`, `UNMET` or `NOT_APPLICABLE` never changes the decision |

VF-P7 is the "no numeric score" invariant: if a count of passing obligations, a
weight or a rank influenced the decision, changing an advisory obligation's state
would change it. The invariant is conditioned on *no `UNKNOWN`* because VF-R3
makes `UNKNOWN` a refusal whatever the requirement; the first statement of VF-P7
omitted that condition and the enumeration produced the counterexample
`states = ["MET", "MET", "UNKNOWN"], required = [true, false, false]`. The
condition was added to the property, not to a result: the rule (VF-R3) did not
change.

**Enforced by** `VF_REFUSED_PROPERTY_VIOLATED`; tests
`test_every_property_holds_over_the_full_small_domain` and the seven
`test_property_*` controls.

## 6. The real result

Produced by `python3 evidence/a23/build_evidence.py` at base
`7c2b5f25f`:

| domain | declared | compared | disagreements |
|---|---:|---:|---:|
| `decision-small` | 585 | 585 | 0 |
| `decision-policy` | 65,536 | 65,536 | 0 |
| `threshold` | 9,100 | 9,100 | 0 |
| `correction` | 386 | 386 | 0 |
| **total** | **75,607** | **75,607** | **0** |

All seven invariants hold on both evaluators. Every control observes its expected
code. The records are `evidence/a23/DIFFERENTIAL.json`,
`evidence/a23/PROPERTIES.json` and `evidence/a23/CONTROLS.json`.

One observation is recorded rather than asserted. The three cycle witnesses are
unsatisfiable under VF-C2: a cycle's predecessor digests would have to equal
functions of themselves, so no canonical-digest cycle exists. The reference
reports VF-C4; the implementation refuses the first appended event with
`CR_REFUSED_PREDECESSOR_MISMATCH`; both refuse, so they agree on admissibility.
The cycle rule is retained as defence in depth, and the differential cannot
exhibit a cycle that fails *only* VF-C4. This is stated, not hidden.

## 7. The controls

Each control is `control-only` and is recorded in
`evidence/a23/CONTROLS.json`.

| control | wrong behaviour | code observed |
|---|---|---|
| `wrong-reference-unknown-as-met` | a reference that reads `UNKNOWN` as `MET` | `VF_REFUSED_DISAGREEMENT` |
| `wrong-reference-not-applicable-as-met` | a reference that reads `NOT_APPLICABLE` as `MET` | `VF_REFUSED_DISAGREEMENT` |
| `wrong-threshold-ignores-aliases` | a count by label, so an alias is two domains | `VF_REFUSED_DISAGREEMENT` |
| `wrong-chain-ignores-digest` | a chain rule that ignores the predecessor digest | `VF_REFUSED_DISAGREEMENT` |
| `domain-incomplete` | a claimed size of 3 for a 16-vector space | `VF_REFUSED_DOMAIN_INCOMPLETE` |
| `enumeration-truncated` | a bounded enumeration reported at the full size | `VF_REFUSED_ENUMERATION_TRUNCATED` |
| `reference-imports-implementation` | a reference whose globals resolve `policy_engine` | `VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION` |
| `property-violated` | the wrong reference fails VF-P4 | `VF_REFUSED_PROPERTY_VIOLATED` |
| `spec-absent` | a missing specification | `VF_REFUSED_SPEC_ABSENT` |
| `unspecified-rule` | a state outside the vocabulary | `VF_REFUSED_UNSPECIFIED_RULE` |

The controls establish that the differential and the invariants can **fail**: a
wrong reference is detected with the exact input, both outputs and the rule, and
the tool exits non-zero. A check that cannot fail is not a check.

## 8. Refusal table

| code | condition | prevents |
|---|---|---|
| `VF_REFUSED_DISAGREEMENT` | implementation and reference differ on some input in a domain | a divergence reported as agreement, or repaired by editing the rule |
| `VF_REFUSED_DOMAIN_INCOMPLETE` | a claimed domain size is not the full `4**n` space | a partial enumeration presented as exhaustive |
| `VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION` | the reference resolves an implementation module | a reference that is the implementation by another name |
| `VF_REFUSED_PROPERTY_VIOLATED` | an invariant fails in its stated domain | an invariant asserted from inspection while a counterexample exists |
| `VF_REFUSED_SPEC_ABSENT` | the specification is absent, unreadable or digest-mismatched | a missing or edited specification treated as the rule |
| `VF_REFUSED_UNSPECIFIED_RULE` | an input is outside the specification | an undecided input given a decision by accident |
| `VF_REFUSED_ENUMERATION_TRUNCATED` | the enumeration was bounded below its declared size | a truncated run reported at the full size |

## 9. What this establishes, and what it does not

**Established.** Over the stated domains, the implementation's decision function
agrees with a reference implemented from the written rules; the real
eight-obligation state space is covered exhaustively; seven invariants hold on
both; and four deliberately wrong references (and one wrong count, one wrong
chain rule) are detected with a counterexample.

**Not established — stated plainly.**

* **The enumeration is finite.** Only `decision-policy` is the whole state space
  of its function. `decision-small`, `threshold` and `correction` are declared
  finite models; an input outside them is not covered, and their sizes are
  choices, not bounds derived from the implementation. Nothing here proves the
  rule for an arbitrary record.
* **It covers the decision function, not the whole tool.** Record reading,
  predicates, applicability evaluation, pins, signatures, roles and history
  witnesses are outside the enumeration. Those are exercised by the A15, A19 and
  A20 suites, which this item did not re-run.
* **The reference shares an author with the implementation.** Agreement is
  evidence of a shared reading, not independent verification (Article 5). No
  external party wrote either the rule or the reference.
* **There is no machine-checked theorem.** No TLA+, Coq, Lean or Kani proof; no
  refinement edge; no correspondence between this model and a compiled binary
  (Article 7). The rules are prose plus a Python predicate, not a checked theory.
* **Cycle detection is not independently exhibited.** VF-C4 is unreachable as a
  sole defect under VF-C2, and the differential records the observation rather
  than claiming it separates the two rules.

## 10. `NOT_RUN`

* An independent reviewer or a distinct trust domain (Article 5).
* A machine-checked proof (TLA+, Coq, Lean, Kani) of any rule, and any
  source-to-binary correspondence (Article 7).
* Re-running the A15, A19 and A20 suites, and any differential that derives
  obligation states from real records rather than from the abstract state vector.
* The threshold domain for `k > available`, for more than 12 archetypes, for
  longer approval sets than four, and for a role model other than A14's.
* Correction chains longer than three events, with `retract` events, with
  signatures or roles, or with the history witness (`check_log`).
* A BOUNDARY audit, a SEAL, and the Rust test suite — no Rust source was
  modified by this item.
