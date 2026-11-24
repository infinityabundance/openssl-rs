# Omission resistance: freezing the expected population and closing against it

This document is the normative description of the **freeze/close** half of A17.
A17 has two halves, and they are different mechanisms:

| half | mechanism | normative record |
|---|---|---|
| claim algebra | a published claim's own evidence, state, aggregate and measure are bound to its verdict (`EG_*` rules) | `evidence/etp/OMISSION-RESISTANCE.md` |
| population closure | an expected population is frozen before execution and reconciled, signed, after it | **this document** |

`evidence/etp/OMISSION-RESISTANCE.md` is the existing **claim-algebra receipt**.
It records `EG_EVIDENCE_CONTRADICTS_VERDICT`, `EG_MULTIPLE_CANDIDATES`,
`EG_AGGREGATE_UNBOUND`, `EG_AGGREGATE_DIGEST_MISMATCH`,
`EG_CONTRADICTION_UNRESOLVED` and `EG_MEASURE_UNTYPED` and its 78 tests. This
document **does not supersede** it and does not change any of those rules. It
describes the complementary rule that the claim algebra cannot express: a
producer that publishes **no claim at all**, or omits an artefact from the
population it asks to be judged on, is detected only by reconciling against a
population frozen before execution.

## 1. The problem

A producer chooses what to publish. If it publishes only successful results, a
validator that inspects the published claims sees a consistent, well-formed,
possibly even signed set -- and cannot see the failure that was never mentioned.
No rule over a claim can detect a claim that does not exist.

The defence is temporal:

> Freeze the expected population **before** execution, then close against it
> **after** execution. Every expected member is accounted for, and every artefact
> that was not declared is reported rather than silently accepted.

The mechanism is implemented in `forensics/tools/omission.py`, the controls are
`forensics/tools/tests/test_omission.py`, and the records are `evidence/a17/`.

## 2. The freeze contract

A freeze has three properties that make later omission detectable.

1. **It exists before the work.** `frozenAt` is recorded, and a closure whose
   `frozenAt` is later than the earliest produced artefact's recorded time is
   refused (`OM_REFUSED_FREEZE_AFTER_EXECUTION`; enforced by the
   `freeze-after-execution` control). The population cannot be chosen
   after seeing which artefacts succeeded.
2. **It has a recorded identity.** The manifest carries its own digest over every
   other field (`freeze_digest`). A manifest whose bytes no longer hash to that
   digest is refused (`OM_REFUSED_FREEZE_AMENDED`; enforced by the
   `freeze-amended` control). Editing a member, a path or a predicate after the
   fact is visible.
3. **It declares exactly one count.** `memberCount` must equal the length of
   `members`; a freeze may not carry a count that is not the length of its member
   list (`OM_REFUSED_FREEZE_AMENDED`). There is no "expected 5, listed 3" state.

Each member is `{id, path, predicate, required, phase}` and optionally
`expectedDigest`. The `id` and `path` are unique (`OM_REFUSED_DUPLICATE_EXPECTED`;
enforced by the `duplicate-expected` control). The freeze also records what
produced it (`producedBy`: the tool path and digest) and when (`frozenAt`,
`recordedAt`). A missing freeze is refused (`OM_REFUSED_FREEZE_ABSENT`; enforced
by the `freeze-absent` control), never treated as an empty population.

A freeze may be `FROZEN` or `OPEN`. `OPEN` is a declaration that the work does
not exist yet; a closure of an `OPEN` freeze never passes.

## 3. The closure states

For every frozen member, `close(freeze, observed)` records exactly one state:

| state | meaning |
|---|---|
| `PRODUCED` | bytes exist at the declared path **and** a digest was recorded (the close computes it from the bytes) |
| `MISSING` | no bytes at the declared path |
| `UNREADABLE` | bytes exist but could not be read |
| `DIGEST_MISMATCH` | the bytes exist but disagree with the frozen `expectedDigest` or with a supplied observation digest |

A non-zero exit code is never production (`OM_REFUSED_EXIT_AS_PRODUCED`), and an
exit status with no bytes at the path is not production either (`OM_REFUSED_EXIT_AS_PRODUCED`;
enforced by the `exit-as-produced` control and
`test_a_missing_freeze_exits_one_with_the_code`). Production requires an artefact,
not a status.

`MISSING` and `UNREADABLE` are different states and are never interchanged
(`OM_REFUSED_UNREADABLE_AS_ABSENT`; enforced in both directions by the
`unreadable-as-absent` and `absent-as-unreadable` controls and
`UnreadableVersusMissing`). "I could not read it" is not "it is not there".

## 4. The reconciliation arithmetic

The summary must reconcile:

```
produced + missing + unreadable + digestMismatch == expected
unexpected                                     is separate
```

Every term is compared with the member rows, and `expected` must equal both the
frozen member count and the number of closure rows. A summary whose counts do not
add up is refused (`OM_REFUSED_COUNT_UNBALANCED`; enforced by
`test_each_perturbed_term_is_refused`, which perturbs each of the four terms in
turn, and by the `count-unbalanced` control).

The closure may not omit a member. Every frozen id appears exactly once; a
closure that leaves out a `MISSING` member, or that lists a different set of
`missingIds`, is refused (`OM_REFUSED_MISSING_SILENT`; enforced by the
`missing-silent` control). The population may not shrink or grow: a different id
or path is refused (`OM_REFUSED_POPULATION_DRIFT`; enforced by the
`population-drift` control), and a reconciliation closing a different freeze
digest or candidate is refused with the same code.

A summary may pass only when every required member is `PRODUCED`. A pass over a
`MISSING` member is refused (`OM_REFUSED_PASS_WITH_MISSING`; enforced by the
`pass-with-missing` control and `PassSummaries`), a pass over an `UNREADABLE`
member is refused (`OM_REFUSED_UNREADABLE_AS_ABSENT`), and a pass over a
`DIGEST_MISMATCH` member is refused (`OM_REFUSED_DIGEST_MISMATCH`; enforced by
the `digest-mismatch` control). A digest mismatch may be recorded -- that is the
point of a closure -- but it cannot be reported as success.

## 5. Unexpected members

Every observed artefact that the freeze did not declare is recorded as an
`UNEXPECTED` entry, with its id, path, digest and recorded time. It is reported,
never silently accepted, and it makes the summary fail. If an observation is
neither declared nor recorded as `UNEXPECTED`, the closure is refused
(`OM_REFUSED_UNEXPECTED_UNDECLARED`; enforced by the `unexpected-undeclared`
control). An observation that names a declared id with a different path (or the
reverse) is population drift, not an unexpected extra
(`OM_REFUSED_POPULATION_DRIFT`).

## 6. The signing boundary

`sign(reconciliation, signer)` returns a DSSE v1 envelope over the **canonical
JSON bytes** of the reconciliation. The PAE, strict base64 and received-bytes
verification are A10's `dsse.py`; this module does not reimplement them.

`verify(freeze, reconciliation, envelope)` requires three things before it checks
the closure:

1. an envelope exists (`OM_REFUSED_RECONCILIATION_UNSIGNED`; enforced by the
   `reconciliation-unsigned` control and `Signing`);
2. the signature verifies over the PAE of the received envelope bytes
   (`OM_REFUSED_SIGNATURE_INVALID`; enforced by the `signature-invalid` control);
3. the verified payload equals the canonical bytes of the reconciliation under
   test (`OM_REFUSED_RECONCILIATION_MUTATED`; enforced by the
   `reconciliation-mutated` control, which signs a reconciliation and then changes
   a member).

Only then is the closure checked against the freeze.

**The A12 caveat.** The only signing key in this tree is A10's test-only
HMAC-SHA256 key, derived from a fixed public seed
(`test-only:hmac-sha256:8e10a5a15d233d54`). A signature made with it proves that
the manifest's bytes have not changed since signing. It does **not** prove that
an independent party closed the reconciliation, that the closer is who they say,
or that the expected population was chosen honestly. A12 records every such
envelope `SELF_ISSUED`; no external trust root exists here. The signature is a
byte-integrity seal over a self-issued closure, nothing more.

## 7. The two real cycles

### 7.1 A real closed cycle (backward), A15

`evidence/a17/FREEZE-a15.json` declares the five `evidence/a15/*.json` records
with their ids, paths, predicates and committed digests, `frozenAt`
`2026-11-24T00:00:00Z`.

`evidence/a17/build_evidence.py` then re-runs `evidence/a15/build_evidence.py`
**read-only into a temporary directory**, closes the freeze against those bytes
at `2026-11-24T00:10:00Z`, signs the reconciliation, and verifies it. The result
is committed as `RECONCILIATION-a15.json` and
`RECONCILIATION-a15.envelope.json`: **5 expected, 5 `PRODUCED`, 0 `MISSING`, 0
`UNREADABLE`, 0 `DIGEST_MISMATCH`, 0 `UNEXPECTED`, pass**. Every produced digest
equals the committed digest, checked by
`test_every_produced_digest_equals_the_committed_one`.

The times are literals, not clock readings, so the producer is byte-reproducible.
They record the in-process order (freeze, then re-run, then close), not a
wall-clock measurement. A producer that misstates its own times is outside what
this check can detect; see §10.

### 7.2 A real forward freeze (forward), A18-A27 and B0-B8

`evidence/a17/FREEZE-forward.json` declares the expected evidence of the
remaining queue items before any of it exists:

* one receipt per item for A18-A27 (10 members);
* B0's registry and recorded service-configuration finding (2 members);
* one receipt per item for B1-B8 (8 members).

That is **20 required members**, recorded `state: OPEN`. It is **not closed**:
there is no `RECONCILIATION-forward.json`, and `STATUS.json` records
`closed: false`, `presentAtFreeze: 0`, `missingAtFreeze: 20` and
`memberCount: 20` at the freeze candidate. Those are **freeze-time facts, not a
live census**: the record does not move when a later item's receipt lands, and
closing the freeze is a separate act that must be recorded. The present tree is
reported only by the explicitly live `omission.py status --live`, which prints
`state=LIVE` and writes nothing; its output is never committed. Any member
missing at freeze time is expected. This freeze is the mechanism that will
detect a future omission; it is **not evidence that any of those items is
done**. Closing it against an empty tree reports 20 `MISSING` and pass false,
which is the correct reading (`ForwardFreeze`).

## 8. Refusal table

Every code is stable. "Enforced by" names the control or test that fires it; all
controls are `control-only` fixtures in `evidence/a17/CONTROLS.json`.

| code | wrong conclusion it prevents | enforced by |
|---|---|---|
| `OM_REFUSED_FREEZE_ABSENT` | closing against no population | `freeze-absent` control |
| `OM_REFUSED_FREEZE_AFTER_EXECUTION` | choosing the population after execution | `freeze-after-execution` control |
| `OM_REFUSED_FREEZE_AMENDED` | editing the freeze to match what was produced | `freeze-amended` control |
| `OM_REFUSED_MISSING_SILENT` | a closure that omits a `MISSING` member | `missing-silent` control |
| `OM_REFUSED_UNEXPECTED_UNDECLARED` | an undeclared artefact entering unseen | `unexpected-undeclared` control |
| `OM_REFUSED_RECONCILIATION_UNSIGNED` | an unsigned closure read as authentication | `reconciliation-unsigned` control |
| `OM_REFUSED_RECONCILIATION_MUTATED` | changing the closure after signing | `reconciliation-mutated` control |
| `OM_REFUSED_DUPLICATE_EXPECTED` | one identity satisfying two requirements | `duplicate-expected` control |
| `OM_REFUSED_DIGEST_MISMATCH` | changed bytes reported as a pass | `digest-mismatch` control |
| `OM_REFUSED_EXIT_AS_PRODUCED` | treating an exit status as an artefact | `exit-as-produced` control |
| `OM_REFUSED_PASS_WITH_MISSING` | a `PASS` over a missing required member | `pass-with-missing` control |
| `OM_REFUSED_POPULATION_DRIFT` | closing a different identity than was frozen | `population-drift` control |
| `OM_REFUSED_UNREADABLE_AS_ABSENT` | interchanging unreadable and absent | `unreadable-as-absent`, `absent-as-unreadable` controls |
| `OM_REFUSED_COUNT_UNBALANCED` | counts that do not add up hiding a member | `count-unbalanced` control, `ReconciliationArithmetic` |
| `OM_REFUSED_MANIFEST_INVALID` | a malformed manifest read as a freeze or closure | `manifest-invalid` control |
| `OM_REFUSED_SIGNATURE_INVALID` | an unverifying signature accepted as signed | `signature-invalid` control |

## 9. The controls

`evidence/a17/CONTROLS.json` holds one control per code (plus a second direction
for `OM_REFUSED_UNREADABLE_AS_ABSENT`) and one positive control. Every control is
labelled `controlOnly: true`: a synthetic freeze, a synthetic artefact in a
temporary directory and a synthetic reconciliation. A control that fires proves
the refusal works; it is not a defect report and not evidence that the
substituted form occurs in the tree. The positive control reaches `OM_VERIFIED`
and establishes the decision procedure, not a real closure.

The two required controls are present and named: a `PASS` summary over a missing
member (`pass-with-missing`) and a signed reconciliation whose bytes were mutated
after signing (`reconciliation-mutated`).

## 10. Limits and non-claims

* **`PRODUCED` is not `PASS`.** It means bytes exist and a digest was recorded.
  It says nothing about correctness, about whether the declared predicate holds,
  or about whether the predicate was the right one. A closed manifest is **not a
  safety, compatibility or cryptographic result**.
* **A signed closure is not an independent closure.** The A12 caveat applies:
  the test-only key proves byte integrity only.
* **The recorded times are declared, not measured.** The producer does not read
  the clock, so `frozenAt` and `recordedAt` are claims by the producer. The
  `OM_REFUSED_FREEZE_AFTER_EXECUTION` check can detect an *inconsistent* declared
  order; it cannot prove wall-clock order. A producer that falsifies its own
  times is outside this mechanism.
* **The population is only as good as the freeze.** A freeze that omits an
  expected artefact, or declares the wrong predicate, produces a closure that is
  arithmetically correct and substantively incomplete. This mechanism detects
  omission relative to a declared population; it does not establish that the
  declared population is complete.
* **An observed artefact is not authenticated.** `close` reads whichever bytes
  the observer points at; `UNEXPECTED` reporting does not prove origin.
* **`OPEN` is not a result.** The forward freeze says what will be expected; it
  does not say any of A18-A27 or B0-B8 has been done.

## `NOT_RUN`

* A real independent closer: **none exists**. Every envelope is signed with
  A10's test-only HMAC key and is `SELF_ISSUED` under A12.
* A wall-clock ordering proof between `frozenAt` and production: the times are
  declared literals; no clock, timestamp authority or transparency log is used.
* A transparency-log inclusion of any freeze or reconciliation: no log is
  configured (A16's inventory is 0 bundles and 0 logs; B1-B5 are TODO).
* Closure of the forward freeze: it is `OPEN` by design and has no
  reconciliation.
* Completeness of the forward freeze's declared population: it is derived from
  the queue rows, and whether every future required record is listed is a
  judgement that no check here establishes.
* Any safety, compatibility, cryptographic or build result: this is evidence
  bookkeeping, not a measurement.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite (`src/` was
  not modified, so no rebuild and no `cargo test` is claimed).
