# Verification summaries — a summary that cannot outlive its evidence

A verification summary is an attestation produced **after** policy evaluation. It
condenses a decision — the counts by state, the decision itself, which obligations
are unmet — so a human can read it. This document is normative for
`forensics/tools/verification_summary.py`, `forensics/tools/tests/test_verification_summary.py`
and the records in `evidence/a21/`.

## 1. The problem

A summary is written once and read for a long time. The sources it condensed keep
moving: a record is regenerated, a decision is superseded, a policy is amended. A
summary that is not bound to the exact bytes it read does not notice. It is
shorter than the records, easier to quote, and often signed, so it is the document
that survives in slides and release notes while the evidence underneath it
changes. The failure is not a wrong sentence on the day it was written. It is a
summary that **drifts from its evidence and then outlives it**, carrying the
appearance of a verification that no longer exists.

The three mechanisms that let a summary drift are removed here:

1. a count copied from the decision's own totals instead of recounted from the
   obligations;
2. a source named without an identity, so any bytes at that path satisfy the
   citation;
3. a consumer that cites the summary in place of the sources, so nothing is ever
   re-read.

## 2. The summary contract

A summary record is a JSON object with exactly these fields:

| field | meaning |
|---|---|
| `schema` | `openssl-rs/a21/summary/1` |
| `topLevel` | the literal `summary` |
| `replacesEvidence` | the literal `false` |
| `decision` | `ADMIT` or `DENY`, equal to the decision record's `decision` |
| `decisionDigest` | SHA-256 of the decision record's canonical bytes |
| `obligations` | one entry per policy obligation: `{id, state, sourcePath, sourceDigest}` |
| `counts` | `{met, unmet, unknown, notApplicable}`, **recounted** from `obligations` |
| `unmet` | the sorted ids whose state is `UNMET` |
| `reconstructedFrom` | every record the decision cites, primary and corroborating: `{path, sha256}` |

The field set is closed. An obligation entry is closed at `{id, state,
sourcePath, sourceDigest}`; a source-manifest entry is closed at `{path, sha256}`.
A summary that carries a field the contract does not admit is refused by
`AS_REFUSED_OVERCLAIM` (`test_the_document_names_no_unknown_refusal_code` guards
the document side).

`sourceDigest` is the SHA-256 of the record's **bytes**, never of a description of
the record. The decision record is the subject of the signed statement and is
cited by `decisionDigest`; the policy is cited by the decision's `policyDigest`.
Every source the decision read — including a corroborating record such as
`evidence/a17/FREEZE-forward.json` — appears in `reconstructedFrom` with its
digest.

Enforced by `AS_REFUSED_NO_SOURCE_DIGEST` and
`test_the_summary_digest_is_the_digest_of_the_decision_record`.

## 3. The reconstruction contract

`reconstruct(summary, repo)` re-reads every cited source by path and digest and
recomputes each obligation with **the same mapping the decision used**:
`policy_engine._evaluate_obligation`, the function A20's `evaluate` calls, over the
bytes whose digests were just checked. It does not trust the summary's states, and
it does not trust the decision's states either: it compares both with what the
sources recompute to.

It refuses when:

* a cited source, the decision record, the policy record or the envelope is absent
  — `AS_REFUSED_EVIDENCE_ABSENT`;
* a source's bytes do not hash to the digest the summary, the decision or the
  source manifest records — `AS_REFUSED_SOURCE_DIGEST_MISMATCH`;
* an obligation in the decision's policy is missing from the summary
  — `AS_REFUSED_COVERAGE_GAP`;
* the summary records an obligation the policy does not declare, or a state or a
  source the decision does not contain — `AS_REFUSED_OVERCLAIM`;
* an obligation id appears twice — `AS_REFUSED_DUPLICATE_OBLIGATION`;
* an obligation carries no well-formed source digest — `AS_REFUSED_NO_SOURCE_DIGEST`;
* a count has no obligation list or source manifest to be derived from
  — `AS_REFUSED_NON_RECONSTRUCTIBLE`;
* a count in the summary differs from the recount of its obligations, from the
  recount over the sources, or from the decision's own totals
  — `AS_REFUSED_COUNTS_MISMATCH`;
* the summary records `ADMIT` where the decision records `DENY`
  — `AS_REFUSED_DECISION_UPGRADED`.

The source manifest must cite exactly the union of the decision's primary and
corroborating records. A manifest entry that neither the decision nor its
corroboration names is an overclaim; a decision citation the manifest omits is
not reconstructible.

`reconstruct` returns the recomputed per-obligation states and counts and whether
they equal the summary. The committed `evidence/a21/RECONSTRUCTION.json` is that
return value for the real summary; `test_the_committed_reconstruction_is_the_live_reconstruction`
refuses a record that no longer reproduces.

## 4. Counts are recounted, never copied

The decision's `met`, `unmet`, `unknown` and `notApplicable` arrays are the field
that drifts. They are a second representation of the obligation states, and two
representations eventually disagree. The summary therefore computes its counts
from the obligation list itself:

    counts[STATE_TO_COUNT[entry["state"]]] += 1

`summarise` never reads the decision's totals. The test
`test_counts_are_recounted_from_a_deliberately_inconsistent_decision` hands it a
decision whose totals name invented and omitted obligations and asserts that the
summary reports the obligation list's count. `reconstruct` then refuses a summary
whose recount disagrees with the decision's totals
(`test_the_recount_must_agree_with_the_decision_totals`): a summary may not
silently correct the record it condenses, because a corrected summary would assert
a decision the decision record does not state.

Enforced by `AS_REFUSED_COUNTS_MISMATCH`.

## 5. `replacesEvidence: false` and the consumer's duty

The marker is part of the record, not a comment. A consumer that cites the summary
must also cite every source the summary was derived from; the summary is a reading
aid over those sources, never a substitute for them.

`consume(summary, cited_paths, summary_path=...)` returns the source paths the
consumer may stand on, or refuses when:

* `replacesEvidence` is not `false`;
* the summary itself appears in the citation list;
* any cited source is missing from the consumer's citation list.

All three are `AS_REFUSED_SUMMARY_AS_EVIDENCE`, and the control
`consumer-cites-summary` establishes it
(`test_a_consumer_may_not_cite_the_summary_as_evidence`). A consumer that wants a
one-line answer must still name the bytes; it may not name the summary of the
bytes.

## 6. The signature boundary and the A12 caveat

The summary is wrapped as an in-toto Statement v1 whose subject is the **decision
record by digest**, and signed as a DSSE envelope (A10) over the exact statement
bytes. `intoto.subject_for` and `intoto.verify_subject` do the subject identity
work; the predicate is

    {
      "summary": { ...the whole summary record... },
      "signature": {
        "label": "SELF_ISSUED",
        "authentication": "NOT_CLAIMED",
        "keyid": "test-only:hmac-sha256:...",
        "note": "A12: self-issued. ..."
      }
    }

The only key in this tree is A10's test-only HMAC-SHA256 key derived from a fixed
public seed. The signature proves that the summary's bytes have not changed since
signing. It does **not** prove who issued the summary, that the decision is
correct, or that an independent party stands behind either. A statement that
labels the signature as anything but `SELF_ISSUED`, or claims authentication, is
refused by `AS_REFUSED_OVERCLAIM`
(`test_the_signature_is_labelled_self_issued_and_claims_no_authentication`).

A summary whose envelope is absent or carries no signature is refused by
`AS_REFUSED_SUMMARY_UNSIGNED`. A summary whose bytes are not the statement's
payload, whose payload does not verify, or which is not the canonical Statement v1
form is refused by `AS_REFUSED_SUMMARY_MUTATED`
(`test_an_unsigned_summary_is_refused`,
`test_a_summary_mutated_after_signing_is_refused`).

**A9 registry gap, retained.** A9's predicate registry (`intoto.PREDICATES`) is
closed, and this item may not edit another item's tool. The A21 predicate type is
therefore validated by this tool against the same Statement v1 shape rather than by
`intoto.decode`. A9's subject constructor and verifier are reused; A9's predicate
registry is not. That is a retained obligation, not a claim of A9 registration.

## 7. The real summary and its reconstruction

`evidence/a21/SUMMARY.json` summarises A20's committed decision
`evidence/a20/DECISION.json` (digest `af85267933550ffd…`). It records the decision
`DENY`, 8 obligations, and counts of 3 `MET`, 5 `UNMET`, 0 `UNKNOWN` and 0
`NOT_APPLICABLE`. `replacesEvidence` is `false`. Nine records are cited: the eight
primary sources and `evidence/a17/FREEZE-forward.json` as corroboration for
`A17.forward-freeze-closed`.

| obligation | state | source |
|---|---|---|
| `A05.populations-admitted` | `MET` | `evidence/a5/ADMISSION.json` |
| `A06.suppression-member-identities` | `UNMET` | `evidence/a6/SUPPRESSIONS.json` |
| `A07.delta-resolution-conditions` | `MET` | `evidence/a7/DELTA.json` |
| `A12.independent-attestation` | `UNMET` | `evidence/a12/VERIFICATION.json` |
| `A14.release-authorised` | `UNMET` | `evidence/a14/AUTHORISATION.json` |
| `A15.release-threshold-met` | `UNMET` | `evidence/a15/EVALUATION.json` |
| `A17.forward-freeze-closed` | `UNMET` | `evidence/a17/STATUS.json` (corroborated by `evidence/a17/FREEZE-forward.json`) |
| `A19.retraction-propagated` | `MET` | `evidence/a19/PROPAGATION.json` |

The unmet set is `A06…`, `A12…`, `A14…`, `A15…`, `A17…`, in the decision's order.
`evidence/a21/RECONSTRUCTION.json` is the output of `reconstruct`: every
obligation's summary state, decision state and recomputed state agree, the
recomputed counts equal the summary's counts, and `equal` is `true`. The
reconstruction reads the policy that supplied the mapping from
`evidence/a20/POLICY.json` and checks its digest against the decision's
`policyDigest`.

`evidence/a21/SUMMARY.envelope.json` is the DSSE envelope. `verify` reports
`code=AS_OK`, `label=SELF_ISSUED` and the same counts. No refusal code fires on
the real records: the summary is a faithful, reconstructible condensation of a
real `DENY`.

## 8. The controls

`evidence/a21/CONTROLS.json` holds 12 `control-only` fixtures, one per refusal
code. Each is synthetic or a temporary mirror of the real records; none is a
finding about a tracked record. The producer refuses to emit a fixture that does
not establish its code, and refuses a missing code
(`test_every_control_is_control_only_and_establishes_its_code`).

| control | code | the wrong conclusion it exercises |
|---|---|---|
| `consumer-cites-summary` | `AS_REFUSED_SUMMARY_AS_EVIDENCE` | the summary is used instead of its sources |
| `counts-disagree-with-list` | `AS_REFUSED_COUNTS_MISMATCH` | a count is copied, not recounted |
| `source-removed` | `AS_REFUSED_EVIDENCE_ABSENT` | absence is read as agreement |
| `source-bytes-changed` | `AS_REFUSED_SOURCE_DIGEST_MISMATCH` | a changed source is still summarised |
| `obligation-without-digest` | `AS_REFUSED_NO_SOURCE_DIGEST` | a path identifies no bytes |
| `obligation-removed` | `AS_REFUSED_COVERAGE_GAP` | the failing obligation is omitted |
| `obligation-duplicated` | `AS_REFUSED_DUPLICATE_OBLIGATION` | one obligation is counted twice |
| `decision-upgraded` | `AS_REFUSED_DECISION_UPGRADED` | a denial is published as an admission |
| `obligation-added` | `AS_REFUSED_OVERCLAIM` | the summary invents coverage |
| `no-source-manifest` | `AS_REFUSED_NON_RECONSTRUCTIBLE` | a tidy summary has no derivation |
| `summary-unsigned` | `AS_REFUSED_SUMMARY_UNSIGNED` | an unsigned record is read as signed |
| `signed-summary-mutated` | `AS_REFUSED_SUMMARY_MUTATED` | an edited summary is read as the signed one |

The source-identity tests additionally exercise a changed **corroborating**
record, a changed decision record and a changed policy
(`test_a_changed_corroborating_source_is_refused`,
`test_a_changed_decision_record_is_refused`,
`test_a_changed_policy_record_is_refused`). The coverage tests exercise both
directions (`test_an_omitted_policy_obligation_is_a_coverage_gap`,
`test_an_obligation_not_in_the_policy_is_an_overclaim`).

## 9. Refusal codes

| code | condition | the wrong conclusion it prevents |
|---|---|---|
| `AS_REFUSED_SUMMARY_AS_EVIDENCE` | a consumer cites the summary in place of the sources, `replacesEvidence` is not false, or a cited source is missing from the consumer's list | a short, signed document is read as the verification |
| `AS_REFUSED_COUNTS_MISMATCH` | a count differs from the recount of the obligation list, the sources, or the decision's totals | a count is copied, rounded or corrected by hand |
| `AS_REFUSED_EVIDENCE_ABSENT` | a cited source, the decision, the policy or the envelope is absent or unreadable | absence is read as agreement |
| `AS_REFUSED_SOURCE_DIGEST_MISMATCH` | the bytes at a cited path hash to something other than the recorded digest | a source changed and the summary still stands |
| `AS_REFUSED_NO_SOURCE_DIGEST` | an obligation carries no well-formed source digest | a path identifies no bytes |
| `AS_REFUSED_COVERAGE_GAP` | a policy obligation is absent from the summary | the failing obligation is omitted |
| `AS_REFUSED_DUPLICATE_OBLIGATION` | two entries share an obligation id | one obligation is counted twice |
| `AS_REFUSED_DECISION_UPGRADED` | the summary records `ADMIT` where the decision records `DENY` | a denial is published as an admission |
| `AS_REFUSED_OVERCLAIM` | the summary states an obligation, source, state, field or decision the decision does not contain, or claims authentication | the summary becomes a second, unaudited decision |
| `AS_REFUSED_NON_RECONSTRUCTIBLE` | a count has no obligation list, source manifest or valid mapping | an internally tidy summary is trusted without a derivation |
| `AS_REFUSED_SUMMARY_UNSIGNED` | verification is asked for and there is no envelope or no signature | an unsigned record is read as signed |
| `AS_REFUSED_SUMMARY_MUTATED` | the summary is not the envelope's payload, no signature verifies, or the statement is not the emitted form | an edited summary is read as the signed one |

Every code is named in this document and the test suite refuses an unknown code
(`test_every_refusal_code_is_named_in_the_document`).

## 10. Non-claims

* A summary is **not a verification**. It reproduces a decision's mapping over the
  cited bytes; it does not establish that the predicates were the right ones, that
  the sources are true, or that the decision is correct.
* A summary is **not an admission**. The real record summarises a `DENY`; nothing
  in this item admits a release, and `ADMIT` is never manufactured.
* A summary is **not a substitute for the sources**. The consumer contract refuses
  exactly that, and `replacesEvidence: false` is part of the record.
* The signature is **not authentication**. It is `SELF_ISSUED` with a test-only
  key from a fixed public seed; A12 records it that way and no trust root exists.
* `reconstruct` recomputes a decision; it does not re-run the tools that produced
  the source records. Whether `evidence/a6/SUPPRESSIONS.json` was produced by
  `forensics/tools/suppression_governance.py` is A2's and A6's question.
* The summary is bound to the decision record's bytes, not to a Git commit. A
  checkout that rewrites both the decision and its sources consistently defeats
  digest binding; an external anchor is A12/A16's subject.

## 11. `NOT_RUN`

* An independent signer, a production key, a key ceremony or a trust root: none
  exists.
* An externally anchored timestamp or transparency-log inclusion of the summary
  envelope: A16's subject, not run here.
* A9 registry registration of the A21 predicate type: the registry is closed and
  another item's tool was not edited; the structural validation described in §6
  stands in, and the gap is retained.
* Reconstruction over any action other than the recorded `release` decision: the
  other A14 actions are not evaluated.
* Independent review, BOUNDARY, SEAL, and the Rust suite: no Rust source was
  modified, so no rebuild and no `cargo test` is claimed.
* A downstream consumer in another repository citing this summary: the consumer
  contract is exercised by `consume` and its control, not by an external party.

## 12. Reproducing the records

```
python3 evidence/a21/build_evidence.py            # writes SUMMARY.json,
                                                  # SUMMARY.envelope.json,
                                                  # RECONSTRUCTION.json, CONTROLS.json
python3 forensics/tools/verification_summary.py summarise
python3 forensics/tools/verification_summary.py reconstruct evidence/a21/SUMMARY.json
python3 forensics/tools/verification_summary.py verify \
    evidence/a21/SUMMARY.json evidence/a21/SUMMARY.envelope.json
python3 -m unittest forensics.tools.tests.test_verification_summary
```

`test_the_producer_reproduces_the_committed_bytes` runs the producer twice into
temporary directories and compares all four records byte for byte.
