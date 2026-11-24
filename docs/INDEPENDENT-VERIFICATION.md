# Independent envelope verification (A12)

A signature made by the same party that produced an envelope is not evidence to a
third party. This document is normative for the root-of-trust contract, the
policy-selection rule and the nine checks that decide whether an envelope is
independently verified. The implementation is
`forensics/tools/independent_verify.py`; the real inventory is
`evidence/a12/TRUST-ROOTS.json`; the real result is `evidence/a12/VERIFICATION.json`;
the controls are `evidence/a12/CONTROLS.json` and
`forensics/tools/tests/test_independent_verify.py`. A10 owns the DSSE envelope and
the PAE; A12 owns only the trust decision.

## 1. The problem

A10 signs and verifies four envelopes with a deterministic test-only HMAC-SHA256
key derived from a fixed public seed. The producer verifies its own envelopes with
the same key it signed with. That establishes framing, the PAE over the received
bytes, and that a signature over that PAE checks out. It establishes nothing to a
party that did not already hold the key, because the verifier could have produced
the signature itself.

The wrong conclusion is: "the signature verified, therefore an independent party
vouched for the statement." The right question is not whether a signature checks
out, but whether the verifier's root of trust is outside the candidate, outside the
party that produced the envelope, and selected by a recorded policy rather than by
the envelope. This document makes that question mechanical.

**Enforced by** `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_KEY_FROM_ENVELOPE`,
`IV_REFUSED_CANDIDATE_TRUST_ROOT` and `IV_REFUSED_SELF_ISSUED`; and by
`test_the_four_real_envelopes_are_self_issued_and_never_independently_verified`.

## 2. The trust-root contract

A trust-root record has exactly these fields:

| field | meaning |
|---|---|
| `keyid` | the identifier the policy selects; it is a policy input, not an envelope hint |
| `algorithm` | the signature algorithm the root is for |
| `publicMaterial` | the public key or public key material, **or** an explicit `symmetric: true` |
| `provenance` | `{path, sha256}` of the record that establishes the root |
| `trustDomain` | a label for the party the root belongs to; it must be distinct from the candidate's and the producer's |
| `independenceBasis` | what makes the root independent: a separate key ceremony, an external operator, a published key |
| `recordedAt` | the date the root record was made |

The **inventory** of roots is a separate tracked record. It is read from
`policy.trustRootsPath` and must not lie inside the evidence being verified
(`policy.candidateEvidenceRoot`). A candidate may not supply the key, the seed or
the record that authorises itself. The inventory is not inferred from the
envelope and an absent inventory is a refusal, never an empty one.

**Enforced by** `IV_REFUSED_TRUST_ROOT_UNRECORDED`,
`IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`,
`test_the_inventory_inside_the_candidate_evidence_is_refused` and
`test_the_inventory_records_no_external_root_explicitly`.

## 3. Policy selection: the envelope may not choose its judge

The policy names the `keyid`. The envelope's `keyid` is an unauthenticated hint
and is recorded for comparison only. If the policy names no keyid, the verifier
does not fall back to the envelope's hint: it refuses with
`IV_REFUSED_KEY_FROM_ENVELOPE`. If the policy names a keyid that is not in the
inventory, the outcome is `IV_REFUSED_TRUST_ROOT_UNRECORDED`, even when the
envelope carries a keyid that *is* recorded.

**Enforced by** `IV_REFUSED_KEY_FROM_ENVELOPE`,
`test_the_envelope_keyid_cannot_select_a_root`.

## 4. Why a symmetric signature can never establish independence

For an HMAC (or any shared-secret scheme), the verifier holds the same secret as
the signer. Given a message and a signature, the verifier could have computed the
signature itself; it therefore learns only that the bytes are consistent with a
key it already holds. Independence requires that the verifier could not have
produced the signature, which requires public-key material and a root outside the
producer.

A symmetric root is therefore refused for an independence claim with
`IV_REFUSED_SYMMETRIC`. It is not refused as a *framing* result: A10's signature
check is still meaningful. It is refused as *independence evidence*.

**Enforced by** `IV_REFUSED_SYMMETRIC`, `test_hmac_is_refused_for_independence`.

## 5. The nine checks

Each check is performed in order and has a stable refusal code.

| # | check | refusal code |
|---|---|---|
| 1 | select the trust root by the **policy's** keyid, never by the envelope's | `IV_REFUSED_KEY_FROM_ENVELOPE` |
| 2 | refuse a symmetric root for an independence claim | `IV_REFUSED_SYMMETRIC` |
| 3 | refuse a root whose provenance is inside the candidate tree | `IV_REFUSED_CANDIDATE_TRUST_ROOT` |
| 4 | refuse an unrecorded root, a digest mismatch, a stale root, or two roots for one keyid | `IV_REFUSED_TRUST_ROOT_UNRECORDED`, `IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH`, `IV_REFUSED_TRUST_ROOT_STALE`, `IV_REFUSED_MULTIPLE_ROOTS` |
| 5 | refuse a root in the candidate's or producer's trust domain | `IV_REFUSED_SAME_DOMAIN` |
| 6 | refuse a recorded self-issued basis | `IV_REFUSED_SELF_ISSUED` |
| 7 | verify the DSSE signature over the received PAE | `IV_REFUSED_SIGNATURE` |
| 8 | re-hash the payload's statement and the artefact; the subject digest must be the artefact's bytes | `IV_REFUSED_PAYLOAD_NOT_SUBJECT`, `IV_REFUSED_SUBJECT_ABSENT` |
| 9 | require the statement to name the artefact being verified | `IV_REFUSED_SUBJECT_MISMATCH` |

Check 7 uses a caller-supplied
`public_verify(keyid, pae_bytes, signature_bytes, public_material) -> bool`. This
module implements no signature primitive. The verifier is called only for a
signature whose `keyid` is the policy's. If no public verifier is supplied and
the root is otherwise acceptable, the outcome is `NOT_RUN` with
`IV_REFUSED_NO_PUBLIC_VERIFIER`, never a pass.

Checks 8 and 9 follow the A9 statement the verified payload carries: the payload
must be a canonical in-toto Statement v1, the statement must name the artefact
under test, and the subject digest for that name must equal the SHA-256 of the
artefact's bytes. A statement about different bytes, a missing artefact and a
statement that names another artefact are distinct refusals.

**Enforced by** the fifteen codes below, `test_subject_rehashing_is_not_skipped`,
`test_no_public_verifier_is_not_run_and_never_pass`.

## 6. Outcome states and what each licenses

| outcome | meaning | what it licenses |
|---|---|---|
| `INDEPENDENTLY_VERIFIED` | every check passed under a policy-selected, external, public root and a caller-supplied verifier | the statement is attested by a party the verifier could not impersonate; it does not make the statement true |
| `SELF_ISSUED` | a root-level refusal establishes that the envelope was issued by the same party: symmetric, candidate-tree provenance, same domain or self-issued basis | nothing about independence. It is not a pass and is never counted as one |
| `UNVERIFIED` | a root is unrecorded, stale, doubly recorded, or a signature, subject or payload check failed | nothing. The envelope may still be internally consistent, but no independence or subject binding is established |
| `NOT_RUN` | the procedure did not reach a signature decision: no public verifier was supplied for an otherwise acceptable root | nothing. It is deferred, never a pass |

A `SELF_ISSUED` result is recorded, counted separately and excluded from the
independently-verified aggregate. A `NOT_RUN` result is never promoted to a pass.

**Enforced by** `test_outcome_states_are_distinct`,
`test_the_four_real_envelopes_are_self_issued_and_never_independently_verified`.

## 7. The real result

`evidence/a12/VERIFICATION.json` records four envelopes against the artefacts
their A9 statements name:

| envelope | artefact | outcome | codes |
|---|---|---|---|
| `evidence/a10/ENVELOPES/a1-sarif.json` | `evidence/a1/SARIF.json` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |
| `evidence/a10/ENVELOPES/a5-admission.json` | `evidence/a5/ADMISSION.json` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |
| `evidence/a10/ENVELOPES/a7-delta.json` | `evidence/a7/DELTA.json` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |
| `evidence/a10/ENVELOPES/a8-shard-000.json` | `evidence/a8/SHARD-000.sarif` | `SELF_ISSUED` | `IV_REFUSED_SYMMETRIC`, `IV_REFUSED_CANDIDATE_TRUST_ROOT`, `IV_REFUSED_SELF_ISSUED` |

**The aggregate is 0 independently verified and 4 self-issued.** This is the
correct output of the machinery, not a defect to repair. The only recorded root is
the A10 test-only HMAC-SHA256 key, derived from a fixed public seed inside this
candidate. It is symmetric, its provenance is inside the candidate tree, and it
records a self-issued basis. No external trust domain exists, so no envelope can
be independently verified by this machinery today. Repairing that means
establishing a real external root, not relaxing a check.

The inventory states the absence of an external root explicitly in
`externalRoots` and `externalRootsNote`, rather than leaving the list empty
without explanation.

**Enforced by** `test_the_aggregate_is_zero_independently_verified`,
`test_the_four_real_envelopes_are_self_issued_and_never_independently_verified`.

## 8. Controls

`evidence/a12/CONTROLS.json` records one control per refusal code: 15 controls
over 15 codes. Each is built from a stub-signed A1 statement and a control root,
and each asserts its named code. The controls prove that the refusal fires for the
substituted form; they do not prove that the form occurs in the tree.

The positive control is labelled **control-only**. A caller-supplied stub verifier
accepts a distinct public-key root and the outcome becomes
`INDEPENDENTLY_VERIFIED`. It establishes that the decision procedure is reachable
and that the outcome state is not vacuous. It does **not** establish a real
independent party: the verifier is a test stub, no signature primitive is
implemented, and no real envelope is independently verified. The positive control
is excluded from the real aggregate.

| control | code |
|---|---|
| `envelope-invalid` | `IV_REFUSED_ENVELOPE` |
| `key-from-envelope` | `IV_REFUSED_KEY_FROM_ENVELOPE` |
| `symmetric-root` | `IV_REFUSED_SYMMETRIC` |
| `candidate-trust-root` | `IV_REFUSED_CANDIDATE_TRUST_ROOT` |
| `trust-root-unrecorded` | `IV_REFUSED_TRUST_ROOT_UNRECORDED` |
| `trust-root-digest-mismatch` | `IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH` |
| `same-domain` | `IV_REFUSED_SAME_DOMAIN` |
| `self-issued-basis` | `IV_REFUSED_SELF_ISSUED` |
| `signature-invalid` | `IV_REFUSED_SIGNATURE` |
| `payload-not-subject` | `IV_REFUSED_PAYLOAD_NOT_SUBJECT` |
| `subject-absent` | `IV_REFUSED_SUBJECT_ABSENT` |
| `subject-mismatch` | `IV_REFUSED_SUBJECT_MISMATCH` |
| `no-public-verifier` | `IV_REFUSED_NO_PUBLIC_VERIFIER` |
| `trust-root-stale` | `IV_REFUSED_TRUST_ROOT_STALE` |
| `multiple-roots` | `IV_REFUSED_MULTIPLE_ROOTS` |
| `stub-verifier-public-key` (control-only) | `INDEPENDENTLY_VERIFIED` |

**Enforced by** `test_controls_cover_every_code_and_fire`,
`test_the_stub_verifier_positive_control_is_control_only`.

## 9. Refusal table

| code | condition | wrong conclusion it prevents |
|---|---|---|
| `IV_REFUSED_ENVELOPE` | the bytes are not a parseable DSSE envelope, or the payload type is not the in-toto statement type | that a malformed or non-attestation envelope is read as the signed one |
| `IV_REFUSED_KEY_FROM_ENVELOPE` | the policy names no keyid | that the envelope chooses its own trust root |
| `IV_REFUSED_SYMMETRIC` | the root is symmetric or records no public material | that a verifier holding the signer's secret reports independence |
| `IV_REFUSED_CANDIDATE_TRUST_ROOT` | the root provenance or the inventory is inside the candidate tree | that the candidate authorises itself |
| `IV_REFUSED_TRUST_ROOT_UNRECORDED` | the policy keyid names no root, or the inventory is absent or malformed | that a key is trusted because it appears in an envelope |
| `IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH` | the provenance record is absent or its digest differs | that a changed key record is read as the establishing record |
| `IV_REFUSED_SAME_DOMAIN` | the root's domain equals the candidate's or the producer's, or is absent | that a root inside the producing party is external |
| `IV_REFUSED_SELF_ISSUED` | the root records a self-issued, same-party or absent basis | that a self-signed claim is third-party verification |
| `IV_REFUSED_SIGNATURE` | no policy-key signature verifies over the received PAE | that another key, or other bytes, is the selected root's signature |
| `IV_REFUSED_PAYLOAD_NOT_SUBJECT` | the payload is not a canonical statement, or the subject digest is not the artefact's bytes | that an attestation about different bytes is about the artefact under test |
| `IV_REFUSED_SUBJECT_ABSENT` | the artefact is absent | that a missing artefact matches an absent digest |
| `IV_REFUSED_SUBJECT_MISMATCH` | the statement names no subject equal to the artefact | that a statement about one artefact is about another |
| `IV_REFUSED_NO_PUBLIC_VERIFIER` | the root is acceptable but no public verifier was supplied | that an unchecked signature is verified, or that this module invents a primitive |
| `IV_REFUSED_TRUST_ROOT_STALE` | the root is older than the policy's freshness bound | that an expired root is current |
| `IV_REFUSED_MULTIPLE_ROOTS` | two roots claim the policy keyid | that one keyid resolves to two keys and the reader chooses |

`IV_REFUSED_ENVELOPE` is also the code when the received bytes are a parsed object
rather than bytes: a value that has lost the received byte identity is not
verified as those bytes.

## 10. Boundary with A14, A15, A16 and A17

* **A14 (role-bound authorisation).** A12 verifies that a statement was signed by
  a policy-selected external key. It does not decide whether that key is allowed
  to make this statement: a maintainer, an analysis producer, an adjudicator and a
  release authority are not interchangeable. A correct A12 result is necessary for
  A14, not sufficient.
* **A15 (thresholds over distinct trust domains).** A12 reports one outcome per
  envelope under one policy-selected key. It does not count signatures, apply a
  threshold, or decide whether two roots are distinct parties. Repeated signatures
  and aliases are A15's.
* **A16 (Sigstore bundles).** A12 has no certificate, transparency entry,
  inclusion proof or timestamp. A Sigstore bundle is A16's; A12's trust-root
  record is not a Sigstore identity.
* **A17 (transparency and omission resistance).** A12 can verify an envelope that
  exists; it cannot detect an envelope or an evidence record that was never
  published. Omission resistance requires the pre-registered manifest and signed
  reconciliation that A17 owns.

**Enforced by** `test_the_document_states_the_boundary`.

## 11. Non-claims

* An `INDEPENDENTLY_VERIFIED` outcome is not a claim that the statement is true,
  current, complete or useful. It is a claim that the verification decision was
  made outside the candidate and the producing party, under a recorded policy.
* A `SELF_ISSUED` outcome is not a malformed envelope and not a bug. It is the
  honest classification of a signature by the producing party.
* The stub-verifier positive control is not an independent party. It establishes
  the decision procedure only.
* The trust-root inventory can record an external root; recording one does not
  make it real, and no external root is recorded today.
* This tool implements no signature primitive. It cannot detect a weakness in the
  caller's verifier, and a caller that supplies a verifier which always returns
  `True` will cause `INDEPENDENTLY_VERIFIED`; that is why the real evidence
  supplies the A10 test-only verifier and still records zero.
* The tool does not prove that the key a root names belongs to the party the
  trust domain names. That is a review and A16/A18 obligation.
* No independent reviewer has adjudicated the code-to-conclusion mapping.

## 12. `NOT_RUN`

* **A real external trust root, key ceremony or external operator.** None exists;
  the inventory records zero external roots.
* **A production signature primitive.** No public-key signature algorithm is
  implemented or used; the positive control uses a stub verifier.
* **A14 role authorisation, A15 thresholds, A16 Sigstore bundles and A17
  transparency.** Not implemented here.
* **Freshness against a live clock.** Freshness is evaluated against the policy's
  recorded `asOf`, never a live clock, so the evidence is deterministic.
* **Independent review, BOUNDARY and SEAL.** No caller/dependency-closure audit,
  no independent reviewer and no full forensic regeneration.
* **The Rust suite.** `src/` was not modified.

## 13. Reproducing the evidence

```
python3 evidence/a12/build_evidence.py --source-commit 1d571da35
python3 forensics/tools/independent_verify.py roots
python3 forensics/tools/independent_verify.py verify \
    evidence/a10/ENVELOPES/a1-sarif.json evidence/a1/SARIF.json
python3 forensics/tools/independent_verify.py qualify
python3 -m unittest forensics.tools.tests.test_independent_verify
```

The producer reads the real envelopes, statements and artefacts, writes the
inventory, verifies the four envelopes, builds the controls and writes all three
records. Two runs are byte-identical and the committed bytes match a fresh build.
The source identity is supplied (`--source-commit`); without it the recorded
`BASE_COMMIT` is reused, never a live `HEAD`.
