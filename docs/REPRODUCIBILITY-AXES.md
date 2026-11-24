# Signature reproducibility and artefact reproducibility (A13)

A deterministic signature and a reproducible build are two different claims. This
document is normative for keeping them apart: the two axes, the four
combinations, the scheme registry, the nonce-reuse refusal, the real result and
the controls. The implementation is `forensics/tools/reproducibility.py`; the
records are `evidence/a13/SIGNATURE.json`, `evidence/a13/ARTEFACT.json`,
`evidence/a13/CLASSIFICATION.json` and `evidence/a13/CONTROLS.json`; the
producer is `evidence/a13/build_evidence.py`; the controls are
`forensics/tools/tests/test_reproducibility.py`.

## 1. The two axes, and why they are orthogonal

**Signature reproducibility** is a property of a *scheme*: whether applying the
same key to the same message twice produces the same signature. HMAC-SHA256,
RSASSA-PKCS1-v1_5 and Ed25519 are deterministic. ECDSA with a fresh
per-signature nonce is randomised: a different signature each time is the
scheme working as designed.

**Artefact reproducibility** is a property of a *build*: whether building the
same sources with the same toolchain, environment and recipe twice produces the
same bytes. It is measured by two completed builds and a comparison of their
product digests.

The two measurements share no input. A stable signature is a statement about
`(key, message) -> signature`; a reproducible build is a statement about
`(sources, toolchain, environment) -> bytes`. Repeating the same envelope
byte-for-byte therefore shows that the signer is a deterministic function of its
inputs. It shows **nothing** about whether the artefact named inside the envelope
can be rebuilt. Conversely, two byte-identical builds do not make a randomised
signer deterministic, and a randomised signer's varying output is not a build
defect.

The wrong conclusion in each direction is ordinary: "the signatures are
identical, so the build reproduces", and "the build reproduces, so the signature
must be deterministic". The rest of this document makes both unavailable.

**Enforced by** `SR_REFUSED_SIGNATURE_AS_ARTEFACT`,
`SR_REFUSED_ARTEFACT_AS_SIGNATURE`, and
`test_the_two_axes_are_orthogonal`.

## 2. The four combinations

The cross product of a measured signature state and a measured artefact state is
a combination label. For each, the table names the inference a consumer may not
draw. A `SIGNATURE_VARIES` state is an accepted measurement for a randomised
scheme; it is never a failure.

| signature | artefact | combination label | prohibited inference |
|---|---|---|---|
| `SIGNATURE_STABLE` | `ARTEFACT_REPRODUCIBLE` | `STABLE_SIGNATURE__REPRODUCIBLE_ARTEFACT` | `SR_REFUSED_SIGNATURE_AS_ARTEFACT`, `SR_REFUSED_ARTEFACT_AS_SIGNATURE`, `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE` |
| `SIGNATURE_STABLE` | `ARTEFACT_NOT_REBUILT` | `STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT` | `SR_REFUSED_SIGNATURE_AS_ARTEFACT`, `SR_REFUSED_REBUILD_NOT_RUN`, `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE` |
| `SIGNATURE_VARIES` | `ARTEFACT_REPRODUCIBLE` | `VARYING_SIGNATURE__REPRODUCIBLE_ARTEFACT` | `SR_REFUSED_ARTEFACT_AS_SIGNATURE`, `SR_REFUSED_NONDETERMINISTIC_AS_FAILURE` |
| `SIGNATURE_VARIES` | `ARTEFACT_NOT_REBUILT` | `VARYING_SIGNATURE__NOT_REBUILT_ARTEFACT` | `SR_REFUSED_SIGNATURE_AS_ARTEFACT`, `SR_REFUSED_REBUILD_NOT_RUN`, `SR_REFUSED_NONDETERMINISTIC_AS_FAILURE` |

The first column never licenses the second. Combination 1 is two measurements
that happen to agree, not one measurement that proves the other. Combination 3
is the case that matters most for a randomised signer: the signatures vary and
the artefact still reproduces. Combination 2 is the real state of this project:
the signature is stable and no artefact has a rebuild.

A completed rebuild whose two products differ is `ARTEFACT_DIFFERS`, labelled
`STABLE_SIGNATURE__DIFFERING_ARTEFACT` or
`VARYING_SIGNATURE__DIFFERING_ARTEFACT`. It is also not one of the four
reproducibility combinations: there is no reproducibility to read.

**Enforced by** `test_all_four_combinations_are_named`,
`test_each_combination_names_its_prohibited_inference`,
`test_a_reproducible_artefact_does_not_make_a_randomised_signer_deterministic`.

## 3. The scheme registry and its determinism classes

The registry has four schemes. Each records `deterministic`, `symmetric`,
`randomised` and the repeat comparison.

| scheme | deterministic | symmetric | repeat comparison |
|---|---|---|---|
| `hmac-sha256` | yes | yes | byte equality |
| `rsa-pkcs1v15` | yes | no | byte equality |
| `ed25519` | yes | no | byte equality |
| `ecdsa` | no | no | non-equality plus a nonce-reuse check |

A deterministic scheme is compared by byte equality: two signatures over
recorded-identical inputs must be the same bytes. If they differ, the scheme
record or the signer is wrong, and the result is `SIGNATURE_VARIES` with
`SR_REFUSED_DETERMINISTIC_VARIED`. A randomised scheme is compared by
non-equality: distinct signatures are `SIGNATURE_VARIES` and are accepted. The
same comparison also checks for a repeated signature or a repeated nonce, which
is the separate `SIGNATURE_NONCE_REUSED` refusal.

An unrecorded scheme is `SIGNATURE_UNKNOWN` with
`SR_REFUSED_SCHEME_UNRECORDED`; the tool does not guess a determinism class.
Fewer than two attempts is `SIGNATURE_UNKNOWN` with
`SR_REFUSED_ATTEMPTS_INSUFFICIENT`; one signature is not a repetition. An
attempt with no decodable signature is `SIGNATURE_UNKNOWN` with
`SR_REFUSED_ATTEMPT_MALFORMED`.

**Enforced by** `test_the_scheme_registry_declares_the_four_classes`,
`test_a_deterministic_scheme_is_compared_by_byte_equality`,
`test_a_deterministic_scheme_that_varies_is_refused`,
`test_fewer_than_two_attempts_is_unknown`,
`test_an_unrecorded_scheme_is_unknown`.

## 4. Nonce reuse is a key-recovery defect, not reproducibility

In ECDSA the signature is `(r, s)` with `r` derived from a per-signature secret
nonce `k`. Two signatures over the same message that produce the same signature
used the same `k`. For two signatures `(r, s1)` and `(r, s2)` over known
messages, `k = (h1 - h2) / (s1 - s2) mod n` and the private key follows from
`s1 = k^-1 (h1 + r d) mod n`. A repeated nonce therefore recovers the private
key. It is not a reproducibility success, and the same signature twice is not
"stable".

The tool refuses the case as `SR_REFUSED_NONCE_REUSE` and reports
`SIGNATURE_NONCE_REUSED`. It checks both an equal signature and, when attempts
record a nonce, an equal nonce. A randomised scheme that varies is accepted; a
randomised scheme that repeats is refused.

**Enforced by** `SR_REFUSED_NONCE_REUSE`,
`test_a_randomised_scheme_that_repeats_is_refused`.

## 5. The real result

`evidence/a13/SIGNATURE.json` records the four real A10 envelopes, signed twice
with the same test-only HMAC-SHA256 key over the same A9 statement bytes. Each
pair is byte-identical, and each attempt reproduces the committed A10 envelope
digest exactly.

| envelope | scheme | attempts | envelope digest (both attempts) | state |
|---|---|---|---:|---|
| `a1-sarif` | `hmac-sha256` | 2 | `8b0aa7989f43e11a7a6773469ea5a423219fd291a09f5a1a66e48e0d4dee84cd` | `SIGNATURE_STABLE` |
| `a5-admission` | `hmac-sha256` | 2 | `8f9144f20d9a6e8ce04dabe03ce701741149f2f5e2c59a5ec92721244d3ea93e` | `SIGNATURE_STABLE` |
| `a7-delta` | `hmac-sha256` | 2 | `068ea1274eae816129be016ec4a043e92d9e2353029bbb88b4436f7cdecb3385` | `SIGNATURE_STABLE` |
| `a8-shard-000` | `hmac-sha256` | 2 | `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9` | `SIGNATURE_STABLE` |

**Signature stability is 4 of 4.** This is a property of HMAC-SHA256 and of the
fixed public test seed. It is not authenticity, not independence, and says
nothing about any build.

`evidence/a13/ARTEFACT.json` records the four evidence artefacts and the DSO
behind the A4 observations.

| subject | kind | recorded digest (first 12) | rebuild record | state |
|---|---|---|---|---|
| `evidence/a1/SARIF.json` | evidence artefact | `5c0cfee62512` | absent | `ARTEFACT_NOT_REBUILT` |
| `evidence/a5/ADMISSION.json` | evidence artefact | `d4871ec97ae3` | absent | `ARTEFACT_NOT_REBUILT` |
| `evidence/a7/DELTA.json` | evidence artefact | `0444a879bf4a` | absent | `ARTEFACT_NOT_REBUILT` |
| `evidence/a8/SHARD-000.sarif` | evidence artefact | `b16d376ae0b2` | absent | `ARTEFACT_NOT_REBUILT` |
| `artifacts/phase2/install/lib/libcrypto.so.3` | build product | `fd25cc9e6424` | recorded `NOT_RUN` | `ARTEFACT_NOT_REBUILT` |

**Artefact reproducibility is `ARTEFACT_NOT_REBUILT` for every subject, so no build-reproducibility claim is made.** The DSO is present and its digest matches
the digest recorded by A4, but a digest is an identity, not a reproduction. Its
rebuild record is the recorded `NOT_RUN`: `MemAvailable 22 GiB` is below the
24 GiB floor, the court is capped at 6 GiB, and the full rebuild script exits
101 in that court. The record is not promoted because the digest is stable.

`evidence/a13/CLASSIFICATION.json` classifies each real pair. Every pair is
`STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT`. The DSO is recorded as `UNPAIRED`: it
is a build product, not one of the four signed statements, and is not given a
signature-axis reading.

**Enforced by** `test_the_real_envelopes_are_signature_stable`,
`test_no_real_subject_is_reproducible`,
`test_the_dso_records_its_digest_and_not_run_rebuild`,
`test_every_real_pair_is_classified`.

## 6. Controls

`evidence/a13/CONTROLS.json` records one control per refusal code: 14 controls
over 14 codes. Each control asserts that its code is produced for the
substituted form. A control proves the refusal fires for that form; it does not
prove that the form occurs in the tree.

| control | code | mechanism | state |
|---|---|---|---|
| `signature-as-artefact` | `SR_REFUSED_SIGNATURE_AS_ARTEFACT` | classify | prohibited |
| `artefact-as-signature` | `SR_REFUSED_ARTEFACT_AS_SIGNATURE` | classify | prohibited |
| `deterministic-scheme-as-independence` | `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE` | classify | prohibited |
| `nondeterministic-as-failure` | `SR_REFUSED_NONDETERMINISTIC_AS_FAILURE` | classify | prohibited |
| `nonce-reuse` | `SR_REFUSED_NONCE_REUSE` | signature | `SIGNATURE_NONCE_REUSED` |
| `envelope-digest-as-build-digest` | `SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST` | artefact | `ARTEFACT_UNKNOWN` |
| `seed-as-key` | `SR_REFUSED_SEED_AS_KEY` | signature | `SIGNATURE_UNKNOWN` |
| `inputs-unstated` | `SR_REFUSED_INPUTS_UNSTATED` | signature | `SIGNATURE_UNKNOWN` |
| `rebuild-not-run` | `SR_REFUSED_REBUILD_NOT_RUN` | artefact | `ARTEFACT_NOT_REBUILT` |
| `scheme-unrecorded` | `SR_REFUSED_SCHEME_UNRECORDED` | signature | `SIGNATURE_UNKNOWN` |
| `replay-as-reproduction` | `SR_REFUSED_REPLAY_AS_REPRODUCTION` | artefact | `ARTEFACT_NOT_REBUILT` |
| `attempts-insufficient` | `SR_REFUSED_ATTEMPTS_INSUFFICIENT` | signature | `SIGNATURE_UNKNOWN` |
| `attempt-malformed` | `SR_REFUSED_ATTEMPT_MALFORMED` | signature | `SIGNATURE_UNKNOWN` |
| `deterministic-varied` | `SR_REFUSED_DETERMINISTIC_VARIED` | signature | `SIGNATURE_VARIES` |

The positive controls are `deterministic-stable` (accepted),
`randomised-varies` (accepted, not a failure),
`artefact-reproducible-synthetic` (accepted, **control-only**) and
`four-combinations` (each combination reachable with its prohibited inference).
The synthetic reproducible artefact is constructed from two equal build digests;
it is not a real rebuild and is excluded from the real result. The randomised
pair that varies is a synthetic randomised-scheme pair and is accepted; the
randomised pair that repeats is refused as `SR_REFUSED_NONCE_REUSE`.

**Enforced by** `test_controls_cover_every_code_and_fire`,
`test_the_randomised_varying_control_is_accepted`,
`test_the_synthetic_reproducible_control_is_control_only`.

## 7. Refusal table

| code | condition | wrong conclusion it prevents |
|---|---|---|
| `SR_REFUSED_SIGNATURE_AS_ARTEFACT` | a stable signature is read as evidence that the artefact can be rebuilt | that repeated identical signatures are a reproducible build |
| `SR_REFUSED_ARTEFACT_AS_SIGNATURE` | a reproducible artefact is read as evidence of a deterministic signer, or a randomised signer is called faulty | that a rebuild is a signature property |
| `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE` | a deterministic scheme or a fixed-seed test key is presented as an independent party | that determinism is independence (A12 owns independence) |
| `SR_REFUSED_NONDETERMINISTIC_AS_FAILURE` | a randomised scheme produces different signatures over the same bytes | that fresh randomness is a defect |
| `SR_REFUSED_NONCE_REUSE` | a randomised scheme produces the same signature twice, or records the same nonce | that nonce or randomness reuse is reproducibility; it is key recovery |
| `SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST` | an envelope or signed-record digest is offered as a build digest | that the envelope digest is the artefact digest |
| `SR_REFUSED_SEED_AS_KEY` | a raw seed is recorded as the signing key | that a fixed public test seed is a production key or trust root |
| `SR_REFUSED_INPUTS_UNSTATED` | the attempts or builds do not record the same inputs, or omit them | that a comparison of different inputs is a repetition |
| `SR_REFUSED_REBUILD_NOT_RUN` | no rebuild record exists, or its outcome is `NOT_RUN` | that a stable digest or an unrun rebuild is reproducible |
| `SR_REFUSED_SCHEME_UNRECORDED` | the scheme is absent from the registry | that an unknown scheme's repeat behaviour is known |
| `SR_REFUSED_REPLAY_AS_REPRODUCTION` | the rebuild record describes a replay of existing bytes | that copying a product is rebuilding it |
| `SR_REFUSED_ATTEMPTS_INSUFFICIENT` | fewer than two signature attempts are recorded | that one signature is stable or varying |
| `SR_REFUSED_ATTEMPT_MALFORMED` | an attempt has no decodable signature, or is not a record | that a missing signature is an attempt |
| `SR_REFUSED_DETERMINISTIC_VARIED` | a deterministic scheme varies over recorded-identical inputs | that a non-deterministic signer is normal reproducibility |

Every code is stable. The CLI always prints the code and the state, and exits 0
for a supported, non-refused answer (`SIGNATURE_STABLE`, `SIGNATURE_VARIES`,
`ARTEFACT_REPRODUCIBLE`, `ARTEFACT_DIFFERS`), 1 for a refusal
(`SIGNATURE_NONCE_REUSED`, `SIGNATURE_UNKNOWN`, `ARTEFACT_NOT_REBUILT`,
`ARTEFACT_UNKNOWN`), and 2 for a usage error.

**Enforced by** `test_the_document_names_every_refusal_code`,
`test_every_code_has_a_control`.

## 8. Boundary with A12 and with the release gate

* **A12 (independence).** A12 asks whether the verifier's root of trust is
  outside the candidate and the producing party. A13 asks whether a signature
  repeats and whether an artefact rebuilds. A deterministic signature is not an
  independent signature: HMAC is symmetric, so the verifier holds the signing
  key. `SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE` names that boundary, and
  the real result here is zero independence claims.
* **The release gate's package reproduction.** The release gate's package item
  (`forensics/tools/release_gate.py`, `gate-5`, and the ETP-6 package verifier)
  asks whether a specific published package contains the inputs its manifest
  names and whether the package verifies. A13 does not run a build, does not
  unpack a package and does not decide a release. It records whether the
  supplied rebuild record is a completed build. A completed rebuild here would
  be necessary for a reproducibility claim, never sufficient for a release.
* **A10/A11.** A10 owns the envelope, PAE and signature verification; A11 owns
  parser hardening. A13 reads their output as bytes and does not re-verify a
  signature, re-parse an envelope or re-run a parser.
* **ETP-2 and `verify.py rebuild`.** ETP-2 records the two-build artefact
  reproduction for its own candidate. The `verify.py rebuild` step is a
  different measurement at a different identity; A13 records its recorded
  `NOT_RUN` for the DSO and does not inherit ETP-2's result.

**Enforced by** `test_the_document_states_the_boundaries`,
`test_independence_and_reproducibility_are_distinct`.

## 9. Non-claims

* A `SIGNATURE_STABLE` result is not a claim that the signature is authentic,
  independent, authorized, current or useful. It is a claim that the scheme
  repeated its output over the recorded inputs.
* A `SIGNATURE_VARIES` result for a randomised scheme is not a defect, a
  downgrade or a failure to reproduce. It is the expected behaviour of the
  scheme.
* An `ARTEFACT_NOT_REBUILT` result is not a claim that the artefact is
  irreproducible. It is the absence of a rebuild record; a rebuild could change
  the answer.
* The synthetic `artefact-reproducible-synthetic` control is not a real build
  and is excluded from the real result.
* A recorded digest is an identity, not a reproduction. Re-hashing a file does
  not rebuild it.
* The tool implements no signature scheme and no build. It cannot detect a
  weakness in a caller's signer or builder.
* The HMAC key is derived from a fixed public test seed. It is not a production
  key and cannot establish authenticity or independence.
* No independent reviewer has adjudicated the code-to-conclusion mapping.

**Enforced by** `test_the_document_declares_non_claims`.

## 10. `NOT_RUN`

* **A completed rebuild of any subject.** Every subject is `ARTEFACT_NOT_REBUILT`.
* **A rebuild of the A4 DSO at its recorded digest.** The digest is recorded,
  not regenerated; the recorded rebuild is `NOT_RUN`.
* **A real randomised-scheme signing.** ECDSA is represented only by synthetic
  controls; no production ECDSA key or signer is used.
* **A production signature scheme or key.** The real envelopes use the A10
  test-only HMAC-SHA256 key.
* **A12 independence.** The real result licenses no independence claim.
* **A release decision or a package reproduction.** Neither is in scope.
* **Independent review, BOUNDARY and SEAL.** No caller/dependency-closure audit,
  no independent reviewer and no full forensic regeneration.
* **The Rust suite.** `src/` was not modified, so no rebuild or `cargo test` was
  run.

**Enforced by** `test_the_document_declares_not_run`.

## 11. Reproducing the evidence

```
python3 evidence/a13/build_evidence.py --source-commit 6b33f1caa
python3 forensics/tools/reproducibility.py classify
python3 -m unittest forensics.tools.tests.test_reproducibility
```

The producer reads the four A10 envelopes, the four A9 statements, the four
A1/A5/A7/A8 artefacts, the A4 DSO and its recorded digest, the ETP-T12 rebuild
record and the gate-reliability receipt. Every digest is computed from bytes;
the reasons a rebuild did not run are read from the recorded records. Two runs
are byte-identical and the committed files match a fresh build, enforced by
`test_the_producer_is_deterministic_and_matches_the_committed_bytes`. The source
identity is supplied (`--source-commit`); without it the recorded `BASE_COMMIT`
is reused, never a live `HEAD`.
