# Trusted timestamping and offline verification (B2)

**Status: `PARTIAL`.** The offline half is implemented and tested; the trusted
half does not exist in this venue and is recorded as `NOT_RUN`.

| half | what it is | status |
|---|---|---|
| **B2a** | integrate an admitted RFC 3161 timestamp token and verify it against a TSA certificate chain and an admitted root | **`NOT_RUN`** — no TSA, no certificate, no root (`TA-B2` `UNMET`) |
| **B2b** | parse and verify a timestamp token offline; record the nine §B.9 times as nine distinct slots | implemented and controlled against deterministic fixtures |

This document is normative for both halves. It does not upgrade B2a: a fixture
token is not an authority, and no sentence here may be read as an admission of a
TSA, a certificate authority or a trust root.

The records are `evidence/b2/TIMES.json`, `evidence/b2/TOKENS.json`,
`evidence/b2/VERIFICATION.json` and `evidence/b2/CONTROLS.json`, produced
deterministically by `evidence/b2/build_evidence.py`. The verifier is
`forensics/tools/timestamp.py`; its controls are
`forensics/tools/tests/test_timestamp.py`.

---

## 1. Two claims that are not the same claim

A timestamp token carries a **message imprint**: a digest of some artefact. A
verifier can compare that imprint with the artefact's own digest **offline**,
with nothing but a hash function. That comparison answers exactly one question:
*were these bytes the bytes the token names?*

A **trusted time** is a different claim. It requires all of the following, in
addition to the imprint:

1. the token signature verifies under a TSA certificate;
2. the certificate chains to a root the verifier admits;
3. the certificate carries the `id-kp-timeStamping` extended key usage;
4. the certificate was valid at the asserted time;
5. the token's policy, nonce (where used), revocation and historical-validity
   requirements are satisfied;
6. the assertion came from an authority that the verifier chooses to trust.

None of 1–6 is checkable from an imprint. None of 1–6 is established here: the
venue has no TSA, no certificate, no root and no network. The strongest outcome
this repository can honestly reach is therefore
`TIMESTAMP_IMPRINT_VERIFIED_UNTRUSTED`, or
`TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED` when a caller supplies a certificate
and a verification function. **`TIMESTAMP_TRUSTED` is never produced.**
**Enforced by** `TS_REFUSED_IMPRINT`, `TS_REFUSED_ROOT`,
`Verification.as_dict()["trusted"] == False`, and
`test_timestamp.SignatureAndTrust.test_with_a_certificate_and_function_the_signature_verifies_untrusted`.

The two claims are recorded separately in
`TIMES.json#/twoClaims`: `imprintMatchesArtefact.checkableOffline` is `true`,
`authorityAssertedTheTime.checkableOffline` is `false`, and both
`establishedForRealArtefacts` are `0`. **Enforced by**
`test_timestamp.RealEvidence.test_the_two_claims_are_recorded_separately`.

---

## 2. The nine times of §B.9

§B.9 requires nine times, **recorded separately and never conflated**. They are
modelled as nine slots, each with `{name, clause, kind, value, source,
recordedBy, accuracy, established}` plus a `reason` when the value is absent or
unknown. The names and clauses are quoted from the addendum:

| # | name | §B.9 clause | kind | what would establish it |
|---:|---|---|---|---|
| 1 | `source-creation` | "source creation" | `local` | a tracked record of when the source tree was created |
| 2 | `experimental-execution` | "experimental execution" | `local` | a run record carrying its own execution timestamp |
| 3 | `evidence-production` | "evidence production" | `local` | the producer's own record of when the evidence was written |
| 4 | `statement-authentication` | "statement authentication" | `client` | a signer's record of when it authenticated the statement |
| 5 | `trusted-timestamping` | "trusted timestamping" | `authority` | an admitted TSA token with a verified chain and root |
| 6 | `transparency-inclusion` | "transparency inclusion" | `log` | an admitted log's integrated time or signed checkpoint |
| 7 | `witness-observation` | "witness observation" | `verifier` | an independent witness's record of observing the log |
| 8 | `release-promotion` | "release promotion" | `publication` | a release record identifying the promoted artefacts |
| 9 | `correction-or-revocation` | "subsequent correction or revocation" | `publication` | an authenticated correction or revocation record |

The kinds are not interchangeable: slot 5 is the only `authority` slot, and slot
6 is the only `log` slot. **Enforced by**
`TS_REFUSED_TIME_MODEL` and
`test_timestamp.NineTimes.test_the_model_has_exactly_the_nine_clause_slots_in_order`.

### 2.1 Ordering invariants

§B.9 states that experiment execution is never inferred solely from a later
timestamp, that an imported historical execution date is preserved separately
from the contemporary authentication/publication event, and that a transparency
commitment is never backdated. §B.33 shows the chain timestamp → inclusion →
verification → archival. From those clauses this document binds:

| earlier | later | clause basis |
|---|---|---|
| `source-creation` | `experimental-execution` | a run cannot precede its source |
| `experimental-execution` | `evidence-production` | evidence is produced from an execution |
| `evidence-production` | `statement-authentication` | a statement is authenticated after it exists |
| `statement-authentication` | `trusted-timestamping` | the token binds the authenticated material |
| `trusted-timestamping` | `transparency-inclusion` | §B.33: trusted timestamp before Rekor v2 inclusion |
| `transparency-inclusion` | `witness-observation` | a witness observes a checkpoint that exists |
| `transparency-inclusion` | `release-promotion` | a commitment is included before it is promoted |
| `release-promotion` | `correction-or-revocation` | a correction follows what it corrects |

A later time that precedes an earlier one is refused unless the later slot
carries a non-empty `explanation`; the only legitimate explanation in §B.9 is a
preserved historical execution date. **Enforced by** `TS_REFUSED_ORDER` and
`test_timestamp.NineTimes.test_each_ordering_invariant_is_enforced` /
`test_an_explained_inversion_is_accepted`.

### 2.2 Refusals specific to the time model

* **`TS_REFUSED_TIME_COLLAPSED`** — two slots carry the same value from the same
  source and recorder. This is the defect a single `timestamp` field produces: a
  record that reports nine events as one instant. **Enforced by**
  `test_timestamp.NineTimes.test_a_collapsed_pair_is_refused`.
* **`TS_REFUSED_TIME_UNSOURCED`** — a slot has a value and no tracked source,
  names a bare clock read, or infers `experimental-execution` from a later
  timestamp. A clock is not a record. **Enforced by**
  `test_timestamp.NineTimes.test_an_unsourced_time_is_refused`,
  `test_a_clock_read_is_not_a_source` and
  `test_execution_is_never_inferred_from_a_later_timestamp`.
* **`TS_REFUSED_TIME_MODEL`** — the record does not have exactly the nine slots,
  in order, with their declared kinds. **Enforced by**
  `test_timestamp.NineTimes.test_a_missing_slot_is_refused_by_the_model` and
  `test_a_wrong_kind_is_refused_by_the_model`.
* **`TS_REFUSED_ACCURACY`** — an established slot has no recognised accuracy
  token, or a token accuracy component is outside its declared range.
  **Enforced by** `test_timestamp.NineTimes.test_an_established_time_without_an_accuracy_is_refused`
  and `test_timestamp.Imprint.test_an_out_of_range_accuracy_is_refused`.

---

## 3. The record for the real artefacts

`TIMES.json` applies the nine slots to the four frozen A9 statements and the B1
fixture publication: five artefacts, forty-five slots. The result is what the
venue supports.

| state | slots | what it means |
|---|---:|---|
| `true` | 10 | two per artefact: `evidence-production` and `statement-authentication`, both at **day** accuracy from the A9/A10 `asOf` |
| `unknown` | 28 | the record names no value: source creation, execution, trusted timestamping, inclusion, witness, promotion |
| `false` | 7 | no correction or revocation exists (and, for the publication, no log inclusion and no witness) |

No slot carries an instant. The two established slots carry a **date** because
the producers record a date; they do not assert a time of day. No slot is filled
from the wall clock, and no slot is inferred from another slot.

For the published A9 statement `a8-shard-000` and the B1 publication the record
is:

| slot | state | value | source |
|---|---|---|---|
| `source-creation` | `unknown` | — | A8 manifest names candidates, no date |
| `experimental-execution` | `unknown` | — | SARIF runs carry candidates, not timestamps |
| `evidence-production` | `true` | `2026-11-24` | `a9/STATEMENTS.json#/sourceIdentity/asOf` (A9) / `b1/PUBLICATION.json#/recordedAt` (B1) |
| `statement-authentication` | `true` | `2026-11-24` | `a10/ENVELOPES.json#/sourceIdentity/asOf` |
| `trusted-timestamping` | `unknown` | — | `TA-B2` `UNMET` |
| `transparency-inclusion` | `unknown` (A9) / `false` (B1) | — | no admitted log; `FIXTURE-1` has no integrated time |
| `witness-observation` | `unknown` (A9) / `false` (B1) | — | no witness exists |
| `release-promotion` | `unknown` | — | no release promoted |
| `correction-or-revocation` | `false` | — | no correction exists |

The day-granularity limitation is stated in each slot's `reason`; it is not
rounded up to an instant. **Enforced by**
`test_timestamp.RealEvidence.test_most_real_slots_are_unknown_and_the_authority_slots_are`.

---

## 4. The offline verifier

`forensics/tools/timestamp.py` parses and verifies a `TimeStampToken` from the
RFC 3161 structure and a strict DER reader written for this purpose. It is not a
third-party timestamp library and it invokes no external program.

### 4.1 What it parses

* `ContentInfo` → `id-signedData` → `SignedData` (version 3);
* `EncapsulatedContentInfo` → `id-ct-TSTInfo` → `TSTInfo`;
* inside `TSTInfo`: `version` (must be 1), `policy`, `messageImprint`
  (`hashAlgorithm` + `hashedMessage`), `serialNumber`, `genTime`, `accuracy`,
  `ordering`, `nonce`, `tsa` and `extensions` presence;
* `SignerInfo`: digest algorithm, signed attributes (content-type and
  message-digest), signature algorithm and signature;
* the first certificate in the token, and a caller-supplied certificate for the
  EKU and root-presence checks.

### 4.2 What it verifies

| check | when it runs | outcome |
|---|---|---|
| strict DER | always | malformed, non-minimal, indefinite, high-tag, unconsumed or trailing bytes → `TS_REFUSED_DER` |
| token version | always | TSTInfo ≠ 1 or SignedData ≠ 3 → `TS_REFUSED_VERSION` |
| imprint algorithm | always | not the declared algorithm, or unknown → `TS_REFUSED_ALGORITHM` |
| message imprint | always | digest mismatch or wrong length → `TS_REFUSED_IMPRINT` |
| `genTime` | always | absent, non-UTC or not a calendar instant → `TS_REFUSED_GEN_TIME` |
| accuracy | when present | out of range → `TS_REFUSED_ACCURACY` |
| nonce | when the caller expects one | absent or different → `TS_REFUSED_NONCE` |
| content binding | always | the message-digest attribute disagrees with the eContent → `TS_REFUSED_SIGNATURE` |
| EKU | only with certificate **and** verification function | missing `id-kp-timeStamping` → `TS_REFUSED_EKU` |
| signature | only with certificate **and** verification function | rejected → `TS_REFUSED_SIGNATURE` |
| root presence | only when a root is supplied or required | absent/mismatched/not self-issued → `TS_REFUSED_ROOT` |
| chain | only when a chain-verification function is supplied | rejected → `TS_REFUSED_ROOT` |
| live-service | when asserted or requested | → `TS_REFUSED_LIVE_SERVICE` |

**Enforced by** the corresponding code in each row and the matching test in
`test_timestamp.Imprint` / `test_timestamp.SignatureAndTrust`.

### 4.3 What cannot be checked without a trust root

Without an admitted root, the verifier cannot establish:

* that the certificate belongs to a TSA;
* that the chain is valid, unrevoked and valid at `genTime`;
* that the token's policy is an admitted one;
* that the asserted time is true.

It can establish that the imprint matches the artefact, that the DER is strict,
that `genTime` is well formed, and — only if the caller supplies a certificate
and a verification function — that the signature verifies under that
certificate. That is why the outcome names `UNTRUSTED`.

A caller-supplied root is a **presence** check (`root=PRESENCE_ONLY`), not an
admission. **Enforced by**
`test_timestamp.SignatureAndTrust.test_a_matching_root_is_presence_only_and_never_trusted`.

### 4.4 No network

The module imports no `socket`, `subprocess`, `urllib`, `http`, `ftplib` or
`ssl`, calls no process-spawning function, and contains no `tsget` or `curl`
invocation. There is no live-service path; a token that asserts one is refused.
**Enforced by** `TS_REFUSED_LIVE_SERVICE` and
`test_timestamp.NoNetwork.test_the_module_imports_no_network_or_process_module`,
`test_the_module_calls_no_external_client` and
`test_importing_the_module_loads_no_network_module`.

---

## 5. The real result

`TOKENS.json` records **zero tokens** in the tree. The scan considers
`.tsr`, `.tst`, `.p7s`, `.der` and `.cms` files and parses each; none is an RFC
3161 token. `VERIFICATION.json` records the same for every artefact:

| artefact | imprint | signature | chain | root | outcome |
|---|---|---|---|---|---|
| `a9-a1-sarif` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `a9-a5-admission` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `a9-a7-delta` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `a9-a8-shard-000` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |
| `b1-publication` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `TIMESTAMP_NO_TOKEN` |

Aggregate: `trusted: 0`, `imprintVerified: 0`, `signatureVerified: 0`,
`chainVerified: 0`, `rootAdmitted: 0`. The absence is recorded, not hidden: no
token was fabricated to make the table greener. **Enforced by**
`test_timestamp.RealEvidence.test_no_token_exists_in_the_tree` and
`test_the_verification_aggregate_is_zero_trusted`.

The `controlBaseline` entry in `VERIFICATION.json` is a **fixture** token: it
shows the verifier works and reaches `TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED`.
It is labelled `control-only` and is not a result for any artefact.

---

## 6. Controls and canaries

`CONTROLS.json` records sixteen control-only fixtures and one positive control.
Every fixture is generated deterministically: a fixed control seed, a fixed
`genTime` of `20261124000000Z`, a fixed serial and nonce, and fixture-local policy
OIDs. Each refusal is paired with a canary: the same call with the mutated field
restored is accepted.

| control | refusal code | canary |
|---|---|---|
| truncated token | `TS_REFUSED_DER` | unmutated token accepted |
| one trailing byte | `TS_REFUSED_DER` | unmutated token accepted |
| `TSTInfo.version` = 2 | `TS_REFUSED_VERSION` | version 1 accepted |
| imprint of another artefact | `TS_REFUSED_IMPRINT` | declared artefact's imprint accepted |
| token names SHA-384, caller declares SHA-256 | `TS_REFUSED_ALGORITHM` | SHA-256 token accepted |
| `genTime` absent | `TS_REFUSED_GEN_TIME` | token with `genTime` accepted |
| certificate without EKU | `TS_REFUSED_EKU` | EKU certificate accepted |
| corrupted signature | `TS_REFUSED_SIGNATURE` | correctly signed fixture accepted |
| required root absent | `TS_REFUSED_ROOT` | same token accepted when no root is required |
| live-service assertion | `TS_REFUSED_LIVE_SERVICE` | normal fixture policy accepted |
| expected nonce 8, token nonce 7 | `TS_REFUSED_NONCE` | expected nonce 7 accepted |
| accuracy millis 1000 | `TS_REFUSED_ACCURACY` | accuracy millis 1 accepted |
| nine slots, one value | `TS_REFUSED_TIME_COLLAPSED` | nine distinct times accepted |
| slot value without source | `TS_REFUSED_TIME_UNSOURCED` | sourced fixture accepted |
| authentication before production | `TS_REFUSED_ORDER` | correctly ordered fixture accepted |
| eight slots | `TS_REFUSED_TIME_MODEL` | nine-slot fixture accepted |

**Enforced by**
`test_timestamp.RealEvidence.test_the_controls_cover_every_refusal_code`,
which also asserts every canary was accepted. A control that fires proves the
verifier refuses that mutation; it does not prove any TSA behaves as the fixture
does, and the fixtures earn no credit outside this module.

---

## 7. Refusal codes

| code | condition | prevents |
|---|---|---|
| `TS_REFUSED_DER` | the token is not one strictly encoded DER value (indefinite/non-minimal length, high-tag form, non-minimal INTEGER, unconsumed child, missing signed attribute, trailing bytes) | two readers disagreeing about the bytes |
| `TS_REFUSED_VERSION` | TSTInfo ≠ 1 or SignedData ≠ 3 | reading another structure as v1 |
| `TS_REFUSED_IMPRINT` | the imprint is not the artefact's digest, or has the wrong length | a token for another artefact |
| `TS_REFUSED_ALGORITHM` | the imprint/signer algorithm is not the declared one or is unknown | verifying under another algorithm |
| `TS_REFUSED_GEN_TIME` | `genTime` absent, non-UTC, or not a calendar instant | an absent/malformed time read as asserted |
| `TS_REFUSED_EKU` | the supplied certificate lacks `id-kp-timeStamping` | a non-TSA certificate accepted |
| `TS_REFUSED_NONCE` | an expected nonce is absent or different | a replayed/unrelated token answering a request |
| `TS_REFUSED_SIGNATURE` | the verification function rejects, or the message-digest attribute disagrees | an unsigned or altered TSTInfo reported as signed |
| `TS_REFUSED_ROOT` | a required root is absent, not self-issued, mismatched, or the chain is rejected | a token under a root it does not chain to |
| `TS_REFUSED_LIVE_SERVICE` | a live-service verification is asserted or requested | an online claim in a venue that opens no socket |
| `TS_REFUSED_TIME_COLLAPSED` | two slots carry one value from one source and recorder | nine events reported as one instant |
| `TS_REFUSED_TIME_UNSOURCED` | a value has no tracked source, names a clock read, or execution is inferred from a timestamp | an unsourced or inferred instant reported as recorded |
| `TS_REFUSED_ORDER` | a later slot precedes an earlier one without an explanation | a backdated submission presented as normal |
| `TS_REFUSED_ACCURACY` | an accuracy component is out of range or a slot's accuracy token is unknown | an impossible accuracy read as precision |
| `TS_REFUSED_TIME_MODEL` | the record is not exactly the nine slots, in order, with their kinds | a missing/renamed/re-kinded slot read as the model |
| `TS_NO_TOKEN` | no token exists for the artefact | reporting a verification that did not occur |
| `TS_OK` | the checks that could run passed | — |
| `TS_REFUSED_USAGE` | no command or a bad invocation | — |
| `TS_REFUSED_IO` | a file could not be read | — |

**Enforced by** `test_timestamp.DocumentSynchronisation.test_every_refusal_code_appears`
and the per-code tests named in §2.2 and §4.2.

---

## 8. Non-claims

* An imprint match is not a trusted time. It says the bytes match; it says
  nothing about who asserted when.
* A fixture token is not an authority. Its signature is HMAC under a fixed public
  seed, its certificate carries no CA signature, and no TSA issued it.
* No clock is trustworthy because it is read. No slot is filled from the wall
  clock, and a clock read is refused as a source.
* A verified signature under a caller-supplied certificate is not a verified
  chain and is not an admitted trust root.
* `TIMESTAMP_TRUSTED` is defined and never produced.
* Nine slots do not prove nine events occurred; they prove the record does not
  conflate the events it claims.
* The controls establish refusal of the mutations they contain, not conformance
  of any external TSA.

**Enforced by**
`test_timestamp.DocumentSynchronisation.test_the_document_states_the_non_claims`.

---

## `NOT_RUN`

* Any RFC 3161 request to a TSA, any token issued by an authority, any TSA
  certificate, chain, EKU evaluation or root admission for a real token.
* Signature verification of a real token; nonce correspondence with a real
  request; policy admission; revocation and historical-validity checks.
* Any network access, and any invocation of `openssl`, `tsget` or `curl`.
* A transparency inclusion time, a witness observation, a release promotion and a
  correction/revocation event: no such record exists.
* Independent review, BOUNDARY and SEAL evidence, and the Rust suite (`src/` was
  not modified).

The forward-freeze member `b2-receipt` is satisfied at `evidence/b2/RECEIPT.md`;
the freeze itself remains `OPEN`.
