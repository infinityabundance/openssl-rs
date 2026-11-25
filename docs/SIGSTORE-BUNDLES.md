# Sigstore bundles — A16

Status: normative. Delivered by item A16 of `docs/ETP-TODO.md`, re-frozen at
candidate `2476a6ceafb4ad7cc9c95e44d9132f5052864a5f` (`staging`). The implementation is
`forensics/tools/sigstore_bundle.py`; the records are
`evidence/a16/INVENTORY.json`, `evidence/a16/PROFILE.json` and
`evidence/a16/CONTROLS.json`; the deterministic producer is
`evidence/a16/build_evidence.py`; the controls are
`forensics/tools/tests/test_sigstore_bundle.py`; the receipt is
`evidence/a16/RECEIPT.md`.

This document is normative for the offline bundle decision. It is cumulative
with `AGENTS.md`, `docs/EARNED-TRUST.md` (Articles 1, 2, 3 and 4),
`docs/DSSE-PAE.md` (A10), `docs/INDEPENDENT-VERIFICATION.md` (A12) and
`docs/TRUST-THRESHOLDS.md` (A15). Where this document and another describe the
same commitment, the stricter reading governs.

## 1. The problem: a bundle is portable but the roots are not in it

A Sigstore bundle is a portable record. It carries:

- a DSSE envelope (A10's PAE and signature);
- the signing certificate chain, or a public key;
- a transparency-log entry with an inclusion promise or proof;
- a timestamp.

Portability is the point and the trap. The bundle carries the **evidence**, not
the **roots**. The log's public key, the CA root that gives the certificate its
meaning, and the timestamp authority's root are supplied by policy and are **not
in the bundle**. The bundle also has no way to prove that its own
`integratedTime` is early enough relative to a later revocation.

A validator that reads only the bundle and prints "verified" has confused "the
record is well formed" with "the record is true". The wrong conclusion this item
prevents is: *"the bundle is verified"* when only its shape was checked.

- Enforced by `SB_REFUSED_CERT_ROOT_ABSENT`, `SB_REFUSED_LOG_KEY_ABSENT`,
  `SB_REFUSED_TIMESTAMP_ROOT_ABSENT` and `SB_REFUSED_POLICY_ABSENT`.
- Enforced by `test_no_verifier_at_all_is_unverifiable_and_never_verified` and
  `test_no_log_verifier_is_unverifiable_and_never_verified`.

## 2. The profile

Only `application/vnd.dev.sigstore.bundle.v0.3+json` is validated. The v0.1 and
v0.2 bundles use a different shape (`content` oneof, versioned media type); this
item does not validate them, so it refuses them as unsupported rather than
reading a v0.2 document with v0.3 field names and letting a missing field pass
vacuously. The refusal is recorded, not hidden.

The machine-readable field list is `sigstore_bundle.bundle_profile()`, written
unchanged to `evidence/a16/PROFILE.json`.

- Enforced by `SB_REFUSED_VERSION` and `SB_REFUSED_MEDIATYPE`.
- Enforced by `test_the_profile_record_matches_the_tool` and
  `test_every_refusal_code_has_a_control`.

## 3. The fields

| field | required | checked | cannot establish |
|---|---|---|---|
| `mediaType` | yes | exactly the v0.3 profile | that any particular tool produced it |
| `verificationMaterial` | yes | an object naming `x509CertificateChain` or `publicKey` | that the material belongs to the expected party |
| `x509CertificateChain.certificates[].rawBytes` | yes | canonical base64 DER, parsed structurally | that the chain is signed by a trusted CA |
| certificate `notBefore`/`notAfter` | yes | `notBefore <= integratedTime <= notAfter`, inclusive | that the certificate was not revoked later |
| certificate `issuer` | yes | exact match against `policy.expectedIssuer` | that the issuer actually issued it until `cert_verify` accepts the path |
| certificate `subjectAltName` | yes | a SAN equal to `policy.expectedIdentity` of the policy's `identityType` | that the workload controls the identity until `cert_verify` accepts the path |
| `dsseEnvelope.payload` | yes | `sha256(payload) == sha256(artefact)` | that the payload's content is true |
| `dsseEnvelope.signatures[].sig` | yes | caller-supplied `signature_verify` over the DSSE PAE | that it verifies with no verifier |
| `tlogEntries[]` | yes | non-empty | that the log is honest or append-only |
| `tlogEntries[].kindVersion` | yes | `{kind: dsse, version: 0.0.1}` | that the entry body is this envelope |
| `tlogEntries[].logIndex`, `.integratedTime` | yes | non-negative integers; the proof's index agrees; `treeSize` covers it | that the log assigned them |
| `tlogEntries[].inclusionPromise` or `.inclusionProof` | yes | one structurally valid form | that the proof verifies without the log key |
| `timestampVerificationData.rfc3161Timestamps[]` | yes | non-empty and canonical base64 | that the TSA signed it without the TSA root |

The `issuer` and SAN are what the certificate **claims about itself**. They
constrain a policy match; they are not authenticated facts until `cert_verify`
accepts the chain. This is why the profile reports them as extracted facts and
keeps `certificate-path` a separate check.

- Enforced by `SB_REFUSED_MATERIAL`, `SB_REFUSED_CERT_CHAIN`,
  `SB_REFUSED_EXPIRED_CERT`, `SB_REFUSED_ISSUER_MISMATCH`,
  `SB_REFUSED_IDENTITY_MISMATCH`, `SB_REFUSED_PAYLOAD_DIGEST`,
  `SB_REFUSED_TLOG_ABSENT`, `SB_REFUSED_TLOG_KIND`,
  `SB_REFUSED_INTEGRATED_TIME`, `SB_REFUSED_INCLUSION_PROOF`,
  `SB_REFUSED_TIMESTAMP_ABSENT` and `SB_REFUSED_TIMESTAMP_INVALID`.
- Enforced by `test_the_certificate_parser_extracts_the_claimed_fields`,
  `test_a_malformed_certificate_is_refused`,
  `test_public_key_only_material_is_refused_for_this_profile`,
  `test_the_payload_digest_binds_the_artefact` and
  `test_a_wrong_tlog_kind_is_refused`.

## 4. The offline verification order

The validator applies these checks in this order and stops at the first hard
failure. `NOT_RUN` checks do not stop the sequence; they accumulate and prevent
`BUNDLE_VERIFIED_OFFLINE`.

1. **Strict parse** — `harden.loads`, which refuses a duplicate key, a BOM, a
   non-finite number, trailing data and an over-large input.
2. **Media type and version** — v0.3 only.
3. **Bundle shape** — top level is an object with `mediaType`,
   `verificationMaterial` and `dsseEnvelope`; the embedded envelope has exactly
   `payloadType`, `payload` and `signatures`.
4. **Verification material** — X.509 chain present. A public-key-only bundle is
   recognised as material but refused, because this profile requires an issuer,
   a SAN and a validity window.
5. **Certificate chain** — canonical base64 DER, structurally parsed; every
   certificate in the chain must parse.
6. **Transparency entry** — at least one `tlogEntries` item.
7. **Entry kind** — `dsse` / `0.0.1` for every entry.
8. **Index and time** — non-negative integers, the proof's `logIndex` equals the
   entry's, `treeSize` covers `logIndex`.
9. **Certificate window** — every `integratedTime` is inside
   `[notBefore, notAfter]`, both ends inclusive.
10. **Issuer policy** — the certificate's claimed issuer equals
    `policy.expectedIssuer`.
11. **Identity policy** — a SAN equals `policy.expectedIdentity` at the policy's
    optional `identityType`.
12. **Payload binding** — `sha256(payload bytes) == sha256(artefact bytes)`.
13. **Inclusion presence** — every entry has a promise or a structurally valid
    proof.
14. **Inclusion verification** — only when the policy supplies a log key and a
    `log_verify` callable.
15. **DSSE signature** — only when a `signature_verify` callable is supplied.
16. **Certificate path** — only when a `cert_verify` callable is supplied.
17. **Timestamp** — present, then verified only when the policy supplies a TSA
    root and a `timestamp_verify` callable.

The certificate window is checked against the transparency entry's
`integratedTime`, not against the validator's clock, so a validator run years
later reaches the same result. That is deliberate: freshness is a property of
the record, and a live-clock comparison would make the result depend on when it
was run.

- Enforced by `test_the_window_is_inclusive_at_both_edges`,
  `test_one_second_outside_the_window_is_refused`,
  `test_inclusion_absent_present_unverifiable_and_verified` and
  `test_an_absent_path_is_not_run`.
- Enforced by `SB_REFUSED_BUNDLE_INVALID`, `SB_REFUSED_DUPLICATE_KEY` and
  `SB_REFUSED_INTEGRATED_TIME`.

## 5. What each offline check establishes, and what it cannot

| check | establishes | cannot establish |
|---|---|---|
| media type / version | the document claims the profile this item implements | that the producer followed it |
| certificate parse | the DER is well formed and the claimed window, issuer and SAN are readable | that any CA signed it |
| certificate window | the certificate was inside its claimed validity at the log's time | that it was not revoked after issue |
| issuer / identity match | the certificate's claimed issuer and SAN equal the policy | that the certificate belongs to the expected party until the path verifies |
| payload digest | the signed bytes are the artefact's bytes | that the artefact is correct |
| tlog kind / index / time | the entry is a DSSE entry with a consistent index and time | that the log accepted it |
| inclusion presence | a promise or proof exists and is structurally valid | that it verifies |
| inclusion verification | the supplied log verifier accepted the proof | that the log is append-only, honest or globally consistent |
| DSSE signature | the supplied signature verifier accepted the PAE | that the certificate's key is trusted |
| certificate path | the supplied certificate verifier accepted the chain | that the CA is trustworthy, or revocation status |
| timestamp | the supplied timestamp verifier accepted the token | that the TSA's clock was correct, or that no later revocation matters |

- Enforced by `test_inclusion_absent_present_unverifiable_and_verified`,
  `test_no_log_verifier_is_unverifiable_and_never_verified` and
  `test_no_verifier_at_all_is_unverifiable_and_never_verified`.

## 6. Trust-root and freshness assumptions

These are the assumptions the profile makes **explicitly**:

1. **The transparency-log public key is supplied by policy**, as
   `policy.logKey`, and the caller's `log_verify` decides inclusion. The key is
   **not in the bundle** and **not in this tree**. Without it inclusion is
   `NOT_RUN`, and the outcome cannot be `BUNDLE_VERIFIED_OFFLINE`. The
   validator cannot establish that the log is append-only, honest, or globally
   consistent.
2. **The CA root is supplied by policy**, as `policy.caRoots`, and the caller's
   `cert_verify` decides the path. It is **not in the bundle** and **not in this
   tree**. Without it the chain is `NOT_RUN`; a parsed certificate is not a
   verified chain. The validator cannot establish revocation status.
3. **The timestamp-authority root is supplied by policy**, as
   `policy.timestampRoots`, and the caller's `timestamp_verify` decides it. It is
   **not in the bundle** and **not in this tree**. Without it the timestamp is
   `NOT_RUN`; presence is not verification.
4. **The expected issuer and identity are supplied by policy**, as
   `policy.expectedIssuer` and `policy.expectedIdentity`. Without them any
   certificate would pass, so the check is `NOT_RUN` and the outcome cannot be
   verified.
5. **Freshness is judged at `integratedTime`, not at the validator's clock.** The
   window is inclusive at both ends. The profile cannot establish that a
   revocation did not happen after `integratedTime`; it can only say the
   certificate was valid at the time the log says it saw the signature.

The four A10 envelopes in this tree are HMAC-SHA256 envelopes signed by a fixed
public test key. They are self-issued DSSE. They are **not** Sigstore bundles,
carry no certificate, no transparency entry, no inclusion proof and no
timestamp, and are not counted as any.

- Enforced by `SB_REFUSED_LOG_KEY_ABSENT`, `SB_REFUSED_CERT_ROOT_ABSENT`,
  `SB_REFUSED_TIMESTAMP_ROOT_ABSENT`, `SB_REFUSED_POLICY_ABSENT` and
  `SB_REFUSED_EXPIRED_CERT`.
- Enforced by `test_policy_absent_is_unverifiable`,
  `test_no_log_verifier_is_unverifiable_and_never_verified` and
  `test_one_second_outside_the_window_is_refused`.

## 7. The real inventory: 0 bundles

`evidence/a16/INVENTORY.json` measures the tree, not the intention:

| quantity | measured |
|---|---:|
| 0 Sigstore bundles | 0 |
| 0 transparency logs | 0 |
| 0 certificates | 0 |
| A10 self-issued DSSE envelopes (not bundled) | 4 |

The population is a **frozen member list**, not a live glob:
`evidence/a16/INVENTORY.json` records the tracked `evidence/**/*.json` files that
existed at the declared candidate, each bound to its `sha256` read from that
candidate's blobs (never the working tree), and `populationFiles` is the list's
length. The record is frozen at
`2476a6ceafb4ad7cc9c95e44d9132f5052864a5f` (**503** members). This item's three own
records are not members: the record declares them separately as
`identityExcluded`, outside the declared cut. Four prior freezes are preserved
inside it with their record digests, rather than overwritten: the immediately
preceding freeze at `05b88afac77bc17886f4db8b2e41606a5abd291b` (503 members),
then the freeze at `9193603682cf77aab52247155ec8650963bb3af3` (503 members),
then the freeze at `e03653ddb913ab84a573800776901b6164487c74` (503 members,
whose records are those committed at `e94c7fdf127d2f2290f7f7c248924a4d6755add6`)
and the earliest freeze at `b26552e21a7465405ad542edeaef7b9104c0298d` (505
members), so the superseded history accumulates rather than replacing.

This item's three records — `INVENTORY.json`, `PROFILE.json` and
`CONTROLS.json` — are outside the population **by identity**: each embeds
`sourceIdentity.baseCommit`, so binding it to a population frozen at that commit
would make the member digest depend on the commit hash that depends on the
record's bytes (a commit-hash fixed point no commit can satisfy). They are not
part of the declared cut, and a record that lists any of them as a member is
refused with `PH_REFUSED_POPULATION_DRIFT` naming the path.

Separately, exactly three A11 records —
`evidence/a11/{SCAN,DIFFERENTIAL,CONTROLS}.json` — are outside it **by
declaration**, because A11 digests this item's records. That exclusion is
**declared, closed and reported**, not silent: the record stores the three paths
and the reason (mutual digest binding: A11's scan is complete over
`evidence/*.json` and therefore contains this item's records, so this population
cannot contain A11's without a cycle), and the growth report reports them as
`NEW_SINCE_RECORD` with their path and digest. An excluded path cannot be frozen
back in, a record whose declared exclusion is any other set is refused, and an
exclusion that names a path absent at the candidate is refused.

Any *other* file that matches the glob but is not a member is reported as
`NEW_SINCE_RECORD` with its path and digest, counted separately; it never changes
the recorded count, and a changed or removed member is refused with
`PH_REFUSED_POPULATION_DRIFT`. The certificate globs are frozen
the same way (empty at that candidate: 0 members). **A new bundle would appear
this way**: it
would be `NEW_SINCE_RECORD` until an explicit re-freeze and a fresh inventory
counted it, so a bundle added after this record cannot be silently included in
the `0` above.

A file is a bundle only when its **top level** carries a Sigstore bundle media
type. `evidence/a16/PROFILE.json` (the profile constant) and
`evidence/a16/CONTROLS.json` (the synthetic fixtures) mention the media type and
are not bundles; they are this item's own records, excluded from the population
by identity, and are not counted as bundles.

This is the honest result. There is no Sigstore bundle to verify, no log public
key, no CA root and no timestamp-authority root. Every real `validate`
invocation is therefore `NOT_RUN`, and `NOT_RUN` is never a pass.

- Enforced by `test_the_real_inventory_is_zero`, `test_every_control_is_control_only`,
  `test_two_runs_are_byte_identical_and_match_committed` and the
  `FrozenPopulation` controls `test_the_frozen_population_reproduces_at_this_tree`,
  `test_growth_is_reported_and_never_absorbed` and
  `test_a_new_bundle_after_the_freeze_is_new_since_record`.
- Enforced by `SB_REFUSED_INPUT_ABSENT` and `test_an_absent_path_is_not_run`.

## 8. The controls

`evidence/a16/CONTROLS.json` holds 27 synthetic fixtures covering all 23 refusal
codes, plus four boundary cases and one positive control. Every fixture is
labelled `control-only`.

The synthetic certificates are **structurally valid DER with a placeholder
signature**. They establish the parse and the decision procedure; they are not a
real certificate, not a real signing event and not an automated build
provenance. The positive control reaches `BUNDLE_VERIFIED_OFFLINE` only because
`cert_verify`, `signature_verify`, `log_verify` and `timestamp_verify` are
stub callables that accept. It is a control, not a verification of anything in
this tree.

The decisive cases:

| control | proves |
|---|---|
| `media-type`, `version-v0.2` | a non-bundle and an unsupported version are refused, not guessed |
| `bundle-invalid-no-envelope` | a missing DSSE envelope is invalid |
| `duplicate-key` | the strict reader refuses a second `mediaType` |
| `material-absent`, `cert-chain-empty` | no signer and no chain are refused |
| `cert-root-absent` | a parsed certificate is `NOT_RUN`, not verified |
| `certificate-expired-at-integrated-time`, `certificate-not-yet-valid-at-integrated-time` | one second outside the window on either side is refused |
| `issuer-mismatch`, `identity-mismatch` | policy identity is binding |
| `payload-digest` | the signature is over one artefact, not another |
| `tlog-absent`, `tlog-kind` | no entry and a wrong entry kind are refused |
| `integrated-time-index-disagreement` | the proof index must agree with the entry |
| `inclusion-proof-absent`, `inclusion-proof-rejected` | unproven and rejected inclusion are refused |
| `log-key-absent` | a proof present is not a proof verified |
| `timestamp-absent`, `timestamp-root-absent`, `timestamp-rejected` | required, root-gated and verifier-gated |
| `signature-rejected`, `signature-verifier-absent` | a rejected or unverified signature is not authentication |
| `policy-absent` | no expected issuer/identity means `NOT_RUN`, not "any identity" |
| `input-absent` | absence is `NOT_RUN`, never a pass |
| `network-import`, `sigstore-client-invocation` | the structural rule fires on a network import and a client call |
| `positive-structurally-complete` | the full decision procedure, under stubs, reaches `BUNDLE_VERIFIED_OFFLINE` |
| `at-not-before`, `at-not-after` | the window is inclusive at both edges |
| `one-second-before-not-before`, `one-second-after-not-after` | one second outside is invalid |

- Enforced by `test_every_control_is_control_only`,
  `test_every_refusal_code_has_a_control`,
  `test_every_control_observed_its_expected_code`,
  `test_the_positive_control_reaches_verified` and
  `test_the_boundary_cases_are_exact`.

## 9. The refusal table

Each code is stable and names the wrong conclusion it prevents. `BUNDLE_INVALID`
means a check failed; `BUNDLE_UNVERIFIABLE_OFFLINE` means a check could not run;
`NOT_RUN` means there was no record to check.

| code | condition | prevents |
|---|---|---|
| `SB_REFUSED_MEDIATYPE` | not a Sigstore bundle media type | an arbitrary JSON object read as a bundle |
| `SB_REFUSED_VERSION` | a Sigstore version other than v0.3 | a v0.1/v0.2 shape read with v0.3 names |
| `SB_REFUSED_BUNDLE_INVALID` | non-strict JSON, wrong top level, unknown field, missing/malformed envelope | a partial bundle read with empty defaults |
| `SB_REFUSED_DUPLICATE_KEY` | a duplicated object key at any depth | a second field silently winning |
| `SB_REFUSED_MATERIAL` | material absent, neither form present, or public-key-only | a bundle with no usable signer |
| `SB_REFUSED_CERT_CHAIN` | chain malformed or rejected by `cert_verify` | an unverified chain treated as verified |
| `SB_REFUSED_CERT_ROOT_ABSENT` | no CA root or `cert_verify` | a parsed certificate treated as a trusted one |
| `SB_REFUSED_EXPIRED_CERT` | certificate not valid at `integratedTime` | a certificate valid at another time |
| `SB_REFUSED_ISSUER_MISMATCH` | claimed issuer differs from policy | another issuer accepted under the policy |
| `SB_REFUSED_IDENTITY_MISMATCH` | no SAN equals the policy identity | another workload or domain accepted |
| `SB_REFUSED_PAYLOAD_DIGEST` | payload digest differs from the artefact digest | one artefact's signature presented for another |
| `SB_REFUSED_TLOG_ABSENT` | no transparency entry | an unlogged bundle read as logged |
| `SB_REFUSED_TLOG_KIND` | not `dsse`/`0.0.1` | another entry type read as this envelope's entry |
| `SB_REFUSED_INTEGRATED_TIME` | malformed or inconsistent index/time | a bad time placing the certificate window |
| `SB_REFUSED_INCLUSION_PROOF` | no promise/proof, malformed proof, or rejected proof | an unproven or rejected entry treated as included |
| `SB_REFUSED_LOG_KEY_ABSENT` | no log key or no `log_verify` | presence of a proof treated as verification |
| `SB_REFUSED_TIMESTAMP_ABSENT` | no timestamp | a bundle without freshness read as fresh |
| `SB_REFUSED_TIMESTAMP_ROOT_ABSENT` | no TSA root or no `timestamp_verify` | an unverified timestamp treated as verified |
| `SB_REFUSED_TIMESTAMP_INVALID` | malformed or rejected timestamp | a rejected timestamp treated as freshness |
| `SB_REFUSED_SIGNATURE` | signature absent, malformed, rejected or unverified | an unverified signature treated as authentication |
| `SB_REFUSED_POLICY_ABSENT` | no expected issuer or identity | any issuer and any SAN passing |
| `SB_REFUSED_NETWORK_OR_CLIENT` | a network import or a shell/client call in the source | an "offline" validator contacting a log or delegating to a client |
| `SB_REFUSED_INPUT_ABSENT` | the named bundle or artefact does not exist | an absent record reported as validated |

- Enforced by `test_every_refusal_code_is_documented` and
  `test_every_control_observed_its_expected_code`.
- Enforced by `sigstore_bundle.py` (`REFUSALS`), which carries the same condition
  and prevention for every code.

## 10. The no-network and no-client rule

The validator is offline by construction, not by intention. There is no network
call and no client invocation anywhere on the path:

- it imports no network client (`requests`, `urllib`, `http`, `socket`, `ssl`,
  and the rest of the A8 set) and no process-spawning module (`subprocess`);
- it does not shell out to `cosign`, `rekor-cli`, `sigstore`, `openssl` or
  `curl`;
- it installs and invokes no Sigstore client;
- it implements no signature primitive and holds no root.

The rule is **structural**, not a promise. `network_or_client_findings(source)`
parses the module with `ast` and returns a finding for a forbidden import, an
`os`/`posix`/`subprocess` shell call, or a call whose argument list starts with a
forbidden client name. The module's own source must return an empty list. The
test also asserts the module's import roots contain none of the forbidden
modules.

The limit is stated: an import spelled from a runtime string, or a command
assembled at run time, is not detected by this inspection. It is not a sandbox;
it is a source rule that fails closed on the spellings it can see.

- Enforced by `SB_REFUSED_NETWORK_OR_CLIENT`.
- Enforced by `test_the_module_imports_no_network_or_process_module`,
  `test_the_module_source_has_no_findings`,
  `test_a_network_import_is_refused_structurally`,
  `test_a_sigstore_client_invocation_is_refused_structurally` and
  `test_a_shell_call_is_refused_structurally`.

## 11. Non-claims

- `BUNDLE_VERIFIED_OFFLINE` does not mean the transparency log is
  trustworthy, append-only or honest. It means the caller's `log_verify`
  accepted the proof under the caller's log key.
- `BUNDLE_VERIFIED_OFFLINE` does not mean the CA is trustworthy or that the
  certificate was not revoked. It means the caller's `cert_verify` accepted the
  chain under the caller's CA root.
- `BUNDLE_VERIFIED_OFFLINE` does not mean the payload is true or the
  artefact is correct. It means the signed bytes are the artefact bytes and the
  supplied verifiers accepted the framing.
- `BUNDLE_VERIFIED_OFFLINE` does not mean the timestamp is trustworthy. It
  means the caller's `timestamp_verify` accepted the token under the caller's
  TSA root.
- **No bundle exists in this tree, so no real bundle is verified.** The only
  `BUNDLE_VERIFIED_OFFLINE` in this item is the `control-only` positive control
  under stub verifiers.
- The extracted issuer and SAN are unauthenticated until the path verifies. A
  policy match is a constraint, not a proof of identity.
- This item does not implement transparency-log inclusion mathematics, a
  certificate-path validator, a signature primitive or a timestamp verifier.
  Those remain caller-supplied, and their absence is `NOT_RUN`.

- Enforced by `test_the_document_states_the_assumptions_and_non_claims` and
  `test_no_verifier_at_all_is_unverifiable_and_never_verified`.

## `NOT_RUN`

The following are explicitly `NOT_RUN`, not passes:

- Any real Sigstore bundle: **0** exist in this tree.
- Any real transparency-log public key, inclusion-proof verification or
  append-only/consistency check: no log key and no `log_verify` exists here.
- Any real CA root, certificate-path validation or revocation check: no CA root
  and no `cert_verify` exists here.
- Any real timestamp-authority root or timestamp verification: no TSA root and
  no `timestamp_verify` exists here.
- Any real DSSE signature verification over a certificate's key: no key and no
  `signature_verify` exists here. The A10 envelopes use a test-only HMAC key
  (A12 records them as `SELF_ISSUED`), which is not a Sigstore certificate.
- A live-clock freshness check: freshness is judged at `integratedTime`, and no
  clock is read.
- An online Rekor/Rekor v2 lookup, a Sigstore client invocation, and any network
  call: forbidden structurally and not attempted.
- Independent review, a BOUNDARY audit, a SEAL, and the Rust suite (`src/` was
  not modified).
