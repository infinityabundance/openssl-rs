# DSSE v1 envelopes and the exact PAE (A10)

A DSSE envelope is the transport this project uses for a signed statement. It is
not the statement, not the signature's meaning and not a trust decision. This
document is normative for the framing, for the pre-authentication encoding (PAE)
and for the one rule that makes the signature mean anything: **verification is
over the bytes that were received**.

## 1. The problem

A DSSE signature is computed over a byte string derived from two values: the
`payloadType` and the payload bytes. If a verifier parses the payload into an
object and re-encodes it before computing that byte string, then a difference in
whitespace, key order, string escaping or number form changes the bytes. The
signature then covers the re-encoding, not the document that arrived.

That is not a cosmetic difference. Two JSON texts that parse to equal objects are
different documents as bytes:

```
{"subject": [],   "x":1}
{"subject":[],"x":1}
```

A verifier that "helpfully" canonicalises accepts a signature made over the
second while claiming to have verified the first. A signed statement has become a
different statement. The same defect appears as: a signature over a pretty-printed
statement accepted for a compact one, a signature over a reordered envelope
accepted for the received order, and a payload whose number form was normalised
(`1.0` or `1e0` accepted for `1`) read as the signed value.

The rule this item enforces is therefore:

> The PAE body is the payload **decoded from the received envelope bytes** and
> nothing else. The payload is never parsed before the signature check and never
> re-encoded at any point.

## 2. The PAE encoding, exactly

```
PAE(type, body) = "DSSEv1" SP decimal(len(type)) SP type SP decimal(len(body)) SP body
```

* `SP` is one byte, `0x20`.
* `len(type)` is the length of the **UTF-8 bytes** of the type, not the character
  count; `len(body)` is the byte length of the body.
* Each length is decimal ASCII with **no padding and no leading zero** (the value
  zero is written `0`).
* `type` is the type string's UTF-8 bytes; `body` is the payload bytes exactly.
* The concatenation is over those bytes. There is no JSON here: the PAE is not a
  re-serialisation of anything.

The specification's vector is recorded verbatim:

| field | value |
|---|---|
| type | `http://example.com/HelloWorld` (29 bytes) |
| body | `hello world` (11 bytes) |
| PAE (ASCII) | `DSSEv1 29 http://example.com/HelloWorld 11 hello world` |
| PAE (hex) | `44535345763120323920687474703a2f2f6578616d706c652e636f6d2f48656c6c6f576f726c642031312068656c6c6f20776f726c64` |
| PAE (SHA-256) | `217751fac2c4f14edb2c9297fbc34abcb016ba88e74757e875ec4ac16fb6b6a1` |

The vector is asserted by the producer, by the tests and in
`evidence/a10/ENVELOPES.json#/paeVector`; `evidence/a10/PAE-VECTOR.txt` carries
the exact bytes as hex. Enforced by `test_the_specification_vector_is_exact`, the
producer's assertion, and `test_the_vector_is_in_the_index_and_the_producer_asserts_it`.

Edge cases are fixed rather than left to interpretation: an empty type is `0`
bytes and an empty body is `0` bytes, so `PAE("", b"")` is `b"DSSEv1 0  0 "`
(two spaces in a row after the first length, because the empty type is followed by
its separator). A multi-byte type uses its UTF-8 byte length: `"\u00e9"` is two
bytes. Enforced by `test_an_empty_type_and_an_empty_body_are_encoded_with_zero_lengths`
and `test_a_multi_byte_utf8_type_uses_its_byte_length`.

`parse_pae` is the inverse and is strict: a declared type or body length that does
not match the bytes, a non-canonical decimal (a leading zero), or bytes after the
declared body are refused rather than re-interpreted.

## 3. The received-bytes rule

The verifier takes bytes. Its received-bytes entry point is
`verify_received_bytes` (a thin wrapper over `verify_pae`, so there is one
implementation). It accepts `bytes`, `bytearray` or `memoryview` and refuses a
`dict`, a `list` or a `str`, because a parsed or decoded value has already lost
the received byte identity (`DS_REFUSED_OBJECT_SUPPLIED`).

The verification order is fixed:

1. parse the **envelope** only, with duplicate-key detection at every object
   (`DS_REFUSED_DUPLICATE_KEY`), and refuse data after the JSON value
   (`DS_REFUSED_TRAILING_BYTES`);
2. base64-decode the payload strictly — canonical standard alphabet, canonical
   padding, no non-zero pad bits, no trailing data
   (`DS_REFUSED_BASE64_NONCANONICAL`);
3. compute `PAE(payloadType as received, decoded payload)` and require that the
   PAE body **is** those decoded bytes (`DS_REFUSED_PAE_RESERIALISED` if it is
   not);
4. call the caller's verifier over that PAE;
5. only then, and only when a statement is required, parse the verified payload
   as an in-toto Statement v1 (`DS_REFUSED_PAYLOAD_NOT_STATEMENT`);
6. return the **received** payload bytes, never a re-encoding.

The envelope itself is parsed because its fields must be read. That does not
weaken the rule: the PAE does not depend on the envelope's JSON encoding, and the
envelope is not signed. What must never be parsed before the check is the
**payload**.

Why re-serialisation is a different statement: the payload is the signed
document. A signature binds exact bytes. Any canonicalisation is a different byte
string, so it is a different statement — even when it parses to the same object,
and even when the difference is one newline. A verifier that accepts the
canonical form while claiming to verify the received form is asserting a fact
about bytes it did not check. Enforced by
`test_a_whitespace_difference_is_a_different_statement`,
`test_the_signature_is_over_the_received_bytes`,
`test_the_payload_is_not_parsed_before_the_signature_check` and
`test_a_verified_statement_payload_is_returned_as_received`.

There is one diagnostic that looks at a canonical form, and it can only reject:
when no signature verifies over the received bytes, and the payload is valid
JSON, and a signature verifies over a canonical re-encoding, the refusal is
`DS_REFUSED_PAE_RESERIALISED` rather than `DS_REFUSED_SIGNATURE_INVALID`. The
canonical form is never accepted; it only names why the received bytes were not
the signed bytes. Passing `classify_reserialisation=False` suppresses the
diagnostic and yields `DS_REFUSED_SIGNATURE_INVALID`.

## 4. The envelope contract

An envelope is a JSON object with exactly three members:

| member | type | rule |
|---|---|---|
| `payloadType` | string | required, non-empty; its UTF-8 bytes are the PAE type |
| `payload` | string | required; canonical standard base64 of the payload bytes |
| `signatures` | array | required, non-empty; each entry `{keyid, sig}` with `keyid` a string and `sig` canonical base64 |

* Unknown top-level members are refused (`DS_REFUSED_ENVELOPE_INVALID`) rather
  than ignored: forward-extension discipline is A11's, and this module does not
  guess.
* Duplicate keys at any object level are refused
  (`DS_REFUSED_DUPLICATE_KEY`): a repeated `payload` or `sig` would let a later
  value replace the verified one.
* A missing `payloadType`, `payload` or `signatures` is its own code
  (`DS_REFUSED_PAYLOAD_TYPE_MISSING`, `DS_REFUSED_PAYLOAD_ABSENT`,
  `DS_REFUSED_SIGNATURES_ABSENT`).
* `payloadType` is not defaulted and is not inferred from the payload. A verifier
  bound to an expected type refuses a different received type
  (`DS_REFUSED_PAYLOAD_TYPE_MISMATCH`).
* Base64 is decoded strictly. Two encodings of one byte string are not both
  accepted, and non-zero pad bits are refused rather than silently masked.
* `keyid` is an unauthenticated hint. This module never uses it to select a key;
  the caller's verifier receives it as a string and decides.

## 5. The signer and verifier boundary

**This module makes no trust decision.** It does not select a key, distribute a
key, bind a `keyid` to an identity, decide whether a signer is authorised, or
establish a root of trust. Those are other items':

* **A12** owns independent cryptographic verification and the root of trust; the
  verifier here is a caller-supplied callable `(keyid, pae_bytes, sig_bytes) ->
  bool`, and a real implementation must not verify with the unverified candidate.
* **A14** owns role-bound authorisation: a signature by a maintainer, an analysis
  producer, an adjudicator and a release authority is not interchangeable.
* **A16** owns the Sigstore bundle and its identity binding.
* **A9** owns the in-toto Statement v1 structure and its record bindings; this
  module only asks A9 whether verified bytes are structurally a statement.
* **A11** owns parser hardening beyond the rules stated here.

The `sign` and `envelope` functions take a signer callable; the module never
holds a long-lived key and never chooses one. The deterministic HMAC-SHA256
helper that ships in `forensics/tools/dsse.py` and backs the command line and the
producer is labelled `test-only` and derived from a fixed public seed. It proves
that the PAE is signed and verified over the same bytes; it proves nothing about
who signed. Enforced by `test_a_keyid_is_a_hint_and_selects_no_key` and
`test_the_signer_is_labelled_test_only_and_is_not_a_trust_root`.

## 6. The refusal table

Every code is stable and is cited verbatim by the tool, the tests, this document
and the evidence. The right-hand column is the wrong conclusion the code prevents.

| code | condition | prevents |
|---|---|---|
| `DS_REFUSED_ENVELOPE_INVALID` | not a JSON object with exactly the three members, or a member has the wrong JSON type | that an array, a bare payload, an unknown field or a non-string field is read as a DSSE envelope |
| `DS_REFUSED_DUPLICATE_KEY` | a duplicated object key in the envelope | that a second `payloadType`, `payload` or `sig` is silently discarded and a different field is verified |
| `DS_REFUSED_PAYLOAD_TYPE_MISSING` | no `payloadType` | that a payload is verified under a default or inferred type, losing the signed type boundary |
| `DS_REFUSED_PAYLOAD_TYPE_MISMATCH` | verification is bound to an expected type and the received type differs | that a payload signed under one type is verified or read as another |
| `DS_REFUSED_BASE64_NONCANONICAL` | wrong alphabet, wrong padding, non-zero pad bits, or trailing data | that two encodings of one byte string are both accepted, or bytes are recovered from a non-canonical encoding |
| `DS_REFUSED_PAYLOAD_ABSENT` | no `payload` | that an envelope with no payload is verified against an empty byte string |
| `DS_REFUSED_SIGNATURES_ABSENT` | no `signatures`, or an empty list | that an unsigned payload is read as a signed one |
| `DS_REFUSED_SIGNATURE_INVALID` | no supplied signature verifies over the PAE | that a payload whose bytes, type or signature changed is accepted |
| `DS_REFUSED_PAE_RESERIALISED` | the PAE body is not the decoded bytes, or a signature verifies only over a canonical re-encoding | that a payload parsed and re-encoded before verification is accepted as the payload that was signed |
| `DS_REFUSED_PAE_LENGTH` | a PAE declares a length that does not match its bytes, or a non-canonical decimal | that a PAE with a wrong length prefix is read as the concatenation it claims to be |
| `DS_REFUSED_PAYLOAD_NOT_STATEMENT` | a statement is required and the verified payload is not a structurally valid Statement v1 | that a structurally valid envelope over arbitrary bytes is read as an in-toto attestation |
| `DS_REFUSED_TRAILING_BYTES` | data after the JSON value | that a second document appended to an envelope is ignored while the first is verified |
| `DS_REFUSED_OBJECT_SUPPLIED` | a parsed object or decoded text was given instead of received bytes | that a caller's in-memory representation, which has lost the byte identity, is verified as those bytes |

Each code has one control in `evidence/a10/CONTROLS.json`, built by
`evidence/a10/build_evidence.py` and asserted by its exact code in
`forensics/tools/tests/test_dsse.py`:

| control | code |
|---|---|
| `invalid-envelope` | `DS_REFUSED_ENVELOPE_INVALID` |
| `duplicate-key` | `DS_REFUSED_DUPLICATE_KEY` |
| `missing-payload-type` | `DS_REFUSED_PAYLOAD_TYPE_MISSING` |
| `type-mismatch` | `DS_REFUSED_PAYLOAD_TYPE_MISMATCH` |
| `noncanonical-base64` | `DS_REFUSED_BASE64_NONCANONICAL` |
| `missing-payload` | `DS_REFUSED_PAYLOAD_ABSENT` |
| `missing-signatures` | `DS_REFUSED_SIGNATURES_ABSENT` |
| `bad-signature` | `DS_REFUSED_SIGNATURE_INVALID` |
| `reserialised-payload` | `DS_REFUSED_PAE_RESERIALISED` |
| `wrong-pae-length` | `DS_REFUSED_PAE_LENGTH` |
| `payload-not-statement` | `DS_REFUSED_PAYLOAD_NOT_STATEMENT` |
| `trailing-bytes` | `DS_REFUSED_TRAILING_BYTES` |
| `object-supplied` | `DS_REFUSED_OBJECT_SUPPLIED` |

A control that does not fire its named code is a producer assertion failure, not a
warning. Enforced by `test_the_controls_are_current_and_fire_their_codes` and one
test per code in the `Refusals` class.

## 7. The real envelopes

There is one envelope per A9 statement. Each signs the **exact committed bytes**
of the statement, verified with `require_statement=True`. Digests are over the
bytes: `payload` is SHA-256 of the decoded payload (equal to the statement's own
digest), `pae` is SHA-256 of the PAE, `envelope` is SHA-256 of the envelope file.

| envelope | statement | bytes | payload SHA-256 | PAE SHA-256 | envelope SHA-256 |
|---|---|---:|---|---|---|
| `evidence/a10/ENVELOPES/a1-sarif.json` | `evidence/a9/STATEMENTS/a1-sarif.json` | 549 | `d53bc4eb66f71bab7227fb9e590d151287a1d64b4446f8dd84b94ca8fef26329` | `a415381b43e461f86641fad9efd6677eeb83708c64f27d4d960dcc9c01835906` | `8b0aa7989f43e11a7a6773469ea5a423219fd291a09f5a1a66e48e0d4dee84cd` |
| `evidence/a10/ENVELOPES/a5-admission.json` | `evidence/a9/STATEMENTS/a5-admission.json` | 528 | `d17bb4c990893dc61ee06687a78b6c1b9a91b772e9dbefe233d1fa8b6c21e45f` | `8713695f2b61dbda99193efd15606c869f51d9de24b1824ec84c12b7c943806e` | `8f9144f20d9a6e8ce04dabe03ce701741149f2f5e2c59a5ec92721244d3ea93e` |
| `evidence/a10/ENVELOPES/a7-delta.json` | `evidence/a9/STATEMENTS/a7-delta.json` | 672 | `d4dfa5a3b374ffc4382964dcac61e8a785cfe7f833cbe5c7731a210c0fe7fba8` | `061a6b36bd909cf1f7ef9264e245eb96c6ebee7847fd9004880409f75d4a32ca` | `068ea1274eae816129be016ec4a043e92d9e2353029bbb88b4436f7cdecb3385` |
| `evidence/a10/ENVELOPES/a8-shard-000.json` | `evidence/a9/STATEMENTS/a8-shard-000.json` | 714 | `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582` | `9e08bc6c908d7964aa05af48a8e81c7806b6835febc31e9ecf022cb9c622280f` | `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9` |

All four use `payloadType` `application/vnd.in-toto+json` and the keyid
`test-only:hmac-sha256:8e10a5a15d233d54`.

**What the real envelopes establish:**

* the envelope framing of these exact statement bytes;
* that the PAE is computed over the received decoded bytes (`payloadSha256`
  equals the statement digest and `statementSha256`);
* that a signature over that PAE verifies — under the test-only key;
* that the verified payload is a structurally valid A9 Statement v1.

**What they do not establish:**

* authenticity. A test key is not a trust root, and its keyid names no party.
* identity or authorisation. `keyid` is an unauthenticated hint; A14's role model
  is absent.
* that the signing key was the one a maintainer would use; no key distribution
  exists here.
* transparency, inclusion or non-equivocation; A16/A17 are not implemented.
* that the A9 statements are true, current or complete. This item adds framing,
  not attestation content.
* independent verification. The producer verifies its own envelopes with the same
  test key it signed with; A12 must verify with a key the candidate cannot choose.

Enforced by `test_the_four_envelopes_verify_and_hold_the_statement_bytes` and
`test_the_signer_is_labelled_test_only_and_is_not_a_trust_root`.

## 8. The controls

`evidence/a10/CONTROLS.json` records 13 controls over the 13 codes: one per code.
Each is built in memory from a real statement's envelope and asserts its named
code; the producer reads the code from the tool and fails if it differs. Enforced
by `test_the_controls_are_current_and_fire_their_codes`, with one test per code in
`Refusals`.

The controls prove a refusal fires for the substituted form. They do not prove
that form occurs anywhere in the tree, and they do not test a second
implementation.

## 9. Non-claims

* An envelope is not evidence that its payload is true, useful or current. It is
  evidence that these bytes, this type and this signature are consistent under
  the PAE.
* A verified signature under a test-only key is not authenticity, authorisation,
  identity or a trust decision.
* The `keyid` is a hint and is not authenticated by this module.
* A structurally valid Statement v1 payload is not an admitted statement; A9's
  subject digests and record bindings are A9's, and `require_statement` does not
  re-hash subjects.
* The canonical envelope encoding this tool writes is for reproducible evidence
  only. Verification never re-encodes an envelope or a payload, and a
  caller-supplied envelope in any valid JSON encoding is verified as received.
* Re-running the producer reproduces bytes; that is a determinism result, not a
  signature that a third party should accept.
* No independent reviewer has adjudicated the code-to-conclusion mapping.

## 10. `NOT_RUN`

* **Independent cryptographic verification.** A12's root of trust, key
  distribution and real signature algorithms. The only signer here is the
  test-only HMAC.
* **Role-bound authorisation, thresholds, Sigstore bundles, transparency.**
  A14–A17.
* **Parser hardening beyond this item's rules.** A11's duplicate-key policy for
  payload JSON, oversize limits, signature-count bounds and algorithm downgrade.
* **Forward extensions.** Unknown envelope members are refused; no extension
  discipline is implemented.
* **JSON Schema validation** of the envelope against a published DSSE schema. No
  validator is in the standard library; `python3 -m json.tool`, the structural
  checks and the controls ran instead.
* **A production signer or any real key.** None exists in the tree and none was
  fabricated.
* **Subject re-hashing on the statement path.** `require_statement` uses A9's
  structural decode; the subject digest and record re-checks are A9's, and the
  A9 statements' own bytes are what is signed.
* **BOUNDARY.** No caller or dependency-closure audit, no independent review and
  no second implementation of PAE or of the envelope parser.
* **SEAL.** No full forensic regeneration, downstream replay or release candidate
  assurance.
* **The Rust suite.** `src/` was not modified, so no rebuild or `cargo test` was
  run.

## 11. Reproducing the evidence

```
python3 evidence/a10/build_evidence.py --source-commit da021a765
python3 forensics/tools/dsse.py verify evidence/a10/ENVELOPES/a1-sarif.json \
    --expected-type application/vnd.in-toto+json --require-statement
python3 -m unittest forensics.tools.tests.test_dsse
```

The producer signs the four A9 statements' exact bytes and verifies each envelope
before writing it. The source identity is supplied (`--source-commit`); without
it the recorded commit in `ENVELOPES.json` is reused, never a live `HEAD`. Every
input is audited by path and SHA-256 in `ENVELOPES.json#/sourceIdentity`. Two runs
are byte-identical and the committed files match a fresh build, enforced by
`test_the_producer_is_deterministic_and_matches_the_committed_bytes`.
