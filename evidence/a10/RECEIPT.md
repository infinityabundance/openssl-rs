# A10 receipt — DSSE v1 envelopes with the exact PAE over the received bytes

## 1. Identity of this batch

| field | value |
|---|---|
| item | A10 (DSSE v1 envelope; pre-authentication encoding; verification over the received bytes; `keyid` an unauthenticated hint) |
| branch | `staging` |
| HEAD at the start | `da021a765` (`a9: a statement may not assert more than its record admits`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 22 18 0 5 23` (total 45, used 22, free 18, available **23** GiB); `Swap: 45 27 18` |
| derived court cap | `min(8g, 23 − 16) = 7g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The derived cap was 7 GiB and the running container's cap is 6 GiB, below it. The
container was reused rather than restarted, as A7, A8 and A9 did: one court holds
the memory budget, and restarting it would not lower the cap. Every reported gate
is Python-only and ran in that court. `free -g` after the work read
`Mem: 45 22 17 0 5 23` (available 23 GiB).

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/DSSE-PAE.md` | 334 lines | normative document: the problem; the PAE encoding exactly, with the specification vector; the received-bytes rule and why re-serialisation is a different statement; the envelope contract; the signer/verifier boundary (no trust decision); all 13 refusal codes and the wrong conclusion each prevents; the four real envelopes and what they do and do not establish; the 13 controls; non-claims; `NOT_RUN`; reproduction |
| `forensics/tools/dsse.py` | 852 lines | `pae`, `parse_pae`, `check_pae_body`, strict base64, `envelope`/`sign` over a caller-supplied signer, `verify_pae` and its received-bytes entry point `verify_received_bytes`, the in-toto statement check, the 13 codes, the labelled test-only HMAC helper and the `pae`/`sign`/`verify` command line |
| `forensics/tools/tests/test_dsse.py` | 639 lines | 44 controls: the specification vector; empty-type, empty-body and multi-byte UTF-8 length cases; one control per refusal code; a whitespace-different re-serialisation; a dict/str/list supplied instead of bytes; signing and verification over received bytes; canonical determinism; CLI exit codes with printed codes; the real envelopes and index; producer determinism and committed-bytes match; document synchronisation |
| `evidence/a10/build_evidence.py` | 408 lines | deterministic producer of the four envelopes, the index, the controls and the PAE vector record; reads every digest from bytes; asserts the vector and every control code |
| `evidence/a10/ENVELOPES/a1-sarif.json` | 910 bytes | DSSE envelope over `evidence/a9/STATEMENTS/a1-sarif.json` (`8b0aa798…`) |
| `evidence/a10/ENVELOPES/a5-admission.json` | 882 bytes | envelope over `evidence/a9/STATEMENTS/a5-admission.json` (`8f9144f2…`) |
| `evidence/a10/ENVELOPES/a7-delta.json` | 1,074 bytes | envelope over `evidence/a9/STATEMENTS/a7-delta.json` (`068ea127…`) |
| `evidence/a10/ENVELOPES/a8-shard-000.json` | 1,130 bytes | envelope over `evidence/a9/STATEMENTS/a8-shard-000.json` (`5bf418cc…`) |
| `evidence/a10/ENVELOPES.json` | 127 lines | index: payload type, payload/PAE/envelope digests, keyid, signer label, verified statement digest, the PAE vector, the signer's establishes/does-not-establish lists and the audited inputs |
| `evidence/a10/CONTROLS.json` | 144 lines | 13 controls over the 13 codes, with the code table and the wrong conclusion each prevents |
| `evidence/a10/PAE-VECTOR.txt` | 1 line | the specification PAE's exact bytes as hex |
| `evidence/a10/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A10 row only; no other row was touched and its
line count is unchanged. No existing record was edited, because no existing record
was defective (§6).

## 3. The rule

> Verification is over the bytes that were received. The payload is never parsed
> before the signature check and never re-encoded, because a difference in
> whitespace, key order, escaping or number form is a different statement.

The sentinel measure is the PAE:

```
DSSEv1 SP decimal(len(type)) SP type SP decimal(len(body)) SP body
```

with `SP` one 0x20 and every length the byte length in decimal ASCII, no padding
and no leading zeros. The signature is over those bytes.

A verifier that parses the payload and canonicalises it before computing the PAE
would accept a signature over a different byte string while reporting that it
verified the received document. Preventing that is the item's substance, so the
verifier takes bytes, refuses a `dict`/`list`/`str`, parses only the envelope,
decodes the payload strictly, computes the PAE from the received `payloadType` and
those decoded bytes, and requires that the PAE body is exactly those bytes.

## 4. The PAE vector and the real envelopes

The specification vector is asserted in the producer, the tests and the index:

| field | value |
|---|---|
| type | `http://example.com/HelloWorld` (29 bytes) |
| body | `hello world` (11 bytes) |
| PAE | `DSSEv1 29 http://example.com/HelloWorld 11 hello world` |
| PAE SHA-256 | `217751fac2c4f14edb2c9297fbc34abcb016ba88e74757e875ec4ac16fb6b6a1` |

Four envelopes, one per A9 statement, each signing the statement's exact
committed bytes under `application/vnd.in-toto+json` with the test-only key
`test-only:hmac-sha256:8e10a5a15d233d54`:

| envelope | statement | payload SHA-256 | PAE SHA-256 | envelope SHA-256 |
|---|---|---|---|---|
| `ENVELOPES/a1-sarif.json` | `evidence/a9/STATEMENTS/a1-sarif.json` | `d53bc4eb66f71bab7227fb9e590d151287a1d64b4446f8dd84b94ca8fef26329` | `a415381b43e461f86641fad9efd6677eeb83708c64f27d4d960dcc9c01835906` | `8b0aa7989f43e11a7a6773469ea5a423219fd291a09f5a1a66e48e0d4dee84cd` |
| `ENVELOPES/a5-admission.json` | `evidence/a9/STATEMENTS/a5-admission.json` | `d17bb4c990893dc61ee06687a78b6c1b9a91b772e9dbefe233d1fa8b6c21e45f` | `8713695f2b61dbda99193efd15606c869f51d9de24b1824ec84c12b7c943806e` | `8f9144f20d9a6e8ce04dabe03ce701741149f2f5e2c59a5ec92721244d3ea93e` |
| `ENVELOPES/a7-delta.json` | `evidence/a9/STATEMENTS/a7-delta.json` | `d4dfa5a3b374ffc4382964dcac61e8a785cfe7f833cbe5c7731a210c0fe7fba8` | `061a6b36bd909cf1f7ef9264e245eb96c6ebee7847fd9004880409f75d4a32ca` | `068ea1274eae816129be016ec4a043e92d9e2353029bbb88b4436f7cdecb3385` |
| `ENVELOPES/a8-shard-000.json` | `evidence/a9/STATEMENTS/a8-shard-000.json` | `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582` | `9e08bc6c908d7964aa05af48a8e81c7806b6835febc31e9ecf022cb9c622280f` | `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9` |

Every payload digest equals the A9 statement's own digest, and the producer
asserts that A9's `encode` of the statement decoded **after** verification is the
payload again. So the signature is over the bytes A9 emitted, and verification
returns the received bytes.

What the envelopes **establish**: the framing of these exact bytes; the PAE over
the received decoded bytes; that a signature over that PAE verifies under the
test-only key; that the verified payload is a structurally valid A9 Statement v1.

What they **do not**: authenticity (a test key is not a trust root); identity or
authorisation (A14); transparency (A16/A17); independent verification (A12); that
the A9 statements are true, current or complete. The producer verifies with the
same test key it signs with; that is a framing check, not a trust decision.

## 5. Controls and measured figures

`evidence/a10/CONTROLS.json` records 13 controls over the 13 codes: one per code,
built in memory from a real statement's envelope, each asserted by its exact code.

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

| quantity | measured |
|---|---|
| envelopes / statements | 4 / 4 |
| payload digests equal to the A9 statement digests | 4 / 4 |
| refusal codes | 13 |
| controls | 13 (one per code) |
| PAE vector | exact, asserted in the producer, tests and index |
| new `unittest` controls | 44 |
| whole tools suite | 1,047 (1,003 before this item) |

`DS_REFUSED_PAE_RESERIALISED` fires on the recorded control and on the structural
rule: a PAE whose body is a re-encoding is refused even when no signature is
involved. `DS_REFUSED_PAYLOAD_TYPE_MISMATCH` fires when verification is bound to
an expected type and the received type differs; with no expected type the
received type is part of the PAE, so a mutated `payloadType` fails as
`DS_REFUSED_SIGNATURE_INVALID`. That split is stated rather than hidden.

## 6. Defects found in existing records

**No defect was found in an existing record, and no existing record was edited.**
The checks that would have found one were run:

* **A9 statements.** All four were re-read as bytes, signed, verified and decoded
  through A9's `decode`; each payload digest equals the statement digest A9
  records and `intoto.encode(decoded)` reproduces the payload. No statement was
  re-encoded, reformatted or rewritten.
* **The specification guard.** `spec_guard.py check` still reports the pinned
  known-nonconformance token set for `docs/ETP-TODO.md` (89 tokens) with no drift:
  the A10 row introduces no internal Rust identifier in a code span and no source
  path.
* **Document consistency.** `docs_consistency.py` reports 20 claims agreeing, so
  no anchored claim was disturbed.

One defect **in this item's own producer** was found and fixed before the first
recorded run, and is preserved here: the `noncanonical-base64` control stripped
padding from the A1 statement's payload, but that statement's length is a multiple
of three so its base64 has no padding and the control did not fire. The control
now uses a payload whose encoding is padded (`{}` → `e30=` → `e30`). The previous
form failed the producer's assertion (it did not silently pass); the new form
fires `DS_REFUSED_BASE64_NONCANONICAL`. The check was not relaxed; the control was
made valid.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 22 18 0 5 23` (available 23 GiB); `Swap: 45 27 18` |
| new controls | `python3 -m unittest forensics.tools.tests.test_dsse` | `Ran 44 tests in 0.228s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1047 tests in 206.809s`; `OK` (**1,003 before + 44 new = 1,047, 0 failures, 0 errors**; no test removed, none newly ignored or skipped) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `ENVELOPES.json`, `CONTROLS.json` and the four envelopes | `ok` for all six, exit 0 each |
| producer, two runs | `python3 evidence/a10/build_evidence.py --out /tmp/a10a --source-commit da021a765` and the same to `/tmp/a10b` | `envelopes=4 statements=4 controls=13 codes=13 commit=da021a765` twice |
| producer byte-identity | `cmp` of `/tmp/a10a/<name>`, `/tmp/a10b/<name>` and `evidence/a10/<name>` | `identical` for `ENVELOPES.json`, `CONTROLS.json`, `PAE-VECTOR.txt` and all four envelopes |
| PAE vector | `python3 forensics/tools/dsse.py pae "http://example.com/HelloWorld" <file>` | stdout `DSSEv1 29 http://example.com/HelloWorld 11 hello world`; stderr `pae: code=DS_OK payloadType='http://example.com/HelloWorld' typeLength=29 bodyLength=11 paeSha256=217751fac2c4f14edb2c9297fbc34abcb016ba88e74757e875ec4ac16fb6b6a1`; exit 0 |
| envelope verification | `python3 forensics/tools/dsse.py verify <envelope> --expected-type application/vnd.in-toto+json --require-statement` | `verify: code=DS_OK …` for `a1-sarif`, `a5-admission`, `a7-delta`, `a8-shard-000`; exit 0 each; the payload SHA-256 in each line is the A9 statement digest |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/DSSE-PAE.md`, `?? evidence/a10/`, `?? forensics/tools/dsse.py`, `?? forensics/tools/tests/test_dsse.py` |

**Reproducibility.** The producer reads the four A9 statements as bytes and
computes every digest from them; nothing is typed. The key is derived from the
fixed `TEST_ONLY_SEED`, so the same statement bytes and the same type reproduce
the same envelope. `--source-commit` is supplied; without it the recorded commit
is reused, never a live `HEAD`. Two runs are byte-identical and the committed
files match a fresh build, enforced by
`test_the_producer_is_deterministic_and_matches_the_committed_bytes` and
`test_the_source_identity_is_supplied_not_read_live`.

## 8. Obligations retained

* **No authenticity.** The only signer is a test-only HMAC-SHA256 helper with a
  fixed public seed. A signature it produces establishes framing and PAE, not that
  any party signed and not that the key is trusted. A12 owns independent
  verification and the root of trust.
* **No identity or authorisation.** `keyid` is carried and returned as an
  unauthenticated hint. This module never selects a key with it. A14 owns the
  role model, A15 thresholds, A16 the Sigstore bundle.
* **No transparency.** A16/A17 are absent; an envelope is not an inclusion proof.
* **One signer form.** HMAC-SHA256 only. No asymmetric algorithm, no key
  distribution, no rotation, no revocation.
* **No second implementation.** The PAE and the envelope parser have one
  implementation and one set of tests; an independent implementation would be
  BOUNDARY evidence.
* **Parser scope.** Duplicate keys and trailing bytes in the envelope are refused,
  but a duplicate key inside the **payload** is never seen (the payload is not
  parsed here), oversize limits and signature-count bounds are absent, and any
  unknown envelope member is refused wholesale rather than by an extension rule.
  Those are A11's.
* **Reserialisation diagnosis is bounded.** The canonical form is consulted only
  to name a refusal, never to accept. A payload that is not valid JSON cannot be
  diagnosed that way and yields `DS_REFUSED_SIGNATURE_INVALID`; the received bytes
  are still never accepted.
* **`require_statement` is structural.** It uses A9's decode without re-hashing
  subject files; the A9 statement bytes themselves are signed, and A9 remains the
  owner of subject digests and record bindings.
* **No independent reviewer.** The author of the tool, document and controls is
  not an independent adjudicator of the code-to-conclusion mapping.

## 9. `NOT_RUN`

* **A12** independent cryptographic verification, root of trust and real key
  distribution.
* **A14–A17** role-bound authorisation, thresholds, Sigstore bundle, transparency
  and omission resistance.
* **A11** parser hardening: payload duplicate keys, encodings, size limits,
  signature-count bounds and algorithm downgrade.
* **Forward extensions.** Refused, not implemented.
* **JSON Schema validation** of the envelope against a published DSSE schema. No
  validator is in the standard library; `json.tool`, the structural checks and the
  controls ran instead.
* **A production signer or a real key.** None exists in the tree and none was
  fabricated.
* **Subject re-hashing** on the statement path (A9's, not this item's).
* **BOUNDARY.** No caller/dependency-closure audit, no independent review and no
  second implementation.
* **SEAL.** No full forensic regeneration, downstream replay or release candidate
  assurance.
* **The Rust suite.** `src/` was not modified, so no rebuild or `cargo test` was
  run.

## 10. Non-claims

An envelope is not evidence that its payload is true, useful or current. A
verification under the test-only key is not authenticity, identity or
authorisation. `keyid` is an unauthenticated hint. A structurally valid Statement
v1 payload is not an admitted statement. The canonical encoding the tool writes
for evidence is not a requirement on received envelopes: verification never
re-encodes an envelope or a payload. Deterministic reproduction of the envelopes
is a determinism result, not a signature a third party should accept.

## 11. Boundary with A9 and A12

A9 emits the bare in-toto Statement v1 and states that it is not a signed
attestation. This item adds exactly the next layer: the DSSE envelope, the exact
PAE over the received bytes and a `keyid` hint, under a test-only key. It does not
make the statement authenticated. A12 must verify the envelope under an authorised
key that the unverified candidate cannot choose; A14 must decide whether the
signer's role licenses the claim; A16/A17 must bind identity and transparency.
None of that is done here, and no envelope in this item is evidence that it has
been.
