# Security hazard register (ETP-T2)

**Status:** normative for ETP-T2 of `docs/ETP-TODO.md`.
**Analysis candidate:** `staging` at `6da02233f94152b865c9d02cdcfe5adeb34952e7`
(the worktree was clean at the start of the item).
**Register:** `evidence/etp-t2/HAZARDS.json` (schema
`openssl-rs/etp/hazards/1`), validated with `python3 -m json.tool` and by
`forensics/tools/hazard_register.py`.
**Projection:** `evidence/etp-t1/TRACEABILITY.json`, graph commit
`21bea318819a56f641b3aa2f25027216b97a1c4d`. The register's hazards are `hazard`
nodes in that graph; the graph records the register's digest, so a register that
drifts from its projection is refused.
**Checker:** `forensics/tools/traceability.py` (hazard structure and claim
reachability) and `forensics/tools/hazard_register.py` (register, fault trees,
FMEA, STPA-Sec, attack graphs and the cross-check).
**Tests:** `forensics/tools/tests/test_hazard_register.py` (23 controls) and the
extended `forensics/tools/tests/test_traceability.py` (17 controls).
**Receipt:** `evidence/etp-t2/RECEIPT.md`.

This is a security hazard analysis, not a safety proof. It records what each
hazard's trigger set is, what barrier exists, and whether that barrier has
evidence. It does not establish that a barrier works; it establishes that the
claim "a barrier exists" is either evidenced or labelled.

## 1. The three input classes

Every API family in scope is classified below. The classes are exhaustive for
this register and mutually exclusive for a single input value.

| class | definition | what the implementation guarantees |
|---|---|---|
| **1 legal** | The value satisfies the documented contract, including documented optionality: NULL where the header permits NULL, a live object, non-overlapping buffers where aliasing is forbidden, a length within the buffer. | The documented behaviour, including a defined error where the operation fails. Memory safety is claimed only where the safety inventory covers the path. |
| **2 adversarial but contract-valid** | An attacker controls the value but it still satisfies the contract: a hostile TLS record, a malformed certificate, a hostile peer public key, an attacker-chosen ciphertext or signature, a caller-chosen public geometry. | A defined refusal or a defined result; no invalid reference, no wrong object released, no silent wrong result. Panic safety is bounded by the barriers recorded here; where a barrier is absent the class-2 guarantee is not claimed. |
| **3 contract violation** | An invalid pointer, a wrong lifetime, overlapping buffers where aliasing is forbidden, a size beyond the buffer, NULL where the header requires non-NULL, a callback that frees the object it runs on, a re-entry the external contract forbids. | **No memory-safety claim.** The practical behaviour is recorded per hazard as one of `DEFINED_ERROR`, `ABORT`, `UB_NOT_CLAIMED_SAFE`, `DEFERRED_CRYPTOGRAPHIC_FAILURE`, `NOT_REACHABLE_FROM_CLASS_3`, together with whether that behaviour is a deliberate recorded divergence or an accident. |

### 1.1 Per-family classification

| family | entry points in scope | class 1 (legal) | class 2 (adversarial, contract-valid) | class 3 (contract violation) |
|---|---|---|---|---|
| `bn` | `BN_mod_exp_mont_consttime`, `BN_mod_exp_mont`, `BN_MONT_CTX_set_locked`, `BN_div`, `BN_mod_inverse`, `BN_CTX_get`, `BN_rand_range` | Live BIGNUM; odd non-zero modulus where required; NULL only where permitted. Checked allocation arithmetic; defined refusal of an even or zero modulus; fallible arithmetic returning 0. | Hostile peer key or attacker-chosen ciphertext as a BIGNUM; caller-chosen public width. Defined result or refusal; a prepared-domain mismatch is refused, not silently used. | Freed or aliased BIGNUM; `BN_CTX` outside start/end; width inconsistent with the buffer. `UB_NOT_CLAIMED_SAFE`. Some NULL tests return 0 by authority parity; the rest is an unchecked C contract. |
| `rsa` | `RSA_private_encrypt`, `RSA_private_decrypt`, `RSA_sign`, `RSA_blinding_on`, `RSA_blinding_off`, `RSA_set_method` | Well-formed key; documented padding; message no longer than the modulus; output buffer of `RSA_size`. Blinding on by default; implicit rejection for an internal key; defined error on failure. | Attacker-chosen ciphertext up to the modulus, hostile signature, or padding probe. The ciphertext is reduced and the padding check attempted; the external-key path takes the implicit-rejection arm with a secret-keyed KDK, but its returned length remains a channel (`HAZ-15`). | Freed key; concurrent method or key mutation; short output buffer; `flen` beyond the input. `UB_NOT_CLAIMED_SAFE`; the pointer contract is the authority's and is not enforced. |
| `ec` | `ECDSA_do_sign`, `ECDSA_sign_setup`, `ECDSA_do_verify`, `EC_KEY_set_method` | Live key on a signing-capable curve; digest; documented `nonce_type`. A secure scalar for `k`; zero rejection; a defined error when the deterministic arm is unavailable. | Attacker-chosen digest or message; hostile peer point; hostile signature. The group method validates the point; verification is a defined result. | Freed key or group; a point from another group; a nonce buffer of the wrong size. `UB_NOT_CLAIMED_SAFE`. |
| `evp` | `EVP_DigestVerifyFinal`, `EVP_DigestVerify`, `EVP_PKEY_verify`, `EVP_CipherUpdate`, `EVP_CipherFinal_ex`, `EVP_CIPHER_fetch` | Initialised context; documented parameter order and lengths; the return value read as documented. A defined return and error; IV uniqueness is the caller's documented obligation and is not enforced. | Hostile ciphertext, tag or AAD; malformed parameters; malformed certificate handed to a decoder. Authentication failure or a defined error; no plaintext claimed for a failed tag. | Reused context where reset is required; freed context; lying output length; overlapping input/output where forbidden; non-zero test of a return that can be `-1`. `UB_NOT_CLAIMED_SAFE` or `DEFERRED_CRYPTOGRAPHIC_FAILURE` per hazard. |
| `bio` | `BIO_set_callback_ex`, `BIO_read`, `BIO_write`, `BIO_ctrl`, `BIO_free`, `BIO_debug_callback_ex` | Live BIO; documented callback protocol; `cb_arg` NULL or a `BIO *`. The callback runs before and after the method; a non-positive pre-call result vetoes the operation. | Hostile stream contents; callback behaviour from an untrusted application layer. A defined return; the library does not sandbox the callback. | `cb_arg` that is not a `BIO *`; a callback that frees the BIO it runs on; a freed BIO. `UB_NOT_CLAIMED_SAFE`; the cast and the write through it are deliberate authority parity. |
| `x509` | `X509_verify_cert`, `X509_STORE_CTX_set_verify_cb`, `X509_policy_check`, `d2i_X509`, `X509V3_EXT_d2i` | Well-formed DER; live store context; `verify_cb` following the documented API. Bounded constructed nesting; an owned chain snapshot before a callback; defined verification errors. | Malformed or hostile certificate; deeply nested constructed value; very large extension; a certificate driving policy-tree growth. A defined parse or verification error; depth and length limits apply. | Freed context or certificate; a callback that mutates cached extension contents in place; a certificate replaced without the ownership protocol. `UB_NOT_CLAIMED_SAFE`; the chain is snapshotted, extension contents are not. |
| `runtime_mem` | `CRYPTO_malloc`, `CRYPTO_zalloc`, `CRYPTO_realloc`, `CRYPTO_free`, `CRYPTO_set_mem_functions`, `OPENSSL_cleanse` | Documented size branch; an installed hook that obeys the external contract. NULL and an error on exhaustion; checked size multiplication; whole-allocation cleansing on covered owners. | An attacker-controlled length reaching an allocation through a parsed field; memory exhaustion. An overflow is a checked failure, not a wrapped request; exhaustion returns NULL where the call site is fallible. | A hook that re-enters ERR on the same thread; a misaligned hook return; a free of a foreign pointer. `UB_NOT_CLAIMED_SAFE`; same-thread ERR re-entry is additionally refused by the B34 guard, a recorded safety divergence. |
| `provider_dispatch` | `OSSL_PROVIDER_load`, `OSSL_PROVIDER_unload`, `EVP_CIPHER_fetch`, `EVP_MD_fetch`, `EVP_PKEY_fetch`, `EVP_set_default_properties` | Fetched method used while the provider is loaded, with the documented reference-count discipline. Reference counting and a defined fetch failure. | Attacker-chosen algorithm name or property query; hostile parameters to a fetched implementation. A defined fetch failure or operation error. | A method pointer used after the provider is unloaded; a method table replaced concurrently. `UB_NOT_CLAIMED_SAFE`. |

## 2. The class-3 statement

**No class-3 input is claimed memory-safe anywhere in this register, and no
hazard's severity is reduced by assuming the caller obeys a contract the API
does not enforce.**

The mechanical consequence is a single rule:

- a hazard whose `trigger_classes` contains `contract_violation` must set
  `memory_safe_claim: false` and must name a `class3_disposition`;
- `traceability.py` refuses a violation with `TG_HAZARD_CLASS3_SAFE_CLAIM`;
- `hazard_register.py` refuses it with `HR_CLASS3_SAFE_CLAIM`.

Seven hazards are reachable from class 3: `HAZ-04`, `HAZ-06`, `HAZ-13`,
`HAZ-14`, `HAZ-18`, `HAZ-19`, `HAZ-20`. Five of them (`HAZ-04`, `HAZ-13`,
`HAZ-14`, `HAZ-19`, `HAZ-20`) are reachable **only** from class 3; they are
placed in the separate fault tree `TE-8`, never under `TE-4`, so the
distinction is structural rather than a sentence in a table.

What happens in practice for class 3 is not uniform, and the register records
the difference:

- **`DEFINED_ERROR`** — `HAZ-13`. The B34 thread-local guard refuses the
  same-thread ERR re-entry. This is a deliberate safety divergence from the
  authority, which would recurse.
- **`DEFERRED_CRYPTOGRAPHIC_FAILURE`** — `HAZ-18`. The API returns defined
  values, but a consumer that tests non-zero as success accepts an error. The
  C ABI cannot force the distinction.
- **`UB_NOT_CLAIMED_SAFE`** — `HAZ-04`, `HAZ-06`, `HAZ-14`, `HAZ-19`, `HAZ-20`.
  Some are authority parity (`HAZ-20`: `cb_arg` is `char *` and is cast to
  `BIO *`); some are a deliberately narrowed contract (`HAZ-19`); some are a
  stated residual (`HAZ-14`: an in-place mutation of a cached extension).
  None is an accident that the register is willing to call safe.

## 3. Hazards

| id | hazard | scope | primary input class | trigger classes | barrier |
|---|---|---|---|---|---|
| `HAZ-01` | Secret storage freed or abandoned without cleansing | `runtime_mem` | legal | legal, class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-02` | Secret-dependent branch, address or early exit survives optimisation | `bn` | class 2 | class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-03` | Secret-bearing allocation aborts or overflows | `runtime_mem` | legal | legal | `CLAIMED_NO_EVIDENCE` |
| `HAZ-04` | Ownership boundary triggers an invalid free or double release | `runtime_mem` | class 3 | class 3 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-05` | Reference or destructor runs over a partially initialised value | `runtime_mem` | legal | legal | `CLAIMED_NO_EVIDENCE` |
| `HAZ-06` | Callback re-enters and invalidates a borrow or lock | `x509` | class 3 | legal, class 3 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-07` | Secret-derived length survives into a copy or allocation | `bn` | legal | legal, class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-08` | RSA private operation runs without blinding | `rsa` | legal | legal | `CLAIMED_NO_EVIDENCE` |
| `HAZ-09` | Fault during CRT produces a faulty signature | `rsa` | class 2 | class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-10` | Stale Montgomery context yields a wrong-modulus result | `bn` | legal | legal | `CLAIMED_NO_EVIDENCE` |
| `HAZ-11` | ECDSA nonce biased or reused | `ec` | legal | legal | `CLAIMED_NO_EVIDENCE` |
| `HAZ-12` | Allocation arithmetic overflows on an attacker-controlled length | `runtime_mem` | class 2 | class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-13` | Allocator hook re-enters the error subsystem | `runtime_mem` | class 3 | class 3 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-14` | Verify callback mutates state the walk is reading | `x509` | class 3 | class 3 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-15` | External-key PKCS#1 v1.5 decryption where the authority has no implicit rejection | `rsa` | class 2 | class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-16` | Panic at the FFI boundary leaves partially mutated state | `runtime_mem` | class 2 | class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-17` | Hostile certificate exhausts stack, time or memory | `x509` | class 2 | class 2 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-18` | Consumer confuses a verification error with a valid signature | `evp` | class 3 | class 3 | **`BARRIER_ABSENT`** |
| `HAZ-19` | Shared object freed or method changed under a live operation | `bn` | class 3 | class 3 | `CLAIMED_NO_EVIDENCE` |
| `HAZ-20` | BIO callback writes through a non-BIO `cb_arg` | `bio` | class 3 | class 3 | **`BARRIER_ABSENT`** |

Counts: 20 hazards; 8 legal-triggered, 8 class-2-triggered, 7 class-3-triggered;
18 `CLAIMED_NO_EVIDENCE`, 2 `BARRIER_ABSENT`, 0 `EVIDENCED`. No barrier is
`EVIDENCED`. `HAZ-15` is `CLAIMED_NO_EVIDENCE`: the external-key PKCS#1 v1.5
arm takes the implicit-rejection check and keys the synthetic answer with
private CRT material or a per-key RNG secret, so the content distinction is
removed. The returned length still distinguishes valid from invalid padding:
the 2,048-block population in `evidence/haz-15/REENTRANCY-AND-LENGTH.md` matched
every protocol-relevant length, with a per-ciphertext probability of order
`1/246` (the 48-byte TLS pre-master length matched 9 of 2,048). The hazard is
only partially mitigated, so the evidence cannot support an `EVIDENCED` barrier.
The same follow-up repairs a re-entrancy edge in the first-use secret path: the
side table's lock is no longer held across the application-reachable
`RAND_priv_bytes` call, same-thread re-entry is a named refusal, peers wait on a
condition variable under a fixed bound, and destruction during initialisation
publishes nothing. That repair removes a deadlock, not the oracle. An independent
adjudication is still required before the obligation closes.

**HAZ-16 progress.** The barrier is no longer absent, but it is also not
claimed complete. A reproducible enumeration found 823 `guard_ffi`-wrapped
mutation candidates across the crate; 79 in the nine security-relevant object
owners were classified (`docs/FFI-FAILURE-ATOMICITY.md`,
`evidence/haz-16/CLASSIFICATION.json`): 72 `FAILURE_ATOMIC`, 3 `ROLLBACK`,
1 `POISONED`, 3 `PARTIAL_EXPOSED`. Three entries were repaired to
failure-atomic publication (`BN_BLINDING_update`, `BN_BLINDING_create_param`)
and remove-before-release (`OPENSSL_sk_pop_free`), each with a test-only panic
injection and a recorded revert control. The remaining 744 candidates are
`NOT_AUDITED`; the three `CRYPTO_EX_DATA` rows remain partial; `evp`, `rsa`,
`ec` and `x509` do not call `guard_ffi`, so a panic there aborts at the C
boundary and is a different, unanalysed defect class. `OBL-PANIC-ATOMICITY`
stays open and still blocks `REL-OPENSSH-B85C`.

## 4. Fault trees

Each tree is a JSON gate structure in `evidence/etp-t2/HAZARDS.json` and is
reproduced here as a readable expression. Every leaf is a mechanism in this
codebase or an assumption the register records; no leaf is "attacker exploits
bug".

### TE-1 — private-key disclosure

```
TE-1 = OR(
  AND(HAZ-08 blinding skipped,        ASM-TIMING-OBSERVER),
  AND(HAZ-11 nonce biased/reused,     ASM-SIGNATURES-OBSERVED),
  AND(HAZ-02 secret branch survives,  ASM-TIMING-OBSERVER),
  HAZ-01 un-cleansed storage,
  ASM-DRBG-COMPROMISE
)
```

Mechanism leaves: `rsa_ossl_private_encrypt`'s `RSA_FLAG_NO_BLINDING` skip;
`ecdsa_sign_setup`'s nonce draw; the constant-pattern ladder; `SecretBuf`'s
`Drop`. Assumptions: a timing observer, signature observation, and a fully
compromised DRBG (THR-08).

### TE-2 — signature forgery or verification bypass

```
TE-2 = OR(
  AND(HAZ-09 CRT fault,              ASM-FAULT-INJECTION),
  AND(HAZ-18 return-value confusion, ASM-CONSUMER-NONZERO-TEST)
)
```

Mechanism leaves: the CRT tail's congruence check and raw-`d` fallback;
`EVP_DigestVerifyFinal`'s 0/-1 distinction.

### TE-3 — plaintext disclosure

```
TE-3 = OR(
  AND(HAZ-15 external-key oracle,            ASM-ATTACKER-CHOSEN-CIPHERTEXT),
  HAZ-01 un-cleansed storage,
  AND(GCM encrypts without a uniqueness check, ASM-AEAD-NONCE-REUSE,
      ASM-ATTACKER-OBSERVES-CIPHERTEXTS)
)
```

The GCM leaf names `ossl_gcm_stream_update`; uniqueness is a caller obligation
the library documents and does not enforce (`FMEA-22`). The `HAZ-15` leaf names
the authority's mechanism: on the corrected candidate the external-key arm takes
the implicit-rejection check and keys the synthetic answer with secret key
material, so the content refusal that made the oracle observable is gone
(`D-RSA-EXTKEY-ORACLE-1`); the returned length remains a channel, measured over
2,048 invalid blocks with a per-ciphertext match probability of order `1/246`
(`evidence/haz-15/REENTRANCY-AND-LENGTH.md`). The leaf stays in the tree because
it is the mechanism a regression would reintroduce.

### TE-4 — memory corruption from a class-1 or class-2 input

```
TE-4 = OR(
  HAZ-05 partial initialisation on OOM,
  HAZ-12 allocation-arithmetic overflow,
  HAZ-06 callback invalidates a legal view,
  AND(HAZ-16 panic caught but state half-applied, ASM-PANIC-REACHABLE-FROM-CLASS2)
)
```

Class-3-only hazards are deliberately absent from this tree. They are in TE-8.

### TE-5 — denial of service by resource exhaustion

```
TE-5 = OR(
  AND(HAZ-03 infallible allocation aborts, ASM-UNBOUNDED-REQUEST),
  AND(HAZ-17 hostile nesting,              ASM-CALLER-CONTROLLED-CERTIFICATE),
  AND(ladder width follows caller geometry, ASM-CALLER-CONTROLS-PUBLIC-GEOMETRY)
)
```

### TE-6 — silent wrong result

```
TE-6 = OR(
  AND(HAZ-10 stale Montgomery context,         ASM-PREPARED-DOMAIN-REUSED),
  AND(HAZ-09 CRT result trusted after fallback, ASM-CRT-CHECK-IS-THE-ONLY-ORACLE)
)
```

### TE-7 — loss of constant-time behaviour

```
TE-7 = OR(
  AND(HAZ-02 secret branch,   ASM-TIMING-OBSERVER),
  AND(HAZ-07 secret length,   ASM-TIMING-OBSERVER),
  AND(HAZ-08 blinding skipped, ASM-TIMING-OBSERVER),
  AND(HAZ-11 nonce source,    ASM-SIGNATURES-OBSERVED)
)
```

### TE-8 — memory corruption reachable only from a contract violation

```
TE-8 = OR(
  HAZ-04 invalid free / double release,
  HAZ-13 allocator-hook re-entry,
  HAZ-14 verify_cb mutates a cached extension,
  HAZ-19 object freed or method changed under an operation,
  HAZ-20 BIO cb_arg is not a BIO
)
```

TE-8 exists so that "reachable only when the caller violates the contract" is a
property of the tree, not a footnote. No leaf of TE-8 is claimed memory-safe.

## 5. FMEA

30 rows over the admitted surfaces. `severity` is the local severity before the
barrier. `control evidence` is a T1 evidence id or `NONE`; `evidence_status`
distinguishes an evidenced control (`EVIDENCED`), a control that exists in source
but has no receipt (`CLAIMED_NO_EVIDENCE`), and an absent control (`NONE`).

| id | component | failure mode | top events | severity | control | evidence | status | residual |
|---|---|---|---|---|---|---|---|---|
| FMEA-01 | `CRYPTO_malloc` | allocation fails | TE-5 | MEDIUM | callers test NULL | NONE | CLAIMED_NO_EVIDENCE | infallible BN `Vec` sites abort |
| FMEA-02 | `CRYPTO_zalloc` | `count*size` overflow | TE-4, TE-5 | HIGH | `ossl_size_mul`, `checked_mul` | NONE | CLAIMED_NO_EVIDENCE | no length fuzz through every helper |
| FMEA-03 | allocator hook | same-thread ERR re-entry | TE-8 | HIGH | B34 thread-local guard | NONE | CLAIMED_NO_EVIDENCE | no re-entering-hook court |
| FMEA-04 | `OPENSSL_cleanse` | write elided | TE-1, TE-3 | HIGH | value barrier | NONE | CLAIMED_NO_EVIDENCE | no emitted-code receipt |
| FMEA-05 | `BN_CTX` scratch | uncleansed temporaries | TE-1 | MEDIUM | none recorded | NONE | NONE | `OBL-T12-RESIDUAL` |
| FMEA-06 | `BN_MONT_CTX_set_locked` | stale/mismatched context | TE-6 | HIGH | `context_matches` + `refuse_context` | NONE | CLAIMED_NO_EVIDENCE | no reuse differential |
| FMEA-07 | Montgomery slot | owner freed under operation | TE-8 | HIGH | atomic publication | NONE | CLAIMED_NO_EVIDENCE | precondition not enforced |
| FMEA-08 | `limbs` division | variable-time on secret | TE-7 | HIGH | `BN_FLG_CONSTTIME` routing | NONE | CLAIMED_NO_EVIDENCE | routing unmeasured (row T28) |
| FMEA-09 | `limbs::mul`/`rem` | infallible `Vec` | TE-5 | HIGH | partially fallible wrappers | NONE | CLAIMED_NO_EVIDENCE | `OBL-BN-ALLOCATOR` |
| FMEA-10 | constant-pattern ladder | secret branch survives | TE-7 | HIGH | BINSEC, branch audit | NONE | CLAIMED_NO_EVIDENCE | BINSEC returns unknown |
| FMEA-11 | staging transfer | secret-length branch | TE-7 | HIGH | public-width read | NONE | CLAIMED_NO_EVIDENCE | `OBL-T9-RESIDUAL` |
| FMEA-12 | `rsa_ossl_private_encrypt` | blinding disabled | TE-1, TE-7 | HIGH | default-on blinding | NONE | CLAIMED_NO_EVIDENCE | no timing court |
| FMEA-13 | `rsa_get_blinding` | blinding cannot be built | TE-1 | MEDIUM | operation fails | NONE | CLAIMED_NO_EVIDENCE | source-only |
| FMEA-14 | CRT tail | non-congruent result | TE-2, TE-6 | CRITICAL | re-exponentiate and fallback | NONE | CLAIMED_NO_EVIDENCE | no fault-injection receipt |
| FMEA-15 | external-key decryption | authority substitutes the refusing check | TE-3 | CRITICAL | implicit rejection with a secret-keyed KDK | NONE | CLAIMED_NO_EVIDENCE | returned length distinguishes; no timing measure, no independent adjudication |
| FMEA-16 | `BN_BLINDING` release | `BN_free`, not cleansed | TE-1 | MEDIUM | none | NONE | NONE | `OBL-T11-RESIDUAL` |
| FMEA-17 | RSA recombination | factor shape observable | TE-7 | HIGH | none | NONE | NONE | `OBL-T6-RESIDUAL` |
| FMEA-18 | `ecdsa_sign_setup` | biased/repeated `k` | TE-1 | CRITICAL | secure scalar, zero rejection, deterministic arm refuses | NONE | CLAIMED_NO_EVIDENCE | no nonce court; D333 open |
| FMEA-19 | `EVP_DigestVerifyFinal` | `-1` read as success | TE-2 | HIGH | documented contract | NONE | CLAIMED_NO_EVIDENCE | no consumer audit |
| FMEA-20 | provider method store | use after unload | TE-8 | HIGH | reference counts | NONE | CLAIMED_NO_EVIDENCE | no unload-race court |
| FMEA-21 | `EVP` fetch | no implementation matches | TE-5 | LOW | defined fetch failure | NONE | CLAIMED_NO_EVIDENCE | no failure-matrix receipt |
| FMEA-22 | GCM IV handling | IV reuse | TE-3 | CRITICAL | none (caller obligation) | NONE | NONE | recorded as an assumption |
| FMEA-23 | `BIO_debug_callback_ex` | non-BIO `cb_arg` | TE-8 | CRITICAL | none (parity) | NONE | NONE | class 3 only |
| FMEA-24 | BIO callback | frees the BIO mid-operation | TE-4 | HIGH | none | NONE | NONE | application behaviour |
| FMEA-25 | `addr_validate_path_internal` | callback replaces the chain | TE-8 | HIGH | `ChainSnapshot` | NONE | CLAIMED_NO_EVIDENCE | no reentrancy court |
| FMEA-26 | cached extension | callback mutates in place | TE-8 | HIGH | none | NONE | NONE | stated residual |
| FMEA-27 | ASN.1 decoder | hostile nesting | TE-5 | MEDIUM | depth caps | NONE | CLAIMED_NO_EVIDENCE | no resource measurement |
| FMEA-28 | X.509 policy tree | OOM mid-construction | TE-4 | HIGH | `OwnedTree`/`OwnedLevels` | NONE | CLAIMED_NO_EVIDENCE | unit test, not receipt |
| FMEA-29 | `guard_ffi` | panic interrupts state | TE-4, TE-6 | HIGH | non-unwinding plus three failure-atomic repairs (HAZ-16) | NONE | CLAIMED_NO_EVIDENCE | 744 candidates `NOT_AUDITED`; three `CRYPTO_EX_DATA` rows partial; `evp`/`rsa`/`ec`/`x509` abort path unanalysed |
| FMEA-30 | ownership adoption | wrong provenance or release | TE-8 | HIGH | unsafe adoption contracts | NONE | CLAIMED_NO_EVIDENCE | no provenance audit |

**Population of `CLAIMED_NO_EVIDENCE`:** 22 rows. **Absent controls
(`NONE`):** 8 rows — `FMEA-05`, `-15`, `-16`, `-17`, `-22`, `-23`, `-24`, `-26`.
**Rows with an evidenced control:** 0.

The zero is not a gap in the table; it is the finding. The T1 evidence tier
(101 evidence nodes) contains instrument qualifications, consumer-closure
receipts and queue-status prose, but no receipt binds a control at one of these
30 components to a measured run.

## 6. STPA-Sec

### 6.1 Control structure

```
CS-APP (application)
  -> CS-API (OpenSSL-compatible C ABI)
       -> CS-EVP (fetch and dispatch)
            -> CS-KERNEL (BN / RSA / EC / cipher kernels)
                 -> CS-ALLOC (allocator seam) -> CS-OS (libc, OS entropy)
                 -> CS-RNG (DRBG)
       -> CS-X509 (ASN.1 parse and verification walk)
            -> CS-ALLOC
            -> CS-CB (verify_cb)
       -> CS-APP (status code and ERR queue)
  -> CS-CB (callback registration and cb_arg)
       -> CS-API (re-entry)
```

`CS-CB` is both an actuator (the library calls application code) and a
controller (the application re-enters through the API). That double role is the
reentrancy edge of `AGENTS.md` §21.

### 6.2 Unsafe control actions

| id | controller | control action | context | loss | hazards | barrier |
|---|---|---|---|---|---|---|
| UCA-01 | CS-API | publish a handle whose lifetime is the caller's | another thread frees the owner or changes its method | use after free / data race | HAZ-19 | atomic slot only; precondition unenforced |
| UCA-02 | CS-API | invoke an application callback holding a reference into a stack or extension | the callback releases, replaces or mutates that object | dangling view | HAZ-06 | x509 snapshot; no BIO or extension-content barrier |
| UCA-03 | CS-ALLOC | call the installed hook while ERR holds the thread's state | the hook calls the ERR API on the same thread | second mutable borrow | HAZ-13 | B34 guard fails closed |
| UCA-04 | CS-KERNEL | exponentiate with blinding disabled | the application disabled blinding or it could not be built | timing channel | HAZ-08 | default-on only |
| UCA-05 | CS-KERNEL | return the v1.5 padding verdict for an external key | the key has `RSA_FLAG_EXT_PKEY` | padding oracle | HAZ-15 | implicit rejection with a secret-keyed KDK; the returned length remains a channel (`D-RSA-EXTKEY-ORACLE-1`) |
| UCA-06 | CS-KERNEL | return a prepared-domain result | the context belongs to another modulus | silent wrong result | HAZ-10 | `context_matches` |
| UCA-07 | CS-KERNEL | return a CRT result | a fault occurs in one CRT half | faulty signature | HAZ-09 | congruence check + fallback |
| UCA-08 | CS-API | catch a panic and return the failure value | the operation already mutated a context | half-applied state | HAZ-16 | non-unwinding plus the three failure-atomic repairs; the rest of the surface is unclassified |
| UCA-09 | CS-EVP | return a verification status | a consumer tests non-zero as success | acceptance of an unverified signature | HAZ-18 | documented contract only |
| UCA-10 | CS-CB | write the debug trace through `cb_arg` | `cb_arg` is not a `BIO *` | write through an arbitrary pointer | HAZ-20 | none |
| UCA-11 | CS-ALLOC | abort when an infallible allocation fails | the secret-bearing BN path allocates while memory is exhausted | denial of service | HAZ-03 | partially fallible |
| UCA-12 | CS-X509 | continue the walk after a callback | the callback mutated a cached extension in place | stale elements | HAZ-14 | none for contents |

## 7. Attack graphs

Every barrier below is recorded as `barrier_evidenced: false`. That is not
modesty in wording: none of the seven has a receipt-bound court at the analysis
candidate that exercises the barrier.

### AG-1 — biased or reused ECDSA nonce to private-key recovery

Preconditions: the signer uses the DSA-style nonce or a DRBG whose output is
biased or repeated; the adversary obtains the signatures.
Steps: sign two messages with equal or related nonces; recover `k`; recover the
private scalar from `k` and one signature.
Barrier: `BN_secure_new` for `k`, rejection of `k == 0` and `r == 0`, and a
refusal of the deterministic arm instead of silently substituting the random
one. Residual: no nonce-distribution or repetition court; D333 leaves RFC 6979
unlanded.

### AG-2 — blinding removal or failure to a timing attack

Preconditions: the application disables blinding or construction fails; the
adversary measures the private operation.
Steps: force the no-blinding path; collect timings for chosen messages;
correlate with the private exponent.
Barrier: blinding on by default; a NULL blinding aborts. Residual: disabling is
documented optionality with no measured consequence.

### AG-3 — CRT fault to a faulty signature and factor recovery

Preconditions: a local fault adversary; the fault lands in one CRT half.
Steps: induce the fault; obtain the faulty signature; combine it with a correct
signature to recover a factor.
Barrier: re-exponentiation with the public exponent, a congruence comparison, and
the raw-`d` fallback. Residual: a unit test exercises the fallback; no
receipt-bound fault court.

### AG-4 — allocation failure mid-operation to a partial or inconsistent state

Preconditions: a failing allocator or process exhaustion; some resources already
acquired.
Steps: fail the Nth allocation; the call returns its failure value; a destructor
or the next call touches the partial state.
Barrier: the fallible seam, `OwnedBuf`/`OwnedTree` release-only-acquired
destructors, and error returns before publication. Residual: infallible BN
`Vec` sites; no failure-injection court at the candidate.

### AG-5 — stale cached Montgomery context to a wrong-modulus result

Preconditions: a caller reuses or shares a prepared context across a modulus
change.
Steps: supply a context prepared for `m1` to an operation on `m2`; the authority
computes with the wrong parameters; the caller uses the plausible wrong value.
Barrier: `context_matches` and `refuse_context`, a recorded divergence from the
authority's silent wrong answer. Residual: no reuse differential.

### AG-6 — a callback re-enters and mutates state under an operation

Preconditions: an application callback registered through a documented entry
point; the callback frees or replaces the object being read.
Steps: the operation invokes the callback; the callback releases the chain,
replaces the BIO, or mutates a cached extension; the operation continues with the
stale pointer.
Barrier: `ChainSnapshot` and per-certificate up-refs for `x509`; the B34 guard
for same-thread ERR re-entry; nothing for `BIO` `cb_arg` or extension contents.
Residual: `OBL-XCUT-CALLBACKS` remains `NOT_ESTABLISHED`.

### AG-7 — external-key PKCS#1 v1.5 padding oracle to plaintext disclosure

Preconditions: a private key held externally (`RSA_FLAG_EXT_PKEY`); the
application decrypts attacker-submitted v1.5 ciphertexts and reports success or
failure.
Steps: submit a modified ciphertext; observe the refusal; iterate to recover the
plaintext (Bleichenbacher/ROBOT).
Barrier: implicit rejection on the external-key path with a secret-keyed KDK
(`D-RSA-EXTKEY-ORACLE-1`); the content distinction is removed, but the returned
length still separates valid from invalid padding. The channel is measured, not
illustrated: over 2,048 invalid blocks every protocol-relevant length matched,
with a per-ciphertext probability of order `1/246`
(`evidence/haz-15/REENTRANCY-AND-LENGTH.md`), so a single query remains a
padding signal with about 0.4% error. Residual: `OBL-RSA-EXTKEY-ORACLE` stays
open because the length channel remains and the receipt is self-authored; an
independent adjudication and a consumer replay are still required, and the
obligation still blocks the b85c graduation until they exist. The first-use
secret initialisation no longer holds its lock across the application RNG
callback; that deadlock repair is separate from the oracle.

## 8. Register integration with the T1 graph

The register does not fork a second model. Each hazard is a `hazard` node in
`evidence/etp-t1/TRACEABILITY.json`, and the register's declared edges are the
graph's edges:

- `motivates`: hazard -> requirement (45 `motivates` edges in the graph, 17 of
  them from the ETP-T2 hazards; the rest are threat motivations).
- `raises`: hazard -> obligation (21 of the graph's 51 `raises` edges come from
  hazards).
- `evidenced_by`: hazard -> evidence (11 of the graph's 61 `evidenced_by` edges
  come from hazards).
- release-claim impact is derived, not asserted: a claim is affected when its
  `scope_requirements` intersect the hazard's motivated requirements, or when an
  obligation the hazard raises has a `constrains` edge to it. The graph refuses a
  hazard that names a claim the derivation does not reach
  (`TG_HAZARD_CLAIM_UNRELATED`).

ETP-T2 adds the following nodes and edges to the T1 seed:

| addition | reason |
|---|---|
| `REQ-CORR-01` | "a cryptographic result is correct or the operation fails"; the existing requirement set had no node for correctness, so `HAZ-10` and `HAZ-18` would have had no requirement to motivate |
| `IMP-BN-MONT` (+ file artefact) | `src/bn/mont.rs` is the mechanism behind `HAZ-10` and had no implementation node |
| `OBL-RSA-EXTKEY-ORACLE` | `HAZ-15` has no evidenced barrier: the content oracle is corrected, but the returned length remains a channel (2,048-block measurement, per-ciphertext probability of order `1/246`); the obligation stays open for an independent adjudication and the consumer replay, and still blocks `REL-OPENSSH-B85C` |
| `OBL-PANIC-ATOMICITY` | `HAZ-16` has no barrier; the obligation blocks `REL-OPENSSH-B85C` |
| `OBL-VERIFY-RETURN-POLARITY` | `HAZ-18` has no barrier; the obligation is recorded without a release block because no in-scope consumer is shown to mishandle the return |
| `REQ-CORR-01` in the b85c scope | a `SAFE_COMPATIBLE` graduation that does not include correctness is not a safety claim |

The graph now contains 325 nodes and 403 edges: 20 hazards, 22 requirements, 20
implementations, 26 artefacts, 81 obligations, 101 evidence, 41 adjudications,
6 release claims and 8 threats. The orphan register grows from 20 to 21 because
`REQ-CORR-01` declares that an independent specification is required and none
exists (`ORPHAN-6:REQ:REQ-CORR-01`). No other orphan class changes; the classes
stay `[1, 3, 6, 8]` and every declared orphan reproduces.

Hazards whose motivated requirements and raised obligations reach **no** release
claim: `HAZ-05`, `HAZ-12`, `HAZ-17`. The cause is not an omission in those rows.
No release claim declares `REQ-MEM-01`, `REQ-MEM-02` or `REQ-MEM-03` in its
scope, so a memory-safety hazard cannot reach a claim through the graph's own
accounting. That is a scope gap in the claims, recorded here rather than repaired
by adding a scope declaration the claim's record does not state.

## 9. Non-claims

- This register does not establish that any hazard is unreachable. It records a
  scope, a trigger classification and a barrier state.
- `CLAIMED_NO_EVIDENCE` is not a discharged control. `BARRIER_ABSENT` is not a
  mitigated hazard. `EVIDENCED` does not mean the barrier is sufficient; it means
  an evidence node exists.
- No class-3 input is claimed memory-safe, and no caller obligation reduces a
  hazard's severity.
- No constant-time claim is made. `ASM-TIMING-OBSERVER` is an assumption the
  register records; it is not a measurement of the candidate's emitted code.
- Population completeness is `UNKNOWN`. No frozen expected-hazard manifest
  exists, so the register cannot prove it lists every hazard in the eight
  families.
- The register does not adjudicate a release claim. A hazard that reaches a
  claim adds an obligation; the adjudication remains ETP-T15's and the claim
  owners' work.
- The register does not decide whether an authority behaviour should be
  conserved or diverged from. It records the divergence and its evidence state;
  `docs/SECURITY_DIVERGENCE_POLICY.md` owns the disposition.
