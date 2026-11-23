# HAZ-15 — KDK correction

Status: the earlier synthetic-message justification is **retracted**. The
external-key PKCS#1 v1.5 synthetic message is now keyed by private key material
or a per-key RNG secret, not by a hash of the decrypted block. The correction
removes the attacker-computable content channel; it does not close `HAZ-15`,
because the returned length still distinguishes valid from invalid padding.

## 1. Identity

| field | value |
|---|---|
| branch | `staging` |
| HEAD at the start | `5750ac15008e6537b9cf12800b4351b7171f6a9b` |
| worktree at the start | clean (`git status --porcelain` empty) |
| `available` at the start | 27 GiB; the build ran under `AGENTS.md` §6.1 with `OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g` |
| court | `openssl-rs-court-tools:1` |
| authority | `openssl-3.6.4-production`, DSO SHA-256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| candidate before | release build of HEAD, DSO SHA-256 `c816b3d15a470cdb820426d78287fa0757649f016a46f634ca149c58195b8a76` |
| candidate after | release build of HEAD plus this correction, DSO SHA-256 `5761b7150c2b0825570e4be1b7ae17dc073a78be0a4bd26987268f23fe61350a` |

## 2. The retracted argument

The first repair set the implicit-rejection KDK to `SHA-256(decrypted block)`.
It argued that the block `m = c^d mod n` is secret because the attacker cannot
compute the private operation. That argument is invalid:

1. RSA encryption is public. For any attacker-chosen representative `m` the
   attacker computes `c = m^e mod n`, and the private operation returns `m`.
2. The attacker therefore knows the decrypted block — and `SHA-256(m)` — for
   every ciphertext the attacker constructed.
3. The synthetic message returned for such a ciphertext is a PRF keyed by a
   value the attacker can compute, so the attacker can compute the synthetic
   message and compare it with the answer, recovering the padding-validity
   distinction the repair was meant to remove.

The construction does not establish the keyed pseudorandomness that implicit
rejection requires. It is withdrawn rather than reworded.

The control is executable:
`rsa::ossl::tests::the_external_synthetic_answer_is_not_attacker_computable`
computes the withdrawn construction's answer from the chosen block and requires
the returned message to differ. With the withdrawn construction temporarily
restored, the test failed with:

```
thread 'rsa::ossl::tests::the_external_synthetic_answer_is_not_attacker_computable' panicked at src/rsa/ossl.rs:3480:13:
the returned message must not be the SHA-256(block)-keyed synthetic one
test result: FAILED. 0 passed; 1 failed; ...
```

## 3. The replacement

`src/rsa/ossl.rs`, `derive_external_kdk`, in this order:

1. **`d` present.** The authority's `derive_kdk` is unchanged: the KDK is
   `HMAC-SHA-256(SHA-256(d padded to the modulus width), ciphertext)`. This path
   is deliberately **not** re-keyed with a new label: changing it would change
   the internal-key synthetic bytes and break the byte-identical parity the
   internal rows in `observables.json` record. Its KDK is used only as the HMAC
   key of `ossl_rsa_prf`, whose `"message"` and `"length"` labels separate the
   two uses. Every new derivation below carries its own label.
2. **`d` absent, `p` and `q` present.** The PRF key is derived once from the CRT
   primes and never leaves the process:
   `K = SHA-256(KEY_LABEL || p || q)`, where the primes are written at their own
   byte widths and `KEY_LABEL` is
   `openssl-rs/rsa/ext-kdk/crt-key/v1`. The KDK is
   `HMAC-SHA-256(K, MAC_LABEL || ciphertext)`, with `MAC_LABEL` =
   `openssl-rs/rsa/ext-kdk/ciphertext/v1`. Both primes are private to the key
   holder, so the attacker cannot compute `K` or the KDK.
3. **No private material at all (the engine-backed `(n, e)` shape).** At first
   use a 32-byte secret `S` is drawn with `RAND_priv_bytes`, stored against the
   object, and the KDK is
   `HMAC-SHA-256(S, RANDOM_LABEL || ciphertext)`, with `RANDOM_LABEL` =
   `openssl-rs/rsa/ext-kdk/random-ciphertext/v1` (distinct from the CRT label, so
   a random secret and a CRT key are never used under the same derivation). RNG
   failure and allocation failure return the defined refusal
   (`derive_external_kdk` answers 0, `rsa_ossl_private_decrypt` breaks to its
   error path). There is no fallback to a publicly-derivable value.

The labels are distinct from the padding check's own `"message"` and `"length"`
labels, and the KDK is used only as the HMAC key of `ossl_rsa_prf`.

**Unpredictability argument.** The attacker's view is `(n, e, c)` and the
returned bytes. In case 2 the attacker lacks `p` and `q`; in case 3 the attacker
lacks `S`. Under the assumption that HMAC-SHA-256 is a PRF under an unknown key,
the synthetic message is unpredictable, and it is deterministic for one key and
ciphertext. No value the attacker can compute from `(n, e, c)` is used as a key.
This is a computational argument, not a proof; no leakage or constant-time
measurement was run on the new derivation.

**Case 1 is unchanged** and the internal-key differential rows remain
byte-identical to the authority (`244` for `bad_type`, `107` for `short_ps` on
the pinned key). The external synthetic lengths span the same `0..244` range on
that key; 58 distinct values were observed in the 64-block population.

## 4. Ownership, lifetime and cleansing

- The per-key secret is an `ExtKdkSecret { rsa: usize, secret: SecretBuf<u8> }`
  in a process-wide `Mutex<Vec<ExtKdkSecret>>` side table. The key is the `RSA`
  object's address.
- A side table is used rather than an `Rsa` field because `Rsa` is a
  `#[repr(C)]` transcription of the authority's `struct rsa_st` whose offsets and
  size are asserted. No field, offset or exported signature changes.
- The secret is allocated with `SecretBuf::try_zeroed`, which uses fallible
  reservation and reports failure instead of aborting. It does not cross the
  `CRYPTO_*` seam: a caller-installed allocator does not see this allocation, and
  an allocation failure is a defined refusal rather than an abort.
- `SecretBuf`'s `Drop` volatile-wipes the whole allocation before releasing it.
  Entries are removed in `Rsa`'s `destroy_body` (`forget_ext_kdk_secret`) before
  the method's `finish`, the lock release and the key components, so the secret
  is gone on every destruction path and a later allocation at the same address
  cannot inherit it.
- The store's lock is held for lookup, reservation, publication and removal only. A hit
  copies the secret into a stack `SecretArray`, and the HMAC runs outside the lock.
- A miss reserves an `INITIALIZING` entry recording the calling thread, **releases the
  lock**, draws the secret with `RAND_priv_bytes`, then re-acquires and publishes. The
  lock is therefore never held across an application-controlled RNG callback. A peer
  that misses concurrently blocks on the store's condition variable and receives the
  published secret; a same-thread re-entry is refused (`ReentrantInitialization`)
  rather than deadlocking; the wait is bounded by a fixed limit; and destruction during
  initialisation removes the reservation, wakes the waiter, and makes the owner's
  publication a refusal. The full state machine and its controls are in
  `evidence/haz-15/REENTRANCY-AND-LENGTH.md` §2–§3.
- Two further stack copies are wiped that the authority leaves in place:
  `derive_kdk`'s `d_hash` (`SHA-256(d)`, from which the KDK is keyed) and
  `rsa_ossl_private_decrypt`'s `kdk` array. These are deliberate safety
  improvements on the secret-bearing path and change no returned value.
- **Two objects built from the same public-only material receive independent
  secrets.** The synthetic answer is therefore deterministic per object and
  ciphertext, not across objects. An application that reconstructs the `RSA`
  object per query loses per-ciphertext determinism, which is a residual for that
  shape. Objects holding the CRT primes do not have this residual: their secret
  is a function of the key material.

## 5. The channel that remains: returned length

`ossl_rsa_padding_check_PKCS1_type_2` returns the synthetic *length* on invalid
padding. On the pinned 2048-bit key (`forensics/etp5_crypto/vectors/rsa_key.json`,
external shape), the test
`rsa::ossl::tests::the_external_length_channel_is_measured` measured:

- valid messages of 8, 16, 32 and 48 bytes returned exactly `[8, 16, 32, 48]`;
- 64 distinct invalid blocks returned

  ```
  [29, 136, 122, 162, 89, 212, 117, 150, 236, 176, 200, 108, 171, 38, 141,
   234, 27, 168, 64, 173, 5, 232, 204, 163, 70, 119, 138, 35, 211, 214, 195,
   225, 194, 151, 67, 4, 96, 14, 236, 173, 76, 151, 203, 81, 202, 170, 106,
   185, 57, 187, 78, 108, 156, 144, 34, 62, 90, 135, 110, 177, 9, 214, 210, 202]
  ```

- 58 distinct invalid lengths;
- **zero** invalid lengths equal to any valid length.

**The lengths distinguish the classes.** The 64-block measurement above was the first
sample; it is superseded by the extended population in
`evidence/haz-15/REENTRANCY-AND-LENGTH.md` §5, which decrypts 2,048 invalid blocks and
matches every protocol-relevant length. For a fixed expected length the per-ciphertext
match probability is of order `1/246` (the 48-byte TLS pre-master length matched 9 of
2,048, 95% Wilson `[0.00231, 0.00833]`), so an application that exposes the returned
length still has a per-query oracle: a valid block returns its message length
deterministically, and an invalid block returns that length only about 0.4% of the
time. The earlier zero-collision result over 64 blocks had probability about 0.35 under
this open channel and bounded nothing. This is a finding, not a pass. The generic check
cannot make the length uniform without changing its contract (valid messages have their
own lengths); the authority's answer for TLS is the fixed-length
`ossl_rsa_padding_check_PKCS1_type_2_TLS`, which this path does not use. The authority's
own internal-key implicit rejection has the same length channel, so this correction
removes the stronger refusal oracle on the external path but does not make the generic
path length-safe. The observable set on the other three axes — return sign,
output-buffer state and error queue — no longer distinguishes: both classes return a
non-negative length, write bytes and leave the queue empty. An invalid block can return
`0`, which an application testing only `ret > 0` reads as failure.

The population is recorded in `observables.json` under `length_population`, and
the per-case rows are regenerated from the rebuilt candidate DSO
(`5761b715…`): external `bad_type` answers `189`, external `short_ps` answers
`180`, both with no error. The withdrawn candidate answered `238` and `8`; the
change in values is expected because the KDK is now secret-keyed.

## 6. Engineering costs

### 6.1 `OPENSSL_sk_pop_free` is linear again

Each element is now removed with `pop` before its destructor runs. The invariant
is preserved: a destructor never runs on an element that is still reachable, the
remaining prefix is untouched, and a retry releases only the remainder. The
release order is now last-to-first; the authority iterates first-to-last, but the
destructors are independent and the stack's own interface does not expose the
order while the call is in progress. The cost is O(n) rather than O(n²).

The revert control was run by temporarily restoring in-place iteration: the test
failed (`assertion left == right failed: the last destructor ran once; left: 0,
right: 1`). Restored, it passes.

### 6.2 Allocation-failure injection at the blinding temporaries

`BN_BLINDING_update`'s square arm allocates `sq` and `inv_sq`;
`BN_BLINDING_create_param` allocates `a`, `ai` and, when an exponent is supplied,
a duplicate of `e`. Each site now consults a test-only, thread-local failure
injection before allocating. The test
`bn::blinding::tests::a_temporary_allocation_failure_leaves_the_blinding_unchanged`
fails sites 1 and 2 of the update and sites 1, 2 and 3 of `create_param` in turn,
and requires on each failure:

- the documented failure result (`0`, or `b` for `create_param`);
- every member — `a`, `ai`, `e` and the counter — equal to its pre-call value;
- a caller-shaped `convert` / exponentiate / `invert` round trip that still
  cancels.

Allocation-count change for the measured paths:

| path | temporary `BIGNUM` allocations | change |
|---|---:|---|
| `BN_BLINDING_update` square arm | 2 (`sq`, `inv_sq`) | was 0; **+2 per update** |
| `BN_BLINDING_create_param`, fresh context | 3 (`a`, `ai`, `e` duplicate) | unchanged; the same three allocations existed before |
| `BN_BLINDING_create_param`, re-creating a populated context | 3 (`a`, `ai`, `e` duplicate) | was 1 (the `e` duplicate) or 0 (no `e`); **+2 or +3** |

The difference is the price of publishing only after every fallible step succeeds: the
re-creation path now allocates its own factor and inverse instead of writing them
into the caller's context. The injection sweep exercises the three sites on that
re-creation path, so the count above is measured from the code path rather than
assumed.

These are Rust allocations, not `CRYPTO_*` seam allocations: an installed
allocator hook does not observe them and the authority's allocation counts are
unchanged. No end-to-end workload allocation census was re-run for this
correction; that remains a `NOT_RUN` measurement, not a pass.

## 7. Gates

Run in the court, one heavy command at a time, with `CARGO_BUILD_JOBS=4`.

```
$ cargo fmt --all -- --check
FMT_OK

$ cargo clippy --all-targets --offline -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.98s

$ cargo test --lib --offline
test result: ok. 2434 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 109.69s

$ cargo test --lib --offline -- --test-threads=4
test result: ok. 2434 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 142.81s

$ python3 forensics/tools/etp_t1_seed.py
wrote /work/evidence/etp-t1/TRACEABILITY.json: 358 nodes, 469 edges, 39 orphans

$ python3 forensics/tools/traceability.py validate
traceability graph at 21bea318819a56f641b3aa2f25027216b97a1c4d: 358 nodes (adjudication=41, artefact=28, evidence=104, hazard=20, implementation=21, obligation=97, refinement_edge=5, refinement_level=6, release_claim=6, requirement=22, threat=8); 469 edges (assessed_by=130, constrains=55, discharges=5, evidenced_by=73, motivates=45, obligates=5, raises=67, realised_by=30, refines_to=5, releases=8, satisfied_by=46)
orphans: 39 declared and reproduced (39 ids), 0 undeclared, 0 stale

$ python3 forensics/tools/hazard_register.py validate
hazard register /work/evidence/etp-t2/HAZARDS.json: 20 hazards, 8 fault trees, 30 FMEA rows, 12 UCAs, 7 attack graphs
barrier states: BARRIER_ABSENT=2, CLAIMED_NO_EVIDENCE=18, EVIDENCED=0; FMEA evidence: CLAIMED_NO_EVIDENCE=23, EVIDENCED=0, NONE=7
BARRIER_ABSENT: HAZ-18, HAZ-20; no release claim: HAZ-05, HAZ-12, HAZ-17
register and traceability graph agree

$ python3 forensics/tools/divergence_obligations.py --check
[divergence-obligations] ok: 10 row(s) match the table (0 blocking)

$ python3 forensics/tools/docs_consistency.py
[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources

$ python3 forensics/tools/tests/test_traceability.py
Ran 26 tests in 13.871s
OK

$ python3 forensics/tools/tests/test_hazard_register.py
Ran 23 tests in 0.889s
OK

$ python3 -m json.tool evidence/haz-15/observables.json
HAZ15_JSON_OK
$ python3 -m json.tool evidence/etp-t2/HAZARDS.json
JSON_OK
$ python3 -m json.tool evidence/etp-t1/TRACEABILITY.json
TRACE_JSON_OK
$ python3 -m json.tool forensics/divergence-obligations.json
DIV_JSON_OK
```

The baseline was 2430 passed / 0 failed / 54 ignored. This correction adds four
tests (three in `rsa::ossl::tests`, one in `bn::blinding::tests`); no test was
removed or newly ignored.

## 8. Honest status

**Threat model.** An attacker who submits chosen ciphertexts to an application
that decrypts with an externally held PKCS#1 v1.5 RSA key, and who can observe
some part of the answer. The content construction no longer gives the attacker a
padding-validity signal through the returned bytes; it still does through the
returned length, at a per-query error of about `1/246`. Timing was not measured.
An application that ignores the length or uses the fixed-length TLS check has no
library-level signal left on the axes measured here.

- **`HAZ-15` is not eliminated.** The content oracle is removed on the return
  sign, output-buffer and error-queue axes. The returned length remains a
  distinguisher, measured over 2,048 invalid blocks in
  `evidence/haz-15/REENTRANCY-AND-LENGTH.md` §5, so the register records
  `CLAIMED_NO_EVIDENCE`, not `EVIDENCED` or `PARTIAL_MITIGATION` (the register's
  vocabulary has no partial state; the partial nature is stated in the barrier's
  `control` and in `would_close`).
- **`OBL-RSA-EXTKEY-ORACLE` stays open.** It needs independent adjudication, a
  consumer replay, and a resolution of the length channel.
- **The first-use lock-across-callback defect is repaired** (this follow-up): the
  store no longer holds its mutex across `RAND_priv_bytes`; same-thread re-entry is
  a named refusal, peers wait on a condition variable under a fixed bound, and
  destruction during initialisation publishes nothing. This is a deadlock repair,
  not a change to the oracle.
- **Not established:** timing/leakage of the new derivation; a real
  `ENGINE`/neverbleed remote operation (the external shape is the CRT parameters
  with `d` removed, and the public-only path is exercised at the KDK helper and
  its failure injection, not through an engine-backed private operation); the
  per-object determinism residual for public-only keys; a whole-workload
  allocation census; sanitizer/Miri/Loom coverage of the new store; and any
  down-stream consumer measurement.
- **What is established:** the withdrawn construction is refuted by an executable
  control; the replacement uses only private key material or an RNG secret under
  explicit domain separation; RNG and allocation failure are defined refusals;
  the secret is owned, fallibly allocated, cleansed and released with the key;
  the re-entrancy edge has executable controls with bounded waits; and the length
  channel is measured over 2,048 blocks rather than assumed absent.
