# HAZ-15 follow-up — the re-entrancy edge in first-use secret initialisation, and the length channel measured

Status: two defects in the external-key first-use KDK path are repaired and controlled.
The returned-length channel is **measured over 2,048 invalid blocks** and is **not
closed**: the earlier zero-collision result over 64 blocks was a statement about a
sample and is now known to be consistent with an open channel. `HAZ-15` remains
`CLAIMED_NO_EVIDENCE`; `OBL-RSA-EXTKEY-ORACLE` remains open.

## 1. Identity

| field | value |
|---|---|
| branch | `staging` |
| HEAD at the start | `a4cf2601a38fcfc883c56df30f495e41345eacd7` |
| worktree at the start | clean (`git --no-optional-locks status --porcelain` empty) |
| `available` at the start | 24 GiB (`free -g`); heavy commands ran only when `available` was 25–26 GiB, under `AGENTS.md` §6.1 with `OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g`, `CARGO_BUILD_JOBS=4`, `--test-threads=4` |
| court | `openssl-rs-court-tools:1` |
| candidate | the working tree at that base plus this change |
| candidate DSO | **not rebuilt** for this follow-up; no DSO digest is bound and no release binary was measured |
| authority | unchanged from `observables.json`; the pinned DSO was not re-run for this follow-up |

The measurements below are produced by named in-crate tests. For the length population
the key is the pinned `forensics/etp5_crypto/vectors/rsa_key.json` and the blocks come
from a fixed SplitMix64 stream, so the counts are reproducible from the test name and
are not a fresh random draw on each run.

## 2. Defect A — the store's lock was held across an application-controlled callback

### 2.1 The defect

The first-use secret for an external key with no private material was produced by:

```
let mut store = lock_ext_kdk_secrets();          // process-wide Mutex<Vec<ExtKdkSecret>>
...
RAND_priv_bytes(fresh.as_mut_ptr(), len);        // may reach an application RAND method
store.push(...);
```

`RAND_priv_bytes` consults the installed `RAND_METHOD` and calls its `bytes` callback
when the table is not the default (`src/rand/rand_lib.rs`, `RAND_priv_bytes_ex`). An
application can install such a table. Two consequences follow:

1. **Same-thread re-entry deadlocks.** A callback that re-enters RSA decryption for the
   same key reaches `per_key_ext_kdk_secret` and blocks on the non-reentrant `Mutex`
   that the same thread already holds. There is no timeout in `Mutex::lock`.
2. **Cross-key first use serialises.** Every unrelated external key's first draw waits
   for the current draw, so an application RNG method with a slow or blocking path
   delays unrelated keys.

This is the `AGENTS.md` §4 / §21 re-entrancy edge: a non-reentrant lock held across an
application-controlled callback. It is recorded here under the `HAZ-15` path because
that is the only caller; it is not a claim about the oracle itself.

### 2.2 The state machine

The store is `Mutex<ExtKdkStore>` plus a process-wide `Condvar`. Each entry is:

```
ExtKdkEntry { rsa: usize, reservation: u64, state: ExtKdkState }
ExtKdkState = Initializing { owner: ThreadId } | Ready(SecretBuf<u8>)
```

`reservation` is a monotonically increasing id, never reused in practice; it makes the
publication check exact even when an address is reused. The transition table:

| event | state before | action | state after |
|---|---|---|---|
| lookup, no entry | — | reserve under the lock: boxed entry + fallible vector growth | `Initializing { owner = caller }` |
| lookup, `Ready` | `Ready` | copy the secret into a stack `SecretArray` | unchanged |
| lookup, `Initializing`, owner = caller | `Initializing` | refuse immediately, **no wait** (`ReentrantInitialization`) | unchanged |
| lookup, `Initializing`, owner ≠ caller | `Initializing` | `Condvar::wait_timeout` on the store's lock, bounded by `EXT_KDK_WAIT_LIMIT` (5 s) | unchanged |
| draw succeeds, reservation still present and owned | `Initializing` | re-acquire, copy out, install the secret, `notify_all` | `Ready` |
| draw or allocation fails | `Initializing` | re-acquire, remove by exact reservation, `notify_all` | entry gone |
| destruction (`forget_ext_kdk_secret`) | any | remove every entry for the address, `notify_all` if an `Initializing` entry was removed | entry gone |
| waiter wakes, reservation gone or replaced | — | refuse (`ReservationAbandoned`), never reserve on the waiter's behalf | unchanged |

Where the lock is held:

| operation | store lock |
|---|---|
| lookup / copy-out | held |
| reserve (entry box, vector growth) | held |
| **`RAND_priv_bytes`** | **not held** |
| publish | held |
| abandon | held |
| `Condvar::wait_timeout` | atomically released for the wait, re-acquired on wake |
| destruction removal | held |

Every step on the reservation path is fallible: the entry's box uses
`runtime::alloc::try_boxed`, the vector growth uses `runtime::alloc::try_reserve`, and
the secret uses `SecretBuf::try_zeroed`. No `push` runs without a successful
reservation. The drawn secret is a `SecretBuf`: it is volatile-wiped on every path that
does not publish it, including RNG failure, allocation failure and an abandoned
reservation. A destroyed object's entry is removed before its address can be reused;
the owner's publication then matches no reservation and is refused, so nothing is
published into a freed object. The reservation is held by a guard whose `Drop`
removes it unless the secret was published, so an unwind between reservation and
publication also removes the entry and wakes the waiter. That guard was `NOT_RUN` at
this batch and is now injected at five points (`PASS`, see `CALLBACK-CONTRACT.md` §5.1);
the injection found that the guard was dropped before the store's lock was released,
which deadlocks on the non-reentrant mutex, and the ordering is repaired (the lock is
released before the guard exists, and the guard is built inside the reservation).

The refusals are internal variants that name the condition:

| variant | condition |
|---|---|
| `ReentrantInitialization` | the caller already owns this object's `INITIALIZING` reservation |
| `ReservationAbandoned` | the reservation disappeared (destruction or a failed initialiser) |
| `WaitTimedOut` | no publication or removal within `EXT_KDK_WAIT_LIMIT` |
| `RngFailure` | `RAND_priv_bytes` returned ≤ 0 |
| `AllocationFailure` | the entry box, vector growth, or secret allocation was refused |

`derive_external_kdk` maps every variant to `0`, which is the refusal the entry point
already handles; no variant falls back to a publicly-derivable value.

## 3. Controls

All four controls run under a process-wide test lock in the same process, one at a
time; the scripted RNG table delegates to the default generator on every thread that
did not arm a script, so unrelated parallel tests observe identical bytes. Every wait
is bounded: a hang is a test failure.

| control | test | observation |
|---|---|---|
| re-entrancy, same key | `rsa::ossl::tests::a_first_use_rng_callback_may_reenter_rsa_decryption` | the outer draw completes (`1`), the re-entered call answers `0` and the internal refusal is `ReentrantInitialization`; the callback finds the store lock free; finished in 0.01 s |
| re-entrancy, different key | same test, second arm | the outer call completes (`1`) and the re-entered call on the other key completes (`1`) with its own entry; both entries are `Ready`; finished in 0.01 s |
| concurrency | `rsa::ossl::tests::concurrent_first_use_installs_exactly_one_secret` | 8 threads on one object; exactly one `INITIALIZING` entry while the owner is parked, at least one thread parked on the condition variable, then one `Ready` entry; all 8 return `1` with byte-identical KDKs; store empty after destruction |
| destruction during initialisation | `rsa::ossl::tests::destruction_during_initialisation_is_a_defined_refusal` | owner parked in RNG, waiter parked on the condition variable, `RSA_free` removes the entry; owner answers `0`, waiter answers `ReservationAbandoned`, no entry survives |
| RNG failure | `rsa::ossl::tests::rng_and_allocation_failure_publish_nothing` | `0`, no entry; a later attempt succeeds, so the abandonment did not poison the object |
| reservation allocation failure | same test | `AllocationFailure`, no entry |
| secret allocation failure | same test | `AllocationFailure`, no entry |

Bounded wall clocks: each scenario is joined through a `recv_timeout` of 10 s and the
condition-variable waits have a 5 s cap, so a regression that reintroduces the lock
across the callback fails the test rather than hanging the suite. The callback also
probes the store lock directly: with the old code a same-thread holder never releases
it and the probe records the defect before the re-entry itself blocks.

**Control limits.** The full `RSA_private_decrypt` arm reaches the RNG only when the
object is engine-backed (`RSA_FLAG_EXT_PKEY` with `rsa_mod_exp` supplied), which this
crate cannot construct without an `ENGINE`; the control therefore drives
`derive_external_kdk`, the exact function that contains the defect and the only caller
of `per_key_ext_kdk_secret`. The destruction control uses a real `RSA_free`; after it
returns, the owner's abandoned path reads no field of the freed object (it returns
before `libctx` is touched) and the waiter never dereferences the object at all. No
sanitizer, Miri or Loom run covers this state machine in this follow-up; those remain
`NOT_RUN`.

## 4. Defect B — comments that contradicted the code

The KDK has three constructions (`d`; the CRT primes; a first-use per-object secret).
The following statements described the withdrawn `SHA-256(decrypted block)`
construction and are corrected at the sites where they appeared:

| site | before | after |
|---|---|---|
| module note, `src/rsa/ossl.rs` (ordering section) | "For an external key the KDK is derived from private key material and the ciphertext … otherwise from a per-key random secret established at first use" with no statement of the `d` path's assumption | the three paths are enumerated, each with its assumption, and the lock-across-callback repair is named |
| `rsa_ossl_private_decrypt` doc, first bullet | "derives the KDK from the decrypted block when `d` is absent" | the three paths and their assumptions are enumerated; the length channel is named as open |
| `rsa_ossl_private_decrypt` doc, KDK bullet | "`buf` holds `ret`'s bytes … the scratch use `derive_kdk` documents" without distinguishing the paths | path 1 uses `buf` as `derive_kdk` documents; paths 2 and 3 only read it |
| inline comment at the top of `rsa_ossl_private_decrypt` | "for a key with no `d` the KDK is derived from the decrypted block below" | "derived from private key material, never from the decrypted block: `d`, otherwise the CRT primes, otherwise a first-use RNG secret" |
| inline comment before the `d`-present `derive_kdk` call | "derive the Key Derivation Key from private exponent and public ciphertext" | labelled as path 1, with paths 2 and 3 pointed at the switch |
| inline comment in the `RSA_PKCS1_PADDING` arm | described the fallback but not the assumptions | paths 2 and 3 with their assumptions (primes private; RNG unpredictable and the side table keeps the secret) |

`derive_kdk`, `derive_external_kdk` and the withdrawal note in `KDK-CORRECTION.md` §2
already described the code; they were not changed except where §5 below supersedes the
64-block measurement.

## 5. Defect C — the length channel, measured

### 5.1 Population and method

`rsa::ossl::tests::the_external_length_channel_is_measured` decrypts 2,048 distinct
attacker-chosen invalid blocks on the pinned 2048-bit key in its external shape
(`n, e, p, q, dmp1, dmq1, iqmp`; `d` absent; `RSA_FLAG_EXT_PKEY`). Four invalid
families are cycled — wrong block type, a padding string shorter than eight octets, no
separator, and a leading byte that is not zero — and the body of each block comes from
a fixed SplitMix64 stream seeded by the block index. Each block is encrypted with the
public exponent, decrypted with `RSA_PKCS1_PADDING`, and its returned length recorded
together with the error queue.

The synthetic length is generated by `ossl_rsa_padding_check_PKCS1_type_2`: 128
candidate 16-bit values from the KDK PRF, reduced by a mask of `0xff` (for a 246-value
range) and selected as the last candidate below `flen - 10`. The support is therefore
`0 ..= 245` for this key. A valid block returns its message length:
`[8, 16, 32, 48]` for the four valid messages.

### 5.2 Observations

- 2,048 invalid blocks returned values in `0 ..= 245`; 245 of the 246 values occurred.
- minimum `0`, maximum `245`; mean count per value `2048 / 246 = 8.33`; maximum bin
  count `19` at length `180`.
- **An invalid block can return `0`**; the length-0 bin held 11 blocks. An application
  that treats only `ret > 0` as success therefore sees a failure signal on those
  invalid blocks. The error queue was empty for all 2,048 calls.

Full empirical distribution over `0 ..= 245` (index = returned length):

```
[11, 7, 6, 12, 7, 12, 12, 6, 8, 6, 16, 9, 6, 7, 2, 3, 10, 5, 10, 8, 7, 7, 12, 9,
 8, 9, 8, 10, 9, 2, 6, 8, 6, 8, 11, 9, 10, 13, 6, 9, 9, 11, 6, 10, 7, 9, 12, 3,
 9, 7, 8, 7, 12, 9, 12, 9, 9, 9, 9, 11, 7, 12, 12, 9, 7, 12, 9, 4, 7, 9, 7, 10,
 11, 9, 8, 13, 9, 13, 12, 8, 10, 5, 6, 10, 11, 10, 6, 2, 3, 8, 8, 6, 11, 6, 14,
 10, 5, 9, 12, 11, 16, 6, 4, 8, 7, 12, 9, 4, 10, 7, 13, 5, 14, 13, 7, 8, 9, 5,
 9, 13, 6, 10, 11, 3, 7, 13, 8, 5, 5, 0, 12, 13, 16, 8, 6, 9, 7, 9, 4, 8, 11, 5,
 12, 7, 5, 13, 13, 10, 7, 7, 9, 7, 10, 7, 3, 8, 14, 16, 5, 8, 8, 10, 8, 4, 7, 9,
 8, 4, 5, 4, 9, 5, 17, 10, 2, 8, 16, 7, 4, 10, 19, 5, 6, 9, 4, 13, 7, 13, 5, 3,
 8, 6, 6, 5, 7, 7, 16, 8, 5, 6, 10, 8, 8, 10, 8, 5, 8, 9, 3, 7, 7, 9, 9, 5, 5,
 6, 7, 10, 12, 6, 6, 9, 4, 9, 12, 14, 5, 5, 3, 12, 11, 9, 9, 7, 2, 10, 9, 3, 9,
 7, 8, 12, 12, 10, 7, 4]
```

Match counts for the protocol-relevant and observed lengths, with a 95% Wilson interval
for the per-ciphertext match probability `p` (`n = 2048`):

| expected length | meaning | matches | `p` estimate | 95% Wilson interval |
|---:|---|---:|---:|---|
| 48 | TLS 1.0–1.2 pre-master secret (`SSL_MAX_MASTER_KEY_LENGTH`) | 9 | 0.00439 | `[0.00231, 0.00833]` |
| 16 | protocol-relevant message length | 10 | 0.00488 | `[0.00265, 0.00897]` |
| 32 | protocol-relevant message length | 6 | 0.00293 | `[0.00134, 0.00638]` |
| 8 | the differential row's valid message length | 8 | 0.00391 | `[0.00198, 0.00769]` |
| 244 | authority internal key, `bad_type` synthetic length | 7 | 0.00342 | `[0.00166, 0.00704]` |
| 107 | authority internal key, `short_ps` synthetic length | 4 | 0.00195 | `[0.00076, 0.00501]` |
| 189 | candidate external `bad_type` synthetic length (`observables.json`) | 3 | 0.00146 | `[0.00050, 0.00430]` |
| 180 | candidate external `short_ps` synthetic length (`observables.json`) | 19 | 0.00928 | `[0.00595, 0.01445]` |

The `180` bin is the high tail of the sample (mean `8.33`, maximum `19`); the other bins
are consistent with the near-uniform `~1/246` implied by the mask, and the elevated bin
changes no conclusion below. The important number is that every one of these lengths is
reachable: **zero matches is not the behaviour**, and the probability is of order
`1/246` per ciphertext, per length.

### 5.3 The probability statement

For a fixed expected length `L` in `0 ..= 245`, an invalid block returns `L` with
probability of order `1/246` (`≈ 0.0041`). The 48-byte measurement is `9/2048`, with a
95% interval of `[0.0023, 0.0083]`; the point estimate agrees with the structural value.
The earlier 64-block sample reported zero collisions. Under `p ≈ 1/245`:

- the probability that 64 invalid blocks contain **no** block returning 48 is
  `≈ 0.77`;
- the probability that they contain no block returning any of the four valid lengths
  `{8, 16, 32, 48}` is `≈ 0.35`.

The 64-block zero was therefore unremarkable under the open channel; it bounded
nothing. A zero over 2,048 blocks would have been a different statement
(`P ≤ e^{-8.3} ≈ 2.5 × 10^{-4}` under the structural value), and the measurement
instead shows the expected matches.

**Why this is an oracle.** A valid block returns its message length deterministically, while
an invalid block returns that same length with probability `p̂ = 0.00439` (95% Wilson
`[0.00231, 0.00833]`). The measured quantity is a **likelihood**, not a posterior: it says
nothing on its own about the probability that a reply is valid, which depends on the prior
probability `π` of receiving a valid ciphertext in the application.

The posterior is
`P(valid | L=48) = π / (π + (1−π)·0.00439)`. With `π = 0.5` that is `0.9954`; with
`π = 0.1` it is `0.958`; with `π = 0.01` it is `0.696`. An earlier revision of this
receipt quoted `99.6%` unconditionally, which silently assumed equal priors; that
statement is withdrawn.

What does not depend on the prior is the per-query **likelihood ratio**, about
`1 / 0.00439 ≈ 228`, in favour of invalidity when the answer is not the expected length
(and symmetrically in favour of validity when it is). An attacker who can submit many
ciphertexts accumulates that evidence, which is why the channel is exploitable in a
chosen-ciphertext setting even though a single query is not decisive. Repeating the *same*
query does not help — the KDK is a function of the key and the ciphertext, so the answer is
stable — but a fresh ciphertext is a fresh trial.

### 5.4 Can the library make the length indistinguishable?

**Not on the generic path, without changing the public contract.** The valid path's
return value *is* the message length: the caller uses it to bound the plaintext. The
invalid path would have to emit a length drawn from the same distribution as the
caller's valid messages, and the library does not know that distribution (a TLS server
expects 48; another protocol expects something else). Making the invalid length a
constant, or zero, is a stronger distinguisher, not a weaker one. The only sound
library-level answer is a caller-selected fixed-length contract, which is exactly what
the authority's TLS check is.

**Application obligation.** An application that must not expose a length oracle on the
external-key path has to select a fixed-length check (the TLS-shaped
`ossl_rsa_padding_check_PKCS1_type_2_TLS` for the TLS pre-master secret) or treat the
returned length as opaque and never branch on it. The generic `RSA_private_decrypt`
signature cannot enforce either. This obligation is recorded on
`OBL-RSA-EXTKEY-ORACLE`; it is not discharged by the library.

### 5.5 The fixed-length path

`rsa::ossl::tests::the_tls_shaped_padding_check_answers_one_length` calls
`ossl_rsa_padding_check_PKCS1_type_2_TLS` directly on a valid TLS-shaped block and on
4,096 deterministic invalid variants. Every call returned exactly `48` and wrote 48
bytes; `distinct_returned_lengths = {48}`. The function draws a random pre-master
secret and selects between the submitted and the random bytes under the same
constant-time mask, so the length axis carries nothing. This function is the
authority's TLS answer and is reached from the provider's asymmetric cipher; the
generic `RSA_private_decrypt` arm in this file does not call it. Updating the exported
entry point to select it would change the public contract and is not done here; the
obligation above stands.

## 6. Honest status

- **`HAZ-15` stays `CLAIMED_NO_EVIDENCE`.** The content oracle is removed on the
  return-sign, output-buffer and error-queue axes (the earlier correction). The
  returned length is now measured to be a channel with per-query match probability of
  order `1/246`, so it cannot be recorded as closed. No independent adjudication and no
  consumer replay exist.
- **`OBL-RSA-EXTKEY-ORACLE` stays open** for: an independent adjudication of this
  evidence, a consumer replay of the divergence, and a resolution of the returned-length
  channel (a fixed-length contract, or a documented per-consumer obligation).
- **Repaired independently of the oracle:** the first-use secret initialisation no
  longer holds the store's lock across the application-reachable `RAND_priv_bytes`; a
  same-thread re-entry is a defined refusal, concurrent waiters are woken rather than
  spinning, the wait is bounded, and destruction during initialisation publishes
  nothing and wakes the waiter. This removes a deadlock and an unrelated-key
  serialisation; it does not change the padding oracle.
- **Not established:** timing/constant-time behaviour of the first-use path and of the
  new derivation; an engine-backed `rsa_ext_pkey` operation (the external shape with
  the CRT primes is exercised, the engine shape at the KDK helper only); a release DSO
  at this candidate (no rebuild); sanitizer/Miri/Loom coverage of the store; and any
  downstream consumer measurement. The follow-up in `STATE-MACHINE.md` adds a
  deterministic interleaving model of the store but explicitly not a Loom run, and
  `CALLBACK-CONTRACT.md` classifies the callback classes; neither closes these gaps.
- **Threat model.** An attacker submits chosen ciphertexts to an application that
  decrypts with an externally held PKCS#1 v1.5 RSA key and can observe the returned
  length. The content of the answer no longer distinguishes the classes; the length
  does, at a per-query error of about `1/246`. Timing is not measured. An application
  that ignores the length, or uses the fixed-length TLS check, has no library-level
  signal on the axes measured here — which is why the fixed-length check remains an
  application obligation rather than a claim.
