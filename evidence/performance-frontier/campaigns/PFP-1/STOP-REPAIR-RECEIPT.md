# PFP-1 STOP-class repair receipt — secret preparation and cache publication

**Queue context:** adversarial review of the landed PFP-1 prepared-Montgomery
work.
**Programme:** `docs/PERFORMANCE-FRONTIER.md` §11 (no optimisation may weaken a
security mechanism); `AGENTS.md` §1, §2, §3, §5, §6.1, §7.
**Claim class:** `SCOPED_OBSERVATION` on the court venue. This receipt records a
repair, not a performance result.
**Evidence root:** `evidence/performance-frontier/campaigns/PFP-1/`.

This is a new receipt. No PFP-0 or PFP-1 raw data, summary, or earlier receipt
was edited.

---

## 1. Source identity

| item | value |
|---|---|
| source HEAD | `a3f7b277cf09ea2cb28c853fded090580f3e80cd` |
| branch | `staging` |
| worktree | dirty: this repair is applied; no commit was made |
| `src/bn/mont.rs` | `e76163b3ce25f35d9399c0b9d06dc24224cd908c4c1826358bddcbb60fd57aea` |
| `src/runtime/alloc.rs` | `e258241eec7e99dac0aba5bbb2b848e3518e7c407cb083a19e5b9b67ce05c669` |
| `src/dh/key.rs` | `2c726db332014dc7a1d6ca79420450c3860d7416d2e7ca29036df8f971ca2628` |
| debug library test binary | `target/debug/deps/openssl_rs-672100dcc99e32ac`, SHA-256 `46356e9dbb04d769f3e6d121bbe8cb50ade37dfd8d2e7e246a53d1dd7b275a71` |
| distribution DSO | not rebuilt by this repair; no configuration or optimisation changed |

The source hashes are the files at the time of the gates. The binary hash above is
the debug test binary the ctgrind runs executed.

## 2. Environment guard

`free -g` at the start reported `available` 28 GiB. The computed cap
`min(8g, available - 16g)` is 8g with the 2g floor satisfied. The court container
in use had a cgroup cap of 8g/8g, equal to the computed cap; every build and test
ran inside `docker/openssl-rs-court.sh exec`, with `CARGO_BUILD_JOBS=4`, one heavy
command at a time, and no host compilation.

## 3. Defect 1 — secret-derived preparation values

### Construction sites, before and after

| value | before | after |
|---|---|---|
| `R^2 mod N` (`rr`) | produced as an ordinary `Vec`, then moved into `SecretBuf` at the end of `mont_set` | adopted at production: `limbs::pow2_mod_consttime(..).map(SecretBuf::from_vec)` |
| `N` (`n`) | copied with `bn::alloc::try_clone_slice` into an ordinary `Vec` | copied directly into secret storage with `clone_secret` |
| `R mod N` (`one`) | produced as an ordinary `Vec` by `mont_mul_fallible`, then moved into `SecretBuf` at the end | adopted at production: `mont_mul_fallible(..).map(SecretBuf::from_vec)` |
| `n0 = -N^-1 mod 2^64` | stored in `MontCtx` but never cleansed on replacement or release | stored in `MontCtx`; wiped by `cleanse_n0` before every replacement and by `MontCtx::drop` |
| modulus in `BN_MONT_CTX_set` | `parts(x)` produced an ordinary temporary copy | `magnitude(x)` borrows the `BigNum` magnitude; `mont_set` is the single transfer into protected storage |

Public geometry is validated before the first secret-bearing allocation:
`refuses` (zero/even), `m.len().checked_mul(64)`, `c_int::try_from`, and the
doubling to `R^2`'s bit length all precede `pow2_mod_consttime`. The modulus is
normalised by the `BigNum` representation the only caller reads, and the radix is
the `MONT_RADIX_BITS` constant.

The temporary `one_plain` buffer remains an ordinary `Vec`: it holds the public
constant one, padded to the modulus width, and never holds modulus-derived data.

### Allocation-failure controls

Test:
`bn::mont::tests::an_allocation_failure_during_preparation_cleanses_the_derived_values`.

The seam records every distinct fallible-allocation site reached by one successful
preparation, including the `MontCtx` box, the fallible helpers inside
`pow2_mod_consttime` and `mont_mul_fallible`, the secret modulus copy and the
`one_plain` reservation. The test then fails each site in turn with
`fail_at_site`. `mont_set` has a test-only hook that arms the existing
`drop_probe` on the first secret-derived buffer (`R^2 mod N`). For every site
reached after that buffer exists, the probe observed:

- `nonzero_before > 0` — the buffer held live derived data before the failure;
- `nonzero_bytes == 0` — the whole allocation was wiped on the failure path;
- the entry point returned 0 — the injected failure was reported, not aborted.

At least one site exercised the armed buffer; the assertion is not vacuous.

**Negative control.** Temporarily reverting the `R^2 mod N` adoption to an
ordinary `Vec` made the same test fail with:

```
no allocation-failure site exercised the earlier secret buffer
```

The test therefore measures a secret-owned release, not merely the return code.
The repair was restored; the final focused test passed.

## 4. Defect 2 — unsynchronised cache publication

### Mechanism

The fast-path read and the publication are `Acquire`/`Release` operations on an
`AtomicPtr<MontCtx>` view of the caller's `*mut MontCtx` slot
(`AtomicPtr::from_ptr`). Compile-time assertions require the atomic view to have
exactly the slot's size and alignment; a target where it does not must fail to
compile rather than reinterpret the ABI slot.

The null-to-context transition is still serialised by the caller's write lock:
the fast path loads with `Acquire`, the under-lock re-read loads with `Acquire`,
and the single publication stores with `Release` before the unlock. A reader
that observes a non-null pointer therefore also observes the fully initialised,
immutable `MontCtx`; every waiter on the lock receives the same pointer.

### Reader and owner rule

`BN_MONT_CTX_set_locked` never frees or replaces a published context. The context
is owned by the enclosing object (`DH`, `DSA`, `RSA`, `RSA_PRIME_INFO`) and is
released once by that object's `finish` hook. A reader's pointer is valid only
while the enclosing object is alive and not being freed or having its method
changed; those transitions perform the non-atomic slot writes and are sound only
under the same exclusive-access precondition. The atomic publication removes the
data race between the fast-path read and the null-to-context store; it does not
extend the context's lifetime. A null `lock` leaves concurrent initialisation to
the caller's own exclusion: slot access is still race-free, but two callers
without exclusion may each create a context.

No public signature, exported symbol, `#[repr(C)]` layout or `CRYPTO_*` seam
changed. No ABI decision is required.

### Concurrency test and its limits

Test: `bn::mont::tests::the_locked_publication_is_atomic_and_publishes_once`
(4 threads × 25 iterations per phase, real threads, no test-only serialisation).

| phase | observation |
|---|---|
| concurrent initialisation | every caller received the same non-null context; the slot holds that pointer |
| concurrent failure (even modulus) | every caller received null; the slot remained null |
| replacement | with a context already published, every concurrent caller received the published pointer unchanged |
| destruction | release is sequenced after every reader joined, then the slot is republished and released again |

The test can detect a fast-path read that observes an unpublished or partially
published context, a second context created for the same slot, and a replacement
of a published pointer. It **cannot** detect a concurrent free while a reader
holds the pointer: that is outside the documented ownership precondition, so the
test does not attempt it. It also cannot observe a reordering that the abstract
`Acquire`/`Release` pair permits; it checks the abstract machine, not arbitrary
compiler or CPU optimisation.

## 5. Declassification boundary in `context_matches`

Direct test:
`bn::mont::tests::context_matches_compares_the_whole_modulus_and_refuses_a_difference`.
Equal operands are accepted; a one-bit difference is refused. The deliberately
broken early-exit comparator (`context_matches_early_exit`, test-only) answers
the same on defined input, so a semantic test alone cannot distinguish it.

ctgrind test:
`bn::mont::tests::ctgrind_context_matches_declassifies_at_the_equality_decision`.
The operand limbs are marked undefined; the stored modulus remains defined.

| run | result |
|---|---|
| tainted equal operand | `ERROR SUMMARY: 0 errors from 0 contexts` |
| tainted unequal operand | same run; no tainted branch |
| `CTGRIND_CONTROL=1`, early-exit comparator | `ERROR SUMMARY: 2 errors from 1 contexts`, at `context_matches_early_exit (mont.rs:1210)` |

The production comparison is branchless over the tainted comparison in this
build: the whole-width accumulation and the equality decision produce a value,
and the test declassifies that value only at the authorised decision point. The
control proves the instrument does see a per-limb early exit of the forbidden
shape.

## 6. DH mutation control

Test:
`dh::key::tests::disabling_dh_parameter_reuse_on_a_warm_object_adds_the_precomputation_allocations`.

The same live DH object, key, parameters, context pool and method are used for
both allocation counts. Only parameter reuse is toggled: the cached Montgomery
context is used for the first count; the flag is then cleared and the cached slot
emptied for the second. Observed with `--nocapture`:

```
DH reuse mutation: reused=19 rebuilt=24
```

Disabling reuse adds five seam-visible precomputation allocations on the warmed
object, so the DH reuse effect is causal at the mechanism level and is not the
fresh-object cold-start cost. This is an allocation-count control, not a timing
row; no timing obligation is discharged.

## 7. ctgrind at this digest

Instrument: valgrind 3.19.0 memcheck with the `VALGRIND_MAKE_MEM_UNDEFINED`
ctgrind technique. Command shape:

```
valgrind --tool=memcheck --error-exitcode=99 \
  target/debug/deps/openssl_rs-672100dcc99e32ac --exact <case> \
  --test-threads=1 --nocapture
```

Verbatim summaries:

```
==69919== ERROR SUMMARY: 97339 errors from 106 contexts (suppressed: 0 from 0)
==69932== ERROR SUMMARY: 97229 errors from 193 contexts (suppressed: 0 from 0)
==69945== ERROR SUMMARY: 97229 errors from 193 contexts (suppressed: 0 from 0)
==69957== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
==69960== ERROR SUMMARY: 2 errors from 1 contexts (suppressed: 0 from 0)
```

| case | errors / contexts | recorded baseline |
|---|---|---|
| `rsa::ossl::tests::ctgrind_rsa_crt_secret_moduli` | 97,339 / 106 | 96,541 / 106 and 96,836 / 112; approximately 98,000 / 105, repeats 97,626 / 111 and 96,155 / 105 |
| `ec::ecdsa_ossl::tests::ctgrind_ecdsa_sign_taints_nonce_and_key`, run 1 | 97,229 / 193 | approximately 97,217 / 186 |
| same, run 2 | 97,229 / 193 | approximately 97,200 / 190 |
| `bn::mont::tests::ctgrind_context_matches_declassifies_at_the_equality_decision` | 0 / 0 | no earlier direct case |
| same with `CTGRIND_CONTROL=1` | 2 / 1 | negative control, expected to fire |

Attribution notes:

- No context in the RSA CRT run names `context_matches`, `cleanse_n0`, the
  `AtomicPtr` publication, or the new preparation statements. The reported sites
  are the pre-existing even-modulus refusal, REDC and ladder sites.
- The ECDSA runs differ from each other and from the checked-in log only by
  counts of the same pre-existing field-arithmetic sites (`limbs::sub_fallible`,
  `limbs::cmp`, `BN_add`, and line-number shifts). A signature comparison against
  `evidence/performance-frontier/campaigns/PFP-1/ctgrind/ecdsa-sign.out` shows no
  new site class. Across the repair builds the spread was 184–193 contexts; the
  two final-binary runs both reported 193. The variation tracks the generated key
  and nonce, not the Montgomery changes.

**Scope statement.** These ctgrind runs execute a **debug test binary**, not the
optimised distribution DSO. They establish source-level dynamic observation of
control flow and addresses at this digest. They are not release-binary timing
assurance, and no constant-time claim is upgraded by them.

## 8. Gates at the final source

Inside `docker/openssl-rs-court.sh exec`, `CARGO_BUILD_JOBS=4`:

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Both exited 0; clippy finished with no diagnostics.

```
test result: ok. 2414 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 323.78s
test result: ok. 2414 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 143.97s
```

The first line is `--test-threads=1`, the second `--test-threads=4`. The baseline
was 2409 / 0 / 54; the five added tests account for the difference. No test was
removed and no test was newly ignored.

## 9. Unsafe accounting

| category | content |
|---|---|
| eliminated | ordinary `Vec` ownership of `R^2 mod N` and `R mod N` during preparation; the ordinary modulus copy in `BN_MONT_CTX_set`; the unsynchronised fast-path read of the cache slot |
| relocated | the `AtomicPtr` view of the caller's ABI slot, with a size/alignment compile-time assertion and a `# Safety` contract; the `cleanse_n0` volatile wipe, with its own `SAFETY` note |
| hidden | 0 |
| newly introduced unsafe ops | one `AtomicPtr::from_ptr`, one `runtime::mem::cleanse` call in `cleanse_n0`, and the test-only valgrind client-request sequences (the established pattern in `bn::arith`, `rsa::ossl` and `ec::ecdsa_ossl`) |
| obligations discharged | preparation failure paths release secret-derived storage cleansed; `n0` is wiped on replacement, copy and destruction; the null-to-context publication is race-free |
| obligations retained | the cached context's lifetime is the enclosing object's precondition; non-atomic finish-path slot writes require exclusive access; a null `lock` leaves concurrent initialisation to the caller; ctgrind does not cover variable-latency instructions |

## 10. Not finished and out of scope

- `BN_mod_exp_mont` and `BN_mod_exp_mont_consttime` still obtain the modulus
  through `parts_fallible`, an ordinary `Vec` copy. That is a pre-existing
  secret-copy path outside the named construction defect; it is recorded here as
  a residual rather than silently repaired.
- `MontCtx`'s `ni` field remains an ordinary empty `Vec`; the crate's word-based
  path never populates it, so it holds no secret.
- No timing obligation, performance claim or constant-time certificate is
  discharged or upgraded by this repair.
