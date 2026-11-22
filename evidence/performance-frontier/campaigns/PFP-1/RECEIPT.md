# PFP-1 receipt — prepared Montgomery domains

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-1.
**Programme:** `docs/PERFORMANCE-FRONTIER.md` §0, §3.1, §5 item 5, §11.
**Claim class:** `SCOPED_OBSERVATION` on the court venue. No PMU is exposed, so
this is not a frontier result.
**Evidence root:** `evidence/performance-frontier/campaigns/PFP-1/`.

---

## 1. Source identity

| item | value |
|---|---|
| source HEAD | `91ac573c0a8e1bc11371718e5f2a6022c55c9535` |
| worktree | dirty: the PFP-1 patch is applied; no commit was made |
| patch digest (`git diff` over the four source files) | `ddd4e0e01cf467880aaf5a6e44762bd19b9efa015df3944fcfa8f217dfdb2c82` |
| distribution DSO | `libcrypto.so.3`, SHA-256 `596f4833e35932da7efff936185dee17dcb56f3b6363f4682300afb741d3c5b9` |
| harness | `courts/performance-frontier/pfp1/bench_pfp1.c`, SHA-256 `481950340cbce3a0450606ec19440bc6649d7d8fd2fc677e10285c6c84f144b8` |
| analyser | `courts/performance-frontier/pfp1/analyse_pfp1.py`, SHA-256 `d6e5e871eec2628e368ea5d5d665a7892210747186ecd85dbb5c0b10fc895a1d` |
| before-control DSO | `libcrypto.so.3` from `git archive 91ac573c0`, SHA-256 `139966033ac9e935efc76290a9df9e91441aa2ea9f183a00089eb95e32093c0c` |

The before-control was built from the same HEAD without the patch. It is a
control, not a second candidate.

The runner (`courts/performance-frontier/pfp1/run_pfp1_perf.sh`, SHA-256
`e51e0500a0e2cf28bd171d60eb0b07da07d726936500ac312a080e9c1b7f7d25`) was amended
after the measured run to compare the mapped device, inode and size in addition
to the path. The amendment touches no latency sample; the stronger check was
applied post-hoc to all 32 process outputs and recorded in
`raw/identity-verify.tsv` (32 of 32 ok).

## 2. Files changed

- `src/bn/mont.rs` — `MontCtx` becomes a prepared domain; validation, refusal,
  secret-owned residues, fallible copy, tests.
- `src/bn/arith.rs` — `PreparedMontParams`; the ladder is split into a
  recomputing wrapper and a shared body that can reuse `R`, `R^2` and `n0`.
- `src/bn/exp.rs` — fixed-top prepared-context differential test.
- `src/rsa/ossl.rs` — prepared versus unprepared CRT differential test.
- `courts/performance-frontier/pfp1/bench_pfp1.c` — supplementary setup versus
  prepared harness over the frozen population.
- `courts/performance-frontier/pfp1/run_pfp1_perf.sh`,
  `courts/performance-frontier/pfp1/analyse_pfp1.py` — campaign runner and
  paired-ratio analysis.

No `docker/` file, no PFP-0 evidence and no other item's receipt was modified.

## 3. The prepared domain

`MontCtx` is the prepared object. Its fields are private and no C caller can
observe them; `BN_MONT_CTX`'s readable API, transfer and reference behaviour are
unchanged.

| field | meaning | ownership |
|---|---|---|
| `n: SecretLimbs` | the modulus `N` | secret-owned, cleansed on drop |
| `rr: SecretLimbs` | `R^2 mod N` | secret-owned, cleansed on drop |
| `one: SecretLimbs` | `R mod N`, the Montgomery form of one | secret-owned, cleansed on drop |
| `n0: [Limb; 2]` | `-N^-1 mod 2^64` | scalar, no storage |
| `ri: c_int` | `64 * N.len()` | public geometry |
| `radix_bits: u32` | `64` | representation identity |
| `backend: MontBackend` | `PortableRedc` | reduction-kernel identity |
| `ni: Vec<Limb>` | empty, as in the authority's word path | no secret |
| `flags: c_int` | copied, not interpreted | public |

`mont_set` prepares all of `N`, `R^2`, `R` and `n0` once, with fallible
allocation throughout; `R` is `R^2 * 1 * R^-1`, one Montgomery multiply.
`SecretBuf`'s `Drop` cleanses the whole allocation on normal return, early
return and unwind. `BN_MONT_CTX_copy` clones each buffer into fresh secret
storage and returns `NULL` if any allocation fails; that is a recorded
improvement over an aborting copy. No exported symbol or signature changed, no
`#[repr(C)]` layout changed, and the `CRYPTO_*` allocator seam is untouched. The
recorded P1 residual (a `MontCtx` box is not observed by
`CRYPTO_set_mem_functions`) is retained rather than reclassified.

### Validity and refusal

Before a supplied context is consumed, `context_matches` checks:

1. the public structure — `radix_bits == 64`, `backend == PortableRedc`,
   `ri == 64 * md.len()`, and `n`, `rr` and `one` each exactly `md.len()` limbs;
2. the modulus contents — a full-width `diff |= stored ^ operand` accumulation
   with no per-limb early exit, followed by one `diff == 0` test;
3. `n0` — re-derived from `md[0]` and folded into the same accumulation.

A structural mismatch returns `false` without reading a modulus limb. A content
mismatch returns `false` after the whole width has been read. The entry point
then raises `BN_R_INVALID_RANGE` at a documented local site (`raise_with` with
line `0`; the authority has no coordinate because it does not validate
`in_mont`) and returns 0. A stale context is an error, never a silent
recompute.

**Classification of the comparison's control flow.** The test reveals only
whether two stored copies of the same modulus agree; on the legitimate path they
always agree. It reveals no modulus value and has no per-limb exit. It is
`SECRET_DEPENDENT_CONTROL` with a declassification boundary at the refusal
decision.

## 4. RSA and DH lifecycles

- **DH.** `dh_init` keeps `DH_FLAG_CACHE_MONT_P`; `ossl_dh_compute_key` continues
  to obtain the context through `BN_MONT_CTX_set_locked` under `dh->lock` and
  passes it to `dh_bn_mod_exp` → `BN_mod_exp_mont`. With the private exponent
  marked `BN_FLG_CONSTTIME`, the constant-time ladder now consumes the prepared
  `R`, `R^2` and `n0`.
- **RSA.** `RSA_FLAG_CACHE_PUBLIC` and `RSA_FLAG_CACHE_PRIVATE` behaviour is
  unchanged. `rsa_ossl_mod_exp` still builds `_method_mod_p`, `_method_mod_q`
  and `_method_mod_n` through `BN_MONT_CTX_set_locked`; the CRT halves now reach
  the ladder through `BN_mod_exp_mont_consttime_x2` with the prepared contexts
  consumed. `rsa_ossl_finish` still releases and clears every slot.
- **EC.** `group->mont_data` is built from `group->order`, and the order
  inversion and `ossl_ec_GFp_mont_field_inv` call shape now consumes it. The
  field context (`field_data1`) is built from `group->field`; each context is
  used only with its own modulus.
- **Mutation.** A key mutation that leaves a stale cached context is refused by
  the equality test on the next operation. The authority does not clear the
  caches in `RSA_set0_key`/`RSA_set0_factors`, so this turns a silent wrong
  answer into an error. The tests cover a same-width different modulus, a
  different width, a different radix and a different backend.
- **Concurrency.** A prepared context is immutable after `mont_set`; the caches
  are installed under the owning object's lock and only move from null to a
  fresh context. The exponentiation takes no lock and holds none across a
  callback. As in the authority, the owning object's lifetime must outlive the
  operation and must not be freed or mutated concurrently; that precondition is
  retained, not hidden.
- **Allocation.** Every prepared-object and ladder allocation is fallible and
  returns the entry point's ordinary failure answer. No new panic or infallible
  allocation is on the hot path.

## 5. Correctness differential

All counts are from the passing test run; no test was removed or newly ignored.

| test | population | result |
|---|---|---|
| `bn::mont::tests::a_prepared_domain_matches_the_unprepared_ladder_over_adversarial_operands` | 5 moduli (1-limb, limb boundary, secret-shaped 2-limb, 4-limb all-ones, 129-bit), 8 exponents (0, 1, all-ones, full-width top bit, 4 pseudorandom), 4 bases; both `BN_mod_exp_mont` (consttime dispatch) and `BN_mod_exp_mont_consttime` | prepared = unprepared = variable-time oracle in every case; ≥100 cases |
| `bn::exp::tests::the_fixed_top_answer_is_unchanged_by_a_prepared_context` | 129-bit modulus and exponent, fixed-top EC call shape | equal |
| `rsa::ossl::tests::the_prepared_crt_path_answers_what_the_unprepared_path_answers` | 2048-bit CRT key; cached (`RSA_FLAG_CACHE_PRIVATE` on) versus rebuilt contexts | equal |
| `bn::mont::tests::a_prepared_domain_removes_the_precomputation_allocations` | same operation with and without a prepared context | prepared reaches fewer fallible-allocation sites |
| `bn::mont::tests::a_prepared_domain_is_cleansed_on_release_and_survives_a_copy` | drop probe on the copied modulus | non-zero before, zero after; copy answers the same value |

Refusal tests:

| test | case | result |
|---|---|---|
| `a_context_for_another_modulus_is_refused` | same width, different modulus; different width; `BN_mod_exp_mont` with a non-consttime dispatch | 0 and `BN_R_INVALID_RANGE` |
| `a_context_for_another_representation_is_refused` | `radix_bits = 32`; a different backend identity; a never-prepared context | 0 and `BN_R_INVALID_RANGE` |

## 6. ctgrind at the same digest

Command shape:

```
valgrind --tool=memcheck --error-exitcode=99 <lib-test-binary> \
  --exact <case> --test-threads=1 --nocapture
```

Verbatim summaries (logs under `evidence/performance-frontier/campaigns/PFP-1/ctgrind/`):

```
==590365== ERROR SUMMARY: 96541 errors from 106 contexts (suppressed: 0 from 0)
==590396== ERROR SUMMARY: 96836 errors from 112 contexts (suppressed: 0 from 0)
```

RSA CRT (`rsa::ossl::tests::ctgrind_rsa_crt_secret_moduli`), two runs:
96,541 / 106 and 96,836 / 112. The recorded baseline is approximately 98,000 /
105, with 97,626 / 111 and 96,155 / 105 on earlier repeats: the observed counts
are inside the instrument's recorded variance. No context is attributed to
`context_matches` (`mont.rs:285-313`) or to the prepared fields; the reported
sites are the pre-existing even-modulus, REDC and ladder sites.

```
==590380== ERROR SUMMARY: 97217 errors from 186 contexts (suppressed: 0 from 0)
```

ECDSA sign (`ec::ecdsa_ossl::tests::ctgrind_ecdsa_sign_taints_nonce_and_key`):
97,217 / 186, against the approximately 97,200 / 190 baseline. The group order
is public, so the validation compares defined values on this path.

No stable new ctgrind context is introduced. ctgrind reports control flow and
addresses, not variable-latency instructions; this is not a constant-time proof.

## 7. Performance

Protocol: `docs/PERFORMANCE-METHODOLOGY.md` §6 applied to a within-candidate
paired comparison. 15 repetitions, one process per mode per repetition, balanced
mode order from `0x50465030`, median of five timed batch means per process,
median of the paired `setup / prepared` ratios, percentile bootstrap interval
(20,000 resamples, same seed). `setup` removes reuse: a NULL context for modexp;
for DH and RSA, a fresh object whose first operation builds the contexts. `EC` is
reported as `unchanged` because PFP-1 gives it no second mode.

### Post-change candidate

| workload | setup µs | prepared µs | paired ratio | 95% bootstrap CI | sign-test p |
|---|---:|---:|---:|---|---:|
| `modexp2048` | 5526.0 | 5411.4 | 1.0215 | [1.0203, 1.0219] | 6.1e-05 |
| `modexp8192` | 362404.6 | 360497.9 | 1.0054 | [1.0031, 1.0078] | 7.4e-03 |
| `dh-synth2048` | 5528.3 | 5413.9 | 1.0213 | [1.0209, 1.0219] | 6.1e-05 |
| `dh-synth3072` | 18855.2 | 18439.5 | 1.0225 | [1.0140, 1.0283] | 6.1e-05 |
| `dh-ffdhe2048` | 5531.1 | 5412.3 | 1.0218 | [1.0213, 1.0277] | 6.1e-05 |
| `dh-ffdhe3072` | 18830.3 | 18447.2 | 1.0204 | [1.0165, 1.0293] | 6.1e-05 |
| `dh-modp2048` | 5537.3 | 5415.2 | 1.0216 | [1.0204, 1.0259] | 6.1e-05 |
| `rsa2048` | 9212.4 | 1839.0 | 5.0139 | [5.0026, 5.0201] | 6.1e-05 |
| `ecdsa256` | 437.0 | 437.0 | control | — | — |

The RSA ratio is not a Montgomery-only figure: the cold arm also creates the
blinding context and both prime contexts on its first operation. The modexp and
DH ratios isolate the prepared-domain reuse.

### Before-control (same HEAD, no patch)

5 repetitions over the same population:

| workload | setup µs | prepared µs | paired ratio | 95% bootstrap CI |
|---|---:|---:|---:|---|
| `modexp2048` | 5583.7 | 5583.5 | 0.9996 | [0.9979, 1.0019] |
| `modexp8192` | 370303.3 | 370469.9 | 0.9997 | [0.9927, 1.0005] |
| `dh-synth2048` | 5693.1 | 5573.9 | 1.0168 | [1.0134, 1.0262] |
| `dh-ffdhe2048` | 5713.1 | 5598.5 | 1.0228 | [0.9959, 1.0366] |
| `rsa2048` | 9478.3 | 1921.8 | 4.9328 | [4.8942, 5.9485] |

The modexp prepared/setup ratio of 0.9996 is the direct control: before the
change, a supplied `BN_MONT_CTX` was ignored, so the prepared arm was the
recompute arm. After the change the ratio is 1.0215. The before prepared
absolute times (`modexp2048` 5583.5 µs, `dh-synth2048` 5573.9 µs, `rsa2048`
1921.8 µs) are also higher than the after prepared times (5411.4, 5413.9 and
1839.0 µs); the before/after comparison is not paired, so the paired ratios are
the primary evidence.

### Mutation-control direction and magnitude

Disabling reuse makes the affected operation slower: +2.15% for `modexp2048`,
+0.54% for `modexp8192`, +2.1% for the 2048-bit DH rows, and the setup-inclusive
RSA first operation is 5.01× the prepared operation. The direction is positive
for every affected row and the bootstrap interval excludes 1 for every affected
row except the before-control `dh-ffdhe2048` row. The change is load-bearing.

A performance result never discharges a timing obligation.

## 8. Gates

Run in `docker/openssl-rs-court.sh exec`, `CARGO_BUILD_JOBS=4`, host `available`
28 GiB, court cap 6g/6g:

```
FMT_EXIT=0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 18.09s
```

`cargo fmt --all -- --check` exited 0; `cargo clippy --all-targets -- -D
warnings` finished with no diagnostics.

Serial and threaded library tests:

```
test result: ok. 2409 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 361.78s
test result: ok. 2409 passed; 0 failed; 54 ignored; 0 measured; 0 filtered out; finished in 130.26s
```

The baseline was 2402; the seven new tests account for the difference. No test
was removed and no test was newly ignored.

## 9. Unsafe accounting

| category | content |
|---|---|
| eliminated | untyped `Vec<Limb>` storage for the secret CRT modulus and residues; silent reuse of a caller context for a different modulus; the aborting context copy |
| relocated | the C-ABI null-or-live pointer checks (`as_ref_mont`) and the refusal raise (`raise_with` at a documented local site) |
| hidden | 0 |
| newly introduced unsafe ops | one `raise_with` call, with a `SAFETY` note; one `as_ref_mont` call in each entry point, with the existing pointer contract |
| retained obligations | `in_mont` is null-or-live and not concurrently freed or mutated; the owning object's lifetime outlives the operation; no lock is held across a callback; the equality decision is classified `SECRET_DEPENDENT_CONTROL` |
| obligations discharged | the prepared domain's interior is safe Rust over `SecretBuf`; the modulus, `R^2` and `R` are cleansed on every exit; allocation failure is reported rather than aborted |
| obligations retained | the C-ABI lifetime/concurrency precondition; ctgrind's blind spots (no variable-latency coverage); no timing obligation is discharged |

## 10. Timing obligations

PFP-1 **discharges no timing obligation**. It removes a repeated precomputation;
it does not change the fixed-width ladder's iteration count, storage policy or
allocation geometry. T6's precomputation loops remain fixed-pattern; the only
modulus-content-dependent decision is the mandated equality test, classified
above and not reported as a new ctgrind context. T11's RSA CRT lifecycle,
blinding, fault verification and result check are unchanged. T23, T24 and T29's
residuals remain open and are not discharged by this item or by its performance
result.

## 11. What this receipt does not establish

- It does not establish a frontier result; the venue has no PMU.
- It does not establish constant-time behaviour; ctgrind covers control flow and
  addresses only.
- It does not establish the authority's behaviour for a stale context: the
  authority silently uses it; this implementation refuses it, and that
  divergence is deliberate.
- It does not establish that the before/after absolute times are paired; only
  the within-campaign paired ratios are.
- It does not discharge any timing, safety-graduation or compatibility obligation
  by virtue of the measured speedup.
