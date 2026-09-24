# Phase 9 — RAND, DRBG and entropy, as subphases

## 0. What this stratum is, and what it is not

Phase 9 is the random layer: `rand.h`'s front, the BN random family that sits behind it, the
providers' DRBG framework and its three instantiations, and the seed sources those draw on.

It is **not** a cryptographic primitive stratum of Phase 8's kind. Phase 8's court question is
"does this construction satisfy its standard"; the random layer's question is a different one,
and this plan's §3 records what it is: an output *distribution* claim that no byte-comparison
can make. What a differential court can do here is exhaustively measured in §3.3.

**Why this stratum is being planned while Phase 8 is still open.** D286 measured that `RSA_new`,
`DH_new`, `DSA_new` and `EC_KEY_new` each reach `RAND_bytes_ex` through their default method
table, so 8.4–8.7's *object layers* cannot land before this stratum's front exists. Phase 8's
remaining open work is therefore almost entirely blocked on this stratum, and D287 scoped the
dependency chain and recorded it as the next unit. This document is that scope, measured.

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed -- and it is **the measurement this
plan made, and not a current reading**. `forensics/phase9-obligations.json` is authoritative for the
present, and three later decisions have moved what is below: D296 moved the two X9 KDF wrappers out
of the phase-8 hand-off row into this stratum's own `open` set, D323 retired the six randomised RSA
padding names, and D324 landed the blinding and prime families. The table is kept as the record of
what the plan rested on rather than retyped, because a hand-written count that a landing can move is
the defect `docs/CI.md` names for a typed count and D205 records for a seal.

**Phase 9's atlas-owned universe is twenty-five exports, and they are all `rand.h`'s.**
`forensics/atlas/symbol-ownership.json` assigns exactly 25 exports to phase 9, each declaring
`rand.h`. No other header in the authority declares an export this stratum owns.

**It also receives seventy hand-offs**, discovered from the other ledgers (`phase*-obligations.json`
rows whose `owning_phase` is 9) rather than listed here:

| from phase | count | what it is |
|---|---|---|
| 4 | 1 | `BIO_f_nbio_test`, whose body is a random-fill |
| 5 | 31 | the BN random family, the blinding family, the prime generators and the primality tests |
| 7 | 12 | `EVP_SealInit`, `EVP_CIPHER_CTX_rand_key`, the `PEM_*` file-encryption helpers, `OSSL_HPKE_get_grease_value`, `BIO_f_reliable` |
| 8 | 26 | the four key types' constructors and generators, the RSA blinding pair, and the six RSA padding functions whose bytes are random (six of these were retired by D323) |

That is a working set of **95 exports as this plan measured it**, and the shape of it is the finding: **Phase 9's work
lives in ten earlier strata's modules**. There is no `src/rand/`-only reading of this stratum. A
`BIO` export, a `PEM` export and four key types' constructors are all *bodies* this stratum owes,
because the authority wrote the random call inside them.

**Phase 9 owns fifteen provider registration rows** (`provider-algorithms.json`, `owning_phase 9`):

```
default / OSSL_OP_CIPHER   8    the AES-GCM three, the ARIA-GCM three, SM4-GCM, DES3-WRAP
default / OSSL_OP_RAND     5    CTR-DRBG, HASH-DRBG, HMAC-DRBG, SEED-SRC, TEST-RAND
default / OSSL_OP_MAC      1    GMAC, blocked on the GCM cipher rows
base    / OSSL_OP_RAND     1    SEED-SRC
```

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 9.0 | **The plan and the census** | `docs/PHASE-9-SUBPHASES.md`, and the measurement in §1. The ledger and the runner are the *next* subphase's, unlike Phase 8's 8.0, and §4 says why. | 8.3 (the provider table machinery), `phase-state.json` | — |
| 9.1 | **The BN random family** | `crypto/bn/bn_rand.c`: `BN_rand`, `BN_rand_ex`, `BN_priv_rand`, `BN_priv_rand_ex`, `BN_rand_range`, `BN_rand_range_ex`, `BN_priv_rand_range`, `BN_priv_rand_range_ex`, `BN_pseudo_rand`, `BN_pseudo_rand_range`, `BN_bntest_rand` and the `bnrand`/`bnrand_range` bodies. Retires eleven of phase 5's thirty-one. | 9.2 | `RT-BN-RAND`, `CT-BN-RAND` |
| 9.2 | **The RAND front** | `crypto/rand/rand_lib.c`'s twenty-five exports, `crypto/rand/rand_pool.c`'s pool -- **landed in D310's predecessor, because it is the one unit of this stratum with no platform dependency and no caller**, so it compiles and is tested before anything else exists -- and `rand_uniform.c`'s internal consumers. **D311 measured the front's cost and its one cross-stratum boundary**: three of the twenty-five (`RAND_get_rand_method`, `RAND_set_rand_method`, `RAND_set_rand_engine`) read and write the `RAND_METHOD`/ENGINE table, and `ENGINE_init`/`ENGINE_finish`/`ENGINE_get_RAND`/`ENGINE_get_default_RAND` are `engine.h`'s and **Phase 13's** -- this profile has ENGINE enabled (the authority exports all four), so those three exports are withheld rather than partially written. The other twenty-two land with `rand_uniform.c`; the remaining cost is `src/runtime/bio/sys.rs`'s `stat`/`fstat`/`fdopen`/`clearerr`/`setbuf`/`chmod` bindings (including a `struct stat` layout, which is architecture-specific and is why it is named rather than ticked off). | 9.3–9.5, **13** | `RT-RAND` |
| 9.3 | **The DRBG framework** | `providers/implementations/rands/drbg.c` — `PROV_DRBG`, the reseed/instantiate/generate state machine, and the three dispatch tables' shared shape — plus its two provider-side prerequisites, `providers/common/provider_seeding.c` (the four seed up-calls, **landed**) and `provider_util.c`'s `ossl_prov_set_macctx`/`ossl_prov_macctx_load` (**landed**). | 9.4 | `RT-RAND` (shared) |
| 9.4 | **The three DRBGs** | `drbg_ctr.c.in`, `drbg_hash.c.in`, `drbg_hmac.c.in`, and the `OSSL_OP_RAND` rows `ossl_drbg_ctr_functions`, `ossl_drbg_hash_functions` and `ossl_drbg_ossl_hmac_functions`. | 9.5 | `RT-DRBG`, `CT-DRBG` |
| 9.5 | **The seed sources** | `seed_src.c.in`, `test_rng.c.in`, **`providers/implementations/rands/seeding/rand_unix.c`** -- where `ossl_pool_acquire_entropy` and `ossl_rand_pool_init`/`_cleanup` actually live, named here because D298's measurement moved them out of `crypto/rand/rand_pool.c` -- and the two SEED-SRC rows plus the TEST-RAND row. **D287 named `providers/implementations/rands/crngt.c` instead of `fips_crng_test.c.in` and that file does not exist in this authority** -- §4.1 is the measurement and `forensics/prerequisites.json`'s `units` block carries the `does_not_exist_in_this_authority` record, so the correction is checked against the committed manifest rather than left as prose. **`fips_crng_test.c.in` is named by the authority but is *not* this stratum's to transcribe**: `providers/implementations/rands/build.info` lists it under `SOURCE[../../libfips.a]` alone, this profile builds no FIPS module, and its only row (`fipsprov.c:445`'s `CRNG-TEST`) is not in an admitted provider -- so the census has no observable for it and D310 records it rather than carrying it. **The `.in` spelling of the four generated units is load-bearing here rather than cosmetic**: the authority's `internal-symbols.json` keys a translation unit by the object name its build gives it, so `plan_reconciliation.py` resolves the source path and has to be able to recognise a `.c.in` to join the two (D420). | 9.3, `src/rand/sys.rs` | `RT-RAND` (shared) |
| 9.6 | **The seventy hand-offs** | the earlier strata's blocked rows, discharged in the order the strata that own their headers: the four key types' object layers first, then 8.4's accessors, then `EVP_sha*`' retrieval, then the `PEM_*` and `HPKE` tails. | 9.1, 9.2 | each stratum's own courts |

The order is forced twice over, and D287 recorded both: `RAND_bytes_ex` cannot be written before
the DRBG it fetches, and the DRBG cannot be courted before the provider row that publishes it.
9.1 is written with 9.2 rather than before it because the BN family's own court needs the front's
fixed-seed path.

## 3. What each subphase must honour

**3.1 The front is a fetch, not a function.** `RAND_bytes_ex` resolves a DRBG through the
provider store and calls `EVP_RAND_generate`; it is not an entropy call. A transcription that
answered bytes from a source of its own would satisfy every vector a probe could write and be a
different library.

**3.2 The provider context carries the library context.** D240's finding applies unchanged: a
fetched DRBG's sub-fetches (the AES under CTR-DRBG, the digest under HASH-DRBG) resolve in the
library context of the provider that created the row, so `PROV_LIBCTX_OF(provctx)` is load-bearing
here rather than incidental. `provider-algorithms.json`'s `provider_context` block already
classifies the authority's acquisition sites and anchors each landed one; the DRBG rows are three
more of them.

**3.3 What a differential court can and cannot establish here.** A probe can compare, byte for
byte: the *parameters* a DRBG reports (`ossl_drbg_get_ctx_params`), the refusal reasons and
coordinates for every invalid-parameter arm, the state transitions (`EVP_RAND_STATE_ERROR` after a
failed instantiate, `_READY` after a successful one), the reseed-interval boundary, the
prediction-resistance path's *observable* refusal, and — with a `TEST-RAND` row and a fixed seed —
the exact bytes both sides produce. It cannot establish that either side's output is
unpredictable. That is a property of the seeding pool, not of a transcript, and this plan records
it as **not courted** rather than leaving it implied. Where the authority's own behaviour *is* the
contract — the refusal shapes, the parameter surface, the state machine — the differential court
is the strongest instrument there is, and those are what 9.2–9.5's arms carry.

**3.4 Nothing here is a parity claim about entropy.** The entropy pool's source on the host is
environmental (`getrandom(2)`, `/dev/urandom`), and a court that compared pool *contents* across
two builds would be comparing two machines. The measured surface is the one above.

## 4. Two measured corrections to D287, and one precondition

**4.1 There is no `providers/implementations/rands/crngt.c` in 3.6.4.** D287's table names that
file as 9.5's unit and it does not exist in the admitted tree. The continuous random number
generator test is `providers/implementations/rands/fips_crng_test.c.in`, whose entry points are
`RCT_test`/`APT_test` and whose dispatch table is `ossl_crng_test_functions`; `implementations.h`
keeps a dead `extern` for the old name. The correction is recorded rather than silently applied,
because a later reader following D287 to that path would conclude the unit was missing. It is also
recorded where the machine can see it: `forensics/prerequisites.json`'s `units` block carries a
`does_not_exist_in_this_authority` row for the path, which `plan_reconciliation.py` verifies against
the committed manifest and fails if the file ever appears.

**4.2 D287's "the `base` provider's single RAND row is the test RNG" is wrong.** `baseprov.c`'s
`base_rands[]` publishes **SEED-SRC** and nothing else; TEST-RAND is `defltprov.c`'s. The census
agrees — `base / OSSL_OP_RAND` is one row, and it is `SEED-SRC` (4.2 is measured by the same
`Counter` that produced §1's table).

**4.3 None of these rows carries an alias or an OID.** The three DRBG rows, both SEED-SRC rows and
TEST-RAND each declare a single `algorithm_names` string (`"CTR-DRBG"`, `"HASH-DRBG"`,
`"HMAC-DRBG"`, `"SEED-SRC"`, `"TEST-RAND"`) and no alias, so the census's alias-sequence identity
check is trivially satisfied for them. Their exactness rests on the *dispatch association* and the
*subsequence order* checks instead, which is where a transcription error in these rows would be
observable.

**4.4 The precondition this plan places on 9.1's commit, and it is not optional.**
`forensics/tools/gen_provider_algorithms.py` currently derives each row's state as

```python
state = "open" if owning_phase == 8 else "deferred"
```

which is **stratum-8-relative**. Activating phase 9 in `forensics/tools/phase_state.py`'s
`STRATUM_EVIDENCE` — the thing that makes a stratum's courts and ledger participate in its
completion rule — would, with that line unchanged, silently reclassify **phase 8's eleven open
cipher rows as `deferred`**, and phase 8 would then be able to reach `open_in_this_stratum == 0`
with eleven provider rows unpublished. The state must become a *projection over the stratum
being judged* (an `implementation_state` of `implemented`/`unimplemented` plus the owning phase,
with `open` and `deferred` derived) before, not after, phase 9 is activated. That refactor lands
with 9.1, in the commit that activates the stratum.

## 5. Process

This stratum inherits Phase 8's process unchanged: a subphase lands its code, its court and its
regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236); every provider row it
publishes is named by a probe of a court that covers it (D245); and an artefact that a source
change moves is regenerated in the same commit. `docs/DECISIONS.md` is append-only and this
document is not a decision record.

**4.5 This plan's own boundaries are the census's, and the census will correct them.** The
subphase table above was written from the dependency chain D287 established and the 95-export
measurement in §1. D283's equivalent table for Phase 8 was corrected twice by measurement -- by
D285, which found that most of a slice was another stratum's, and by D287, which found a
prerequisite the slice's name could not show. The same is expected here and is not a defect in
this document: the census is the authority, and a subphase that discovers its unit is somewhere
else records that rather than forcing the row.

**Landed exports (checked against the ledger):**

None. No export of this stratum is implemented: the crate defines none of the twenty-five `rand.h`
exports it owns, and none of the seventy that earlier strata handed it. The stratum's provider rows
are likewise unpublished -- fifteen rows, none of them landed.

**Open exports (checked against the ledger):**

All ninety-five, beginning with the twenty-five this stratum owns and the seventy it receives.
The `rand.h` front is `RAND_bytes_ex`, `RAND_bytes`, `RAND_priv_bytes_ex`, `RAND_priv_bytes`,
`RAND_get0_primary`, `RAND_get0_public`, `RAND_get0_private`, `RAND_status`, `RAND_seed`,
`RAND_add`, `RAND_poll`, `RAND_OpenSSL`, `RAND_get_rand_method`, `RAND_set_rand_method`,
`RAND_set_rand_engine`, `RAND_set_DRBG_type`, `RAND_set_seed_source_type`,
`RAND_set1_random_provider`, `RAND_set0_public`, `RAND_set0_private`, `RAND_pseudo_bytes`,
`RAND_file_name`, `RAND_load_file`, `RAND_write_file` and `RAND_keep_random_devices_open`. The
hand-offs are the BN random and blinding families (`BN_rand`, `BN_rand_ex`, `BN_priv_rand`,
`BN_priv_rand_range_ex`, `BN_pseudo_rand_range`, `BN_bntest_rand`, `BN_BLINDING_create_param`),
the prime generators (`BN_generate_prime_ex2`, `BN_check_prime`, `BN_X931_generate_prime_ex`), the
key generators (`RSA_generate_key_ex`, `DH_generate_key`, `DSA_generate_key`,
`EC_KEY_generate_key`), the four key types' constructors (`RSA_new`, `RSA_new_method`), the RSA
blinding pair and the six RSA padding functions whose bytes are random
(`RSA_padding_add_PKCS1_type_2`, `RSA_padding_add_PKCS1_OAEP_mgf1`, `RSA_padding_add_PKCS1_PSS`,
`RSA_padding_add_PKCS1_PSS_mgf1`, `RSA_padding_check_PKCS1_type_2`, `RSA_X931_generate_key_ex`),
and the tails (`EVP_SealInit`, `EVP_CIPHER_CTX_rand_key`, `DES_random_key`, `PEM_do_header`,
`OSSL_HPKE_get_grease_value`, `BIO_f_reliable`, `BIO_f_nbio_test`, `DH_KDF_X9_42`,
`ECDH_KDF_X9_62`).

**Why 9.0 is staged over two commits.** The plan and the census land with the stratum's ledger and
court runner, because `phase_state.py` refuses any stratum that has a plan, a ledger or a court file
on disk without a `STRATUM_EVIDENCE` row, and the row cannot be added while a third stratum's
activation would move another's numbers -- which is the provider-state projection D295 landed
first, in its own commit and with its own self-test.
