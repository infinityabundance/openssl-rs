# Phase 9 — RAND, DRBG and entropy: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. `forensics/phase-state.json:456` reads `complete` for phase 9,
`docs/SEAL-CENSUS.md:305` reads `complete`, `forensics/phase9-obligations.json:9` reads
`open_in_this_stratum: 0`, and every earlier stratum is `complete`, which is the rule
`forensics/phase-state.json:612` states. The one field that is *not* yet derived is
`seal_sha256`, which `forensics/phase-state.json:455` reads as `null`, and whose census line is
`seal: none written yet (unnamed)` (`docs/SEAL-CENSUS.md:306`): this document is the plan's own last
artefact and the thing the missing hash will be computed over. Reaching `complete` means the stratum
has reached the state a seal *records* (D421, `docs/DECISIONS.md:30283-30287`); it is **not** a
parity claim, and this document is where what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which `forensics/tools/render_seal_census.py`
generates from the ledgers and the court results. This seal cites that document rather than restating
its arithmetic, because a number typed here is a number that can drift from the evidence it summarises
(D97), and the census's own header (`docs/SEAL-CENSUS.md:6-9`) says so. The one table this document
*does* carry — §3's court list — is copied from `artifacts/phase9/COURTS.json`, and it says so.

This is **not** a claim that openssl-rs is a usable OpenSSL, and it is **not a parity claim**.
`docs/PARITY_MODEL.md` is the authority on what the labels mean: `implemented` means a symbol with
that name is defined, and a passing bounded court is a differential result over the behaviours that
court exercises. `PARITY_VERIFIED` is not claimed for any symbol here, and `forensics/STATUS.md:294-301`
carries the non-claims the generated status emits. All `libssl` exports remain `SCAFFOLDED` and abort
when called.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`, the second entry),
  named as the authority by `artifacts/phase9/COURTS.json:5`
- Court results: `artifacts/phase9/COURTS.json` — four courts, `all_pass` true
  (`artifacts/phase9/COURTS.json:4`), zero residuals; the totals are `docs/SEAL-CENSUS.md`'s and the
  per-court table is §3. **One pending court, `CT-DRBG`**, is recorded at
  `artifacts/phase9/COURTS.json:77-79` and is not counted among the four
- Obligation ledger: `forensics/phase9-obligations.json` — `open_in_this_stratum` 0
  (`forensics/phase9-obligations.json:9`), `deferred_to_later_phase` 0
  (`forensics/phase9-obligations.json:7`)
- Court coverage: `forensics/atlas/court-coverage.json` — phase 9's block at
  `forensics/atlas/court-coverage.json:22095`; the counts are `docs/SEAL-CENSUS.md` §Court coverage,
  and the weaker meaning of `directly_courted` is stated there and in §1 below (D199)
- Derived state: `forensics/phase-state.json:428-458`
- Provider rows: `forensics/atlas/provider-algorithms.json`'s `projection` block
  (`forensics/atlas/provider-algorithms.json:75-88`) and the `provider_rows` block of
  `forensics/phase-state.json` (`forensics/phase-state.json:450-453`) — every registration row the
  plan gives this stratum is implemented
- FRF receipts and claim: **none** — `.frf/` carries no Phase 9 declaration. §8 states this as the
  state of the instrument rather than of the courts
- Gemel checkpoint: **none** — `forensics/GEMEL_TRAJECTORY.md`'s head is Phase 8's `C76`/`K47`
  (`forensics/GEMEL_TRAJECTORY.md:13,157`). §8 states this
- Deciding record: `docs/DECISIONS.md` — **D287** (the scope this stratum's plan rests on), the
  census and activation series **D294–D298**, the landing series **D310–D318** and **D323–D324**,
  **D346** and **D350** (two names this stratum owed itself), **D413** (the chain Phase 8 joined,
  which fixes what a chain entry requires), and this stratum's own **D417–D421**; with
  `docs/PHASE-9-SUBPHASES.md` for the subphase plan this seal closes

## 1. What this phase owns, and how that was decided

Phase 9 is **the random layer**: `rand.h`'s front, the BN random family that sits behind it, the
providers' DRBG framework and its three instantiations, and the seed sources those draw on
(`docs/PHASE-9-SUBPHASES.md:5-6`). It is deliberately *not* a cryptographic primitive stratum of
Phase 8's kind. Phase 8's court question is "does this construction satisfy its standard"; this
stratum's is a different one, and the plan's §3 records it (`docs/PHASE-9-SUBPHASES.md:8-11`): an
output *distribution* claim that no byte-comparison can make, and what a differential court *can*
do here is exhaustively measured at `docs/PHASE-9-SUBPHASES.md:88-97`.

**Why this stratum was planned while Phase 8 was still open.** D286 measured that `RSA_new`,
`DH_new`, `DSA_new` and `EC_KEY_new` each reach `RAND_bytes_ex` through their default method table,
so 8.4–8.7's *object layers* could not land before this stratum's front existed
(`docs/PHASE-9-SUBPHASES.md:13-17`). D287 scoped the dependency chain and recorded it as the next
unit; `docs/PHASE-9-SUBPHASES.md` is that scope, measured.

**The working set is derived, not chosen.** The rule is the ledger's own, at
`forensics/phase9-obligations.json:564`:

> the stratum's working set is the projection of `forensics/atlas/symbol-ownership.json` for phase 9,
> plus every symbol an earlier stratum's ledger records as handed to it: a symbol belongs to the
> stratum that owns the header declaring it, and a discharged hand-off belongs to the stratum that
> built it

The census's per-stratum row (`docs/SEAL-CENSUS.md:37`) reads `atlas-owned` 25, `ledger owned` 69,
`implemented` 69, `deferred` 0, `open` 0; the ledger's `counts` block
(`forensics/phase9-obligations.json:5-12`) reads `atlas_owned` 25, `received_by_handoff` 44,
`owned` 69. The 25 are all `rand.h`'s, and the 44 are the hand-offs the census enumerates at
`docs/SEAL-CENSUS.md:314-318`: one from phase 4, thirty-one from phase 5, twelve from phase 7.

**The plan's §1 and the census disagree, and the census is the authority — the plan says so itself.**
The plan measured the working set at **95** (25 owned plus 70 handed,
`docs/PHASE-9-SUBPHASES.md:29-46`) and named a 70-hand-off table including 26 from phase 8
(`docs/PHASE-9-SUBPHASES.md:36-41`). The ledger and census now read 69, and the census's hand-off list
names phases 4, 5 and 7 and **no phase-8 edge at all** (`docs/SEAL-CENSUS.md:314-318`). That is not a
contradiction the seal has to resolve: the plan's §1 is explicitly "**the measurement this plan made,
and not a current reading**" (`docs/PHASE-9-SUBPHASES.md:21-23`) and names D296, D323 and D324 as the
decisions that moved it. §10 records the readings.

**The six subphases, and the one that is a seal.** `docs/PHASE-9-SUBPHASES.md:59-67` divides the work
as 9.0 the plan and the census, 9.1 the BN random family, 9.2 the RAND front, 9.3 the DRBG framework,
9.4 the three DRBGs, 9.5 the seed sources, and 9.6 the earlier strata's hand-offs. There is no separate
"seal" row in this table, unlike Phase 8's 8.10; this document is the plan's last artefact and
`docs/PHASE-9-SUBPHASES.md:160-185` is the plan's own closing state, kept as the record of what was
open when the plan was written rather than retyped.

**The two planes, and which one this stratum's evidence is.** D201's commitment — every
primitive-bearing subphase carries a differential `RT-*` court *and* a correctness `CT-*` court — is
inherited here, but Phase 9's correctness plane is **not populated**: `CT-DRBG` is a pending court and
`CT-BN-RAND` was absent from both of `forensics/tools/phase9_courts.py`'s sets until **D423**
registered it there as pending, which is the gap that registration closes. §6 names both, and §8
explains why the differential four are the whole of this stratum's chain-relevant evidence.

## 2. What has been built

**9.1, the BN random family.** `crypto/bn/bn_rand.c` becomes `src/bn/rand.rs` (twelve of the phase-5
hand-offs, `forensics/phase9-obligations.json:556`), and with it the blinding family
(`crypto/bn/bn_blind.c`, `src/bn/blinding.rs`, four names) and the prime generators, primality tests
and the GF(2<sup>m</sup>) search pair (`crypto/bn/bn_prime.c` and `crypto/bn/bn_gf2m.c`,
`src/bn/primes.rs` and `src/bn/gf2m.rs`) landed by **D314** and **D324**. `BN_generate_dsa_nonce`
landed in D418, its body already present as D333's `ossl_bn_gen_dsa_nonce_fixed_top`
(`docs/DECISIONS.md:30047-30051`). The court is `RT-BN-RAND`, and it observes *properties rather than
values*, because the two sides seed from different pools (`forensics/tools/phase9_courts.py:53-69`).

**9.2, the RAND front.** `crypto/rand/rand_lib.c` becomes `src/rand/rand_lib.rs` (25 names,
`forensics/phase9-obligations.json:561`), with `crypto/rand/rand_pool.c` as `src/rand/pool.rs`,
`rand_uniform.c` as `src/rand/rand_uniform.rs`, and the two platform units as `src/rand/sys.rs` and
`src/rand/unix.rs`. The pool and the seeding arm landed first, because the pool is the one unit of
this stratum with no platform dependency and no caller (`docs/PHASE-9-SUBPHASES.md:63`, **D298**,
**D310**); the `sys` bindings and the front landed with `RT-RAND` (**D311**, **D312**, **D313**), and
the front's three `RAND_METHOD`/ENGINE-reading exports — `RAND_get_rand_method`, `RAND_set_rand_method`
and `RAND_set_rand_engine` — are written with the **no-engine reduction** D312 decided, not withheld
as D311 first measured (`docs/DECISIONS.md:20259-20268`). §10 records the plan row this supersedes.

**9.3 and 9.4, the DRBG framework and its three instantiations.** `providers/implementations/rands/drbg.c`
and its two provider-side prerequisites `providers/common/provider_seeding.c` and `provider_util.c`'s
`ossl_prov_set_macctx`/`ossl_prov_macctx_load` (`src/provider/seeding.rs`, `src/provider/util.rs`),
then `drbg_ctr.c.in`, `drbg_hash.c.in` and `drbg_hmac.c.in` and their three `OSSL_OP_RAND` rows. The
three dispatch tables' crate constants were renamed to the authority's `ossl_drbg_*_functions`
spellings by **D420** (`docs/DECISIONS.md:30158-30164`). The court is `RT-DRBG`.

**9.5, the seed sources.** `seed_src.c.in` and `test_rng.c.in`
(`ossl_seed_src_functions`, `ossl_test_rng_functions`), `providers/implementations/rands/seeding/rand_unix.c`
— where `ossl_pool_acquire_entropy` and `ossl_rand_pool_init`/`_cleanup` actually live, which D298's
measurement moved out of `crypto/rand/rand_pool.c` (`docs/PHASE-9-SUBPHASES.md:66`) — and, in **D421**,
the base provider module `src/provider/base.rs`, which publishes the last of the fifteen rows
(`docs/DECISIONS.md:30232-30246`).

**The fifteen provider registration rows.** `docs/PHASE-9-SUBPHASES.md:48-55` groups them: eight
`default`/`OSSL_OP_CIPHER` rows (the AES-GCM three, the ARIA-GCM three, SM4-GCM and DES3-WRAP), five
`default`/`OSSL_OP_RAND` rows (CTR-DRBG, HASH-DRBG, HMAC-DRBG, SEED-SRC, TEST-RAND), one
`default`/`OSSL_OP_MAC` row (GMAC) and one `base`/`OSSL_OP_RAND` row (SEED-SRC). The cipher half was
handed to this stratum on `RAND_bytes_ex` and landed by **D417** and **D418**; GMAC by **D419**; the
base SEED-SRC by **D421**. The census's `forensics/phase-state.json:450-453` reads `implemented` 15 of
`owned` 15, and the projection's `open["9"]` is 0 (`forensics/atlas/provider-algorithms.json:86`).

**The hand-offs this stratum received and discharged.** The census enumerates them by name at
`docs/SEAL-CENSUS.md:314-318`; they are the BN random, blinding and prime families (phase 5),
`BIO_f_nbio_test` (phase 4), and the twelve phase-7 names — `BIO_f_reliable`,
`EVP_CIPHER_CTX_rand_key`, `EVP_SealInit`, `OSSL_HPKE_get_grease_value`, and the eight `PEM_*`
readers and writers. The key types' object layers that once depended on this stratum landed inside
Phase 8's arc, which is why phase 8's seal records no edge into phase 9
(`docs/PHASE-8-CRYPTO-SEAL.md:465-469`).

## 3. The evidence

Copied from `artifacts/phase9/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-DRBG` | differential | 361 | `courts/phase9/rt_drbg_probe.c` |
| `RT-RAND` | differential | 145 | `courts/phase9/rt_rand_probe.c` |
| `RT-BN-RAND` | differential | 487 | `courts/phase9/rt_bn_rand_probe.c` |
| `RT-RAND-USERS` | differential | 111 | `courts/phase9/rt_rand_users_probe.c` |

All four rows carry `residual_count: 0` and `verdict: "pass"`
(`artifacts/phase9/COURTS.json:7-75`), and the summary reads `pass` 4 of `total` 4
(`artifacts/phase9/COURTS.json:80-84`). The totals over the four transcript courts are
`docs/SEAL-CENSUS.md`'s (`docs/SEAL-CENSUS.md:320`), and the per-court rows there
(`docs/SEAL-CENSUS.md:322-327`) are the same computation.

**There is no `CT-*` row here, and the distinction is the two-plane one.** Every court this stratum
ran is differential: a probe compiled twice, against the authority and the candidate, with the two
transcripts diffed line by line (`forensics/tools/phase9_courts.py:4-10`). `forensics/tools/phase9_courts.py`'s
`extra_defs` returns nothing for this stratum, because every observation is a return code, a state, a
name, a parameter key/type pair or an `ERR_GET_LIB`/`ERR_GET_REASON` pair, so a difference in a
transcript can only be a difference in behaviour (`forensics/tools/phase9_courts.py:146-156`). The
correctness plane that Phase 8's §3 also carries is §6's not-claimed list.

**The court coverage join is clean, and its meaning is the weaker one.** `docs/SEAL-CENSUS.md:348`
reads phase 9 as 69 implemented, 69 `directly_courted`, 0 indirect, 0 non-observable, 0 unmatched.
`directly_courted` means *referenced by a staged candidate probe that ran and produced a transcript*
(`docs/SEAL-CENSUS.md:335-338`), a proof of **reference** rather than that every arm of the symbol was
driven — the same reading Phase 8's seal adopts (`docs/PHASE-8-CRYPTO-SEAL.md:6-11`).

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's two
planes found real defects, including two in the evidence machinery.

**`RT-DRBG`'s first run produced 180 residual lines, and every one was the same defect.** The
candidate refused every instantiation with `PROV_R_ERROR_RETRIEVING_NONCE` while the authority
succeeded, because `ossl_lib_ctx_get_data(NULL, OSSL_LIB_CTX_DRBG_NONCE_INDEX)` answered NULL — the
`context_init` slot was never built — and the core published none of the eight seeding callbacks the
provider seeks entropy and nonces through (`forensics/tools/phase9_courts.py:31-37`). It is the shape
this stratum's evidence is for: the failure was invisible to source comparison and unambiguous to a
transcript.

**`probe_hygiene.py` caught a defect the differential court passed clean.** D403's finding is a
carry-propagation loop in the HASH-DRBG `add_bytes`
(`src/provider/rand.rs`, transcribed from `drbg_hash.c.in:156-184`): the authority writes `*d += 1;`
on an `unsigned char`, which wraps silently, while the crate is built with `overflow-checks = true`,
so on a carry that reached a `0xff` byte the Rust **panicked**. It was latent and flaky — measured at
about **1 run in 6** — and the court's own run had passed by luck; `probe_hygiene.py` runs each probe
at three optimisation levels and saw it (`docs/DECISIONS.md:29099-29107`).

**The `nbio` filter's court arm was a function of a draw, and the differential court could not see
it.** D418 landed `BIO_f_nbio_test` and the phase-4 court `RT-BIO-FILTER` found two defects in the new
arm, both the same class: `BIO_ctrl(BIO_CTRL_INFO)` printed `written - read` where **both** are draws
(a differential residual), and `BIO_should_read`/`_write` on their own *are* the draw's outcome, so
the transcript varied between `-O0` and `-O1` of the same source. `probe_hygiene` caught the second
(`nbio.read.should_read: -O1='0' -O0='1'`); both are now printed as *relations* to whether the call
answered `-1` (`docs/DECISIONS.md:30074-30083`). It is the same failure mode D320 named for
`blocker_liveness`, one layer down, in a probe rather than a checker.

**The courts found a finding in the provider census, twice.** D417 found that `rt_deflt_row_census` had
listed the seven GCM rows as "Phase 9's … absent from this list rather than listed-and-skipped", and
that `provider_court_coverage.py` was then failing closed on published rows no probe named; D421 found
that `gen_provider_algorithms.py` carried a **single** `CRATE_QUERY_UNIT`/`CRATE_QUERY_PROVIDER` pair —
`deflt_query`, provider `default` — so `base`'s `SEED-SRC` row was `unimplemented` **by construction
however the crate was shaped** (`docs/DECISIONS.md:30252-30258`). The reader that D417 caught dropping
rows silently was, here, reading the wrong provider silently. Wiring the second reader surfaced two
more defects of the same class: a query arm documented with a `//` comment went unread, and a row
spelling `algorithm_names` through a module const could not be read
(`docs/DECISIONS.md:30260-30273`).

**And the plan reconciler was answering a smaller question than it was asked.** D420 reports that
making phase 9 `complete`-eligible turned on `plan_reconciliation.py`'s checks for a complete stratum
for the first time, and it reported **16 findings — three real and thirteen the machinery's**. The
machinery's were structural: `internal-symbols.json` keys a translation unit by the object name its
build gives it, while a plan names the source path, so `drbg.c` and every `.c.in` looked unreached —
and only for the units a *named build goal* compiles, a subset no other tool could see either
(`docs/DECISIONS.md:30177-30206`). This is D396's and D417's class for the third time in the stratum.

**One cross-stratum measurement, recorded rather than described as equivalent.** Landing the
`DES3-WRAP` row surfaced that the crate has **no** `ossl_tdes_newctx`, `ossl_tdes_dupctx`, `tdes_init`,
`ossl_tdes_einit` or `ossl_tdes_dinit`; the eleven TDES rows publish
`ossl_cipher_generic_einit`/`_dinit` in their place, and the two init bodies are **not equivalent**.
D418 measured **three** deltas — an `EVP_CIPH_ECB_MODE` guard present in one and not the other, an
`updated` reset present in one and not the other, and a raise at a different coordinate — and deltas
one and two sit behind arms no court drives (`docs/DECISIONS.md:30085-30103`). §6 records it as
unclaimed.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an uninitialised field, or **aborts**, the court
does not call it and `docs/SECURITY_DIVERGENCE_POLICY.md` records the divergence with the phase or
condition that would make the behaviour reachable, so the record retires with that phase rather than
with a re-reading of this document. **The register carries no entry whose subject code is a
`crypto/rand/` unit**; the two entries that touch this stratum are these, and both are stated as the
register currently reads rather than as this seal would prefer them to read:

- **`D-GF2M-1`** (`docs/SECURITY_DIVERGENCE_POLICY.md:385-406`) — `BN_GF2m_mod_inv` returns the right
  value without the authority's blinding, and it is a Phase 5 divergence whose **close-obligation is
  this stratum's**: `OBL-GF2M-INV-BLINDING`, "owned by Phase 9, and it closes by adding the blinding
  when RAND exists" (`docs/SECURITY_DIVERGENCE_POLICY.md:405-406`). The registered reason is that
  "`BN_priv_rand_ex` is Phase 9 and does not exist" (`docs/SECURITY_DIVERGENCE_POLICY.md:398`), and
  that callee **now exists** — D314 landed `BN_priv_rand_ex` — but the blinding is **not** added:
  `src/bn/gf2m.rs:25-28` still reads "RAND is Phase 9", and `BN_GF2m_mod_inv` (`src/bn/gf2m.rs:607-639`)
  computes the inverse by extended Euclid with no blinding factor. The value is identical, the timing
  claim is removed, and the boundary therefore **stands**. This seal records it rather than claiming
  its retirement: the register's reason is now historical, and the obligation is prose rather than a
  machine-checked row.
- **`D-CBCHMAC-MULTIBLOCK-ENC-1`** (`docs/SECURITY_DIVERGENCE_POLICY.md:1245-1271`) — the
  `OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC` parameter is answered 0, because its IVs come from the
  random layer. Its **trigger is this stratum**: "Phase 9's first commit that lands `crypto/rand/`. At
  that point `tls1_multiblock_encrypt` is written … and the entry is removed with the arm's green"
  (`docs/SECURITY_DIVERGENCE_POLICY.md:1269-1271`). The first commit landed at D313, and the register
  still carries the entry; `courts/phase8/rt_cipher_probe.c`'s `rt_cbchmac_records` drives
  `..._ENC_LEN` and the AAD and max-buffer-size parameters (`courts/phase8/rt_cipher_probe.c:4062`)
  but **not** the multiblock encrypt parameter, so the arm the trigger names has not been added. The
  boundary stands and the trigger is unexecuted.

**Observation counts quoted inside older decision and divergence entries are the values current when
those entries were written** and are not this document's counts. `docs/SEAL-CENSUS.md` and
`artifacts/phase9/COURTS.json` are authoritative; a stale count inside a historical record is a stale
sentence, not a missing court. (`docs/DECISIONS.md:30110-30111` cites `RT-BN-RAND` at "467" and
`RT-RAND-USERS` at "61"; neither matches §3, and neither is meant to.)

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; `forensics/STATUS.md:294-301`
   carries the current non-claims. No symbol here is `PARITY_VERIFIED`.
2. **Nothing here is a parity claim about entropy.** The entropy pool's source on the host is
   environmental (`getrandom(2)`, `/dev/urandom`), and a court that compared pool *contents* across two
   builds would be comparing two machines (`docs/PHASE-9-SUBPHASES.md:99-101`). A passing `RT-*` court
   here establishes differential compatibility for the behaviours its probe exercises and **not** that
   either side's output is unpredictable, which is a property of the seeding pool rather than of a
   transcript (`docs/PHASE-9-SUBPHASES.md:88-97`, `artifacts/phase9/COURTS.json:6`).
3. **`CT-DRBG` is a pending court, not a passing one.** It is recorded with its corpus and the
   subphase that brings it: "9.4 — the DRBGs' construction vectors, which the pinned tree already
   carries: `test/recipes/30-test_evp_data/evprand.txt` mirror the NIST CAVP `drbgtestvectors.zip`
   sets … and `evpkdf_hmac_drbg.txt` carries the HMAC-DRBG KDF cases"
   (`artifacts/phase9/COURTS.json:77-79`, `forensics/tools/phase9_courts.py:137-143`). It is printed on
   every run so that "not run yet" cannot be read as "passed".
4. **`CT-BN-RAND` is a court the runner did not carry, and D423 registers it as pending.**
   `docs/PHASE-9-SUBPHASES.md:62` lists `CT-BN-RAND` beside `RT-BN-RAND` as row 9.1's courts, and
   `forensics/tools/phase9_courts.py`'s registered `COURTS`
   (`forensics/tools/phase9_courts.py:127-132`) and its `PENDING_COURTS` (`:137-143`) each omitted it
   — a gap in the instrument rather than a court nobody ran, which D421 named and D423 closes by
   adding the name and its corpus to `PENDING_COURTS`, so it is now printed on every run and "not
   run yet" cannot be read as "passed". **The corpus is identifiable and named there**:
   `crypto/bn/bn_rand.c`'s exports are draws, so a construction court needs a *fixed* seed, and the
   path is `test_rng.c.in`'s — `test_rng_set_ctx_params` accepts an `entropy` octet string and, with
   `generate` unset, `test_rng_generate` returns exactly those bytes in order (`test_rng.c.in:88-105`)
   — but driving it means `RAND_set_seed_source_type` and the seed-source context, and that driver is
   owed rather than written. What the court would close is `BN_rand`'s exact output under a committed
   seed; what it would not is anything `RT-BN-RAND`'s postconditions already cover.
5. **`BIO_f_reliable`'s write path is owed to Phase 13.** `sig_out` fills the record's digest half with
   `RAND_bytes`, and with a provider digest the authority reaches `memcpy(buf, NULL, 32)` on the first
   `BIO_write` — its own live `FIXME` (`docs/DECISIONS.md:20609-20630`). The filter needs a **legacy**
   `EVP_MD`, and those statics are Phase 13's; so the framing path is "owed rather than measurable",
   and the `RT-RAND-USERS` transcript carries `BIO_f_reliable.write_path=NOT_MEASURED_LEGACY_EVP_MD_IS_PHASE_13`
   so that "not run" cannot be read as "passed"
   (`docs/DECISIONS.md:20632-20639`, `courts/phase9/rt_rand_users_probe.c:425`).
6. **The TDES init pair substitution, and its three measured deltas.** Eleven TDES rows publish
   `ossl_cipher_generic_einit`/`_dinit` where the authority publishes `tdes_init`'s pair, and the two
   init bodies are not equivalent; deltas one and two sit behind arms no court drives
   (`docs/DECISIONS.md:30085-30103`). This is unclaimed in either direction, and the fix is a separate
   pass.
7. **The base provider's three unlanded operation ids.** `base_encoder[]` (241 rows),
   `base_decoder[]` (76) and `base_store[]` (1) are deliberately not transcribed — **318 rows that are
   `owning_phase: 10` and `unimplemented`** in `forensics/atlas/provider-algorithms.json`; `base_query`
   therefore answers NULL for `OSSL_OP_ENCODER`, `OSSL_OP_DECODER` and `OSSL_OP_STORE`, which is the
   authority's own answer for an operation a provider does not handle
   (`docs/DECISIONS.md:30240-30246`; the tables are at
   `forensics/atlas/provider-algorithms.json:446-474`).
8. **Nothing about a build profile or platform other than the admitted one.** Linux x86-64 only; the
   front's `struct stat`, `__NR_getrandom` and `fd_set` are ABI facts a wrong layout would make a
   memory-safety defect rather than a wrong answer (D301, D302).
9. **Nothing covered by an FRF receipt, challenge, claim or Gemel checkpoint, because there are none
   for this stratum.** §8 states this with the file that makes it a convention.
10. **Every count is `docs/SEAL-CENSUS.md`'s.** This document types none, except §3's per-court table,
    which names the file it was read from.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:38-55`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-9-SUBPHASES.md:143-158`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); every provider row it publishes is named by a probe of a court that covers it
(D245) — and its §4.4 precondition (D295, which landed the derived provider projection before this
stratum was activated). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase9-obligations.json`: `open_in_this_stratum` 0 and `deferred_to_later_phase` 0; the generator `forensics/tools/phase9_obligations.py` fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a differential court | `forensics/atlas/court-coverage.json` phase-9 block; `unmatched` 0, enforced for `complete` by `forensics/tools/phase_state.py` |
| every provider row the plan gives this stratum is implemented | `forensics/phase-state.json:450-453` reads `implemented` 15 of `owned` 15; `forensics/atlas/provider-algorithms.json:86` reads `open["9"]` 0 |
| no authority fault is reproduced | §5, and `docs/SECURITY_DIVERGENCE_POLICY.md`'s register |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty (`:1181`), `implemented_by_two_strata` empty (`:998`) |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 (`:11`) |
| the dispatch plane clean | `forensics/atlas/dispatch-court.json`: `problems` 0 (`:18`) |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty (`:501`) |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty (`:29`); D420 is the change that got it there |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json:612` |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is the
authority's own list (`docs/RELEASE_GATES.md:38-55`); the second says what this stratum's evidence
for it is, and, where an item is **not met**, says so plainly rather than leaving the row empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json` pins `openssl-3.6.4-production`; `artifacts/phase9/COURTS.json:5` names it |
| 2 | obligation inventory | `forensics/phase9-obligations.json` (`:5-12`), and, for the provider rows, `forensics/atlas/provider-algorithms.json` |
| 3 | court manifests | `artifacts/phase9/COURTS.json` |
| 4 | raw captures | **met in the court venue, not in the FRF venue.** The four staged `artifacts/phase9/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (`artifacts/phase9/COURTS.json:19-22`). `.frf/captures/` carries **no** Phase 9 capture, because the stratum has no FRF declaration (§8) |
| 5 | residual set | **met in the court venue, not in the FRF venue.** Every court's `residual_count` is 0 and every `residuals` list is empty (`artifacts/phase9/COURTS.json:7-75`). `.frf/residuals/` carries **no** Phase 9 record, for the same reason as item 4 |
| 6 | mutation / sensitivity evidence | **not met.** There is no `.frf/challenges/` record for this stratum, because no Phase 9 court is declared (§8) |
| 7 | resolution runs | **not applicable, and therefore not met.** No `fixed` disposition attaches to this stratum: the FRF venue has no residual to dispose, and §5's two register boundaries are Phase 5's and Phase 8's records rather than this stratum's chain residuals. `--resolution-run` is required only for `fixed`, and `fixed` requires a *changed* candidate artifact |
| 8 | FRF receipts | **not met.** No `.frf/receipts/` record names a Phase 9 court (§8); every receipt on disk belongs to an earlier stratum |
| 9 | generated parity projection | `forensics/STATUS.md` (`:221-238`), rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **not met.** `forensics/GEMEL_TRAJECTORY.md`'s `current:` is Phase 8's `C76` (`:157`); no Phase 9 checkpoint exists (§8) |

**What "not met" here means, precisely.** Items 4, 6, 7, 8 and 10 are the **FRF chain** items, and
this stratum has not entered the chain. That is the one place this `complete` is weaker than Phase 8's,
and it is not a weakness of the four courts: those courts ran, passed, and are re-derived by the
pipeline. It is the state a stratum is in **between** reaching `complete` and joining the chain, and
D413 records it is a state this project does not seal in: "this entry does not seal first and declare
later" (`docs/DECISIONS.md:29716-29720`).

## 8. FRF and Gemel

Phase 8's chain entry shows what one requires, and D413 fixes it: fifteen `(id, phase, probe,
description)` rows added to `forensics/tools/gen_frf_courts.py`'s `COURTS` table — one per **differential**
court, each naming the `artifacts/phase8/probes/<probe>.{authority,candidate}` pair the court stages
and the `courts/phase8/<probe>.c` it was compiled from — then the store **added to** rather than
recreated, producing one receipt and two challenge records per court, a compiled `sensitivity-backed`
claim, and a Gemel checkpoint (`docs/DECISIONS.md:29722-29732`, `29744-29755`, `29810-29818`). D413 is
also explicit that the vector-driven `CT-*` courts **cannot** be declared, because such a court has no
authority transcript to diff and no fixture a challenge could locate (`docs/DECISIONS.md:29734-29742`).

**Phase 9's chain entry does not exist yet, and the honest statement of that is that nothing here was
found, because nothing here was looked for.** The evidence for each clause:

- **No declarations.** `forensics/frf/courts/` contains no `openssl-rs-rt-rand`,
  `openssl-rs-rt-drbg`, `openssl-rs-rt-bn-rand` or `openssl-rs-rt-rand-users`; the only RAND-shaped
  directory is `openssl-rs-rt-evp-rand`, which is **Phase 7's** `EVP_RAND` framework court. A grep of
  `forensics/frf/` for `phase9`, `rt-rand`, `rt-drbg`, `rt-bn-rand` and `rand-drbg` returns nothing.
- **No Phase 9 objects in `.frf/`.** A grep of the whole store for those names returns three
  `sha256`-addressed objects, and all three are **Phase 7's**: `.frf/objects/sha256/8622403b…` is the
  `RT-EVP-RAND` probe source, and the other two are its compiled binaries. `.frf/`'s receipts (82),
  challenges (164), captures (246) and residuals carry no Phase 9 run.
- **No Gemel checkpoint.** `forensics/GEMEL_TRAJECTORY.md`'s head is `C76`/`K47`, which is Phase 8's
  disposition and corrected claim (`forensics/GEMEL_TRAJECTORY.md:13`), and its `current:` is the same
  change's state (`forensics/GEMEL_TRAJECTORY.md:157`). There is no `C77`/`K48`.

**What the seal does *not* do is invent the entry.** The declarations, the receipts, the challenges,
the claim and the checkpoint are produced by running the chain in the FRF tooling container, never on
the host, and none of them exists to cite. §6's items and §7's items 4, 6, 7, 8 and 10 are the
coordinates of the gap, and the two "not met" readings that matter — `CT-DRBG` (a court the plan gives
this stratum that has not landed) and `CT-BN-RAND` (a court the runner did not carry, registered
pending by D423) — travel with them.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase9-obligations.json`'s
`deferred` list is empty (`:13`) and its `deferred_by_phase` is empty (`:14`), and the census reads
`deferred to a later stratum with a stated reason: 0` (`docs/SEAL-CENSUS.md:311`). Every export this
stratum owns is implemented, and the 44 it *received* are discharged rather than passed on. The
`handed_on` figure in the provider census — `forensics/phase-state.json:451` reads 675, and
`forensics/atlas/provider-algorithms.json:80` reads `handed_on["9"]` 675 — is provider *registration*
rows the plan gives later strata, not exports this stratum left unwritten; the projection derives it
from `owning_phase` rather than storing it (D295).

**The immediate next actions this seal's own findings point at**, recorded so they are not lost:

- **`CT-DRBG` and `CT-BN-RAND`.** Both are pending courts now: the first's corpus already ships in
  the pinned tree (§6.3), and the second's is `test_rng.c.in`'s committed `entropy` path (§6.4), which
  D423 registers and names. Each needs its driver written.
- **`BIO_f_reliable`'s write path** retires when Phase 13 lands `EVP_sha256()`'s family (§6.5).
- **The TDES init pair** needs the five `cipher_tdes_common.c` bodies, which are in no ledger and no
  atlas because they are declared in the uninstalled `prov/implementations.h` (§6.6).
- **The `base` provider's 318 encoder, decoder and store rows** become real when Phase 10 lands them
  (§6.7).
- **`D-GF2M-1`'s obligation** stands with the register's reason now historical: `BN_priv_rand_ex`
  exists, so the blinding could be added, and the boundary would retire with it (§5).
- **`D-CBCHMAC-MULTIBLOCK-ENC-1`'s trigger** fired at D313 and its entry and arm are still owed (§5).
- **This stratum's FRF chain entry** is §8's subject: four declarations, and the receipts, challenges,
  claim and checkpoint they produce.
- **`forensics/phase9-obligations.json` is the place a reader should look before believing any figure
  in this document**, because this document deliberately types none outside §3.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 5 seal's §9 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced.

1. **The plan's §1 working set is a historical measurement, and the seal states the drift rather than
   the number.** `docs/PHASE-9-SUBPHASES.md:29-46` reads 95 exports (25 owned plus 70 handed);
   `docs/SEAL-CENSUS.md:37` and `forensics/phase9-obligations.json:5-12` read 69 (25 owned plus 44
   received). The plan flags its own figure as "the measurement this plan made, and not a current
   reading" (`docs/PHASE-9-SUBPHASES.md:21-23`) and names D296, D323 and D324 as the decisions that
   moved it. No number is restated here: the census is where this arithmetic lives.

2. **Plan row 9.2 says three front exports are withheld; D312 decided otherwise and they are
   implemented.** `docs/PHASE-9-SUBPHASES.md:63` reads that `RAND_get_rand_method`,
   `RAND_set_rand_method` and `RAND_set_rand_engine` "are withheld rather than partially written".
   D312 decided they "**will be written with the no-engine reduction, not withheld**" — this crate
   exports no `ENGINE_add`/`ENGINE_by_id`/`ENGINE_new`, so no `ENGINE *` can be constructed and every
   reachable argument is NULL (`docs/DECISIONS.md:20259-20268`) — and D313 landed them. The ledger's
   `implemented` list carries all three (`forensics/phase9-obligations.json:418,430-431`), so the plan
   row is stale and the ledger is authoritative for the present.

3. **D287's table named a file that does not exist and misread the base provider's RAND row.** D287
   named `providers/implementations/rands/crngt.c` as 9.5's unit; it does not exist in 3.6.4, and the
   continuous test is `fips_crng_test.c.in` (`docs/DECISIONS.md:19268-19273`). D287 also said the
   `base` provider's single RAND row is the test RNG; `baseprov.c`'s `base_rands[]` publishes
   **SEED-SRC**, and TEST-RAND is `defltprov.c`'s (`docs/DECISIONS.md:19274-19278`). The plan carries
   both corrections in prose (`docs/PHASE-9-SUBPHASES.md:105-118`) and the second is now in the
   machine-readable plan as well (D420, `docs/DECISIONS.md:30216-30219`).

4. **The provider census reader was reading the wrong provider, and dropping rows in silence.**
   `gen_provider_algorithms.py` carried one `CRATE_QUERY_UNIT`/`CRATE_QUERY_PROVIDER` pair, so a row
   the `base` provider publishes could never be read as implemented however the crate was shaped
   (D421); the same reader had already been caught by D417 listing the seven GCM rows as absent rather
   than listed-and-skipped. Both are corrected, and the checks that should have existed — a reader
   that recognises no arm is fatal, not an empty table — are the D421 finding
   (`docs/DECISIONS.md:30252-30273`).

5. **The plan reconciler keyed units by build-object name and missed every `.c.in`.** D420's sixteen
   findings were three real (three symbols built under non-authority constant names, one stale
   deferral) and thirteen the machinery's: a plan names a source path and `internal-symbols.json`
   keys a translation unit by the object name its build gives it, so a unit the crate demonstrably
   reaches was reported unreached — and only for the units a named build goal compiles, a subset no
   other tool could see (`docs/DECISIONS.md:30177-30206`). The `.in` spelling is load-bearing here
   rather than cosmetic (`docs/PHASE-9-SUBPHASES.md:66`).

6. **`CT-BN-RAND` was absent from the runner's sets, and D423 registers it as pending.** Named by
   `docs/PHASE-9-SUBPHASES.md:62`, omitted from both `forensics/tools/phase9_courts.py:127-132` and
   `:137-143` until D423; D421 is the decision that named it as a runner gap rather than a court nobody
   ran (`docs/DECISIONS.md:30285-30287`). §6.4 and §9 record it.

7. **Observation counts inside older decision entries are historical.** §5's closing note. They are
   not restated, they are not corrected in place, and they are not this document's counts.
