# PFP8-WIDTH-POLICY — the DH ladder's iteration count

**Item:** the `PFP8-WIDTH-POLICY` obligation recorded by the PFP-8 refusal
(`RECEIPT.md` §9, `BOUND.md` §5).
**Claim class:** `SCOPED_OBSERVATION` — one court venue, no PMU; the timings are
paired per-repetition ratios with a percentile bootstrap, not a frontier result.
**Source `S`:** `staging` `20b655ba902e61d7680e30dfcb30feb4225397cc` plus the
working-tree change to `src/bn/arith.rs`, `src/bn/mont.rs`, `src/dh/key.rs`
(`width-policy/build/source.env` records each file's SHA-256 and the tree
fingerprint `b83a9516a369f19130b320a0f3944418d2b2d8f3ac45493c9b11e0112c0e67c4`).
**Candidate DSO:** `6302e05a14e47b74bd546f03e7509e234a2884511ddec5c3f9a7f4382bd9a25b`
(archive `72c27b70e77e58c99e3d84bf7c0397b44b2d8e44fb1b18c3666934918cef4e6d`).
Two fresh `CARGO_TARGET_DIR` builds agree byte for byte
(`build/variants.txt`).
**Previous build:** `88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87`
(the PFP-8/M-A1 artefact: the same source without this change).
**Authority:** OpenSSL 3.6.4 production DSO
`611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`,
source `forensics/authorities/src/openssl-3.6.4`.

---

## 1. Where the iteration count came from before

The ladder runs `64 · width` iterations, and `width` was the **modulus** limb
count:

* `src/bn/mont.rs` (before this change) passed `md.len()` into the ladder:
  `mod_exp_core_consttime_from_parts_prepared(&ad, pd, &md, md.len(), …)`.
* `src/bn/arith.rs:2279` computed `let width = declared_limbs.max(md.len()).max(1);`
  so a caller could widen the ladder but never narrow it below the modulus.
* `src/bn/arith.rs:2551` is the loop bound: `let bits = width.checked_mul(64)?;`.

For `ffdhe2048` that is **2,048** iterations for a 225-bit private exponent. The
authority runs the exponent's own limb width, `bits = p->top * BN_BITS2`
(`bn_exp.c:637`; the comment at `:634-635` explains the choice: "Use all bits
stored in |p|, rather than |BN_num_bits|, so we do not leak whether the top bits
are zero"), i.e. **256** for the same key. That 8× iteration difference is the
14.82× key-generation ratio and the 14.04× shared-secret ratio PFP-8 measured.

## 2. What the authority actually uses, per group

Two public values decide a DH private key's length in the authority:

1. **`dh->length`** — the caller's explicit bound (`DH_set_length(dh, n)`, also
   decoded from a PKCS#3 `recommended-private-length`). For the named-group path
   `dh_key.c:320` passes it straight to `ossl_ffc_generate_private_key`.
2. **`params->keylength`** — the named group's RFC 7919 key length, assigned by
   `ossl_ffc_named_group_set` (`ffc_dh.c:169`) and applied when `N == 0`
   (`ffc_key_generate.c:31-32`).

`ffc_dh.c:63-90` is the authority's table; the crate mirrors it byte for byte in
`src/ffc/dh.rs`. The width the *ladder* may run is `ceil(N / 64)` limbs:

| group | authority `keylength` | policy limbs | ladder bits | modulus bits |
|---|---:|---:|---:|---:|
| ffdhe2048 | 225 | 4 | 256 | 2,048 |
| ffdhe3072 | 275 | 5 | 320 | 3,072 |
| ffdhe4096 | 325 | 6 | 384 | 4,096 |
| ffdhe6144 | 375 | 6 | 384 | 6,144 |
| ffdhe8192 | 400 | 7 | 448 | 8,192 |
| modp1536 | 200 | 4 | 256 | 1,536 |
| modp2048 | 225 | 4 | 256 | 2,048 |
| modp3072 | 275 | 5 | 320 | 3,072 |
| modp4096 | 325 | 6 | 384 | 4,096 |
| modp6144 | 375 | 6 | 384 | 6,144 |
| modp8192 | 400 | 7 | 448 | 8,192 |
| dh_1024_160 / dh_2048_224 / dh_2048_256 (RFC 5114) | 0 | — | modulus width | 1,024 / 2,048 |

Measured, not only read (`raw/keylengths.json`, `measure_keylengths_wp.py`, bound
to candidate `6302e05a…` and authority `611e511d…`): eight real `DH_generate_key`
calls per group per library reach **exactly** the table's key length and exactly
its limb count, for **both** libraries — 22 rows, all `max_bits == keylength` and
`max_limbs == ceil(keylength/64)`. The TLS DHE
requirement this reflects is RFC 7919 §5.1's "private key size" column for the
FFDHE groups (225/257/305/353/401): the authority's table records
225/275/325/375/400, and the numbers the authority's own generation uses are the
ones this policy follows. The RFC 5114 groups carry `keylength = 0`, so they have
**no policy width** and keep the modulus-width ladder unchanged.

## 3. What the iteration count may depend on without leaking

The admissible value is the **declared/policy width** `N` — `dh->length` if the
caller set one, else the named group's `keylength`. Both are object
configuration: they are written by `DH_set_length`, `DH_new_by_nid` and parameter
decoding, never computed from a private exponent.

The following are **not** admitted: the exponent's actual bit length, its
normalised limb count, its leading zeros or its value. The crate's own policy is
therefore **stricter** than the authority's, which derives `bits` from `p->top`
and thus exposes the exponent's limb count at 64-bit granularity.

If the only width available had been the exponent's own length, this item would
have stopped here. It was not: `dh->length`/`keylength` supply a public bound.

## 4. Implementation, and why the count is constant

* `src/dh/key.rs` — `dh_policy_limbs(dh)` reads `dh->length` when positive, else
  `params.keylength`, and answers `ceil(bits / 64)`; `0` means "no declared
  bound". `dh_bn_mod_exp` passes that to the ladder. Reading `dh->length` does
  not change it, and no validation, blinding, subgroup or peer check moves.
* `src/bn/mont.rs` — `bn_mod_exp_mont_impl` gained one optional argument; the
  constant-time arm calls `mod_exp_core_consttime_policy` when it is present and
  the previous `…from_parts_prepared(…, md.len(), …)` when it is not. The
  variable-time arm, the prepared-context validation, the even-modulus refusal
  and the result store are untouched. `BN_mod_exp_mont_consttime` keeps the
  modulus width.
* `src/bn/arith.rs:2463` — `mod_exp_core_consttime_policy`: clamp the policy to
  the modulus limb count (public), then stage the exponent into exactly
  `width = 64 · ceil(N/64)` limbs and run the same windowed ladder.

**Constancy argument.** For one object and configuration the schedule is
`width = 64 · ceil(N/64)` with `N` fixed by §3. From `width` alone the ladder
computes `windows = ceil(width / 5)`, `windows · 5` squarings, `windows`
multiplications, `2^5` table rows and one conversion — no term depends on the
exponent. The exponent is copied into a buffer whose allocation and write count
are `width` (the staging loop writes every limb, with an all-ones/all-zeros
presence mask), and every index inside the ladder is `i >> 6`, `i & 63` or
`window_start`, all public. Two exponents of different values, or different bit
lengths, therefore perform the identical instruction schedule and the identical
sequence of memory addresses. The residual `pd.get(i)` presence test inside the
staging copy is the one already documented at `arith.rs:1610-1618` and reported
by ctgrind under length taint; its loop bound is the public width.

**The one admission.** If the supplied exponent is *wider* than the policy
(`pd.len() > ceil(N/64)`), the function runs
`mod_exp_core_consttime_from_parts_prepared(…, md.len(), …)` — byte for byte the
previous behaviour, including its refusal of an exponent wider than the modulus.
That branch can only be taken by a caller who supplied a private key outside the
object's own declared bound; the crate's key generation cannot produce one
(`ossl_ffc_generate_private_key` bounds `N` by `dh->length`/`keylength`, and
§2's measurement confirms the generated width). It is the same class of
admission read of `pd.len()` that `ladder_geometry` already documents, and it is
recorded here rather than hidden.

**Fallback for groups without a policy width.** `keylength == 0` and
`dh->length == 0` (the RFC 5114 groups, or an unnamed group) give
`dh_policy_limbs == 0`, and `mod_exp_core_consttime_policy` returns exactly
`mod_exp_core_consttime_from_parts_prepared(…, md.len(), …)`. Nothing changes
there; the group's own `q`-based generation length (up to 2,047 bits) is within
one limb of the modulus anyway.

## 5. Correctness — every group, both directions

`raw/differential.json` (driver `courts/performance-frontier/pfp8/differential_wp.py`,
harness `bench_pfp8.c`), candidate `6302e05a` vs authority `611e511d`:

| population | comparisons | mismatches |
|---|---:|---:|
| shared secret, 222-bit exponent, 11 prepared groups | 11 | 0 |
| `g^priv` for the same exponent (the keygen exponentiation), 11 groups | 11 | 0 |
| shared secret, 2,039-bit exponent (policy fallback), 10 groups ≥ 2048 | 10 | 0 |
| key generation: shape of each library's own pair, 11 groups × 2 | 22 | 0 |
| key generation: each pair recomputed by **both** libraries as `g^priv` | 22 | 0 |
| named vs explicitly-loaded construction, 3 fixtures × 2 exponents | 6 | 0 |
| **subtotal** | **103** | **0** |
| malformed-peer return codes (7 values × 3 fixtures) | 21 | 0 |
| keygen with a caller-supplied private key | 3 | **known STOP** |

The 22 `g^priv` rows are the task's "public key equals the authority's for the
same private exponent": one library's generated private key is exponentiated by
**both** libraries and the three values (generated public key, candidate
`2^priv`, authority `2^priv`) are equal byte for byte. All 44 generation/replay
rows (22 keys × 2) pass, so a shorter ladder produced the identical result, not
an approximation, on both sides of the policy boundary.

The 21 malformed-peer codes are the PFP-8 record, unchanged: `0` and `1` refused
with `0`; `p−2`, `p−1`, `p`, `p+1` refused with `−1`; `2` accepted — identical
in all 21 cases. No validation, subgroup or error path was modified.

`PFP8-KEYGEN-PRESET-PRIV` is **not** closed by this batch: `DH_generate_key` on
a caller-supplied private key still returns 0 with no public key (candidate
`rc=1`, authority `rc=0` and a 256/384/512-byte public key for
ffdhe2048/3072/4096). It is a separate divergence in `src/dh/key.rs`'s
`'generate` block.

## 6. Timing, measured at one digest

Method: `bench_pfp8_wp`, one process per arm per workload per repetition, arm
order alternated, `taskset -c 1`, 15 repetitions, 10 calls per process; median of
paired per-repetition ratios with a 95 % percentile bootstrap (20,000 resamples,
seed `0x50465038`). Raw: `timing/raw/`, `timing/results.json`.

| workload | cand µs | prev µs | auth µs | cand/auth | prev/auth | cand/prev |
|---|---:|---:|---:|---|---|---|
| keygen `ffdhe2048` | 467.5 | 2,613.5 | 177.8 | **2.6323× [2.6025, 2.6924]** | 14.6981× [14.4153, 15.9613] | 0.1805 [0.1747, 0.1827] |
| keygen `ffdhe3072` | 1,234.3 | 8,871.0 | 450.7 | **2.7026× [2.6895, 2.7477]** | 19.6217× [19.5326, 19.8451] | 0.1378 [0.1374, 0.1402] |
| shared secret, 222-bit exp, `ffdhe2048` | 344.0 | 2,446.3 | 174.4 | **1.9651× [1.9279, 1.9787]** | 13.9578× [13.7561, 14.3393] | 0.1390 [0.1374, 0.1426] |
| shared secret, 2,039-bit exp (fallback) | 2,455.9 | 2,419.2 | 1,220.6 | 2.0130× [1.9840, 2.0465] | 1.9800× [1.9585, 2.0167] | 1.0163 [0.9982, 1.0268] |
| shared secret, 275-bit exp, `ffdhe3072` | 953.5 | 8,623.3 | 450.7 | **2.1017× [2.0914, 2.2136]** | 19.3054× [19.1428, 19.4593] | 0.1108 [0.1095, 0.1137] |

Against the two recorded ratios: key generation was **14.8226×** and is now
**2.6323×** (the previous build's ratio at this digest is
14.6981× [14.4153, 15.9613], and the recorded 14.8226× lies **inside** that
interval); the 2048-bit-exponent shared secret was **1.9876×** and is now
**2.0130×**, unchanged, because that workload's exponent is outside the declared
bound and takes §4's fallback (cand/prev 1.0163 [0.9982, 1.0268], whose interval
contains unity); the recorded 1.9876× lies inside this run's previous-build
interval 1.9800× [1.9585, 2.0167]. The
225-bit-exponent shared secret — the real group policy — moves from **13.97×** to
**1.9651×**. (The `PRIV225` operand is 222 bits, inside the group's 225-bit
bound; the ladder runs the bound's 4 limbs either way.)

### Was the predicted ~8× realised?

The iteration ratio is **8.00** for 2048→256 and **9.60** for 3072→320.

| workload | width ratio | ir bound (Amdahl) | measured cand/prev | speed-up |
|---|---:|---:|---:|---:|
| shared secret, 222-bit exp | 8.00 | 6.8× | 0.1390 | **7.19×** |
| shared secret, 275-bit exp (3072) | 9.60 | 8.9× | 0.1108 | **9.03×** |
| keygen `ffdhe2048` | 8.00 | 3.75× | 0.1805 | **5.54×** |
| keygen `ffdhe3072` | 9.60 | 5.2× | 0.1378 | **7.26×** |
| shared secret, 2,039-bit exp | 1.00 | 1.0× | 1.0163 | 0.98× (no change) |

The ~8× was realised where the exponentiation dominates: **7.19×** for the
2048-bit shared secret and **9.03×** for the 3072-bit one. Key generation is
**5.54×**, not 8×, because 14.8 % of its instruction count (the fresh
`BN_MONT_CTX_set`, the rejection-sampling RNG loop, object allocation) is outside
the exponentiation and does not shrink — the Amdahl prediction is 3.75×, so the
measurement is *better* than the instruction-count model, which is exactly as far
as that model can be trusted. The 2039-bit-exponent row is deliberately
unchanged: the policy must not truncate an exponent the caller supplied.

## 7. Taint

`ctgrind` (valgrind memcheck) on a debug test binary, `CARGO_PROFILE_TEST_DEBUG=0`,
`ctgrind/meta.txt` names the test-binary digest. The exponent's limb bytes are
marked undefined; the modulus and the lengths stay defined.

| case | test | errors | contexts | origins |
|---|---|---:|---:|---|
| policy taint (new, 8-limb modulus, 4-limb policy → 256 iterations) | `ctgrind_secret_exponent_policy_width` | **0** | **0** | none (`ctgrind/origins.txt`) |
| policy control (`CTGRIND_POLICY_CONTROL=1`) | same test | 4 | 1 | the deliberate branch on a marked limb |
| modulus-width taint (unchanged path) | `ctgrind_secret_exponent_window` | **0** | **0** | none |

The shortened schedule introduces **no** secret-dependent iteration and **no**
secret-derived transfer: with a shorter width the only thing that changed is the
public loop bound. This is a source-bound instrument over one code path, not a
constant-time proof.

## 8. Branch audit at `6302e05a`

Every `jcc`/`setcc`/`cmovcc` in the four carriers this change reaches, classified
by `courts/performance-frontier/pfp8/classify_wp.py` with a per-address allowlist
(`audit/public-arith.json`, each entry carrying its reason). A `jcc` from an
unlisted arithmetic flag source, a `jcc` from a secret bit, a class-(b) `setcc`
consumed by a control transfer, or an arithmetic-source `cmovcc` aborts the
script; it did not abort. Raw: `audit/raw/disasm/*-classification.{tsv,md}`.

| carrier | jcc | setcc | cmovcc | secret-derived control transfers |
|---|---|---|---|---|
| `mont_mul_ladder_into` (CIOS kernel) | 40 = 39 `cmp`/`test` + 1 geometry | 64 class-b carry/borrow, all consumed arithmetically | 0 | **0** |
| `run_mont_ladder` (window loop + masked scan) | 100 = 84 `cmp`/`test` + 16 reviewed geometry | 18 = 17 `cmp`/`test` + 1 `bt` secret bit consumed **as data** | 2, both `cmp`/`test` | **0** |
| `bn_mod_exp_mont_impl` (the new dispatch) | 61 = 57 `cmp`/`test` + 4 reviewed (INT_MAX, consttime-flag identity, allocation, `context_matches` declassification boundary) | 4 `cmp`/`test` | 3, all `cmp`/`test` | **0** |
| `dh_bn_mod_exp` (reads the public bound) | 3, all `cmp`/`test` | 0 | 0 | **0** |

The kernel's body is instruction-for-instruction the M-A1 one (only relocation
displacements differ; the geometry site moved from `0x2fa80b` to `0x4783ab`,
identical `xor`/`or` of limb-count masks). `run_mont_ladder` was re-classified
from this digest's own listing because its frame grew by `0x20`; the 16 geometry
transfers are the allocation/length/size checks previously reviewed under the
same rules, plus the masked-scan loop over the row's public limb count. The
`context_matches` site is the documented declassification boundary the crate
already tests (`ctgrind_context_matches_declassifies_at_the_equality_decision`).

The audit is a review aid, not a constant-time proof.

## 9. Repository gates

| gate | result |
|---|---|
| `cargo test --lib -- dh` | 79 passed, 0 failed, 2 ignored (5 new tests) |
| full `cargo test --lib` | 2,498 passed, 0 failed, 54 ignored |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| unsafe ops added | 0 new unsafe operations in a safe signature: `dh_policy_limbs` is an `unsafe fn` with a `# Safety` contract, `bn_mod_exp_mont_policy` forwards under `BN_mod_exp_mont`'s contract, and the moved body's unsafe blocks are the existing ones |
| `#[repr(C)]` layouts, exported symbols, `CRYPTO_*` seam | unchanged |

New tests: `policy_width_matches_the_modulus_width_ladder` (every policy from 0
to `md.len()+1` against the modulus-width ladder), 
`policy_width_never_truncates_and_refuses_wider_than_the_modulus`,
`ctgrind_secret_exponent_policy_width`,
`the_policy_width_is_the_groups_declared_key_length`,
`the_policy_width_keygen_equals_the_modulus_width_exponentiation`.

## 10. What this does not establish

* It is not a frontier result: one venue, no PMU, `SCOPED_OBSERVATION`.
* It does not establish constant-time behaviour. ctgrind is source-bound and the
  branch audit is a review aid; neither is a proof under optimisation.
* It does not close `PFP8-KEYGEN-PRESET-PRIV` (a caller-supplied private key is
  still not exponentiated) or `PFP8-REFUSED-TABLE-BUILD`.
* It asserts no `SAFE_COMPATIBLE` graduation.
* The "previous build" comparison is a same-instrument, different-digest
  comparison; the recorded 14.8226×/1.9876× are reproduced within their
  intervals, and no trend across digests is claimed.
