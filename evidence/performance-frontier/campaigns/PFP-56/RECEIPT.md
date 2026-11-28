# PFP-56 — sweep every ladder / `BN_mod_exp_mont*` call site (verdict: one wrong site, fixed)

```yaml
task:            PFP-56
subject:         where does each constant-time schedule get its width
source_identity: HEAD c1a100a8 (branch staging), worktree uncommitted
src_fingerprint: 47b0ee362fa36f538c029325f1a7d40dfd03e2f215f8031b6f8d6e6a3042ff74
candidate_dso:   5b52e4736a7c5bb23f6cf0e3962cfd333ad941a6e62aa7a9033712c0ea50e65c
authority:       forensics/authorities/src/openssl-3.6.4
```

Width vocabulary: **exponent length** = `bit_len(e)` (variable-time core);
**policy metadata** = a declared public bound; **modulus** = `md.len()` limbs.
The ladder's iteration count is exactly `64 * width`; the variable-time core's is
`bit_len(exponent)`.

## 1. RSA verify/encrypt first (the hypothesis under test)

The hypothesis — “a modulus-width ladder runs on a one-limb public exponent in
RSA verify/encrypt” — is **false on this candidate**. In `rsa_ossl_public_encrypt`
(`src/rsa/ossl.rs:929`), `rsa_ossl_public_decrypt` (`:2332`) and the CRT tail
check (`:2880`), neither `e` nor `n` carries `BN_FLG_CONSTTIME`
(`RSA_set0_key` marks only `d`: `src/rsa/object.rs:1024-1031`; `BN_with_flags`
copies instead of flagging its source: `src/bn/bignum.rs:1188-1197`). With no
flagged operand, `bn_mod_exp_mont_impl` takes `mod_exp_core`, whose loop bound is
`bit_len(e) = 17` for `e = 65537`. No ladder is entered.

Proved by `src/rsa/ossl.rs::tests::rsa_public_operations_use_the_public_exponent_bit_length`:
public encrypt and public decrypt both observe `ladder_bits=[]`,
`vartime_bits=[17]`.

## 2. Call-site table

| # | site (file:line) | operation | exponent | width source | correct |
|---|---|---|---|---|---|
| 1 | `src/rsa/ossl.rs:929` | public encrypt `m^e mod n` | `e` public, 1 limb | variable-time: exponent length (17) | yes |
| 2 | `src/rsa/ossl.rs:2332` | public decrypt / verify `s^e mod n` | `e` public, 1 limb | variable-time: exponent length (17) | yes |
| 3 | `src/rsa/ossl.rs:2880` | CRT-result tail verify `r0^e mod n` | `e` public, 1 limb | variable-time: exponent length (17) | yes |
| 4 | `src/bn/blinding.rs:1026` | blinding refresh `A^e mod n` | `e` public, 1 limb | `LadderWidth::PublicExponent` = exponent length (64) | yes (PFP-51) |
| 5 | `src/rsa/sp800.rs:583` | SP800-56B pairwise, `k^e mod n` | `e` public, 1 limb | **was modulus (1024); now `PublicExponent` (64)** | **fixed** |
| 6 | `src/rsa/sp800.rs:591` | SP800-56B pairwise, `(k^e)^d mod n` | `d` secret | modulus (1024) | yes |
| 7 | `src/rsa/ossl.rs:2563` | paired CRT `a^dmp1 mod p`, `a^dmq1 mod q` | `dmp1`,`dmq1` secret | each prime's modulus (512 each) | yes |
| 8 | `src/dh/key.rs:438` | DH `g^x`, `pub^x` | `x` secret | policy metadata, widened by the ingestion-bound length (`max(policy, modulus, stored)`) | yes (PFP-39/43) |
| 9 | `src/dsa/ossl.rs:689` | DSA sign setup `g^k mod p` | `k` secret, fixed-length | modulus `p` (2048) | yes (conservative) |
| 10 | `src/dsa/ossl.rs:1037` | DSA Fermat inverse `k^(q-2) mod q` | `q-2` public, full width | modulus `q` (== exponent length, 256) | yes |
| 11 | `src/dsa/ossl.rs:903` | DSA verify `g^u1 y^u2 mod p` | `u1`,`u2` public | variable-time: each exponent's length | yes |
| 12 | `src/ec/mont.rs:487` | EC field inverse `a^(p-2) mod p` | `p-2` public, full width | modulus/field (== exponent length) | yes |
| 13 | `src/ec/lib.rs:2440` | EC order inverse `x^(order-2) mod order` | `order-2` public, full width | modulus/order (== exponent length) | yes |
| 14 | `src/bn/primes.rs:658` | Miller–Rabin `b^m mod w` | `m` secret, ~modulus width | modulus `w` | yes |
| 15 | `src/ffc/params_generate.rs:258,359` | FFC `h^e / H^e mod p` | `e` public | variable-time: exponent length | yes |
| 16 | `src/ffc/params_validate.rs:111` | FFC `g^q mod p` | `q` public | variable-time: exponent length | yes |
| 17 | `src/ffc/key_validate.rs:153` | FFC public-key `pub^q mod p` | `q` public | variable-time: exponent length | yes |
| 18 | `src/dh/check.rs:331` | DH check `g^q mod p` | `q` public | variable-time: exponent length | yes |
| 19 | `src/pem/pvkfmt.rs:710`, `src/dsa/backend.rs:393`, `src/dsa/key.rs:115` | `g^priv mod p` | private, `BN_FLG_CONSTTIME` | `BN_mod_exp` consttime branch → modulus | yes |
| 20 | `src/bn/arith.rs:1470` | `BN_mod_exp` consttime arm | any flagged | modulus | yes (deliberate: the generic API cannot know `e` is public) |
| 21 | `src/srp/srp_lib.rs:258,270,327,506,571,593`, `src/srp/srp_vfy.rs:1420` | SRP exponentiations | protocol values, unflagged | variable-time: exponent length (authority parity) | yes |

Not in this table because they never reach this ladder: ECDSA/EdDSA verification
(EC scalar multiplication in `src/ec/mult.rs`, not `BN_mod_exp*`);
`BN_mod_exp_mont_word` (refuses a consttime operand; no production caller).

## 3. What was wrong, and what changed

One production site used modulus width for a short **public** exponent:
`src/rsa/sp800.rs:570-571` (now `:583`). The base `k = 2` is marked
`BN_FLG_CONSTTIME` for the later `d` exponentiation, which also routed the
public-`e` step through the modulus-width ladder.

Change: that step now calls `bn_mod_exp_mont_impl(..., LadderWidth::PublicExponent)`
(the arm PFP-51 added for blinding). The `d` step is untouched: secret exponent,
modulus width. No new unsafe function or raw-pointer type; one documented
`unsafe` call to an existing `pub(crate)` entry inside the existing façade.
The Montgomery entry refuses an even modulus, where `BN_mod_exp` would have used
its variable-time fallback; `rsa->n` is odd for every valid RSA key and the
pairwise test runs only on a generated/validated key, so that arm is unreachable
here. Recorded, not hidden.

Deterministic schedule (test `the_pairwise_test_sizes_the_public_exponent_step_from_the_exponent`):
`ladder_bits = [64, 1024]` for a 1024-bit key, i.e. 64 and 1024 iterations.

Measured (test `sp800_pairwise_public_step_before_and_after`, 100 reps each,
same operands, same build; `raw` log `timing-sp800.txt`):

```
PFP56-PAIRWISE-E old_ns=421437832 new_ns=80683275 old_per_op_ns=4214378 new_per_op_ns=806832
```

≈ 4.21 ms → 0.81 ms per public step (~5.2x wall-clock; the ladder itself is 16x
shorter, the remainder is fixed Montgomery setup and allocation).

## 4. Tests pinning the classification (no wall-clock assertions)

| test | site/class | pinned count |
|---|---|---|
| `bn::mont::tests::ladder_width_arms_resolve_to_pinned_iteration_counts` | Modulus / Policy in / Policy out-of-policy / PublicExponent | 2048 / 256 / 2432 / 64 |
| `bn::mont::tests::an_unflagged_public_exponent_uses_the_exponent_bit_length` | unflagged `BN_mod_exp_mont` (all public-only sites) | vartime 17, no ladder |
| `rsa::ossl::tests::rsa_public_operations_use_the_public_exponent_bit_length` | RSA public encrypt + decrypt/verify | vartime 17, no ladder |
| `rsa::ossl::tests::rsa_crt_pair_uses_each_primes_limb_count` | paired CRT | ladder `[512, 512]` |
| `rsa::sp800::tests::the_pairwise_test_sizes_the_public_exponent_step_from_the_exponent` | pairwise e then d | ladder `[64, 1024]` |
| `bn::blinding::tests::create_param_sizes_the_public_exponent_ladder_from_the_exponent` | blinding refresh | ladder `[64]` |
| `dsa::ossl::tests::fermat_inverse_uses_the_group_order_width` | `k^(q-2) mod q` | ladder `[256]` |
| `dsa::ossl::tests::dsa_verify_pair_uses_the_public_exponents_bit_lengths` | `BN_mod_exp2_mont` verify | vartime `[13, 256]`, no ladder |
| `bn::exp::tests::the_ec_inversion_entry_keeps_the_modulus_width` | EC fixed-top inversion entry | ladder `[128]` |
| `dh::key::tests::a_conforming_dh_private_key_runs_the_policy_width` | DH compute | ladder `[256]` |
| `dh::key::tests::mutating_the_exponent_after_set0_key_cannot_change_the_resolved_schedule` | DH PFP-52 | ladder `[2048]` before and after mutation |

## 5. Compatibility courts (exact candidate DSO)

* DH 30-row preset court: **`MATRIX rows=30 mismatches=0`** (`raw/keygen-matrix.out`).
* C ABI transcript `pfp5_diff`: **161/161 lines IDENTICAL** to the authority,
  `MX=150 RSA=8 DH=2` (`raw/diff-candidate.txt` vs `raw/diff-authority.txt`).
* No differential mismatch; no STOP condition.

## 6. Gate and memory

* `cargo fmt --all -- --check`: RC 0.
* `cargo clippy --all-targets -- -D warnings`: RC 0.
* `cargo test --lib -- --test-threads=4`: **2581 passed / 0 failed / 56 ignored**
  (baseline 2569 + 12 new tests; no test removed, weakened, or newly ignored).
* Court: `docker/openssl-rs-court.sh`, `--memory=4g --memory-swap=4g`,
  `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`; `memory.events oom=0
  oom_kill=0`, `memory.max=4294967296`.

| command | available (GiB) | swap free (GiB) | cap |
|---|---:|---:|---:|
| `cargo check --lib` | 13 | 7 | 4g |
| focused ladder tests | 19 | not re-read | 4g |
| full suite (first) | 19 | not re-read | 4g |
| clippy (×2) | 19 | not re-read | 4g |
| DSO build (`build_dso.sh`) | 19 | not re-read | 4g |
| ABI + DH court (`run_diff.sh`) | 19 | not re-read | 4g |
| full suite (final) | 19 | not re-read | 4g |
| end of session (`free -g`) | 19 | 0 | — |

Below the brief's 16 GiB advisory at the start, the operative cap was
`min(4, available-8) = 4 GiB` (13 → 4; 19 → 4), recorded here. `oom_kill=0`
throughout.
