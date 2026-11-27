# PFP8-KEYGEN-PRESET-PRIV — caller-supplied private key repair

```yaml
task_id:       PFP8-KEYGEN-PRESET-PRIV
branch:        staging
source_identity:
  commit:      983437d2a415d493c7f7206c6332723bce591073
  src_tree:    6211bc6eeede65a98941843c50e3ded8b906fa7e
  worktree:    "M src/dh/key.rs (the repair and its regression test are uncommitted)"
  dh_key_sha256: 88ebedd147c14a31ca859bbae32a5aa60e6aa8e52209181a6de370953f065c0b
  arith_sha256:  8b3682381560f592cdd50f4657b71b46a646331609df27b4015f000050627593
  mont_sha256:   cc9e7e3f6133457089cf0a6cb741614ae5b1f52249eabb67c48e7ae26c5f1e6b
  candidate_dso: e3ef3d84166a65408e5c89eaa4cc444a2c9208fea5e2acb1c272b6a0b612b187
  candidate_archive: 460291c49a8bcb0940771e5d9fdb77a66d5d219daf0e576db46af8b7dd421dfb
  size:        17140320
  build_id:    c3dcea6eb69c06da815cb07ae98d5dbf957230b1
  repro:       two fresh CARGO_TARGET_DIR builds agree byte for byte (preset-priv/build/variants.txt)
  previous_dso: 6302e05a14e47b74bd546f03e7509e234a2884511ddec5c3f9a7f4382bd9a25b
authority:
  dso_sha256:  611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
  source:      forensics/authorities/src/openssl-3.6.4
  contract:    crypto/dh/dh_key.c:265-387, public-key call at :370
obligation:    PFP8-KEYGEN-PRESET-PRIV — OPEN (repair merged into the worktree; one input class remains)
```

## 1. The authority's contract (pinned first)

`generate_key()` allocates `priv_key`/`pub_key`, runs the private-key branch only
under `if (generate_new_key)`, and then **unconditionally** calls
`ossl_dh_generate_public_key(ctx, dh, priv_key, pub_key)` at `dh_key.c:370`
(the call is outside the `if`). The authority is consistent across all four
combinations; there is no pair where it skips the public-key derivation.

| private key | public slot | private generation | public key | `DH_generate_key` | error queue |
|---|---|---|---|---|---|
| generated (`priv_key == NULL`) | absent | yes | `g^priv mod p` into a fresh `BIGNUM` | **1** | empty |
| generated (`priv_key == NULL`) | present | yes | recomputed into the existing `BIGNUM` (overwritten in place) | **1** | empty |
| caller-supplied (preset) | absent | no | `g^priv mod p` into a fresh `BIGNUM` | **1** | empty |
| caller-supplied (preset) | present | no | recomputed into the existing `BIGNUM` (overwritten in place) | **1** | empty |

The only error-queue entry is `ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB)` at the shared
`err:` label when `ok != 1` (allocation or exponentiation failure). Success raises
nothing. `generate_key()` performs no range or width check on a caller-supplied
private exponent; a 1-bit and a 2400-bit exponent are both admitted and
exponentiated by `BN_mod_exp_mont_consttime`.

Measured on the authority DSO, 30 rows (3 groups × 2 public states ×
[generated + 4 preset widths]): every row returns **1**, has a public key, and
leaves the error queue **empty**. Raw: `raw/preset-priv-matrix.json` (`auth`).

## 2. Our behaviour before the repair

At HEAD `983437d2` (and the width-policy DSO `6302e05a`), `src/dh/key.rs` opened
the generation block with `if generate_new_key == 0 { break 'generate; }` and
placed `ossl_dh_generate_public_key` inside that block, so a preset private key
skipped the public-key call entirely.

| combination | before (all 3 groups) |
|---|---|
| generated / public absent | rc 1, public key computed, queue empty (agreed) |
| generated / public present | rc 1, existing slot overwritten, queue empty (agreed) |
| preset / public absent | **rc 0, no public key**, queue `[ERR_LIB_DH, 0x80003]` |
| preset / public present | **rc 0, existing sentinel kept (not overwritten)**, queue `[ERR_LIB_DH, 0x80003]` |

Before matrix: 24 rows, **18 mismatches** — exactly the six preset rows per group
(`matrix-before.json`; the same `old` column is retained in the new 30-row file).

## 3. The repair

In `src/dh/key.rs`:

* the `generate_new_key == 0` early `break` is removed;
* the three private-generation arms are wrapped in `if generate_new_key != 0`;
* `ossl_dh_generate_public_key` remains after that block, so all four
  combinations reach it, and an existing `dh->pub_key` is recomputed in place.

That is the whole source change. `dh->length`, the exponent width policy, the
subgroup/parameter checks, peer validation, blinding and every arithmetic
routine are untouched; there are **0 new unsafe operations**, no `#[repr(C)]`
change and no `CRYPTO_*` seam change. The authority's `err:` cleanup tests
(`pub_key != dh->pub_key`, `priv_key != dh->priv_key`) are unchanged.

## 4. Matrix after the repair

Candidate `e3ef3d84`, authority `611e511d`, 30 rows, **26 agree / 4 differ**
(`raw/preset-priv-matrix.json`, `raw/preset-priv-matrix.txt`). Public-key bytes
are compared byte for byte on every preset row.

| population | rows | result |
|---|---:|---|
| generated private, public absent/present | 6 | agree: rc 1, public key, empty queue |
| in-bound preset `PRIV225` (222 bits), both public states | 6 | agree: rc 1, public key bytes equal, empty queue |
| short preset `01` (1 bit), both public states | 6 | agree: rc 1, public key bytes equal (`2`; sentinel is the correct value), empty queue |
| long preset `PRIV2048` (2048 bits, **within** the modulus), both public states | 6 | agree: rc 1, public key bytes equal, empty queue |
| long preset `ab × 300` (2400 bits) on **ffdhe3072** (3072-bit modulus) | 2 | agree: rc 1, public key bytes equal, empty queue |
| long preset `ab × 300` (2400 bits) on **ffdhe2048** and **modp2048** (2048-bit modulus) | 4 | **differ** (see §5) |

So the named defect — a caller-supplied private key that is accepted by the
authority — is repaired for every preset whose limb count does not exceed the
modulus. An existing public-key slot is overwritten in place, as the authority
does.

## 5. Exact residual (why the obligation stays open)

For a 2400-bit preset on a 2048-bit group:

| field | candidate | authority |
|---|---|---|
| `rc` | 0 | 1 |
| public key, slot absent | absent | 2048-bit `g^priv mod p` |
| public key, slot present | sentinel `2` kept | overwritten with `g^priv mod p` |
| error queue | `[ERR_LIB_DH, 0x80003]` (the `err:` path) | empty |

Cause: `src/bn/arith.rs::mod_exp_core_consttime_policy` sets
`width = md.len()` when the exponent is wider than the group's declared policy,
then **refuses** (`return None`) when `pd.len() > width`. A 2400-bit exponent is
38 limbs; the 2048-bit modulus is 32 limbs, so the public-key exponentiation
fails. The authority's `BN_mod_exp_mont_consttime` scans all exponent bits and
does not require the exponent to be narrower than the modulus.

This was **not** repaired here: the task forbids altering the exponent width
policy, and every available correction (widen the ladder to the secret's length,
or reduce the exponent modulo the group order) is a change to the ladder
schedule/algorithm, not to the generation flow. It is a pre-existing width-policy
admission, not a regression of this repair.

## 6. Regression test

`dh::key::tests::the_four_key_state_combinations_all_derive_the_public_key`
(`src/dh/key.rs`). Its doc comment states that the expectations are the
**OpenSSL 3.6.4 authority's**, citing `crypto/dh/dh_key.c:265-387` and the call at
`:370`, not this crate's implementation. It pins, for all three groups:

1. generated private + absent public: rc 1, public key present, queue empty;
2. preset private + absent public: rc 1, public key present, preset bit length
   unchanged, public bytes equal to the authority's `g^priv mod p`;
3. generated private + present public: rc 1, the supplied slot is overwritten;
4. preset private + present public: rc 1, public bytes equal to the authority's
   `g^priv mod p`, preset unchanged.

The three 512/768-byte expected values are the authority's own outputs recorded
in `raw/preset-priv-matrix.json`; they are pins, not recomputed by the candidate.
The test's hex helper was made infallible without `unwrap`/`expect`/`panic!` so
the crate's `-D warnings` clippy gate stays clean; that is test-only.

Exact run: `cargo test --lib -- --exact
dh::key::tests::the_four_key_state_combinations_all_derive_the_public_key`
→ 1 passed, 0 failed.

## 7. Key generation from scratch and shared secrets

The generation branch body is unchanged operation-for-operation; only the guard
around it moved, so the from-scratch path executes the same sequence and draws
its exponent from the same DRBG call. Independent DRBGs are not reproducible
across the two libraries, so "same randomness" is measured through the same
supplied exponent, which is the value the DRBG would yield:

* `keygen-fixed --priv PRIV2048`: candidate public key == authority public key,
  3/3 groups (512, 768, 512 bytes);
* the same check on the `pub present` combination: 6/6 probe rows equal;
* shared secret: `old == new == authority` for 3 groups × {2048-bit, 225-bit
  exponent} = 6/6 byte-identical.

The full differential at this digest is **45/45 comparisons, 0 mismatches,
0 stops** (`raw/differential-after.json`): 6 shared-secret + 6 named-vs-explicit,
9 key-generation cross-checks, 3 preset-private key generations, and the
**21/21 malformed-peer return codes** unchanged.

## 8. Secret-bearing path, taint and branch audit

This repair does **not** change a secret-bearing arithmetic path. The function
`ossl_dh_generate_public_key` and everything it calls (`dh_bn_mod_exp`,
`bn_mod_exp_mont_impl`, `run_mont_ladder`, `mont_mul_ladder_into`) are unmodified;
the change only controls *whether* a preset key reaches the unchanged call. The
modified branch depends on whether the caller supplied a key (public
configuration), not on key material.

The applicable instrument is therefore the width-policy one, not a new run:
`arith.rs 8b3682…` and `mont.rs cc9e7e…` are byte-identical to the source of
`width-policy/ctgrind` and `width-policy/audit`. At that source:

| case | errors | contexts |
|---|---:|---:|
| policy taint (`ctgrind_secret_exponent_policy_width`) | **0** | **0** |
| policy control (`CTGRIND_POLICY_CONTROL=1`) | 4 | 1 |
| modulus-width window taint | **0** | **0** |

and the branch audit reports **0 secret-derived control transfers** in
`mont_mul_ladder_into`, `run_mont_ladder`, `bn_mod_exp_mont_impl` and
`dh_bn_mod_exp` (the last is inside `key.rs` but is not the function this repair
edited). No new ctgrind or branch-audit run is claimed: the arithmetic source is
identical, while the audit's per-address allowlist is bound to DSO `6302e05a`
and was not regenerated for `e3ef3d84`. This is a review aid, not a
constant-time proof.

## 9. Repository gates

| gate | result |
|---|---|
| `cargo test --lib -- dh` | **80 passed, 0 failed, 2 ignored** |
| full `cargo test --lib` | **2,499 passed, 0 failed, 54 ignored** |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| unsafe operations added | **0** |
| `#[repr(C)]`, exported symbols, `CRYPTO_*` seam | unchanged |

The ignored count is unchanged at 54; the passed count grew by the width-policy
tests already present in `391bc419` and by this regression test.

## 10. Obligation state

**OPEN.** The four key-state combinations now agree with the authority for
generated keys and for caller-supplied private keys whose limb count is at most
the modulus (including the group-sized, shorter-than-bound, and 2048-bit
within-modulus presets). The remaining divergence is a preset exponent **wider
than the modulus** on the 2048-bit groups (4/30 rows), caused by the width
policy's refusal documented in §5. Closing the obligation requires a separate,
explicit decision to change that policy; it is not claimed here.

## 11. What this does not establish

* It is not a frontier or timing result.
* It does not establish constant-time behaviour; §8 is a source-bound instrument
  and a review aid.
* It does not close `PFP8-KEYGEN-PRESET-PRIV` for exponents wider than the
  modulus, nor `PFP8-WIDTH-POLICY` or `PFP8-REFUSED-TABLE-BUILD`.
* It asserts no `SAFE_COMPATIBLE` graduation.

## Raw files

| file | content |
|---|---|
| `raw/preset-priv-matrix.json` | 30 rows: candidate, authority, previous DSO; rc, public presence/bytes, sentinel, error queue |
| `raw/preset-priv-matrix.txt` | row/mismatch count (`rows=30 mismatches=4`) |
| `raw/differential-after.json` | 45 comparisons, 0 mismatches, 0 stops at `e3ef3d84` |
| `raw/matrix-before.json` (court scratch) | 24 rows, 18 mismatches at `6302e05a` |
| `preset-priv/build/source.env`, `variants.txt` | source identity and two-build digest agreement |
