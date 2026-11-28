# PFP-45 receipt — reduce the DH secret exponent modulo the subgroup order

**Item:** PFP-45. **No commit or push.** The change is in the worktree on
`staging` at HEAD `854a8940` plus this batch's edits.

## 0. Answer, including one premise correction

The reduction is implemented, publicly gated, constant-time in its schedule, and
correct: **30/30 preset rows, 0 mismatches; 161/161 ABI lines identical; 2611
lib tests passed / 0 failed / 56 ignored.**

**The row's projected `x mod q` width is wrong.** For ffdhe2048, `q = (p-1)/2`
is the **2047-bit** subgroup order (`crypto/bn/bn_dh.c:809`,
`ffdhe2048_q[]`), i.e. **32 limbs / 2048 iterations**. The 225-bit / 4-limb
number is RFC 7919's recommended *private-key length* (`dh->params.keylength`),
not an order; `x mod q` is not 225 bits. Reducing to 4 limbs would truncate the
exponent and **change the key**, so the acceptance criterion "the reduced ladder
width must equal the policy width" is unsatisfiable as written and was **not**
faked. The true property delivered is: the ladder width is
`max(policy, len(q)) = 32`, **independent of `x`'s value and limb count** for a
gated group; the covering-width fallback no longer runs for gated groups.

Measured out-of-policy preset: **3047.5 µs → 2682.5 µs, ratio 0.8643 (1.16×
faster)**, not 8.6×. The authority is 1469.1 µs, so we move from 2.07× to 1.83×
the authority. The reduction itself adds ~0.1 ms over the 2048-iteration
projection.

## 1. Gate (public, and fails closed)

`src/dh/key.rs::dh_reduction_order` returns `q` only when
`ossl_dh_is_named_safe_prime_group(dh) != 0` (`DH_get_nid(dh) > 3`) and
`params.q` is non-NULL. `DH_get_nid` is a cache, but **every** public mutation of
the parameters re-derives it from the actual `p`, `q`, `g`: `DH_set0_pqg`
(`src/dh/object.rs:617-618`) and the decoder's `dh_cb` both call
`ossl_dh_cache_named_group`, which flushes and re-runs
`ossl_ffc_numbers_to_dh_named_group`. A tampered `g` or `q` therefore yields
`NID_undef`. For the named safe-prime sets `q = (p-1)/2` and `g` generates the
order-`q` subgroup, which is `DH_check`'s own `g^q == 1 mod p` test.

On gate failure the call is exactly the PFP-43 widening path (`reduce == false`);
it never reduces. `src/dh/key.rs::pfp45_gate_requires_canonical_safe_prime_parameters`
tests the accept and reject arms; `pfp45_non_conforming_group_falls_back_and_still_computes`
takes a 2048-bit `p/q` with a non-canonical `g` and a 2400-bit exponent, and
checks the result against the independent `mod_exp_core`.

## 2. The reduction is constant-time in its schedule — and the evidence

`src/bn/limbs.rs::rem_consttime` is fixed-iteration binary long division:
`64 * u.len()` outer iterations, each a `m.len() + 1`-limb shift and **one
masked conditional subtraction**. The bit is read at a public index and enters
the remainder as a value; `ct_sub_into` returns an all-ones borrow mask and the
select is bitwise. `u.len()` is the exponent buffer's declassified width
(PFP-39/PFP-43), never a value; `m.len()` is the public order length.

Evidence, not source inspection alone:

| instrument | result |
|---|---|
| ctgrind, dividend bytes marked undefined (`ctgrind_rem_consttime_secret_dividend`) | **0 errors / 0 contexts** |
| same test, `CTGRIND_CONTROL=1` (branch on a marked limb) | **38 errors / 1 context** — the instrument fires |
| branch audit of the emitted `rem_consttime` (`raw/rem_consttime.dis`, DSO `de229393…`) | 31 conditional jumps and 12 unconditional (cold allocation/overflow/bounds/loop-counter paths), **0 `cmov`, 0 `div`, 0 `cpuid`**, 9 `setcc` carry/borrow *data* writes |

**Scope:** this is a schedule/branch observation at source and emitted-code
identity plus a valgrind taint run. It is **not** a proof of constant time, and
no DSO-bound constant-time claim is made. **No secret-derived transfer or address
was observed**; the only secret-dependent quantity admitted to control is the
already-declassified limb count.

## 3. Change

| file | change |
|---|---|
| `src/bn/limbs.rs` | `rem_consttime` (secret dividend, public modulus) and 3 tests including the ctgrind case |
| `src/bn/mont.rs` | `bn_mod_exp_mont_policy` gains `order` + `reduce`; reduction is taken only when `policy > 0 && stored > policy`; ladder width `max(policy, len(q))`; all other call sites pass `None` |
| `src/dh/key.rs` | `dh_reduction_order` public gate; the bn call passes `q` only when it holds; 2 tests |
| `src/bn/blinding.rs`, `src/rsa/sp800.rs` | argument plumbing only (`None`) |

Source diffstat: `limbs.rs +202`, `dh/key.rs +166/−?`, `mont.rs +59`, two call
sites +1 line each. No new production `unsafe`; the only new `unsafe` is
test-only (valgrind client request and the existing test setup style). `q` is read
through the existing DH facade window; no new boundary and **hidden = 0**.

## 4. Correctness

| check | result |
|---|---|
| DH preset matrix, 3 groups × 4 states × 4 scalars (after vs authority) | **rows=30 mismatches=0**, every row `old==new` |
| PFP-5 C ABI transcript (MX 150, RSA 8, DH 2) | **161/161 IDENTICAL** for before and after |
| `rem_consttime` vs variable-time division, 256 random shapes up to 38 limbs | 256/256 equal, result `< m`, width `= len(m)` |
| 2400-bit preset geometry (38 limbs / 32-limb order) | equal, `< m` |
| in-policy path | unchanged: same code path, matrix `old==new`, timing 461.6 → 455.6 µs (0.977, within noise) |

Raw: `raw/keygen-matrix.out`, `raw/diff-*.txt`.

## 5. Timing (µs, median of 15 paired repetitions, `taskset -c 1`)

| workload | before | after | ratio | authority | auth/after |
|---|---:|---:|---:|---:|---:|
| out-of-policy 2400-bit preset | 3047.469 | **2682.476** | **0.8643** | 1469.112 | 0.5464 |
| in-policy 225-bit preset | 461.634 | 455.619 | 0.9770 | 179.854 | 0.3978 |

Raw: `raw/timing/` (`summary.txt`, `run-meta.env`). Iterations 2432 → 2048; the
remaining reduction cost keeps the measured gain below the pure iteration ratio.

## 6. Gate and identity

| item | value |
|---|---|
| before DSO | `3f64590e9a178f824f997fa372f4503715ca5bec452a2fce4005e6629446e4d4` |
| after DSO | `de229393d3d937e0cef70ed59f213f06d09117c8bcf1504c2986dd1a3c42d7ec` |
| authority DSO | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test --lib -- --test-threads=4` | **2611 passed, 0 failed, 56 ignored** (baseline 2606 + 5 new; none newly ignored) |

## 7. Memory protocol (per heavy command)

| command | available | Swap free | cap |
|---|---:|---:|---|
| before/after release builds | 19 / 19 GiB | 0 GiB | 4 GiB |
| `cargo check` / focused tests | 18 / 16 GiB | 0 GiB | 4 GiB |
| correctness court (ABI + matrix) | 19 GiB | 0 GiB | 4 GiB |
| timing court | 18 GiB | 0 GiB | 4 GiB |
| ctgrind build (court) + valgrind (tools court) | 19 GiB | 0 GiB | 4 GiB each |
| clippy / full suite | 16 / 19 GiB | 0 GiB | 4 GiB |

Swap free was 0 GiB throughout (advisory); `available` dipped once to 15 GiB, so
the operative cap stayed `min(4, available − 8) = 4 GiB` (floor met). One heavy
command at a time; `CARGO_BUILD_JOBS=1`; no release `--test` build; `test_sigstore_bundle` not run.

## 8. Residuals

1. **`PFP45-POLICY-WIDTH` (OPEN):** the reduced width is the order width (32),
   not the 4-limb policy. The stated criterion cannot hold for a 2400-bit `x`.
2. **`PFP45-LENGTH-DECLASSIFICATION` (retained):** the reduction scans the
   exponent buffer's declassified limb count; the *ladder* width no longer
   depends on `x`, but the length channel PFP-43 recorded is not removed.
3. **`PFP45-GATE-INVARIANT` (retained, tested):** the whitelist trusts the nid's
   re-derivation from `p/q/g`. Both mutation choke points were read and the
   tampered-generator case is tested; a direct write into the opaque `DH` object
   is outside the C contract.
4. No DSO-bound constant-time proof: `PFP45-CT-PROOF` is `NOT_RUN`.
