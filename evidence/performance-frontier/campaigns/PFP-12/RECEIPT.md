# PFP-12 receipt — AEAD / SHA-2 extension audit; SHA-256 SHA-NI integrated

## 1. Identity

| | |
|---|---|
| source | `staging` HEAD `fee52629aa516c95ff7a7711ba0101e50e0fd46c`; one uncommitted build input: `src/digest/sha2.rs` sha256 `286c007c17155486d7a23c20b94cb962b3be57be2c3c90caa048797ba66471c8` |
| other build inputs | `src/aes.rs` `bc7142f8…`, `src/modes/gcm.rs` `61f51222…`, `src/chacha.rs` `ea956d5b…`, `src/mac/poly1305.rs` `600bd8ae…` (all unchanged from HEAD) |
| candidate DSO | `3c7ced9c5193e7ce5d2a616fb07aa49a8288624359def3e02d13ffc88c7dfc67`, build id `4bec7a59333a25cf35d14723335a93932baa8fa4`, 17 036 744 bytes |
| archive | `78e0e54ab3df93eb52340acf2ec10f9792d438e9711a00f3c6efdd832c9d48eb` |
| authority | `openssl-3.6.4-production` DSO `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| harness | `bench_pfp12.c` source `8fe9fd3d…`, binary `65500d9a…` |
| machine | i9-13900K: SHA-NI, AES-NI, PCLMULQDQ, AVX2; no AVX-512 |

## 2. What exists (detail in `BOUNDS.md` §1)

Before this batch every primitive on the item was **portable scalar code**:
byte-oriented AES with an S-box lookup (`src/aes.rs:372`); bit-by-bit GHASH
(`src/modes/gcm.rs:145`); scalar one-block ChaCha20 (`src/chacha.rs:129`);
scalar 3-limb Poly1305 (`src/mac/poly1305.rs:194`); the
`OPENSSL_SMALL_FOOTPRINT` SHA-2 arms (`src/digest/sha2.rs:359`, `:427`). No
AES-NI, PCLMULQDQ, SHA-NI, AVX2 or bitsliced path existed. There was no fast
path to "finish": the work was to add one.

## 3. Implemented and refused

**Implemented: SHA-256 over SHA-NI** (`sha256_blocks_sha_ni`,
`src/digest/sha2.rs:259`; dispatch `sha256_block`, `:333`). 16 KiB ratio moved
**6.061× → 1.052×** (candidate 38.0955 → 6.5988 µs, 5.77×), against an Amdahl
prediction of 5.71× and a 99.80 % attributable compression share.

**Refused, with arithmetic:**

* **AES-GCM** — the named x86 arm is VAES/VPCLMULQDQ; this CPU has no AVX-512,
  so it is recorded **`NOT_APPLICABLE_HARDWARE` tied to V1**. The available
  AES-NI+PCLMUL arm has an 80.3 % (64 B) / 99.9 % (16 KiB) arithmetic share
  (ceilings 5.1× / 833×) and clears 10 %, but is a two-extension rewrite of the
  AES core **and** the constant-time GHASH, beyond the one-primitive budget.
  Measured 7.031× / 136.022× (AES-128) and 7.730× / 137.869× (AES-256).
* **ChaCha20-Poly1305** — arithmetic share 55.2 % / 98.8 % (ceilings 2.23× /
  85×); the route is an 8-way AVX2 ChaCha20 plus an AVX2 Poly1305, a second SIMD
  boundary. Measured 2.020× / 3.858×.
* **SHA-512** — no applicable ISA extension here (SHA-NI does not cover it, the
  SHA512 CPUID bit and AVX-512 are absent); a handwritten single-stream AVX2
  compressor would only match the authority (A=1.69 → ≈1.0×), a second
  implementation outside the budget. Measured 1.685×.

Exactly one primitive was implemented; the other three are refusals whose
ceilings clear 10 % but whose implementation cost/route did not fit this batch.

## 4. Exact unsafe surface

Added to `src/digest/sha2.rs`:

* `sha256_blocks_sha_ni` — one `#[cfg(target_arch = "x86_64")]`,
  `#[target_feature(enable = "sha,sse4.1")]`, `unsafe fn`, with one `unsafe {}`
  block: 4 unaligned 16-byte message loads per block, 12 public `K256` loads,
  2 state loads, 2 state stores.
* The call site in `sha256_block`: one `unsafe { … }` guarded by
  `sha256_ni_available()`, with a `SAFETY:` comment.
* `sha256_ni_available` — safe; the **only** runtime `is_x86_feature_detected!`
  site on this path, cached in a `OnceLock`; also the only `OPENSSL_ia32cap`
  read.

No `asm!`, no new `#[no_mangle]` symbol, no `#[repr(C)]`/layout change, no new
safe-looking `unsafe fn`. `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks`
and `missing_safety_doc` remain deny-level and clean.

## 5. Constant-time position (before and after)

| requirement | today | after this change |
|---|---|---|
| GHASH must not table-lookup secret data | holds: `gf_mul` is bitwise (128 iterations), no table; the `H` operand is never branched on. Residual: it branches on the **block** operand, which is ciphertext/AAD, not `H` | unchanged (not touched) |
| Poly1305 must not table-lookup secret data | holds: limb arithmetic + `constant_time_carry` (`src/mac/poly1305.rs:148`) | unchanged |
| tag comparison full-length constant-time, not `memcmp` | holds: `CRYPTO_memcmp` (`src/runtime/mem.rs:1092`) accumulates `r |= a^b` over all bytes | unchanged |
| new code | — | SHA-256 indexes `K256` by public loop index only; no secret-dependent table lookup or branch introduced |

## 6. Correctness before timing

`run_diff.sh` / `run_fallback.sh`, candidate vs authority, same harness, same
vectors:

* **16 KAT cases**, all `IDENTICAL` cross-library: NIST GCM test cases 1
  (empty plaintext, empty AAD) and 2 (one zero block, empty AAD) with hard-coded
  expected tag/ciphertext (both matched; `kat_mismatch_lines = []`), plus
  AES-128/AES-256/ChaCha20-Poly1305 at (pt, aad) ∈ {(0,0), (0,16), (16,0),
  (64,16), (16384,16)}.
* **All 8 operation lines** (ciphertext + tag + `open=ok` + `tamper=rejected`)
  byte-identical to the authority. A one-bit tag flip is rejected by both; any
  mismatch or an accepted tampered tag exits non-zero and would have been a STOP.
* SHA-256/SHA-512 16 KiB digests identical.
* `sha256_block_portable` vs `sha256_block` on the same two blocks produce the
  same chaining state (`the_portable_compression_matches_the_dispatched_path`),
  and the `OPENSSL_ia32cap` parser has its own unit test.

## 7. Fallback proven live and measured

With `OPENSSL_ia32cap=":~0x20000000"` (SHA CPUID bit cleared) on the candidate,
the same 16 KAT/differential suite is `IDENTICAL` and the paired timing is:

| operation | cand µs | auth µs | ratio | 95 % CI | cand noise |
|---|---:|---:|---:|---|---:|
| SHA-256 16 KiB, feature forced off | 37.1919 | 6.2841 | **5.860** | [5.834, 5.981] | 0.1553 |

This is the pre-change implementation (baseline 38.0955 µs), so the fallback is
reachable, correct and measured — not merely present.

## 8. Gate

* `cargo fmt --all -- --check`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo test --lib -- --test-threads=4`: **2541 passed, 0 failed, 56 ignored**
  (baseline 2539/0/56; the +2 are the two new tests; no test newly ignored).

## 9. Memory (per heavy command)

`free -g` before each: available **24 GiB**, swap free **8 GiB**. Swap free
< 16 → cap = `min(4, available − 8)` = **4 GiB**, floor 2.
All commands ran in the court container already capped
`Mem=MemSwap=4294967296`; the attribution ran in a second tools court capped
`4g/4g`. `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`,
`--test-threads=4`; one heavy command at a time.

## 10. Residuals

As `BOUNDS.md` §6: AES-GCM VAES arm `NOT_APPLICABLE_HARDWARE`/V1 and non-VAES
arm deferred; ChaCha AVX2 deferred; SHA-512 has no applicable extension; GHASH's
block-operand branch unchanged; `OPENSSL_ia32cap` modelled only for the SHA
clear mask; AArch64 arms not exercised.
