# PFP-12 — AES-GCM, ChaCha20-Poly1305 and SHA-2 extension audit

**Item (verbatim).** "AES-GCM (VAES/VPCLMULQDQ on x86, AES/PMULL on AArch64),
ChaCha20-Poly1305, SHA-2 extensions; complete AEAD operation including tag
verification and AAD. Acceptance: 64-byte latency and 16 KiB throughput reported
separately; fallback paths for CPUs without the extensions."

**Candidate.** Working tree at `staging` HEAD
`fee52629aa516c95ff7a7711ba0101e50e0fd46c` (uncommitted `src/digest/sha2.rs`,
sha256 `286c007c17155486d7a23c20b94cb962b3be57be2c3c90caa048797ba66471c8`).
Candidate DSO
`3c7ced9c5193e7ce5d2a616fb07aa49a8288624359def3e02d13ffc88c7dfc67`
(build id `4bec7a59333a25cf35d14723335a93932baa8fa4`). Authority
`openssl-3.6.4-production` DSO
`611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.
Harness source `8fe9fd3db20f152d28d228232b3f1779e475056f77d42d9f67036996ef85d11f`,
binary `65500d9a4cdd3dcc88aae6d834eb8d4ceda17f481bb8451b4f248a245ec41ebd`.
Machine: 13th Gen Intel Core i9-13900K, SHA-NI + AES-NI + PCLMULQDQ + AVX2,
**no AVX-512** (so no VAES/VPCLMULQDQ).

**Decision in one line.** Every primitive clears the 10 % Amdahl threshold on
arithmetic share, but exactly **one** was implemented: **SHA-256 over SHA-NI**,
which moved the 16 KiB ratio from **6.061× slower** to **1.052× slower**
(5.77× candidate speedup). AES-GCM is refused for this batch with its
VAES/VPCLMULQDQ arm recorded `NOT_APPLICABLE_HARDWARE` tied to **V1**; the
available non-VAES AES-NI+PCLMUL rewrite is deferred. ChaCha20-Poly1305 and
SHA-512 are refused with their arithmetic.

---

## 1. What already exists (source reading, not inferred)

| primitive | module / entry point | today's implementation | hardware path? |
|---|---|---|---|
| AES key schedule | `src/aes.rs:167` `aes_expand`; export `AES_set_encrypt_key` `src/aes.rs:297` | logical expansion, then `bswap_schedule` so `rd_key` memory is the FIPS round-key bytes | **none** |
| AES block | `src/aes.rs:372` `AES_encrypt` | byte-oriented FIPS-197 round: `sub_bytes` S-box lookup (`:105`), `shift_rows` (`:117`), scalar `mix_columns` (`:135`) | **none** — no AES-NI, no T-tables, no bitsliced path |
| GCM / GHASH | `src/modes/gcm.rs:145` `gf_mul`; `:178` `ossl_gcm_gmult_4bit`; `:212` `ossl_gcm_ghash_4bit` | bit-by-bit SP 800-38D Algorithm 1: 128 iterations, xor + conditional reduction, per 16-byte block | **none** — no PCLMULQDQ, no 4-bit Shoup table |
| tag verification | `src/modes/gcm.rs:631` `CRYPTO_gcm128_finish` → `src/runtime/mem.rs:1092` `CRYPTO_memcmp` | full-length `r |= a[i]^b[i]` accumulation, one branch at the end | portable, already constant-time |
| ChaCha20 | `src/chacha.rs:129` `chacha20_core`, `:112` `quarterround`; `:175` `ChaCha20_ctr32` | scalar one-block core, ten double rounds, u32 wrapping ops | **none** — no SSE2/AVX2, no 4/8-way |
| Poly1305 | `src/mac/poly1305.rs:194` `poly1305_blocks`; `:148` `constant_time_carry` | 3×u64 limbs, 128-bit products, branchless carry | **none** — no AVX2 |
| SHA-256 | `src/digest/sha2.rs:359` `sha256_block_portable` (was `:206` before this batch) | `OPENSSL_SMALL_FOOTPRINT` transcription, scalar round function | **was none**; this batch adds SHA-NI |
| SHA-512 | `src/digest/sha2.rs:427` `sha512_block` | `OPENSSL_SMALL_FOOTPRINT` transcription, scalar | **none** |

Capability probes do exist (`ia32cap_aesni` `src/provider/cipher.rs:11067`,
p256's `arch_supported` `src/ec/p256.rs:922`, `x25519_fe64_eligible`
`src/ec/curve25519.rs:158`) but no symmetric primitive consumes an x86 crypto
extension. So the work is **"add a fast path"**, not "the path exists and the gap
is elsewhere".

---

## 2. Timing, both regimes separately

Instrument `bench_pfp12.c`: one `libcrypto.so.3` per process
(`dlopen(RTLD_NOW|RTLD_LOCAL)`), one process = one independent replication,
`taskset -c 1`, 15 repetitions, 5 timed batches per process, warm-up `iters/4`.
Each iteration is the **complete** AEAD operation in both directions:
`EVP_EncryptInit_ex` (cipher, then key+IV), AAD (16 B), plaintext, Final,
`GET_TAG`; then `EVP_DecryptInit_ex`, AAD, ciphertext, `SET_TAG`, and
`EVP_DecryptFinal_ex`, whose return is the tag verification. Ratio =
cand/auth (>1 = candidate slower); CI is a 95 % percentile bootstrap over the 15
paired ratios; noise floor is the authority arm's own relative half-range.

**Baseline (pre-change; SHA-256 row is the row that moved).**

| operation | cand µs | auth µs | ratio | 95 % CI | auth noise |
|---|---:|---:|---:|---|---:|
| AES-128-GCM 64 B | 4.5367 | 0.6495 | **6.993** | [6.949, 7.038] | 0.1109 |
| AES-128-GCM 16 KiB | 512.7471 | 3.8041 | **134.927** | [134.555, 135.397] | 0.0115 |
| AES-256-GCM 64 B | 5.0684 | 0.6616 | **7.669** | [7.628, 7.684] | 0.0396 |
| AES-256-GCM 16 KiB | 601.8317 | 4.3533 | **138.309** | [137.910, 138.644] | 0.0110 |
| ChaCha20-Poly1305 64 B | 1.5782 | 0.7855 | **2.003** | [1.998, 2.015] | 0.0784 |
| ChaCha20-Poly1305 16 KiB | 41.6276 | 10.7518 | **3.871** | [3.698, 3.876] | 0.0977 |
| SHA-256 16 KiB | 38.0955 | 6.2825 | **6.061** | [6.009, 6.148] | 0.0078 |
| SHA-512 16 KiB | 25.0221 | 14.2253 | **1.761** | [1.731, 1.807] | 0.6150 |

The baseline SHA-512 authority half-range was 61.5 % (one scheduling outlier in
15); the re-measurement below is 1.7 %.

**Final (post-change).** Only SHA-256 changed; the others are re-measured but
their source is untouched.

| operation | cand µs | auth µs | ratio | 95 % CI | auth noise |
|---|---:|---:|---:|---|---:|
| AES-128-GCM 64 B | 4.5689 | 0.6514 | **7.031** | [7.002, 7.065] | 0.0422 |
| AES-128-GCM 16 KiB | 515.6351 | 3.7906 | **136.022** | [135.288, 136.384] | 0.0123 |
| AES-256-GCM 64 B | 5.0997 | 0.6614 | **7.730** | [7.685, 7.822] | 0.0133 |
| AES-256-GCM 16 KiB | 601.5434 | 4.3620 | **137.869** | [137.059, 138.260] | 0.0287 |
| ChaCha20-Poly1305 64 B | 1.5904 | 0.7875 | **2.020** | [2.014, 2.029] | 0.0161 |
| ChaCha20-Poly1305 16 KiB | 41.6189 | 10.7605 | **3.858** | [3.630, 3.873] | 0.1553 |
| **SHA-256 16 KiB** | **6.5988** | **6.2838** | **1.052** | [1.047, 1.054] | 0.0068 |
| SHA-512 16 KiB | 23.9821 | 14.2119 | **1.685** | [1.680, 1.692] | 0.0172 |

The two ChaCha rows report a candidate-side half-range of ≈0.61; their paired CI
is narrow, but the ratio should be read with that floor. No regime is averaged
with the other.

---

## 3. Attribution (instruction counts, two-point differencing)

`callgrind` on the exact DSOs (valgrind 3.19, tools court). Two iteration counts
per (arm, operation) are subtracted function-by-function, cancelling the one-time
provider/namemap/loader startup; the result is a **disjoint self-cost partition**
in instructions. Each function maps to one group in priority order; the
unclassified share is `other`.

| arm-operation | key sched | block cipher | GHASH | Poly1305 | ChaCha | tag | SHA compress | EVP framing | other |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cand AES-128-GCM 64 B | 0.63 | 42.40 | 37.31 | — | — | 7.01 | — | 5.67 | 6.98 |
| cand AES-128-GCM 16 KiB | 0.00 | 48.56 | 51.32 | — | — | 0.05 | — | 0.04 | 0.03 |
| cand AES-256-GCM 64 B | 0.73 | 50.97 | 31.66 | — | — | 5.93 | — | 4.80 | 5.91 |
| cand AES-256-GCM 16 KiB | 0.00 | 57.28 | 42.62 | — | — | 0.04 | — | 0.03 | 0.03 |
| cand ChaCha20-Poly1305 64 B | 1.21 | — | — | 27.94 | 26.09 | — | — | 8.66 | 36.10 |
| cand ChaCha20-Poly1305 16 KiB | 0.03 | — | — | 16.17 | 82.63 | — | — | 0.22 | 0.94 |
| cand SHA-256 16 KiB | — | — | — | — | — | — | 99.80 | 0.04 | 0.16 |
| cand SHA-512 16 KiB | — | — | — | — | — | — | 99.65 | 0.09 | 0.24 |
| auth AES-128-GCM 16 KiB | 0.46 | 0.28 | 88.35¹ | — | — | 0.19 | — | 2.53 | 8.20 |
| auth ChaCha20-Poly1305 16 KiB | 0.38 | — | — | 32.96 | 62.32 | 0.01 | — | 1.33 | 3.00 |
| auth SHA-256 16 KiB | — | — | — | — | — | — | 99.55 | 0.07 | 0.34 |

¹ the authority's `_aesni_ctr32_ghash_6x` fuses AES and GHASH in one 6-block
interleaved routine, so its block/GHASH split is not separable; the 88.35 % is
the fused arithmetic.

**Where the gap is.** At 16 KiB every candidate is arithmetic-bound (AES 99.9 %,
ChaCha 98.8 %, SHA-256 99.8 %, SHA-512 99.65 %). At 64 B the candidate is
**per-operation-overhead-bound**: AES 64 B still spends 5.7–7.0 % in tag, 4.8–5.7 %
EVP framing and 5.9–7.0 % in property/namemap/lock/malloc (`other` top entries:
`OSSL_PARAM_locate`, `name2num_inner`, thread locks), and ChaCha 64 B spends
36.1 % there. That is why a large-message throughput win and a small-message
latency win have different ceilings.

---

## 4. Amdahl and decision per primitive

Arithmetic share `S` = key schedule + block + GHASH (AES), key + ChaCha +
Poly1305 (ChaCha), or SHA compression (SHA). Speedup for a core accelerated by
`A` is `1/((1−S) + S/A)`; the `A→∞` column is the ceiling.

| primitive | S 64 B / 16 KiB | ceiling (A→∞) | realistic A → total speedup | resulting ratio 64 B / 16 KiB | clears 10 %? | decision |
|---|---|---|---:|---|---|---|
| AES-128-GCM | 80.3 % / 99.9 % | 5.1× / 833× | A=10 → 3.6× / 9.9× | ≈1.95 / ≈13.8 | yes | **REFUSED** (see below) |
| AES-256-GCM | 83.4 % / 99.9 % | 6.0× / 1000× | A=10 → 4.0× / 9.9× | ≈1.93 / ≈13.9 | yes | **REFUSED** |
| ChaCha20-Poly1305 | 55.2 % / 98.8 % | 2.23× / 85× | 5× ChaCha, 3× Poly → 1.65× / 4.3× | ≈1.22 / ≈0.89 | yes | **REFUSED** |
| SHA-256 | — / 99.80 % | 500× | measured 5.77× → 5.71× predicted | — / **1.05** | yes | **IMPLEMENTED** |
| SHA-512 | — / 99.65 % | 286× (theoretical) | matching authority's AVX2 (A=1.69) → 1.67× | — / ≈1.0 | yes | **REFUSED** (no ISA extension) |

Decisions, with the arithmetic that produced them:

* **AES-GCM — refused this batch.** The item names **VAES/VPCLMULQDQ** as the
  x86 arm. This machine has AES-NI and PCLMULQDQ but **no AVX-512**, so
  VAES/VPCLMULQDQ cannot be executed at all: that arm is
  **`NOT_APPLICABLE_HARDWARE` tied to V1**, not measured and not implemented
  blind. The narrower AES-NI + PCLMUL arm is available and its Amdahl ceiling is
  large (80.3 % / 99.9 %), but it is a two-extension rewrite — AES-NI key
  schedule/block **and** a PCLMUL field multiply that must replace the
  constant-time GHASH — a larger unsafe boundary than the one-primitive budget.
  Deferred; the 64 B floor is the 19.7–26.6 % non-arithmetic share.
* **ChaCha20-Poly1305 — refused.** Ceiling 2.23× (64 B) / 85× (16 KiB) clears
  10 %, but the route is an 8-way AVX2 ChaCha20 **and** an AVX2 Poly1305, a
  second large SIMD boundary. Deferred; at 64 B 44.8 % is already non-arithmetic
  and cannot be recovered by vectorising the core.
* **SHA-256 — implemented.** 99.80 % is the compression function; SHA-NI is a
  single pure `#[target_feature]` function, so the whole attributable share is
  addressable inside the one-primitive budget. Measured candidate speedup
  38.0955 → 6.5988 µs = **5.77×**, against a predicted 5.71× at A=5.77.
* **SHA-512 — refused.** The 286× `A→∞` figure needs an accelerator, and none
  exists on this machine: SHA-NI does not cover SHA-512, the SHA512 CPUID bit is
  absent, and AVX-512 is absent. The only route is a handwritten single-stream
  AVX2 compressor whose realistic gain is the authority's own 1.69× (→ ≈1.0×
  ratio). That is a second implementation, not a SHA-2 *extension*, and is out
  of this batch's budget.

---

## 5. The one implemented primitive: SHA-256 over SHA-NI

`src/digest/sha2.rs`:

* `sha256_block` (`:333`) is the single dispatch site. For `num > 0` it tests
  `sha256_ni_available` (`:233`); the predicate is cached in a `OnceLock`, checks
  `OPENSSL_ia32cap`'s SHA clear mask, then `is_x86_feature_detected!("sha")` and
  `("sse4.1")`.
* `sha256_blocks_sha_ni` (`:259`) is one `#[target_feature(enable =
  "sha,sse4.1")] unsafe fn`; four message vectors, `sha256rnds2` for two rounds
  per instruction, `sha256msg1`/`sha256msg2` for the schedule.
* `sha256_block_portable` (`:359`) is the unchanged scalar transcription and
  remains the fallback and the differential reference.
* `ia32cap_sha_cleared` (`:212`) parses only the `~` clear-mask form of
  `OPENSSL_ia32cap`'s second vector (SHA = CPUID.7.0:EBX bit 29); the value-set
  form stays unmodelled (`RT-CPU-CAPABILITY` partially addressed).

Unsafe surface (exact): **one** `#[target_feature]` `unsafe fn`, with **one**
`unsafe {}` block inside it covering 4 per-block message loads, 12 public
round-constant loads, 2 state loads and 2 state stores; **one** call site in
`sha256_block` guarded by the feature predicate. No `asm!`, no new exported
symbol, no `#[repr(C)]` change, no new `unsafe fn` with a safe-looking signature.

Correctness and fallback evidence is in `RECEIPT.md`; the forced-off arm (via
`OPENSSL_ia32cap=":~0x20000000"`) measured **37.1919 µs** versus the authority's
6.2841 µs (ratio 5.860, CI [5.834, 5.981]) with byte-identical KAT and
differential output, i.e. the portable path is live and is the pre-change
implementation.

---

## 6. Residuals (recorded, not hidden)

1. **AES-GCM VAES/VPCLMULQDQ**: `NOT_APPLICABLE_HARDWARE` tied to **V1**; the
   AES-NI + PCLMUL non-VAES arm is unimplemented and its constant-time GHASH
   replacement is a future batch.
2. **ChaCha20-Poly1305 AVX2** (8-way core + Poly1305) unimplemented.
3. **SHA-512** has no applicable ISA extension on this machine.
4. **GHASH timing**: `gf_mul` does not table-lookup on secret data (it is
   bitwise), but it branches on the GHASH block operand; `H` is not branched on.
   This is a pre-existing constant-time residual, unchanged by this batch and not
   a new obligation.
5. **`OPENSSL_ia32cap`** is honoured only for the SHA clear mask; other
   capability reads still ignore it (`RT-CPU-CAPABILITY`).
6. **AArch64 AES/PMULL and SHA2 crypto extensions** are not implemented (no
   AArch64 hardware in this venue); the item's AArch64 arm is unmeasured.
7. The baseline per-repetition timing files were replaced when the final run
   reused the instrument directory; the baseline table above is the recorded
   first run, and the portable SHA-256 arm is re-measured in `fallback-timing/`.
