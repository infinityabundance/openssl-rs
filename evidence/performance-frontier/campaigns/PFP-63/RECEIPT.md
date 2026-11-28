# PFP-63 / PFP-64 (phase 1) — RECEIPT

## 1. Identity

| | |
|---|---|
| branch / commit | `staging` `baa48aad0953a738169eaf5b8a133b3b502ad397` (no commit made by this batch) |
| uncommitted build inputs | `src/aes.rs` `7de26c6a…`, `src/modes/gcm.rs` `c9995d06…` (2 files; `git status` build inputs = 2) |
| before source | `src/aes.rs` `bc7142f8…`, `src/modes/gcm.rs` `61f51222…` |
| before DSO | `3c7ced9c5193e7ce5d2a616fb07aa49a8288624359def3e02d13ffc88c7dfc67`, 17 036 744 B, build id `4bec7a59…` |
| after DSO | `c772f71e075065776aae106ed0b1987d4320bf18c1805928ef87c81217e6f807`, 17 162 424 B, build id `3b32cfab…` |
| after archive | `00d49b454b2d93b4d5ebb96938ccbafe6f677c5a934f3c5e00b8123dccba84c5` |
| authority | `openssl-3.6.4-production` DSO `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| instrument | `bench_pfp63` binary `65500d9a…` = PFP-12 `bench_pfp12`; source `8fe9fd3d…` |
| machine / toolchain | i9-13900K, rustc 1.98.1, gcc 12.2.0, no AVX-512 |

Every measurement and audit in `raw/` is bound to the **after DSO** above (the
DSO was rebuilt after the last source edit and the whole diff/timing/audit set was
re-run on that digest; test-only edits do not enter the release artefact, but the
artefact was regenerated and re-measured anyway).

## 2. What changed

* `src/aes.rs` — AES-NI key expansion (`aes_expand_ni`, `ni_subword_pair`) and
  block cipher (`aes_encrypt_ni`, `aes_decrypt_ni`) for 128/192/256, behind one
  production `is_x86_feature_detected!("aes")` predicate (`aes_ni_available`).
  The portable table path is retained as the fallback and is **not** claimed
  constant-time.
* `src/modes/gcm.rs` — PCLMULQDQ field multiply (`gf_mul_clmul`), two-fold bounded
  reduction (`reduce_gcm`), behind one production
  `is_x86_feature_detected!("pclmulqdq")` predicate (`pclmul_available`). The
  bit-by-bit `gf_mul_portable` is retained as the fallback.
* No `#[no_mangle]`, `#[repr(C)]`, layout, exported-signature or `CRYPTO_*` seam
  change. `AesKey` and `GcmCtx` are unchanged.
* Three new tests: `aes_ni_matches_portable`, `clmul_matches_portable_gf_mul`,
  `gcm_rejects_tampered_ciphertext_aad_and_tag`.

## 3. Hardware truth and positive controls (`raw/hardware-truth.txt`)

`aes=1 pclmulqdq=1 sse2=1 ssse3=1 avx=1 avx2=1 vaes=1 vpclmulqdq=1
avx512f=0 avx512vl=0`; `XCR0=0x207 os_avx=1 os_avx512=0`. Executed controls:
`aes_control=PASS` (FIPS-197 C.1), `pclmul_control=PASS` (software reference),
`vaes_control=PASS`, `vpclmul_control=PASS` (256-bit forms, no AVX-512).
`poscontrol=PASS`. The "VAES needs AVX-512" premise is disproved on this host.

## 4. `gf_mul` adjudication (`raw/gf_mul-before-adjudication.txt`)

`gf_mul` is inlined in the before DSO. In the shipped instructions the two source
conditionals are **cmov/mask**, not branches
(`test cl,0x40; cmovne …` and `test r11b,0x1; cmovne`); the only conditional
transfer is the fixed 128-count loop back-edge `add ecx,-1; jb` (`ecx` starts
`0x7f`). No secret-indexed memory in that loop. The source-shape claim that
`gf_mul` branches is withdrawn **for this digest**, on instructions.

## 5. Reduction bound

Modulus `x^128+x^7+x^2+x+1`; product degree ≤254 = `hi·x^128+lo`, `deg hi≤126`.
Fold 1: `lo + hi·q`, `deg(hi·q)≤133`, carry ≤5 (≤7 bits). Fold 2: `carry·q`,
`deg ≤ 12 < 128`. Two folds, fixed shifts/XORs, no loop, no branch, no
data-dependent count.

## 6. Unsafe surface

Six boundary IDs: `B-AES-DETECT`, `B-AES-EXPAND`, `B-AES-ENC`, `B-AES-DEC`,
`B-GHASH-DETECT`, `B-GHASH-MUL` (details in `BOUNDS.md` §5). Each `#[target_feature]`
callee has one `unsafe {}` with a `SAFETY:` contract; each dispatcher makes one
guarded call. `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks`,
`missing_safety_doc` remain deny-level and clean. Eliminated on the fast path:
S-box table indexing and the 128-iteration GHASH loop. Relocated: SIMD/provenance
obligations into the six boundaries. Hidden: 0 found. Retained: the portable table
and bit-by-bit paths.

## 7. Correctness before timing

* NI vs portable: 64 random keys/size → identical schedules and blocks; decrypt
  round-trip recovers the plaintext.
* CLMUL vs portable: 512 random + 36 edge pairs + `E(K,0)`-shaped keys → equal.
* Tamper: one-bit flip in ciphertext, AAD or tag each rejected; clean accepted.
* FIPS-197 C.1/C.2/C.3 and NIST GCM cases 1/2/5 pass.
* Cross-library: 4 ops + 16 KATs, **IDENTICAL** to the authority on all five arms
  (`before`, `after`, `off`, `off-aes`, `off-pclmul`); `mismatches=0`.

## 8. Performance (`raw/timing-*.json`; cand/auth, >1 = slower)

| op | before | before ratio | after | after ratio [95% CI] |
|---|---:|---|---:|---|
| AES-128-GCM 64 B | 4.5689 µs | 7.025 | 1.6253 µs | **2.495** [2.490, 2.512] |
| AES-128-GCM 16 KiB | 513.9942 µs | 135.707 | 50.0287 µs | **13.206** [13.159, 13.242] |
| AES-256-GCM 64 B | 5.0760 µs | 7.676 | 1.6572 µs | **2.504** [2.490, 2.517] |
| AES-256-GCM 16 KiB | 601.8505 µs | 138.558 | 50.7984 µs | **11.687** [11.670, 11.717] |

Forced off (`OPENSSL_ia32cap='~0x2000002'`) — still correct, reproduces baseline:
6.960 / 134.208 (128 b), 7.652 / 138.241 (256 b). The 16 KiB ratio drops ~10.4×.

## 9. Instruction audit (`raw/audit-after.json`)

| carrier | jcc | setcc | cmov | indexed memory | SIMD |
|---|---:|---:|---:|---:|---|
| `aes_encrypt_ni` | 6 (round count) | 0 | 0 | 2 (input, round key) | `aesenc`,`aesenclast` |
| `aes_decrypt_ni` | 6 (round count) | 0 | 0 | 2 (input, round key) | `aesdec`,`aesdeclast` |
| `aes_expand_ni` | 8 (null/key size/loop) | 1 (key size) | 1 (key size) | 0 | `aeskeygenassist` |
| `gf_mul_clmul` | **0** | **0** | **0** | **0** | 4× `pclmul*` |

The fast path has **no table indexing at all**. The wrappers (`crypt`,
`CRYPTO_gcm128_aad/_finish/_setiv`) contain public-metadata branches plus the
inlined portable fallback (cmov loop), skipped when the feature bit is set.

## 10. Gate

* `cargo fmt --all -- --check`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo test --lib -- --test-threads=4`: **2544 passed, 0 failed, 56 ignored**
  (baseline 2541 passed / 0 / 56; +3 new tests; none newly ignored).

## 11. Memory

`free -g` before each heavy command: available **20–24 GiB**, swap free **8–9 GiB**;
`cap = min(4, available-8) = 4 GiB` (floor 2). Commands ran in the court with
`Mem=MemSwap=4294967296` (4 GiB), `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`, one heavy command at a time.

## 12. Not claimed

Portable table AES is **not** constant-time (S-box indexed by secret state; STOP
**open**). Portable GHASH is **not** claimed constant-time. The fast path claim is
only "no secret-indexed memory access, no secret-derived branch, no secret-derived
address at this digest"; it is not a cache/latency proof. No
`SAFETY_DISCHARGED`/`SAFE_COMPATIBLE` promotion and no closure of PFP-63. VAES/
VPCLMUL are not used. No throughput-parity claim (still 2.5× / ~12–13×).
