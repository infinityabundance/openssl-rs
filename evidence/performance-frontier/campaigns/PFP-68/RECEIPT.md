# PFP-68 — profile first, then convert the GHASH representation

Source identity: `staging` HEAD `c27e9373` plus the required working-tree
`pub(crate) mod cpu;` declaration in `src/runtime/mod.rs`. No commit or push
was made. Final candidate DSO
`f53e2622112379f9a74b584a336b52cf282b7b38c83949efacb3a1a33c9ad926`;
authority DSO
`611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.

## 1. What the profile said (before any optimisation)

One `gf_mul_clmul` call, from callgrind per-instruction counts
(`raw/gf-mul-attribution.txt`), 4,132 calls:
bit reversal **66.46%** (both operands 45.7%, result 20.7%), four CLMULs 4.27%,
reduction 18.90%, stack round-trip **0** (LLVM had already used register moves).
Hypothesis (a) — the bit-order conversion — is the material per-call cost.

CTR/AES answer (`raw/ctr-block-issue.txt`): **yes, one AES block at a time**.
`aes_encrypt_ni` ran 270,864 Ir over ~4,096 calls (66.1 Ir/call): a serial
`aesenc` chain per 16-byte block, independent of GHASH.

## 2. Stages (isolated; `raw/stage-table.txt`)

| stage | 16 KiB | 64 B |
|---|---:|---:|
| baseline | 63.02 us | 1.689 us |
| PFP-69 value-only carriers | 63.11 us (~0) | 1.696 us (~0) |
| PFP-68 reflected domain | 48.81 us (-22.7%) | 1.622 us (-4.4%) |
| PFP-62 group reduction | 45.16 us (-7.5%) | 1.614 us (-0.5%) |
| PFP-5 multi-block AES/VAES | 7.72 us (-82.9%) | 1.500 us (-6.4%) |

Final paired authority ratio: **1.999x at 16 KiB, 2.303x at 64 B**
(from 13.206x / 2.495x). AES-256-GCM: 1.879x / 2.302x.

PFP-69 is reported as a **lost stage**: the before disassembly had no stack
traffic, so making the carriers explicitly value-only changed no instruction
that mattered. It is retained for the boundary (no raw pointer crosses the SIMD
edge; the body is safe Rust inside the classified dispatch).

## 3. Representation change (the correctness trap)

The reflected multiply is `alg9(clmul(x, twist(y)))`, not `alg9(clmul(x, y))`:
the reflected reciprocal-domain product consumes the pre-twisted H operand.
`twist` is the reflected `<<1` with the constant
`0xC2000000000000000000000000000001`. This was established first in
`court/tmp/pfp68/model.py` against the bit-by-bit multiply over 8,000 random
and 64 edge pairs, then in-crate by `clmul_matches_portable_gf_mul` and the
NIST/width tests. Two implementation defects were caught this way before
measurement: the wrong (low-lane `0x1c2`) constant, and a sign-extension of the
`i64` returned by `_mm_cvtsi128_si64` when cast straight to `u128`.

## 4. Differential and KATs

* In-crate: `gcm_stream_path_matches_serial_reference` covers
  (pt,aad) = (0,0),(0,16),(16,0),(64,16),(16384,16) and partials
  1,15,17,31,33,63,65,95,127,129,255,1000 at **every** width 1..=8, for two key
  sizes and two IV lengths; `gcm_stream_path_split_inplace_and_tamper` covers
  split calls, in-place, and ct/aad/tag tamper at widths 2/4/8.
  `gcm_all_widths_match_serial_reference` and the NIST cases run at every
  width. All pass.
* Cross-library: `raw/diff-summary.txt` — ciphertext+tag and open result are
  byte-identical to the pinned authority for AES-128-GCM 64 B/16 KiB and
  AES-256-GCM 16 KiB, and the 16-case KAT transcript is identical, on all five
  arms: default, `~0x2000000` (AES off), `~0x2` (PCLMUL off), `~0x2000002`
  (both off), `0x0:0x0` (value-set). `DIFF_STATUS=0`.

## 5. Boundary classification

* `gf_mul_clmul`, `clmul_twist`, `clmul_reduce` take and return fixed-size
  values only (`_mm_set_epi64x`, `_mm_cvtsi128_si64`/`_mm_unpackhi_epi64`).
  No pointer crosses the SIMD boundary. The kernel is **not** `ZERO_UNSAFE`:
  it has one classified dispatch call (`gf_mul`) establishing `pclmulqdq`.
* New: `aes_ctr32_encrypt_blocks` (classified dispatch to `vaes`/`aes`/
  portable) and `ghash_group_clmul` (dispatched only when `has_pclmul`). Each
  has a `SAFETY:` contract; `unsafe_op_in_unsafe_fn`,
  `undocumented_unsafe_blocks` and `missing_safety_doc` remain deny-level and
  clean.
* Constant time: H and its powers live in stack `u128`s and registers, selected
  only by the public width/loop index; no table is indexed by ciphertext or a
  secret. VAES/AES and GHASH have fixed instruction shape, no secret branches.

## 6. Gate (final tree)

* `cargo fmt --all -- --check`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo test --lib -- --test-threads=4`: **2564 passed, 0 failed, 56 ignored**
  (baseline 2562 + 2 new tests; none newly ignored).
* Same suite with `OPENSSL_ia32cap=0x0:0x0`: **2564 passed, 0 failed, 56
  ignored**.

## 7. Memory

`free -g` before every heavy command: available 19-26 GiB, Swap free 3-6 GiB.
Cap = min(4, available-8) = 4 GiB (>=16 GiB available, swap advisory), set as
`OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g`, `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`; one heavy command at a time, in
`docker/openssl-rs-court.sh`.
