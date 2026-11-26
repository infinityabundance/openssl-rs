# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp31/repair/r/distribution/libcrypto.so.3`
- SHA-256: `43a23e9b7b4628cb236d75bb8bc4b73583a035f3335bd0244f1771e81b773557`
- objdump: `GNU objdump (GNU Binutils for Debian) 2.40`
- Secret-dependence is NOT established here. A conditional jump is
  listed because the compiler emitted it in the named function; the
  reviewer maps each condition to the Rust source's secret
  classification. BINSEC `-checkct` (T16) can establish control-flow
  and memory-address dependence on a declared secret split; it does
  not model microarchitectural timing.

## Per-function summary

| function | symbol @ offset | bytes | insns | jcc | div/idiv | cmov | setcc | jo/jno | loop | calls | cpuid |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_sos_into` @ 0x585410 | 1013 | 249 | 19 | 0 | 0 | 10 | 0 | 0 | 5 | 0 |
| Montgomery ladder carrier (ladder multiplies inlined here) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith15run_mont_ladder` @ 0x5840c0 | 3383 | 734 | 51 | 0 | 2 | 11 | 0 | 0 | 49 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x166640 | 961 | 231 | 17 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x585e20 (carries `mod_exp_core_consttime_from_parts`) | 1693 | 430 | 42 | 0 | 2 | 4 | 0 | 0 | 20 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x287110 | 9648 | 2225 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x28cd90 | 3158 | 780 | 125 | 0 | 5 | 7 | 1 | 0 | 78 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x2fce90 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x1ca940 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x1c5310 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x1c5130 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| DH key agreement (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2dh3key19ossl_dh_compute_key` @ 0x28aa90 | 1281 | 294 | 36 | 0 | 1 | 0 | 1 | 0 | 32 | 0 |
| EC wNAF multiply (verification / public-scalar core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` @ 0x28b510 | 5396 | 1236 | 147 | 4 | 34 | 3 | 2 | 0 | 80 | 0 |
| ML-KEM decapsulation (provider driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` @ 0x1d06e0 | 998 | 210 | 15 | 0 | 1 | 4 | 0 | 0 | 13 | 0 |
| ML-KEM K-PKE decrypt | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11decrypt_cpa` @ 0x296690 | 2864 | 683 | 37 | 0 | 0 | 6 | 0 | 0 | 10 | 0 |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11encrypt_cpa` @ 0x2971c0 | 8922 | 1844 | 44 | 0 | 6 | 46 | 2 | 0 | 16 | 0 |
| ML-KEM inverse NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith18scalar_inverse_ntt` @ 0x29a3d0 | 1366 | 295 | 12 | 0 | 13 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM inner product | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13inner_product` @ 0x299610 | 2209 | 455 | 11 | 0 | 2 | 12 | 1 | 0 | 1 | 0 |
| ML-KEM matrix transpose-multiply-add | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith25matrix_mult_transpose_add` @ 0x29a930 | 2439 | 513 | 10 | 0 | 3 | 12 | 0 | 0 | 0 | 0 |
| ML-KEM matrix expansion (public) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13matrix_expand` @ 0x299ec0 | 584 | 134 | 16 | 0 | 0 | 0 | 0 | 0 | 6 | 0 |
| ML-KEM vector decode 12-bit | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith16vector_decode_12` @ 0x29a200 | 136 | 35 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-KEM vector encode | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13vector_encode` @ 0x29a110 | 237 | 71 | 10 | 0 | 0 | 0 | 0 | 0 | 5 | 0 |
| ML-KEM CBD sampling eta=2 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_2` @ 0x29b400 | 413 | 93 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD sampling eta=3 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_3` @ 0x29b5a0 | 1021 | 239 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD vector sampling then NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` @ 0x29a290 | 312 | 83 | 3 | 0 | 0 | 1 | 0 | 0 | 2 | 0 |
| ML-KEM hash H | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_h` @ 0x29ba60 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM hash G | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_g` @ 0x29b9a0 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM public-key hash | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13hash_h_pubkey` @ 0x2994a0 | 358 | 104 | 7 | 0 | 0 | 2 | 0 | 0 | 6 | 0 |
| ML-KEM KDF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3kdf` @ 0x29b2c0 | 128 | 46 | 3 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM PRF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3prf` @ 0x29b340 | 177 | 60 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356` @ 0x1d32b0 | 1554 | 341 | 16 | 0 | 1 | 1 | 0 | 0 | 9 | 0 |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith10scalar_ntt.llvm.8914366393463869599` @ 0x296280 | 1030 | 235 | 10 | 0 | 14 | 0 | 0 | 0 | 3 | 0 |

## Coverage

- expected targets: 31
- resolved uniquely and disassembled: 31
- of those, audited through a verified inline mapping: 1
  - Constant-time ladder core: intended `mod_exp_core_consttime_from_parts` -> carrier `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared`
- failed: 0

## Inline mappings declared by the inventory

A mapping is admitted only when the audit re-establishes the name derivation (`resolves_to` is `symbol` + `suffix`), the carrier's extent, a direct call from the declared caller, the wrapper's constant argument at that site, and the producer string in this DSO. It does not prove the wrapper was inlined rather than source-edited away; those are the same instructions (see the module docstring).

| target | carrier | state | caller | call site | constant | carrier extent | producer |
|---|---|---|---|---|---|---:|---|
| `mod_exp_core_consttime_from_parts` | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` | **verified, audited** | `BN_mod_exp` | +0x181 | `push $0x0` | 1693 B | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **Constant-time ladder core** recorded check: mod_exp_core_consttime_from_parts(ad, pd, md, n) is the one-line forwarder to mod_exp_core_consttime_from_parts_prepared(ad, pd, md, n, None); in the release DSO its only non-test caller BN_mod_exp calls the prepared entry directly with the None tag, so no out-of-line body of the wrapper is emitted

## LLVM-suffixed local copies declared by the inventory

The exact-identifier rule is unchanged. A suffixed copy is admitted only when the whole symbol matches the v0 structural form with exact length prefixes, no alias shares its start address, the producer string is in this DSO, and a declared caller has a direct call to the copy. The call site is the witness that the reviewed path reaches this body; it does not prove source identity beyond those facts (see the module docstring).

| target | observed suffix | extent | caller | direct call sites | producer |
|---|---|---:|---|---|---|
| `key::decap` | `3key5decap.llvm.8141794212082648356` | 1554 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` | +0x108, +0x216, +0x300 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |
| `arith::scalar_ntt` | `5arith10scalar_ntt.llvm.8914366393463869599` | 1030 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` | +0x65 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **ML-KEM decapsulation carrier (implicit-rejection comparison + select)** recorded check: src/ml_kem/key.rs::decap is the only body of the identifier. The release DSO has no unsuffixed symbol for it; the only defined .text symbol of that identifier is the .llvm.<digits> local copy, and ossl_ml_kem_decap calls that entry directly at three sites. The copy contains the inlined CRYPTO_memcmp accumulation, the constant_time_eq_int_8 mask and the constant_time_select_8 store loop of src/ml_kem/key.rs:633-639.

- **ML-KEM forward NTT (used by re-encryption on secret-derived data)** recorded check: src/ml_kem/arith.rs::scalar_ntt has no unsuffixed out-of-line body in the release DSO; its only defined .text symbol of that identifier is the .llvm.<digits> local copy. gencbd_vector_ntt calls that entry directly, and the same single entry is the target of two further direct calls in the file (recorded in MLKEM-REJECTION.md). The loop bounds are fixed by the degree; the value-dependent reductions compile to cmovcc, which the per-function counts report.

## Comparison-result branch contract

Register taint is seeded on the XOR/OR comparison accumulation and propagated over the basic-block CFG. `public-bound` means no tracked comparison register reaches the condition, not that the branch is harmless. Memory and implicit flow are not modelled.

### ML-KEM decapsulation carrier (implicit-rejection comparison + select)

- accumulated registers: `xmm0`, `xmm1`
- accumulation loop 0x1d359c..0x1d35cb: `xmm0`, `xmm1`

| kind | addr | instruction | condition source | class |
|---|---|---|---|---|
| jcc | `0x1d3350` | `je 1d345f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x1af>` | `0x1d334e: test %eax,%eax` | **public-bound** |
| jcc | `0x1d3369` | `je 1d345f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x1af>` | `0x1d3367: test %eax,%eax` | **public-bound** |
| jcc | `0x1d3380` | `je 1d345f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x1af>` | `0x1d337e: test %eax,%eax` | **public-bound** |
| jcc | `0x1d339b` | `je 1d345f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x1af>` | `0x1d3399: test %eax,%eax` | **public-bound** |
| jcc | `0x1d3405` | `je 1d353c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x28c>` | `0x1d33fb: test %eax,%eax` | **public-bound** |
| jcc | `0x1d3428` | `je 1d353c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x28c>` | `0x1d3426: test %eax,%eax` | **public-bound** |
| jcc | `0x1d3435` | `je 1d355e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x2ae>` | `0x1d3432: test %rax,%rax` | **public-bound** |
| jcc | `0x1d343e` | `je 1d356d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x2bd>` | `0x1d343b: test %r14,%r14` | **public-bound** |
| jcc | `0x1d3450` | `jae 1d357f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x2cf>` | `0x1d3444: cmp $0x4,%rax` | **public-bound** |
| jcc | `0x1d3583` | `jae 1d358b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x2db>` | `0x1d357f: cmp $0x20,%rax` | **public-bound** |
| jcc | `0x1d35cb` | `jne 1d359c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x2ec>` | `0x1d35c8: cmp %rdx,%rcx` | **public-bound** |
| jcc | `0x1d3604` | `je 1d3671 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x3c1>` | `0x1d3601: cmp %rcx,%rax` | **public-bound** |
| jcc | `0x1d3608` | `je 1d365e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x3ae>` | `0x1d3606: test $0x1c,%al` | **public-bound** |
| jcc | `0x1d3636` | `jne 1d3620 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x370>` | `0x1d3633: cmp %rsi,%rcx` | **public-bound** |
| jcc | `0x1d366f` | `jne 1d365e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x3ae>` | `0x1d366c: cmp %rcx,%rax` | **public-bound** |
| setcc | `0x1d3675` | `setne %al` | `0x1d3673: test %dl,%dl` | **secret-derived** |
| cmov | `0x1d3696` | `cmovne %rcx,%rdx` | `0x1d3689: cmpl $0x0,0xa0(%rsp)` | **public-bound** |
| jcc | `0x1d36d7` | `jne 1d36a0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.8141794212082648356+0x3f0>` | `0x1d36d3: cmp $0x20,%rcx` | **public-bound** |

- secret-derived conditional jumps: 0
- undetermined conditions: 0

## Divisions

- **EC wNAF multiply (verification / public-scalar core)** `+0x653` (0x28bb63): `div %rcx`
- **EC wNAF multiply (verification / public-scalar core)** `+0x84a` (0x28bd5a): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0x89d` (0x28bdad): `div %ecx`
- **EC wNAF multiply (verification / public-scalar core)** `+0x1107` (0x28c617): `div %esi`

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d238, 0x16d259, 0x16d27a, 0x16d291, 0x16d2e3, 0x16d2fa, 0x16d485, 0x16d593, 0x16d639, 0x16d7f8, 0x1c57bb, 0x1c7cb4, 0x1c7d22, 0x1c7d90, 0x1c7dfe, 0x2a9ddc, 0x2a9e0c, 0x32709c, 0x32974c, 0x32c48c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x33 | jne | reg/arith | `0x585440: or %r9,%rax` | memory | 0x585560 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x4c | jne | reg/arith | `0x585459: cmp %rax,%rcx` | memory | 0x585560 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x7d | je | reg/arith | `0x58548a: test %r14,%r14` | memory | 0x585562 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xe1 | je | reg/arith | `0x5854ee: cmp %rdi,%rbp` | memory | 0x585571 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xf4 | je | reg/arith | `0x585501: test %rax,%rax` | memory | 0x5854c0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x142 | jne | reg/arith | `0x58554f: cmp %r8,%r13` | arithmetic/control | 0x585510 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x148 | jne | reg/arith | `0x585554: test $0x1,%dil` | arithmetic/control | 0x5854c0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1bd | je | reg/arith | `0x5855ca: cmp %rdi,%rax` | memory | 0x58567a | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1cb | je | mem | `0x5855d3: cmp 0x90(%rsp),%r9` | memory | 0x5857ca | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x203 | je | reg/arith | `0x585610: cmp %rsi,%rbx` | memory | 0x5857af | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x22f | jne | reg/arith | `0x58563c: cmp %rsi,%rdi` | memory | 0x585610 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x23d | je | mem | `0x585648: cmp 0x28(%rsp),%r9` | memory | 0x5855b0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x263 | jne | reg/arith | `0x585670: cmp %rax,%rbp` | arithmetic/control | 0x585660 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x282 | je | reg/arith | `0x58568f: test %rdx,%rdx` | memory | 0x585702 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2e8 | jne | reg/arith | `0x5856f5: cmp %rsi,%r13` | arithmetic/control | 0x5856c0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2ee | jne | reg/arith | `0x5856fa: test $0x1,%dil` | arithmetic/control | 0x58571d | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x367 | jae | reg/arith | `0x585774: cmp %r14,%rcx` | arithmetic/control | 0x5857f2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x36c | je | reg/arith | `0x585779: cmp %r10,%rdi` | memory | 0x5857e2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x398 | jne | reg/arith | `0x5857a4: add $0xfffffffffffffff8,%r8` | arithmetic/control | 0x585770 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e | jne | reg/arith | `0x5840ea: shr $0x3a,%rax` | memory | 0x584742 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4d | jbe | reg/arith | `0x58410a: cmp %rbx,%rdx` | call+memory | 0x5841f0 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6c | je | reg/arith | `0x584128: cmp $0xffffffffffffffff,%r12` | memory | 0x5842bb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8d | jne | reg/arith | `0x584142: test %rbx,%rbx` | memory | 0x584574 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc7 | jne | reg/arith | `0x584185: or %al,%cl` | memory | 0x5841c8 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x106 | jne | reg/arith | `0x5841c3: cmp %rax,%rsi` | arithmetic/control | 0x584190 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10b | je | reg/arith | `0x5841c8: test %r12,%r12` | memory | 0x5841db | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x141 | jne | reg/arith | `0x5841fe: test %rbx,%rbx` | memory | 0x584473 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x18c | jne | reg/arith | `0x584248: cmp $0xffffffffffffffff,%rax` | memory | 0x584357 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x19c | je | reg/arith | `0x584259: test %rbx,%rbx` | memory | 0x5842ca | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1e6 | jne | reg/arith | `0x5842a3: cmp %rax,%rbx` | memory | 0x584270 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x22e | jne | reg/arith | `0x5842ec: or %cl,%dl` | memory | 0x584330 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x26e | jne | reg/arith | `0x58432b: cmp %rdx,%rsi` | arithmetic/control | 0x584300 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x273 | je | reg/arith | `0x584330: test %rax,%rax` | memory | 0x584345 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2b5 | jne | reg/arith | `0x584372: test %rbx,%rbx` | call+memory | 0x5844bc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e8 | je | mem | `0x58439e: cmpb $0x0,0x10(%rsp)` | memory | 0x584cb7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x321 | jne | reg/arith | `0x5843df: or %al,%cl` | memory | 0x584428 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x366 | jne | reg/arith | `0x584423: cmp %rax,%rsi` | arithmetic/control | 0x5843f0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x36b | je | reg/arith | `0x584428: test %rdx,%rdx` | memory | 0x584441 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x38c | je | reg/arith | `0x584441: test %rbx,%rbx` | memory | 0x5844fc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x3e9 | je | mem | `0x5844a4: cmpb $0x0,0x10(%rsp)` | memory | 0x584630 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x426 | je | mem | `0x5844e1: cmpb $0x0,0x10(%rsp)` | memory | 0x5846c2 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x45c | jne | reg/arith | `0x58451a: or %al,%cl` | memory | 0x584558 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x496 | jne | reg/arith | `0x584553: cmp %rax,%rsi` | arithmetic/control | 0x584520 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x49b | je | reg/arith | `0x584558: test %rdi,%rdi` | memory | 0x584259 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4e2 | je | mem | `0x58459d: cmpb $0x0,0x10(%rsp)` | memory | 0x58467e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x510 | jne | reg/arith | `0x5845ce: or %al,%cl` | memory | 0x58460c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x54a | jne | reg/arith | `0x584607: cmp %rax,%rsi` | memory | 0x5845d4 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x557 | je | reg/arith | `0x58460c: test %r12,%r12` | memory | 0x5842ca | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x57c | je | reg/arith | `0x584638: cmp $0x1,%rbx` | memory | 0x584659 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x5ca | je | reg/arith | `0x584686: cmp $0x1,%rbx` | memory | 0x5846a7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x615 | je | reg/arith | `0x5846d1: cmp $0x1,%rbx` | memory | 0x5846fa | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x666 | je | mem | `0x584721: cmpb $0x0,0x10(%rsp)` | memory | 0x58474e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x69f | je | reg/arith | `0x58475b: cmp $0x1,%rbx` | memory | 0x58477c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6fd | je | mem | `0x5847b8: cmpb $0x0,0x10(%rsp)` | memory | 0x5847c9 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x759 | je | mem | `0x584814: cmpb $0x0,0x10(%rsp)` | memory | 0x5848a1 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7b6 | jne | reg/arith | `0x584873: cmp %rax,%rcx` | memory | 0x584847 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7ef | je | reg/arith | `0x5848ab: cmp $0x1,%rbx` | memory | 0x5848d4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x840 | je | mem | `0x5848fb: cmpb $0x0,0x10(%rsp)` | memory | 0x584920 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x877 | je | reg/arith | `0x584933: cmp $0x1,%rbx` | memory | 0x58495c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8cd | je | mem | `0x584984: cmpq $0x0,0x80(%rsp)` | memory | 0x584b55 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x930 | jae | mem | `0x5849eb: cmp 0x78(%rsp),%rdi` | memory | 0x584d16 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x994 | je | reg/arith | `0x584a52: test %al,%al` | memory | 0x584b44 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9a3 | je | mem | `0x584a5a: cmpq $0x0,0x98(%rsp)` | memory | 0x584ab4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9f2 | jne | mem | `0x584aaa: cmp %rcx,0x98(%rsp)` | memory | 0x584a78 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa36 | je | reg/arith | `0x584af4: test %al,%al` | memory | 0x584b44 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa7c | jne | mem | `0x584b34: cmp 0x80(%rsp),%rsi` | arithmetic/control | 0x5849d3 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xad9 | je | reg/arith | `0x584b97: test %al,%al` | memory | 0x584c25 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xbdd | jne | reg/arith | `0x584c9a: cmp %rax,%r13` | memory | 0x584c6f | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc97 | je | reg/arith | `0x584d54: test %rbx,%rbx` | memory | 0x584d71 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xcdd | je | reg/arith | `0x584d9a: test %rbx,%rbx` | memory | 0x584db7 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x166679: test %rbx,%rbx` | memory | 0x1666d0 | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x1666b6: cmpb $0x0,0x8(%rsp)` | memory | 0x166715 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | jne | reg/arith | `0x1666c5: test %rbx,%rbx` | arithmetic/control | 0x1668e6 | fwd |
| Montgomery multiply (allocating wrapper) | +0xb8 | je | mem | `0x1666f3: cmpb $0x0,0x8(%rsp)` | memory | 0x166909 | fwd |
| Montgomery multiply (allocating wrapper) | +0xe4 | jne | reg/arith | `0x166721: test %rbx,%rbx` | memory | 0x166941 | fwd |
| Montgomery multiply (allocating wrapper) | +0x12a | je | reg/arith | `0x166768: test %al,%al` | memory | 0x166828 | fwd |
| Montgomery multiply (allocating wrapper) | +0x143 | je | reg/arith | `0x166780: test %rbx,%rbx` | memory | 0x1667d9 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x1667c3: cmp %rax,%rbx` | memory | 0x166790 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x166813: cmp %rax,%r14` | arithmetic/control | 0x1667e0 | back |
| Montgomery multiply (allocating wrapper) | +0x1f3 | je | reg/arith | `0x166830: test %rbx,%rbx` | memory | 0x166886 | fwd |
| Montgomery multiply (allocating wrapper) | +0x236 | jne | reg/arith | `0x166873: cmp %rax,%rsi` | memory | 0x166840 | back |
| Montgomery multiply (allocating wrapper) | +0x286 | jne | reg/arith | `0x1668c3: cmp %rax,%r14` | memory | 0x166890 | back |
| Montgomery multiply (allocating wrapper) | +0x2a0 | je | reg/arith | `0x1668dd: test %rbx,%rbx` | arithmetic/control | 0x166706 | back |
| Montgomery multiply (allocating wrapper) | +0x2d5 | je | reg/arith | `0x166911: cmp $0x1,%rbx` | memory | 0x166932 | fwd |
| Montgomery multiply (allocating wrapper) | +0x343 | je | mem | `0x16697e: cmpb $0x0,0x8(%rsp)` | memory | 0x166992 | fwd |
| Montgomery multiply (allocating wrapper) | +0x35b | jne | reg/arith | `0x166997: cmp $0x1,%rbx` | arithmetic/control | 0x1669a5 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3a1 | je | reg/arith | `0x1669de: test %rbx,%rbx` | memory | 0x1669f9 | fwd |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x585e36: test %r12,%r12` | memory | 0x585ea8 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x585e51: cmp $0x1,%r12` | memory | 0x585e79 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x585e5a: cmp $0x1,%r15` | memory | 0x585e7c | fwd |
| Constant-time ladder core | +0x60 | jne | reg/arith | `0x585e7c: test $0x1,%r15b` | call | 0x585e9c | fwd |
| Constant-time ladder core | +0x86 | jbe | reg/arith | `0x585ea3: cmp %rbx,%r13` | memory | 0x585ebe | fwd |
| Constant-time ladder core | +0xe1 | je | mem | `0x585efc: cmpb $0x0,0x10(%rsp)` | memory | 0x585f11 | fwd |
| Constant-time ladder core | +0x102 | je | reg/arith | `0x585f19: cmp $0x1,%rbx` | memory | 0x585f51 | fwd |
| Constant-time ladder core | +0x154 | jae | reg/arith | `0x585f70: cmp $0x18,%rcx` | memory | 0x585f85 | fwd |
| Constant-time ladder core | +0x186 | je | reg/arith | `0x585fa3: cmp %rdi,%r8` | arithmetic/control | 0x586021 | fwd |
| Constant-time ladder core | +0x191 | jae | reg/arith | `0x585fae: cmp %r13,%r8` | memory | 0x585fe4 | fwd |
| Constant-time ladder core | +0x1a2 | jb | reg/arith | `0x585fbf: cmp %r13,%r8` | memory | 0x585ff3 | fwd |
| Constant-time ladder core | +0x1b1 | jb | reg/arith | `0x585fce: cmp %r13,%r8` | memory | 0x586004 | fwd |
| Constant-time ladder core | +0x1c0 | jb | reg/arith | `0x585fdd: cmp %r13,%r8` | arithmetic/control | 0x585f93 | back |
| Constant-time ladder core | +0x1d1 | jae | reg/arith | `0x585fee: cmp %r13,%r8` | memory | 0x585fc4 | back |
| Constant-time ladder core | +0x1e2 | jae | reg/arith | `0x585fff: cmp %r13,%r8` | memory | 0x585fd3 | back |
| Constant-time ladder core | +0x1f3 | jb | reg/arith | `0x586010: cmp %r13,%r8` | arithmetic/control | 0x585f93 | back |
| Constant-time ladder core | +0x204 | je | reg/arith | `0x586021: test %rax,%rax` | memory | 0x586066 | fwd |
| Constant-time ladder core | +0x22c | je | reg/arith | `0x586049: cmp %r8,%rax` | memory | 0x586066 | fwd |
| Constant-time ladder core | +0x235 | jb | reg/arith | `0x586052: cmp %r13,%r9` | memory | 0x58603e | back |
| Constant-time ladder core | +0x244 | jne | reg/arith | `0x586061: cmp %r8,%rax` | arithmetic/control | 0x58604e | back |
| Constant-time ladder core | +0x249 | je | reg/arith | `0x586066: test %r14,%r14` | memory | 0x5860d6 | fwd |
| Constant-time ladder core | +0x252 | jne | reg/arith | `0x58606f: test %r12,%r12` | memory | 0x58636d | fwd |
| Constant-time ladder core | +0x2b9 | je | reg/arith | `0x5860d6: test %r12,%r12` | arithmetic/control | 0x58644e | fwd |
| Constant-time ladder core | +0x2c6 | jne | reg/arith | `0x5860e2: shr $0x3a,%rax` | arithmetic/control | 0x58639b | fwd |
| Constant-time ladder core | +0x2d3 | jne | reg/arith | `0x5860ef: shr $0x39,%rax` | call+memory | 0x58639b | fwd |
| Constant-time ladder core | +0x2f6 | je | reg/arith | `0x586112: cmp $0xffffffffffffffff,%r14` | call+memory | 0x58639b | fwd |
| Constant-time ladder core | +0x334 | je | reg/arith | `0x586146: cmp $0xffffffffffffffff,%rbp` | memory | 0x5862d5 | fwd |
| Constant-time ladder core | +0x34c | je | reg/arith | `0x586164: test %r8,%r8` | arithmetic/control | 0x586461 | fwd |
| Constant-time ladder core | +0x3f3 | je | mem | `0x5861fe: cmpq $0xffffffffffffffff,0x10(%rsp)` | memory | 0x5862de | fwd |
| Constant-time ladder core | +0x437 | je | reg/arith | `0x586254: test %rbp,%rbp` | memory | 0x586270 | fwd |
| Constant-time ladder core | +0x46a | jne | reg/arith | `0x586288: or %al,%cl` | memory | 0x5862c7 | fwd |
| Constant-time ladder core | +0x4a5 | jne | reg/arith | `0x5862c2: cmp %rax,%rsi` | arithmetic/control | 0x58628e | back |
| Constant-time ladder core | +0x4aa | je | reg/arith | `0x5862c7: test %r14,%r14` | arithmetic/control | 0x5863a7 | fwd |
| Constant-time ladder core | +0x4c8 | je | reg/arith | `0x5862e5: test %rbp,%rbp` | memory | 0x586301 | fwd |
| Constant-time ladder core | +0x4fb | jne | reg/arith | `0x586319: or %al,%cl` | memory | 0x586358 | fwd |
| Constant-time ladder core | +0x536 | jne | reg/arith | `0x586353: cmp %rax,%rsi` | arithmetic/control | 0x58631f | back |
| Constant-time ladder core | +0x53b | je | reg/arith | `0x586358: test %r14,%r14` | memory | 0x5863a7 | fwd |
| Constant-time ladder core | +0x579 | je | mem | `0x586394: cmpb $0x0,0x10(%rsp)` | memory | 0x586405 | fwd |
| Constant-time ladder core | +0x58a | je | reg/arith | `0x5863a7: test %rbx,%rbx` | memory | 0x585eaf | back |
| Constant-time ladder core | +0x5ca | jne | reg/arith | `0x5863e7: cmp %rax,%rsi` | memory | 0x5863bc | back |
| Constant-time ladder core | +0x5f1 | je | reg/arith | `0x58640d: cmp $0x1,%r12` | memory | 0x586431 | fwd |
| Constant-time ladder core | +0x65f | je | reg/arith | `0x58647c: test %rbp,%rbp` | memory | 0x586498 | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x287124: test %r8,%r8` | memory | 0x28717b | fwd |
| Constant-time inversion | +0x1c | je | mem | `0x287129: testb $0x1,(%rcx)` | arithmetic/control | 0x28717b | fwd |
| Constant-time inversion | +0x2f | jne | reg/arith | `0x28713b: shr $0x39,%rdi` | memory | 0x28717b | fwd |
| Constant-time inversion | +0x66 | je | mem | `0x287171: cmpb $0x0,0x18(%rsp)` | memory | 0x287194 | fwd |
| Constant-time inversion | +0x90 | je | reg/arith | `0x28719c: cmp $0x1,%rbx` | memory | 0x2871bd | fwd |
| Constant-time inversion | +0x104 | je | mem | `0x28720f: cmpb $0x0,0x18(%rsp)` | memory | 0x28727b | fwd |
| Constant-time inversion | +0x14e | jne | reg/arith | `0x28725b: cmp %rcx,%rbx` | memory | 0x287230 | back |
| Constant-time inversion | +0x177 | je | reg/arith | `0x287283: cmp $0x1,%rbx` | memory | 0x2872a4 | fwd |
| Constant-time inversion | +0x1f5 | je | mem | `0x287300: cmpb $0x0,0x18(%rsp)` | memory | 0x287361 | fwd |
| Constant-time inversion | +0x237 | jne | reg/arith | `0x287344: cmp %rcx,%rsi` | memory | 0x287319 | back |
| Constant-time inversion | +0x263 | je | mem | `0x28736e: cmpq $0x1,(%rsp)` | memory | 0x287391 | fwd |
| Constant-time inversion | +0x2d5 | je | mem | `0x2873e0: cmpb $0x0,0x18(%rsp)` | memory | 0x287470 | fwd |
| Constant-time inversion | +0x2ff | jne | reg/arith | `0x28740d: or %cl,%dl` | memory | 0x28744f | fwd |
| Constant-time inversion | +0x339 | jne | reg/arith | `0x287446: cmp %rcx,%rsi` | memory | 0x28741b | back |
| Constant-time inversion | +0x342 | je | reg/arith | `0x28744f: test %rax,%rax` | memory | 0x287307 | back |
| Constant-time inversion | +0x372 | je | mem | `0x28747d: cmpq $0x1,(%rsp)` | memory | 0x2874a8 | fwd |
| Constant-time inversion | +0x3e8 | je | mem | `0x2874f3: cmpb $0x0,0x18(%rsp)` | memory | 0x287585 | fwd |
| Constant-time inversion | +0x416 | jne | reg/arith | `0x287524: or %cl,%al` | memory | 0x287562 | fwd |
| Constant-time inversion | +0x450 | jne | reg/arith | `0x28755d: cmp %rcx,%rsi` | memory | 0x287532 | back |
| Constant-time inversion | +0x457 | je | mem | `0x287562: cmpq $0x0,(%rsp)` | memory | 0x28757c | fwd |
| Constant-time inversion | +0x483 | je | reg/arith | `0x28758f: cmp $0x1,%rbx` | memory | 0x2875b5 | fwd |
| Constant-time inversion | +0x4ee | je | mem | `0x2875f9: cmpb $0x0,0x18(%rsp)` | memory | 0x287609 | fwd |
| Constant-time inversion | +0x507 | je | reg/arith | `0x287613: cmp $0x1,%rbx` | memory | 0x287639 | fwd |
| Constant-time inversion | +0x562 | je | mem | `0x28766c: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x28790d | fwd |
| Constant-time inversion | +0x599 | je | mem | `0x2876a3: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x287916 | fwd |
| Constant-time inversion | +0x5d0 | je | mem | `0x2876da: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x28920d | fwd |
| Constant-time inversion | +0x607 | je | mem | `0x287711: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x289216 | fwd |
| Constant-time inversion | +0x63f | je | mem | `0x287749: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x28921f | fwd |
| Constant-time inversion | +0x677 | je | mem | `0x287781: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x289228 | fwd |
| Constant-time inversion | +0x6af | je | mem | `0x2877b9: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x289231 | fwd |
| Constant-time inversion | +0x6e7 | je | mem | `0x2877f1: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x28923a | fwd |
| Constant-time inversion | +0x71f | je | mem | `0x287829: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x289243 | fwd |
| Constant-time inversion | +0x757 | je | mem | `0x287861: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x289459 | fwd |
| Constant-time inversion | +0x793 | je | mem | `0x28789d: cmpq $0xffffffffffffffff,0x18(%rsp)` | memory | 0x28945f | fwd |
| Constant-time inversion | +0x9ad | je | mem | `0x287aa5: cmp 0x2c8(%rsp),%rax` | memory | 0x28924c | fwd |
| Constant-time inversion | +0x9dc | je | reg/arith | `0x287ae9: test %rcx,%rcx` | memory | 0x287b48 | fwd |
| Constant-time inversion | +0xa20 | je | reg/arith | `0x287b2c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x287b4b | fwd |
| Constant-time inversion | +0xa25 | jae | reg/arith | `0x287b32: cmp %rbx,%rcx` | memory | 0x287b3d | fwd |
| Constant-time inversion | +0xa32 | jb | reg/arith | `0x287b3f: cmp %rbx,%rcx` | arithmetic/control | 0x287b02 | back |
| Constant-time inversion | +0xa58 | je | reg/arith | `0x287b65: test %rcx,%rcx` | memory | 0x287bc1 | fwd |
| Constant-time inversion | +0xa94 | je | reg/arith | `0x287ba0: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x287bc1 | fwd |
| Constant-time inversion | +0xa99 | jae | reg/arith | `0x287ba6: cmp %rbx,%rcx` | memory | 0x287bb6 | fwd |
| Constant-time inversion | +0xaab | jb | reg/arith | `0x287bb8: cmp %rbx,%rcx` | arithmetic/control | 0x287b7d | back |
| Constant-time inversion | +0xb16 | je | reg/arith | `0x287c23: test %rcx,%rcx` | memory | 0x287d1e | fwd |
| Constant-time inversion | +0xb2c | je | reg/arith | `0x287c39: test %r14,%r14` | memory | 0x287ce5 | fwd |
| Constant-time inversion | +0xb96 | je | reg/arith | `0x287ca2: add $0xfffffffffffffffe,%rdx` | memory | 0x287cda | fwd |
| Constant-time inversion | +0xba3 | jae | reg/arith | `0x287cb0: cmp %rbx,%r11` | memory | 0x287cbb | fwd |
| Constant-time inversion | +0xbc3 | jb | reg/arith | `0x287cd0: cmp %rbx,%r8` | arithmetic/control | 0x287c83 | back |
| Constant-time inversion | +0xbce | je | reg/arith | `0x287cda: test $0x1,%r14b` | arithmetic/control | 0x287d1e | fwd |
| Constant-time inversion | +0xbfc | jae | reg/arith | `0x287d09: cmp %rbx,%rcx` | memory | 0x287d14 | fwd |
| Constant-time inversion | +0xc26 | je | reg/arith | `0x287d33: test %r8,%r8` | memory | 0x287e2b | fwd |
| Constant-time inversion | +0xc37 | je | reg/arith | `0x287d44: test %r13,%r13` | memory | 0x287df1 | fwd |
| Constant-time inversion | +0xc9f | je | reg/arith | `0x287dab: add $0xfffffffffffffffe,%r10` | memory | 0x287de6 | fwd |
| Constant-time inversion | +0xcae | jae | mem | `0x287db9: cmp 0x50(%rsp),%r14` | memory | 0x287dc6 | fwd |
| Constant-time inversion | +0xcd0 | jb | mem | `0x287ddb: cmp 0x50(%rsp),%rax` | arithmetic/control | 0x287d8c | back |
| Constant-time inversion | +0xcda | je | reg/arith | `0x287de6: test $0x1,%r13b` | arithmetic/control | 0x287e2b | fwd |
| Constant-time inversion | +0xd04 | jae | mem | `0x287e0f: cmp 0x50(%rsp),%rsi` | memory | 0x287e21 | fwd |
| Constant-time inversion | +0xd9b | je | reg/arith | `0x287ea7: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x287ee0 | fwd |
| Constant-time inversion | +0xda0 | jae | reg/arith | `0x287ead: cmp %rbx,%rcx` | memory | 0x287eb8 | fwd |
| Constant-time inversion | +0xdaf | jae | mem | `0x287eba: cmp 0x10(%rsp),%rcx` | memory | 0x287ecc | fwd |
| Constant-time inversion | +0xdc9 | jb | reg/arith | `0x287ed6: cmp %r8,%rcx` | arithmetic/control | 0x287e84 | back |
| Constant-time inversion | +0xdd6 | je | mem | `0x287ee0: cmpq $0x0,0x10(%rsp)` | memory | 0x287fe4 | fwd |
| Constant-time inversion | +0xdec | je | reg/arith | `0x287ef9: test %r10,%r10` | memory | 0x287fa7 | fwd |
| Constant-time inversion | +0xe59 | je | reg/arith | `0x287f65: add $0xfffffffffffffffe,%r11` | memory | 0x287f9c | fwd |
| Constant-time inversion | +0xe66 | jae | reg/arith | `0x287f73: cmp %rbx,%r14` | memory | 0x287f7e | fwd |
| Constant-time inversion | +0xe86 | jb | reg/arith | `0x287f93: cmp %rbx,%rax` | arithmetic/control | 0x287f46 | back |
| Constant-time inversion | +0xe90 | je | reg/arith | `0x287f9c: test $0x1,%r10b` | arithmetic/control | 0x287fe4 | fwd |
| Constant-time inversion | +0xebd | jae | reg/arith | `0x287fca: cmp %rbx,%rsi` | memory | 0x287fda | fwd |
| Constant-time inversion | +0xed7 | je | reg/arith | `0x287fe4: test %r8,%r8` | memory | 0x2880dc | fwd |
| Constant-time inversion | +0xee8 | je | reg/arith | `0x287ff5: test %r10,%r10` | memory | 0x2880a2 | fwd |
| Constant-time inversion | +0xf50 | je | reg/arith | `0x28805c: add $0xfffffffffffffffe,%r11` | memory | 0x288097 | fwd |
| Constant-time inversion | +0xf5f | jae | mem | `0x28806a: cmp 0x68(%rsp),%r14` | memory | 0x288077 | fwd |
| Constant-time inversion | +0xf81 | jb | mem | `0x28808c: cmp 0x68(%rsp),%rax` | arithmetic/control | 0x28803d | back |
| Constant-time inversion | +0xf8b | je | reg/arith | `0x288097: test $0x1,%r10b` | arithmetic/control | 0x2880dc | fwd |
| Constant-time inversion | +0xfb5 | jae | mem | `0x2880c0: cmp 0x68(%rsp),%rsi` | memory | 0x2880d2 | fwd |
| Constant-time inversion | +0x1023 | je | reg/arith | `0x28812f: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x28816d | fwd |
| Constant-time inversion | +0x1028 | jae | reg/arith | `0x288135: cmp %rbx,%rcx` | memory | 0x288145 | fwd |
| Constant-time inversion | +0x103c | jae | mem | `0x288147: cmp 0x10(%rsp),%rcx` | memory | 0x288159 | fwd |
| Constant-time inversion | +0x1056 | jb | reg/arith | `0x288163: cmp %r8,%rcx` | arithmetic/control | 0x28810c | back |
| Constant-time inversion | +0x10af | je | mem | `0x2881b6: cmpq $0x0,0x80(%rsp)` | memory | 0x2881d1 | fwd |
| Constant-time inversion | +0x10ee | je | reg/arith | `0x2881fb: test %rcx,%rcx` | arithmetic/control | 0x2882f1 | fwd |
| Constant-time inversion | +0x10fb | je | reg/arith | `0x288207: add $0xfffffffffffffff8,%r8` | memory | 0x2882b5 | fwd |
| Constant-time inversion | +0x115e | je | reg/arith | `0x28826a: add $0xfffffffffffffffe,%r9` | memory | 0x2882aa | fwd |
| Constant-time inversion | +0x1170 | jae | mem | `0x288278: cmp 0x80(%rsp),%rdi` | memory | 0x288288 | fwd |
| Constant-time inversion | +0x1194 | jb | mem | `0x28829c: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x28824b | back |
| Constant-time inversion | +0x119e | je | reg/arith | `0x2882aa: test $0x1,%r8b` | arithmetic/control | 0x2882f1 | fwd |
| Constant-time inversion | +0x11c7 | jae | mem | `0x2882cf: cmp 0x80(%rsp),%rdi` | memory | 0x2882e7 | fwd |
| Constant-time inversion | +0x11ec | je | reg/arith | `0x2882f9: test %rdx,%rdx` | arithmetic/control | 0x288357 | fwd |
| Constant-time inversion | +0x1220 | je | reg/arith | `0x28832c: add $0xfffffffffffffff8,%rax` | memory | 0x288357 | fwd |
| Constant-time inversion | +0x122a | jae | mem | `0x288332: cmp 0x80(%rsp),%rcx` | memory | 0x28834a | fwd |
| Constant-time inversion | +0x1240 | jb | mem | `0x28834c: cmp (%rsp),%rcx` | arithmetic/control | 0x288307 | back |
| Constant-time inversion | +0x124b | ja | mem | `0x288357: cmp %rdx,(%rsp)` | arithmetic/control | 0x289577 | fwd |
| Constant-time inversion | +0x1251 | jae | unknown | `?` | memory | 0x2895a0 | fwd |
| Constant-time inversion | +0x125d | je | mem | `0x288367: cmpq $0x0,0x10(%rsp)` | memory | 0x28843e | fwd |
| Constant-time inversion | +0x1289 | jne | reg/arith | `0x288396: test $0x8,%dl` | memory | 0x2883d5 | fwd |
| Constant-time inversion | +0x12a7 | jae | mem | `0x2883b3: cmp (%rsp),%rdi` | memory | 0x2883c4 | fwd |
| Constant-time inversion | +0x12c8 | je | reg/arith | `0x2883d5: test %rdx,%rdx` | memory | 0x28843e | fwd |
| Constant-time inversion | +0x12f7 | je | mem | `0x288402: cmp 0x8(%rsp),%rax` | memory | 0x28843e | fwd |
| Constant-time inversion | +0x1304 | jae | mem | `0x288410: cmp (%rsp),%rsi` | memory | 0x288421 | fwd |
| Constant-time inversion | +0x1328 | jb | mem | `0x288434: cmp (%rsp),%rcx` | arithmetic/control | 0x2883e8 | back |
| Constant-time inversion | +0x1334 | je | mem | `0x28843e: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x288516 | fwd |
| Constant-time inversion | +0x1341 | je | reg/arith | `0x28844d: add $0xfffffffffffffff8,%rdx` | memory | 0x2884ea | fwd |
| Constant-time inversion | +0x138e | je | reg/arith | `0x28849b: cmp %rsi,%rdi` | memory | 0x2884db | fwd |
| Constant-time inversion | +0x139b | jae | mem | `0x2884a6: cmp 0x10(%rsp),%rdi` | memory | 0x2884b8 | fwd |
| Constant-time inversion | +0x13c4 | jb | mem | `0x2884cf: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x288477 | back |
| Constant-time inversion | +0x13ce | je | reg/arith | `0x2884db: test $0x1,%dl` | arithmetic/control | 0x288516 | fwd |
| Constant-time inversion | +0x13e6 | jae | mem | `0x2884f1: cmp 0x10(%rsp),%rcx` | memory | 0x288503 | fwd |
| Constant-time inversion | +0x1438 | je | reg/arith | `0x288545: test %rax,%rax` | memory | 0x2885b6 | fwd |
| Constant-time inversion | +0x1477 | je | reg/arith | `0x288583: add $0xfffffffffffffff8,%rcx` | memory | 0x2885b1 | fwd |
| Constant-time inversion | +0x1481 | jae | mem | `0x288589: cmp 0x80(%rsp),%rdx` | memory | 0x2885a1 | fwd |
| Constant-time inversion | +0x149b | jb | mem | `0x2885a3: cmp 0x88(%rsp),%rdx` | arithmetic/control | 0x288558 | back |
| Constant-time inversion | +0x14b8 | je | reg/arith | `0x2885c5: test %rdx,%rdx` | arithmetic/control | 0x288648 | fwd |
| Constant-time inversion | +0x14f1 | je | reg/arith | `0x2885fd: add $0xfffffffffffffff8,%rdx` | memory | 0x288621 | fwd |
| Constant-time inversion | +0x14f7 | jae | mem | `0x288603: cmp (%rsp),%rsi` | memory | 0x288612 | fwd |
| Constant-time inversion | +0x150a | jb | mem | `0x288615: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x2885d3 | back |
| Constant-time inversion | +0x157f | je | reg/arith | `0x28868c: test %rsi,%rsi` | arithmetic/control | 0x288777 | fwd |
| Constant-time inversion | +0x158c | je | reg/arith | `0x288698: add $0xfffffffffffffff8,%r11` | memory | 0x288740 | fwd |
| Constant-time inversion | +0x15ed | je | reg/arith | `0x2886f9: add $0xfffffffffffffffe,%rsi` | memory | 0x288735 | fwd |
| Constant-time inversion | +0x15fc | jae | mem | `0x288707: cmp 0x58(%rsp),%r14` | memory | 0x288714 | fwd |
| Constant-time inversion | +0x161e | jb | mem | `0x288729: cmp 0x58(%rsp),%r13` | arithmetic/control | 0x2886da | back |
| Constant-time inversion | +0x1629 | je | reg/arith | `0x288735: test $0x1,%r11b` | arithmetic/control | 0x288777 | fwd |
| Constant-time inversion | +0x1650 | jae | mem | `0x28875b: cmp 0x58(%rsp),%rdi` | memory | 0x28876d | fwd |
| Constant-time inversion | +0x16a9 | je | reg/arith | `0x2887b5: add $0xfffffffffffffff8,%rsi` | memory | 0x2887db | fwd |
| Constant-time inversion | +0x16b0 | jae | mem | `0x2887bb: cmp 0x58(%rsp),%rdi` | memory | 0x2887cd | fwd |
| Constant-time inversion | +0x16c4 | jb | mem | `0x2887d0: cmp (%rsp),%rdi` | arithmetic/control | 0x28878f | back |
| Constant-time inversion | +0x16d1 | je | mem | `0x2887db: cmpq $0x0,0x10(%rsp)` | memory | 0x2888a0 | fwd |
| Constant-time inversion | +0x16f4 | jne | reg/arith | `0x288800: test $0x8,%dil` | memory | 0x28881e | fwd |
| Constant-time inversion | +0x1701 | jae | mem | `0x28880d: cmp (%rsp),%rsi` | memory | 0x288823 | fwd |
| Constant-time inversion | +0x1728 | je | reg/arith | `0x288835: test %rdi,%rdi` | memory | 0x2888a0 | fwd |
| Constant-time inversion | +0x1757 | je | mem | `0x288862: cmp 0x8(%rsp),%rsi` | memory | 0x2888a0 | fwd |
| Constant-time inversion | +0x1764 | jae | mem | `0x288870: cmp (%rsp),%r9` | memory | 0x288881 | fwd |
| Constant-time inversion | +0x1789 | jb | mem | `0x288895: cmp (%rsp),%r10` | arithmetic/control | 0x288848 | back |
| Constant-time inversion | +0x1796 | je | mem | `0x2888a0: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x28897f | fwd |
| Constant-time inversion | +0x17a3 | je | reg/arith | `0x2888af: add $0xfffffffffffffff8,%r11` | memory | 0x288951 | fwd |
| Constant-time inversion | +0x17f1 | je | reg/arith | `0x2888fe: cmp %r9,%r10` | memory | 0x288941 | fwd |
| Constant-time inversion | +0x17fe | jae | mem | `0x288909: cmp 0x10(%rsp),%r10` | memory | 0x28891b | fwd |
| Constant-time inversion | +0x182a | jb | mem | `0x288935: cmp 0x10(%rsp),%r10` | arithmetic/control | 0x2888da | back |
| Constant-time inversion | +0x1835 | je | reg/arith | `0x288941: test $0x1,%r11b` | arithmetic/control | 0x28897f | fwd |
| Constant-time inversion | +0x184d | jae | mem | `0x288958: cmp 0x10(%rsp),%rsi` | memory | 0x28896a | fwd |
| Constant-time inversion | +0x18a6 | je | reg/arith | `0x2889b3: test %rsi,%rsi` | arithmetic/control | 0x288a29 | fwd |
| Constant-time inversion | +0x18db | je | reg/arith | `0x2889e7: add $0xfffffffffffffff8,%rsi` | memory | 0x288a29 | fwd |
| Constant-time inversion | +0x18e5 | jae | mem | `0x2889ed: cmp 0x80(%rsp),%rdi` | memory | 0x288a05 | fwd |
| Constant-time inversion | +0x18fd | jae | mem | `0x288a08: cmp 0x40(%rsp),%rdi` | memory | 0x288a1a | fwd |
| Constant-time inversion | +0x1912 | jb | mem | `0x288a1d: cmp 0x68(%rsp),%rdi` | arithmetic/control | 0x2889c0 | back |
| Constant-time inversion | +0x1922 | je | mem | `0x288a29: cmpq $0x0,0x88(%rsp)` | memory | 0x288a44 | fwd |
| Constant-time inversion | +0x1949 | je | mem | `0x288a53: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x288b6f | fwd |
| Constant-time inversion | +0x1956 | je | reg/arith | `0x288a62: add $0xfffffffffffffff8,%rsi` | memory | 0x288b32 | fwd |
| Constant-time inversion | +0x19ce | je | reg/arith | `0x288ada: add $0xfffffffffffffffe,%rsi` | memory | 0x288b21 | fwd |
| Constant-time inversion | +0x19e0 | jae | mem | `0x288ae8: cmp 0x88(%rsp),%r14` | memory | 0x288af8 | fwd |
| Constant-time inversion | +0x1a0a | jb | mem | `0x288b12: cmp 0x88(%rsp),%r13` | arithmetic/control | 0x288ab1 | back |
| Constant-time inversion | +0x1a19 | je | mem | `0x288b21: testb $0x1,0xa0(%rsp)` | memory | 0x288b6f | fwd |
| Constant-time inversion | +0x1a45 | jae | mem | `0x288b4d: cmp 0x88(%rsp),%rdi` | memory | 0x288b65 | fwd |
| Constant-time inversion | +0x1a93 | je | reg/arith | `0x288b9f: add $0xfffffffffffffff8,%rsi` | memory | 0x288bcb | fwd |
| Constant-time inversion | +0x1a9d | jae | mem | `0x288ba5: cmp 0x88(%rsp),%rdi` | memory | 0x288bbd | fwd |
| Constant-time inversion | +0x1ab4 | jb | mem | `0x288bc0: cmp (%rsp),%rdi` | arithmetic/control | 0x288b79 | back |
| Constant-time inversion | +0x1ac1 | je | mem | `0x288bcb: cmpq $0x0,0x10(%rsp)` | memory | 0x288c90 | fwd |
| Constant-time inversion | +0x1ae4 | jne | reg/arith | `0x288bf0: test $0x8,%dil` | memory | 0x288c0e | fwd |
| Constant-time inversion | +0x1af1 | jae | mem | `0x288bfd: cmp (%rsp),%rsi` | memory | 0x288c13 | fwd |
| Constant-time inversion | +0x1b18 | je | reg/arith | `0x288c25: test %rdi,%rdi` | memory | 0x288c90 | fwd |
| Constant-time inversion | +0x1b47 | je | mem | `0x288c52: cmp 0x8(%rsp),%rsi` | memory | 0x288c90 | fwd |
| Constant-time inversion | +0x1b54 | jae | mem | `0x288c60: cmp (%rsp),%r9` | memory | 0x288c71 | fwd |
| Constant-time inversion | +0x1b79 | jb | mem | `0x288c85: cmp (%rsp),%r10` | arithmetic/control | 0x288c38 | back |
| Constant-time inversion | +0x1b86 | je | mem | `0x288c90: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x288d68 | fwd |
| Constant-time inversion | +0x1b90 | je | reg/arith | `0x288c9c: add $0xfffffffffffffff8,%r12` | memory | 0x288d3c | fwd |
| Constant-time inversion | +0x1bde | je | reg/arith | `0x288ceb: cmp %rdi,%r9` | memory | 0x288d2c | fwd |
| Constant-time inversion | +0x1beb | jae | mem | `0x288cf6: cmp 0x10(%rsp),%r9` | memory | 0x288d08 | fwd |
| Constant-time inversion | +0x1c15 | jb | mem | `0x288d20: cmp 0x10(%rsp),%r9` | arithmetic/control | 0x288cc7 | back |
| Constant-time inversion | +0x1c20 | je | reg/arith | `0x288d2c: test $0x1,%r12b` | arithmetic/control | 0x288d68 | fwd |
| Constant-time inversion | +0x1c38 | jae | mem | `0x288d43: cmp 0x10(%rsp),%rsi` | memory | 0x288d55 | fwd |
| Constant-time inversion | +0x1c5e | je | mem | `0x288d68: cmpq $0x0,0x10(%rsp)` | memory | 0x288de1 | fwd |
| Constant-time inversion | +0x1ca0 | je | reg/arith | `0x288dac: add $0xfffffffffffffff8,%rsi` | memory | 0x288ddc | fwd |
| Constant-time inversion | +0x1caa | jae | mem | `0x288db2: cmp 0x88(%rsp),%rdi` | memory | 0x288dca | fwd |
| Constant-time inversion | +0x1cc5 | jb | mem | `0x288dcd: cmp 0x80(%rsp),%rdi` | arithmetic/control | 0x288d7f | back |
| Constant-time inversion | +0x1cda | je | mem | `0x288de4: cmpq $0x0,0x58(%rsp)` | arithmetic/control | 0x288e4d | fwd |
| Constant-time inversion | +0x1d10 | je | reg/arith | `0x288e1c: add $0xfffffffffffffff8,%rcx` | memory | 0x288e40 | fwd |
| Constant-time inversion | +0x1d16 | jae | mem | `0x288e22: cmp (%rsp),%rsi` | memory | 0x288e31 | fwd |
| Constant-time inversion | +0x1d29 | jb | mem | `0x288e34: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x288df2 | back |
| Constant-time inversion | +0x1d52 | je | mem | `0x288e5c: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x288f5d | fwd |
| Constant-time inversion | +0x1d5f | je | reg/arith | `0x288e6b: add $0xfffffffffffffff8,%r10` | memory | 0x288f27 | fwd |
| Constant-time inversion | +0x1dce | je | reg/arith | `0x288eda: add $0xfffffffffffffffe,%rsi` | memory | 0x288f1a | fwd |
| Constant-time inversion | +0x1ddd | jae | mem | `0x288ee8: cmp 0x58(%rsp),%r14` | memory | 0x288ef5 | fwd |
| Constant-time inversion | +0x1e04 | jb | mem | `0x288f0f: cmp 0x58(%rsp),%rcx` | arithmetic/control | 0x288eb1 | back |
| Constant-time inversion | +0x1e0e | je | reg/arith | `0x288f1a: test $0x1,%r10b` | memory | 0x288f5d | fwd |
| Constant-time inversion | +0x1e36 | jae | mem | `0x288f41: cmp 0x58(%rsp),%rdi` | memory | 0x288f53 | fwd |
| Constant-time inversion | +0x1e7c | je | reg/arith | `0x288f88: add $0xfffffffffffffff8,%r8` | memory | 0x288fad | fwd |
| Constant-time inversion | +0x1e83 | jae | mem | `0x288f8e: cmp 0x58(%rsp),%rcx` | memory | 0x288fa0 | fwd |
| Constant-time inversion | +0x1e96 | jb | mem | `0x288fa2: cmp (%rsp),%rcx` | arithmetic/control | 0x288f63 | back |
| Constant-time inversion | +0x1ea3 | je | mem | `0x288fad: cmpq $0x0,0x10(%rsp)` | memory | 0x28906d | fwd |
| Constant-time inversion | +0x1ec9 | jne | reg/arith | `0x288fd5: test $0x8,%sil` | memory | 0x289004 | fwd |
| Constant-time inversion | +0x1ed6 | jae | mem | `0x288fe2: cmp (%rsp),%rsi` | memory | 0x288ff3 | fwd |
| Constant-time inversion | +0x1ef7 | je | reg/arith | `0x289004: test %rdi,%rdi` | memory | 0x28906d | fwd |
| Constant-time inversion | +0x1f26 | je | mem | `0x289031: cmp 0x8(%rsp),%rax` | memory | 0x28906d | fwd |
| Constant-time inversion | +0x1f33 | jae | mem | `0x28903f: cmp (%rsp),%rdi` | memory | 0x289050 | fwd |
| Constant-time inversion | +0x1f57 | jb | mem | `0x289063: cmp (%rsp),%rcx` | arithmetic/control | 0x289017 | back |
| Constant-time inversion | +0x1f63 | je | mem | `0x28906d: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x289142 | fwd |
| Constant-time inversion | +0x1f6d | je | reg/arith | `0x289079: add $0xfffffffffffffff8,%rdx` | memory | 0x289116 | fwd |
| Constant-time inversion | +0x1fba | je | reg/arith | `0x2890c7: cmp %rsi,%rdi` | memory | 0x289107 | fwd |
| Constant-time inversion | +0x1fc7 | jae | mem | `0x2890d2: cmp 0x10(%rsp),%rdi` | memory | 0x2890e4 | fwd |
| Constant-time inversion | +0x1ff0 | jb | mem | `0x2890fb: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x2890a3 | back |
| Constant-time inversion | +0x1ffa | je | reg/arith | `0x289107: test $0x1,%dl` | arithmetic/control | 0x289142 | fwd |
| Constant-time inversion | +0x2012 | jae | mem | `0x28911d: cmp 0x10(%rsp),%rcx` | memory | 0x28912f | fwd |
| Constant-time inversion | +0x2080 | je | reg/arith | `0x28918d: test %rcx,%rcx` | memory | 0x28791f | back |
| Constant-time inversion | +0x20be | je | reg/arith | `0x2891ca: add $0xfffffffffffffff8,%rax` | memory | 0x28791f | back |
| Constant-time inversion | +0x20cc | jae | mem | `0x2891d4: cmp 0x88(%rsp),%rcx` | memory | 0x2891ec | fwd |
| Constant-time inversion | +0x20e3 | jae | mem | `0x2891ee: cmp 0x40(%rsp),%rcx` | memory | 0x289200 | fwd |
| Constant-time inversion | +0x20f7 | jb | mem | `0x289202: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x28919f | back |
| Constant-time inversion | +0x214c | je | reg/arith | `0x289258: cmp $0x1,%rbx` | memory | 0x2892fb | fwd |
| Constant-time inversion | +0x216b | jb | reg/arith | `0x289277: cmp $0x18,%rcx` | memory | 0x2892e0 | fwd |
| Constant-time inversion | +0x21b7 | jne | reg/arith | `0x2892c4: cmp %rdx,%rsi` | arithmetic/control | 0x2892ac | back |
| Constant-time inversion | +0x21ce | je | reg/arith | `0x2892db: cmp %rsi,%rcx` | memory | 0x2892fb | fwd |
| Constant-time inversion | +0x21e9 | jne | mem | `0x2892f4: cmp 0x8(%rsp),%rax` | call+memory | 0x2892ed | back |
| Constant-time inversion | +0x2204 | je | reg/arith | `0x289310: cmp $0xffffffffffffffff,%r12` | memory | 0x289465 | fwd |
| Constant-time inversion | +0x2219 | jne | mem | `0x289324: cmp 0x38(%rsp),%rdi` | memory | 0x28958c | fwd |
| Constant-time inversion | +0x2315 | je | reg/arith | `0x289422: test %r15,%r15` | memory | 0x289561 | fwd |
| Constant-time inversion | +0x2326 | je | reg/arith | `0x289433: test %r12,%r12` | memory | 0x287182 | back |
| Constant-time inversion | +0x2437 | jne | reg/arith | `0x289544: cmp %rax,%rsi` | memory | 0x289519 | back |
| Constant-time inversion | +0x24af | je | reg/arith | `0x2895bc: test %r12,%r12` | memory | 0x2895db | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x28cdb0: test %rcx,%rcx` | memory | 0x28ce24 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x28cdc0: test %rax,%rax` | memory | 0x28ce18 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x28cdcc: cmp (%r15),%rcx` | memory | 0x28ce1f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x28cdd5: test %ecx,%ecx` | memory | 0x28cde5 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x28cddd: test %edx,%edx` | arithmetic/control | 0x28cde5 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x28cde1: cmp %edx,%ecx` | call | 0x28ce1f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x28cded: test %eax,%eax` | memory | 0x28ce24 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x28cdf9: test %rax,%rax` | memory | 0x28cf52 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x28ce02: cmp (%r12),%rcx` | memory | 0x28d193 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x28ce2f: test %rcx,%rcx` | memory | 0x28cf30 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x28ce50: cmp %rdx,%rcx` | memory | 0x28cf30 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x28ce59: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x28ce50 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x28ce6f: test %rcx,%rcx` | memory | 0x28cf30 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x28ce90: cmp %rdx,%rcx` | memory | 0x28cf30 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x28ce99: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x28ce90 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x28cead: test %r13,%r13` | memory | 0x28cf49 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x28ceba: cmpq $0x0,0x50(%rax)` | memory | 0x28cf60 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x28cedc: test %rax,%rax` | memory | 0x28cf2b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x28cef7: test %rax,%rax` | call | 0x28cf05 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x28cf01: test %eax,%eax` | call+memory | 0x28cf78 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x28cf6f: test %r13,%r13` | memory | 0x28d0bd | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x28cf7c: cmpq $0x0,0x50(%rax)` | memory | 0x28d0b4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x28cfa3: test %rax,%rax` | memory | 0x28d0f1 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x28cfc2: test %rax,%rax` | call | 0x28d0cb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x28cfd0: test %eax,%eax` | memory | 0x28d0cb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x28cfe2: test %r14,%r14` | arithmetic/control | 0x28d1ac | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x28cfeb: test %r15,%r15` | memory | 0x28d1b7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x28cffe: test %rcx,%rcx` | memory | 0x28d038 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x28d007: test %rax,%rax` | memory | 0x28d038 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x28d013: cmp (%r15),%rcx` | memory | 0x28d038 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x28d01c: test %ecx,%ecx` | memory | 0x28d2fa | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x28d028: test %edx,%edx` | arithmetic/control | 0x28d2fa | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x28d030: cmp %ecx,%edx` | call | 0x28d2fa | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x28d052: test %rax,%rax` | memory | 0x28d065 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x28d05b: test %rax,%rax` | call | 0x28d065 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x28d096: test %rbx,%rbx` | memory | 0x28d2ce | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x28d0a3: test %rcx,%rcx` | arithmetic/control | 0x28d179 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x28d112: test %bpl,%bpl` | memory | 0x28d158 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x28d11f: test %rax,%rax` | memory | 0x28d132 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x28d128: test %rax,%rax` | call | 0x28d132 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x28d163: test %rbx,%rbx` | memory | 0x28cf37 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x28d170: test %rcx,%rcx` | memory | 0x28cf37 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x28d1c4: test %eax,%eax` | memory | 0x28d2d6 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x28d1d0: test %rax,%rax` | memory | 0x28d1d9 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x28d1dd: test %rax,%rax` | memory | 0x28d1e6 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x28d1ea: test %rax,%rax` | memory | 0x28d1f3 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x28d1f8: test %rax,%rax` | memory | 0x28d201 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x28d206: test %rax,%rax` | memory | 0x28d20f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x28d214: test %rax,%rax` | memory | 0x28d21d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x28d226: test %rax,%rax` | memory | 0x28d22f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x28d238: test %rax,%rax` | memory | 0x28d241 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x28d24a: test %rax,%rax` | call+memory | 0x28d253 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x28d27b: test %rax,%rax` | memory | 0x28d2e2 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x28d299: test %eax,%eax` | memory | 0x28d2ee | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x28d2aa: test %r15,%r15` | memory | 0x28d318 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x28d2b3: test $0xffffffff80000000,%rax` | memory | 0x28d32b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x28d2fa: cmp %r15,%r14` | call | 0x28d1cc | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x28d30b: test %eax,%eax` | arithmetic/control | 0x28d1cc | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x28d336: test $0x1,%al` | memory | 0x28d978 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x28d343: test %eax,%eax` | memory | 0x28d371 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x28d34e: cmp %rsi,(%rdi)` | call+memory | 0x28d37b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x28d363: test %al,%cl` | arithmetic/control | 0x28d384 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x28d371: test %r15,%r15` | arithmetic/control | 0x28d399 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x28d37b: test %r15,%r15` | memory | 0x28d464 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x28d384: cmp %rsi,(%r15)` | call | 0x28d399 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x28d391: test %al,%al` | memory | 0x28d464 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x28d3aa: test %rax,%rax` | memory | 0x28d470 | fwd |
| ECDSA scalar ladder (driver) | +0x635 | jg | mem | `0x28d3c1: cmp 0x24(%rsp),%eax` | memory | 0x28d3ce | fwd |
| ECDSA scalar ladder (driver) | +0x63c | je | mem | `0x28d3c7: cmpl $0x0,0x18(%r15)` | memory | 0x28d3ea | fwd |
| ECDSA scalar ladder (driver) | +0x654 | je | reg/arith | `0x28d3e2: test %eax,%eax` | memory | 0x28d47c | fwd |
| ECDSA scalar ladder (driver) | +0x672 | je | reg/arith | `0x28d400: test %eax,%eax` | memory | 0x28d488 | fwd |
| ECDSA scalar ladder (driver) | +0x68f | je | reg/arith | `0x28d41d: test %eax,%eax` | memory | 0x28d65e | fwd |
| ECDSA scalar ladder (driver) | +0x6a3 | js | mem | `0x28d42e: cmpl $0x0,0x24(%rsp)` | memory | 0x28d494 | fwd |
| ECDSA scalar ladder (driver) | +0x6b5 | jae | mem | `0x28d441: cmp 0x10(%rcx),%rax` | memory | 0x28d494 | fwd |
| ECDSA scalar ladder (driver) | +0x722 | je | reg/arith | `0x28d4af: test %rax,%rax` | memory | 0x28d4cc | fwd |
| ECDSA scalar ladder (driver) | +0x74f | je | reg/arith | `0x28d4dc: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x75d | jae | mem | `0x28d4ea: cmp %r15,(%rdi)` | call | 0x28d4ff | fwd |
| ECDSA scalar ladder (driver) | +0x769 | je | reg/arith | `0x28d4f7: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x77b | je | reg/arith | `0x28d508: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x784 | jae | mem | `0x28d511: cmp %r15,(%rdi)` | call | 0x28d526 | fwd |
| ECDSA scalar ladder (driver) | +0x790 | je | reg/arith | `0x28d51e: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x7a2 | je | reg/arith | `0x28d52f: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ab | jae | mem | `0x28d538: cmp %r15,(%rdi)` | call | 0x28d54d | fwd |
| ECDSA scalar ladder (driver) | +0x7b7 | je | reg/arith | `0x28d545: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x7c5 | je | reg/arith | `0x28d552: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ce | jae | mem | `0x28d55b: cmp %r15,(%rdi)` | call | 0x28d570 | fwd |
| ECDSA scalar ladder (driver) | +0x7da | je | reg/arith | `0x28d568: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x7e8 | je | reg/arith | `0x28d575: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x7f1 | jae | mem | `0x28d57e: cmp %r15,(%rdi)` | call | 0x28d593 | fwd |
| ECDSA scalar ladder (driver) | +0x7fd | je | reg/arith | `0x28d58b: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x80b | je | reg/arith | `0x28d598: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x814 | jae | mem | `0x28d5a1: cmp %r15,(%rdi)` | call | 0x28d5b6 | fwd |
| ECDSA scalar ladder (driver) | +0x820 | je | reg/arith | `0x28d5ae: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x832 | je | reg/arith | `0x28d5bf: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x83b | jae | mem | `0x28d5c8: cmp %r15,(%rdi)` | call | 0x28d5dd | fwd |
| ECDSA scalar ladder (driver) | +0x847 | je | reg/arith | `0x28d5d5: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x859 | je | reg/arith | `0x28d5e6: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x862 | jae | mem | `0x28d5ef: cmp %r15,(%rdi)` | call | 0x28d604 | fwd |
| ECDSA scalar ladder (driver) | +0x86e | je | reg/arith | `0x28d5fc: test %al,%al` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x880 | je | reg/arith | `0x28d60d: test %rdi,%rdi` | memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0x88e | jae | mem | `0x28d616: cmp %r15,(%rdi)` | call | 0x28d630 | fwd |
| ECDSA scalar ladder (driver) | +0x89a | je | reg/arith | `0x28d628: test %al,%al` | memory | 0x28d044 | back |
| ECDSA scalar ladder (driver) | +0x8a5 | je | mem | `0x28d630: cmpl $0x0,0x28(%r14)` | call+memory | 0x28d792 | fwd |
| ECDSA scalar ladder (driver) | +0x8b9 | je | reg/arith | `0x28d647: test %al,%al` | memory | 0x28d66a | fwd |
| ECDSA scalar ladder (driver) | +0x8e8 | jne | reg/arith | `0x28d674: cmp $0x4,%rdx` | memory | 0x28d6bd | fwd |
| ECDSA scalar ladder (driver) | +0x922 | jne | reg/arith | `0x28d6ae: cmp $0x1,%dil` | call | 0x28d6bf | fwd |
| ECDSA scalar ladder (driver) | +0x934 | je | reg/arith | `0x28d6c2: test %cl,%cl` | arithmetic/control | 0x28d738 | fwd |
| ECDSA scalar ladder (driver) | +0x939 | jne | reg/arith | `0x28d6c6: test %sil,%sil` | memory | 0x28d738 | fwd |
| ECDSA scalar ladder (driver) | +0x985 | je | mem | `0x28d70c: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x28d802 | fwd |
| ECDSA scalar ladder (driver) | +0x9cb | je | reg/arith | `0x28d759: test %eax,%eax` | arithmetic/control | 0x28d7d0 | fwd |
| ECDSA scalar ladder (driver) | +0x9d4 | jg | reg/arith | `0x28d761: cmp $0x1,%eax` | arithmetic/control | 0x28d7dc | fwd |
| ECDSA scalar ladder (driver) | +0x9d8 | jne | reg/arith | `0x28d766: test %eax,%eax` | call+memory | 0x28d813 | fwd |
| ECDSA scalar ladder (driver) | +0xa17 | je | reg/arith | `0x28d7a4: test %rax,%rax` | call+memory | 0x28d7c6 | fwd |
| ECDSA scalar ladder (driver) | +0xa2b | jne | reg/arith | `0x28d7b9: test %eax,%eax` | arithmetic/control | 0x28d63b | back |
| ECDSA scalar ladder (driver) | +0xa4f | jne | reg/arith | `0x28d7dc: cmp $0x2,%eax` | call+memory | 0x28d846 | fwd |
| ECDSA scalar ladder (driver) | +0xaa4 | jne | reg/arith | `0x28d832: test %eax,%eax` | memory | 0x28d90b | fwd |
| ECDSA scalar ladder (driver) | +0xaba | jo | mem | `0x28d846: decl 0x24(%rsp)` | arithmetic/control | 0x28d987 | fwd |
| ECDSA scalar ladder (driver) | +0xac0 | js | unknown | `?` | memory | 0x28d8f2 | fwd |
| ECDSA scalar ladder (driver) | +0xae9 | jae | mem | `0x28d875: cmp 0x10(%rcx),%rax` | memory | 0x28d892 | fwd |
| ECDSA scalar ladder (driver) | +0xb1c | je | mem | `0x28d8a6: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x28d8c5 | fwd |
| ECDSA scalar ladder (driver) | +0xb4f | je | reg/arith | `0x28d8dd: test %eax,%eax` | memory | 0x28d94d | fwd |
| ECDSA scalar ladder (driver) | +0xb5a | jg | reg/arith | `0x28d8e3: test %r15,%r15` | arithmetic/control | 0x28d867 | back |
| ECDSA scalar ladder (driver) | +0xb89 | je | reg/arith | `0x28d916: test %rax,%rax` | call+memory | 0x28d934 | fwd |
| ECDSA scalar ladder (driver) | +0xba2 | je | reg/arith | `0x28d930: test %eax,%eax` | call+memory | 0x28d946 | fwd |
| ECDSA scalar ladder (driver) | +0xbdd | jne | reg/arith | `0x28d96a: test %rax,%rax` | arithmetic/control | 0x28d057 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x2fcf07: test %rax,%rax` | memory | 0x2fd4a5 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x2fcf22: test %rbp,%rbp` | memory | 0x2fd4a5 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x2fcf32: test %rax,%rax` | call+memory | 0x2fd4a5 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x2fcf54: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x2fcf72: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x2fcf90: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x2fcfae: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x2fcfd4: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x2fcff4: test %eax,%eax` | arithmetic/control | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x2fcffc: test %r15,%r15` | memory | 0x2fd022 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x2fd00e: test %rdx,%rdx` | arithmetic/control | 0x2fd044 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x2fd03a: test %rdx,%rdx` | memory | 0x2fd050 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x2fd053: sub $0x1,%r9` | memory | 0x2fd077 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x2fd059: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x2fd050 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x2fd070: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x2fd080 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x2fd07a: sub $0x1,%r8` | arithmetic/control | 0x2fd070 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x2fd080: cmp %r9,%rdi` | memory | 0x2fd0a0 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x2fd090: sub $0x1,%rdi` | memory | 0x2fd0a2 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x2fd09a: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x2fd090 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x2fd0bd | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x2fd0b5: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x2fd0cf: test %eax,%eax` | arithmetic/control | 0x2fd4a5 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x2fd0dc: test %r15,%r15` | memory | 0x2fd0eb | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x2fd103: sub $0x1,%rdi` | memory | 0x2fd127 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x2fd109: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x2fd100 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x2fd120: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x2fd130 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x2fd12a: sub $0x1,%rsi` | arithmetic/control | 0x2fd120 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x2fd130: cmp %rdi,%rdx` | arithmetic/control | 0x2fd145 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x2fd135: sub $0x1,%rdx` | memory | 0x2fd147 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x2fd13f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x2fd135 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x2fd15e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x2fd156: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x2fd173: test %eax,%eax` | memory | 0x2fd4a5 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x2fd18d: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x2fd1b0: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x2fd1cb: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x2fd1e5: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x2fd207: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x2fd221: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x2fd244: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x2fd266: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x2fd288: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x2fd2aa: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x2fd2c4: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x2fd2e0: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x2fd304: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x2fd31e: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x2fd33d: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x2fd35c: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x2fd37b: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x2fd395: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x2fd3b4: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x2fd3d1: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x2fd3f6: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x2fd415: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x2fd431: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x2fd44a: test %eax,%eax` | call+memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x2fd463: test %eax,%eax` | memory | 0x2fd4a3 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x2fd479: test %eax,%eax` | memory | 0x2fd4a5 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x2fd4a5: test %rbx,%rbx` | memory | 0x2fd4c8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x2fd4ae: test %rax,%rax` | memory | 0x2fd4c8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x1ca98b: test %rax,%rax` | memory | 0x1cb3f8 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x1ca9a5: cmpl $0x1,0x10(%rbp)` | memory | 0x1ca9cd | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x1ca9b5: test %rax,%rax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x1ca9c4: cmp $0xfffffffd,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x1ca9d5: testb $0x4,0xa4(%rbp)` | memory | 0x1ca9f5 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x1ca9de: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x1caa56 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x1ca9e7: test %r13b,%r13b` | arithmetic/control | 0x1cab30 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x1ca9fb: test %rax,%rax` | memory | 0x1cb3f8 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x1caa29: test %rax,%rax` | arithmetic/control | 0x1caf40 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x1caa32: test %r15,%r15` | memory | 0x1caa40 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x1caa4a: test %rax,%rax` | arithmetic/control | 0x1caab8 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x1caa73: test %r15,%r15` | arithmetic/control | 0x1cab10 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x1caa7c: test %r14,%r14` | memory | 0x1caa8a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x1caa91: test %r15,%r15` | memory | 0x1cab02 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x1caaab: test %eax,%eax` | memory | 0x1caaf6 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x1caad4: test %eax,%eax` | memory | 0x1caf17 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x1cab02: test %r14,%r14` | memory | 0x1cab10 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x1cab16: or %r13b,%al` | arithmetic/control | 0x1cad42 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x1cab27: test %r15,%r15` | memory | 0x1cb3f8 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x1cab36: test %rax,%rax` | memory | 0x1cb3f8 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x1cab79: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x1cab87: test %rax,%rax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x1cabad: test %rax,%rax` | call+memory | 0x1cb8a0 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x1cabd6: test %eax,%eax` | call+memory | 0x1cb8a0 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x1cac24: test %al,0x38(%rsp)` | memory | 0x1caca3 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x1cac35: test %rax,%rax` | memory | 0x1cb3f8 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x1cac5b: test %rax,%rax` | call+memory | 0x1cb2f2 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x1cac95: test %ebp,%ebp` | arithmetic/control | 0x1cb3fb | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x1caca5: test %ebx,%ebx` | memory | 0x1cb15e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x1cacb7: test %r15b,%r15b` | call+memory | 0x1cb168 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x1cacde: test %r13,%r13` | arithmetic/control | 0x1cb89b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x1cacec: test %rax,%rax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x1cacfe: test %rax,%rax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x1cad0e: test %rcx,%rcx` | memory | 0x1cb2ff | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x1cad26: cmpq $0x0,0x10(%rcx)` | memory | 0x1cb309 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x1cad67: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x1cad85: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x1cadaf: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x1cadcd: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x1cae06: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x1cae28: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x1cae41: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x1cae49: test %rbx,%rbx` | memory | 0x1cae94 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x1cae58: cmpl $0x0,0x18(%rbx)` | memory | 0x1cae94 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x1cae6e: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x1cae76: cmpl $0x0,0x18(%rbx)` | memory | 0x1cae94 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x1cae8c: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x1caeaa: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x1caecc: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x1caee9: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x1caf27: test %r15,%r15` | memory | 0x1caf35 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x1caf35: test %bl,%bl` | memory | 0x1cafe8 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x1caf62: test %rax,%rax` | arithmetic/control | 0x1caff0 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x1caf6b: test %r15,%r15` | memory | 0x1caf79 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x1caf83: test %rax,%rax` | arithmetic/control | 0x1caf8c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x1cafa8: test %eax,%eax` | memory | 0x1cafc3 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x1cafd3: test %r15,%r15` | memory | 0x1cafe1 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x1cafe1: test %bl,%bl` | arithmetic/control | 0x1caff0 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x1caffa: test %ebx,%ebx` | memory | 0x1cb0eb | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x1cb029: test %bl,%bl` | arithmetic/control | 0x1cb151 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x1cb034: cmp %r14,%r13` | memory | 0x1cb0eb | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x1cb068: test %rax,%rax` | arithmetic/control | 0x1cb031 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x1cb06d: test %r15,%r15` | memory | 0x1cb07b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x1cb07f: test %rax,%rax` | arithmetic/control | 0x1cb08d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x1cb086: test %r15,%r15` | arithmetic/control | 0x1cb020 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x1cb0a2: test %eax,%eax` | memory | 0x1cb0c8 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x1cb0ba: test %r15,%r15` | arithmetic/control | 0x1cb020 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x1cb0dd: test %r15,%r15` | arithmetic/control | 0x1cb020 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x1cb0f9: test %ebx,%ebx` | memory | 0x1cb144 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x1cb105: cmp 0x701204(%rip),%rax        # 8cc310 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x368d30>` | call+memory | 0x1ca9de | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x1cb16d: test %al,%r14b` | memory | 0x1cb3ef | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x1cb1a3: test %eax,%eax` | arithmetic/control | 0x1cb3fb | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x1cb1ab: test %rbx,%rbx` | memory | 0x1cb1ce | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x1cb1b0: cmpl $0x0,0x18(%rbx)` | memory | 0x1cb1ce | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x1cb1c6: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x1cb1e3: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x1cb1f1: test %rax,%rax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x1cb23d: test %ebp,%ebp` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x1cb245: test %rbx,%rbx` | memory | 0x1cb26d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x1cb24f: cmpl $0x0,0x18(%rbx)` | memory | 0x1cb26d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x1cb265: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x1cb285: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x1cb29e: test %eax,%eax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x1cb2a6: cmpl $0x0,0x28(%rsp)` | memory | 0x1cb5fc | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x1cb2bc: test %rax,%rax` | memory | 0x1cb3fb | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x1cb2d2: test %rax,%rax` | memory | 0x1cb509 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x1cb2db: cmpq $0x0,0x10(%rax)` | memory | 0x1cb509 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x1cb34d: test %eax,%eax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x1cb362: test %rax,%rax` | call+memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x1cb386: test %eax,%eax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x1cb38e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x1cb434 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x1cb3e6: test %al,%r14b` | arithmetic/control | 0x1cb176 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x1cb3ef: test %r15b,%r15b` | arithmetic/control | 0x1cb5fc | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x1cb3fb: test %r12,%r12` | memory | 0x1cb422 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x1cb405: test %rax,%rax` | memory | 0x1cb422 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x1cb43d: test %rax,%rax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x1cb457: test %rax,%rax` | memory | 0x1cb46d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x1cb45c: cmpq $0x2,0x10(%rax)` | memory | 0x1cb46d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x1cb4aa: test %eax,%eax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x1cb4bf: test %rax,%rax` | call+memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x1cb4e3: test %eax,%eax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x1cb4eb: cmpl $0x2,0x28(%rsp)` | memory | 0x1cb7b3 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x1cb521: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x1cb53e: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x1cb575: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x1cb57d: cmpq $0x0,0x8(%rsp)` | memory | 0x1cb5a9 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x1cb58a: cmpl $0x0,0x18(%rax)` | memory | 0x1cb5a9 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x1cb5a1: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x1cb5be: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x1cb5d9: test %eax,%eax` | memory | 0x1cb8b3 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x1cb5e1: cmpl $0x1,0x28(%rsp)` | memory | 0x1cb8cb | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x1cb600: test %rdx,%rdx` | memory | 0x1cb792 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x1cb60d: test %rcx,%rcx` | memory | 0x1cb792 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x1cb61e: cmp 0x700ceb(%rip),%rax        # 8cc310 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x368d30>` | memory | 0x1cb648 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x1cb627: test %rax,%rax` | call+memory | 0x1cb3f8 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x1cb665: test %eax,%eax` | memory | 0x1cb3fb | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x1cb680: test %eax,%eax` | memory | 0x1cb3fb | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x1cb6a0: cmp %rdx,%rcx` | memory | 0x1cb792 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x1cb6a9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x1cb6a0 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x1cb6d4: test %eax,%eax` | memory | 0x1cb79d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x1cb6e1: cmpl $0x0,0x18(%rax)` | memory | 0x1cb704 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x1cb6fc: test %eax,%eax` | memory | 0x1cb3fb | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x1cb717: cmp %rdx,%rcx` | memory | 0x1cb7a5 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x1cb720: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x1cb717 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x1cb736: test %rax,%rax` | memory | 0x1cb7ec | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x1cb75b: test %rax,%rax` | call+memory | 0x1cb8c3 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x1cb7c1: test %rax,%rax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x1cb7d6: test %rax,%rax` | memory | 0x1cb7f7 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x1cb7db: cmpq $0x3,0x10(%rax)` | memory | 0x1cb7f7 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x1cb834: test %eax,%eax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x1cb845: test %rax,%rax` | call+memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x1cb865: test %eax,%eax` | memory | 0x1cb89b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x1cb869: cmpl $0x3,0x28(%rsp)` | memory | 0x1cb3ab | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x1cb8da: test %rax,%rax` | memory | 0x1cb8f0 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x1cb8df: cmpq $0x2,0x10(%rax)` | memory | 0x1cb8f0 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x1cb908: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x1cb921: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x1cb954: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x1cb95c: cmpq $0x0,0x8(%rsp)` | memory | 0x1cb988 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x1cb969: cmpl $0x0,0x18(%rax)` | memory | 0x1cb988 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x1cb980: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x1cb99d: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x1cb9b8: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x1cb9c0: cmpl $0x2,0x28(%rsp)` | memory | 0x1cb5ec | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x1cb9da: test %rax,%rax` | memory | 0x1cb9f0 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x1cb9df: cmpq $0x3,0x10(%rax)` | memory | 0x1cb9f0 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x1cba08: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x1cba25: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x1cba5c: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x112a | je | mem | `0x1cba64: cmpq $0x0,0x8(%rsp)` | memory | 0x1cba90 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x1cba71: cmpl $0x0,0x18(%rax)` | memory | 0x1cba90 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x1cba88: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x1cbaa5: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x1cbac0: test %eax,%eax` | memory | 0x1cb8b3 | back |
| RSA CRT arms | +0x118d | je | mem | `0x1cbac8: cmpl $0x3,0x28(%rsp)` | memory | 0x1cb5ec | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x1c55fa: test %r8,%r8` | memory | 0x1c572b | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x1c5722: dec %r8` | memory | 0x1c5610 | back |
| DH key agreement (driver) | +0x26 | jle | reg/arith | `0x28aab1: cmp $0x2710,%eax` | memory | 0x28aac1 | fwd |
| DH key agreement (driver) | +0x39 | je | reg/arith | `0x28aac6: test %rdi,%rdi` | memory | 0x28aaeb | fwd |
| DH key agreement (driver) | +0x46 | jle | reg/arith | `0x28aad1: cmp $0x2710,%eax` | call+memory | 0x28aaeb | fwd |
| DH key agreement (driver) | +0x6b | jge | reg/arith | `0x28aaf6: cmp $0x200,%eax` | call+memory | 0x28ab1c | fwd |
| DH key agreement (driver) | +0xbb | jne | mem | `0x28ab46: cmpl $0x1,0x30(%rsp)` | arithmetic/control | 0x28ab54 | fwd |
| DH key agreement (driver) | +0xe2 | je | reg/arith | `0x28ab6f: test %rax,%rax` | memory | 0x28abf2 | fwd |
| DH key agreement (driver) | +0x13f | je | reg/arith | `0x28abcc: test %rax,%rax` | memory | 0x28ad36 | fwd |
| DH key agreement (driver) | +0x14e | je | mem | `0x28abd8: cmpq $0x0,0x78(%r12)` | memory | 0x28ac0f | fwd |
| DH key agreement (driver) | +0x159 | jne | mem | `0x28abe0: testb $0x1,0x80(%r12)` | arithmetic/control | 0x28ac3d | fwd |
| DH key agreement (driver) | +0x191 | je | reg/arith | `0x28ac1e: test %rdx,%rdx` | memory | 0x28ad23 | fwd |
| DH key agreement (driver) | +0x1a4 | jae | reg/arith | `0x28ac30: cmp $0x8,%rdx` | arithmetic/control | 0x28acb2 | fwd |
| DH key agreement (driver) | +0x1c5 | jne | reg/arith | `0x28ac52: test %rdx,%rdx` | memory | 0x28ad8d | fwd |
| DH key agreement (driver) | +0x1d3 | je | reg/arith | `0x28ac5b: test %rbp,%rbp` | memory | 0x28ac6e | fwd |
| DH key agreement (driver) | +0x1e9 | jne | reg/arith | `0x28ac76: test %rdx,%rdx` | memory | 0x28ad75 | fwd |
| DH key agreement (driver) | +0x20a | je | reg/arith | `0x28ac98: test %eax,%eax` | memory | 0x28ad68 | fwd |
| DH key agreement (driver) | +0x276 | jne | reg/arith | `0x28ad03: cmp %rsi,%rdx` | arithmetic/control | 0x28acb8 | back |
| DH key agreement (driver) | +0x27b | je | reg/arith | `0x28ad08: test %rax,%rax` | memory | 0x28ad23 | fwd |
| DH key agreement (driver) | +0x291 | jne | reg/arith | `0x28ad1e: cmp %rdx,%rax` | memory | 0x28ad13 | back |
| DH key agreement (driver) | +0x2b1 | je | reg/arith | `0x28ad39: test %rax,%rax` | memory | 0x28ad58 | fwd |
| DH key agreement (driver) | +0x2e8 | je | reg/arith | `0x28ad75: test %rbp,%rbp` | memory | 0x28ad8d | fwd |
| DH key agreement (driver) | +0x305 | je | reg/arith | `0x28ad92: test %rax,%rax` | memory | 0x28ad9b | fwd |
| DH key agreement (driver) | +0x30e | je | reg/arith | `0x28ad9b: test %rdx,%rdx` | memory | 0x28ae80 | fwd |
| DH key agreement (driver) | +0x324 | je | reg/arith | `0x28adb1: test %rax,%rax` | memory | 0x28aeac | fwd |
| DH key agreement (driver) | +0x331 | je | reg/arith | `0x28adbe: test %rax,%rax` | call+memory | 0x28aeac | fwd |
| DH key agreement (driver) | +0x357 | je | reg/arith | `0x28ade5: test %eax,%eax` | memory | 0x28ae97 | fwd |
| DH key agreement (driver) | +0x37a | je | reg/arith | `0x28ae07: test %rax,%rax` | memory | 0x28aea7 | fwd |
| DH key agreement (driver) | +0x390 | je | reg/arith | `0x28ae1e: test %eax,%eax` | memory | 0x28aea0 | fwd |
| DH key agreement (driver) | +0x3a6 | jle | reg/arith | `0x28ae34: test %eax,%eax` | memory | 0x28aea0 | fwd |
| DH key agreement (driver) | +0x3bf | je | reg/arith | `0x28ae46: test %eax,%eax` | memory | 0x28aea7 | fwd |
| DH key agreement (driver) | +0x3cf | jo | reg/arith | `0x28ae5c: add $0x7,%eax` | memory | 0x28af7c | fwd |
| DH key agreement (driver) | +0x422 | je | reg/arith | `0x28aeaf: test %rdx,%rdx` | memory | 0x28af3c | fwd |
| DH key agreement (driver) | +0x435 | jae | reg/arith | `0x28aec1: cmp $0x8,%rdx` | arithmetic/control | 0x28aecb | fwd |
| DH key agreement (driver) | +0x48f | jne | reg/arith | `0x28af1c: cmp %rsi,%rdx` | arithmetic/control | 0x28aed1 | back |
| DH key agreement (driver) | +0x494 | je | reg/arith | `0x28af21: test %rax,%rax` | memory | 0x28af3c | fwd |
| DH key agreement (driver) | +0x4aa | jne | reg/arith | `0x28af37: cmp %rdx,%rax` | memory | 0x28af2c | back |
| DH key agreement (driver) | +0x4ca | je | reg/arith | `0x28af52: test %rax,%rax` | memory | 0x28af71 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x39 | je | reg/arith | `0x28b53c: test %rax,%rax` | memory | 0x28b5f9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x53 | je | reg/arith | `0x28b560: cmp %rsi,%rdx` | memory | 0x28b5f9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x62 | je | mem | `0x28b569: cmpq $0x0,(%rcx,%rsi,1)` | memory | 0x28b560 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x6b | je | reg/arith | `0x28b578: test %rdx,%rdx` | memory | 0x28b5f9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x83 | je | reg/arith | `0x28b590: cmp %rsi,%rdx` | memory | 0x28b5f9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8e | je | mem | `0x28b595: cmpq $0x0,(%rcx,%rsi,1)` | arithmetic/control | 0x28b590 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x93 | je | reg/arith | `0x28b5a0: cmp %rax,%rbp` | arithmetic/control | 0x28b5c2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa3 | je | reg/arith | `0x28b5b1: test %dl,%cl` | arithmetic/control | 0x28b5c2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbc | jne | reg/arith | `0x28b5c9: or %rbp,%rcx` | memory | 0x28b5f9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc4 | je | reg/arith | `0x28b5d1: cmp %rax,%rdx` | memory | 0x28b6a1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec | je | reg/arith | `0x28b5f9: test %rbp,%rbp` | memory | 0x28b6a1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf9 | je | reg/arith | `0x28b606: test %r13,%r13` | memory | 0x28b6cf | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x118 | je | reg/arith | `0x28b620: test %rax,%rax` | memory | 0x28b6ee | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x123 | je | mem | `0x28b62e: cmpq $0x0,0x10(%rax)` | memory | 0x28b6ee | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13b | je | reg/arith | `0x28b648: test %rax,%rax` | memory | 0x28b6e2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14c | jne | mem | `0x28b658: cmp 0x0(%r13),%rcx` | memory | 0x28b6e9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x164 | je | reg/arith | `0x28b672: test %esi,%esi` | memory | 0x28bcf9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x171 | je | reg/arith | `0x28b67e: test %r8d,%r8d` | arithmetic/control | 0x28b688 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x176 | jne | reg/arith | `0x28b683: cmp %r8d,%esi` | memory | 0x28b6e9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x17b | jne | mem | `0x28b688: cmp (%rdx),%rcx` | memory | 0x28b6e9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x182 | je | reg/arith | `0x28b690: test %ecx,%ecx` | arithmetic/control | 0x28bd02 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x18a | jne | reg/arith | `0x28b698: cmp %ecx,%esi` | arithmetic/control | 0x28b6e9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x21b | jb | reg/arith | `0x28b728: add %r12,%rbp` | memory | 0x28c949 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x27b | je | reg/arith | `0x28b787: cmp $0xffffffffffffffff,%rbp` | call+memory | 0x28c952 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2c1 | je | reg/arith | `0x28b7ce: test %r13,%r13` | memory | 0x28b94e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2d7 | je | reg/arith | `0x28b7e4: test %rdi,%rdi` | arithmetic/control | 0x28b9ad | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2e0 | je | reg/arith | `0x28b7ed: test %r14,%r14` | arithmetic/control | 0x28b9ad | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2e9 | je | reg/arith | `0x28b7f6: test %r12,%r12` | memory | 0x28b9ad | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2fc | jb | mem | `0x28b807: add 0x50(%rsp),%rbx` | memory | 0x28c95b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x319 | je | unknown | `?` | memory | 0x28baa0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x34a | jae | mem | `0x28b855: cmp 0x50(%rsp),%rbp` | memory | 0x28b865 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x365 | ja | reg/arith | `0x28b870: cmp $0x7cf,%eax` | arithmetic/control | 0x28b8b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x371 | ja | reg/arith | `0x28b87c: cmp $0x31f,%eax` | arithmetic/control | 0x28b8b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x37d | ja | reg/arith | `0x28b888: cmp $0x12b,%eax` | arithmetic/control | 0x28b8b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x387 | ja | reg/arith | `0x28b894: cmp $0x45,%eax` | memory | 0x28b8b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3b6 | jb | reg/arith | `0x28b8c3: add %rax,%r15` | memory | 0x28c970 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3cf | jae | mem | `0x28b8da: cmp 0x50(%rsp),%rbp` | call+memory | 0x28b8ea | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x400 | je | reg/arith | `0x28b90d: test %rax,%rax` | memory | 0x28bb6b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x420 | jne | reg/arith | `0x28b928: dec %rbx` | memory | 0x28b850 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x433 | jne | reg/arith | `0x28b93b: test %rbx,%rbx` | arithmetic/control | 0x28bab9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x446 | je | reg/arith | `0x28b953: test %rdi,%rdi` | call+memory | 0x28b97b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x46e | je | reg/arith | `0x28b97b: test %r14,%r14` | memory | 0x28ba6a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4a0 | je | reg/arith | `0x28b9ad: test %rdi,%rdi` | call+memory | 0x28b9d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4c8 | je | reg/arith | `0x28b9d5: test %r14,%r14` | call+memory | 0x28ba00 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4f7 | je | reg/arith | `0x28ba04: test %rdi,%rdi` | memory | 0x28ba44 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x532 | jne | reg/arith | `0x28ba3f: test %rdi,%rdi` | call+memory | 0x28ba20 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x55f | je | reg/arith | `0x28ba6c: test %r12,%r12` | call+memory | 0x28c2e0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5a3 | je | reg/arith | `0x28baab: test %rbx,%rbx` | memory | 0x28bf33 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5b1 | je | reg/arith | `0x28babe: test %rax,%rax` | memory | 0x28bc2e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5c8 | je | mem | `0x28bad3: cmpb $0x0,0x78(%rsp)` | call+memory | 0x28bc61 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x600 | je | reg/arith | `0x28bb05: test %rax,%rax` | memory | 0x28bc48 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x611 | jbe | reg/arith | `0x28bb1e: cmp %r14,%rsi` | arithmetic/control | 0x28bd65 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x61d | jo | reg/arith | `0x28bb2a: mul %rcx` | memory | 0x28c97d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x62f | jae | reg/arith | `0x28bb3c: cmp %rax,%rsi` | arithmetic/control | 0x28be0c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x638 | je | reg/arith | `0x28bb45: test %rcx,%rcx` | arithmetic/control | 0x28c98f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x648 | je | reg/arith | `0x28bb54: shr $0x20,%rax` | division | 0x28bda9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6af | je | reg/arith | `0x28bbbc: test %rdi,%rdi` | call+memory | 0x28bbf4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6e2 | jne | reg/arith | `0x28bbef: test %rdi,%rdi` | call+memory | 0x28bbd0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x726 | jne | mem | `0x28bc2e: cmpb $0x0,0x90(%rsp)` | call+memory | 0x28bf33 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7ac | je | reg/arith | `0x28bcb9: test %rdi,%rdi` | call+memory | 0x28c154 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7e2 | jne | reg/arith | `0x28bcef: test %rdi,%rdi` | arithmetic/control | 0x28bcd0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x7ec | jne | mem | `0x28bcf9: cmp (%rdx),%rcx` | call+memory | 0x28b6e9 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x801 | jne | reg/arith | `0x28bd0f: test %eax,%eax` | memory | 0x28b6ee | back |
| EC wNAF multiply (verification / public-scalar core) | +0x82c | je | reg/arith | `0x28bd39: test %rsi,%rsi` | arithmetic/control | 0x28c998 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x83f | je | reg/arith | `0x28bd4b: shr $0x20,%rdx` | division | 0x28c615 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x85e | je | reg/arith | `0x28bd6a: cmp $0xffffffffffffffff,%rcx` | memory | 0x28c986 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8b0 | jbe | mem | `0x28bdbc: cmp 0x10(%rdx),%rax` | call+memory | 0x28bdf9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8f6 | jb | mem | `0x28bdf9: add 0x50(%rsp),%rax` | memory | 0x28c9f1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x90c | jae | reg/arith | `0x28be19: cmp %rax,%rbx` | memory | 0x28bf03 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x937 | jae | mem | `0x28be3d: cmp 0x38(%rsp),%rbx` | memory | 0x28be67 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x945 | jb | reg/arith | `0x28be52: sub %rcx,%rsi` | memory | 0x28c69d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x98d | je | reg/arith | `0x28be9a: test %rax,%rax` | memory | 0x28c56a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x9ad | je | mem | `0x28beb9: cmpq $0x0,(%rdi)` | memory | 0x28c5b5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x9ed | jne | mem | `0x28beeb: cmp %rbx,0x80(%rsp)` | call+memory | 0x28be3d | back |
| EC wNAF multiply (verification / public-scalar core) | +0xa27 | je | reg/arith | `0x28bf33: cmp $0xffffffffffffffff,%r15` | memory | 0x28c964 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa4b | je | reg/arith | `0x28bf58: test %rax,%rax` | memory | 0x28c0c9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa6d | je | mem | `0x28bf6c: cmpq $0x0,0x88(%rsp)` | memory | 0x28c08a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xaa0 | je | reg/arith | `0x28bfad: test %rcx,%rcx` | memory | 0x28c9bc | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xaac | je | mem | `0x28bfb6: cmpq $0x0,0x40(%rsp)` | memory | 0x28c54a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xac4 | ja | reg/arith | `0x28bfd0: cmp $0x40,%rcx` | arithmetic/control | 0x28c9d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xad5 | jne | reg/arith | `0x28bfe2: test %rax,%rax` | memory | 0x28c06f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xae8 | je | mem | `0x28bff3: cmpq $0x0,0x50(%rax)` | memory | 0x28c1ab | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb08 | je | reg/arith | `0x28c015: test %rax,%rax` | memory | 0x28c19f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb2a | je | reg/arith | `0x28c037: test %rax,%rax` | call | 0x28c179 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb37 | je | reg/arith | `0x28c045: test %eax,%eax` | memory | 0x28c179 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb54 | jne | reg/arith | `0x28c061: test %rcx,%rcx` | arithmetic/control | 0x28bfd0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xb74 | jne | mem | `0x28c072: cmp 0x88(%rsp),%rbx` | memory | 0x28bfa0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xb84 | je | reg/arith | `0x28c08e: cmp %rax,%r13` | call+memory | 0x28c2f4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc08 | je | reg/arith | `0x28c115: test %rdi,%rdi` | call+memory | 0x28c154 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc42 | jne | reg/arith | `0x28c14f: test %rdi,%rdi` | memory | 0x28c130 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xd0b | je | reg/arith | `0x28c218: test %rdi,%rdi` | call+memory | 0x28c254 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd42 | jne | reg/arith | `0x28c24f: test %rdi,%rdi` | call+memory | 0x28c230 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xd6e | je | reg/arith | `0x28c27b: test %rdi,%rdi` | call+memory | 0x28c29f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd8d | jne | reg/arith | `0x28c29a: test %rdi,%rdi` | call+memory | 0x28c290 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xdf2 | je | reg/arith | `0x28c2ff: test %rax,%rax` | memory | 0x28c4ac | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe08 | je | reg/arith | `0x28c315: test %r13,%r13` | memory | 0x28c4c7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe35 | je | reg/arith | `0x28c33d: cmp %r13,%rbp` | memory | 0x28c4c7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe47 | jae | mem | `0x28c352: cmp 0x50(%rsp),%rbp` | memory | 0x28c367 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe67 | je | reg/arith | `0x28c375: test %eax,%eax` | memory | 0x28c5f6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe77 | jbe | mem | `0x28c382: cmpq $0x1,(%rax,%rbp,8)` | memory | 0x28c33a | back |
| EC wNAF multiply (verification / public-scalar core) | +0xe97 | je | reg/arith | `0x28c3a5: test %eax,%eax` | memory | 0x28c529 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xea9 | je | reg/arith | `0x28c3b6: test %rcx,%rcx` | arithmetic/control | 0x28c9bc | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xeb8 | ja | reg/arith | `0x28c3c4: cmp $0x40,%rcx` | arithmetic/control | 0x28c9d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec9 | jne | reg/arith | `0x28c3d6: test %rax,%rax` | memory | 0x28c33a | back |
| EC wNAF multiply (verification / public-scalar core) | +0xee1 | je | reg/arith | `0x28c3ee: test %rax,%rax` | memory | 0x28c70f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xef2 | jne | mem | `0x28c3ff: cmp (%rsi),%r9` | memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf07 | je | reg/arith | `0x28c415: test %edi,%edi` | memory | 0x28c467 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf10 | je | reg/arith | `0x28c41d: test %r8d,%r8d` | arithmetic/control | 0x28c42b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf15 | jne | reg/arith | `0x28c422: cmp %r8d,%edi` | memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf1e | jne | mem | `0x28c42b: cmp (%rdx),%r9` | memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf2b | je | reg/arith | `0x28c438: test %r8d,%r8d` | arithmetic/control | 0x28c446 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf30 | jne | reg/arith | `0x28c43d: cmp %r8d,%edi` | memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf3e | jne | mem | `0x28c44b: cmp (%rcx),%r9` | memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf4b | je | reg/arith | `0x28c458: test %r8d,%r8d` | arithmetic/control | 0x28c47e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf50 | je | reg/arith | `0x28c45d: cmp %r8d,%edi` | arithmetic/control | 0x28c47e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf5a | jne | mem | `0x28c467: cmp (%rdx),%r9` | memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf68 | jne | mem | `0x28c475: cmp (%rcx),%r9` | call+memory | 0x28c51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf7c | je | reg/arith | `0x28c48a: test %eax,%eax` | memory | 0x28c529 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf91 | jne | reg/arith | `0x28c49e: test %rcx,%rcx` | arithmetic/control | 0x28c3c4 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xfc9 | je | reg/arith | `0x28c4d6: test %rax,%rax` | call+memory | 0x28c5f6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xfee | je | reg/arith | `0x28c4f2: test %eax,%eax` | memory | 0x28c6fa | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1000 | jbe | reg/arith | `0x28c504: cmp $0x7fffffff,%r14` | memory | 0x28c71b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x103e | jae | reg/arith | `0x28c54a: cmp $0x41,%rcx` | memory | 0x28c9d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1114 | je | reg/arith | `0x28c620: cmp $0xffffffffffffffff,%rdi` | memory | 0x28c9a7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1133 | jb | reg/arith | `0x28c63f: sub $0x1,%rcx` | arithmetic/control | 0x28c9b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x113d | jae | reg/arith | `0x28c649: cmp $0x41,%rdx` | memory | 0x28c9c9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1153 | jo | reg/arith | `0x28c660: mul %rdx` | memory | 0x28c9e2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1162 | jne | mem | `0x28c66e: cmp %rax,0x28(%rcx)` | memory | 0x28c691 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x120e | je | reg/arith | `0x28c71b: test %r14,%r14` | arithmetic/control | 0x28c9fd | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x122e | jle | mem | `0x28c72f: cmpl $0x1,0x50(%rsp)` | arithmetic/control | 0x28c8bf | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1237 | jne | reg/arith | `0x28c744: test %r13d,%r13d` | memory | 0x28c767 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1251 | je | reg/arith | `0x28c75f: test %eax,%eax` | memory | 0x28c529 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1268 | je | mem | `0x28c76f: cmpq $0x0,0x80(%rsp)` | arithmetic/control | 0x28c72f | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1294 | je | reg/arith | `0x28c79d: test %eax,%eax` | memory | 0x28c8a9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12a5 | je | mem | `0x28c7ad: cmp %r12,0x80(%rsp)` | memory | 0x28c72f | back |
| EC wNAF multiply (verification / public-scalar core) | +0x12b4 | jbe | mem | `0x28c7c0: cmp %rbp,(%rax,%r12,8)` | memory | 0x28c7aa | back |
| EC wNAF multiply (verification / public-scalar core) | +0x12c5 | je | reg/arith | `0x28c7d3: test %ebx,%ebx` | arithmetic/control | 0x28c7aa | back |
| EC wNAF multiply (verification / public-scalar core) | +0x12cf | je | reg/arith | `0x28c7dc: cmp %eax,%r15d` | arithmetic/control | 0x28c80e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12d4 | jne | reg/arith | `0x28c7e1: test %r13d,%r13d` | memory | 0x28c803 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12ed | je | reg/arith | `0x28c7fb: test %eax,%eax` | memory | 0x28c921 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x131c | je | reg/arith | `0x28c829: test %r13d,%r13d` | memory | 0x28c782 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1337 | je | reg/arith | `0x28c840: test %eax,%eax` | memory | 0x28c921 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1352 | je | reg/arith | `0x28c85a: test %rax,%rax` | call+memory | 0x28c7aa | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1366 | jne | reg/arith | `0x28c874: test %eax,%eax` | call+memory | 0x28c7aa | back |
| EC wNAF multiply (verification / public-scalar core) | +0x13b2 | je | reg/arith | `0x28c8bf: test %r13d,%r13d` | memory | 0x28c8d6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13c9 | je | reg/arith | `0x28c8d6: test %r15d,%r15d` | memory | 0x28c8f4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13e2 | je | reg/arith | `0x28c8f0: test %eax,%eax` | call+memory | 0x28c921 | fwd |
| ML-KEM decapsulation (provider driver) | +0x7 | je | mem | `0x1d06e2: cmpq $0x0,0x50(%r8)` | arithmetic/control | 0x1d08b3 | fwd |
| ML-KEM decapsulation (provider driver) | +0x1f | jne | reg/arith | `0x1d06fc: or %r9b,%r10b` | memory | 0x1d08b3 | fwd |
| ML-KEM decapsulation (provider driver) | +0x5c | jne | reg/arith | `0x1d0739: or %al,%sil` | memory | 0x1d088a | fwd |
| ML-KEM decapsulation (provider driver) | +0x66 | jne | mem | `0x1d0742: cmp 0x28(%r15),%rcx` | memory | 0x1d088a | fwd |
| ML-KEM decapsulation (provider driver) | +0x8f | je | reg/arith | `0x1d076c: test %rax,%rax` | memory | 0x1d088a | fwd |
| ML-KEM decapsulation (provider driver) | +0xa2 | je | reg/arith | `0x1d077c: cmp $0x5ae,%ecx` | arithmetic/control | 0x1d099a | fwd |
| ML-KEM decapsulation (provider driver) | +0xae | je | reg/arith | `0x1d0788: cmp $0x5af,%ecx` | arithmetic/control | 0x1d08b4 | fwd |
| ML-KEM decapsulation (provider driver) | +0xbc | jne | reg/arith | `0x1d0796: cmp $0x5b0,%ecx` | call+memory | 0x1d0a85 | fwd |
| ML-KEM decapsulation (provider driver) | +0x163 | jne | reg/arith | `0x1d083c: cmp $0x1000,%r15` | memory | 0x1d07f0 | back |
| ML-KEM decapsulation (provider driver) | +0x1a3 | jne | reg/arith | `0x1d087c: cmp $0x627,%rcx` | arithmetic/control | 0x1d0850 | back |
| ML-KEM decapsulation (provider driver) | +0x26b | jne | reg/arith | `0x1d0944: cmp $0xc07,%rcx` | memory | 0x1d0900 | back |
| ML-KEM decapsulation (provider driver) | +0x2b3 | jne | reg/arith | `0x1d098c: cmp $0x447,%rcx` | arithmetic/control | 0x1d0960 | back |
| ML-KEM decapsulation (provider driver) | +0x363 | jne | reg/arith | `0x1d0a3c: cmp $0x800,%r15` | memory | 0x1d09f0 | back |
| ML-KEM decapsulation (provider driver) | +0x3a3 | jne | reg/arith | `0x1d0a7c: cmp $0x307,%rcx` | arithmetic/control | 0x1d0a50 | back |
| ML-KEM decapsulation (provider driver) | +0x3a8 | jne | reg/arith | `0x1d0a85: test $0x7,%bl` | memory | 0x1d08a2 | back |
| ML-KEM K-PKE decrypt | +0x65 | js | reg/arith | `0x2966f2: test %r14,%r14` | memory | 0x2970bb | fwd |
| ML-KEM K-PKE decrypt | +0x70 | jle | reg/arith | `0x2966fe: test %ebp,%ebp` | arithmetic/control | 0x296915 | fwd |
| ML-KEM K-PKE decrypt | +0x84 | ja | reg/arith | `0x296710: cmp $0xf,%r14d` | memory | 0x2970ae | fwd |
| ML-KEM K-PKE decrypt | +0x9f | jae | reg/arith | `0x296727: cmp $0x20,%eax` | memory | 0x2970c8 | fwd |
| ML-KEM K-PKE decrypt | +0x140 | jae | reg/arith | `0x2967c9: cmp $0x100,%rdx` | arithmetic/control | 0x29686b | fwd |
| ML-KEM K-PKE decrypt | +0x148 | jne | reg/arith | `0x2967d6: test %ecx,%ecx` | memory | 0x2967e6 | fwd |
| ML-KEM K-PKE decrypt | +0x169 | je | reg/arith | `0x2967f6: test %bl,%r11b` | memory | 0x296820 | fwd |
| ML-KEM K-PKE decrypt | +0x18b | jb | reg/arith | `0x296814: cmp $0x100,%rdx` | arithmetic/control | 0x2967d6 | back |
| ML-KEM K-PKE decrypt | +0x196 | jb | reg/arith | `0x296823: sub %eax,%r10d` | arithmetic/control | 0x2967b0 | back |
| ML-KEM K-PKE decrypt | +0x19d | jb | reg/arith | `0x29682b: sub %eax,%ecx` | arithmetic/control | 0x2971b3 | fwd |
| ML-KEM K-PKE decrypt | +0x1a6 | ja | reg/arith | `0x296833: cmp $0xf,%ecx` | memory | 0x2971a6 | fwd |
| ML-KEM K-PKE decrypt | +0x1d5 | jb | reg/arith | `0x29685e: cmp $0x100,%rdx` | memory | 0x2967d6 | back |
| ML-KEM K-PKE decrypt | +0x24e | jne | reg/arith | `0x2968d8: cmp $0x100,%rax` | call | 0x296870 | back |
| ML-KEM K-PKE decrypt | +0x27f | jg | reg/arith | `0x29690c: dec %r13d` | memory | 0x296790 | back |
| ML-KEM K-PKE decrypt | +0x28e | ja | reg/arith | `0x29691a: cmp $0xf,%r15d` | memory | 0x2970ae | fwd |
| ML-KEM K-PKE decrypt | +0x2ef | jbe | reg/arith | `0x296978: cmp $0xff,%rsi` | arithmetic/control | 0x2969b2 | fwd |
| ML-KEM K-PKE decrypt | +0x320 | ja | reg/arith | `0x2969a9: cmp $0xff,%rsi` | arithmetic/control | 0x296a12 | fwd |
| ML-KEM K-PKE decrypt | +0x324 | jne | reg/arith | `0x2969b2: test %ecx,%ecx` | memory | 0x2969c2 | fwd |
| ML-KEM K-PKE decrypt | +0x345 | jne | reg/arith | `0x2969d2: test %bl,%r11b` | arithmetic/control | 0x296990 | back |
| ML-KEM K-PKE decrypt | +0x34d | jb | reg/arith | `0x2969da: sub %eax,%r10d` | arithmetic/control | 0x296960 | back |
| ML-KEM K-PKE decrypt | +0x354 | jb | reg/arith | `0x2969e2: sub %eax,%ecx` | arithmetic/control | 0x2971b3 | fwd |
| ML-KEM K-PKE decrypt | +0x35d | jae | reg/arith | `0x2969ea: cmp $0x10,%ecx` | memory | 0x2971a6 | fwd |
| ML-KEM K-PKE decrypt | +0x389 | ja | reg/arith | `0x296a16: cmp $0x1f,%eax` | memory | 0x297199 | fwd |
| ML-KEM K-PKE decrypt | +0x43e | jne | reg/arith | `0x296ac8: cmp $0x100,%rax` | call+memory | 0x296a60 | back |
| ML-KEM K-PKE decrypt | +0x4fc | jne | reg/arith | `0x296b86: cmp $0x100,%rax` | memory | 0x296b10 | back |
| ML-KEM K-PKE decrypt | +0x614 | jne | reg/arith | `0x296c9e: cmp $0x100,%rax` | memory | 0x296bd0 | back |
| ML-KEM K-PKE decrypt | +0x96b | jne | reg/arith | `0x296ff7: cmp $0x20,%rcx` | memory | 0x296d00 | back |
| ML-KEM K-PKE decrypt | +0x9b2 | jne | reg/arith | `0x29703c: cmp $0x200,%rax` | memory | 0x297010 | back |
| ML-KEM K-PKE decrypt | +0xa0a | jne | reg/arith | `0x297094: cmp $0x200,%rax` | arithmetic/control | 0x297050 | back |
| ML-KEM K-PKE decrypt | +0xa66 | ja | reg/arith | `0x2970ef: cmp $0xff,%rdx` | arithmetic/control | 0x297199 | fwd |
| ML-KEM K-PKE decrypt | +0xa6e | jne | reg/arith | `0x2970fc: test %ecx,%ecx` | memory | 0x29710c | fwd |
| ML-KEM K-PKE decrypt | +0xa90 | je | reg/arith | `0x29711d: test %r11b,%r10b` | memory | 0x297150 | fwd |
| ML-KEM K-PKE decrypt | +0xab5 | jbe | reg/arith | `0x29713e: cmp $0xff,%rdx` | arithmetic/control | 0x2970fc | back |
| ML-KEM K-PKE decrypt | +0xac6 | jb | reg/arith | `0x297153: sub %eax,%r9d` | arithmetic/control | 0x2970d7 | back |
| ML-KEM K-PKE decrypt | +0xad1 | jb | reg/arith | `0x29715f: sub %eax,%ecx` | arithmetic/control | 0x2971b3 | fwd |
| ML-KEM K-PKE decrypt | +0xad6 | jae | reg/arith | `0x297163: cmp $0x10,%ecx` | memory | 0x2971a6 | fwd |
| ML-KEM K-PKE decrypt | +0xb03 | jbe | reg/arith | `0x29718c: cmp $0xff,%rdx` | memory | 0x2970fc | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xc3 | jle | reg/arith | `0x297270: test %r12,%r12` | call+memory | 0x2972e4 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x103 | je | reg/arith | `0x2972c1: test %eax,%eax` | call | 0x2991d8 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x120 | jg | reg/arith | `0x2972dd: cmp $0x1,%ebp` | arithmetic/control | 0x2972a0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x237 | jle | reg/arith | `0x2973e4: test %r14d,%r14d` | memory | 0x29815d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x47e | jle | reg/arith | `0x29762f: cmp $0x1,%r12d` | memory | 0x297f4b | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x528 | je | reg/arith | `0x2976dc: test $0x1,%sil` | memory | 0x2977d0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x603 | jne | reg/arith | `0x2977bc: cmp $0x100,%rcx` | arithmetic/control | 0x2976f0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x856 | jne | reg/arith | `0x297a0f: cmp $0x100,%rdx` | memory | 0x2977e0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x867 | je | reg/arith | `0x297a24: cmp $0x1,%edx` | memory | 0x2975d0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xa04 | jle | reg/arith | `0x297bbe: cmp $0x2,%edx` | arithmetic/control | 0x2975d0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xa0e | je | reg/arith | `0x297bcc: test $0x1,%al` | memory | 0x297ce0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xb11 | jne | reg/arith | `0x297cca: cmp $0x100,%rsi` | arithmetic/control | 0x297be0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xd80 | jne | reg/arith | `0x297f39: cmp $0x100,%rsi` | arithmetic/control | 0x297ce0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xe57 | je | reg/arith | `0x298015: test %eax,%eax` | memory | 0x2980f5 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf2f | jne | reg/arith | `0x2980e8: cmp $0x80,%rcx` | memory | 0x298020 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf83 | jne | reg/arith | `0x29813c: cmp $0x80,%rcx` | arithmetic/control | 0x298110 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf87 | je | reg/arith | `0x298145: test %eax,%eax` | arithmetic/control | 0x299285 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf97 | jg | reg/arith | `0x298154: dec %r14d` | memory | 0x297f90 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x10b2 | je | reg/arith | `0x298270: test %al,%al` | memory | 0x298300 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x112b | jne | reg/arith | `0x2982e4: cmp $0x101,%r8` | arithmetic/control | 0x298280 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11d5 | jne | reg/arith | `0x29838e: cmp $0x108,%r9` | arithmetic/control | 0x298320 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11d9 | jo | reg/arith | `0x298397: dec %edx` | arithmetic/control | 0x29943f | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11ef | jg | reg/arith | `0x2983ad: test %edx,%edx` | memory | 0x298270 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1206 | ja | reg/arith | `0x2983c3: cmp $0x1f,%ecx` | memory | 0x29948d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13b9 | jne | reg/arith | `0x298572: cmp $0x100,%rdx` | arithmetic/control | 0x298430 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13c1 | jo | reg/arith | `0x29857f: dec %eax` | arithmetic/control | 0x29944c | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13d0 | jg | reg/arith | `0x29858e: test %eax,%eax` | call | 0x298420 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x147f | je | reg/arith | `0x29863d: test %eax,%eax` | memory | 0x298734 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x156e | jne | reg/arith | `0x298727: cmp $0x80,%rcx` | memory | 0x298660 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15c3 | jne | reg/arith | `0x29877c: cmp $0x80,%rcx` | arithmetic/control | 0x298750 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15c7 | je | reg/arith | `0x298785: test %eax,%eax` | memory | 0x299332 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x165f | jne | reg/arith | `0x298819: cmp $0x100,%rax` | memory | 0x2987a0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dc8 | jne | reg/arith | `0x298f84: cmp $0x20,%rax` | arithmetic/control | 0x298830 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dd1 | ja | reg/arith | `0x298f8e: cmp $0x1f,%ebx` | arithmetic/control | 0x29948d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f70 | jne | reg/arith | `0x29912a: cmp $0x100,%rax` | memory | 0x298fe0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fa2 | je | reg/arith | `0x29915c: cmp $0x200,%rax` | arithmetic/control | 0x2991ce | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fa8 | jb | reg/arith | `0x299166: add %ebx,%esi` | memory | 0x299459 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fb9 | jb | reg/arith | `0x299176: cmp $0x40,%esi` | arithmetic/control | 0x299150 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fbb | jne | unknown | `?` | arithmetic/control | 0x2991a0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fc0 | jae | reg/arith | `0x29917d: cmp $0x40,%ecx` | memory | 0x299480 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fe3 | jae | reg/arith | `0x2991a0: cmp $0x40,%ecx` | memory | 0x299466 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1ff7 | je | reg/arith | `0x2991b5: test %ecx,%ecx` | arithmetic/control | 0x299473 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x216c | je | reg/arith | `0x299329: test %r14d,%r14d` | memory | 0x298201 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x226b | jne | reg/arith | `0x299424: cmp $0x200,%rcx` | arithmetic/control | 0x2993e0 | back |
| ML-KEM inverse NTT | +0x56 | jb | reg/arith | `0x29a423: add %rsi,%rbx` | memory | 0x29a904 | fwd |
| ML-KEM inverse NTT | +0x64 | ja | reg/arith | `0x29a430: cmp $0x7e,%r8` | memory | 0x29a911 | fwd |
| ML-KEM inverse NTT | +0xb8 | jbe | reg/arith | `0x29a484: cmp $0x7,%r8` | memory | 0x29a4df | fwd |
| ML-KEM inverse NTT | +0x101 | jae | reg/arith | `0x29a4ce: cmp %r13,%r14` | memory | 0x29a4f0 | fwd |
| ML-KEM inverse NTT | +0x10d | jae | reg/arith | `0x29a4da: cmp %r12,%r15` | arithmetic/control | 0x29a4f0 | fwd |
| ML-KEM inverse NTT | +0x2fa | jne | reg/arith | `0x29a6c7: cmp %r13,%r8` | memory | 0x29a520 | back |
| ML-KEM inverse NTT | +0x317 | ja | reg/arith | `0x29a6e0: cmp $0xff,%r8` | arithmetic/control | 0x29a8ef | fwd |
| ML-KEM inverse NTT | +0x324 | jae | reg/arith | `0x29a6ed: cmp $0x100,%rcx` | memory | 0x29a8da | fwd |
| ML-KEM inverse NTT | +0x3b4 | jb | reg/arith | `0x29a781: cmp %rbx,%r8` | arithmetic/control | 0x29a6e0 | back |
| ML-KEM inverse NTT | +0x3c4 | jne | reg/arith | `0x29a78d: cmp $0x100,%rcx` | arithmetic/control | 0x29a420 | back |
| ML-KEM inverse NTT | +0x3d4 | jb | reg/arith | `0x29a79d: cmp $0x100,%rsi` | memory | 0x29a410 | back |
| ML-KEM inverse NTT | +0x4f5 | jne | reg/arith | `0x29a8bf: cmp $0x100,%rax` | arithmetic/control | 0x29a7c0 | back |
| ML-KEM inner product | +0x5b | jne | reg/arith | `0x299668: test %r12b,%r15b` | arithmetic/control | 0x29991b | fwd |
| ML-KEM inner product | +0x64 | jne | reg/arith | `0x299671: and %bpl,%r8b` | arithmetic/control | 0x29991b | fwd |
| ML-KEM inner product | +0x6d | jne | reg/arith | `0x29967a: and %r14b,%r10b` | memory | 0x29991b | fwd |
| ML-KEM inner product | +0x300 | jne | reg/arith | `0x299909: cmp $0x100,%r8` | arithmetic/control | 0x2996b0 | back |
| ML-KEM inner product | +0x3fa | jne | reg/arith | `0x299a03: cmp $0x100,%r14` | arithmetic/control | 0x299930 | back |
| ML-KEM inner product | +0x406 | jo | reg/arith | `0x299a13: dec %r8d` | arithmetic/control | 0x299ea4 | fwd |
| ML-KEM inner product | +0x40f | jle | reg/arith | `0x299a1c: test %r8d,%r8d` | memory | 0x299e95 | fwd |
| ML-KEM inner product | +0x4c1 | jle | reg/arith | `0x299ace: dec %r8d` | arithmetic/control | 0x299e95 | fwd |
| ML-KEM inner product | +0x4cc | je | reg/arith | `0x299ada: test %cl,%cl` | memory | 0x299c00 | fwd |
| ML-KEM inner product | +0x5dc | jne | reg/arith | `0x299be5: cmp $0x100,%r10` | arithmetic/control | 0x299af0 | back |
| ML-KEM inner product | +0x87a | jne | reg/arith | `0x299e83: cmp $0x100,%r10` | arithmetic/control | 0x299c00 | back |
| ML-KEM matrix transpose-multiply-add | +0x1b | jle | reg/arith | `0x29a949: test %ecx,%ecx` | memory | 0x29b2ac | fwd |
| ML-KEM matrix transpose-multiply-add | +0x16f | jle | reg/arith | `0x29aa91: cmp $0x1,%eax` | memory | 0x29b2ac | fwd |
| ML-KEM matrix transpose-multiply-add | +0x17f | je | mem | `0x29aaaa: cmpb $0x0,-0x62(%rsp)` | memory | 0x29abb0 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x26e | jne | reg/arith | `0x29ab97: cmp $0x100,%r11` | arithmetic/control | 0x29aac0 | back |
| ML-KEM matrix transpose-multiply-add | +0x510 | jne | reg/arith | `0x29ae3a: cmp $0x100,%rax` | memory | 0x29abc0 | back |
| ML-KEM matrix transpose-multiply-add | +0x51b | je | mem | `0x29ae46: cmpl $0x1,-0x60(%rsp)` | memory | 0x29aa70 | back |
| ML-KEM matrix transpose-multiply-add | +0x5c7 | jle | reg/arith | `0x29aeec: cmp $0x2,%r9d` | memory | 0x29aa70 | back |
| ML-KEM matrix transpose-multiply-add | +0x5d2 | je | mem | `0x29aefd: cmpb $0x0,-0x61(%rsp)` | memory | 0x29b010 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x6d1 | jne | reg/arith | `0x29affa: cmp $0x100,%rbp` | arithmetic/control | 0x29af10 | back |
| ML-KEM matrix transpose-multiply-add | +0x971 | jne | reg/arith | `0x29b29a: cmp $0x100,%rbp` | arithmetic/control | 0x29b020 | back |
| ML-KEM matrix expansion (public) | +0x3f | jle | reg/arith | `0x299efd: test %ecx,%ecx` | memory | 0x29a0c1 | fwd |
| ML-KEM matrix expansion (public) | +0x6c | je | mem | `0x299f27: cmp 0x4(%rsp),%r14d` | call+memory | 0x29a0b2 | fwd |
| ML-KEM matrix expansion (public) | +0x92 | je | reg/arith | `0x299f50: test %eax,%eax` | memory | 0x29a0e7 | fwd |
| ML-KEM matrix expansion (public) | +0xad | je | reg/arith | `0x299f6b: test %eax,%eax` | memory | 0x29a0e7 | fwd |
| ML-KEM matrix expansion (public) | +0x116 | je | reg/arith | `0x299fd3: test %rax,%rax` | memory | 0x29a0c9 | fwd |
| ML-KEM matrix expansion (public) | +0x121 | je | mem | `0x299fdc: cmpq $0x0,0x70(%rax)` | memory | 0x29a0d2 | fwd |
| ML-KEM matrix expansion (public) | +0x131 | je | reg/arith | `0x299fee: test %rax,%rax` | memory | 0x29a0db | fwd |
| ML-KEM matrix expansion (public) | +0x13e | je | reg/arith | `0x299ffb: test %rdi,%rdi` | call+memory | 0x29a0e7 | fwd |
| ML-KEM matrix expansion (public) | +0x160 | je | reg/arith | `0x29a01e: test %eax,%eax` | arithmetic/control | 0x29a0e7 | fwd |
| ML-KEM matrix expansion (public) | +0x17a | je | reg/arith | `0x29a034: cmp $0xaa,%rax` | arithmetic/control | 0x29a0a0 | fwd |
| ML-KEM matrix expansion (public) | +0x183 | ja | reg/arith | `0x29a03c: cmp $0xff,%r13` | memory | 0x299f20 | back |
| ML-KEM matrix expansion (public) | +0x1a9 | ja | reg/arith | `0x29a063: cmp $0xd00,%esi` | memory | 0x29a080 | fwd |
| ML-KEM matrix expansion (public) | +0x1b7 | je | reg/arith | `0x29a070: cmp $0xff,%r13` | arithmetic/control | 0x299f20 | back |
| ML-KEM matrix expansion (public) | +0x1d4 | ja | reg/arith | `0x29a08e: cmp $0xd00,%ecx` | memory | 0x29a030 | back |
| ML-KEM matrix expansion (public) | +0x1e7 | jb | reg/arith | `0x29a0a0: cmp $0x100,%r13` | arithmetic/control | 0x299fcf | back |
| ML-KEM matrix expansion (public) | +0x1fb | jne | mem | `0x29a0b7: cmp 0x4(%rsp),%ebp` | arithmetic/control | 0x299f0a | back |
| ML-KEM vector decode 12-bit | +0x2 | jle | reg/arith | `0x29a200: test %edx,%edx` | memory | 0x29a282 | fwd |
| ML-KEM vector decode 12-bit | +0x17 | je | reg/arith | `0x29a210: cmp $0x80,%rcx` | memory | 0x29a270 | fwd |
| ML-KEM vector decode 12-bit | +0x54 | ja | reg/arith | `0x29a24d: cmp $0xd00,%r11d` | arithmetic/control | 0x29a287 | fwd |
| ML-KEM vector decode 12-bit | +0x68 | jb | reg/arith | `0x29a261: cmp $0xd01,%r9d` | arithmetic/control | 0x29a210 | back |
| ML-KEM vector decode 12-bit | +0x80 | jg | reg/arith | `0x29a27e: dec %edx` | arithmetic/control | 0x29a204 | back |
| ML-KEM vector encode | +0x7 | js | reg/arith | `0x29a115: test %edx,%edx` | arithmetic/control | 0x29a1f0 | fwd |
| ML-KEM vector encode | +0x11 | jle | reg/arith | `0x29a11f: test %ecx,%ecx` | arithmetic/control | 0x29a1b6 | fwd |
| ML-KEM vector encode | +0x2c | jle | reg/arith | `0x29a13a: dec %eax` | arithmetic/control | 0x29a1b6 | fwd |
| ML-KEM vector encode | +0x53 | je | reg/arith | `0x29a15c: cmp $0x200,%r10` | arithmetic/control | 0x29a130 | back |
| ML-KEM vector encode | +0x59 | jb | reg/arith | `0x29a167: add %edx,%ebx` | memory | 0x29a1bc | fwd |
| ML-KEM vector encode | +0x63 | jb | reg/arith | `0x29a170: cmp $0x40,%ebx` | arithmetic/control | 0x29a150 | back |
| ML-KEM vector encode | +0x65 | jne | unknown | `?` | arithmetic/control | 0x29a190 | fwd |
| ML-KEM vector encode | +0x6a | jae | reg/arith | `0x29a177: cmp $0x40,%ecx` | memory | 0x29a1e3 | fwd |
| ML-KEM vector encode | +0x83 | jae | reg/arith | `0x29a190: cmp $0x40,%ecx` | memory | 0x29a1c9 | fwd |
| ML-KEM vector encode | +0x93 | je | reg/arith | `0x29a1a1: test %ecx,%ecx` | arithmetic/control | 0x29a1d6 | fwd |
| ML-KEM CBD sampling eta=2 | +0x5a | je | reg/arith | `0x29b458: test %eax,%eax` | memory | 0x29b557 | fwd |
| ML-KEM CBD sampling eta=2 | +0x14a | jne | reg/arith | `0x29b544: cmp $0x80,%rax` | arithmetic/control | 0x29b480 | back |
| ML-KEM CBD sampling eta=2 | +0x192 | jne | reg/arith | `0x29b58b: cmp $0x80,%rcx` | arithmetic/control | 0x29b560 | back |
| ML-KEM CBD sampling eta=3 | +0x7e | je | reg/arith | `0x29b61c: test %eax,%eax` | memory | 0x29b957 | fwd |
| ML-KEM CBD sampling eta=3 | +0x3aa | jne | reg/arith | `0x29b946: cmp $0x40,%rcx` | arithmetic/control | 0x29b640 | back |
| ML-KEM CBD sampling eta=3 | +0x3f2 | jne | reg/arith | `0x29b98b: cmp $0xc7,%rcx` | arithmetic/control | 0x29b960 | back |
| ML-KEM CBD vector sampling then NTT | +0x21 | jle | reg/arith | `0x29a2ae: test %r8d,%r8d` | memory | 0x29a310 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x60 | je | reg/arith | `0x29a2ee: test %eax,%eax` | call | 0x29a307 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x73 | jg | reg/arith | `0x29a301: dec %ebx` | arithmetic/control | 0x29a2d0 | back |
| ML-KEM hash H | +0x2e | je | reg/arith | `0x29ba8c: test %eax,%eax` | memory | 0x29bafd | fwd |
| ML-KEM hash H | +0x49 | je | reg/arith | `0x29baa7: test %eax,%eax` | arithmetic/control | 0x29bae4 | fwd |
| ML-KEM hash H | +0x4e | je | reg/arith | `0x29baab: test %rbx,%rbx` | memory | 0x29babe | fwd |
| ML-KEM hash H | +0x56 | je | reg/arith | `0x29bab3: test %rax,%rax` | memory | 0x29babe | fwd |
| ML-KEM hash H | +0x5c | jne | mem | `0x29bab8: testb $0x2,0x10(%rax)` | memory | 0x29bae9 | fwd |
| ML-KEM hash G | +0x2e | je | reg/arith | `0x29b9cc: test %eax,%eax` | memory | 0x29ba3d | fwd |
| ML-KEM hash G | +0x49 | je | reg/arith | `0x29b9e7: test %eax,%eax` | arithmetic/control | 0x29ba24 | fwd |
| ML-KEM hash G | +0x4e | je | reg/arith | `0x29b9eb: test %rbx,%rbx` | memory | 0x29b9fe | fwd |
| ML-KEM hash G | +0x56 | je | reg/arith | `0x29b9f3: test %rax,%rax` | memory | 0x29b9fe | fwd |
| ML-KEM hash G | +0x5c | jne | mem | `0x29b9f8: testb $0x2,0x10(%rax)` | memory | 0x29ba29 | fwd |
| ML-KEM public-key hash | +0x59 | je | reg/arith | `0x2994f7: test %eax,%eax` | memory | 0x2995eb | fwd |
| ML-KEM public-key hash | +0x96 | je | reg/arith | `0x29952f: cmp $0x200,%rsi` | memory | 0x299580 | fwd |
| ML-KEM public-key hash | +0xa5 | jbe | reg/arith | `0x299542: cmp $0x33,%eax` | memory | 0x299520 | back |
| ML-KEM public-key hash | +0xb9 | je | reg/arith | `0x299555: cmp $0x40,%r8d` | arithmetic/control | 0x299571 | fwd |
| ML-KEM public-key hash | +0xf6 | je | reg/arith | `0x299594: test %eax,%eax` | memory | 0x2995eb | fwd |
| ML-KEM public-key hash | +0x109 | jb | reg/arith | `0x2995a6: cmp %rax,%rbp` | memory | 0x299510 | back |
| ML-KEM public-key hash | +0x123 | je | reg/arith | `0x2995c1: test %eax,%eax` | memory | 0x2995eb | fwd |
| ML-KEM KDF | +0x2a | je | reg/arith | `0x29b2e8: test %eax,%eax` | memory | 0x29b32e | fwd |
| ML-KEM KDF | +0x3f | je | reg/arith | `0x29b2fd: test %eax,%eax` | memory | 0x29b32e | fwd |
| ML-KEM KDF | +0x52 | je | reg/arith | `0x29b310: test %eax,%eax` | memory | 0x29b32e | fwd |
| ML-KEM PRF | +0x2d | je | reg/arith | `0x29b36b: test %eax,%eax` | memory | 0x29b3da | fwd |
| ML-KEM PRF | +0x46 | je | reg/arith | `0x29b384: test %eax,%eax` | arithmetic/control | 0x29b3c3 | fwd |
| ML-KEM PRF | +0x4b | je | reg/arith | `0x29b388: test %r14,%r14` | memory | 0x29b39b | fwd |
| ML-KEM PRF | +0x53 | je | reg/arith | `0x29b390: test %rax,%rax` | memory | 0x29b39b | fwd |
| ML-KEM PRF | +0x59 | jne | mem | `0x29b395: testb $0x2,0x10(%rax)` | memory | 0x29b3c8 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xa0 | je | reg/arith | `0x1d334e: test %eax,%eax` | memory | 0x1d345f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xb9 | je | reg/arith | `0x1d3367: test %eax,%eax` | memory | 0x1d345f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xd0 | je | reg/arith | `0x1d337e: test %eax,%eax` | memory | 0x1d345f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xeb | je | reg/arith | `0x1d3399: test %eax,%eax` | call+memory | 0x1d345f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x155 | je | reg/arith | `0x1d33fb: test %eax,%eax` | call+memory | 0x1d353c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x178 | je | reg/arith | `0x1d3426: test %eax,%eax` | memory | 0x1d353c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x185 | je | reg/arith | `0x1d3432: test %rax,%rax` | arithmetic/control | 0x1d355e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x18e | je | reg/arith | `0x1d343b: test %r14,%r14` | memory | 0x1d356d | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x1a0 | jae | reg/arith | `0x1d3444: cmp $0x4,%rax` | arithmetic/control | 0x1d357f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x2d3 | jae | reg/arith | `0x1d357f: cmp $0x20,%rax` | arithmetic/control | 0x1d358b | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x31b | jne | reg/arith | `0x1d35c8: cmp %rdx,%rcx` | arithmetic/control | 0x1d359c | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x354 | je | reg/arith | `0x1d3601: cmp %rcx,%rax` | arithmetic/control | 0x1d3671 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x358 | je | reg/arith | `0x1d3606: test $0x1c,%al` | memory | 0x1d365e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x386 | jne | reg/arith | `0x1d3633: cmp %rsi,%rcx` | arithmetic/control | 0x1d3620 | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x3bf | jne | reg/arith | `0x1d366c: cmp %rcx,%rax` | memory | 0x1d365e | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x427 | jne | reg/arith | `0x1d36d3: cmp $0x20,%rcx` | memory | 0x1d36a0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x58 | ja | reg/arith | `0x2962d0: cmp $0x7e,%rax` | memory | 0x296671 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xb0 | jbe | reg/arith | `0x29632c: cmp $0x7,%r8` | memory | 0x296387 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xf9 | jae | reg/arith | `0x296376: cmp %r13,%r14` | memory | 0x296390 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x105 | jae | reg/arith | `0x296382: cmp %r12,%r15` | arithmetic/control | 0x296390 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2c0 | jne | reg/arith | `0x29653d: cmp %r13,%r8` | memory | 0x2963d0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2d7 | ja | reg/arith | `0x296550: cmp $0xff,%r8` | arithmetic/control | 0x29665c | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2e4 | jae | reg/arith | `0x29655d: cmp $0x100,%rcx` | memory | 0x296647 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x392 | jb | reg/arith | `0x29660f: cmp %rbx,%r8` | arithmetic/control | 0x296550 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x39f | jne | reg/arith | `0x296618: cmp $0x100,%rcx` | arithmetic/control | 0x2962d0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x3b2 | ja | reg/arith | `0x29662b: cmp $0x3,%rsi` | arithmetic/control | 0x2962c0 | back |
