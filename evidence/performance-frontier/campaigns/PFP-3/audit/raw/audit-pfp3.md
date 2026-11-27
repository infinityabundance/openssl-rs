# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp3-ctgrind/a/libcrypto.so.3`
- SHA-256: `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`
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
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_sos_into` @ 0x325720 | 1013 | 249 | 19 | 0 | 0 | 10 | 0 | 0 | 5 | 0 |
| Montgomery ladder carrier (ladder multiplies inlined here) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith15run_mont_ladder` @ 0x3243d0 | 3383 | 734 | 51 | 0 | 2 | 11 | 0 | 0 | 49 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x165470 | 961 | 231 | 17 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x326130 (carries `mod_exp_core_consttime_from_parts`) | 1693 | 430 | 42 | 0 | 2 | 4 | 0 | 0 | 20 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x23c680 | 9817 | 2259 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x2427a0 | 3158 | 780 | 125 | 0 | 5 | 7 | 1 | 0 | 78 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x4adab0 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x2b80d0 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x2b3f50 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x2b3d40 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| DH key agreement (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2dh3key19ossl_dh_compute_key` @ 0x23fd80 | 1281 | 294 | 36 | 0 | 1 | 0 | 1 | 0 | 32 | 0 |
| EC wNAF multiply (verification / public-scalar core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` @ 0x240800 | 7223 | 1525 | 186 | 4 | 33 | 5 | 2 | 0 | 101 | 0 |
| ML-KEM decapsulation (provider driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` @ 0x1c7100 | 998 | 210 | 15 | 0 | 1 | 4 | 0 | 0 | 13 | 0 |
| ML-KEM K-PKE decrypt | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11decrypt_cpa` @ 0x24d210 | 2864 | 683 | 37 | 0 | 0 | 6 | 0 | 0 | 10 | 0 |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11encrypt_cpa` @ 0x24dd40 | 8922 | 1844 | 44 | 0 | 6 | 46 | 2 | 0 | 16 | 0 |
| ML-KEM inverse NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith18scalar_inverse_ntt` @ 0x250f50 | 1366 | 295 | 12 | 0 | 13 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM inner product | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13inner_product` @ 0x250190 | 2209 | 455 | 11 | 0 | 2 | 12 | 1 | 0 | 1 | 0 |
| ML-KEM matrix transpose-multiply-add | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith25matrix_mult_transpose_add` @ 0x2514b0 | 2439 | 513 | 10 | 0 | 3 | 12 | 0 | 0 | 0 | 0 |
| ML-KEM matrix expansion (public) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13matrix_expand` @ 0x250a40 | 584 | 134 | 16 | 0 | 0 | 0 | 0 | 0 | 6 | 0 |
| ML-KEM vector decode 12-bit | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith16vector_decode_12` @ 0x250d80 | 136 | 35 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-KEM vector encode | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13vector_encode` @ 0x250c90 | 237 | 71 | 10 | 0 | 0 | 0 | 0 | 0 | 5 | 0 |
| ML-KEM CBD sampling eta=2 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_2` @ 0x251f80 | 413 | 93 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD sampling eta=3 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_3` @ 0x252120 | 1021 | 239 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD vector sampling then NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` @ 0x250e10 | 312 | 83 | 3 | 0 | 0 | 1 | 0 | 0 | 2 | 0 |
| ML-KEM hash H | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_h` @ 0x2525e0 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM hash G | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_g` @ 0x252520 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM public-key hash | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13hash_h_pubkey` @ 0x250020 | 358 | 104 | 7 | 0 | 0 | 2 | 0 | 0 | 6 | 0 |
| ML-KEM KDF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3kdf` @ 0x251e40 | 128 | 46 | 3 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM PRF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3prf` @ 0x251ec0 | 177 | 60 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590` @ 0x1c9cd0 | 1554 | 341 | 16 | 0 | 1 | 1 | 0 | 0 | 9 | 0 |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith10scalar_ntt.llvm.10589707065378727853` @ 0x24ce00 | 1030 | 235 | 10 | 0 | 14 | 0 | 0 | 0 | 3 | 0 |

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
| `key::decap` | `3key5decap.llvm.11272150836271317590` | 1554 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` | +0x108, +0x216, +0x300 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |
| `arith::scalar_ntt` | `5arith10scalar_ntt.llvm.10589707065378727853` | 1030 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` | +0x65 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **ML-KEM decapsulation carrier (implicit-rejection comparison + select)** recorded check: src/ml_kem/key.rs::decap is the only body of the identifier. The release DSO has no unsuffixed symbol for it; the only defined .text symbol of that identifier is the .llvm.<digits> local copy, and ossl_ml_kem_decap calls that entry directly at three sites. The copy contains the inlined CRYPTO_memcmp accumulation, the constant_time_eq_int_8 mask and the constant_time_select_8 store loop of src/ml_kem/key.rs:633-639.

- **ML-KEM forward NTT (used by re-encryption on secret-derived data)** recorded check: src/ml_kem/arith.rs::scalar_ntt has no unsuffixed out-of-line body in the release DSO; its only defined .text symbol of that identifier is the .llvm.<digits> local copy. gencbd_vector_ntt calls that entry directly, and the same single entry is the target of two further direct calls in the file (recorded in MLKEM-REJECTION.md). The loop bounds are fixed by the degree; the value-dependent reductions compile to cmovcc, which the per-function counts report.

## Comparison-result branch contract

Register taint is seeded on the XOR/OR comparison accumulation and propagated over the basic-block CFG. `public-bound` means no tracked comparison register reaches the condition, not that the branch is harmless. Memory and implicit flow are not modelled.

### ML-KEM decapsulation carrier (implicit-rejection comparison + select)

- accumulated registers: `xmm0`, `xmm1`
- accumulation loop 0x1c9fbc..0x1c9feb: `xmm0`, `xmm1`

| kind | addr | instruction | condition source | class |
|---|---|---|---|---|
| jcc | `0x1c9d70` | `je 1c9e7f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x1af>` | `0x1c9d6e: test %eax,%eax` | **public-bound** |
| jcc | `0x1c9d89` | `je 1c9e7f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x1af>` | `0x1c9d87: test %eax,%eax` | **public-bound** |
| jcc | `0x1c9da0` | `je 1c9e7f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x1af>` | `0x1c9d9e: test %eax,%eax` | **public-bound** |
| jcc | `0x1c9dbb` | `je 1c9e7f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x1af>` | `0x1c9db9: test %eax,%eax` | **public-bound** |
| jcc | `0x1c9e25` | `je 1c9f5c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x28c>` | `0x1c9e1b: test %eax,%eax` | **public-bound** |
| jcc | `0x1c9e48` | `je 1c9f5c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x28c>` | `0x1c9e46: test %eax,%eax` | **public-bound** |
| jcc | `0x1c9e55` | `je 1c9f7e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x2ae>` | `0x1c9e52: test %rax,%rax` | **public-bound** |
| jcc | `0x1c9e5e` | `je 1c9f8d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x2bd>` | `0x1c9e5b: test %r14,%r14` | **public-bound** |
| jcc | `0x1c9e70` | `jae 1c9f9f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x2cf>` | `0x1c9e64: cmp $0x4,%rax` | **public-bound** |
| jcc | `0x1c9fa3` | `jae 1c9fab <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x2db>` | `0x1c9f9f: cmp $0x20,%rax` | **public-bound** |
| jcc | `0x1c9feb` | `jne 1c9fbc <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x2ec>` | `0x1c9fe8: cmp %rdx,%rcx` | **public-bound** |
| jcc | `0x1ca024` | `je 1ca091 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x3c1>` | `0x1ca021: cmp %rcx,%rax` | **public-bound** |
| jcc | `0x1ca028` | `je 1ca07e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x3ae>` | `0x1ca026: test $0x1c,%al` | **public-bound** |
| jcc | `0x1ca056` | `jne 1ca040 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x370>` | `0x1ca053: cmp %rsi,%rcx` | **public-bound** |
| jcc | `0x1ca08f` | `jne 1ca07e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x3ae>` | `0x1ca08c: cmp %rcx,%rax` | **public-bound** |
| setcc | `0x1ca095` | `setne %al` | `0x1ca093: test %dl,%dl` | **secret-derived** |
| cmov | `0x1ca0b6` | `cmovne %rcx,%rdx` | `0x1ca0a9: cmpl $0x0,0xa0(%rsp)` | **public-bound** |
| jcc | `0x1ca0f7` | `jne 1ca0c0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.11272150836271317590+0x3f0>` | `0x1ca0f3: cmp $0x20,%rcx` | **public-bound** |

- secret-derived conditional jumps: 0
- undetermined conditions: 0

## Divisions

- **EC wNAF multiply (verification / public-scalar core)** `+0x8c4` (0x2410c4): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0xaf4` (0x2412f4): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0xb58` (0x241358): `div %esi`
- **EC wNAF multiply (verification / public-scalar core)** `+0x13a7` (0x241ba7): `div %esi`

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d378, 0x16d399, 0x16d3ba, 0x16d3d1, 0x16d423, 0x16d43a, 0x16d5c5, 0x16d6d3, 0x16d779, 0x16d938, 0x2479a4, 0x247a12, 0x247a80, 0x247aee, 0x2b43fb, 0x3bad0c, 0x3bad3c, 0x42810c, 0x42813c, 0x4da48c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x33 | jne | reg/arith | `0x325750: or %r9,%rax` | memory | 0x325870 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x4c | jne | reg/arith | `0x325769: cmp %rax,%rcx` | memory | 0x325870 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x7d | je | reg/arith | `0x32579a: test %r14,%r14` | memory | 0x325872 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xe1 | je | reg/arith | `0x3257fe: cmp %rdi,%rbp` | memory | 0x325881 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xf4 | je | reg/arith | `0x325811: test %rax,%rax` | memory | 0x3257d0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x142 | jne | reg/arith | `0x32585f: cmp %r8,%r13` | arithmetic/control | 0x325820 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x148 | jne | reg/arith | `0x325864: test $0x1,%dil` | arithmetic/control | 0x3257d0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1bd | je | reg/arith | `0x3258da: cmp %rdi,%rax` | memory | 0x32598a | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1cb | je | mem | `0x3258e3: cmp 0x90(%rsp),%r9` | memory | 0x325ada | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x203 | je | reg/arith | `0x325920: cmp %rsi,%rbx` | memory | 0x325abf | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x22f | jne | reg/arith | `0x32594c: cmp %rsi,%rdi` | memory | 0x325920 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x23d | je | mem | `0x325958: cmp 0x28(%rsp),%r9` | memory | 0x3258c0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x263 | jne | reg/arith | `0x325980: cmp %rax,%rbp` | arithmetic/control | 0x325970 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x282 | je | reg/arith | `0x32599f: test %rdx,%rdx` | memory | 0x325a12 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2e8 | jne | reg/arith | `0x325a05: cmp %rsi,%r13` | arithmetic/control | 0x3259d0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2ee | jne | reg/arith | `0x325a0a: test $0x1,%dil` | arithmetic/control | 0x325a2d | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x367 | jae | reg/arith | `0x325a84: cmp %r14,%rcx` | arithmetic/control | 0x325b02 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x36c | je | reg/arith | `0x325a89: cmp %r10,%rdi` | memory | 0x325af2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x398 | jne | reg/arith | `0x325ab4: add $0xfffffffffffffff8,%r8` | arithmetic/control | 0x325a80 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e | jne | reg/arith | `0x3243fa: shr $0x3a,%rax` | memory | 0x324a52 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4d | jbe | reg/arith | `0x32441a: cmp %rbx,%rdx` | call+memory | 0x324500 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6c | je | reg/arith | `0x324438: cmp $0xffffffffffffffff,%r12` | memory | 0x3245cb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8d | jne | reg/arith | `0x324452: test %rbx,%rbx` | memory | 0x324884 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc7 | jne | reg/arith | `0x324495: or %al,%cl` | memory | 0x3244d8 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x106 | jne | reg/arith | `0x3244d3: cmp %rax,%rsi` | arithmetic/control | 0x3244a0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10b | je | reg/arith | `0x3244d8: test %r12,%r12` | memory | 0x3244eb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x141 | jne | reg/arith | `0x32450e: test %rbx,%rbx` | memory | 0x324783 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x18c | jne | reg/arith | `0x324558: cmp $0xffffffffffffffff,%rax` | memory | 0x324667 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x19c | je | reg/arith | `0x324569: test %rbx,%rbx` | memory | 0x3245da | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1e6 | jne | reg/arith | `0x3245b3: cmp %rax,%rbx` | memory | 0x324580 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x22e | jne | reg/arith | `0x3245fc: or %cl,%dl` | memory | 0x324640 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x26e | jne | reg/arith | `0x32463b: cmp %rdx,%rsi` | arithmetic/control | 0x324610 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x273 | je | reg/arith | `0x324640: test %rax,%rax` | memory | 0x324655 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2b5 | jne | reg/arith | `0x324682: test %rbx,%rbx` | call+memory | 0x3247cc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e8 | je | mem | `0x3246ae: cmpb $0x0,0x10(%rsp)` | memory | 0x324fc7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x321 | jne | reg/arith | `0x3246ef: or %al,%cl` | memory | 0x324738 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x366 | jne | reg/arith | `0x324733: cmp %rax,%rsi` | arithmetic/control | 0x324700 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x36b | je | reg/arith | `0x324738: test %rdx,%rdx` | memory | 0x324751 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x38c | je | reg/arith | `0x324751: test %rbx,%rbx` | memory | 0x32480c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x3e9 | je | mem | `0x3247b4: cmpb $0x0,0x10(%rsp)` | memory | 0x324940 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x426 | je | mem | `0x3247f1: cmpb $0x0,0x10(%rsp)` | memory | 0x3249d2 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x45c | jne | reg/arith | `0x32482a: or %al,%cl` | memory | 0x324868 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x496 | jne | reg/arith | `0x324863: cmp %rax,%rsi` | arithmetic/control | 0x324830 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x49b | je | reg/arith | `0x324868: test %rdi,%rdi` | memory | 0x324569 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4e2 | je | mem | `0x3248ad: cmpb $0x0,0x10(%rsp)` | memory | 0x32498e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x510 | jne | reg/arith | `0x3248de: or %al,%cl` | memory | 0x32491c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x54a | jne | reg/arith | `0x324917: cmp %rax,%rsi` | memory | 0x3248e4 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x557 | je | reg/arith | `0x32491c: test %r12,%r12` | memory | 0x3245da | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x57c | je | reg/arith | `0x324948: cmp $0x1,%rbx` | memory | 0x324969 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x5ca | je | reg/arith | `0x324996: cmp $0x1,%rbx` | memory | 0x3249b7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x615 | je | reg/arith | `0x3249e1: cmp $0x1,%rbx` | memory | 0x324a0a | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x666 | je | mem | `0x324a31: cmpb $0x0,0x10(%rsp)` | memory | 0x324a5e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x69f | je | reg/arith | `0x324a6b: cmp $0x1,%rbx` | memory | 0x324a8c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6fd | je | mem | `0x324ac8: cmpb $0x0,0x10(%rsp)` | memory | 0x324ad9 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x759 | je | mem | `0x324b24: cmpb $0x0,0x10(%rsp)` | memory | 0x324bb1 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7b6 | jne | reg/arith | `0x324b83: cmp %rax,%rcx` | memory | 0x324b57 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7ef | je | reg/arith | `0x324bbb: cmp $0x1,%rbx` | memory | 0x324be4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x840 | je | mem | `0x324c0b: cmpb $0x0,0x10(%rsp)` | memory | 0x324c30 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x877 | je | reg/arith | `0x324c43: cmp $0x1,%rbx` | memory | 0x324c6c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8cd | je | mem | `0x324c94: cmpq $0x0,0x80(%rsp)` | memory | 0x324e65 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x930 | jae | mem | `0x324cfb: cmp 0x78(%rsp),%rdi` | memory | 0x325026 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x994 | je | reg/arith | `0x324d62: test %al,%al` | memory | 0x324e54 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9a3 | je | mem | `0x324d6a: cmpq $0x0,0x98(%rsp)` | memory | 0x324dc4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9f2 | jne | mem | `0x324dba: cmp %rcx,0x98(%rsp)` | memory | 0x324d88 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa36 | je | reg/arith | `0x324e04: test %al,%al` | memory | 0x324e54 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa7c | jne | mem | `0x324e44: cmp 0x80(%rsp),%rsi` | arithmetic/control | 0x324ce3 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xad9 | je | reg/arith | `0x324ea7: test %al,%al` | memory | 0x324f35 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xbdd | jne | reg/arith | `0x324faa: cmp %rax,%r13` | memory | 0x324f7f | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc97 | je | reg/arith | `0x325064: test %rbx,%rbx` | memory | 0x325081 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xcdd | je | reg/arith | `0x3250aa: test %rbx,%rbx` | memory | 0x3250c7 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x1654a9: test %rbx,%rbx` | memory | 0x165500 | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x1654e6: cmpb $0x0,0x8(%rsp)` | memory | 0x165545 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | jne | reg/arith | `0x1654f5: test %rbx,%rbx` | arithmetic/control | 0x165716 | fwd |
| Montgomery multiply (allocating wrapper) | +0xb8 | je | mem | `0x165523: cmpb $0x0,0x8(%rsp)` | memory | 0x165739 | fwd |
| Montgomery multiply (allocating wrapper) | +0xe4 | jne | reg/arith | `0x165551: test %rbx,%rbx` | memory | 0x165771 | fwd |
| Montgomery multiply (allocating wrapper) | +0x12a | je | reg/arith | `0x165598: test %al,%al` | memory | 0x165658 | fwd |
| Montgomery multiply (allocating wrapper) | +0x143 | je | reg/arith | `0x1655b0: test %rbx,%rbx` | memory | 0x165609 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x1655f3: cmp %rax,%rbx` | memory | 0x1655c0 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x165643: cmp %rax,%r14` | arithmetic/control | 0x165610 | back |
| Montgomery multiply (allocating wrapper) | +0x1f3 | je | reg/arith | `0x165660: test %rbx,%rbx` | memory | 0x1656b6 | fwd |
| Montgomery multiply (allocating wrapper) | +0x236 | jne | reg/arith | `0x1656a3: cmp %rax,%rsi` | memory | 0x165670 | back |
| Montgomery multiply (allocating wrapper) | +0x286 | jne | reg/arith | `0x1656f3: cmp %rax,%r14` | memory | 0x1656c0 | back |
| Montgomery multiply (allocating wrapper) | +0x2a0 | je | reg/arith | `0x16570d: test %rbx,%rbx` | arithmetic/control | 0x165536 | back |
| Montgomery multiply (allocating wrapper) | +0x2d5 | je | reg/arith | `0x165741: cmp $0x1,%rbx` | memory | 0x165762 | fwd |
| Montgomery multiply (allocating wrapper) | +0x343 | je | mem | `0x1657ae: cmpb $0x0,0x8(%rsp)` | memory | 0x1657c2 | fwd |
| Montgomery multiply (allocating wrapper) | +0x35b | jne | reg/arith | `0x1657c7: cmp $0x1,%rbx` | arithmetic/control | 0x1657d5 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3a1 | je | reg/arith | `0x16580e: test %rbx,%rbx` | memory | 0x165829 | fwd |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x326146: test %r12,%r12` | memory | 0x3261b8 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x326161: cmp $0x1,%r12` | memory | 0x326189 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x32616a: cmp $0x1,%r15` | memory | 0x32618c | fwd |
| Constant-time ladder core | +0x60 | jne | reg/arith | `0x32618c: test $0x1,%r15b` | call | 0x3261ac | fwd |
| Constant-time ladder core | +0x86 | jbe | reg/arith | `0x3261b3: cmp %rbx,%r13` | memory | 0x3261ce | fwd |
| Constant-time ladder core | +0xe1 | je | mem | `0x32620c: cmpb $0x0,0x10(%rsp)` | memory | 0x326221 | fwd |
| Constant-time ladder core | +0x102 | je | reg/arith | `0x326229: cmp $0x1,%rbx` | memory | 0x326261 | fwd |
| Constant-time ladder core | +0x154 | jae | reg/arith | `0x326280: cmp $0x18,%rcx` | memory | 0x326295 | fwd |
| Constant-time ladder core | +0x186 | je | reg/arith | `0x3262b3: cmp %rdi,%r8` | arithmetic/control | 0x326331 | fwd |
| Constant-time ladder core | +0x191 | jae | reg/arith | `0x3262be: cmp %r13,%r8` | memory | 0x3262f4 | fwd |
| Constant-time ladder core | +0x1a2 | jb | reg/arith | `0x3262cf: cmp %r13,%r8` | memory | 0x326303 | fwd |
| Constant-time ladder core | +0x1b1 | jb | reg/arith | `0x3262de: cmp %r13,%r8` | memory | 0x326314 | fwd |
| Constant-time ladder core | +0x1c0 | jb | reg/arith | `0x3262ed: cmp %r13,%r8` | arithmetic/control | 0x3262a3 | back |
| Constant-time ladder core | +0x1d1 | jae | reg/arith | `0x3262fe: cmp %r13,%r8` | memory | 0x3262d4 | back |
| Constant-time ladder core | +0x1e2 | jae | reg/arith | `0x32630f: cmp %r13,%r8` | memory | 0x3262e3 | back |
| Constant-time ladder core | +0x1f3 | jb | reg/arith | `0x326320: cmp %r13,%r8` | arithmetic/control | 0x3262a3 | back |
| Constant-time ladder core | +0x204 | je | reg/arith | `0x326331: test %rax,%rax` | memory | 0x326376 | fwd |
| Constant-time ladder core | +0x22c | je | reg/arith | `0x326359: cmp %r8,%rax` | memory | 0x326376 | fwd |
| Constant-time ladder core | +0x235 | jb | reg/arith | `0x326362: cmp %r13,%r9` | memory | 0x32634e | back |
| Constant-time ladder core | +0x244 | jne | reg/arith | `0x326371: cmp %r8,%rax` | arithmetic/control | 0x32635e | back |
| Constant-time ladder core | +0x249 | je | reg/arith | `0x326376: test %r14,%r14` | memory | 0x3263e6 | fwd |
| Constant-time ladder core | +0x252 | jne | reg/arith | `0x32637f: test %r12,%r12` | memory | 0x32667d | fwd |
| Constant-time ladder core | +0x2b9 | je | reg/arith | `0x3263e6: test %r12,%r12` | arithmetic/control | 0x32675e | fwd |
| Constant-time ladder core | +0x2c6 | jne | reg/arith | `0x3263f2: shr $0x3a,%rax` | arithmetic/control | 0x3266ab | fwd |
| Constant-time ladder core | +0x2d3 | jne | reg/arith | `0x3263ff: shr $0x39,%rax` | call+memory | 0x3266ab | fwd |
| Constant-time ladder core | +0x2f6 | je | reg/arith | `0x326422: cmp $0xffffffffffffffff,%r14` | call+memory | 0x3266ab | fwd |
| Constant-time ladder core | +0x334 | je | reg/arith | `0x326456: cmp $0xffffffffffffffff,%rbp` | memory | 0x3265e5 | fwd |
| Constant-time ladder core | +0x34c | je | reg/arith | `0x326474: test %r8,%r8` | arithmetic/control | 0x326771 | fwd |
| Constant-time ladder core | +0x3f3 | je | mem | `0x32650e: cmpq $0xffffffffffffffff,0x10(%rsp)` | memory | 0x3265ee | fwd |
| Constant-time ladder core | +0x437 | je | reg/arith | `0x326564: test %rbp,%rbp` | memory | 0x326580 | fwd |
| Constant-time ladder core | +0x46a | jne | reg/arith | `0x326598: or %al,%cl` | memory | 0x3265d7 | fwd |
| Constant-time ladder core | +0x4a5 | jne | reg/arith | `0x3265d2: cmp %rax,%rsi` | arithmetic/control | 0x32659e | back |
| Constant-time ladder core | +0x4aa | je | reg/arith | `0x3265d7: test %r14,%r14` | arithmetic/control | 0x3266b7 | fwd |
| Constant-time ladder core | +0x4c8 | je | reg/arith | `0x3265f5: test %rbp,%rbp` | memory | 0x326611 | fwd |
| Constant-time ladder core | +0x4fb | jne | reg/arith | `0x326629: or %al,%cl` | memory | 0x326668 | fwd |
| Constant-time ladder core | +0x536 | jne | reg/arith | `0x326663: cmp %rax,%rsi` | arithmetic/control | 0x32662f | back |
| Constant-time ladder core | +0x53b | je | reg/arith | `0x326668: test %r14,%r14` | memory | 0x3266b7 | fwd |
| Constant-time ladder core | +0x579 | je | mem | `0x3266a4: cmpb $0x0,0x10(%rsp)` | memory | 0x326715 | fwd |
| Constant-time ladder core | +0x58a | je | reg/arith | `0x3266b7: test %rbx,%rbx` | memory | 0x3261bf | back |
| Constant-time ladder core | +0x5ca | jne | reg/arith | `0x3266f7: cmp %rax,%rsi` | memory | 0x3266cc | back |
| Constant-time ladder core | +0x5f1 | je | reg/arith | `0x32671d: cmp $0x1,%r12` | memory | 0x326741 | fwd |
| Constant-time ladder core | +0x65f | je | reg/arith | `0x32678c: test %rbp,%rbp` | memory | 0x3267a8 | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x23c694: test %r8,%r8` | memory | 0x23c6eb | fwd |
| Constant-time inversion | +0x1c | je | mem | `0x23c699: testb $0x1,(%rcx)` | arithmetic/control | 0x23c6eb | fwd |
| Constant-time inversion | +0x2f | jne | reg/arith | `0x23c6ab: shr $0x39,%rdi` | memory | 0x23c6eb | fwd |
| Constant-time inversion | +0x66 | je | mem | `0x23c6e1: cmpb $0x0,0x18(%rsp)` | memory | 0x23c704 | fwd |
| Constant-time inversion | +0x90 | je | reg/arith | `0x23c70c: cmp $0x1,%rbx` | memory | 0x23c72d | fwd |
| Constant-time inversion | +0x104 | je | mem | `0x23c77f: cmpb $0x0,0x18(%rsp)` | memory | 0x23c7eb | fwd |
| Constant-time inversion | +0x14e | jne | reg/arith | `0x23c7cb: cmp %rcx,%rbx` | memory | 0x23c7a0 | back |
| Constant-time inversion | +0x177 | je | reg/arith | `0x23c7f3: cmp $0x1,%rbx` | memory | 0x23c814 | fwd |
| Constant-time inversion | +0x1f5 | je | mem | `0x23c870: cmpb $0x0,0x18(%rsp)` | memory | 0x23c8d1 | fwd |
| Constant-time inversion | +0x237 | jne | reg/arith | `0x23c8b4: cmp %rcx,%rsi` | memory | 0x23c889 | back |
| Constant-time inversion | +0x263 | je | mem | `0x23c8de: cmpq $0x1,(%rsp)` | memory | 0x23c901 | fwd |
| Constant-time inversion | +0x2d5 | je | mem | `0x23c950: cmpb $0x0,0x18(%rsp)` | memory | 0x23c9e0 | fwd |
| Constant-time inversion | +0x2ff | jne | reg/arith | `0x23c97d: or %cl,%dl` | memory | 0x23c9bf | fwd |
| Constant-time inversion | +0x339 | jne | reg/arith | `0x23c9b6: cmp %rcx,%rsi` | memory | 0x23c98b | back |
| Constant-time inversion | +0x342 | je | reg/arith | `0x23c9bf: test %rax,%rax` | memory | 0x23c877 | back |
| Constant-time inversion | +0x372 | je | mem | `0x23c9ed: cmpq $0x1,(%rsp)` | memory | 0x23ca18 | fwd |
| Constant-time inversion | +0x3e8 | je | mem | `0x23ca63: cmpb $0x0,0x18(%rsp)` | memory | 0x23caf5 | fwd |
| Constant-time inversion | +0x416 | jne | reg/arith | `0x23ca94: or %cl,%al` | memory | 0x23cad2 | fwd |
| Constant-time inversion | +0x450 | jne | reg/arith | `0x23cacd: cmp %rcx,%rsi` | memory | 0x23caa2 | back |
| Constant-time inversion | +0x457 | je | mem | `0x23cad2: cmpq $0x0,(%rsp)` | memory | 0x23caec | fwd |
| Constant-time inversion | +0x483 | je | reg/arith | `0x23caff: cmp $0x1,%rbx` | memory | 0x23cb25 | fwd |
| Constant-time inversion | +0x4ee | je | mem | `0x23cb69: cmpb $0x0,0x18(%rsp)` | memory | 0x23cb79 | fwd |
| Constant-time inversion | +0x507 | je | reg/arith | `0x23cb83: cmp $0x1,%rbx` | memory | 0x23cba9 | fwd |
| Constant-time inversion | +0x569 | je | mem | `0x23cbe3: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23ceca | fwd |
| Constant-time inversion | +0x5a7 | je | mem | `0x23cc21: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23ced3 | fwd |
| Constant-time inversion | +0x5e5 | je | mem | `0x23cc5f: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e7ca | fwd |
| Constant-time inversion | +0x623 | je | mem | `0x23cc9d: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e7d3 | fwd |
| Constant-time inversion | +0x662 | je | mem | `0x23ccdc: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e7dc | fwd |
| Constant-time inversion | +0x6a1 | je | mem | `0x23cd1b: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e7e5 | fwd |
| Constant-time inversion | +0x6e0 | je | mem | `0x23cd5a: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e7ee | fwd |
| Constant-time inversion | +0x71f | je | mem | `0x23cd99: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e7f7 | fwd |
| Constant-time inversion | +0x75e | je | mem | `0x23cdd8: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23e800 | fwd |
| Constant-time inversion | +0x79d | je | mem | `0x23ce17: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x23ea1d | fwd |
| Constant-time inversion | +0x7e0 | je | mem | `0x23ce5a: cmpq $0xffffffffffffffff,0x18(%rsp)` | memory | 0x23ea23 | fwd |
| Constant-time inversion | +0x9fa | je | mem | `0x23d062: cmp 0x2c8(%rsp),%rax` | memory | 0x23e809 | fwd |
| Constant-time inversion | +0xa29 | je | reg/arith | `0x23d0a6: test %rcx,%rcx` | memory | 0x23d105 | fwd |
| Constant-time inversion | +0xa6d | je | reg/arith | `0x23d0e9: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x23d108 | fwd |
| Constant-time inversion | +0xa72 | jae | reg/arith | `0x23d0ef: cmp %rbx,%rcx` | memory | 0x23d0fa | fwd |
| Constant-time inversion | +0xa7f | jb | reg/arith | `0x23d0fc: cmp %rbx,%rcx` | arithmetic/control | 0x23d0bf | back |
| Constant-time inversion | +0xaa5 | je | reg/arith | `0x23d122: test %rcx,%rcx` | memory | 0x23d17e | fwd |
| Constant-time inversion | +0xae1 | je | reg/arith | `0x23d15d: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x23d17e | fwd |
| Constant-time inversion | +0xae6 | jae | reg/arith | `0x23d163: cmp %rbx,%rcx` | memory | 0x23d173 | fwd |
| Constant-time inversion | +0xaf8 | jb | reg/arith | `0x23d175: cmp %rbx,%rcx` | arithmetic/control | 0x23d13a | back |
| Constant-time inversion | +0xb63 | je | reg/arith | `0x23d1e0: test %rcx,%rcx` | memory | 0x23d2db | fwd |
| Constant-time inversion | +0xb79 | je | reg/arith | `0x23d1f6: test %r14,%r14` | memory | 0x23d2a2 | fwd |
| Constant-time inversion | +0xbe3 | je | reg/arith | `0x23d25f: add $0xfffffffffffffffe,%rdx` | memory | 0x23d297 | fwd |
| Constant-time inversion | +0xbf0 | jae | reg/arith | `0x23d26d: cmp %rbx,%r11` | memory | 0x23d278 | fwd |
| Constant-time inversion | +0xc10 | jb | reg/arith | `0x23d28d: cmp %rbx,%r8` | arithmetic/control | 0x23d240 | back |
| Constant-time inversion | +0xc1b | je | reg/arith | `0x23d297: test $0x1,%r14b` | arithmetic/control | 0x23d2db | fwd |
| Constant-time inversion | +0xc49 | jae | reg/arith | `0x23d2c6: cmp %rbx,%rcx` | memory | 0x23d2d1 | fwd |
| Constant-time inversion | +0xc73 | je | reg/arith | `0x23d2f0: test %r8,%r8` | memory | 0x23d3e8 | fwd |
| Constant-time inversion | +0xc84 | je | reg/arith | `0x23d301: test %r13,%r13` | memory | 0x23d3ae | fwd |
| Constant-time inversion | +0xcec | je | reg/arith | `0x23d368: add $0xfffffffffffffffe,%r10` | memory | 0x23d3a3 | fwd |
| Constant-time inversion | +0xcfb | jae | mem | `0x23d376: cmp 0x50(%rsp),%r14` | memory | 0x23d383 | fwd |
| Constant-time inversion | +0xd1d | jb | mem | `0x23d398: cmp 0x50(%rsp),%rax` | arithmetic/control | 0x23d349 | back |
| Constant-time inversion | +0xd27 | je | reg/arith | `0x23d3a3: test $0x1,%r13b` | arithmetic/control | 0x23d3e8 | fwd |
| Constant-time inversion | +0xd51 | jae | mem | `0x23d3cc: cmp 0x50(%rsp),%rsi` | memory | 0x23d3de | fwd |
| Constant-time inversion | +0xde8 | je | reg/arith | `0x23d464: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x23d49d | fwd |
| Constant-time inversion | +0xded | jae | reg/arith | `0x23d46a: cmp %rbx,%rcx` | memory | 0x23d475 | fwd |
| Constant-time inversion | +0xdfc | jae | mem | `0x23d477: cmp 0x10(%rsp),%rcx` | memory | 0x23d489 | fwd |
| Constant-time inversion | +0xe16 | jb | reg/arith | `0x23d493: cmp %r8,%rcx` | arithmetic/control | 0x23d441 | back |
| Constant-time inversion | +0xe23 | je | mem | `0x23d49d: cmpq $0x0,0x10(%rsp)` | memory | 0x23d5a1 | fwd |
| Constant-time inversion | +0xe39 | je | reg/arith | `0x23d4b6: test %r10,%r10` | memory | 0x23d564 | fwd |
| Constant-time inversion | +0xea6 | je | reg/arith | `0x23d522: add $0xfffffffffffffffe,%r11` | memory | 0x23d559 | fwd |
| Constant-time inversion | +0xeb3 | jae | reg/arith | `0x23d530: cmp %rbx,%r14` | memory | 0x23d53b | fwd |
| Constant-time inversion | +0xed3 | jb | reg/arith | `0x23d550: cmp %rbx,%rax` | arithmetic/control | 0x23d503 | back |
| Constant-time inversion | +0xedd | je | reg/arith | `0x23d559: test $0x1,%r10b` | arithmetic/control | 0x23d5a1 | fwd |
| Constant-time inversion | +0xf0a | jae | reg/arith | `0x23d587: cmp %rbx,%rsi` | memory | 0x23d597 | fwd |
| Constant-time inversion | +0xf24 | je | reg/arith | `0x23d5a1: test %r8,%r8` | memory | 0x23d699 | fwd |
| Constant-time inversion | +0xf35 | je | reg/arith | `0x23d5b2: test %r10,%r10` | memory | 0x23d65f | fwd |
| Constant-time inversion | +0xf9d | je | reg/arith | `0x23d619: add $0xfffffffffffffffe,%r11` | memory | 0x23d654 | fwd |
| Constant-time inversion | +0xfac | jae | mem | `0x23d627: cmp 0x68(%rsp),%r14` | memory | 0x23d634 | fwd |
| Constant-time inversion | +0xfce | jb | mem | `0x23d649: cmp 0x68(%rsp),%rax` | arithmetic/control | 0x23d5fa | back |
| Constant-time inversion | +0xfd8 | je | reg/arith | `0x23d654: test $0x1,%r10b` | arithmetic/control | 0x23d699 | fwd |
| Constant-time inversion | +0x1002 | jae | mem | `0x23d67d: cmp 0x68(%rsp),%rsi` | memory | 0x23d68f | fwd |
| Constant-time inversion | +0x1070 | je | reg/arith | `0x23d6ec: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x23d72a | fwd |
| Constant-time inversion | +0x1075 | jae | reg/arith | `0x23d6f2: cmp %rbx,%rcx` | memory | 0x23d702 | fwd |
| Constant-time inversion | +0x1089 | jae | mem | `0x23d704: cmp 0x10(%rsp),%rcx` | memory | 0x23d716 | fwd |
| Constant-time inversion | +0x10a3 | jb | reg/arith | `0x23d720: cmp %r8,%rcx` | arithmetic/control | 0x23d6c9 | back |
| Constant-time inversion | +0x10fc | je | mem | `0x23d773: cmpq $0x0,0x80(%rsp)` | memory | 0x23d78e | fwd |
| Constant-time inversion | +0x113b | je | reg/arith | `0x23d7b8: test %rcx,%rcx` | arithmetic/control | 0x23d8ae | fwd |
| Constant-time inversion | +0x1148 | je | reg/arith | `0x23d7c4: add $0xfffffffffffffff8,%r8` | memory | 0x23d872 | fwd |
| Constant-time inversion | +0x11ab | je | reg/arith | `0x23d827: add $0xfffffffffffffffe,%r9` | memory | 0x23d867 | fwd |
| Constant-time inversion | +0x11bd | jae | mem | `0x23d835: cmp 0x80(%rsp),%rdi` | memory | 0x23d845 | fwd |
| Constant-time inversion | +0x11e1 | jb | mem | `0x23d859: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x23d808 | back |
| Constant-time inversion | +0x11eb | je | reg/arith | `0x23d867: test $0x1,%r8b` | arithmetic/control | 0x23d8ae | fwd |
| Constant-time inversion | +0x1214 | jae | mem | `0x23d88c: cmp 0x80(%rsp),%rdi` | memory | 0x23d8a4 | fwd |
| Constant-time inversion | +0x1239 | je | reg/arith | `0x23d8b6: test %rdx,%rdx` | arithmetic/control | 0x23d914 | fwd |
| Constant-time inversion | +0x126d | je | reg/arith | `0x23d8e9: add $0xfffffffffffffff8,%rax` | memory | 0x23d914 | fwd |
| Constant-time inversion | +0x1277 | jae | mem | `0x23d8ef: cmp 0x80(%rsp),%rcx` | memory | 0x23d907 | fwd |
| Constant-time inversion | +0x128d | jb | mem | `0x23d909: cmp (%rsp),%rcx` | arithmetic/control | 0x23d8c4 | back |
| Constant-time inversion | +0x1298 | ja | mem | `0x23d914: cmp %rdx,(%rsp)` | arithmetic/control | 0x23eb3b | fwd |
| Constant-time inversion | +0x129e | jae | unknown | `?` | memory | 0x23eb64 | fwd |
| Constant-time inversion | +0x12aa | je | mem | `0x23d924: cmpq $0x0,0x10(%rsp)` | memory | 0x23d9fb | fwd |
| Constant-time inversion | +0x12d6 | jne | reg/arith | `0x23d953: test $0x8,%dl` | memory | 0x23d992 | fwd |
| Constant-time inversion | +0x12f4 | jae | mem | `0x23d970: cmp (%rsp),%rdi` | memory | 0x23d981 | fwd |
| Constant-time inversion | +0x1315 | je | reg/arith | `0x23d992: test %rdx,%rdx` | memory | 0x23d9fb | fwd |
| Constant-time inversion | +0x1344 | je | mem | `0x23d9bf: cmp 0x8(%rsp),%rax` | memory | 0x23d9fb | fwd |
| Constant-time inversion | +0x1351 | jae | mem | `0x23d9cd: cmp (%rsp),%rsi` | memory | 0x23d9de | fwd |
| Constant-time inversion | +0x1375 | jb | mem | `0x23d9f1: cmp (%rsp),%rcx` | arithmetic/control | 0x23d9a5 | back |
| Constant-time inversion | +0x1381 | je | mem | `0x23d9fb: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x23dad3 | fwd |
| Constant-time inversion | +0x138e | je | reg/arith | `0x23da0a: add $0xfffffffffffffff8,%rdx` | memory | 0x23daa7 | fwd |
| Constant-time inversion | +0x13db | je | reg/arith | `0x23da58: cmp %rsi,%rdi` | memory | 0x23da98 | fwd |
| Constant-time inversion | +0x13e8 | jae | mem | `0x23da63: cmp 0x10(%rsp),%rdi` | memory | 0x23da75 | fwd |
| Constant-time inversion | +0x1411 | jb | mem | `0x23da8c: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x23da34 | back |
| Constant-time inversion | +0x141b | je | reg/arith | `0x23da98: test $0x1,%dl` | arithmetic/control | 0x23dad3 | fwd |
| Constant-time inversion | +0x1433 | jae | mem | `0x23daae: cmp 0x10(%rsp),%rcx` | memory | 0x23dac0 | fwd |
| Constant-time inversion | +0x1485 | je | reg/arith | `0x23db02: test %rax,%rax` | memory | 0x23db73 | fwd |
| Constant-time inversion | +0x14c4 | je | reg/arith | `0x23db40: add $0xfffffffffffffff8,%rcx` | memory | 0x23db6e | fwd |
| Constant-time inversion | +0x14ce | jae | mem | `0x23db46: cmp 0x80(%rsp),%rdx` | memory | 0x23db5e | fwd |
| Constant-time inversion | +0x14e8 | jb | mem | `0x23db60: cmp 0x88(%rsp),%rdx` | arithmetic/control | 0x23db15 | back |
| Constant-time inversion | +0x1505 | je | reg/arith | `0x23db82: test %rdx,%rdx` | arithmetic/control | 0x23dc05 | fwd |
| Constant-time inversion | +0x153e | je | reg/arith | `0x23dbba: add $0xfffffffffffffff8,%rdx` | memory | 0x23dbde | fwd |
| Constant-time inversion | +0x1544 | jae | mem | `0x23dbc0: cmp (%rsp),%rsi` | memory | 0x23dbcf | fwd |
| Constant-time inversion | +0x1557 | jb | mem | `0x23dbd2: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x23db90 | back |
| Constant-time inversion | +0x15cc | je | reg/arith | `0x23dc49: test %rsi,%rsi` | arithmetic/control | 0x23dd34 | fwd |
| Constant-time inversion | +0x15d9 | je | reg/arith | `0x23dc55: add $0xfffffffffffffff8,%r11` | memory | 0x23dcfd | fwd |
| Constant-time inversion | +0x163a | je | reg/arith | `0x23dcb6: add $0xfffffffffffffffe,%rsi` | memory | 0x23dcf2 | fwd |
| Constant-time inversion | +0x1649 | jae | mem | `0x23dcc4: cmp 0x58(%rsp),%r14` | memory | 0x23dcd1 | fwd |
| Constant-time inversion | +0x166b | jb | mem | `0x23dce6: cmp 0x58(%rsp),%r13` | arithmetic/control | 0x23dc97 | back |
| Constant-time inversion | +0x1676 | je | reg/arith | `0x23dcf2: test $0x1,%r11b` | arithmetic/control | 0x23dd34 | fwd |
| Constant-time inversion | +0x169d | jae | mem | `0x23dd18: cmp 0x58(%rsp),%rdi` | memory | 0x23dd2a | fwd |
| Constant-time inversion | +0x16f6 | je | reg/arith | `0x23dd72: add $0xfffffffffffffff8,%rsi` | memory | 0x23dd98 | fwd |
| Constant-time inversion | +0x16fd | jae | mem | `0x23dd78: cmp 0x58(%rsp),%rdi` | memory | 0x23dd8a | fwd |
| Constant-time inversion | +0x1711 | jb | mem | `0x23dd8d: cmp (%rsp),%rdi` | arithmetic/control | 0x23dd4c | back |
| Constant-time inversion | +0x171e | je | mem | `0x23dd98: cmpq $0x0,0x10(%rsp)` | memory | 0x23de5d | fwd |
| Constant-time inversion | +0x1741 | jne | reg/arith | `0x23ddbd: test $0x8,%dil` | memory | 0x23dddb | fwd |
| Constant-time inversion | +0x174e | jae | mem | `0x23ddca: cmp (%rsp),%rsi` | memory | 0x23dde0 | fwd |
| Constant-time inversion | +0x1775 | je | reg/arith | `0x23ddf2: test %rdi,%rdi` | memory | 0x23de5d | fwd |
| Constant-time inversion | +0x17a4 | je | mem | `0x23de1f: cmp 0x8(%rsp),%rsi` | memory | 0x23de5d | fwd |
| Constant-time inversion | +0x17b1 | jae | mem | `0x23de2d: cmp (%rsp),%r9` | memory | 0x23de3e | fwd |
| Constant-time inversion | +0x17d6 | jb | mem | `0x23de52: cmp (%rsp),%r10` | arithmetic/control | 0x23de05 | back |
| Constant-time inversion | +0x17e3 | je | mem | `0x23de5d: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x23df3c | fwd |
| Constant-time inversion | +0x17f0 | je | reg/arith | `0x23de6c: add $0xfffffffffffffff8,%r11` | memory | 0x23df0e | fwd |
| Constant-time inversion | +0x183e | je | reg/arith | `0x23debb: cmp %r9,%r10` | memory | 0x23defe | fwd |
| Constant-time inversion | +0x184b | jae | mem | `0x23dec6: cmp 0x10(%rsp),%r10` | memory | 0x23ded8 | fwd |
| Constant-time inversion | +0x1877 | jb | mem | `0x23def2: cmp 0x10(%rsp),%r10` | arithmetic/control | 0x23de97 | back |
| Constant-time inversion | +0x1882 | je | reg/arith | `0x23defe: test $0x1,%r11b` | arithmetic/control | 0x23df3c | fwd |
| Constant-time inversion | +0x189a | jae | mem | `0x23df15: cmp 0x10(%rsp),%rsi` | memory | 0x23df27 | fwd |
| Constant-time inversion | +0x18f3 | je | reg/arith | `0x23df70: test %rsi,%rsi` | arithmetic/control | 0x23dfe6 | fwd |
| Constant-time inversion | +0x1928 | je | reg/arith | `0x23dfa4: add $0xfffffffffffffff8,%rsi` | memory | 0x23dfe6 | fwd |
| Constant-time inversion | +0x1932 | jae | mem | `0x23dfaa: cmp 0x80(%rsp),%rdi` | memory | 0x23dfc2 | fwd |
| Constant-time inversion | +0x194a | jae | mem | `0x23dfc5: cmp 0x40(%rsp),%rdi` | memory | 0x23dfd7 | fwd |
| Constant-time inversion | +0x195f | jb | mem | `0x23dfda: cmp 0x68(%rsp),%rdi` | arithmetic/control | 0x23df7d | back |
| Constant-time inversion | +0x196f | je | mem | `0x23dfe6: cmpq $0x0,0x88(%rsp)` | memory | 0x23e001 | fwd |
| Constant-time inversion | +0x1996 | je | mem | `0x23e010: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x23e12c | fwd |
| Constant-time inversion | +0x19a3 | je | reg/arith | `0x23e01f: add $0xfffffffffffffff8,%rsi` | memory | 0x23e0ef | fwd |
| Constant-time inversion | +0x1a1b | je | reg/arith | `0x23e097: add $0xfffffffffffffffe,%rsi` | memory | 0x23e0de | fwd |
| Constant-time inversion | +0x1a2d | jae | mem | `0x23e0a5: cmp 0x88(%rsp),%r14` | memory | 0x23e0b5 | fwd |
| Constant-time inversion | +0x1a57 | jb | mem | `0x23e0cf: cmp 0x88(%rsp),%r13` | arithmetic/control | 0x23e06e | back |
| Constant-time inversion | +0x1a66 | je | mem | `0x23e0de: testb $0x1,0xa0(%rsp)` | memory | 0x23e12c | fwd |
| Constant-time inversion | +0x1a92 | jae | mem | `0x23e10a: cmp 0x88(%rsp),%rdi` | memory | 0x23e122 | fwd |
| Constant-time inversion | +0x1ae0 | je | reg/arith | `0x23e15c: add $0xfffffffffffffff8,%rsi` | memory | 0x23e188 | fwd |
| Constant-time inversion | +0x1aea | jae | mem | `0x23e162: cmp 0x88(%rsp),%rdi` | memory | 0x23e17a | fwd |
| Constant-time inversion | +0x1b01 | jb | mem | `0x23e17d: cmp (%rsp),%rdi` | arithmetic/control | 0x23e136 | back |
| Constant-time inversion | +0x1b0e | je | mem | `0x23e188: cmpq $0x0,0x10(%rsp)` | memory | 0x23e24d | fwd |
| Constant-time inversion | +0x1b31 | jne | reg/arith | `0x23e1ad: test $0x8,%dil` | memory | 0x23e1cb | fwd |
| Constant-time inversion | +0x1b3e | jae | mem | `0x23e1ba: cmp (%rsp),%rsi` | memory | 0x23e1d0 | fwd |
| Constant-time inversion | +0x1b65 | je | reg/arith | `0x23e1e2: test %rdi,%rdi` | memory | 0x23e24d | fwd |
| Constant-time inversion | +0x1b94 | je | mem | `0x23e20f: cmp 0x8(%rsp),%rsi` | memory | 0x23e24d | fwd |
| Constant-time inversion | +0x1ba1 | jae | mem | `0x23e21d: cmp (%rsp),%r9` | memory | 0x23e22e | fwd |
| Constant-time inversion | +0x1bc6 | jb | mem | `0x23e242: cmp (%rsp),%r10` | arithmetic/control | 0x23e1f5 | back |
| Constant-time inversion | +0x1bd3 | je | mem | `0x23e24d: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x23e325 | fwd |
| Constant-time inversion | +0x1bdd | je | reg/arith | `0x23e259: add $0xfffffffffffffff8,%r12` | memory | 0x23e2f9 | fwd |
| Constant-time inversion | +0x1c2b | je | reg/arith | `0x23e2a8: cmp %rdi,%r9` | memory | 0x23e2e9 | fwd |
| Constant-time inversion | +0x1c38 | jae | mem | `0x23e2b3: cmp 0x10(%rsp),%r9` | memory | 0x23e2c5 | fwd |
| Constant-time inversion | +0x1c62 | jb | mem | `0x23e2dd: cmp 0x10(%rsp),%r9` | arithmetic/control | 0x23e284 | back |
| Constant-time inversion | +0x1c6d | je | reg/arith | `0x23e2e9: test $0x1,%r12b` | arithmetic/control | 0x23e325 | fwd |
| Constant-time inversion | +0x1c85 | jae | mem | `0x23e300: cmp 0x10(%rsp),%rsi` | memory | 0x23e312 | fwd |
| Constant-time inversion | +0x1cab | je | mem | `0x23e325: cmpq $0x0,0x10(%rsp)` | memory | 0x23e39e | fwd |
| Constant-time inversion | +0x1ced | je | reg/arith | `0x23e369: add $0xfffffffffffffff8,%rsi` | memory | 0x23e399 | fwd |
| Constant-time inversion | +0x1cf7 | jae | mem | `0x23e36f: cmp 0x88(%rsp),%rdi` | memory | 0x23e387 | fwd |
| Constant-time inversion | +0x1d12 | jb | mem | `0x23e38a: cmp 0x80(%rsp),%rdi` | arithmetic/control | 0x23e33c | back |
| Constant-time inversion | +0x1d27 | je | mem | `0x23e3a1: cmpq $0x0,0x58(%rsp)` | arithmetic/control | 0x23e40a | fwd |
| Constant-time inversion | +0x1d5d | je | reg/arith | `0x23e3d9: add $0xfffffffffffffff8,%rcx` | memory | 0x23e3fd | fwd |
| Constant-time inversion | +0x1d63 | jae | mem | `0x23e3df: cmp (%rsp),%rsi` | memory | 0x23e3ee | fwd |
| Constant-time inversion | +0x1d76 | jb | mem | `0x23e3f1: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x23e3af | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x23e419: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x23e51a | fwd |
| Constant-time inversion | +0x1dac | je | reg/arith | `0x23e428: add $0xfffffffffffffff8,%r10` | memory | 0x23e4e4 | fwd |
| Constant-time inversion | +0x1e1b | je | reg/arith | `0x23e497: add $0xfffffffffffffffe,%rsi` | memory | 0x23e4d7 | fwd |
| Constant-time inversion | +0x1e2a | jae | mem | `0x23e4a5: cmp 0x58(%rsp),%r14` | memory | 0x23e4b2 | fwd |
| Constant-time inversion | +0x1e51 | jb | mem | `0x23e4cc: cmp 0x58(%rsp),%rcx` | arithmetic/control | 0x23e46e | back |
| Constant-time inversion | +0x1e5b | je | reg/arith | `0x23e4d7: test $0x1,%r10b` | memory | 0x23e51a | fwd |
| Constant-time inversion | +0x1e83 | jae | mem | `0x23e4fe: cmp 0x58(%rsp),%rdi` | memory | 0x23e510 | fwd |
| Constant-time inversion | +0x1ec9 | je | reg/arith | `0x23e545: add $0xfffffffffffffff8,%r8` | memory | 0x23e56a | fwd |
| Constant-time inversion | +0x1ed0 | jae | mem | `0x23e54b: cmp 0x58(%rsp),%rcx` | memory | 0x23e55d | fwd |
| Constant-time inversion | +0x1ee3 | jb | mem | `0x23e55f: cmp (%rsp),%rcx` | arithmetic/control | 0x23e520 | back |
| Constant-time inversion | +0x1ef0 | je | mem | `0x23e56a: cmpq $0x0,0x10(%rsp)` | memory | 0x23e62a | fwd |
| Constant-time inversion | +0x1f16 | jne | reg/arith | `0x23e592: test $0x8,%sil` | memory | 0x23e5c1 | fwd |
| Constant-time inversion | +0x1f23 | jae | mem | `0x23e59f: cmp (%rsp),%rsi` | memory | 0x23e5b0 | fwd |
| Constant-time inversion | +0x1f44 | je | reg/arith | `0x23e5c1: test %rdi,%rdi` | memory | 0x23e62a | fwd |
| Constant-time inversion | +0x1f73 | je | mem | `0x23e5ee: cmp 0x8(%rsp),%rax` | memory | 0x23e62a | fwd |
| Constant-time inversion | +0x1f80 | jae | mem | `0x23e5fc: cmp (%rsp),%rdi` | memory | 0x23e60d | fwd |
| Constant-time inversion | +0x1fa4 | jb | mem | `0x23e620: cmp (%rsp),%rcx` | arithmetic/control | 0x23e5d4 | back |
| Constant-time inversion | +0x1fb0 | je | mem | `0x23e62a: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x23e6ff | fwd |
| Constant-time inversion | +0x1fba | je | reg/arith | `0x23e636: add $0xfffffffffffffff8,%rdx` | memory | 0x23e6d3 | fwd |
| Constant-time inversion | +0x2007 | je | reg/arith | `0x23e684: cmp %rsi,%rdi` | memory | 0x23e6c4 | fwd |
| Constant-time inversion | +0x2014 | jae | mem | `0x23e68f: cmp 0x10(%rsp),%rdi` | memory | 0x23e6a1 | fwd |
| Constant-time inversion | +0x203d | jb | mem | `0x23e6b8: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x23e660 | back |
| Constant-time inversion | +0x2047 | je | reg/arith | `0x23e6c4: test $0x1,%dl` | arithmetic/control | 0x23e6ff | fwd |
| Constant-time inversion | +0x205f | jae | mem | `0x23e6da: cmp 0x10(%rsp),%rcx` | memory | 0x23e6ec | fwd |
| Constant-time inversion | +0x20cd | je | reg/arith | `0x23e74a: test %rcx,%rcx` | memory | 0x23cedc | back |
| Constant-time inversion | +0x210b | je | reg/arith | `0x23e787: add $0xfffffffffffffff8,%rax` | memory | 0x23cedc | back |
| Constant-time inversion | +0x2119 | jae | mem | `0x23e791: cmp 0x88(%rsp),%rcx` | memory | 0x23e7a9 | fwd |
| Constant-time inversion | +0x2130 | jae | mem | `0x23e7ab: cmp 0x40(%rsp),%rcx` | memory | 0x23e7bd | fwd |
| Constant-time inversion | +0x2144 | jb | mem | `0x23e7bf: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x23e75c | back |
| Constant-time inversion | +0x2199 | je | reg/arith | `0x23e815: cmp $0x1,%rbx` | memory | 0x23e8b8 | fwd |
| Constant-time inversion | +0x21b8 | jb | reg/arith | `0x23e834: cmp $0x18,%rcx` | memory | 0x23e89d | fwd |
| Constant-time inversion | +0x2204 | jne | reg/arith | `0x23e881: cmp %rdx,%rsi` | arithmetic/control | 0x23e869 | back |
| Constant-time inversion | +0x221b | je | reg/arith | `0x23e898: cmp %rsi,%rcx` | memory | 0x23e8b8 | fwd |
| Constant-time inversion | +0x2236 | jne | mem | `0x23e8b1: cmp 0x8(%rsp),%rax` | call+memory | 0x23e8aa | back |
| Constant-time inversion | +0x2258 | je | reg/arith | `0x23e8d4: cmp $0xffffffffffffffff,%r13` | memory | 0x23ea29 | fwd |
| Constant-time inversion | +0x226d | jne | mem | `0x23e8e8: cmp 0x38(%rsp),%rdi` | memory | 0x23eb50 | fwd |
| Constant-time inversion | +0x2369 | je | reg/arith | `0x23e9e6: test %r12,%r12` | memory | 0x23eb25 | fwd |
| Constant-time inversion | +0x237a | je | reg/arith | `0x23e9f7: test %r13,%r13` | memory | 0x23c6f2 | back |
| Constant-time inversion | +0x248b | jne | reg/arith | `0x23eb08: cmp %rax,%rsi` | memory | 0x23eadd | back |
| Constant-time inversion | +0x2558 | je | reg/arith | `0x23ebd5: test %r13,%r13` | memory | 0x23ebf4 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x2427c0: test %rcx,%rcx` | memory | 0x242834 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x2427d0: test %rax,%rax` | memory | 0x242828 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x2427dc: cmp (%r15),%rcx` | memory | 0x24282f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x2427e5: test %ecx,%ecx` | memory | 0x2427f5 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x2427ed: test %edx,%edx` | arithmetic/control | 0x2427f5 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x2427f1: cmp %edx,%ecx` | call | 0x24282f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x2427fd: test %eax,%eax` | memory | 0x242834 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x242809: test %rax,%rax` | memory | 0x242962 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x242812: cmp (%r12),%rcx` | memory | 0x242ba3 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x24283f: test %rcx,%rcx` | memory | 0x242940 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x242860: cmp %rdx,%rcx` | memory | 0x242940 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x242869: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x242860 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x24287f: test %rcx,%rcx` | memory | 0x242940 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x2428a0: cmp %rdx,%rcx` | memory | 0x242940 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x2428a9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2428a0 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x2428bd: test %r13,%r13` | memory | 0x242959 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x2428ca: cmpq $0x0,0x50(%rax)` | memory | 0x242970 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x2428ec: test %rax,%rax` | memory | 0x24293b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x242907: test %rax,%rax` | call | 0x242915 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x242911: test %eax,%eax` | call+memory | 0x242988 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x24297f: test %r13,%r13` | memory | 0x242acd | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x24298c: cmpq $0x0,0x50(%rax)` | memory | 0x242ac4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x2429b3: test %rax,%rax` | memory | 0x242b01 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x2429d2: test %rax,%rax` | call | 0x242adb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x2429e0: test %eax,%eax` | memory | 0x242adb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x2429f2: test %r14,%r14` | arithmetic/control | 0x242bbc | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x2429fb: test %r15,%r15` | memory | 0x242bc7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x242a0e: test %rcx,%rcx` | memory | 0x242a48 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x242a17: test %rax,%rax` | memory | 0x242a48 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x242a23: cmp (%r15),%rcx` | memory | 0x242a48 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x242a2c: test %ecx,%ecx` | memory | 0x242d0a | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x242a38: test %edx,%edx` | arithmetic/control | 0x242d0a | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x242a40: cmp %ecx,%edx` | call | 0x242d0a | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x242a62: test %rax,%rax` | memory | 0x242a75 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x242a6b: test %rax,%rax` | call | 0x242a75 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x242aa6: test %rbx,%rbx` | memory | 0x242cde | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x242ab3: test %rcx,%rcx` | arithmetic/control | 0x242b89 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x242b22: test %bpl,%bpl` | memory | 0x242b68 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x242b2f: test %rax,%rax` | memory | 0x242b42 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x242b38: test %rax,%rax` | call | 0x242b42 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x242b73: test %rbx,%rbx` | memory | 0x242947 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x242b80: test %rcx,%rcx` | memory | 0x242947 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x242bd4: test %eax,%eax` | memory | 0x242ce6 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x242be0: test %rax,%rax` | memory | 0x242be9 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x242bed: test %rax,%rax` | memory | 0x242bf6 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x242bfa: test %rax,%rax` | memory | 0x242c03 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x242c08: test %rax,%rax` | memory | 0x242c11 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x242c16: test %rax,%rax` | memory | 0x242c1f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x242c24: test %rax,%rax` | memory | 0x242c2d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x242c36: test %rax,%rax` | memory | 0x242c3f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x242c48: test %rax,%rax` | memory | 0x242c51 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x242c5a: test %rax,%rax` | call+memory | 0x242c63 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x242c8b: test %rax,%rax` | memory | 0x242cf2 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x242ca9: test %eax,%eax` | memory | 0x242cfe | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x242cba: test %r15,%r15` | memory | 0x242d28 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x242cc3: test $0xffffffff80000000,%rax` | memory | 0x242d3b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x242d0a: cmp %r15,%r14` | call | 0x242bdc | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x242d1b: test %eax,%eax` | arithmetic/control | 0x242bdc | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x242d46: test $0x1,%al` | memory | 0x243388 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x242d53: test %eax,%eax` | memory | 0x242d81 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x242d5e: cmp %rsi,(%rdi)` | call+memory | 0x242d8b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x242d73: test %al,%cl` | arithmetic/control | 0x242d94 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x242d81: test %r15,%r15` | arithmetic/control | 0x242da9 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x242d8b: test %r15,%r15` | memory | 0x242e74 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x242d94: cmp %rsi,(%r15)` | call | 0x242da9 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x242da1: test %al,%al` | memory | 0x242e74 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x242dba: test %rax,%rax` | memory | 0x242e80 | fwd |
| ECDSA scalar ladder (driver) | +0x635 | jg | mem | `0x242dd1: cmp 0x24(%rsp),%eax` | memory | 0x242dde | fwd |
| ECDSA scalar ladder (driver) | +0x63c | je | mem | `0x242dd7: cmpl $0x0,0x18(%r15)` | memory | 0x242dfa | fwd |
| ECDSA scalar ladder (driver) | +0x654 | je | reg/arith | `0x242df2: test %eax,%eax` | memory | 0x242e8c | fwd |
| ECDSA scalar ladder (driver) | +0x672 | je | reg/arith | `0x242e10: test %eax,%eax` | memory | 0x242e98 | fwd |
| ECDSA scalar ladder (driver) | +0x68f | je | reg/arith | `0x242e2d: test %eax,%eax` | memory | 0x24306e | fwd |
| ECDSA scalar ladder (driver) | +0x6a3 | js | mem | `0x242e3e: cmpl $0x0,0x24(%rsp)` | memory | 0x242ea4 | fwd |
| ECDSA scalar ladder (driver) | +0x6b5 | jae | mem | `0x242e51: cmp 0x10(%rcx),%rax` | memory | 0x242ea4 | fwd |
| ECDSA scalar ladder (driver) | +0x722 | je | reg/arith | `0x242ebf: test %rax,%rax` | memory | 0x242edc | fwd |
| ECDSA scalar ladder (driver) | +0x74f | je | reg/arith | `0x242eec: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x75d | jae | mem | `0x242efa: cmp %r15,(%rdi)` | call | 0x242f0f | fwd |
| ECDSA scalar ladder (driver) | +0x769 | je | reg/arith | `0x242f07: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x77b | je | reg/arith | `0x242f18: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x784 | jae | mem | `0x242f21: cmp %r15,(%rdi)` | call | 0x242f36 | fwd |
| ECDSA scalar ladder (driver) | +0x790 | je | reg/arith | `0x242f2e: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x7a2 | je | reg/arith | `0x242f3f: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ab | jae | mem | `0x242f48: cmp %r15,(%rdi)` | call | 0x242f5d | fwd |
| ECDSA scalar ladder (driver) | +0x7b7 | je | reg/arith | `0x242f55: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x7c5 | je | reg/arith | `0x242f62: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ce | jae | mem | `0x242f6b: cmp %r15,(%rdi)` | call | 0x242f80 | fwd |
| ECDSA scalar ladder (driver) | +0x7da | je | reg/arith | `0x242f78: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x7e8 | je | reg/arith | `0x242f85: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x7f1 | jae | mem | `0x242f8e: cmp %r15,(%rdi)` | call | 0x242fa3 | fwd |
| ECDSA scalar ladder (driver) | +0x7fd | je | reg/arith | `0x242f9b: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x80b | je | reg/arith | `0x242fa8: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x814 | jae | mem | `0x242fb1: cmp %r15,(%rdi)` | call | 0x242fc6 | fwd |
| ECDSA scalar ladder (driver) | +0x820 | je | reg/arith | `0x242fbe: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x832 | je | reg/arith | `0x242fcf: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x83b | jae | mem | `0x242fd8: cmp %r15,(%rdi)` | call | 0x242fed | fwd |
| ECDSA scalar ladder (driver) | +0x847 | je | reg/arith | `0x242fe5: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x859 | je | reg/arith | `0x242ff6: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x862 | jae | mem | `0x242fff: cmp %r15,(%rdi)` | call | 0x243014 | fwd |
| ECDSA scalar ladder (driver) | +0x86e | je | reg/arith | `0x24300c: test %al,%al` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x880 | je | reg/arith | `0x24301d: test %rdi,%rdi` | memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0x88e | jae | mem | `0x243026: cmp %r15,(%rdi)` | call | 0x243040 | fwd |
| ECDSA scalar ladder (driver) | +0x89a | je | reg/arith | `0x243038: test %al,%al` | memory | 0x242a54 | back |
| ECDSA scalar ladder (driver) | +0x8a5 | je | mem | `0x243040: cmpl $0x0,0x28(%r14)` | call+memory | 0x2431a2 | fwd |
| ECDSA scalar ladder (driver) | +0x8b9 | je | reg/arith | `0x243057: test %al,%al` | memory | 0x24307a | fwd |
| ECDSA scalar ladder (driver) | +0x8e8 | jne | reg/arith | `0x243084: cmp $0x4,%rdx` | memory | 0x2430cd | fwd |
| ECDSA scalar ladder (driver) | +0x922 | jne | reg/arith | `0x2430be: cmp $0x1,%dil` | call | 0x2430cf | fwd |
| ECDSA scalar ladder (driver) | +0x934 | je | reg/arith | `0x2430d2: test %cl,%cl` | arithmetic/control | 0x243148 | fwd |
| ECDSA scalar ladder (driver) | +0x939 | jne | reg/arith | `0x2430d6: test %sil,%sil` | memory | 0x243148 | fwd |
| ECDSA scalar ladder (driver) | +0x985 | je | mem | `0x24311c: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x243212 | fwd |
| ECDSA scalar ladder (driver) | +0x9cb | je | reg/arith | `0x243169: test %eax,%eax` | arithmetic/control | 0x2431e0 | fwd |
| ECDSA scalar ladder (driver) | +0x9d4 | jg | reg/arith | `0x243171: cmp $0x1,%eax` | arithmetic/control | 0x2431ec | fwd |
| ECDSA scalar ladder (driver) | +0x9d8 | jne | reg/arith | `0x243176: test %eax,%eax` | call+memory | 0x243223 | fwd |
| ECDSA scalar ladder (driver) | +0xa17 | je | reg/arith | `0x2431b4: test %rax,%rax` | call+memory | 0x2431d6 | fwd |
| ECDSA scalar ladder (driver) | +0xa2b | jne | reg/arith | `0x2431c9: test %eax,%eax` | arithmetic/control | 0x24304b | back |
| ECDSA scalar ladder (driver) | +0xa4f | jne | reg/arith | `0x2431ec: cmp $0x2,%eax` | call+memory | 0x243256 | fwd |
| ECDSA scalar ladder (driver) | +0xaa4 | jne | reg/arith | `0x243242: test %eax,%eax` | memory | 0x24331b | fwd |
| ECDSA scalar ladder (driver) | +0xaba | jo | mem | `0x243256: decl 0x24(%rsp)` | arithmetic/control | 0x243397 | fwd |
| ECDSA scalar ladder (driver) | +0xac0 | js | unknown | `?` | memory | 0x243302 | fwd |
| ECDSA scalar ladder (driver) | +0xae9 | jae | mem | `0x243285: cmp 0x10(%rcx),%rax` | memory | 0x2432a2 | fwd |
| ECDSA scalar ladder (driver) | +0xb1c | je | mem | `0x2432b6: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x2432d5 | fwd |
| ECDSA scalar ladder (driver) | +0xb4f | je | reg/arith | `0x2432ed: test %eax,%eax` | memory | 0x24335d | fwd |
| ECDSA scalar ladder (driver) | +0xb5a | jg | reg/arith | `0x2432f3: test %r15,%r15` | arithmetic/control | 0x243277 | back |
| ECDSA scalar ladder (driver) | +0xb89 | je | reg/arith | `0x243326: test %rax,%rax` | call+memory | 0x243344 | fwd |
| ECDSA scalar ladder (driver) | +0xba2 | je | reg/arith | `0x243340: test %eax,%eax` | call+memory | 0x243356 | fwd |
| ECDSA scalar ladder (driver) | +0xbdd | jne | reg/arith | `0x24337a: test %rax,%rax` | arithmetic/control | 0x242a67 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x4adb27: test %rax,%rax` | memory | 0x4ae0c5 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x4adb42: test %rbp,%rbp` | memory | 0x4ae0c5 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x4adb52: test %rax,%rax` | call+memory | 0x4ae0c5 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x4adb74: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x4adb92: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x4adbb0: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x4adbce: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x4adbf4: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x4adc14: test %eax,%eax` | arithmetic/control | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x4adc1c: test %r15,%r15` | memory | 0x4adc42 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x4adc2e: test %rdx,%rdx` | arithmetic/control | 0x4adc64 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x4adc5a: test %rdx,%rdx` | memory | 0x4adc70 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x4adc73: sub $0x1,%r9` | memory | 0x4adc97 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x4adc79: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x4adc70 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x4adc90: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x4adca0 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x4adc9a: sub $0x1,%r8` | arithmetic/control | 0x4adc90 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x4adca0: cmp %r9,%rdi` | memory | 0x4adcc0 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x4adcb0: sub $0x1,%rdi` | memory | 0x4adcc2 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x4adcba: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x4adcb0 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x4adcdd | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x4adcd5: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x4adcef: test %eax,%eax` | arithmetic/control | 0x4ae0c5 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x4adcfc: test %r15,%r15` | memory | 0x4add0b | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x4add23: sub $0x1,%rdi` | memory | 0x4add47 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x4add29: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x4add20 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x4add40: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x4add50 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x4add4a: sub $0x1,%rsi` | arithmetic/control | 0x4add40 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x4add50: cmp %rdi,%rdx` | arithmetic/control | 0x4add65 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x4add55: sub $0x1,%rdx` | memory | 0x4add67 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x4add5f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x4add55 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x4add7e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x4add76: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x4add93: test %eax,%eax` | memory | 0x4ae0c5 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x4addad: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x4addd0: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x4addeb: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x4ade05: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x4ade27: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x4ade41: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x4ade64: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x4ade86: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x4adea8: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x4adeca: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x4adee4: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x4adf00: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x4adf24: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x4adf3e: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x4adf5d: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x4adf7c: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x4adf9b: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x4adfb5: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x4adfd4: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x4adff1: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x4ae016: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x4ae035: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x4ae051: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x4ae06a: test %eax,%eax` | call+memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x4ae083: test %eax,%eax` | memory | 0x4ae0c3 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x4ae099: test %eax,%eax` | memory | 0x4ae0c5 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x4ae0c5: test %rbx,%rbx` | memory | 0x4ae0e8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x4ae0ce: test %rax,%rax` | memory | 0x4ae0e8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x2b811b: test %rax,%rax` | memory | 0x2b8b88 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x2b8135: cmpl $0x1,0x10(%rbp)` | memory | 0x2b815d | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x2b8145: test %rax,%rax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x2b8154: cmp $0xfffffffd,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x2b8165: testb $0x4,0xa4(%rbp)` | memory | 0x2b8185 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x2b816e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x2b81e6 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x2b8177: test %r13b,%r13b` | arithmetic/control | 0x2b82c0 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x2b818b: test %rax,%rax` | memory | 0x2b8b88 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x2b81b9: test %rax,%rax` | arithmetic/control | 0x2b86d0 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x2b81c2: test %r15,%r15` | memory | 0x2b81d0 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x2b81da: test %rax,%rax` | arithmetic/control | 0x2b8248 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x2b8203: test %r15,%r15` | arithmetic/control | 0x2b82a0 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x2b820c: test %r14,%r14` | memory | 0x2b821a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x2b8221: test %r15,%r15` | memory | 0x2b8292 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x2b823b: test %eax,%eax` | memory | 0x2b8286 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x2b8264: test %eax,%eax` | memory | 0x2b86a7 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x2b8292: test %r14,%r14` | memory | 0x2b82a0 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x2b82a6: or %r13b,%al` | arithmetic/control | 0x2b84d2 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x2b82b7: test %r15,%r15` | memory | 0x2b8b88 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x2b82c6: test %rax,%rax` | memory | 0x2b8b88 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x2b8309: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x2b8317: test %rax,%rax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x2b833d: test %rax,%rax` | call+memory | 0x2b9030 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x2b8366: test %eax,%eax` | call+memory | 0x2b9030 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x2b83b4: test %al,0x38(%rsp)` | memory | 0x2b8433 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x2b83c5: test %rax,%rax` | memory | 0x2b8b88 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x2b83eb: test %rax,%rax` | call+memory | 0x2b8a82 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x2b8425: test %ebp,%ebp` | arithmetic/control | 0x2b8b8b | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x2b8435: test %ebx,%ebx` | memory | 0x2b88ee | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x2b8447: test %r15b,%r15b` | call+memory | 0x2b88f8 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x2b846e: test %r13,%r13` | arithmetic/control | 0x2b902b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x2b847c: test %rax,%rax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x2b848e: test %rax,%rax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x2b849e: test %rcx,%rcx` | memory | 0x2b8a8f | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x2b84b6: cmpq $0x0,0x10(%rcx)` | memory | 0x2b8a99 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x2b84f7: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x2b8515: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x2b853f: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x2b855d: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x2b8596: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x2b85b8: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x2b85d1: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x2b85d9: test %rbx,%rbx` | memory | 0x2b8624 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x2b85e8: cmpl $0x0,0x18(%rbx)` | memory | 0x2b8624 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x2b85fe: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x2b8606: cmpl $0x0,0x18(%rbx)` | memory | 0x2b8624 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x2b861c: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x2b863a: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x2b865c: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x2b8679: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x2b86b7: test %r15,%r15` | memory | 0x2b86c5 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x2b86c5: test %bl,%bl` | memory | 0x2b8778 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x2b86f2: test %rax,%rax` | arithmetic/control | 0x2b8780 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x2b86fb: test %r15,%r15` | memory | 0x2b8709 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x2b8713: test %rax,%rax` | arithmetic/control | 0x2b871c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x2b8738: test %eax,%eax` | memory | 0x2b8753 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x2b8763: test %r15,%r15` | memory | 0x2b8771 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x2b8771: test %bl,%bl` | arithmetic/control | 0x2b8780 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x2b878a: test %ebx,%ebx` | memory | 0x2b887b | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x2b87b9: test %bl,%bl` | arithmetic/control | 0x2b88e1 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x2b87c4: cmp %r14,%r13` | memory | 0x2b887b | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x2b87f8: test %rax,%rax` | arithmetic/control | 0x2b87c1 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x2b87fd: test %r15,%r15` | memory | 0x2b880b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x2b880f: test %rax,%rax` | arithmetic/control | 0x2b881d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x2b8816: test %r15,%r15` | arithmetic/control | 0x2b87b0 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x2b8832: test %eax,%eax` | memory | 0x2b8858 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x2b884a: test %r15,%r15` | arithmetic/control | 0x2b87b0 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x2b886d: test %r15,%r15` | arithmetic/control | 0x2b87b0 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x2b8889: test %ebx,%ebx` | memory | 0x2b88d4 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x2b8895: cmp 0x618ac4(%rip),%rax        # 8d1360 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x5cfe20>` | call+memory | 0x2b816e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x2b88fd: test %al,%r14b` | memory | 0x2b8b7f | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x2b8933: test %eax,%eax` | arithmetic/control | 0x2b8b8b | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x2b893b: test %rbx,%rbx` | memory | 0x2b895e | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x2b8940: cmpl $0x0,0x18(%rbx)` | memory | 0x2b895e | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x2b8956: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x2b8973: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x2b8981: test %rax,%rax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x2b89cd: test %ebp,%ebp` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x2b89d5: test %rbx,%rbx` | memory | 0x2b89fd | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x2b89df: cmpl $0x0,0x18(%rbx)` | memory | 0x2b89fd | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x2b89f5: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x2b8a15: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x2b8a2e: test %eax,%eax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x2b8a36: cmpl $0x0,0x28(%rsp)` | memory | 0x2b8d8c | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x2b8a4c: test %rax,%rax` | memory | 0x2b8b8b | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x2b8a62: test %rax,%rax` | memory | 0x2b8c99 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x2b8a6b: cmpq $0x0,0x10(%rax)` | memory | 0x2b8c99 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x2b8add: test %eax,%eax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x2b8af2: test %rax,%rax` | call+memory | 0x2b902b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x2b8b16: test %eax,%eax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x2b8b1e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x2b8bc4 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x2b8b76: test %al,%r14b` | arithmetic/control | 0x2b8906 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x2b8b7f: test %r15b,%r15b` | arithmetic/control | 0x2b8d8c | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x2b8b8b: test %r12,%r12` | memory | 0x2b8bb2 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x2b8b95: test %rax,%rax` | memory | 0x2b8bb2 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x2b8bcd: test %rax,%rax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x2b8be7: test %rax,%rax` | memory | 0x2b8bfd | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x2b8bec: cmpq $0x2,0x10(%rax)` | memory | 0x2b8bfd | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x2b8c3a: test %eax,%eax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x2b8c4f: test %rax,%rax` | call+memory | 0x2b902b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x2b8c73: test %eax,%eax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x2b8c7b: cmpl $0x2,0x28(%rsp)` | memory | 0x2b8f43 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x2b8cb1: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x2b8cce: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x2b8d05: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x2b8d0d: cmpq $0x0,0x8(%rsp)` | memory | 0x2b8d39 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x2b8d1a: cmpl $0x0,0x18(%rax)` | memory | 0x2b8d39 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x2b8d31: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x2b8d4e: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x2b8d69: test %eax,%eax` | memory | 0x2b9043 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x2b8d71: cmpl $0x1,0x28(%rsp)` | memory | 0x2b905b | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x2b8d90: test %rdx,%rdx` | memory | 0x2b8f22 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x2b8d9d: test %rcx,%rcx` | memory | 0x2b8f22 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x2b8dae: cmp 0x6185ab(%rip),%rax        # 8d1360 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x5cfe20>` | memory | 0x2b8dd8 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x2b8db7: test %rax,%rax` | call+memory | 0x2b8b88 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x2b8df5: test %eax,%eax` | memory | 0x2b8b8b | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x2b8e10: test %eax,%eax` | memory | 0x2b8b8b | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x2b8e30: cmp %rdx,%rcx` | memory | 0x2b8f22 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x2b8e39: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2b8e30 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x2b8e64: test %eax,%eax` | memory | 0x2b8f2d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x2b8e71: cmpl $0x0,0x18(%rax)` | memory | 0x2b8e94 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x2b8e8c: test %eax,%eax` | memory | 0x2b8b8b | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x2b8ea7: cmp %rdx,%rcx` | memory | 0x2b8f35 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x2b8eb0: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2b8ea7 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x2b8ec6: test %rax,%rax` | memory | 0x2b8f7c | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x2b8eeb: test %rax,%rax` | call+memory | 0x2b9053 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x2b8f51: test %rax,%rax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x2b8f66: test %rax,%rax` | memory | 0x2b8f87 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x2b8f6b: cmpq $0x3,0x10(%rax)` | memory | 0x2b8f87 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x2b8fc4: test %eax,%eax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x2b8fd5: test %rax,%rax` | call+memory | 0x2b902b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x2b8ff5: test %eax,%eax` | memory | 0x2b902b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x2b8ff9: cmpl $0x3,0x28(%rsp)` | memory | 0x2b8b3b | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x2b906a: test %rax,%rax` | memory | 0x2b9080 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x2b906f: cmpq $0x2,0x10(%rax)` | memory | 0x2b9080 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x2b9098: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x2b90b1: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x2b90e4: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x2b90ec: cmpq $0x0,0x8(%rsp)` | memory | 0x2b9118 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x2b90f9: cmpl $0x0,0x18(%rax)` | memory | 0x2b9118 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x2b9110: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x2b912d: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x2b9148: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x2b9150: cmpl $0x2,0x28(%rsp)` | memory | 0x2b8d7c | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x2b916a: test %rax,%rax` | memory | 0x2b9180 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x2b916f: cmpq $0x3,0x10(%rax)` | memory | 0x2b9180 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x2b9198: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x2b91b5: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x2b91ec: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x112a | je | mem | `0x2b91f4: cmpq $0x0,0x8(%rsp)` | memory | 0x2b9220 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x2b9201: cmpl $0x0,0x18(%rax)` | memory | 0x2b9220 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x2b9218: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x2b9235: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x2b9250: test %eax,%eax` | memory | 0x2b9043 | back |
| RSA CRT arms | +0x118d | je | mem | `0x2b9258: cmpl $0x3,0x28(%rsp)` | memory | 0x2b8d7c | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x2b423a: test %r8,%r8` | memory | 0x2b436b | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x2b4362: dec %r8` | memory | 0x2b4250 | back |
| DH key agreement (driver) | +0x26 | jle | reg/arith | `0x23fda1: cmp $0x2710,%eax` | memory | 0x23fdb1 | fwd |
| DH key agreement (driver) | +0x39 | je | reg/arith | `0x23fdb6: test %rdi,%rdi` | memory | 0x23fddb | fwd |
| DH key agreement (driver) | +0x46 | jle | reg/arith | `0x23fdc1: cmp $0x2710,%eax` | call+memory | 0x23fddb | fwd |
| DH key agreement (driver) | +0x6b | jge | reg/arith | `0x23fde6: cmp $0x200,%eax` | call+memory | 0x23fe0c | fwd |
| DH key agreement (driver) | +0xbb | jne | mem | `0x23fe36: cmpl $0x1,0x30(%rsp)` | arithmetic/control | 0x23fe44 | fwd |
| DH key agreement (driver) | +0xe2 | je | reg/arith | `0x23fe5f: test %rax,%rax` | memory | 0x23fee2 | fwd |
| DH key agreement (driver) | +0x13f | je | reg/arith | `0x23febc: test %rax,%rax` | memory | 0x240026 | fwd |
| DH key agreement (driver) | +0x14e | je | mem | `0x23fec8: cmpq $0x0,0x78(%r12)` | memory | 0x23feff | fwd |
| DH key agreement (driver) | +0x159 | jne | mem | `0x23fed0: testb $0x1,0x80(%r12)` | arithmetic/control | 0x23ff2d | fwd |
| DH key agreement (driver) | +0x191 | je | reg/arith | `0x23ff0e: test %rdx,%rdx` | memory | 0x240013 | fwd |
| DH key agreement (driver) | +0x1a4 | jae | reg/arith | `0x23ff20: cmp $0x8,%rdx` | arithmetic/control | 0x23ffa2 | fwd |
| DH key agreement (driver) | +0x1c5 | jne | reg/arith | `0x23ff42: test %rdx,%rdx` | memory | 0x24007d | fwd |
| DH key agreement (driver) | +0x1d3 | je | reg/arith | `0x23ff4b: test %rbp,%rbp` | memory | 0x23ff5e | fwd |
| DH key agreement (driver) | +0x1e9 | jne | reg/arith | `0x23ff66: test %rdx,%rdx` | memory | 0x240065 | fwd |
| DH key agreement (driver) | +0x20a | je | reg/arith | `0x23ff88: test %eax,%eax` | memory | 0x240058 | fwd |
| DH key agreement (driver) | +0x276 | jne | reg/arith | `0x23fff3: cmp %rsi,%rdx` | arithmetic/control | 0x23ffa8 | back |
| DH key agreement (driver) | +0x27b | je | reg/arith | `0x23fff8: test %rax,%rax` | memory | 0x240013 | fwd |
| DH key agreement (driver) | +0x291 | jne | reg/arith | `0x24000e: cmp %rdx,%rax` | memory | 0x240003 | back |
| DH key agreement (driver) | +0x2b1 | je | reg/arith | `0x240029: test %rax,%rax` | memory | 0x240048 | fwd |
| DH key agreement (driver) | +0x2e8 | je | reg/arith | `0x240065: test %rbp,%rbp` | memory | 0x24007d | fwd |
| DH key agreement (driver) | +0x305 | je | reg/arith | `0x240082: test %rax,%rax` | memory | 0x24008b | fwd |
| DH key agreement (driver) | +0x30e | je | reg/arith | `0x24008b: test %rdx,%rdx` | memory | 0x240170 | fwd |
| DH key agreement (driver) | +0x324 | je | reg/arith | `0x2400a1: test %rax,%rax` | memory | 0x24019c | fwd |
| DH key agreement (driver) | +0x331 | je | reg/arith | `0x2400ae: test %rax,%rax` | call+memory | 0x24019c | fwd |
| DH key agreement (driver) | +0x357 | je | reg/arith | `0x2400d5: test %eax,%eax` | memory | 0x240187 | fwd |
| DH key agreement (driver) | +0x37a | je | reg/arith | `0x2400f7: test %rax,%rax` | memory | 0x240197 | fwd |
| DH key agreement (driver) | +0x390 | je | reg/arith | `0x24010e: test %eax,%eax` | memory | 0x240190 | fwd |
| DH key agreement (driver) | +0x3a6 | jle | reg/arith | `0x240124: test %eax,%eax` | memory | 0x240190 | fwd |
| DH key agreement (driver) | +0x3bf | je | reg/arith | `0x240136: test %eax,%eax` | memory | 0x240197 | fwd |
| DH key agreement (driver) | +0x3cf | jo | reg/arith | `0x24014c: add $0x7,%eax` | memory | 0x24026c | fwd |
| DH key agreement (driver) | +0x422 | je | reg/arith | `0x24019f: test %rdx,%rdx` | memory | 0x24022c | fwd |
| DH key agreement (driver) | +0x435 | jae | reg/arith | `0x2401b1: cmp $0x8,%rdx` | arithmetic/control | 0x2401bb | fwd |
| DH key agreement (driver) | +0x48f | jne | reg/arith | `0x24020c: cmp %rsi,%rdx` | arithmetic/control | 0x2401c1 | back |
| DH key agreement (driver) | +0x494 | je | reg/arith | `0x240211: test %rax,%rax` | memory | 0x24022c | fwd |
| DH key agreement (driver) | +0x4aa | jne | reg/arith | `0x240227: cmp %rdx,%rax` | memory | 0x24021c | back |
| DH key agreement (driver) | +0x4ca | je | reg/arith | `0x240242: test %rax,%rax` | memory | 0x240261 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x39 | je | reg/arith | `0x24082c: test %r11,%r11` | memory | 0x240b6b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x63 | je | reg/arith | `0x240860: cmp %rcx,%rax` | memory | 0x240b6b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x72 | je | mem | `0x240869: cmpq $0x0,(%rsi,%rcx,1)` | memory | 0x240860 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x7b | je | reg/arith | `0x240878: test %rcx,%rcx` | memory | 0x240b6b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa3 | je | reg/arith | `0x2408a0: cmp %r9,%rdx` | memory | 0x240b6b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb2 | je | mem | `0x2408a9: cmpq $0x0,(%rax,%r9,1)` | arithmetic/control | 0x2408a0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xb7 | je | reg/arith | `0x2408b4: cmp %r11,%r13` | arithmetic/control | 0x240b34 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xcd | je | reg/arith | `0x2408ca: test %r9b,%dl` | arithmetic/control | 0x240b34 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdf | je | reg/arith | `0x2408dc: test %r15,%r15` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec | je | reg/arith | `0x2408e9: test %r10,%r10` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf9 | je | reg/arith | `0x2408f6: test %r9,%r9` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x106 | je | reg/arith | `0x240903: test %r8,%r8` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x118 | je | reg/arith | `0x240915: test %rdx,%rdx` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x125 | je | reg/arith | `0x240922: test %r11,%r11` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x135 | je | reg/arith | `0x240932: test %rbx,%rbx` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x145 | je | reg/arith | `0x240942: test %rdx,%rdx` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x162 | jne | reg/arith | `0x24095f: or %rbx,%rdx` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x170 | jne | mem | `0x240968: cmpq $0x0,0x118(%r11)` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x17e | jne | mem | `0x240976: cmpq $0x0,0x120(%r11)` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x18c | jne | mem | `0x240984: cmpq $0x0,0x128(%r11)` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1a0 | jne | mem | `0x240999: cmp %rbx,0x1a8(%r11)` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1ab | jne | mem | `0x2409a6: cmpq $0x4,0x10(%r10)` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1ef | jne | reg/arith | `0x2409ec: or %r10b,%dil` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x21c | jne | reg/arith | `0x240a16: cmp $0xffff,%esi` | memory | 0x240b24 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x260 | jne | reg/arith | `0x240a5c: cmp $0x4,%rdi` | memory | 0x240b1e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x28f | jne | reg/arith | `0x240a89: cmp $0xffff,%esi` | memory | 0x240b1e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2e9 | jne | reg/arith | `0x240ae5: cmp $0x4,%rdi` | memory | 0x240b1e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x318 | je | reg/arith | `0x240b12: cmp $0xffff,%esi` | arithmetic/control | 0x241eea | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x33e | jne | reg/arith | `0x240b3b: or %r13,%rax` | memory | 0x240b6b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x346 | je | reg/arith | `0x240b43: cmp %r11,%rdx` | memory | 0x240c25 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x36e | je | reg/arith | `0x240b6b: test %r13,%r13` | memory | 0x240c25 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x37b | je | reg/arith | `0x240b78: test %r12,%r12` | memory | 0x240ff1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x39f | je | reg/arith | `0x240b92: test %rax,%rax` | memory | 0x241175 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3aa | je | mem | `0x240ba5: cmpq $0x0,0x10(%rax)` | memory | 0x241175 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3c3 | je | reg/arith | `0x240bc0: test %rax,%rax` | memory | 0x241169 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3d4 | jne | mem | `0x240bd0: cmp (%r12),%rcx` | memory | 0x241170 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3eb | je | reg/arith | `0x240be9: test %esi,%esi` | memory | 0x241299 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3f9 | je | reg/arith | `0x240bf6: test %r8d,%r8d` | arithmetic/control | 0x240c04 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3fe | jne | reg/arith | `0x240bfb: cmp %r8d,%esi` | memory | 0x241170 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x407 | jne | mem | `0x240c04: cmp (%rdx),%rcx` | memory | 0x241170 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x412 | je | reg/arith | `0x240c10: test %ecx,%ecx` | arithmetic/control | 0x2412a2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x41a | jne | reg/arith | `0x240c18: cmp %ecx,%esi` | arithmetic/control | 0x241170 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x472 | jb | reg/arith | `0x240c6f: add %r14,%r13` | call+memory | 0x2411b7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4cf | je | reg/arith | `0x240ccb: cmp $0xffffffffffffffff,%r13` | call+memory | 0x241ebc | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x514 | je | reg/arith | `0x240d11: test %r12,%r12` | memory | 0x240e87 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x534 | je | reg/arith | `0x240d2c: test %rdi,%rdi` | arithmetic/control | 0x240eeb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x53d | je | reg/arith | `0x240d3a: test %rbx,%rbx` | arithmetic/control | 0x240eeb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x546 | je | reg/arith | `0x240d43: test %r13,%r13` | memory | 0x240eeb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x551 | jb | mem | `0x240d4c: add 0x58(%rsp),%r15` | memory | 0x241ec5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x569 | je | unknown | `?` | memory | 0x241005 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x59a | jae | mem | `0x240d95: cmp 0x58(%rsp),%r15` | memory | 0x240da5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5b5 | ja | reg/arith | `0x240db0: cmp $0x7cf,%eax` | arithmetic/control | 0x240df0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5c1 | ja | reg/arith | `0x240dbc: cmp $0x31f,%eax` | arithmetic/control | 0x240df0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5cd | ja | reg/arith | `0x240dc8: cmp $0x12b,%eax` | arithmetic/control | 0x240df0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5d7 | ja | reg/arith | `0x240dd4: cmp $0x45,%eax` | memory | 0x240df0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x606 | jb | reg/arith | `0x240e03: add %rax,%rbp` | memory | 0x241eda | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x624 | jae | mem | `0x240e1f: cmp 0x58(%rsp),%r15` | call+memory | 0x240e2f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x64f | je | reg/arith | `0x240e4c: test %rax,%rax` | memory | 0x2410cc | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x66e | jne | reg/arith | `0x240e66: dec %r14` | memory | 0x240d90 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x67c | jne | reg/arith | `0x240e79: test %r14,%r14` | arithmetic/control | 0x241018 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x694 | je | reg/arith | `0x240e8c: test %rdi,%rdi` | call+memory | 0x240eb9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6bc | je | reg/arith | `0x240eb9: test %rbx,%rbx` | memory | 0x240fba | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6ee | je | reg/arith | `0x240eeb: test %rdi,%rdi` | call+memory | 0x240f13 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x71b | je | reg/arith | `0x240f13: test %rbx,%rbx` | call+memory | 0x240f43 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x74a | je | reg/arith | `0x240f47: test %rdi,%rdi` | memory | 0x240f94 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x792 | jne | reg/arith | `0x240f8f: test %rdi,%rdi` | call+memory | 0x240f70 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x7c0 | je | reg/arith | `0x240fbd: test %r13,%r13` | call+memory | 0x2418a1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x812 | je | reg/arith | `0x24100f: test %r14,%r14` | memory | 0x2414dd | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x825 | je | reg/arith | `0x24101d: test %rax,%rax` | memory | 0x2411c3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x83f | je | mem | `0x241037: cmpb $0x0,0x88(%rsp)` | call+memory | 0x2411f5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x86c | je | reg/arith | `0x241069: test %rax,%rax` | memory | 0x2411dd | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x87d | jbe | reg/arith | `0x24107a: cmp %r13,%rcx` | memory | 0x2412ff | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x88e | jo | reg/arith | `0x24108b: mul %rsi` | memory | 0x2422f5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8a0 | jae | reg/arith | `0x24109d: cmp %rax,%rcx` | arithmetic/control | 0x2413be | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8a9 | je | reg/arith | `0x2410a6: test %rsi,%rsi` | arithmetic/control | 0x24230a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8b9 | je | reg/arith | `0x2410b5: shr $0x20,%rax` | division | 0x241354 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x920 | je | reg/arith | `0x24111d: test %rdi,%rdi` | call+memory | 0x241704 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x962 | jne | reg/arith | `0x24115f: test %rdi,%rdi` | arithmetic/control | 0x241140 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x9b1 | jae | reg/arith | `0x2411ae: add %r14,%r13` | memory | 0x240c78 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x9cb | jne | mem | `0x2411c3: cmpb $0x0,0x98(%rsp)` | call+memory | 0x2414e2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa54 | je | reg/arith | `0x241251: test %rdi,%rdi` | call+memory | 0x241704 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa92 | jne | reg/arith | `0x24128f: test %rdi,%rdi` | arithmetic/control | 0x241270 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xa9c | jne | mem | `0x241299: cmp (%rdx),%rcx` | call+memory | 0x241170 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xab1 | jne | reg/arith | `0x2412af: test %eax,%eax` | memory | 0x241175 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xad6 | je | reg/arith | `0x2412d3: test %rsi,%rsi` | arithmetic/control | 0x242313 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xae9 | je | reg/arith | `0x2412e5: shr $0x20,%rdx` | division | 0x241ba5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb08 | je | reg/arith | `0x241304: cmp $0xffffffffffffffff,%rdx` | memory | 0x2422fe | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb6b | jbe | mem | `0x241367: cmp 0x10(%rcx),%rax` | call+memory | 0x2413ab | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbb8 | jb | mem | `0x2413ab: add 0x58(%rsp),%rax` | memory | 0x24236f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbce | jae | reg/arith | `0x2413cb: cmp %rax,%r14` | memory | 0x2414b5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbf9 | jae | mem | `0x2413ef: cmp 0x48(%rsp),%r14` | memory | 0x241424 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc0f | jb | reg/arith | `0x24140c: sub %rsi,%rax` | memory | 0x241c47 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc5b | je | reg/arith | `0x241458: test %rax,%rax` | memory | 0x241b32 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc7a | je | mem | `0x241476: cmpq $0x0,(%rdi)` | memory | 0x241b69 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xcaf | jne | mem | `0x2414a7: cmp %r14,0x90(%rsp)` | call+memory | 0x2413ef | back |
| EC wNAF multiply (verification / public-scalar core) | +0xce6 | je | reg/arith | `0x2414e2: cmp $0xffffffffffffffff,%rbp` | memory | 0x241ece | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd0a | je | reg/arith | `0x241507: test %rax,%rax` | memory | 0x241676 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd29 | je | reg/arith | `0x241526: test %rcx,%rcx` | memory | 0x241639 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd62 | je | reg/arith | `0x24155f: test %rcx,%rcx` | memory | 0x24233a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd6e | je | mem | `0x241568: cmpq $0x0,0x40(%rsp)` | memory | 0x241b0f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd84 | ja | reg/arith | `0x241580: cmp $0x40,%rcx` | arithmetic/control | 0x242353 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd95 | jne | reg/arith | `0x241592: test %rax,%rax` | memory | 0x241620 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xda8 | je | mem | `0x2415a3: cmpq $0x0,0x50(%rax)` | memory | 0x241770 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdc8 | je | reg/arith | `0x2415c5: test %rax,%rax` | memory | 0x241764 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdec | je | reg/arith | `0x2415e9: test %rax,%rax` | call | 0x24173e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdf9 | je | reg/arith | `0x2415f7: test %eax,%eax` | memory | 0x24173e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe15 | jne | reg/arith | `0x241612: test %rcx,%rcx` | arithmetic/control | 0x241580 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xe33 | jne | reg/arith | `0x24162b: cmp %rcx,%r14` | memory | 0x241552 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xe40 | je | reg/arith | `0x24163d: cmp %rax,%rbx` | call+memory | 0x2418b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec8 | je | reg/arith | `0x2416c5: test %rdi,%rdi` | call+memory | 0x241704 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf02 | jne | reg/arith | `0x2416ff: test %rdi,%rdi` | call+memory | 0x2416e0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xfdc | je | reg/arith | `0x2417d9: test %rdi,%rdi` | call+memory | 0x241814 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1012 | jne | reg/arith | `0x24180f: test %rdi,%rdi` | call+memory | 0x2417f0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x103e | je | reg/arith | `0x24183b: test %rdi,%rdi` | call+memory | 0x24185f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x105d | jne | reg/arith | `0x24185a: test %rdi,%rdi` | call+memory | 0x241850 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x10cc | je | reg/arith | `0x2418c9: test %rax,%rax` | arithmetic/control | 0x241a75 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10d5 | je | reg/arith | `0x2418d2: test %rbx,%rbx` | memory | 0x241a87 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10fe | je | reg/arith | `0x2418fb: cmp %rbx,%r12` | memory | 0x241a87 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1115 | jae | mem | `0x241910: cmp 0x58(%rsp),%r12` | memory | 0x241925 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1135 | je | reg/arith | `0x241933: test %eax,%eax` | memory | 0x241ae9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1145 | jbe | mem | `0x241940: cmpq $0x1,(%rax,%r12,8)` | memory | 0x2418f8 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x116a | je | reg/arith | `0x241968: test %eax,%eax` | memory | 0x241ae9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x117c | je | reg/arith | `0x241979: test %rcx,%rcx` | arithmetic/control | 0x24233a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x118c | ja | reg/arith | `0x241988: cmp $0x40,%rcx` | arithmetic/control | 0x242353 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x119d | jne | reg/arith | `0x24199a: test %rax,%rax` | memory | 0x2418f8 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x11b5 | je | reg/arith | `0x2419b2: test %rax,%rax` | memory | 0x241c92 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11cb | jne | mem | `0x2419c8: cmp (%rsi),%r9` | memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11e0 | je | reg/arith | `0x2419de: test %edi,%edi` | memory | 0x241a30 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11e9 | je | reg/arith | `0x2419e6: test %r8d,%r8d` | arithmetic/control | 0x2419f4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11ee | jne | reg/arith | `0x2419eb: cmp %r8d,%edi` | memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11f7 | jne | mem | `0x2419f4: cmp (%rdx),%r9` | memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1204 | je | reg/arith | `0x241a01: test %r8d,%r8d` | arithmetic/control | 0x241a0f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1209 | jne | reg/arith | `0x241a06: cmp %r8d,%edi` | memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1217 | jne | mem | `0x241a14: cmp (%rcx),%r9` | memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1224 | je | reg/arith | `0x241a21: test %r8d,%r8d` | arithmetic/control | 0x241a47 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1229 | je | reg/arith | `0x241a26: cmp %r8d,%edi` | arithmetic/control | 0x241a47 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1233 | jne | mem | `0x241a30: cmp (%rdx),%r9` | memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1241 | jne | mem | `0x241a3e: cmp (%rcx),%r9` | call+memory | 0x241add | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1255 | je | reg/arith | `0x241a53: test %eax,%eax` | memory | 0x241ae9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x126a | jne | reg/arith | `0x241a67: test %rcx,%rcx` | arithmetic/control | 0x241988 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1299 | je | reg/arith | `0x241a96: test %rax,%rax` | call+memory | 0x241ae9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12bc | je | reg/arith | `0x241aab: test %eax,%eax` | memory | 0x241af8 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12cf | jbe | reg/arith | `0x241ac3: cmp $0x7fffffff,%r13` | arithmetic/control | 0x241c9e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1313 | jae | reg/arith | `0x241b0f: cmp $0x41,%rcx` | memory | 0x242353 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13b4 | je | reg/arith | `0x241bb0: cmp $0xffffffffffffffff,%rsi` | memory | 0x242322 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13d3 | jb | reg/arith | `0x241bcf: sub $0x1,%rcx` | arithmetic/control | 0x24232e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13dd | jae | reg/arith | `0x241bd9: cmp $0x41,%rdx` | memory | 0x242347 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13f6 | jo | reg/arith | `0x241bf3: mul %rdx` | memory | 0x242360 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1405 | jne | mem | `0x241c01: cmp %rax,0x28(%rcx)` | memory | 0x241c3b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1430 | jae | reg/arith | `0x241c2d: add %r14,%r13` | arithmetic/control | 0x240c78 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x14a1 | je | reg/arith | `0x241c9e: test %r13,%r13` | memory | 0x24237b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14ca | jle | mem | `0x241cb6: cmpl $0x1,0x58(%rsp)` | arithmetic/control | 0x241e28 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14d3 | jne | reg/arith | `0x241cd0: test %r12d,%r12d` | memory | 0x241cee | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14e8 | je | reg/arith | `0x241ce6: test %eax,%eax` | memory | 0x241e3f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14ff | je | mem | `0x241cf6: cmpq $0x0,0x90(%rsp)` | arithmetic/control | 0x241cb6 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1526 | je | reg/arith | `0x241d24: test %eax,%eax` | memory | 0x241e9e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1537 | je | mem | `0x241d2f: cmp %r15,0x90(%rsp)` | memory | 0x241cb6 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1546 | jbe | mem | `0x241d42: cmp %rbp,(%rax,%r15,8)` | memory | 0x241d2c | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1559 | je | reg/arith | `0x241d56: test %r14d,%r14d` | arithmetic/control | 0x241d2c | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1563 | je | reg/arith | `0x241d61: cmp %eax,%ebx` | arithmetic/control | 0x241d90 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1568 | jne | reg/arith | `0x241d65: test %r12d,%r12d` | memory | 0x241d87 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1581 | je | reg/arith | `0x241d7f: test %eax,%eax` | memory | 0x241e9e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15b3 | je | reg/arith | `0x241db0: test %r12d,%r12d` | memory | 0x241d09 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x15c9 | je | reg/arith | `0x241dc7: test %eax,%eax` | memory | 0x241e9e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15e4 | je | reg/arith | `0x241de1: test %rax,%rax` | call+memory | 0x241d2c | back |
| EC wNAF multiply (verification / public-scalar core) | +0x15f8 | jne | reg/arith | `0x241df6: test %eax,%eax` | call+memory | 0x241d2c | back |
| EC wNAF multiply (verification / public-scalar core) | +0x162b | je | reg/arith | `0x241e28: test %r12d,%r12d` | memory | 0x241e53 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1655 | je | reg/arith | `0x241e53: test %ebx,%ebx` | memory | 0x241e70 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x166e | je | reg/arith | `0x241e6c: test %eax,%eax` | call+memory | 0x241e9e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x16f4 | jne | reg/arith | `0x241eea: cmp $0x1,%rcx` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x16fe | jne | mem | `0x241efa: cmpq $0x1,(%rax)` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x170d | je | mem | `0x241f09: cmpl $0x0,0x28(%rax)` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x171f | je | reg/arith | `0x241f1c: test %rsi,%rsi` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1731 | je | reg/arith | `0x241f2e: test %rax,%rax` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x178b | jne | reg/arith | `0x241f87: cmp $0x4,%rdx` | memory | 0x240b1e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x17be | jne | reg/arith | `0x241fb8: cmp $0xffff,%ecx` | memory | 0x240b1e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1818 | jne | reg/arith | `0x242014: cmp $0x4,%rax` | memory | 0x240b1e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x184a | jne | reg/arith | `0x242045: cmp $0xffff,%eax` | memory | 0x240b1e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x185c | jne | mem | `0x242050: cmpl $0x0,0x18(%r12)` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x186b | ja | reg/arith | `0x242067: cmp $0x4,%rdx` | memory | 0x240b24 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1938 | je | reg/arith | `0x242135: test $0x1,%cl` | call | 0x240b1e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1945 | jne | reg/arith | `0x242143: test %al,%al` | call+memory | 0x240b1e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x19fb | jne | reg/arith | `0x2421f9: test %eax,%eax` | call+memory | 0x2423bf | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1a69 | je | reg/arith | `0x242267: test %al,%al` | call+memory | 0x242384 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1a87 | je | reg/arith | `0x242285: test %al,%al` | call+memory | 0x242384 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1aa5 | je | reg/arith | `0x2422a3: test %al,%al` | call+memory | 0x242384 | fwd |
| ML-KEM decapsulation (provider driver) | +0x7 | je | mem | `0x1c7102: cmpq $0x0,0x50(%r8)` | arithmetic/control | 0x1c72d3 | fwd |
| ML-KEM decapsulation (provider driver) | +0x1f | jne | reg/arith | `0x1c711c: or %r9b,%r10b` | memory | 0x1c72d3 | fwd |
| ML-KEM decapsulation (provider driver) | +0x5c | jne | reg/arith | `0x1c7159: or %al,%sil` | memory | 0x1c72aa | fwd |
| ML-KEM decapsulation (provider driver) | +0x66 | jne | mem | `0x1c7162: cmp 0x28(%r15),%rcx` | memory | 0x1c72aa | fwd |
| ML-KEM decapsulation (provider driver) | +0x8f | je | reg/arith | `0x1c718c: test %rax,%rax` | memory | 0x1c72aa | fwd |
| ML-KEM decapsulation (provider driver) | +0xa2 | je | reg/arith | `0x1c719c: cmp $0x5ae,%ecx` | arithmetic/control | 0x1c73ba | fwd |
| ML-KEM decapsulation (provider driver) | +0xae | je | reg/arith | `0x1c71a8: cmp $0x5af,%ecx` | arithmetic/control | 0x1c72d4 | fwd |
| ML-KEM decapsulation (provider driver) | +0xbc | jne | reg/arith | `0x1c71b6: cmp $0x5b0,%ecx` | call+memory | 0x1c74a5 | fwd |
| ML-KEM decapsulation (provider driver) | +0x163 | jne | reg/arith | `0x1c725c: cmp $0x1000,%r15` | memory | 0x1c7210 | back |
| ML-KEM decapsulation (provider driver) | +0x1a3 | jne | reg/arith | `0x1c729c: cmp $0x627,%rcx` | arithmetic/control | 0x1c7270 | back |
| ML-KEM decapsulation (provider driver) | +0x26b | jne | reg/arith | `0x1c7364: cmp $0xc07,%rcx` | memory | 0x1c7320 | back |
| ML-KEM decapsulation (provider driver) | +0x2b3 | jne | reg/arith | `0x1c73ac: cmp $0x447,%rcx` | arithmetic/control | 0x1c7380 | back |
| ML-KEM decapsulation (provider driver) | +0x363 | jne | reg/arith | `0x1c745c: cmp $0x800,%r15` | memory | 0x1c7410 | back |
| ML-KEM decapsulation (provider driver) | +0x3a3 | jne | reg/arith | `0x1c749c: cmp $0x307,%rcx` | arithmetic/control | 0x1c7470 | back |
| ML-KEM decapsulation (provider driver) | +0x3a8 | jne | reg/arith | `0x1c74a5: test $0x7,%bl` | memory | 0x1c72c2 | back |
| ML-KEM K-PKE decrypt | +0x65 | js | reg/arith | `0x24d272: test %r14,%r14` | memory | 0x24dc3b | fwd |
| ML-KEM K-PKE decrypt | +0x70 | jle | reg/arith | `0x24d27e: test %ebp,%ebp` | arithmetic/control | 0x24d495 | fwd |
| ML-KEM K-PKE decrypt | +0x84 | ja | reg/arith | `0x24d290: cmp $0xf,%r14d` | memory | 0x24dc2e | fwd |
| ML-KEM K-PKE decrypt | +0x9f | jae | reg/arith | `0x24d2a7: cmp $0x20,%eax` | memory | 0x24dc48 | fwd |
| ML-KEM K-PKE decrypt | +0x140 | jae | reg/arith | `0x24d349: cmp $0x100,%rdx` | arithmetic/control | 0x24d3eb | fwd |
| ML-KEM K-PKE decrypt | +0x148 | jne | reg/arith | `0x24d356: test %ecx,%ecx` | memory | 0x24d366 | fwd |
| ML-KEM K-PKE decrypt | +0x169 | je | reg/arith | `0x24d376: test %bl,%r11b` | memory | 0x24d3a0 | fwd |
| ML-KEM K-PKE decrypt | +0x18b | jb | reg/arith | `0x24d394: cmp $0x100,%rdx` | arithmetic/control | 0x24d356 | back |
| ML-KEM K-PKE decrypt | +0x196 | jb | reg/arith | `0x24d3a3: sub %eax,%r10d` | arithmetic/control | 0x24d330 | back |
| ML-KEM K-PKE decrypt | +0x19d | jb | reg/arith | `0x24d3ab: sub %eax,%ecx` | arithmetic/control | 0x24dd33 | fwd |
| ML-KEM K-PKE decrypt | +0x1a6 | ja | reg/arith | `0x24d3b3: cmp $0xf,%ecx` | memory | 0x24dd26 | fwd |
| ML-KEM K-PKE decrypt | +0x1d5 | jb | reg/arith | `0x24d3de: cmp $0x100,%rdx` | memory | 0x24d356 | back |
| ML-KEM K-PKE decrypt | +0x24e | jne | reg/arith | `0x24d458: cmp $0x100,%rax` | call | 0x24d3f0 | back |
| ML-KEM K-PKE decrypt | +0x27f | jg | reg/arith | `0x24d48c: dec %r13d` | memory | 0x24d310 | back |
| ML-KEM K-PKE decrypt | +0x28e | ja | reg/arith | `0x24d49a: cmp $0xf,%r15d` | memory | 0x24dc2e | fwd |
| ML-KEM K-PKE decrypt | +0x2ef | jbe | reg/arith | `0x24d4f8: cmp $0xff,%rsi` | arithmetic/control | 0x24d532 | fwd |
| ML-KEM K-PKE decrypt | +0x320 | ja | reg/arith | `0x24d529: cmp $0xff,%rsi` | arithmetic/control | 0x24d592 | fwd |
| ML-KEM K-PKE decrypt | +0x324 | jne | reg/arith | `0x24d532: test %ecx,%ecx` | memory | 0x24d542 | fwd |
| ML-KEM K-PKE decrypt | +0x345 | jne | reg/arith | `0x24d552: test %bl,%r11b` | arithmetic/control | 0x24d510 | back |
| ML-KEM K-PKE decrypt | +0x34d | jb | reg/arith | `0x24d55a: sub %eax,%r10d` | arithmetic/control | 0x24d4e0 | back |
| ML-KEM K-PKE decrypt | +0x354 | jb | reg/arith | `0x24d562: sub %eax,%ecx` | arithmetic/control | 0x24dd33 | fwd |
| ML-KEM K-PKE decrypt | +0x35d | jae | reg/arith | `0x24d56a: cmp $0x10,%ecx` | memory | 0x24dd26 | fwd |
| ML-KEM K-PKE decrypt | +0x389 | ja | reg/arith | `0x24d596: cmp $0x1f,%eax` | memory | 0x24dd19 | fwd |
| ML-KEM K-PKE decrypt | +0x43e | jne | reg/arith | `0x24d648: cmp $0x100,%rax` | call+memory | 0x24d5e0 | back |
| ML-KEM K-PKE decrypt | +0x4fc | jne | reg/arith | `0x24d706: cmp $0x100,%rax` | memory | 0x24d690 | back |
| ML-KEM K-PKE decrypt | +0x614 | jne | reg/arith | `0x24d81e: cmp $0x100,%rax` | memory | 0x24d750 | back |
| ML-KEM K-PKE decrypt | +0x96b | jne | reg/arith | `0x24db77: cmp $0x20,%rcx` | memory | 0x24d880 | back |
| ML-KEM K-PKE decrypt | +0x9b2 | jne | reg/arith | `0x24dbbc: cmp $0x200,%rax` | memory | 0x24db90 | back |
| ML-KEM K-PKE decrypt | +0xa0a | jne | reg/arith | `0x24dc14: cmp $0x200,%rax` | arithmetic/control | 0x24dbd0 | back |
| ML-KEM K-PKE decrypt | +0xa66 | ja | reg/arith | `0x24dc6f: cmp $0xff,%rdx` | arithmetic/control | 0x24dd19 | fwd |
| ML-KEM K-PKE decrypt | +0xa6e | jne | reg/arith | `0x24dc7c: test %ecx,%ecx` | memory | 0x24dc8c | fwd |
| ML-KEM K-PKE decrypt | +0xa90 | je | reg/arith | `0x24dc9d: test %r11b,%r10b` | memory | 0x24dcd0 | fwd |
| ML-KEM K-PKE decrypt | +0xab5 | jbe | reg/arith | `0x24dcbe: cmp $0xff,%rdx` | arithmetic/control | 0x24dc7c | back |
| ML-KEM K-PKE decrypt | +0xac6 | jb | reg/arith | `0x24dcd3: sub %eax,%r9d` | arithmetic/control | 0x24dc57 | back |
| ML-KEM K-PKE decrypt | +0xad1 | jb | reg/arith | `0x24dcdf: sub %eax,%ecx` | arithmetic/control | 0x24dd33 | fwd |
| ML-KEM K-PKE decrypt | +0xad6 | jae | reg/arith | `0x24dce3: cmp $0x10,%ecx` | memory | 0x24dd26 | fwd |
| ML-KEM K-PKE decrypt | +0xb03 | jbe | reg/arith | `0x24dd0c: cmp $0xff,%rdx` | memory | 0x24dc7c | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xc3 | jle | reg/arith | `0x24ddf0: test %r12,%r12` | call+memory | 0x24de64 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x103 | je | reg/arith | `0x24de41: test %eax,%eax` | call | 0x24fd58 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x120 | jg | reg/arith | `0x24de5d: cmp $0x1,%ebp` | arithmetic/control | 0x24de20 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x237 | jle | reg/arith | `0x24df64: test %r14d,%r14d` | memory | 0x24ecdd | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x47e | jle | reg/arith | `0x24e1af: cmp $0x1,%r12d` | memory | 0x24eacb | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x528 | je | reg/arith | `0x24e25c: test $0x1,%sil` | memory | 0x24e350 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x603 | jne | reg/arith | `0x24e33c: cmp $0x100,%rcx` | arithmetic/control | 0x24e270 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x856 | jne | reg/arith | `0x24e58f: cmp $0x100,%rdx` | memory | 0x24e360 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x867 | je | reg/arith | `0x24e5a4: cmp $0x1,%edx` | memory | 0x24e150 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xa04 | jle | reg/arith | `0x24e73e: cmp $0x2,%edx` | arithmetic/control | 0x24e150 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xa0e | je | reg/arith | `0x24e74c: test $0x1,%al` | memory | 0x24e860 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xb11 | jne | reg/arith | `0x24e84a: cmp $0x100,%rsi` | arithmetic/control | 0x24e760 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xd80 | jne | reg/arith | `0x24eab9: cmp $0x100,%rsi` | arithmetic/control | 0x24e860 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xe57 | je | reg/arith | `0x24eb95: test %eax,%eax` | memory | 0x24ec75 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf2f | jne | reg/arith | `0x24ec68: cmp $0x80,%rcx` | memory | 0x24eba0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf83 | jne | reg/arith | `0x24ecbc: cmp $0x80,%rcx` | arithmetic/control | 0x24ec90 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf87 | je | reg/arith | `0x24ecc5: test %eax,%eax` | arithmetic/control | 0x24fe05 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf97 | jg | reg/arith | `0x24ecd4: dec %r14d` | memory | 0x24eb10 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x10b2 | je | reg/arith | `0x24edf0: test %al,%al` | memory | 0x24ee80 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x112b | jne | reg/arith | `0x24ee64: cmp $0x101,%r8` | arithmetic/control | 0x24ee00 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11d5 | jne | reg/arith | `0x24ef0e: cmp $0x108,%r9` | arithmetic/control | 0x24eea0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11d9 | jo | reg/arith | `0x24ef17: dec %edx` | arithmetic/control | 0x24ffbf | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11ef | jg | reg/arith | `0x24ef2d: test %edx,%edx` | memory | 0x24edf0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1206 | ja | reg/arith | `0x24ef43: cmp $0x1f,%ecx` | memory | 0x25000d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13b9 | jne | reg/arith | `0x24f0f2: cmp $0x100,%rdx` | arithmetic/control | 0x24efb0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13c1 | jo | reg/arith | `0x24f0ff: dec %eax` | arithmetic/control | 0x24ffcc | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13d0 | jg | reg/arith | `0x24f10e: test %eax,%eax` | call | 0x24efa0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x147f | je | reg/arith | `0x24f1bd: test %eax,%eax` | memory | 0x24f2b4 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x156e | jne | reg/arith | `0x24f2a7: cmp $0x80,%rcx` | memory | 0x24f1e0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15c3 | jne | reg/arith | `0x24f2fc: cmp $0x80,%rcx` | arithmetic/control | 0x24f2d0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15c7 | je | reg/arith | `0x24f305: test %eax,%eax` | memory | 0x24feb2 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x165f | jne | reg/arith | `0x24f399: cmp $0x100,%rax` | memory | 0x24f320 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dc8 | jne | reg/arith | `0x24fb04: cmp $0x20,%rax` | arithmetic/control | 0x24f3b0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dd1 | ja | reg/arith | `0x24fb0e: cmp $0x1f,%ebx` | arithmetic/control | 0x25000d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f70 | jne | reg/arith | `0x24fcaa: cmp $0x100,%rax` | memory | 0x24fb60 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fa2 | je | reg/arith | `0x24fcdc: cmp $0x200,%rax` | arithmetic/control | 0x24fd4e | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fa8 | jb | reg/arith | `0x24fce6: add %ebx,%esi` | memory | 0x24ffd9 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fb9 | jb | reg/arith | `0x24fcf6: cmp $0x40,%esi` | arithmetic/control | 0x24fcd0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fbb | jne | unknown | `?` | arithmetic/control | 0x24fd20 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fc0 | jae | reg/arith | `0x24fcfd: cmp $0x40,%ecx` | memory | 0x250000 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fe3 | jae | reg/arith | `0x24fd20: cmp $0x40,%ecx` | memory | 0x24ffe6 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1ff7 | je | reg/arith | `0x24fd35: test %ecx,%ecx` | arithmetic/control | 0x24fff3 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x216c | je | reg/arith | `0x24fea9: test %r14d,%r14d` | memory | 0x24ed81 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x226b | jne | reg/arith | `0x24ffa4: cmp $0x200,%rcx` | arithmetic/control | 0x24ff60 | back |
| ML-KEM inverse NTT | +0x56 | jb | reg/arith | `0x250fa3: add %rsi,%rbx` | memory | 0x251484 | fwd |
| ML-KEM inverse NTT | +0x64 | ja | reg/arith | `0x250fb0: cmp $0x7e,%r8` | memory | 0x251491 | fwd |
| ML-KEM inverse NTT | +0xb8 | jbe | reg/arith | `0x251004: cmp $0x7,%r8` | memory | 0x25105f | fwd |
| ML-KEM inverse NTT | +0x101 | jae | reg/arith | `0x25104e: cmp %r13,%r14` | memory | 0x251070 | fwd |
| ML-KEM inverse NTT | +0x10d | jae | reg/arith | `0x25105a: cmp %r12,%r15` | arithmetic/control | 0x251070 | fwd |
| ML-KEM inverse NTT | +0x2fa | jne | reg/arith | `0x251247: cmp %r13,%r8` | memory | 0x2510a0 | back |
| ML-KEM inverse NTT | +0x317 | ja | reg/arith | `0x251260: cmp $0xff,%r8` | arithmetic/control | 0x25146f | fwd |
| ML-KEM inverse NTT | +0x324 | jae | reg/arith | `0x25126d: cmp $0x100,%rcx` | memory | 0x25145a | fwd |
| ML-KEM inverse NTT | +0x3b4 | jb | reg/arith | `0x251301: cmp %rbx,%r8` | arithmetic/control | 0x251260 | back |
| ML-KEM inverse NTT | +0x3c4 | jne | reg/arith | `0x25130d: cmp $0x100,%rcx` | arithmetic/control | 0x250fa0 | back |
| ML-KEM inverse NTT | +0x3d4 | jb | reg/arith | `0x25131d: cmp $0x100,%rsi` | memory | 0x250f90 | back |
| ML-KEM inverse NTT | +0x4f5 | jne | reg/arith | `0x25143f: cmp $0x100,%rax` | arithmetic/control | 0x251340 | back |
| ML-KEM inner product | +0x5b | jne | reg/arith | `0x2501e8: test %r12b,%r15b` | arithmetic/control | 0x25049b | fwd |
| ML-KEM inner product | +0x64 | jne | reg/arith | `0x2501f1: and %bpl,%r8b` | arithmetic/control | 0x25049b | fwd |
| ML-KEM inner product | +0x6d | jne | reg/arith | `0x2501fa: and %r14b,%r10b` | memory | 0x25049b | fwd |
| ML-KEM inner product | +0x300 | jne | reg/arith | `0x250489: cmp $0x100,%r8` | arithmetic/control | 0x250230 | back |
| ML-KEM inner product | +0x3fa | jne | reg/arith | `0x250583: cmp $0x100,%r14` | arithmetic/control | 0x2504b0 | back |
| ML-KEM inner product | +0x406 | jo | reg/arith | `0x250593: dec %r8d` | arithmetic/control | 0x250a24 | fwd |
| ML-KEM inner product | +0x40f | jle | reg/arith | `0x25059c: test %r8d,%r8d` | memory | 0x250a15 | fwd |
| ML-KEM inner product | +0x4c1 | jle | reg/arith | `0x25064e: dec %r8d` | arithmetic/control | 0x250a15 | fwd |
| ML-KEM inner product | +0x4cc | je | reg/arith | `0x25065a: test %cl,%cl` | memory | 0x250780 | fwd |
| ML-KEM inner product | +0x5dc | jne | reg/arith | `0x250765: cmp $0x100,%r10` | arithmetic/control | 0x250670 | back |
| ML-KEM inner product | +0x87a | jne | reg/arith | `0x250a03: cmp $0x100,%r10` | arithmetic/control | 0x250780 | back |
| ML-KEM matrix transpose-multiply-add | +0x1b | jle | reg/arith | `0x2514c9: test %ecx,%ecx` | memory | 0x251e2c | fwd |
| ML-KEM matrix transpose-multiply-add | +0x16f | jle | reg/arith | `0x251611: cmp $0x1,%eax` | memory | 0x251e2c | fwd |
| ML-KEM matrix transpose-multiply-add | +0x17f | je | mem | `0x25162a: cmpb $0x0,-0x62(%rsp)` | memory | 0x251730 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x26e | jne | reg/arith | `0x251717: cmp $0x100,%r11` | arithmetic/control | 0x251640 | back |
| ML-KEM matrix transpose-multiply-add | +0x510 | jne | reg/arith | `0x2519ba: cmp $0x100,%rax` | memory | 0x251740 | back |
| ML-KEM matrix transpose-multiply-add | +0x51b | je | mem | `0x2519c6: cmpl $0x1,-0x60(%rsp)` | memory | 0x2515f0 | back |
| ML-KEM matrix transpose-multiply-add | +0x5c7 | jle | reg/arith | `0x251a6c: cmp $0x2,%r9d` | memory | 0x2515f0 | back |
| ML-KEM matrix transpose-multiply-add | +0x5d2 | je | mem | `0x251a7d: cmpb $0x0,-0x61(%rsp)` | memory | 0x251b90 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x6d1 | jne | reg/arith | `0x251b7a: cmp $0x100,%rbp` | arithmetic/control | 0x251a90 | back |
| ML-KEM matrix transpose-multiply-add | +0x971 | jne | reg/arith | `0x251e1a: cmp $0x100,%rbp` | arithmetic/control | 0x251ba0 | back |
| ML-KEM matrix expansion (public) | +0x3f | jle | reg/arith | `0x250a7d: test %ecx,%ecx` | memory | 0x250c41 | fwd |
| ML-KEM matrix expansion (public) | +0x6c | je | mem | `0x250aa7: cmp 0x4(%rsp),%r14d` | call+memory | 0x250c32 | fwd |
| ML-KEM matrix expansion (public) | +0x92 | je | reg/arith | `0x250ad0: test %eax,%eax` | memory | 0x250c67 | fwd |
| ML-KEM matrix expansion (public) | +0xad | je | reg/arith | `0x250aeb: test %eax,%eax` | memory | 0x250c67 | fwd |
| ML-KEM matrix expansion (public) | +0x116 | je | reg/arith | `0x250b53: test %rax,%rax` | memory | 0x250c49 | fwd |
| ML-KEM matrix expansion (public) | +0x121 | je | mem | `0x250b5c: cmpq $0x0,0x70(%rax)` | memory | 0x250c52 | fwd |
| ML-KEM matrix expansion (public) | +0x131 | je | reg/arith | `0x250b6e: test %rax,%rax` | memory | 0x250c5b | fwd |
| ML-KEM matrix expansion (public) | +0x13e | je | reg/arith | `0x250b7b: test %rdi,%rdi` | call+memory | 0x250c67 | fwd |
| ML-KEM matrix expansion (public) | +0x160 | je | reg/arith | `0x250b9e: test %eax,%eax` | arithmetic/control | 0x250c67 | fwd |
| ML-KEM matrix expansion (public) | +0x17a | je | reg/arith | `0x250bb4: cmp $0xaa,%rax` | arithmetic/control | 0x250c20 | fwd |
| ML-KEM matrix expansion (public) | +0x183 | ja | reg/arith | `0x250bbc: cmp $0xff,%r13` | memory | 0x250aa0 | back |
| ML-KEM matrix expansion (public) | +0x1a9 | ja | reg/arith | `0x250be3: cmp $0xd00,%esi` | memory | 0x250c00 | fwd |
| ML-KEM matrix expansion (public) | +0x1b7 | je | reg/arith | `0x250bf0: cmp $0xff,%r13` | arithmetic/control | 0x250aa0 | back |
| ML-KEM matrix expansion (public) | +0x1d4 | ja | reg/arith | `0x250c0e: cmp $0xd00,%ecx` | memory | 0x250bb0 | back |
| ML-KEM matrix expansion (public) | +0x1e7 | jb | reg/arith | `0x250c20: cmp $0x100,%r13` | arithmetic/control | 0x250b4f | back |
| ML-KEM matrix expansion (public) | +0x1fb | jne | mem | `0x250c37: cmp 0x4(%rsp),%ebp` | arithmetic/control | 0x250a8a | back |
| ML-KEM vector decode 12-bit | +0x2 | jle | reg/arith | `0x250d80: test %edx,%edx` | memory | 0x250e02 | fwd |
| ML-KEM vector decode 12-bit | +0x17 | je | reg/arith | `0x250d90: cmp $0x80,%rcx` | memory | 0x250df0 | fwd |
| ML-KEM vector decode 12-bit | +0x54 | ja | reg/arith | `0x250dcd: cmp $0xd00,%r11d` | arithmetic/control | 0x250e07 | fwd |
| ML-KEM vector decode 12-bit | +0x68 | jb | reg/arith | `0x250de1: cmp $0xd01,%r9d` | arithmetic/control | 0x250d90 | back |
| ML-KEM vector decode 12-bit | +0x80 | jg | reg/arith | `0x250dfe: dec %edx` | arithmetic/control | 0x250d84 | back |
| ML-KEM vector encode | +0x7 | js | reg/arith | `0x250c95: test %edx,%edx` | arithmetic/control | 0x250d70 | fwd |
| ML-KEM vector encode | +0x11 | jle | reg/arith | `0x250c9f: test %ecx,%ecx` | arithmetic/control | 0x250d36 | fwd |
| ML-KEM vector encode | +0x2c | jle | reg/arith | `0x250cba: dec %eax` | arithmetic/control | 0x250d36 | fwd |
| ML-KEM vector encode | +0x53 | je | reg/arith | `0x250cdc: cmp $0x200,%r10` | arithmetic/control | 0x250cb0 | back |
| ML-KEM vector encode | +0x59 | jb | reg/arith | `0x250ce7: add %edx,%ebx` | memory | 0x250d3c | fwd |
| ML-KEM vector encode | +0x63 | jb | reg/arith | `0x250cf0: cmp $0x40,%ebx` | arithmetic/control | 0x250cd0 | back |
| ML-KEM vector encode | +0x65 | jne | unknown | `?` | arithmetic/control | 0x250d10 | fwd |
| ML-KEM vector encode | +0x6a | jae | reg/arith | `0x250cf7: cmp $0x40,%ecx` | memory | 0x250d63 | fwd |
| ML-KEM vector encode | +0x83 | jae | reg/arith | `0x250d10: cmp $0x40,%ecx` | memory | 0x250d49 | fwd |
| ML-KEM vector encode | +0x93 | je | reg/arith | `0x250d21: test %ecx,%ecx` | arithmetic/control | 0x250d56 | fwd |
| ML-KEM CBD sampling eta=2 | +0x5a | je | reg/arith | `0x251fd8: test %eax,%eax` | memory | 0x2520d7 | fwd |
| ML-KEM CBD sampling eta=2 | +0x14a | jne | reg/arith | `0x2520c4: cmp $0x80,%rax` | arithmetic/control | 0x252000 | back |
| ML-KEM CBD sampling eta=2 | +0x192 | jne | reg/arith | `0x25210b: cmp $0x80,%rcx` | arithmetic/control | 0x2520e0 | back |
| ML-KEM CBD sampling eta=3 | +0x7e | je | reg/arith | `0x25219c: test %eax,%eax` | memory | 0x2524d7 | fwd |
| ML-KEM CBD sampling eta=3 | +0x3aa | jne | reg/arith | `0x2524c6: cmp $0x40,%rcx` | arithmetic/control | 0x2521c0 | back |
| ML-KEM CBD sampling eta=3 | +0x3f2 | jne | reg/arith | `0x25250b: cmp $0xc7,%rcx` | arithmetic/control | 0x2524e0 | back |
| ML-KEM CBD vector sampling then NTT | +0x21 | jle | reg/arith | `0x250e2e: test %r8d,%r8d` | memory | 0x250e90 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x60 | je | reg/arith | `0x250e6e: test %eax,%eax` | call | 0x250e87 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x73 | jg | reg/arith | `0x250e81: dec %ebx` | arithmetic/control | 0x250e50 | back |
| ML-KEM hash H | +0x2e | je | reg/arith | `0x25260c: test %eax,%eax` | memory | 0x25267d | fwd |
| ML-KEM hash H | +0x49 | je | reg/arith | `0x252627: test %eax,%eax` | arithmetic/control | 0x252664 | fwd |
| ML-KEM hash H | +0x4e | je | reg/arith | `0x25262b: test %rbx,%rbx` | memory | 0x25263e | fwd |
| ML-KEM hash H | +0x56 | je | reg/arith | `0x252633: test %rax,%rax` | memory | 0x25263e | fwd |
| ML-KEM hash H | +0x5c | jne | mem | `0x252638: testb $0x2,0x10(%rax)` | memory | 0x252669 | fwd |
| ML-KEM hash G | +0x2e | je | reg/arith | `0x25254c: test %eax,%eax` | memory | 0x2525bd | fwd |
| ML-KEM hash G | +0x49 | je | reg/arith | `0x252567: test %eax,%eax` | arithmetic/control | 0x2525a4 | fwd |
| ML-KEM hash G | +0x4e | je | reg/arith | `0x25256b: test %rbx,%rbx` | memory | 0x25257e | fwd |
| ML-KEM hash G | +0x56 | je | reg/arith | `0x252573: test %rax,%rax` | memory | 0x25257e | fwd |
| ML-KEM hash G | +0x5c | jne | mem | `0x252578: testb $0x2,0x10(%rax)` | memory | 0x2525a9 | fwd |
| ML-KEM public-key hash | +0x59 | je | reg/arith | `0x250077: test %eax,%eax` | memory | 0x25016b | fwd |
| ML-KEM public-key hash | +0x96 | je | reg/arith | `0x2500af: cmp $0x200,%rsi` | memory | 0x250100 | fwd |
| ML-KEM public-key hash | +0xa5 | jbe | reg/arith | `0x2500c2: cmp $0x33,%eax` | memory | 0x2500a0 | back |
| ML-KEM public-key hash | +0xb9 | je | reg/arith | `0x2500d5: cmp $0x40,%r8d` | arithmetic/control | 0x2500f1 | fwd |
| ML-KEM public-key hash | +0xf6 | je | reg/arith | `0x250114: test %eax,%eax` | memory | 0x25016b | fwd |
| ML-KEM public-key hash | +0x109 | jb | reg/arith | `0x250126: cmp %rax,%rbp` | memory | 0x250090 | back |
| ML-KEM public-key hash | +0x123 | je | reg/arith | `0x250141: test %eax,%eax` | memory | 0x25016b | fwd |
| ML-KEM KDF | +0x2a | je | reg/arith | `0x251e68: test %eax,%eax` | memory | 0x251eae | fwd |
| ML-KEM KDF | +0x3f | je | reg/arith | `0x251e7d: test %eax,%eax` | memory | 0x251eae | fwd |
| ML-KEM KDF | +0x52 | je | reg/arith | `0x251e90: test %eax,%eax` | memory | 0x251eae | fwd |
| ML-KEM PRF | +0x2d | je | reg/arith | `0x251eeb: test %eax,%eax` | memory | 0x251f5a | fwd |
| ML-KEM PRF | +0x46 | je | reg/arith | `0x251f04: test %eax,%eax` | arithmetic/control | 0x251f43 | fwd |
| ML-KEM PRF | +0x4b | je | reg/arith | `0x251f08: test %r14,%r14` | memory | 0x251f1b | fwd |
| ML-KEM PRF | +0x53 | je | reg/arith | `0x251f10: test %rax,%rax` | memory | 0x251f1b | fwd |
| ML-KEM PRF | +0x59 | jne | mem | `0x251f15: testb $0x2,0x10(%rax)` | memory | 0x251f48 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xa0 | je | reg/arith | `0x1c9d6e: test %eax,%eax` | memory | 0x1c9e7f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xb9 | je | reg/arith | `0x1c9d87: test %eax,%eax` | memory | 0x1c9e7f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xd0 | je | reg/arith | `0x1c9d9e: test %eax,%eax` | memory | 0x1c9e7f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xeb | je | reg/arith | `0x1c9db9: test %eax,%eax` | call+memory | 0x1c9e7f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x155 | je | reg/arith | `0x1c9e1b: test %eax,%eax` | call+memory | 0x1c9f5c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x178 | je | reg/arith | `0x1c9e46: test %eax,%eax` | memory | 0x1c9f5c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x185 | je | reg/arith | `0x1c9e52: test %rax,%rax` | arithmetic/control | 0x1c9f7e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x18e | je | reg/arith | `0x1c9e5b: test %r14,%r14` | memory | 0x1c9f8d | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x1a0 | jae | reg/arith | `0x1c9e64: cmp $0x4,%rax` | arithmetic/control | 0x1c9f9f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x2d3 | jae | reg/arith | `0x1c9f9f: cmp $0x20,%rax` | arithmetic/control | 0x1c9fab | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x31b | jne | reg/arith | `0x1c9fe8: cmp %rdx,%rcx` | arithmetic/control | 0x1c9fbc | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x354 | je | reg/arith | `0x1ca021: cmp %rcx,%rax` | arithmetic/control | 0x1ca091 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x358 | je | reg/arith | `0x1ca026: test $0x1c,%al` | memory | 0x1ca07e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x386 | jne | reg/arith | `0x1ca053: cmp %rsi,%rcx` | arithmetic/control | 0x1ca040 | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x3bf | jne | reg/arith | `0x1ca08c: cmp %rcx,%rax` | memory | 0x1ca07e | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x427 | jne | reg/arith | `0x1ca0f3: cmp $0x20,%rcx` | memory | 0x1ca0c0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x58 | ja | reg/arith | `0x24ce50: cmp $0x7e,%rax` | memory | 0x24d1f1 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xb0 | jbe | reg/arith | `0x24ceac: cmp $0x7,%r8` | memory | 0x24cf07 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xf9 | jae | reg/arith | `0x24cef6: cmp %r13,%r14` | memory | 0x24cf10 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x105 | jae | reg/arith | `0x24cf02: cmp %r12,%r15` | arithmetic/control | 0x24cf10 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2c0 | jne | reg/arith | `0x24d0bd: cmp %r13,%r8` | memory | 0x24cf50 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2d7 | ja | reg/arith | `0x24d0d0: cmp $0xff,%r8` | arithmetic/control | 0x24d1dc | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2e4 | jae | reg/arith | `0x24d0dd: cmp $0x100,%rcx` | memory | 0x24d1c7 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x392 | jb | reg/arith | `0x24d18f: cmp %rbx,%r8` | arithmetic/control | 0x24d0d0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x39f | jne | reg/arith | `0x24d198: cmp $0x100,%rcx` | arithmetic/control | 0x24ce50 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x3b2 | ja | reg/arith | `0x24d1ab: cmp $0x3,%rsi` | arithmetic/control | 0x24ce40 | back |
