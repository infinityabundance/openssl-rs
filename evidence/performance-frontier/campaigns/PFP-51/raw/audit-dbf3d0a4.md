# Binary branch audit — review aid, not a proof

- DSO: `court/tmp/pfp51/B/libcrypto.so.3`
- SHA-256: `dbf3d0a427ad9a63eb9b724f1434e2b48a3a005242e60e450cf49db922653e3a`
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
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | **missing** (`arith::mont_mul_sos_into`) | | | | | | | | | | |
| Montgomery ladder carrier (ladder multiplies inlined here) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith15run_mont_ladder` @ 0x3b7550 | 5470 | 1144 | 97 | 2 | 3 | 18 | 5 | 0 | 66 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x164590 | 1815 | 432 | 31 | 0 | 0 | 10 | 0 | 0 | 16 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x3bc390 (carries `mod_exp_core_consttime_from_parts`) | 1011 | 271 | 27 | 0 | 2 | 0 | 0 | 0 | 11 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x226b40 | 11101 | 2380 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x1d4f50 | 3158 | 780 | 125 | 0 | 5 | 7 | 1 | 0 | 78 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x259680 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x260d70 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x256460 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x256250 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| DH key agreement (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2dh3key19ossl_dh_compute_key` @ 0x254390 | 1281 | 294 | 36 | 0 | 1 | 0 | 1 | 0 | 32 | 0 |
| EC wNAF multiply (verification / public-scalar core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` @ 0x1d3320 | 6339 | 1399 | 156 | 4 | 34 | 3 | 2 | 0 | 105 | 0 |
| ML-KEM decapsulation (provider driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` @ 0x4a69c0 | 998 | 210 | 15 | 0 | 1 | 4 | 0 | 0 | 13 | 0 |
| ML-KEM K-PKE decrypt | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11decrypt_cpa` @ 0x196ef0 | 2864 | 683 | 37 | 0 | 0 | 6 | 0 | 0 | 10 | 0 |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11encrypt_cpa` @ 0x197a20 | 8042 | 1696 | 40 | 0 | 6 | 48 | 2 | 0 | 16 | 0 |
| ML-KEM inverse NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith18scalar_inverse_ntt` @ 0x19a8c0 | 1366 | 295 | 12 | 0 | 13 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM inner product | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13inner_product` @ 0x199b00 | 2209 | 455 | 11 | 0 | 2 | 12 | 1 | 0 | 1 | 0 |
| ML-KEM matrix transpose-multiply-add | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith25matrix_mult_transpose_add` @ 0x19ae20 | 2439 | 513 | 10 | 0 | 3 | 12 | 0 | 0 | 0 | 0 |
| ML-KEM matrix expansion (public) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13matrix_expand` @ 0x19a3b0 | 584 | 134 | 16 | 0 | 0 | 0 | 0 | 0 | 6 | 0 |
| ML-KEM vector decode 12-bit | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith16vector_decode_12` @ 0x19a6f0 | 136 | 35 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-KEM vector encode | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13vector_encode` @ 0x19a600 | 237 | 71 | 10 | 0 | 0 | 0 | 0 | 0 | 5 | 0 |
| ML-KEM CBD sampling eta=2 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_2` @ 0x19b8f0 | 477 | 108 | 4 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD sampling eta=3 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_3` @ 0x19bad0 | 1102 | 255 | 4 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD vector sampling then NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` @ 0x19a780 | 312 | 83 | 3 | 0 | 0 | 1 | 0 | 0 | 2 | 0 |
| ML-KEM hash H | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_h` @ 0x19bfe0 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM hash G | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_g` @ 0x19bf20 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM public-key hash | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13hash_h_pubkey` @ 0x199990 | 358 | 104 | 7 | 0 | 0 | 2 | 0 | 0 | 6 | 0 |
| ML-KEM KDF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3kdf` @ 0x19b7b0 | 128 | 46 | 3 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM PRF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3prf` @ 0x19b830 | 177 | 60 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802` @ 0x4a9480 | 1554 | 341 | 16 | 0 | 1 | 1 | 0 | 0 | 9 | 0 |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith10scalar_ntt.llvm.1911735635625062108` @ 0x196ae0 | 1030 | 235 | 10 | 0 | 14 | 0 | 0 | 0 | 3 | 0 |

## Coverage

- expected targets: 31
- resolved uniquely and disassembled: 30
- of those, audited through a verified inline mapping: 1
  - Constant-time ladder core: intended `mod_exp_core_consttime_from_parts` -> carrier `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared`
- failed: 1
  - Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) (`arith::mont_mul_sos_into`): missing

## Inline mappings declared by the inventory

A mapping is admitted only when the audit re-establishes the name derivation (`resolves_to` is `symbol` + `suffix`), the carrier's extent, a direct call from the declared caller, the wrapper's constant argument at that site, and the producer string in this DSO. It does not prove the wrapper was inlined rather than source-edited away; those are the same instructions (see the module docstring).

| target | carrier | state | caller | call site | constant | carrier extent | producer |
|---|---|---|---|---|---|---:|---|
| `mod_exp_core_consttime_from_parts` | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` | **verified, audited** | `BN_mod_exp` | +0x181 | `push $0x0` | 1011 B | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **Constant-time ladder core** recorded check: mod_exp_core_consttime_from_parts(ad, pd, md, n) is the one-line forwarder to mod_exp_core_consttime_from_parts_prepared(ad, pd, md, n, None); in the release DSO its only non-test caller BN_mod_exp calls the prepared entry directly with the None tag, so no out-of-line body of the wrapper is emitted

## LLVM-suffixed local copies declared by the inventory

The exact-identifier rule is unchanged. A suffixed copy is admitted only when the whole symbol matches the v0 structural form with exact length prefixes, no alias shares its start address, the producer string is in this DSO, and a declared caller has a direct call to the copy. The call site is the witness that the reviewed path reaches this body; it does not prove source identity beyond those facts (see the module docstring).

| target | observed suffix | extent | caller | direct call sites | producer |
|---|---|---:|---|---|---|
| `key::decap` | `3key5decap.llvm.14688115778985508802` | 1554 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` | +0x108, +0x216, +0x300 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |
| `arith::scalar_ntt` | `5arith10scalar_ntt.llvm.1911735635625062108` | 1030 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` | +0x65 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **ML-KEM decapsulation carrier (implicit-rejection comparison + select)** recorded check: src/ml_kem/key.rs::decap is the only body of the identifier. The release DSO has no unsuffixed symbol for it; the only defined .text symbol of that identifier is the .llvm.<digits> local copy, and ossl_ml_kem_decap calls that entry directly at three sites. The copy contains the inlined CRYPTO_memcmp accumulation, the constant_time_eq_int_8 mask and the constant_time_select_8 store loop of src/ml_kem/key.rs:633-639.

- **ML-KEM forward NTT (used by re-encryption on secret-derived data)** recorded check: src/ml_kem/arith.rs::scalar_ntt has no unsuffixed out-of-line body in the release DSO; its only defined .text symbol of that identifier is the .llvm.<digits> local copy. gencbd_vector_ntt calls that entry directly, and the same single entry is the target of two further direct calls in the file (recorded in MLKEM-REJECTION.md). The loop bounds are fixed by the degree; the value-dependent reductions compile to cmovcc, which the per-function counts report.

## Comparison-result branch contract

Register taint is seeded on the XOR/OR comparison accumulation and propagated over the basic-block CFG. `public-bound` means no tracked comparison register reaches the condition, not that the branch is harmless. Memory and implicit flow are not modelled.

### ML-KEM decapsulation carrier (implicit-rejection comparison + select)

- accumulated registers: `xmm0`, `xmm1`
- accumulation loop 0x4a976c..0x4a979b: `xmm0`, `xmm1`

| kind | addr | instruction | condition source | class |
|---|---|---|---|---|
| jcc | `0x4a9520` | `je 4a962f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x1af>` | `0x4a951e: test %eax,%eax` | **public-bound** |
| jcc | `0x4a9539` | `je 4a962f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x1af>` | `0x4a9537: test %eax,%eax` | **public-bound** |
| jcc | `0x4a9550` | `je 4a962f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x1af>` | `0x4a954e: test %eax,%eax` | **public-bound** |
| jcc | `0x4a956b` | `je 4a962f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x1af>` | `0x4a9569: test %eax,%eax` | **public-bound** |
| jcc | `0x4a95d5` | `je 4a970c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x28c>` | `0x4a95cb: test %eax,%eax` | **public-bound** |
| jcc | `0x4a95f8` | `je 4a970c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x28c>` | `0x4a95f6: test %eax,%eax` | **public-bound** |
| jcc | `0x4a9605` | `je 4a972e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x2ae>` | `0x4a9602: test %rax,%rax` | **public-bound** |
| jcc | `0x4a960e` | `je 4a973d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x2bd>` | `0x4a960b: test %r14,%r14` | **public-bound** |
| jcc | `0x4a9620` | `jae 4a974f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x2cf>` | `0x4a9614: cmp $0x4,%rax` | **public-bound** |
| jcc | `0x4a9753` | `jae 4a975b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x2db>` | `0x4a974f: cmp $0x20,%rax` | **public-bound** |
| jcc | `0x4a979b` | `jne 4a976c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x2ec>` | `0x4a9798: cmp %rdx,%rcx` | **public-bound** |
| jcc | `0x4a97d4` | `je 4a9841 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x3c1>` | `0x4a97d1: cmp %rcx,%rax` | **public-bound** |
| jcc | `0x4a97d8` | `je 4a982e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x3ae>` | `0x4a97d6: test $0x1c,%al` | **public-bound** |
| jcc | `0x4a9806` | `jne 4a97f0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x370>` | `0x4a9803: cmp %rsi,%rcx` | **public-bound** |
| jcc | `0x4a983f` | `jne 4a982e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x3ae>` | `0x4a983c: cmp %rcx,%rax` | **public-bound** |
| setcc | `0x4a9845` | `setne %al` | `0x4a9843: test %dl,%dl` | **secret-derived** |
| cmov | `0x4a9866` | `cmovne %rcx,%rdx` | `0x4a9859: cmpl $0x0,0xa0(%rsp)` | **public-bound** |
| jcc | `0x4a98a7` | `jne 4a9870 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14688115778985508802+0x3f0>` | `0x4a98a3: cmp $0x20,%rcx` | **public-bound** |

- secret-derived conditional jumps: 0
- undetermined conditions: 0

## Divisions

- **Montgomery ladder carrier (ladder multiplies inlined here)** `+0xd7a` (0x3b82ca): `divq 0x98(%rsp)`
- **Montgomery ladder carrier (ladder multiplies inlined here)** `+0xd88` (0x3b82d8): `divl 0x98(%rsp)`
- **EC wNAF multiply (verification / public-scalar core)** `+0x6c4` (0x1d39e4): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0xa73` (0x1d3d93): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0xa82` (0x1d3da2): `div %esi`
- **EC wNAF multiply (verification / public-scalar core)** `+0x129f` (0x1d45bf): `div %esi`

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16bce8, 0x16bd09, 0x16bd2a, 0x16bd41, 0x16bd93, 0x16bdaa, 0x16bf35, 0x16c043, 0x16c0e9, 0x16c2a8, 0x1ad3fc, 0x1ad42c, 0x1fb82c, 0x1fd7fc, 0x25690b, 0x2e6484, 0x2e64f2, 0x2e6560, 0x2e65ce, 0x31390c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2b | jne | reg/arith | `0x3b7577: shr $0x3a,%rax` | memory | 0x3b7836 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7f | jbe | reg/arith | `0x3b75cc: cmp %rbx,%rdx` | call+memory | 0x3b76bb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa6 | je | reg/arith | `0x3b75f2: cmp $0xffffffffffffffff,%r15` | memory | 0x3b7836 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc6 | jne | reg/arith | `0x3b760b: test %rbx,%rbx` | memory | 0x3b7994 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x108 | jne | reg/arith | `0x3b7651: or %al,%cl` | memory | 0x3b7699 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x147 | jne | reg/arith | `0x3b7694: cmp %rax,%rsi` | arithmetic/control | 0x3b7660 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x14c | je | reg/arith | `0x3b7699: test %r15,%r15` | memory | 0x3b76ac | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x17c | jne | reg/arith | `0x3b76c9: test %rbx,%rbx` | memory | 0x3b77fb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1bc | jne | reg/arith | `0x3b7708: cmp $0xffffffffffffffff,%r12` | memory | 0x3b777e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1c9 | je | reg/arith | `0x3b7716: test %rbx,%rbx` | memory | 0x3b783e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x216 | jne | reg/arith | `0x3b7763: cmp %rax,%rbx` | memory | 0x3b7730 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x24b | jne | reg/arith | `0x3b7798: test %rbx,%rbx` | call+memory | 0x3b78df | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x273 | je | mem | `0x3b77be: cmpb $0x0,0x48(%rsp)` | memory | 0x3b8177 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x28d | je | reg/arith | `0x3b77da: test %rbx,%rbx` | memory | 0x3b791b | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e0 | je | mem | `0x3b782b: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7a4e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x312 | jne | reg/arith | `0x3b7860: or %cl,%dl` | memory | 0x3b78a4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x34e | jne | reg/arith | `0x3b789b: cmp %rdx,%rax` | memory | 0x3b7870 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x357 | je | reg/arith | `0x3b78a4: test %rsi,%rsi` | memory | 0x3b78cd | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x3b9 | je | mem | `0x3b7904: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7ad3 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x3eb | jne | reg/arith | `0x3b7939: or %al,%cl` | memory | 0x3b7978 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x426 | jne | reg/arith | `0x3b7973: cmp %rax,%rsi` | arithmetic/control | 0x3b7940 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x42b | je | reg/arith | `0x3b7978: test %r12,%r12` | memory | 0x3b7716 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x46e | je | mem | `0x3b79b9: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7a93 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4a5 | jne | reg/arith | `0x3b79ee: or %al,%cl` | memory | 0x3b7a32 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4e0 | jne | reg/arith | `0x3b7a2d: cmp %rax,%rsi` | arithmetic/control | 0x3b79f9 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4e5 | je | reg/arith | `0x3b7a32: test %r15,%r15` | memory | 0x3b783e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x50a | je | reg/arith | `0x3b7a56: cmp $0x1,%rbx` | memory | 0x3b7a77 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x54f | je | reg/arith | `0x3b7a9b: cmp $0x1,%rbx` | memory | 0x3b7abc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x596 | je | reg/arith | `0x3b7ae2: cmp $0x1,%rbx` | memory | 0x3b7b0a | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x5e6 | je | mem | `0x3b7b31: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7b4e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x621 | je | reg/arith | `0x3b7b6d: cmp $0x1,%rbx` | memory | 0x3b7b96 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x677 | je | mem | `0x3b7bc2: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7c2e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6c2 | jne | reg/arith | `0x3b7c0f: cmp %rax,%rsi` | memory | 0x3b7be4 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x72e | je | mem | `0x3b7c79: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7d87 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x797 | jne | reg/arith | `0x3b7ce4: cmp %rax,%rcx` | memory | 0x3b7cb0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7cf | jne | reg/arith | `0x3b7d1d: or %al,%cl` | memory | 0x3b7d58 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x806 | jne | reg/arith | `0x3b7d53: cmp %rax,%rsi` | arithmetic/control | 0x3b7d28 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x80b | je | reg/arith | `0x3b7d58: test %rbp,%rbp` | memory | 0x3b7d6d | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x82c | jne | mem | `0x3b7d6d: cmpb $0x0,0x78(%rsp)` | arithmetic/control | 0x3b77da | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x845 | je | reg/arith | `0x3b7d91: cmp $0x1,%rbx` | memory | 0x3b7dba | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x896 | je | mem | `0x3b7de1: cmpb $0x0,0x48(%rsp)` | memory | 0x3b7e12 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8d3 | je | reg/arith | `0x3b7e1f: cmp $0x1,%rbx` | memory | 0x3b7e4b | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x916 | ja | mem | `0x3b7e61: cmpl $0x3f,0x40(%rsp)` | memory | 0x3b80a6 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x93c | je | reg/arith | `0x3b7e8a: test %esi,%esi` | memory | 0x3b80a6 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x94d | jo | reg/arith | `0x3b7e9a: mul %rbx` | call+memory | 0x3b80a6 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x97a | je | reg/arith | `0x3b7ec6: cmp $0xffffffffffffffff,%rax` | call+memory | 0x3b80a6 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9be | je | reg/arith | `0x3b7f0a: cmp $0xffffffffffffffff,%rax` | memory | 0x3b81bb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9d6 | ja | mem | `0x3b7f1e: cmp 0x80(%rsp),%rbx` | memory | 0x3b8884 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9f0 | ja | reg/arith | `0x3b7f3d: cmp %rax,%rbx` | memory | 0x3b889d | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa3b | ja | mem | `0x3b7f83: cmp 0x80(%rsp),%rbp` | memory | 0x3b88c6 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa46 | jne | mem | `0x3b7f91: cmp 0x38(%rsp),%rbx` | memory | 0x3b88e0 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xab4 | jb | reg/arith | `0x3b8000: sub $0x1,%rbp` | memory | 0x3b81c3 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xac2 | jo | reg/arith | `0x3b800f: mul %rbx` | memory | 0x3b8930 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xad6 | jb | reg/arith | `0x3b8023: sub %rax,%rcx` | memory | 0x3b86d4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xae7 | jo | reg/arith | `0x3b8034: mul %rbx` | arithmetic/control | 0x3b8921 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xaf3 | jb | reg/arith | `0x3b8040: sub %rax,%rsi` | arithmetic/control | 0x3b8701 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xafc | ja | reg/arith | `0x3b8049: cmp %rcx,%rbx` | memory | 0x3b870b | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xb48 | jne | reg/arith | `0x3b8096: test %al,%al` | arithmetic/control | 0x3b8000 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xba9 | jae | reg/arith | `0x3b80f5: cmp $0x7,%rcx` | arithmetic/control | 0x3b80ff | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xbf0 | jne | reg/arith | `0x3b813d: cmp %rcx,%rdx` | arithmetic/control | 0x3b8112 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xbf5 | je | reg/arith | `0x3b8142: test %rax,%rax` | memory | 0x3b815a | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc08 | jne | reg/arith | `0x3b8155: cmp %rdx,%rax` | memory | 0x3b814e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc8d | jb | reg/arith | `0x3b81da: cmp %rax,%rbp` | memory | 0x3b809e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc9b | jne | mem | `0x3b81e3: cmp %rbx,0xb0(%rsp)` | memory | 0x3b88f1 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xcc4 | jae | mem | `0x3b820c: cmp 0x98(%rsp),%rbp` | memory | 0x3b82bc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xd20 | je | reg/arith | `0x3b826e: test %al,%al` | call+memory | 0x3b8766 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xd73 | je | reg/arith | `0x3b82bf: shr $0x20,%rax` | division | 0x3b82d4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xe73 | jo | mem | `0x3b83bb: mulq 0x98(%rsp)` | memory | 0x3b8766 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xea1 | je | mem | `0x3b83e9: cmp %rcx,0x98(%rsp)` | arithmetic/control | 0x3b8435 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xea9 | jb | reg/arith | `0x3b83f6: add %rax,%rsi` | memory | 0x3b8766 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xeb7 | jae | mem | `0x3b83ff: cmp 0xf8(%rsp),%rsi` | memory | 0x3b83d9 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xec8 | jae | mem | `0x3b8410: cmp 0xf0(%rsp),%rdi` | memory | 0x3b894f | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xf66 | je | reg/arith | `0x3b84b4: test %al,%al` | memory | 0x3b8766 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xf97 | jne | mem | `0x3b84df: decq 0xd8(%rsp)` | memory | 0x3b845e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xfa6 | je | mem | `0x3b84ed: cmpq $0x0,0xe8(%rsp)` | memory | 0x3b850d | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xfe7 | je | mem | `0x3b852f: cmp 0xe0(%rsp),%rcx` | arithmetic/control | 0x3b8650 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xff3 | jo | reg/arith | `0x3b8540: mul %rbx` | arithmetic/control | 0x3b8975 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xfff | jb | reg/arith | `0x3b854c: add %rbx,%rsi` | memory | 0x3b8984 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x100d | ja | mem | `0x3b8555: cmp 0x80(%rsp),%rsi` | memory | 0x3b8867 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1019 | je | mem | `0x3b8563: cmpq $0x0,0x38(%rsp)` | memory | 0x3b851e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1023 | jne | mem | `0x3b856b: cmp %rcx,0x90(%rsp)` | memory | 0x3b851e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1034 | je | reg/arith | `0x3b8582: test $0x1,%al` | arithmetic/control | 0x3b858a | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1070 | jne | mem | `0x3b85b8: cmp %rax,0xb0(%rsp)` | memory | 0x3b858c | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1082 | je | mem | `0x3b85cd: cmp %rax,0x38(%rsp)` | memory | 0x3b851e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1094 | je | mem | `0x3b85db: cmpq $0x0,0x100(%rsp)` | memory | 0x3b8606 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10b4 | jne | reg/arith | `0x3b8601: dec %rsi` | memory | 0x3b85f1 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10bf | ja | reg/arith | `0x3b860b: cmp $0xfffffffffffffffc,%rdx` | memory | 0x3b851e | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10f9 | jne | mem | `0x3b8644: cmp %rax,0x38(%rsp)` | arithmetic/control | 0x3b8615 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1148 | je | reg/arith | `0x3b8696: test %al,%al` | memory | 0x3b8757 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1179 | jne | mem | `0x3b86c0: cmpq $0x0,0xc0(%rsp)` | arithmetic/control | 0x3b83a8 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x123e | jne | reg/arith | `0x3b878c: or %al,%cl` | memory | 0x3b87c7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1275 | jne | reg/arith | `0x3b87c2: cmp %rax,%rsi` | memory | 0x3b8797 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1280 | je | mem | `0x3b87c7: cmpq $0x0,0xc8(%rsp)` | memory | 0x3b87e2 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x12ba | jne | reg/arith | `0x3b8808: or %al,%cl` | memory | 0x3b8843 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x12f1 | jne | reg/arith | `0x3b883e: cmp %rax,%rsi` | memory | 0x3b8813 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x12fc | je | mem | `0x3b8843: cmpq $0x0,0xd0(%rsp)` | memory | 0x3b80a9 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x148b | jne | reg/arith | `0x3b89d8: test %rbx,%rbx` | call+memory | 0x3b8a0b | fwd |
| Montgomery multiply (allocating wrapper) | +0x42 | jne | reg/arith | `0x1645cf: test %rbx,%rbx` | call+memory | 0x16461a | fwd |
| Montgomery multiply (allocating wrapper) | +0x6e | je | mem | `0x1645f9: cmpb $0x0,0x30(%rsp)` | memory | 0x164656 | fwd |
| Montgomery multiply (allocating wrapper) | +0x7f | jne | reg/arith | `0x16460c: test %rbx,%rbx` | arithmetic/control | 0x164740 | fwd |
| Montgomery multiply (allocating wrapper) | +0xaf | je | mem | `0x16463a: cmpb $0x0,0x30(%rsp)` | memory | 0x164772 | fwd |
| Montgomery multiply (allocating wrapper) | +0xce | jne | reg/arith | `0x16465b: test %rbx,%rbx` | memory | 0x1647a7 | fwd |
| Montgomery multiply (allocating wrapper) | +0xe4 | jne | reg/arith | `0x164671: or %rbp,%r14` | memory | 0x1646e3 | fwd |
| Montgomery multiply (allocating wrapper) | +0x13e | jne | reg/arith | `0x1646cb: cmp %rax,%r14` | memory | 0x1646a0 | back |
| Montgomery multiply (allocating wrapper) | +0x19e | jne | reg/arith | `0x16472b: cmp %rax,%rsi` | memory | 0x164700 | back |
| Montgomery multiply (allocating wrapper) | +0x1ae | je | reg/arith | `0x16473b: test %rbx,%rbx` | arithmetic/control | 0x164763 | fwd |
| Montgomery multiply (allocating wrapper) | +0x1ee | je | reg/arith | `0x16477a: cmp $0x1,%rbx` | memory | 0x16479b | fwd |
| Montgomery multiply (allocating wrapper) | +0x267 | je | mem | `0x1647f2: cmpb $0x0,0x30(%rsp)` | memory | 0x16480a | fwd |
| Montgomery multiply (allocating wrapper) | +0x288 | je | reg/arith | `0x164814: cmp $0x1,%rbx` | memory | 0x16483c | fwd |
| Montgomery multiply (allocating wrapper) | +0x2bc | jne | reg/arith | `0x164849: or %rbp,%r14` | memory | 0x164942 | fwd |
| Montgomery multiply (allocating wrapper) | +0x33d | je | reg/arith | `0x1648ca: cmp %rbx,%r15` | memory | 0x1649a2 | fwd |
| Montgomery multiply (allocating wrapper) | +0x353 | je | reg/arith | `0x1648e0: test %rax,%rax` | memory | 0x164897 | back |
| Montgomery multiply (allocating wrapper) | +0x3a2 | jne | reg/arith | `0x16492f: cmp %r8,%rbp` | arithmetic/control | 0x1648f0 | back |
| Montgomery multiply (allocating wrapper) | +0x3a7 | jne | reg/arith | `0x164934: test $0x1,%bl` | arithmetic/control | 0x164897 | back |
| Montgomery multiply (allocating wrapper) | +0x3fb | jne | reg/arith | `0x164988: cmp %rax,%rsi` | memory | 0x16495d | back |
| Montgomery multiply (allocating wrapper) | +0x47a | je | reg/arith | `0x164a02: cmp %rbx,%rax` | memory | 0x164aaa | fwd |
| Montgomery multiply (allocating wrapper) | +0x488 | je | reg/arith | `0x164a15: cmp %rax,%r11` | memory | 0x164c43 | fwd |
| Montgomery multiply (allocating wrapper) | +0x4b3 | je | reg/arith | `0x164a40: cmp %rdi,%r15` | memory | 0x164c1d | fwd |
| Montgomery multiply (allocating wrapper) | +0x4dd | jne | reg/arith | `0x164a6a: cmp %rdi,%rbx` | memory | 0x164a40 | back |
| Montgomery multiply (allocating wrapper) | +0x4eb | je | mem | `0x164a76: cmp 0x60(%rsp),%r11` | memory | 0x1649e3 | back |
| Montgomery multiply (allocating wrapper) | +0x513 | jne | reg/arith | `0x164aa0: cmp %rax,%r13` | arithmetic/control | 0x164a90 | back |
| Montgomery multiply (allocating wrapper) | +0x52f | je | reg/arith | `0x164abc: test %rax,%rax` | memory | 0x164b18 | fwd |
| Montgomery multiply (allocating wrapper) | +0x57f | jne | reg/arith | `0x164b0c: cmp %rdx,%rbp` | arithmetic/control | 0x164ad7 | back |
| Montgomery multiply (allocating wrapper) | +0x584 | jne | reg/arith | `0x164b11: test $0x1,%bl` | arithmetic/control | 0x164b26 | fwd |
| Montgomery multiply (allocating wrapper) | +0x5ee | ja | reg/arith | `0x164b7b: cmp %r12,%rdi` | arithmetic/control | 0x164c50 | fwd |
| Montgomery multiply (allocating wrapper) | +0x5f7 | je | reg/arith | `0x164b84: cmp %r8,%rbx` | memory | 0x164c59 | fwd |
| Montgomery multiply (allocating wrapper) | +0x628 | jne | reg/arith | `0x164bb4: add $0xfffffffffffffff8,%r10` | memory | 0x164b77 | back |
| Montgomery multiply (allocating wrapper) | +0x673 | jne | reg/arith | `0x164c00: cmp %rax,%rsi` | memory | 0x164bcc | back |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x3bc3a6: test %r14,%r14` | memory | 0x3bc413 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x3bc3c1: cmp $0x1,%r14` | memory | 0x3bc3e9 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x3bc3ca: cmp $0x1,%rax` | memory | 0x3bc3ec | fwd |
| Constant-time ladder core | +0x5e | jne | reg/arith | `0x3bc3ec: test $0x1,%al` | call | 0x3bc407 | fwd |
| Constant-time ladder core | +0x81 | jbe | reg/arith | `0x3bc40e: cmp %rbx,%rbp` | memory | 0x3bc429 | fwd |
| Constant-time ladder core | +0xdc | je | mem | `0x3bc467: cmpb $0x0,0x18(%rsp)` | memory | 0x3bc47c | fwd |
| Constant-time ladder core | +0xf8 | je | reg/arith | `0x3bc484: cmp $0x1,%rbx` | memory | 0x3bc4b2 | fwd |
| Constant-time ladder core | +0x145 | jae | reg/arith | `0x3bc4d1: cmp $0x18,%rcx` | arithmetic/control | 0x3bc4e1 | fwd |
| Constant-time ladder core | +0x16f | je | reg/arith | `0x3bc4fc: cmp %rsi,%rdi` | arithmetic/control | 0x3bc579 | fwd |
| Constant-time ladder core | +0x17a | jae | reg/arith | `0x3bc507: cmp %rbp,%rdi` | memory | 0x3bc53d | fwd |
| Constant-time ladder core | +0x18b | jb | reg/arith | `0x3bc518: cmp %rbp,%rdi` | memory | 0x3bc54b | fwd |
| Constant-time ladder core | +0x19a | jb | reg/arith | `0x3bc527: cmp %rbp,%rdi` | memory | 0x3bc55c | fwd |
| Constant-time ladder core | +0x1a9 | jb | reg/arith | `0x3bc536: cmp %rbp,%rdi` | arithmetic/control | 0x3bc4ec | back |
| Constant-time ladder core | +0x1b9 | jae | reg/arith | `0x3bc546: cmp %rbp,%rdi` | memory | 0x3bc51d | back |
| Constant-time ladder core | +0x1ca | jae | reg/arith | `0x3bc557: cmp %rbp,%rdi` | memory | 0x3bc52c | back |
| Constant-time ladder core | +0x1db | jb | reg/arith | `0x3bc568: cmp %rbp,%rdi` | arithmetic/control | 0x3bc4ec | back |
| Constant-time ladder core | +0x1ec | je | reg/arith | `0x3bc579: test %rax,%rax` | memory | 0x3bc5bd | fwd |
| Constant-time ladder core | +0x213 | je | reg/arith | `0x3bc5a0: cmp %rdi,%rax` | memory | 0x3bc5bd | fwd |
| Constant-time ladder core | +0x21c | jb | reg/arith | `0x3bc5a9: cmp %rbp,%r8` | memory | 0x3bc595 | back |
| Constant-time ladder core | +0x22b | jne | reg/arith | `0x3bc5b8: cmp %rdi,%rax` | call | 0x3bc5a5 | back |
| Constant-time ladder core | +0x23e | je | reg/arith | `0x3bc5cb: test %r15,%r15` | memory | 0x3bc641 | fwd |
| Constant-time ladder core | +0x247 | jne | reg/arith | `0x3bc5d4: test %r14,%r14` | memory | 0x3bc6d1 | fwd |
| Constant-time ladder core | +0x2e0 | je | reg/arith | `0x3bc66d: test %rbx,%rbx` | memory | 0x3bc41a | back |
| Constant-time ladder core | +0x323 | jne | reg/arith | `0x3bc6b0: cmp %rax,%rsi` | memory | 0x3bc67d | back |
| Constant-time ladder core | +0x374 | je | mem | `0x3bc6ff: cmpb $0x0,0x18(%rsp)` | memory | 0x3bc720 | fwd |
| Constant-time ladder core | +0x385 | je | reg/arith | `0x3bc712: test %rbx,%rbx` | arithmetic/control | 0x3bc41a | back |
| Constant-time ladder core | +0x39c | je | reg/arith | `0x3bc728: cmp $0x1,%r14` | memory | 0x3bc74c | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x226b54: test %r8,%r8` | memory | 0x226ba5 | fwd |
| Constant-time inversion | +0x1f | je | mem | `0x226b5c: testb $0x1,(%rcx)` | arithmetic/control | 0x226ba5 | fwd |
| Constant-time inversion | +0x32 | jne | reg/arith | `0x226b6e: shr $0x39,%rax` | call+memory | 0x226ba5 | fwd |
| Constant-time inversion | +0x63 | je | mem | `0x226b9e: cmpb $0x0,0x10(%rsp)` | memory | 0x226bc2 | fwd |
| Constant-time inversion | +0x8e | je | reg/arith | `0x226bca: cmp $0x1,%rbx` | memory | 0x226beb | fwd |
| Constant-time inversion | +0xea | je | mem | `0x226c25: cmpb $0x0,0x10(%rsp)` | memory | 0x226c8e | fwd |
| Constant-time inversion | +0x136 | jne | reg/arith | `0x226c73: cmp %rax,%rbx` | memory | 0x226c40 | back |
| Constant-time inversion | +0x15a | je | reg/arith | `0x226c96: cmp $0x1,%rbx` | memory | 0x226cb7 | fwd |
| Constant-time inversion | +0x1c0 | je | mem | `0x226cfb: cmpb $0x0,0x10(%rsp)` | memory | 0x226d57 | fwd |
| Constant-time inversion | +0x202 | jne | reg/arith | `0x226d3f: cmp %rax,%rsi` | memory | 0x226d0c | back |
| Constant-time inversion | +0x22c | je | mem | `0x226d5f: cmpq $0x1,(%rsp)` | memory | 0x226d97 | fwd |
| Constant-time inversion | +0x28b | je | mem | `0x226dc6: cmpb $0x0,0x10(%rsp)` | memory | 0x226e56 | fwd |
| Constant-time inversion | +0x2b5 | jne | reg/arith | `0x226df3: or %cl,%dl` | memory | 0x226e35 | fwd |
| Constant-time inversion | +0x2ef | jne | reg/arith | `0x226e2c: cmp %rax,%rsi` | memory | 0x226e01 | back |
| Constant-time inversion | +0x2f8 | je | reg/arith | `0x226e35: test %rax,%rax` | memory | 0x226d02 | back |
| Constant-time inversion | +0x328 | je | mem | `0x226e63: cmpq $0x1,(%rsp)` | memory | 0x226e92 | fwd |
| Constant-time inversion | +0x37e | je | mem | `0x226eb9: cmpb $0x0,0x10(%rsp)` | memory | 0x226f55 | fwd |
| Constant-time inversion | +0x3b1 | jne | reg/arith | `0x226eef: or %cl,%al` | memory | 0x226f2d | fwd |
| Constant-time inversion | +0x3eb | jne | reg/arith | `0x226f28: cmp %rax,%rsi` | memory | 0x226efd | back |
| Constant-time inversion | +0x3f2 | je | mem | `0x226f2d: cmpq $0x0,(%rsp)` | memory | 0x226f47 | fwd |
| Constant-time inversion | +0x421 | je | reg/arith | `0x226f5d: cmp $0x1,%rbx` | memory | 0x226f81 | fwd |
| Constant-time inversion | +0x46d | je | mem | `0x226fa8: cmpb $0x0,0x10(%rsp)` | memory | 0x226fbd | fwd |
| Constant-time inversion | +0x48b | je | reg/arith | `0x226fc7: cmp $0x1,%rbx` | memory | 0x226fef | fwd |
| Constant-time inversion | +0x4dd | je | reg/arith | `0x227019: cmp $0xffffffffffffffff,%rax` | call+memory | 0x227596 | fwd |
| Constant-time inversion | +0x524 | je | reg/arith | `0x227060: cmp $0xffffffffffffffff,%rax` | call+memory | 0x2275a4 | fwd |
| Constant-time inversion | +0x56b | je | reg/arith | `0x2270a7: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228df0 | fwd |
| Constant-time inversion | +0x5b2 | je | reg/arith | `0x2270ee: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228dfe | fwd |
| Constant-time inversion | +0x5fa | je | reg/arith | `0x227136: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228e0c | fwd |
| Constant-time inversion | +0x642 | je | reg/arith | `0x22717e: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228e1a | fwd |
| Constant-time inversion | +0x68a | je | reg/arith | `0x2271c6: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228e28 | fwd |
| Constant-time inversion | +0x6cf | je | reg/arith | `0x22720b: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228e36 | fwd |
| Constant-time inversion | +0x714 | je | reg/arith | `0x227250: cmp $0xffffffffffffffff,%rax` | call+memory | 0x228e44 | fwd |
| Constant-time inversion | +0x759 | je | reg/arith | `0x227295: cmp $0xffffffffffffffff,%rax` | call+memory | 0x2290f5 | fwd |
| Constant-time inversion | +0x79f | je | reg/arith | `0x2272db: cmp $0xffffffffffffffff,%rax` | memory | 0x229100 | fwd |
| Constant-time inversion | +0xb14 | je | mem | `0x22763c: cmp 0x2b0(%rsp),%rdx` | memory | 0x228e52 | fwd |
| Constant-time inversion | +0xbcf | je | mem | `0x227706: cmpq $0x0,0x148(%rsp)` | memory | 0x227768 | fwd |
| Constant-time inversion | +0xc0e | je | reg/arith | `0x22774a: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x22776a | fwd |
| Constant-time inversion | +0xc13 | jae | reg/arith | `0x227750: cmp %rbx,%rcx` | memory | 0x22775c | fwd |
| Constant-time inversion | +0xc21 | jb | reg/arith | `0x22775e: cmp %rbx,%rcx` | arithmetic/control | 0x22771f | back |
| Constant-time inversion | +0xc33 | je | mem | `0x22776a: cmpq $0x0,0x140(%rsp)` | memory | 0x2277cf | fwd |
| Constant-time inversion | +0xc71 | je | reg/arith | `0x2277ad: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x2277cf | fwd |
| Constant-time inversion | +0xc76 | jae | reg/arith | `0x2277b3: cmp %rbx,%rcx` | memory | 0x2277c3 | fwd |
| Constant-time inversion | +0xc88 | jb | reg/arith | `0x2277c5: cmp %rbx,%rcx` | arithmetic/control | 0x227784 | back |
| Constant-time inversion | +0xcdf | je | mem | `0x227816: cmpq $0x0,0x130(%rsp)` | memory | 0x22790e | fwd |
| Constant-time inversion | +0xcee | je | mem | `0x227825: cmpq $0x0,0x270(%rsp)` | memory | 0x2278d8 | fwd |
| Constant-time inversion | +0xd47 | je | reg/arith | `0x227883: add $0xfffffffffffffffe,%r8` | memory | 0x2278c7 | fwd |
| Constant-time inversion | +0xd58 | jae | reg/arith | `0x227895: cmp %rbx,%rdi` | memory | 0x2278a5 | fwd |
| Constant-time inversion | +0xd81 | jb | reg/arith | `0x2278be: cmp %rbx,%rcx` | arithmetic/control | 0x22785a | back |
| Constant-time inversion | +0xd8f | je | mem | `0x2278c7: testb $0x1,0x250(%rsp)` | memory | 0x22790e | fwd |
| Constant-time inversion | +0xdbb | jae | reg/arith | `0x2278f8: cmp %rbx,%rdi` | memory | 0x227904 | fwd |
| Constant-time inversion | +0xdd7 | je | mem | `0x22790e: cmpq $0x0,0x150(%rsp)` | memory | 0x227a21 | fwd |
| Constant-time inversion | +0xde6 | je | mem | `0x22791d: cmpq $0x0,0x268(%rsp)` | memory | 0x2279df | fwd |
| Constant-time inversion | +0xe43 | je | reg/arith | `0x22797f: add $0xfffffffffffffffe,%r8` | memory | 0x2279ce | fwd |
| Constant-time inversion | +0xe5a | jae | mem | `0x227992: cmp 0x148(%rsp),%rdi` | memory | 0x2279a7 | fwd |
| Constant-time inversion | +0xe88 | jb | mem | `0x2279c0: cmp 0x148(%rsp),%rcx` | arithmetic/control | 0x227956 | back |
| Constant-time inversion | +0xe96 | je | mem | `0x2279ce: testb $0x1,0x248(%rsp)` | memory | 0x227a21 | fwd |
| Constant-time inversion | +0xec7 | jae | mem | `0x2279ff: cmp 0x148(%rsp),%rdi` | memory | 0x227a17 | fwd |
| Constant-time inversion | +0xf60 | je | reg/arith | `0x227a9c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x227ae4 | fwd |
| Constant-time inversion | +0xf65 | jae | reg/arith | `0x227aa2: cmp %rbx,%rcx` | memory | 0x227aae | fwd |
| Constant-time inversion | +0xf78 | jae | mem | `0x227ab0: cmp 0x130(%rsp),%rcx` | memory | 0x227ac8 | fwd |
| Constant-time inversion | +0xf9e | jb | mem | `0x227ad6: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x227a7b | back |
| Constant-time inversion | +0xfad | je | mem | `0x227ae4: cmpq $0x0,0x130(%rsp)` | memory | 0x227be5 | fwd |
| Constant-time inversion | +0xfbc | je | mem | `0x227af3: cmpq $0x0,0x270(%rsp)` | memory | 0x227bab | fwd |
| Constant-time inversion | +0x101a | je | reg/arith | `0x227b56: add $0xfffffffffffffffe,%r8` | memory | 0x227b9a | fwd |
| Constant-time inversion | +0x102b | jae | reg/arith | `0x227b68: cmp %rbx,%rdi` | memory | 0x227b78 | fwd |
| Constant-time inversion | +0x1054 | jb | reg/arith | `0x227b91: cmp %rbx,%rcx` | arithmetic/control | 0x227b2d | back |
| Constant-time inversion | +0x1062 | je | mem | `0x227b9a: testb $0x1,0x250(%rsp)` | memory | 0x227be5 | fwd |
| Constant-time inversion | +0x108e | jae | reg/arith | `0x227bcb: cmp %rbx,%rdi` | memory | 0x227bdb | fwd |
| Constant-time inversion | +0x10ae | je | mem | `0x227be5: cmpq $0x0,0x150(%rsp)` | memory | 0x227cf8 | fwd |
| Constant-time inversion | +0x10bd | je | mem | `0x227bf4: cmpq $0x0,0x268(%rsp)` | memory | 0x227cb6 | fwd |
| Constant-time inversion | +0x111a | je | reg/arith | `0x227c56: add $0xfffffffffffffffe,%r8` | memory | 0x227ca5 | fwd |
| Constant-time inversion | +0x1131 | jae | mem | `0x227c69: cmp 0x140(%rsp),%rdi` | memory | 0x227c7e | fwd |
| Constant-time inversion | +0x115f | jb | mem | `0x227c97: cmp 0x140(%rsp),%rcx` | arithmetic/control | 0x227c2d | back |
| Constant-time inversion | +0x116d | je | mem | `0x227ca5: testb $0x1,0x248(%rsp)` | memory | 0x227cf8 | fwd |
| Constant-time inversion | +0x119e | jae | mem | `0x227cd6: cmp 0x140(%rsp),%rdi` | memory | 0x227cee | fwd |
| Constant-time inversion | +0x121f | je | reg/arith | `0x227d5b: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x227da7 | fwd |
| Constant-time inversion | +0x1224 | jae | reg/arith | `0x227d61: cmp %rbx,%rcx` | memory | 0x227d71 | fwd |
| Constant-time inversion | +0x123b | jae | mem | `0x227d73: cmp 0x130(%rsp),%rcx` | memory | 0x227d8b | fwd |
| Constant-time inversion | +0x1261 | jb | mem | `0x227d99: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x227d3a | back |
| Constant-time inversion | +0x1270 | je | mem | `0x227da7: cmpq $0x0,0x80(%rsp)` | memory | 0x227dbf | fwd |
| Constant-time inversion | +0x1297 | je | mem | `0x227dce: cmpq $0x0,0x118(%rsp)` | memory | 0x227eef | fwd |
| Constant-time inversion | +0x12a6 | je | mem | `0x227ddd: cmpq $0x0,0x198(%rsp)` | memory | 0x227eb3 | fwd |
| Constant-time inversion | +0x1307 | je | reg/arith | `0x227e43: add $0xfffffffffffffffe,%r8` | memory | 0x227e9f | fwd |
| Constant-time inversion | +0x1321 | jae | mem | `0x227e59: cmp 0x80(%rsp),%rdi` | memory | 0x227e71 | fwd |
| Constant-time inversion | +0x1355 | jb | mem | `0x227e8d: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x227e14 | back |
| Constant-time inversion | +0x1367 | je | mem | `0x227e9f: testb $0x1,0x180(%rsp)` | memory | 0x227eef | fwd |
| Constant-time inversion | +0x1398 | jae | mem | `0x227ed0: cmp 0x80(%rsp),%rdi` | memory | 0x227ee5 | fwd |
| Constant-time inversion | +0x13b8 | je | mem | `0x227eef: cmpq $0x0,0x188(%rsp)` | memory | 0x227f53 | fwd |
| Constant-time inversion | +0x13ef | je | reg/arith | `0x227f2b: add $0xfffffffffffffff8,%rax` | memory | 0x227f53 | fwd |
| Constant-time inversion | +0x13f9 | jae | mem | `0x227f31: cmp 0x80(%rsp),%rcx` | memory | 0x227f46 | fwd |
| Constant-time inversion | +0x140c | jb | mem | `0x227f48: cmp (%rsp),%rcx` | arithmetic/control | 0x227f08 | back |
| Constant-time inversion | +0x141f | ja | mem | `0x227f5b: cmp %rax,(%rsp)` | arithmetic/control | 0x2292a9 | fwd |
| Constant-time inversion | +0x1425 | jae | unknown | `?` | memory | 0x229363 | fwd |
| Constant-time inversion | +0x1431 | je | mem | `0x227f6b: cmpq $0x0,0x28(%rsp)` | memory | 0x228040 | fwd |
| Constant-time inversion | +0x144c | jne | mem | `0x227f84: testb $0x8,0xa0(%rsp)` | memory | 0x227faf | fwd |
| Constant-time inversion | +0x145a | jae | mem | `0x227f96: cmp (%rsp),%rax` | memory | 0x227fb9 | fwd |
| Constant-time inversion | +0x149a | je | mem | `0x227fd1: cmpq $0x0,0xa0(%rsp)` | memory | 0x228040 | fwd |
| Constant-time inversion | +0x14c8 | je | mem | `0x228003: cmp 0x30(%rsp),%rax` | memory | 0x228040 | fwd |
| Constant-time inversion | +0x14d5 | jae | mem | `0x228011: cmp (%rsp),%rdi` | memory | 0x228022 | fwd |
| Constant-time inversion | +0x14fa | jb | mem | `0x228036: cmp (%rsp),%rcx` | arithmetic/control | 0x227fe9 | back |
| Constant-time inversion | +0x1509 | je | mem | `0x228040: cmpq $0x0,0x118(%rsp)` | memory | 0x22810f | fwd |
| Constant-time inversion | +0x1518 | je | mem | `0x22804f: cmpq $0x0,0x198(%rsp)` | memory | 0x2280e3 | fwd |
| Constant-time inversion | +0x1553 | je | mem | `0x22808b: cmp 0x1b0(%rsp),%rdx` | memory | 0x2280cf | fwd |
| Constant-time inversion | +0x1560 | jae | mem | `0x22809b: cmp 0x28(%rsp),%rdx` | memory | 0x2280ad | fwd |
| Constant-time inversion | +0x1589 | jb | mem | `0x2280c4: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x228067 | back |
| Constant-time inversion | +0x1597 | je | mem | `0x2280cf: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x22810f | fwd |
| Constant-time inversion | +0x15af | jae | mem | `0x2280ea: cmp 0x28(%rsp),%rax` | memory | 0x2280fc | fwd |
| Constant-time inversion | +0x15d5 | je | mem | `0x22810f: cmpq $0x0,0x28(%rsp)` | memory | 0x22817e | fwd |
| Constant-time inversion | +0x1611 | je | reg/arith | `0x22814d: add $0xfffffffffffffff8,%rax` | memory | 0x228179 | fwd |
| Constant-time inversion | +0x161b | jae | mem | `0x228153: cmp 0x80(%rsp),%rcx` | memory | 0x228168 | fwd |
| Constant-time inversion | +0x1632 | jb | mem | `0x22816a: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x228125 | back |
| Constant-time inversion | +0x1646 | je | mem | `0x228180: cmpq $0x0,0x68(%rsp)` | memory | 0x2281f7 | fwd |
| Constant-time inversion | +0x1688 | je | reg/arith | `0x2281c4: add $0xfffffffffffffff8,%rax` | memory | 0x2281e7 | fwd |
| Constant-time inversion | +0x168e | jae | mem | `0x2281ca: cmp (%rsp),%rcx` | memory | 0x2281d9 | fwd |
| Constant-time inversion | +0x16a0 | jb | mem | `0x2281db: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x228197 | back |
| Constant-time inversion | +0x16cf | je | mem | `0x228206: cmpq $0x0,0x110(%rsp)` | memory | 0x22831c | fwd |
| Constant-time inversion | +0x16de | je | mem | `0x228215: cmpq $0x0,0x190(%rsp)` | memory | 0x2282e0 | fwd |
| Constant-time inversion | +0x173e | je | reg/arith | `0x22827a: add $0xfffffffffffffffe,%r8` | memory | 0x2282cc | fwd |
| Constant-time inversion | +0x1755 | jae | mem | `0x228290: cmp 0x68(%rsp),%rdi` | memory | 0x2282a5 | fwd |
| Constant-time inversion | +0x1786 | jb | mem | `0x2282c1: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x22824b | back |
| Constant-time inversion | +0x1794 | je | mem | `0x2282cc: testb $0x1,0x178(%rsp)` | memory | 0x22831c | fwd |
| Constant-time inversion | +0x17c2 | jae | mem | `0x2282fd: cmp 0x68(%rsp),%rdi` | memory | 0x228312 | fwd |
| Constant-time inversion | +0x1811 | je | reg/arith | `0x22834d: add $0xfffffffffffffff8,%rax` | memory | 0x228375 | fwd |
| Constant-time inversion | +0x1818 | jae | mem | `0x228353: cmp 0x68(%rsp),%rcx` | memory | 0x228368 | fwd |
| Constant-time inversion | +0x182e | jb | mem | `0x22836a: cmp (%rsp),%rcx` | arithmetic/control | 0x22832a | back |
| Constant-time inversion | +0x183b | je | mem | `0x228375: cmpq $0x0,0x28(%rsp)` | memory | 0x22844a | fwd |
| Constant-time inversion | +0x1856 | jne | mem | `0x22838e: testb $0x8,0xa0(%rsp)` | memory | 0x2283b9 | fwd |
| Constant-time inversion | +0x1864 | jae | mem | `0x2283a0: cmp (%rsp),%rax` | memory | 0x2283c3 | fwd |
| Constant-time inversion | +0x18a4 | je | mem | `0x2283db: cmpq $0x0,0xa0(%rsp)` | memory | 0x22844a | fwd |
| Constant-time inversion | +0x18d2 | je | mem | `0x22840d: cmp 0x30(%rsp),%rax` | memory | 0x22844a | fwd |
| Constant-time inversion | +0x18df | jae | mem | `0x22841b: cmp (%rsp),%rdi` | memory | 0x22842c | fwd |
| Constant-time inversion | +0x1904 | jb | mem | `0x228440: cmp (%rsp),%rcx` | arithmetic/control | 0x2283f3 | back |
| Constant-time inversion | +0x1913 | je | mem | `0x22844a: cmpq $0x0,0x110(%rsp)` | memory | 0x228519 | fwd |
| Constant-time inversion | +0x1922 | je | mem | `0x228459: cmpq $0x0,0x190(%rsp)` | memory | 0x2284ed | fwd |
| Constant-time inversion | +0x195d | je | mem | `0x228495: cmp 0x1a8(%rsp),%rdx` | memory | 0x2284d9 | fwd |
| Constant-time inversion | +0x196a | jae | mem | `0x2284a5: cmp 0x28(%rsp),%rdx` | memory | 0x2284b7 | fwd |
| Constant-time inversion | +0x1993 | jb | mem | `0x2284ce: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x228471 | back |
| Constant-time inversion | +0x19a1 | je | mem | `0x2284d9: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x228519 | fwd |
| Constant-time inversion | +0x19b9 | jae | mem | `0x2284f4: cmp 0x28(%rsp),%rax` | memory | 0x228506 | fwd |
| Constant-time inversion | +0x1a04 | je | mem | `0x22853b: cmpq $0x0,0x1f8(%rsp)` | memory | 0x2285d2 | fwd |
| Constant-time inversion | +0x1a53 | je | reg/arith | `0x22858f: add $0xfffffffffffffff8,%rax` | memory | 0x2285d2 | fwd |
| Constant-time inversion | +0x1a5d | jae | mem | `0x228595: cmp 0x80(%rsp),%rcx` | memory | 0x2285aa | fwd |
| Constant-time inversion | +0x1a74 | jae | mem | `0x2285ac: cmp 0x118(%rsp),%rcx` | memory | 0x2285c1 | fwd |
| Constant-time inversion | +0x1a8c | jb | mem | `0x2285c4: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x22855e | back |
| Constant-time inversion | +0x1a9b | je | mem | `0x2285d2: cmpq $0x0,0x88(%rsp)` | memory | 0x2285ea | fwd |
| Constant-time inversion | +0x1ac2 | je | mem | `0x2285f9: cmpq $0x0,0x118(%rsp)` | memory | 0x22871a | fwd |
| Constant-time inversion | +0x1ad1 | je | mem | `0x228608: cmpq $0x0,0x198(%rsp)` | memory | 0x2286de | fwd |
| Constant-time inversion | +0x1b32 | je | reg/arith | `0x22866e: add $0xfffffffffffffffe,%r8` | memory | 0x2286ca | fwd |
| Constant-time inversion | +0x1b4c | jae | mem | `0x228684: cmp 0x88(%rsp),%rdi` | memory | 0x22869c | fwd |
| Constant-time inversion | +0x1b80 | jb | mem | `0x2286b8: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x22863f | back |
| Constant-time inversion | +0x1b92 | je | mem | `0x2286ca: testb $0x1,0x180(%rsp)` | memory | 0x22871a | fwd |
| Constant-time inversion | +0x1bc3 | jae | mem | `0x2286fb: cmp 0x88(%rsp),%rdi` | memory | 0x228710 | fwd |
| Constant-time inversion | +0x1c0f | je | reg/arith | `0x22874b: add $0xfffffffffffffff8,%rax` | memory | 0x228773 | fwd |
| Constant-time inversion | +0x1c19 | jae | mem | `0x228751: cmp 0x88(%rsp),%rcx` | memory | 0x228766 | fwd |
| Constant-time inversion | +0x1c2c | jb | mem | `0x228768: cmp (%rsp),%rcx` | arithmetic/control | 0x228728 | back |
| Constant-time inversion | +0x1c39 | je | mem | `0x228773: cmpq $0x0,0x28(%rsp)` | memory | 0x228848 | fwd |
| Constant-time inversion | +0x1c54 | jne | mem | `0x22878c: testb $0x8,0xa0(%rsp)` | memory | 0x2287b7 | fwd |
| Constant-time inversion | +0x1c62 | jae | mem | `0x22879e: cmp (%rsp),%rax` | memory | 0x2287c1 | fwd |
| Constant-time inversion | +0x1ca2 | je | mem | `0x2287d9: cmpq $0x0,0xa0(%rsp)` | memory | 0x228848 | fwd |
| Constant-time inversion | +0x1cd0 | je | mem | `0x22880b: cmp 0x30(%rsp),%rax` | memory | 0x228848 | fwd |
| Constant-time inversion | +0x1cdd | jae | mem | `0x228819: cmp (%rsp),%rdi` | memory | 0x22882a | fwd |
| Constant-time inversion | +0x1d02 | jb | mem | `0x22883e: cmp (%rsp),%rcx` | arithmetic/control | 0x2287f1 | back |
| Constant-time inversion | +0x1d11 | je | mem | `0x228848: cmpq $0x0,0x118(%rsp)` | memory | 0x228917 | fwd |
| Constant-time inversion | +0x1d20 | je | mem | `0x228857: cmpq $0x0,0x198(%rsp)` | memory | 0x2288eb | fwd |
| Constant-time inversion | +0x1d5b | je | mem | `0x228893: cmp 0x1b0(%rsp),%rdx` | memory | 0x2288d7 | fwd |
| Constant-time inversion | +0x1d68 | jae | mem | `0x2288a3: cmp 0x28(%rsp),%rdx` | memory | 0x2288b5 | fwd |
| Constant-time inversion | +0x1d91 | jb | mem | `0x2288cc: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x22886f | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x2288d7: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x228917 | fwd |
| Constant-time inversion | +0x1db7 | jae | mem | `0x2288f2: cmp 0x28(%rsp),%rax` | memory | 0x228904 | fwd |
| Constant-time inversion | +0x1ddd | je | mem | `0x228917: cmpq $0x0,0x28(%rsp)` | memory | 0x228986 | fwd |
| Constant-time inversion | +0x1e19 | je | reg/arith | `0x228955: add $0xfffffffffffffff8,%rax` | memory | 0x228981 | fwd |
| Constant-time inversion | +0x1e23 | jae | mem | `0x22895b: cmp 0x88(%rsp),%rcx` | memory | 0x228970 | fwd |
| Constant-time inversion | +0x1e3a | jb | mem | `0x228972: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x22892d | back |
| Constant-time inversion | +0x1e4e | je | mem | `0x228988: cmpq $0x0,0x68(%rsp)` | memory | 0x2289ff | fwd |
| Constant-time inversion | +0x1e90 | je | reg/arith | `0x2289cc: add $0xfffffffffffffff8,%rax` | memory | 0x2289ef | fwd |
| Constant-time inversion | +0x1e96 | jae | mem | `0x2289d2: cmp (%rsp),%rcx` | memory | 0x2289e1 | fwd |
| Constant-time inversion | +0x1ea8 | jb | mem | `0x2289e3: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x22899f | back |
| Constant-time inversion | +0x1ed7 | je | mem | `0x228a0e: cmpq $0x0,0x110(%rsp)` | memory | 0x228b24 | fwd |
| Constant-time inversion | +0x1ee6 | je | mem | `0x228a1d: cmpq $0x0,0x190(%rsp)` | memory | 0x228ae8 | fwd |
| Constant-time inversion | +0x1f46 | je | reg/arith | `0x228a82: add $0xfffffffffffffffe,%r8` | memory | 0x228ad4 | fwd |
| Constant-time inversion | +0x1f5d | jae | mem | `0x228a98: cmp 0x68(%rsp),%rdi` | memory | 0x228aad | fwd |
| Constant-time inversion | +0x1f8e | jb | mem | `0x228ac9: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x228a53 | back |
| Constant-time inversion | +0x1f9c | je | mem | `0x228ad4: testb $0x1,0x178(%rsp)` | memory | 0x228b24 | fwd |
| Constant-time inversion | +0x1fca | jae | mem | `0x228b05: cmp 0x68(%rsp),%rdi` | memory | 0x228b1a | fwd |
| Constant-time inversion | +0x2019 | je | reg/arith | `0x228b55: add $0xfffffffffffffff8,%rax` | memory | 0x228b7d | fwd |
| Constant-time inversion | +0x2020 | jae | mem | `0x228b5b: cmp 0x68(%rsp),%rcx` | memory | 0x228b70 | fwd |
| Constant-time inversion | +0x2036 | jb | mem | `0x228b72: cmp (%rsp),%rcx` | arithmetic/control | 0x228b32 | back |
| Constant-time inversion | +0x2043 | je | mem | `0x228b7d: cmpq $0x0,0x28(%rsp)` | memory | 0x228c52 | fwd |
| Constant-time inversion | +0x205e | jne | mem | `0x228b96: testb $0x8,0xa0(%rsp)` | memory | 0x228bc1 | fwd |
| Constant-time inversion | +0x206c | jae | mem | `0x228ba8: cmp (%rsp),%rax` | memory | 0x228bcb | fwd |
| Constant-time inversion | +0x20ac | je | mem | `0x228be3: cmpq $0x0,0xa0(%rsp)` | memory | 0x228c52 | fwd |
| Constant-time inversion | +0x20da | je | mem | `0x228c15: cmp 0x30(%rsp),%rax` | memory | 0x228c52 | fwd |
| Constant-time inversion | +0x20e7 | jae | mem | `0x228c23: cmp (%rsp),%rdi` | memory | 0x228c34 | fwd |
| Constant-time inversion | +0x210c | jb | mem | `0x228c48: cmp (%rsp),%rcx` | arithmetic/control | 0x228bfb | back |
| Constant-time inversion | +0x211b | je | mem | `0x228c52: cmpq $0x0,0x110(%rsp)` | memory | 0x228d21 | fwd |
| Constant-time inversion | +0x212a | je | mem | `0x228c61: cmpq $0x0,0x190(%rsp)` | memory | 0x228cf5 | fwd |
| Constant-time inversion | +0x2165 | je | mem | `0x228c9d: cmp 0x1a8(%rsp),%rdx` | memory | 0x228ce1 | fwd |
| Constant-time inversion | +0x2172 | jae | mem | `0x228cad: cmp 0x28(%rsp),%rdx` | memory | 0x228cbf | fwd |
| Constant-time inversion | +0x219b | jb | mem | `0x228cd6: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x228c79 | back |
| Constant-time inversion | +0x21a9 | je | mem | `0x228ce1: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x228d21 | fwd |
| Constant-time inversion | +0x21c1 | jae | mem | `0x228cfc: cmp 0x28(%rsp),%rax` | memory | 0x228d0e | fwd |
| Constant-time inversion | +0x2226 | je | reg/arith | `0x228d63: test %rax,%rax` | memory | 0x2275b2 | back |
| Constant-time inversion | +0x226d | je | reg/arith | `0x228da9: add $0xfffffffffffffff8,%rax` | memory | 0x2275b2 | back |
| Constant-time inversion | +0x227b | jae | mem | `0x228db3: cmp 0x88(%rsp),%rcx` | memory | 0x228dc8 | fwd |
| Constant-time inversion | +0x2292 | jae | mem | `0x228dca: cmp 0x118(%rsp),%rcx` | memory | 0x228ddf | fwd |
| Constant-time inversion | +0x22aa | jb | mem | `0x228de2: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x228d78 | back |
| Constant-time inversion | +0x231d | je | reg/arith | `0x228e59: cmp $0x1,%rbx` | memory | 0x228eed | fwd |
| Constant-time inversion | +0x2337 | jb | reg/arith | `0x228e73: cmp $0x18,%rdx` | memory | 0x228edc | fwd |
| Constant-time inversion | +0x2383 | jne | reg/arith | `0x228ec0: cmp %rcx,%rdx` | arithmetic/control | 0x228ea6 | back |
| Constant-time inversion | +0x239a | je | reg/arith | `0x228ed7: cmp %rdx,%rsi` | memory | 0x228eed | fwd |
| Constant-time inversion | +0x23ab | jne | mem | `0x228ee3: cmp 0x2b8(%rsp),%rax` | memory | 0x228edc | back |
| Constant-time inversion | +0x2414 | je | reg/arith | `0x228f50: cmp $0xffffffffffffffff,%rax` | memory | 0x22910b | fwd |
| Constant-time inversion | +0x2431 | jne | mem | `0x228f69: cmp 0x138(%rsp),%rdi` | memory | 0x229349 | fwd |
| Constant-time inversion | +0x257f | je | reg/arith | `0x2290bc: test %r12,%r12` | memory | 0x229287 | fwd |
| Constant-time inversion | +0x2592 | je | mem | `0x2290cd: cmpq $0x0,(%rsp)` | memory | 0x226bad | back |
| Constant-time inversion | +0x2732 | jne | reg/arith | `0x22926f: cmp %rax,%rsi` | memory | 0x229243 | back |
| Constant-time inversion | +0x2981 | je | mem | `0x2294bc: cmpq $0x0,(%rsp)` | memory | 0x229523 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x1d4f70: test %rcx,%rcx` | memory | 0x1d4fe4 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x1d4f80: test %rax,%rax` | memory | 0x1d4fd8 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x1d4f8c: cmp (%r15),%rcx` | memory | 0x1d4fdf | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x1d4f95: test %ecx,%ecx` | memory | 0x1d4fa5 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x1d4f9d: test %edx,%edx` | arithmetic/control | 0x1d4fa5 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x1d4fa1: cmp %edx,%ecx` | call | 0x1d4fdf | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x1d4fad: test %eax,%eax` | memory | 0x1d4fe4 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x1d4fb9: test %rax,%rax` | memory | 0x1d5112 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x1d4fc2: cmp (%r12),%rcx` | memory | 0x1d5353 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x1d4fef: test %rcx,%rcx` | memory | 0x1d50f0 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x1d5010: cmp %rdx,%rcx` | memory | 0x1d50f0 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x1d5019: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x1d5010 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x1d502f: test %rcx,%rcx` | memory | 0x1d50f0 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x1d5050: cmp %rdx,%rcx` | memory | 0x1d50f0 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x1d5059: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x1d5050 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x1d506d: test %r13,%r13` | memory | 0x1d5109 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x1d507a: cmpq $0x0,0x50(%rax)` | memory | 0x1d5120 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x1d509c: test %rax,%rax` | memory | 0x1d50eb | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x1d50b7: test %rax,%rax` | call | 0x1d50c5 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x1d50c1: test %eax,%eax` | call+memory | 0x1d5138 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x1d512f: test %r13,%r13` | memory | 0x1d527d | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x1d513c: cmpq $0x0,0x50(%rax)` | memory | 0x1d5274 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x1d5163: test %rax,%rax` | memory | 0x1d52b1 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x1d5182: test %rax,%rax` | call | 0x1d528b | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x1d5190: test %eax,%eax` | memory | 0x1d528b | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x1d51a2: test %r14,%r14` | arithmetic/control | 0x1d536c | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x1d51ab: test %r15,%r15` | memory | 0x1d5377 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x1d51be: test %rcx,%rcx` | memory | 0x1d51f8 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x1d51c7: test %rax,%rax` | memory | 0x1d51f8 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x1d51d3: cmp (%r15),%rcx` | memory | 0x1d51f8 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x1d51dc: test %ecx,%ecx` | memory | 0x1d54ba | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x1d51e8: test %edx,%edx` | arithmetic/control | 0x1d54ba | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x1d51f0: cmp %ecx,%edx` | call | 0x1d54ba | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x1d5212: test %rax,%rax` | memory | 0x1d5225 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x1d521b: test %rax,%rax` | call | 0x1d5225 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x1d5256: test %rbx,%rbx` | memory | 0x1d548e | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x1d5263: test %rcx,%rcx` | arithmetic/control | 0x1d5339 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x1d52d2: test %bpl,%bpl` | memory | 0x1d5318 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x1d52df: test %rax,%rax` | memory | 0x1d52f2 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x1d52e8: test %rax,%rax` | call | 0x1d52f2 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x1d5323: test %rbx,%rbx` | memory | 0x1d50f7 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x1d5330: test %rcx,%rcx` | memory | 0x1d50f7 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x1d5384: test %eax,%eax` | memory | 0x1d5496 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x1d5390: test %rax,%rax` | memory | 0x1d5399 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x1d539d: test %rax,%rax` | memory | 0x1d53a6 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x1d53aa: test %rax,%rax` | memory | 0x1d53b3 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x1d53b8: test %rax,%rax` | memory | 0x1d53c1 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x1d53c6: test %rax,%rax` | memory | 0x1d53cf | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x1d53d4: test %rax,%rax` | memory | 0x1d53dd | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x1d53e6: test %rax,%rax` | memory | 0x1d53ef | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x1d53f8: test %rax,%rax` | memory | 0x1d5401 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x1d540a: test %rax,%rax` | call+memory | 0x1d5413 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x1d543b: test %rax,%rax` | memory | 0x1d54a2 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x1d5459: test %eax,%eax` | memory | 0x1d54ae | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x1d546a: test %r15,%r15` | memory | 0x1d54d8 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x1d5473: test $0xffffffff80000000,%rax` | memory | 0x1d54eb | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x1d54ba: cmp %r15,%r14` | call | 0x1d538c | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x1d54cb: test %eax,%eax` | arithmetic/control | 0x1d538c | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x1d54f6: test $0x1,%al` | memory | 0x1d5b38 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x1d5503: test %eax,%eax` | memory | 0x1d5531 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x1d550e: cmp %rsi,(%rdi)` | call+memory | 0x1d553b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x1d5523: test %al,%cl` | arithmetic/control | 0x1d5544 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x1d5531: test %r15,%r15` | arithmetic/control | 0x1d5559 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x1d553b: test %r15,%r15` | memory | 0x1d5624 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x1d5544: cmp %rsi,(%r15)` | call | 0x1d5559 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x1d5551: test %al,%al` | memory | 0x1d5624 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x1d556a: test %rax,%rax` | memory | 0x1d5630 | fwd |
| ECDSA scalar ladder (driver) | +0x635 | jg | mem | `0x1d5581: cmp 0x24(%rsp),%eax` | memory | 0x1d558e | fwd |
| ECDSA scalar ladder (driver) | +0x63c | je | mem | `0x1d5587: cmpl $0x0,0x18(%r15)` | memory | 0x1d55aa | fwd |
| ECDSA scalar ladder (driver) | +0x654 | je | reg/arith | `0x1d55a2: test %eax,%eax` | memory | 0x1d563c | fwd |
| ECDSA scalar ladder (driver) | +0x672 | je | reg/arith | `0x1d55c0: test %eax,%eax` | memory | 0x1d5648 | fwd |
| ECDSA scalar ladder (driver) | +0x68f | je | reg/arith | `0x1d55dd: test %eax,%eax` | memory | 0x1d581e | fwd |
| ECDSA scalar ladder (driver) | +0x6a3 | js | mem | `0x1d55ee: cmpl $0x0,0x24(%rsp)` | memory | 0x1d5654 | fwd |
| ECDSA scalar ladder (driver) | +0x6b5 | jae | mem | `0x1d5601: cmp 0x10(%rcx),%rax` | memory | 0x1d5654 | fwd |
| ECDSA scalar ladder (driver) | +0x722 | je | reg/arith | `0x1d566f: test %rax,%rax` | memory | 0x1d568c | fwd |
| ECDSA scalar ladder (driver) | +0x74f | je | reg/arith | `0x1d569c: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x75d | jae | mem | `0x1d56aa: cmp %r15,(%rdi)` | call | 0x1d56bf | fwd |
| ECDSA scalar ladder (driver) | +0x769 | je | reg/arith | `0x1d56b7: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x77b | je | reg/arith | `0x1d56c8: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x784 | jae | mem | `0x1d56d1: cmp %r15,(%rdi)` | call | 0x1d56e6 | fwd |
| ECDSA scalar ladder (driver) | +0x790 | je | reg/arith | `0x1d56de: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x7a2 | je | reg/arith | `0x1d56ef: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x7ab | jae | mem | `0x1d56f8: cmp %r15,(%rdi)` | call | 0x1d570d | fwd |
| ECDSA scalar ladder (driver) | +0x7b7 | je | reg/arith | `0x1d5705: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x7c5 | je | reg/arith | `0x1d5712: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x7ce | jae | mem | `0x1d571b: cmp %r15,(%rdi)` | call | 0x1d5730 | fwd |
| ECDSA scalar ladder (driver) | +0x7da | je | reg/arith | `0x1d5728: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x7e8 | je | reg/arith | `0x1d5735: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x7f1 | jae | mem | `0x1d573e: cmp %r15,(%rdi)` | call | 0x1d5753 | fwd |
| ECDSA scalar ladder (driver) | +0x7fd | je | reg/arith | `0x1d574b: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x80b | je | reg/arith | `0x1d5758: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x814 | jae | mem | `0x1d5761: cmp %r15,(%rdi)` | call | 0x1d5776 | fwd |
| ECDSA scalar ladder (driver) | +0x820 | je | reg/arith | `0x1d576e: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x832 | je | reg/arith | `0x1d577f: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x83b | jae | mem | `0x1d5788: cmp %r15,(%rdi)` | call | 0x1d579d | fwd |
| ECDSA scalar ladder (driver) | +0x847 | je | reg/arith | `0x1d5795: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x859 | je | reg/arith | `0x1d57a6: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x862 | jae | mem | `0x1d57af: cmp %r15,(%rdi)` | call | 0x1d57c4 | fwd |
| ECDSA scalar ladder (driver) | +0x86e | je | reg/arith | `0x1d57bc: test %al,%al` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x880 | je | reg/arith | `0x1d57cd: test %rdi,%rdi` | memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0x88e | jae | mem | `0x1d57d6: cmp %r15,(%rdi)` | call | 0x1d57f0 | fwd |
| ECDSA scalar ladder (driver) | +0x89a | je | reg/arith | `0x1d57e8: test %al,%al` | memory | 0x1d5204 | back |
| ECDSA scalar ladder (driver) | +0x8a5 | je | mem | `0x1d57f0: cmpl $0x0,0x28(%r14)` | call+memory | 0x1d5952 | fwd |
| ECDSA scalar ladder (driver) | +0x8b9 | je | reg/arith | `0x1d5807: test %al,%al` | memory | 0x1d582a | fwd |
| ECDSA scalar ladder (driver) | +0x8e8 | jne | reg/arith | `0x1d5834: cmp $0x4,%rdx` | memory | 0x1d587d | fwd |
| ECDSA scalar ladder (driver) | +0x922 | jne | reg/arith | `0x1d586e: cmp $0x1,%dil` | call | 0x1d587f | fwd |
| ECDSA scalar ladder (driver) | +0x934 | je | reg/arith | `0x1d5882: test %cl,%cl` | arithmetic/control | 0x1d58f8 | fwd |
| ECDSA scalar ladder (driver) | +0x939 | jne | reg/arith | `0x1d5886: test %sil,%sil` | memory | 0x1d58f8 | fwd |
| ECDSA scalar ladder (driver) | +0x985 | je | mem | `0x1d58cc: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x1d59c2 | fwd |
| ECDSA scalar ladder (driver) | +0x9cb | je | reg/arith | `0x1d5919: test %eax,%eax` | arithmetic/control | 0x1d5990 | fwd |
| ECDSA scalar ladder (driver) | +0x9d4 | jg | reg/arith | `0x1d5921: cmp $0x1,%eax` | arithmetic/control | 0x1d599c | fwd |
| ECDSA scalar ladder (driver) | +0x9d8 | jne | reg/arith | `0x1d5926: test %eax,%eax` | call+memory | 0x1d59d3 | fwd |
| ECDSA scalar ladder (driver) | +0xa17 | je | reg/arith | `0x1d5964: test %rax,%rax` | call+memory | 0x1d5986 | fwd |
| ECDSA scalar ladder (driver) | +0xa2b | jne | reg/arith | `0x1d5979: test %eax,%eax` | arithmetic/control | 0x1d57fb | back |
| ECDSA scalar ladder (driver) | +0xa4f | jne | reg/arith | `0x1d599c: cmp $0x2,%eax` | call+memory | 0x1d5a06 | fwd |
| ECDSA scalar ladder (driver) | +0xaa4 | jne | reg/arith | `0x1d59f2: test %eax,%eax` | memory | 0x1d5acb | fwd |
| ECDSA scalar ladder (driver) | +0xaba | jo | mem | `0x1d5a06: decl 0x24(%rsp)` | arithmetic/control | 0x1d5b47 | fwd |
| ECDSA scalar ladder (driver) | +0xac0 | js | unknown | `?` | memory | 0x1d5ab2 | fwd |
| ECDSA scalar ladder (driver) | +0xae9 | jae | mem | `0x1d5a35: cmp 0x10(%rcx),%rax` | memory | 0x1d5a52 | fwd |
| ECDSA scalar ladder (driver) | +0xb1c | je | mem | `0x1d5a66: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x1d5a85 | fwd |
| ECDSA scalar ladder (driver) | +0xb4f | je | reg/arith | `0x1d5a9d: test %eax,%eax` | memory | 0x1d5b0d | fwd |
| ECDSA scalar ladder (driver) | +0xb5a | jg | reg/arith | `0x1d5aa3: test %r15,%r15` | arithmetic/control | 0x1d5a27 | back |
| ECDSA scalar ladder (driver) | +0xb89 | je | reg/arith | `0x1d5ad6: test %rax,%rax` | call+memory | 0x1d5af4 | fwd |
| ECDSA scalar ladder (driver) | +0xba2 | je | reg/arith | `0x1d5af0: test %eax,%eax` | call+memory | 0x1d5b06 | fwd |
| ECDSA scalar ladder (driver) | +0xbdd | jne | reg/arith | `0x1d5b2a: test %rax,%rax` | arithmetic/control | 0x1d5217 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x2596f7: test %rax,%rax` | memory | 0x259c95 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x259712: test %rbp,%rbp` | memory | 0x259c95 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x259722: test %rax,%rax` | call+memory | 0x259c95 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x259744: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x259762: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x259780: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x25979e: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x2597c4: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x2597e4: test %eax,%eax` | arithmetic/control | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x2597ec: test %r15,%r15` | memory | 0x259812 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x2597fe: test %rdx,%rdx` | arithmetic/control | 0x259834 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x25982a: test %rdx,%rdx` | memory | 0x259840 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x259843: sub $0x1,%r9` | memory | 0x259867 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x259849: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x259840 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x259860: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x259870 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x25986a: sub $0x1,%r8` | arithmetic/control | 0x259860 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x259870: cmp %r9,%rdi` | memory | 0x259890 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x259880: sub $0x1,%rdi` | memory | 0x259892 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x25988a: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x259880 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x2598ad | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x2598a5: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x2598bf: test %eax,%eax` | arithmetic/control | 0x259c95 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x2598cc: test %r15,%r15` | memory | 0x2598db | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x2598f3: sub $0x1,%rdi` | memory | 0x259917 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x2598f9: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x2598f0 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x259910: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x259920 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x25991a: sub $0x1,%rsi` | arithmetic/control | 0x259910 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x259920: cmp %rdi,%rdx` | arithmetic/control | 0x259935 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x259925: sub $0x1,%rdx` | memory | 0x259937 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x25992f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x259925 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x25994e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x259946: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x259963: test %eax,%eax` | memory | 0x259c95 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x25997d: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x2599a0: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x2599bb: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x2599d5: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x2599f7: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x259a11: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x259a34: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x259a56: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x259a78: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x259a9a: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x259ab4: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x259ad0: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x259af4: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x259b0e: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x259b2d: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x259b4c: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x259b6b: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x259b85: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x259ba4: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x259bc1: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x259be6: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x259c05: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x259c21: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x259c3a: test %eax,%eax` | call+memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x259c53: test %eax,%eax` | memory | 0x259c93 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x259c69: test %eax,%eax` | memory | 0x259c95 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x259c95: test %rbx,%rbx` | memory | 0x259cb8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x259c9e: test %rax,%rax` | memory | 0x259cb8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x260dbb: test %rax,%rax` | memory | 0x261828 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x260dd5: cmpl $0x1,0x10(%rbp)` | memory | 0x260dfd | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x260de5: test %rax,%rax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x260df4: cmp $0xfffffffd,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x260e05: testb $0x4,0xa4(%rbp)` | memory | 0x260e25 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x260e0e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x260e86 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x260e17: test %r13b,%r13b` | arithmetic/control | 0x260f60 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x260e2b: test %rax,%rax` | memory | 0x261828 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x260e59: test %rax,%rax` | arithmetic/control | 0x261370 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x260e62: test %r15,%r15` | memory | 0x260e70 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x260e7a: test %rax,%rax` | arithmetic/control | 0x260ee8 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x260ea3: test %r15,%r15` | arithmetic/control | 0x260f40 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x260eac: test %r14,%r14` | memory | 0x260eba | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x260ec1: test %r15,%r15` | memory | 0x260f32 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x260edb: test %eax,%eax` | memory | 0x260f26 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x260f04: test %eax,%eax` | memory | 0x261347 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x260f32: test %r14,%r14` | memory | 0x260f40 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x260f46: or %r13b,%al` | arithmetic/control | 0x261172 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x260f57: test %r15,%r15` | memory | 0x261828 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x260f66: test %rax,%rax` | memory | 0x261828 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x260fa9: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x260fb7: test %rax,%rax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x260fdd: test %rax,%rax` | call+memory | 0x261cd0 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x261006: test %eax,%eax` | call+memory | 0x261cd0 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x261054: test %al,0x38(%rsp)` | memory | 0x2610d3 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x261065: test %rax,%rax` | memory | 0x261828 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x26108b: test %rax,%rax` | call+memory | 0x261722 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x2610c5: test %ebp,%ebp` | arithmetic/control | 0x26182b | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x2610d5: test %ebx,%ebx` | memory | 0x26158e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x2610e7: test %r15b,%r15b` | call+memory | 0x261598 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x26110e: test %r13,%r13` | arithmetic/control | 0x261ccb | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x26111c: test %rax,%rax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x26112e: test %rax,%rax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x26113e: test %rcx,%rcx` | memory | 0x26172f | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x261156: cmpq $0x0,0x10(%rcx)` | memory | 0x261739 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x261197: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x2611b5: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x2611df: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x2611fd: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x261236: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x261258: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x261271: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x261279: test %rbx,%rbx` | memory | 0x2612c4 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x261288: cmpl $0x0,0x18(%rbx)` | memory | 0x2612c4 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x26129e: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x2612a6: cmpl $0x0,0x18(%rbx)` | memory | 0x2612c4 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x2612bc: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x2612da: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x2612fc: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x261319: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x261357: test %r15,%r15` | memory | 0x261365 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x261365: test %bl,%bl` | memory | 0x261418 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x261392: test %rax,%rax` | arithmetic/control | 0x261420 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x26139b: test %r15,%r15` | memory | 0x2613a9 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x2613b3: test %rax,%rax` | arithmetic/control | 0x2613bc | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x2613d8: test %eax,%eax` | memory | 0x2613f3 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x261403: test %r15,%r15` | memory | 0x261411 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x261411: test %bl,%bl` | arithmetic/control | 0x261420 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x26142a: test %ebx,%ebx` | memory | 0x26151b | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x261459: test %bl,%bl` | arithmetic/control | 0x261581 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x261464: cmp %r14,%r13` | memory | 0x26151b | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x261498: test %rax,%rax` | arithmetic/control | 0x261461 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x26149d: test %r15,%r15` | memory | 0x2614ab | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x2614af: test %rax,%rax` | arithmetic/control | 0x2614bd | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x2614b6: test %r15,%r15` | arithmetic/control | 0x261450 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x2614d2: test %eax,%eax` | memory | 0x2614f8 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x2614ea: test %r15,%r15` | arithmetic/control | 0x261450 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x26150d: test %r15,%r15` | arithmetic/control | 0x261450 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x261529: test %ebx,%ebx` | memory | 0x261574 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x261535: cmp 0x66de8c(%rip),%rax        # 8cf3c8 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x537358>` | call+memory | 0x260e0e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x26159d: test %al,%r14b` | memory | 0x26181f | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x2615d3: test %eax,%eax` | arithmetic/control | 0x26182b | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x2615db: test %rbx,%rbx` | memory | 0x2615fe | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x2615e0: cmpl $0x0,0x18(%rbx)` | memory | 0x2615fe | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x2615f6: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x261613: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x261621: test %rax,%rax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x26166d: test %ebp,%ebp` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x261675: test %rbx,%rbx` | memory | 0x26169d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x26167f: cmpl $0x0,0x18(%rbx)` | memory | 0x26169d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x261695: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x2616b5: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x2616ce: test %eax,%eax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x2616d6: cmpl $0x0,0x28(%rsp)` | memory | 0x261a2c | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x2616ec: test %rax,%rax` | memory | 0x26182b | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x261702: test %rax,%rax` | memory | 0x261939 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x26170b: cmpq $0x0,0x10(%rax)` | memory | 0x261939 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x26177d: test %eax,%eax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x261792: test %rax,%rax` | call+memory | 0x261ccb | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x2617b6: test %eax,%eax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x2617be: cmpl $0x1,0x28(%rsp)` | call+memory | 0x261864 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x261816: test %al,%r14b` | arithmetic/control | 0x2615a6 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x26181f: test %r15b,%r15b` | arithmetic/control | 0x261a2c | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x26182b: test %r12,%r12` | memory | 0x261852 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x261835: test %rax,%rax` | memory | 0x261852 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x26186d: test %rax,%rax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x261887: test %rax,%rax` | memory | 0x26189d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x26188c: cmpq $0x2,0x10(%rax)` | memory | 0x26189d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x2618da: test %eax,%eax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x2618ef: test %rax,%rax` | call+memory | 0x261ccb | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x261913: test %eax,%eax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x26191b: cmpl $0x2,0x28(%rsp)` | memory | 0x261be3 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x261951: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x26196e: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x2619a5: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x2619ad: cmpq $0x0,0x8(%rsp)` | memory | 0x2619d9 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x2619ba: cmpl $0x0,0x18(%rax)` | memory | 0x2619d9 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x2619d1: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x2619ee: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x261a09: test %eax,%eax` | memory | 0x261ce3 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x261a11: cmpl $0x1,0x28(%rsp)` | memory | 0x261cfb | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x261a30: test %rdx,%rdx` | memory | 0x261bc2 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x261a3d: test %rcx,%rcx` | memory | 0x261bc2 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x261a4e: cmp 0x66d973(%rip),%rax        # 8cf3c8 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x537358>` | memory | 0x261a78 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x261a57: test %rax,%rax` | call+memory | 0x261828 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x261a95: test %eax,%eax` | memory | 0x26182b | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x261ab0: test %eax,%eax` | memory | 0x26182b | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x261ad0: cmp %rdx,%rcx` | memory | 0x261bc2 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x261ad9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x261ad0 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x261b04: test %eax,%eax` | memory | 0x261bcd | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x261b11: cmpl $0x0,0x18(%rax)` | memory | 0x261b34 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x261b2c: test %eax,%eax` | memory | 0x26182b | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x261b47: cmp %rdx,%rcx` | memory | 0x261bd5 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x261b50: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x261b47 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x261b66: test %rax,%rax` | memory | 0x261c1c | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x261b8b: test %rax,%rax` | call+memory | 0x261cf3 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x261bf1: test %rax,%rax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x261c06: test %rax,%rax` | memory | 0x261c27 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x261c0b: cmpq $0x3,0x10(%rax)` | memory | 0x261c27 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x261c64: test %eax,%eax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x261c75: test %rax,%rax` | call+memory | 0x261ccb | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x261c95: test %eax,%eax` | memory | 0x261ccb | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x261c99: cmpl $0x3,0x28(%rsp)` | memory | 0x2617db | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x261d0a: test %rax,%rax` | memory | 0x261d20 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x261d0f: cmpq $0x2,0x10(%rax)` | memory | 0x261d20 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x261d38: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x261d51: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x261d84: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x261d8c: cmpq $0x0,0x8(%rsp)` | memory | 0x261db8 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x261d99: cmpl $0x0,0x18(%rax)` | memory | 0x261db8 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x261db0: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x261dcd: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x261de8: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x261df0: cmpl $0x2,0x28(%rsp)` | memory | 0x261a1c | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x261e0a: test %rax,%rax` | memory | 0x261e20 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x261e0f: cmpq $0x3,0x10(%rax)` | memory | 0x261e20 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x261e38: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x261e55: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x261e8c: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x112a | je | mem | `0x261e94: cmpq $0x0,0x8(%rsp)` | memory | 0x261ec0 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x261ea1: cmpl $0x0,0x18(%rax)` | memory | 0x261ec0 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x261eb8: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x261ed5: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x261ef0: test %eax,%eax` | memory | 0x261ce3 | back |
| RSA CRT arms | +0x118d | je | mem | `0x261ef8: cmpl $0x3,0x28(%rsp)` | memory | 0x261a1c | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x25674a: test %r8,%r8` | memory | 0x25687b | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x256872: dec %r8` | memory | 0x256760 | back |
| DH key agreement (driver) | +0x26 | jle | reg/arith | `0x2543b1: cmp $0x2710,%eax` | memory | 0x2543c1 | fwd |
| DH key agreement (driver) | +0x39 | je | reg/arith | `0x2543c6: test %rdi,%rdi` | memory | 0x2543eb | fwd |
| DH key agreement (driver) | +0x46 | jle | reg/arith | `0x2543d1: cmp $0x2710,%eax` | call+memory | 0x2543eb | fwd |
| DH key agreement (driver) | +0x6b | jge | reg/arith | `0x2543f6: cmp $0x200,%eax` | call+memory | 0x25441c | fwd |
| DH key agreement (driver) | +0xbb | jne | mem | `0x254446: cmpl $0x1,0x30(%rsp)` | arithmetic/control | 0x254454 | fwd |
| DH key agreement (driver) | +0xe2 | je | reg/arith | `0x25446f: test %rax,%rax` | memory | 0x2544f2 | fwd |
| DH key agreement (driver) | +0x13f | je | reg/arith | `0x2544cc: test %rax,%rax` | memory | 0x254636 | fwd |
| DH key agreement (driver) | +0x14e | je | mem | `0x2544d8: cmpq $0x0,0x78(%r12)` | memory | 0x25450f | fwd |
| DH key agreement (driver) | +0x159 | jne | mem | `0x2544e0: testb $0x1,0x80(%r12)` | arithmetic/control | 0x25453d | fwd |
| DH key agreement (driver) | +0x191 | je | reg/arith | `0x25451e: test %rdx,%rdx` | memory | 0x254623 | fwd |
| DH key agreement (driver) | +0x1a4 | jae | reg/arith | `0x254530: cmp $0x8,%rdx` | arithmetic/control | 0x2545b2 | fwd |
| DH key agreement (driver) | +0x1c5 | jne | reg/arith | `0x254552: test %rdx,%rdx` | memory | 0x25468d | fwd |
| DH key agreement (driver) | +0x1d3 | je | reg/arith | `0x25455b: test %rbp,%rbp` | memory | 0x25456e | fwd |
| DH key agreement (driver) | +0x1e9 | jne | reg/arith | `0x254576: test %rdx,%rdx` | memory | 0x254675 | fwd |
| DH key agreement (driver) | +0x20a | je | reg/arith | `0x254598: test %eax,%eax` | memory | 0x254668 | fwd |
| DH key agreement (driver) | +0x276 | jne | reg/arith | `0x254603: cmp %rsi,%rdx` | arithmetic/control | 0x2545b8 | back |
| DH key agreement (driver) | +0x27b | je | reg/arith | `0x254608: test %rax,%rax` | memory | 0x254623 | fwd |
| DH key agreement (driver) | +0x291 | jne | reg/arith | `0x25461e: cmp %rdx,%rax` | memory | 0x254613 | back |
| DH key agreement (driver) | +0x2b1 | je | reg/arith | `0x254639: test %rax,%rax` | memory | 0x254658 | fwd |
| DH key agreement (driver) | +0x2e8 | je | reg/arith | `0x254675: test %rbp,%rbp` | memory | 0x25468d | fwd |
| DH key agreement (driver) | +0x305 | je | reg/arith | `0x254692: test %rax,%rax` | memory | 0x25469b | fwd |
| DH key agreement (driver) | +0x30e | je | reg/arith | `0x25469b: test %rdx,%rdx` | memory | 0x254780 | fwd |
| DH key agreement (driver) | +0x324 | je | reg/arith | `0x2546b1: test %rax,%rax` | memory | 0x2547ac | fwd |
| DH key agreement (driver) | +0x331 | je | reg/arith | `0x2546be: test %rax,%rax` | call+memory | 0x2547ac | fwd |
| DH key agreement (driver) | +0x357 | je | reg/arith | `0x2546e5: test %eax,%eax` | memory | 0x254797 | fwd |
| DH key agreement (driver) | +0x37a | je | reg/arith | `0x254707: test %rax,%rax` | memory | 0x2547a7 | fwd |
| DH key agreement (driver) | +0x390 | je | reg/arith | `0x25471e: test %eax,%eax` | memory | 0x2547a0 | fwd |
| DH key agreement (driver) | +0x3a6 | jle | reg/arith | `0x254734: test %eax,%eax` | memory | 0x2547a0 | fwd |
| DH key agreement (driver) | +0x3bf | je | reg/arith | `0x254746: test %eax,%eax` | memory | 0x2547a7 | fwd |
| DH key agreement (driver) | +0x3cf | jo | reg/arith | `0x25475c: add $0x7,%eax` | memory | 0x25487c | fwd |
| DH key agreement (driver) | +0x422 | je | reg/arith | `0x2547af: test %rdx,%rdx` | memory | 0x25483c | fwd |
| DH key agreement (driver) | +0x435 | jae | reg/arith | `0x2547c1: cmp $0x8,%rdx` | arithmetic/control | 0x2547cb | fwd |
| DH key agreement (driver) | +0x48f | jne | reg/arith | `0x25481c: cmp %rsi,%rdx` | arithmetic/control | 0x2547d1 | back |
| DH key agreement (driver) | +0x494 | je | reg/arith | `0x254821: test %rax,%rax` | memory | 0x25483c | fwd |
| DH key agreement (driver) | +0x4aa | jne | reg/arith | `0x254837: cmp %rdx,%rax` | memory | 0x25482c | back |
| DH key agreement (driver) | +0x4ca | je | reg/arith | `0x254852: test %rax,%rax` | memory | 0x254871 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3e | je | reg/arith | `0x1d3349: test %rax,%rax` | memory | 0x1d35b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x63 | je | reg/arith | `0x1d3380: cmp %rsi,%rdx` | memory | 0x1d35b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x72 | je | mem | `0x1d3389: cmpq $0x0,(%rcx,%rsi,1)` | memory | 0x1d3380 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x7b | je | reg/arith | `0x1d3398: test %rdx,%rdx` | memory | 0x1d35b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x93 | je | reg/arith | `0x1d33b0: cmp %rsi,%rdx` | memory | 0x1d35b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa2 | je | mem | `0x1d33b9: cmpq $0x0,(%rcx,%rsi,1)` | arithmetic/control | 0x1d33b0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xa7 | je | reg/arith | `0x1d33c4: cmp %rax,%r15` | arithmetic/control | 0x1d3585 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbb | je | reg/arith | `0x1d33d9: test %dl,%cl` | arithmetic/control | 0x1d3585 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc4 | je | reg/arith | `0x1d33e1: test %r13,%r13` | call | 0x1d356e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd7 | je | reg/arith | `0x1d33f5: test %al,%al` | memory | 0x1d356e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe2 | jne | mem | `0x1d33fd: cmpl $0x0,0x18(%r15)` | memory | 0x1d356e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf0 | ja | reg/arith | `0x1d340c: cmp $0x4,%rdx` | memory | 0x1d356e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x240 | je | reg/arith | `0x1d355e: test %al,%al` | call+memory | 0x1d4642 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x26f | jne | reg/arith | `0x1d358c: or %r15,%rcx` | memory | 0x1d35b0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x277 | je | reg/arith | `0x1d3594: cmp %rax,%rdx` | call+memory | 0x1d3650 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x293 | je | reg/arith | `0x1d35b0: test %r15,%r15` | memory | 0x1d3650 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2a0 | je | reg/arith | `0x1d35bd: test %r13,%r13` | memory | 0x1d3675 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2bf | je | reg/arith | `0x1d35d7: test %rax,%rax` | memory | 0x1d36ce | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2ca | je | mem | `0x1d35e5: cmpq $0x0,0x10(%rax)` | memory | 0x1d36ce | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2e2 | je | reg/arith | `0x1d35ff: test %rax,%rax` | memory | 0x1d3688 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2f6 | jne | mem | `0x1d3612: cmp 0x0(%r13),%rcx` | memory | 0x1d368f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x30a | je | reg/arith | `0x1d3628: test %esi,%esi` | memory | 0x1d36b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x317 | je | reg/arith | `0x1d3634: test %r8d,%r8d` | arithmetic/control | 0x1d363e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x31c | jne | reg/arith | `0x1d3639: cmp %r8d,%esi` | memory | 0x1d368f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x321 | jne | mem | `0x1d363e: cmp (%rdx),%rcx` | memory | 0x1d368f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x328 | je | reg/arith | `0x1d3646: test %ecx,%ecx` | arithmetic/control | 0x1d36bb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x32c | jne | reg/arith | `0x1d364a: cmp %ecx,%esi` | arithmetic/control | 0x1d368f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x399 | jne | mem | `0x1d36b6: cmp (%rdx),%rcx` | call | 0x1d368f | back |
| EC wNAF multiply (verification / public-scalar core) | +0x3a8 | je | reg/arith | `0x1d36c6: test %eax,%eax` | memory | 0x1d3d5d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3ee | jb | reg/arith | `0x1d370b: add %r12,%r15` | call+memory | 0x1d4ab5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x448 | je | reg/arith | `0x1d3764: cmp $0xffffffffffffffff,%r15` | call+memory | 0x1d4abe | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x488 | je | reg/arith | `0x1d37a5: test %r13,%r13` | memory | 0x1d39ef | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4a0 | je | mem | `0x1d37b6: cmpq $0x0,(%rsp)` | arithmetic/control | 0x1d3a52 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4a9 | je | reg/arith | `0x1d37c6: test %r14,%r14` | arithmetic/control | 0x1d3a52 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4b2 | je | reg/arith | `0x1d37cf: test %r12,%r12` | memory | 0x1d3a52 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4c5 | jb | mem | `0x1d37e0: add 0x48(%rsp),%rax` | memory | 0x1d4ad6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4dd | je | unknown | `?` | memory | 0x1d3b50 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x51a | jae | mem | `0x1d3835: cmp 0x48(%rsp),%rbx` | memory | 0x1d3845 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x535 | ja | reg/arith | `0x1d3850: cmp $0x7cf,%eax` | arithmetic/control | 0x1d3890 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x541 | ja | reg/arith | `0x1d385c: cmp $0x31f,%eax` | arithmetic/control | 0x1d3890 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x54d | ja | reg/arith | `0x1d3868: cmp $0x12b,%eax` | arithmetic/control | 0x1d3890 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x557 | ja | reg/arith | `0x1d3874: cmp $0x45,%eax` | memory | 0x1d3890 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x585 | jb | reg/arith | `0x1d38a2: add %rax,%r15` | memory | 0x1d4aeb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5a3 | jae | mem | `0x1d38be: cmp 0x48(%rsp),%rbx` | call+memory | 0x1d38ce | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5cd | je | reg/arith | `0x1d38ea: test %rax,%rax` | memory | 0x1d3b79 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5f6 | jne | reg/arith | `0x1d390e: dec %r13` | memory | 0x1d3830 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x609 | je | reg/arith | `0x1d3921: test %rbx,%rbx` | memory | 0x1d3b6f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x61c | je | reg/arith | `0x1d3934: test %rax,%rax` | memory | 0x1d3c3e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x633 | je | mem | `0x1d394e: cmpb $0x0,0x50(%rsp)` | call+memory | 0x1d3c72 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x667 | je | reg/arith | `0x1d397c: test %rax,%rax` | memory | 0x1d3c58 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x682 | jbe | mem | `0x1d3998: cmp 0x60(%rsp),%rcx` | arithmetic/control | 0x1d3d19 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x68e | jo | reg/arith | `0x1d39ab: mul %rsi` | memory | 0x1d4af8 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6a0 | jae | reg/arith | `0x1d39bd: cmp %rax,%rcx` | arithmetic/control | 0x1d3dfc | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6a9 | je | reg/arith | `0x1d39c6: test %rsi,%rsi` | arithmetic/control | 0x1d4b0a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6b9 | je | reg/arith | `0x1d39d5: shr $0x20,%rax` | division | 0x1d3d9e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6db | je | reg/arith | `0x1d39f3: test %rdi,%rdi` | call+memory | 0x1d3a20 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x703 | je | reg/arith | `0x1d3a20: test %rbx,%rbx` | memory | 0x1d3b1a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x739 | je | reg/arith | `0x1d3a56: test %rdi,%rdi` | call+memory | 0x1d3a7e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x761 | je | reg/arith | `0x1d3a7e: test %r14,%r14` | call+memory | 0x1d3aa9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x790 | je | reg/arith | `0x1d3aad: test %rdi,%rdi` | memory | 0x1d3af4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7d2 | jne | reg/arith | `0x1d3aef: test %rdi,%rdi` | call+memory | 0x1d3ad0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x7ff | je | reg/arith | `0x1d3b1c: test %r12,%r12` | call+memory | 0x1d42e0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x849 | jne | reg/arith | `0x1d3b61: test %rbx,%rbx` | memory | 0x1d392f | back |
| EC wNAF multiply (verification / public-scalar core) | +0x8ac | je | reg/arith | `0x1d3bc9: test %rdi,%rdi` | call+memory | 0x1d3c04 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8e2 | jne | reg/arith | `0x1d3bff: test %rdi,%rdi` | call+memory | 0x1d3be0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x926 | jne | mem | `0x1d3c3e: cmpb $0x0,0x88(%rsp)` | call+memory | 0x1d3f27 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x9b0 | je | reg/arith | `0x1d3ccd: test %rdi,%rdi` | call+memory | 0x1d4144 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x9f2 | jne | reg/arith | `0x1d3d0f: test %rdi,%rdi` | arithmetic/control | 0x1d3cf0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xa02 | je | reg/arith | `0x1d3d1e: cmp $0xffffffffffffffff,%rcx` | memory | 0x1d4b01 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa52 | je | reg/arith | `0x1d3d6f: test %rbx,%rbx` | arithmetic/control | 0x1d4b13 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa68 | je | reg/arith | `0x1d3d84: shr $0x20,%rdx` | division | 0x1d45bd | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa98 | jbe | mem | `0x1d3db4: cmp 0x10(%rax),%r12` | call+memory | 0x1d3df1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xad6 | jb | mem | `0x1d3df1: add 0x48(%rsp),%r12` | memory | 0x1d4b6c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xae9 | jae | reg/arith | `0x1d3e01: cmp %r12,%rbx` | memory | 0x1d3efa | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb13 | jae | mem | `0x1d3e29: cmp 0x58(%rsp),%rbx` | memory | 0x1d3e5e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb29 | jb | reg/arith | `0x1d3e46: sub %rsi,%rax` | memory | 0x1d4812 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb76 | je | reg/arith | `0x1d3e93: test %rax,%rax` | memory | 0x1d4537 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb95 | je | mem | `0x1d3eb1: cmpq $0x0,(%rdi)` | memory | 0x1d4581 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbd4 | jne | reg/arith | `0x1d3ef1: cmp %rbx,%r12` | call+memory | 0x1d3e29 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xc0b | je | reg/arith | `0x1d3f27: cmp $0xffffffffffffffff,%r15` | memory | 0x1d4adf | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc2f | je | reg/arith | `0x1d3f4c: test %rax,%rax` | memory | 0x1d40ba | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc55 | je | reg/arith | `0x1d3f68: test %rcx,%rcx` | memory | 0x1d407d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc88 | je | reg/arith | `0x1d3fa5: test %rcx,%rcx` | memory | 0x1d4b37 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc94 | je | mem | `0x1d3fae: cmpq $0x0,0x30(%rsp)` | memory | 0x1d4518 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xca4 | ja | reg/arith | `0x1d3fc0: cmp $0x40,%rcx` | arithmetic/control | 0x1d4b50 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xcb5 | jne | reg/arith | `0x1d3fd2: test %rax,%rax` | memory | 0x1d405f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xcc8 | je | mem | `0x1d3fe3: cmpq $0x0,0x50(%rax)` | memory | 0x1d419c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xce8 | je | reg/arith | `0x1d4005: test %rax,%rax` | memory | 0x1d4191 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd0c | je | reg/arith | `0x1d4029: test %rax,%rax` | call | 0x1d416b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd19 | je | reg/arith | `0x1d4037: test %eax,%eax` | memory | 0x1d416b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd34 | jne | reg/arith | `0x1d4051: test %rcx,%rcx` | arithmetic/control | 0x1d3fc0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xd57 | jne | reg/arith | `0x1d406a: cmp %rcx,%rbx` | memory | 0x1d3f98 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xd64 | je | reg/arith | `0x1d4081: cmp %rax,%r14` | call+memory | 0x1d42f1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdec | je | reg/arith | `0x1d4109: test %rdi,%rdi` | call+memory | 0x1d4144 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe22 | jne | reg/arith | `0x1d413f: test %rdi,%rdi` | memory | 0x1d4120 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xee9 | je | reg/arith | `0x1d4206: test %rdi,%rdi` | call+memory | 0x1d4244 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf22 | jne | reg/arith | `0x1d423f: test %rdi,%rdi` | call+memory | 0x1d4220 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xf50 | je | reg/arith | `0x1d426d: test %rdi,%rdi` | call+memory | 0x1d429f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf7d | jne | reg/arith | `0x1d429a: test %rdi,%rdi` | call+memory | 0x1d4290 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xfe2 | je | reg/arith | `0x1d42ff: test %rax,%rax` | memory | 0x1d4096 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xff0 | je | reg/arith | `0x1d430d: test %r14,%r14` | memory | 0x1d4496 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1019 | je | reg/arith | `0x1d4336: cmp %r14,%r12` | memory | 0x1d4496 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x102c | jae | mem | `0x1d4347: cmp 0x48(%rsp),%r12` | memory | 0x1d435c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x104c | je | reg/arith | `0x1d436a: test %eax,%eax` | memory | 0x1d44f3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x105b | jbe | mem | `0x1d4376: cmpq $0x1,(%rax,%r12,8)` | memory | 0x1d4333 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x107b | je | reg/arith | `0x1d4399: test %eax,%eax` | memory | 0x1d44f3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x108c | je | reg/arith | `0x1d43a9: test %rcx,%rcx` | arithmetic/control | 0x1d4b37 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x109b | ja | reg/arith | `0x1d43b7: cmp $0x40,%rcx` | arithmetic/control | 0x1d4b50 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10ac | jne | reg/arith | `0x1d43c9: test %rax,%rax` | memory | 0x1d4333 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x10c4 | je | reg/arith | `0x1d43e1: test %rax,%rax` | memory | 0x1d4886 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10d6 | jne | mem | `0x1d43f3: cmp (%rsi),%r9` | memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10eb | je | reg/arith | `0x1d4409: test %edi,%edi` | memory | 0x1d445b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10f4 | je | reg/arith | `0x1d4411: test %r8d,%r8d` | arithmetic/control | 0x1d441f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10f9 | jne | reg/arith | `0x1d4416: cmp %r8d,%edi` | memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1102 | jne | mem | `0x1d441f: cmp (%rdx),%r9` | memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x110f | je | reg/arith | `0x1d442c: test %r8d,%r8d` | arithmetic/control | 0x1d443a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1114 | jne | reg/arith | `0x1d4431: cmp %r8d,%edi` | memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1122 | jne | mem | `0x1d443f: cmp (%rcx),%r9` | memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x112f | je | reg/arith | `0x1d444c: test %r8d,%r8d` | arithmetic/control | 0x1d446e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1134 | je | reg/arith | `0x1d4451: cmp %r8d,%edi` | arithmetic/control | 0x1d446e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x113e | jne | mem | `0x1d445b: cmp (%rdx),%r9` | memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x114c | jne | mem | `0x1d4469: cmp (%rcx),%r9` | call+memory | 0x1d44e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x115b | je | reg/arith | `0x1d4479: test %eax,%eax` | memory | 0x1d44f3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x116b | jne | reg/arith | `0x1d4488: test %rcx,%rcx` | arithmetic/control | 0x1d43b7 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1188 | je | reg/arith | `0x1d44a5: test %rax,%rax` | call+memory | 0x1d44f3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11a2 | je | reg/arith | `0x1d44bb: test %eax,%eax` | memory | 0x1d486d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11b7 | jbe | reg/arith | `0x1d44cd: cmp $0x7fffffff,%rax` | memory | 0x1d4892 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11fc | jae | reg/arith | `0x1d4518: cmp $0x41,%rcx` | memory | 0x1d4b50 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12ac | je | reg/arith | `0x1d45c8: cmp $0xffffffffffffffff,%rdi` | memory | 0x1d4b22 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12cb | jb | reg/arith | `0x1d45e7: sub $0x1,%rcx` | arithmetic/control | 0x1d4b2b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12d5 | jae | reg/arith | `0x1d45f1: cmp $0x41,%rdx` | memory | 0x1d4b44 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12eb | jo | reg/arith | `0x1d4608: mul %rdx` | memory | 0x1d4b5d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12fa | jne | mem | `0x1d4616: cmp %rax,0x28(%rcx)` | memory | 0x1d4636 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13d2 | jne | reg/arith | `0x1d46f0: test %eax,%eax` | call+memory | 0x1d4ac7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1440 | je | reg/arith | `0x1d475e: test %al,%al` | call+memory | 0x1d47d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x145a | je | reg/arith | `0x1d4778: test %al,%al` | call+memory | 0x1d47d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1474 | je | reg/arith | `0x1d4792: test %al,%al` | call+memory | 0x1d47d5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1575 | je | reg/arith | `0x1d4892: test %rax,%rax` | memory | 0x1d4b78 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15a5 | jle | mem | `0x1d48b1: cmpl $0x1,0x58(%rsp)` | arithmetic/control | 0x1d4a1a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15b1 | jne | reg/arith | `0x1d48ce: test %r15d,%r15d` | memory | 0x1d48f5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15cf | je | reg/arith | `0x1d48ed: test %eax,%eax` | memory | 0x1d4a34 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15e7 | je | reg/arith | `0x1d48ff: test %r14,%r14` | arithmetic/control | 0x1d48b1 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1610 | je | reg/arith | `0x1d492e: test %eax,%eax` | memory | 0x1d44f3 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x161e | je | mem | `0x1d4939: cmp %r14,0x78(%rsp)` | memory | 0x1d48b1 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x162d | jbe | mem | `0x1d4949: cmp %r12,(%rax,%r14,8)` | memory | 0x1d4936 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x163f | je | reg/arith | `0x1d495d: test %ebx,%ebx` | memory | 0x1d4936 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x164a | je | mem | `0x1d4966: cmp %eax,0x48(%rsp)` | arithmetic/control | 0x1d499f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x164f | jne | reg/arith | `0x1d496c: test %r15d,%r15d` | memory | 0x1d4990 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x166a | je | reg/arith | `0x1d4988: test %eax,%eax` | memory | 0x1d44f3 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1699 | je | reg/arith | `0x1d49b6: test %r15d,%r15d` | memory | 0x1d4911 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x16b2 | je | reg/arith | `0x1d49d0: test %eax,%eax` | memory | 0x1d44f3 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x16cd | je | reg/arith | `0x1d49ea: test %rax,%rax` | call+memory | 0x1d4936 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x16e3 | jne | reg/arith | `0x1d4a01: test %eax,%eax` | call+memory | 0x1d4936 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x16fd | je | reg/arith | `0x1d4a1a: test %r15d,%r15d` | memory | 0x1d4a45 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x172a | je | mem | `0x1d4a45: cmpl $0x0,0x48(%rsp)` | memory | 0x1d4a67 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1745 | je | reg/arith | `0x1d4a63: test %eax,%eax` | call+memory | 0x1d4a93 | fwd |
| ML-KEM decapsulation (provider driver) | +0x7 | je | mem | `0x4a69c2: cmpq $0x0,0x50(%r8)` | arithmetic/control | 0x4a6b93 | fwd |
| ML-KEM decapsulation (provider driver) | +0x1f | jne | reg/arith | `0x4a69dc: or %r9b,%r10b` | memory | 0x4a6b93 | fwd |
| ML-KEM decapsulation (provider driver) | +0x5c | jne | reg/arith | `0x4a6a19: or %al,%sil` | memory | 0x4a6b6a | fwd |
| ML-KEM decapsulation (provider driver) | +0x66 | jne | mem | `0x4a6a22: cmp 0x28(%r15),%rcx` | memory | 0x4a6b6a | fwd |
| ML-KEM decapsulation (provider driver) | +0x8f | je | reg/arith | `0x4a6a4c: test %rax,%rax` | memory | 0x4a6b6a | fwd |
| ML-KEM decapsulation (provider driver) | +0xa2 | je | reg/arith | `0x4a6a5c: cmp $0x5ae,%ecx` | arithmetic/control | 0x4a6c7a | fwd |
| ML-KEM decapsulation (provider driver) | +0xae | je | reg/arith | `0x4a6a68: cmp $0x5af,%ecx` | arithmetic/control | 0x4a6b94 | fwd |
| ML-KEM decapsulation (provider driver) | +0xbc | jne | reg/arith | `0x4a6a76: cmp $0x5b0,%ecx` | call+memory | 0x4a6d65 | fwd |
| ML-KEM decapsulation (provider driver) | +0x163 | jne | reg/arith | `0x4a6b1c: cmp $0x1000,%r15` | memory | 0x4a6ad0 | back |
| ML-KEM decapsulation (provider driver) | +0x1a3 | jne | reg/arith | `0x4a6b5c: cmp $0x627,%rcx` | arithmetic/control | 0x4a6b30 | back |
| ML-KEM decapsulation (provider driver) | +0x26b | jne | reg/arith | `0x4a6c24: cmp $0xc07,%rcx` | memory | 0x4a6be0 | back |
| ML-KEM decapsulation (provider driver) | +0x2b3 | jne | reg/arith | `0x4a6c6c: cmp $0x447,%rcx` | arithmetic/control | 0x4a6c40 | back |
| ML-KEM decapsulation (provider driver) | +0x363 | jne | reg/arith | `0x4a6d1c: cmp $0x800,%r15` | memory | 0x4a6cd0 | back |
| ML-KEM decapsulation (provider driver) | +0x3a3 | jne | reg/arith | `0x4a6d5c: cmp $0x307,%rcx` | arithmetic/control | 0x4a6d30 | back |
| ML-KEM decapsulation (provider driver) | +0x3a8 | jne | reg/arith | `0x4a6d65: test $0x7,%bl` | memory | 0x4a6b82 | back |
| ML-KEM K-PKE decrypt | +0x65 | js | reg/arith | `0x196f52: test %r14,%r14` | memory | 0x19791b | fwd |
| ML-KEM K-PKE decrypt | +0x70 | jle | reg/arith | `0x196f5e: test %ebp,%ebp` | arithmetic/control | 0x197175 | fwd |
| ML-KEM K-PKE decrypt | +0x84 | ja | reg/arith | `0x196f70: cmp $0xf,%r14d` | memory | 0x19790e | fwd |
| ML-KEM K-PKE decrypt | +0x9f | jae | reg/arith | `0x196f87: cmp $0x20,%eax` | memory | 0x197928 | fwd |
| ML-KEM K-PKE decrypt | +0x140 | jae | reg/arith | `0x197029: cmp $0x100,%rdx` | arithmetic/control | 0x1970cb | fwd |
| ML-KEM K-PKE decrypt | +0x148 | jne | reg/arith | `0x197036: test %ecx,%ecx` | memory | 0x197046 | fwd |
| ML-KEM K-PKE decrypt | +0x169 | je | reg/arith | `0x197056: test %bl,%r11b` | memory | 0x197080 | fwd |
| ML-KEM K-PKE decrypt | +0x18b | jb | reg/arith | `0x197074: cmp $0x100,%rdx` | arithmetic/control | 0x197036 | back |
| ML-KEM K-PKE decrypt | +0x196 | jb | reg/arith | `0x197083: sub %eax,%r10d` | arithmetic/control | 0x197010 | back |
| ML-KEM K-PKE decrypt | +0x19d | jb | reg/arith | `0x19708b: sub %eax,%ecx` | arithmetic/control | 0x197a13 | fwd |
| ML-KEM K-PKE decrypt | +0x1a6 | ja | reg/arith | `0x197093: cmp $0xf,%ecx` | memory | 0x197a06 | fwd |
| ML-KEM K-PKE decrypt | +0x1d5 | jb | reg/arith | `0x1970be: cmp $0x100,%rdx` | memory | 0x197036 | back |
| ML-KEM K-PKE decrypt | +0x24e | jne | reg/arith | `0x197138: cmp $0x100,%rax` | call | 0x1970d0 | back |
| ML-KEM K-PKE decrypt | +0x27f | jg | reg/arith | `0x19716c: dec %r13d` | memory | 0x196ff0 | back |
| ML-KEM K-PKE decrypt | +0x28e | ja | reg/arith | `0x19717a: cmp $0xf,%r15d` | memory | 0x19790e | fwd |
| ML-KEM K-PKE decrypt | +0x2ef | jbe | reg/arith | `0x1971d8: cmp $0xff,%rsi` | arithmetic/control | 0x197212 | fwd |
| ML-KEM K-PKE decrypt | +0x320 | ja | reg/arith | `0x197209: cmp $0xff,%rsi` | arithmetic/control | 0x197272 | fwd |
| ML-KEM K-PKE decrypt | +0x324 | jne | reg/arith | `0x197212: test %ecx,%ecx` | memory | 0x197222 | fwd |
| ML-KEM K-PKE decrypt | +0x345 | jne | reg/arith | `0x197232: test %bl,%r11b` | arithmetic/control | 0x1971f0 | back |
| ML-KEM K-PKE decrypt | +0x34d | jb | reg/arith | `0x19723a: sub %eax,%r10d` | arithmetic/control | 0x1971c0 | back |
| ML-KEM K-PKE decrypt | +0x354 | jb | reg/arith | `0x197242: sub %eax,%ecx` | arithmetic/control | 0x197a13 | fwd |
| ML-KEM K-PKE decrypt | +0x35d | jae | reg/arith | `0x19724a: cmp $0x10,%ecx` | memory | 0x197a06 | fwd |
| ML-KEM K-PKE decrypt | +0x389 | ja | reg/arith | `0x197276: cmp $0x1f,%eax` | memory | 0x1979f9 | fwd |
| ML-KEM K-PKE decrypt | +0x43e | jne | reg/arith | `0x197328: cmp $0x100,%rax` | call+memory | 0x1972c0 | back |
| ML-KEM K-PKE decrypt | +0x4fc | jne | reg/arith | `0x1973e6: cmp $0x100,%rax` | memory | 0x197370 | back |
| ML-KEM K-PKE decrypt | +0x614 | jne | reg/arith | `0x1974fe: cmp $0x100,%rax` | memory | 0x197430 | back |
| ML-KEM K-PKE decrypt | +0x96b | jne | reg/arith | `0x197857: cmp $0x20,%rcx` | memory | 0x197560 | back |
| ML-KEM K-PKE decrypt | +0x9b2 | jne | reg/arith | `0x19789c: cmp $0x200,%rax` | memory | 0x197870 | back |
| ML-KEM K-PKE decrypt | +0xa0a | jne | reg/arith | `0x1978f4: cmp $0x200,%rax` | arithmetic/control | 0x1978b0 | back |
| ML-KEM K-PKE decrypt | +0xa66 | ja | reg/arith | `0x19794f: cmp $0xff,%rdx` | arithmetic/control | 0x1979f9 | fwd |
| ML-KEM K-PKE decrypt | +0xa6e | jne | reg/arith | `0x19795c: test %ecx,%ecx` | memory | 0x19796c | fwd |
| ML-KEM K-PKE decrypt | +0xa90 | je | reg/arith | `0x19797d: test %r11b,%r10b` | memory | 0x1979b0 | fwd |
| ML-KEM K-PKE decrypt | +0xab5 | jbe | reg/arith | `0x19799e: cmp $0xff,%rdx` | arithmetic/control | 0x19795c | back |
| ML-KEM K-PKE decrypt | +0xac6 | jb | reg/arith | `0x1979b3: sub %eax,%r9d` | arithmetic/control | 0x197937 | back |
| ML-KEM K-PKE decrypt | +0xad1 | jb | reg/arith | `0x1979bf: sub %eax,%ecx` | arithmetic/control | 0x197a13 | fwd |
| ML-KEM K-PKE decrypt | +0xad6 | jae | reg/arith | `0x1979c3: cmp $0x10,%ecx` | memory | 0x197a06 | fwd |
| ML-KEM K-PKE decrypt | +0xb03 | jbe | reg/arith | `0x1979ec: cmp $0xff,%rdx` | memory | 0x19795c | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xc3 | jle | reg/arith | `0x197acc: test %rbp,%rbp` | memory | 0x197b41 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x101 | je | reg/arith | `0x197b1f: test %eax,%eax` | call | 0x197b47 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x118 | jg | reg/arith | `0x197b36: dec %ebp` | arithmetic/control | 0x197b00 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1e5 | je | reg/arith | `0x197c03: test %al,%al` | memory | 0x197d12 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x2eb | jne | reg/arith | `0x197d04: cmp $0x200,%rcx` | arithmetic/control | 0x197cc0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x32e | jle | reg/arith | `0x197d46: test %r12d,%r12d` | memory | 0x198939 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x57d | jle | reg/arith | `0x197f8e: cmp $0x1,%r13d` | memory | 0x1988ac | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x624 | je | reg/arith | `0x198038: test $0x1,%sil` | memory | 0x198130 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x704 | jne | reg/arith | `0x19811d: cmp $0x100,%rcx` | arithmetic/control | 0x198050 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x958 | jne | reg/arith | `0x198371: cmp $0x100,%rdx` | memory | 0x198140 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x966 | je | reg/arith | `0x198383: cmp $0x1,%edx` | memory | 0x197f30 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xb04 | jle | reg/arith | `0x19851e: cmp $0x2,%edx` | arithmetic/control | 0x197f30 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xb0e | je | reg/arith | `0x19852c: test $0x1,%al` | memory | 0x198640 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xc11 | jne | reg/arith | `0x19862a: cmp $0x100,%rsi` | arithmetic/control | 0x198540 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xe81 | jne | reg/arith | `0x19889a: cmp $0x100,%rsi` | arithmetic/control | 0x198640 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xedf | je | reg/arith | `0x1988fd: test %eax,%eax` | memory | 0x198912 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xeee | jg | reg/arith | `0x19890c: dec %ebp` | memory | 0x1988e0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xfc6 | jne | reg/arith | `0x1989e4: test %al,%al` | memory | 0x19981e | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1032 | je | reg/arith | `0x198a50: test %al,%al` | memory | 0x198ae0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x10aa | jne | reg/arith | `0x198ac3: cmp $0x101,%r8` | arithmetic/control | 0x198a60 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1144 | jne | reg/arith | `0x198b5d: cmp $0x108,%r9` | arithmetic/control | 0x198af0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1148 | jo | reg/arith | `0x198b66: dec %edx` | arithmetic/control | 0x19992f | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x115e | jg | reg/arith | `0x198b7c: test %edx,%edx` | memory | 0x198a50 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x117a | ja | reg/arith | `0x198b8f: cmp $0x1f,%ecx` | memory | 0x19997d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1329 | jne | reg/arith | `0x198d42: cmp $0x100,%rdx` | arithmetic/control | 0x198c00 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1331 | jo | reg/arith | `0x198d4f: dec %eax` | arithmetic/control | 0x19993c | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1340 | jg | reg/arith | `0x198d5e: test %eax,%eax` | call+memory | 0x198bf0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x139a | je | reg/arith | `0x198db8: test %eax,%eax` | memory | 0x19981e | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1430 | jne | reg/arith | `0x198e4a: cmp $0x100,%rax` | memory | 0x198dd0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1bae | jne | reg/arith | `0x1995ca: cmp $0x20,%rax` | arithmetic/control | 0x198e70 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1bb8 | ja | reg/arith | `0x1995d4: cmp $0x1f,%r9d` | arithmetic/control | 0x19997d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1d60 | jne | reg/arith | `0x19977a: cmp $0x100,%rax` | memory | 0x199630 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1d92 | je | reg/arith | `0x1997ac: cmp $0x200,%rax` | arithmetic/control | 0x199822 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1d99 | jb | reg/arith | `0x1997b6: add %r9d,%esi` | memory | 0x199949 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1daa | jb | reg/arith | `0x1997c7: cmp $0x40,%esi` | arithmetic/control | 0x1997a0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dac | jne | unknown | `?` | arithmetic/control | 0x1997f0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1db1 | jae | reg/arith | `0x1997ce: cmp $0x40,%ecx` | memory | 0x199970 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dd3 | jae | reg/arith | `0x1997f0: cmp $0x40,%ecx` | memory | 0x199956 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1de7 | je | reg/arith | `0x199805: test %ecx,%ecx` | arithmetic/control | 0x199963 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1efb | jne | reg/arith | `0x199914: cmp $0x200,%rcx` | arithmetic/control | 0x1998d0 | back |
| ML-KEM inverse NTT | +0x56 | jb | reg/arith | `0x19a913: add %rsi,%rbx` | memory | 0x19adf4 | fwd |
| ML-KEM inverse NTT | +0x64 | ja | reg/arith | `0x19a920: cmp $0x7e,%r8` | memory | 0x19ae01 | fwd |
| ML-KEM inverse NTT | +0xb8 | jbe | reg/arith | `0x19a974: cmp $0x7,%r8` | memory | 0x19a9cf | fwd |
| ML-KEM inverse NTT | +0x101 | jae | reg/arith | `0x19a9be: cmp %r13,%r14` | memory | 0x19a9e0 | fwd |
| ML-KEM inverse NTT | +0x10d | jae | reg/arith | `0x19a9ca: cmp %r12,%r15` | arithmetic/control | 0x19a9e0 | fwd |
| ML-KEM inverse NTT | +0x2fa | jne | reg/arith | `0x19abb7: cmp %r13,%r8` | memory | 0x19aa10 | back |
| ML-KEM inverse NTT | +0x317 | ja | reg/arith | `0x19abd0: cmp $0xff,%r8` | arithmetic/control | 0x19addf | fwd |
| ML-KEM inverse NTT | +0x324 | jae | reg/arith | `0x19abdd: cmp $0x100,%rcx` | memory | 0x19adca | fwd |
| ML-KEM inverse NTT | +0x3b4 | jb | reg/arith | `0x19ac71: cmp %rbx,%r8` | arithmetic/control | 0x19abd0 | back |
| ML-KEM inverse NTT | +0x3c4 | jne | reg/arith | `0x19ac7d: cmp $0x100,%rcx` | arithmetic/control | 0x19a910 | back |
| ML-KEM inverse NTT | +0x3d4 | jb | reg/arith | `0x19ac8d: cmp $0x100,%rsi` | memory | 0x19a900 | back |
| ML-KEM inverse NTT | +0x4f5 | jne | reg/arith | `0x19adaf: cmp $0x100,%rax` | arithmetic/control | 0x19acb0 | back |
| ML-KEM inner product | +0x5b | jne | reg/arith | `0x199b58: test %r12b,%r15b` | arithmetic/control | 0x199e0b | fwd |
| ML-KEM inner product | +0x64 | jne | reg/arith | `0x199b61: and %bpl,%r8b` | arithmetic/control | 0x199e0b | fwd |
| ML-KEM inner product | +0x6d | jne | reg/arith | `0x199b6a: and %r14b,%r10b` | memory | 0x199e0b | fwd |
| ML-KEM inner product | +0x300 | jne | reg/arith | `0x199df9: cmp $0x100,%r8` | arithmetic/control | 0x199ba0 | back |
| ML-KEM inner product | +0x3fa | jne | reg/arith | `0x199ef3: cmp $0x100,%r14` | arithmetic/control | 0x199e20 | back |
| ML-KEM inner product | +0x406 | jo | reg/arith | `0x199f03: dec %r8d` | arithmetic/control | 0x19a394 | fwd |
| ML-KEM inner product | +0x40f | jle | reg/arith | `0x199f0c: test %r8d,%r8d` | memory | 0x19a385 | fwd |
| ML-KEM inner product | +0x4c1 | jle | reg/arith | `0x199fbe: dec %r8d` | arithmetic/control | 0x19a385 | fwd |
| ML-KEM inner product | +0x4cc | je | reg/arith | `0x199fca: test %cl,%cl` | memory | 0x19a0f0 | fwd |
| ML-KEM inner product | +0x5dc | jne | reg/arith | `0x19a0d5: cmp $0x100,%r10` | arithmetic/control | 0x199fe0 | back |
| ML-KEM inner product | +0x87a | jne | reg/arith | `0x19a373: cmp $0x100,%r10` | arithmetic/control | 0x19a0f0 | back |
| ML-KEM matrix transpose-multiply-add | +0x1b | jle | reg/arith | `0x19ae39: test %ecx,%ecx` | memory | 0x19b79c | fwd |
| ML-KEM matrix transpose-multiply-add | +0x16f | jle | reg/arith | `0x19af81: cmp $0x1,%eax` | memory | 0x19b79c | fwd |
| ML-KEM matrix transpose-multiply-add | +0x17f | je | mem | `0x19af9a: cmpb $0x0,-0x62(%rsp)` | memory | 0x19b0a0 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x26e | jne | reg/arith | `0x19b087: cmp $0x100,%r11` | arithmetic/control | 0x19afb0 | back |
| ML-KEM matrix transpose-multiply-add | +0x510 | jne | reg/arith | `0x19b32a: cmp $0x100,%rax` | memory | 0x19b0b0 | back |
| ML-KEM matrix transpose-multiply-add | +0x51b | je | mem | `0x19b336: cmpl $0x1,-0x60(%rsp)` | memory | 0x19af60 | back |
| ML-KEM matrix transpose-multiply-add | +0x5c7 | jle | reg/arith | `0x19b3dc: cmp $0x2,%r9d` | memory | 0x19af60 | back |
| ML-KEM matrix transpose-multiply-add | +0x5d2 | je | mem | `0x19b3ed: cmpb $0x0,-0x61(%rsp)` | memory | 0x19b500 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x6d1 | jne | reg/arith | `0x19b4ea: cmp $0x100,%rbp` | arithmetic/control | 0x19b400 | back |
| ML-KEM matrix transpose-multiply-add | +0x971 | jne | reg/arith | `0x19b78a: cmp $0x100,%rbp` | arithmetic/control | 0x19b510 | back |
| ML-KEM matrix expansion (public) | +0x3f | jle | reg/arith | `0x19a3ed: test %ecx,%ecx` | memory | 0x19a5b1 | fwd |
| ML-KEM matrix expansion (public) | +0x6c | je | mem | `0x19a417: cmp 0x4(%rsp),%r14d` | call+memory | 0x19a5a2 | fwd |
| ML-KEM matrix expansion (public) | +0x92 | je | reg/arith | `0x19a440: test %eax,%eax` | memory | 0x19a5d7 | fwd |
| ML-KEM matrix expansion (public) | +0xad | je | reg/arith | `0x19a45b: test %eax,%eax` | memory | 0x19a5d7 | fwd |
| ML-KEM matrix expansion (public) | +0x116 | je | reg/arith | `0x19a4c3: test %rax,%rax` | memory | 0x19a5b9 | fwd |
| ML-KEM matrix expansion (public) | +0x121 | je | mem | `0x19a4cc: cmpq $0x0,0x70(%rax)` | memory | 0x19a5c2 | fwd |
| ML-KEM matrix expansion (public) | +0x131 | je | reg/arith | `0x19a4de: test %rax,%rax` | memory | 0x19a5cb | fwd |
| ML-KEM matrix expansion (public) | +0x13e | je | reg/arith | `0x19a4eb: test %rdi,%rdi` | call+memory | 0x19a5d7 | fwd |
| ML-KEM matrix expansion (public) | +0x160 | je | reg/arith | `0x19a50e: test %eax,%eax` | arithmetic/control | 0x19a5d7 | fwd |
| ML-KEM matrix expansion (public) | +0x17a | je | reg/arith | `0x19a524: cmp $0xaa,%rax` | arithmetic/control | 0x19a590 | fwd |
| ML-KEM matrix expansion (public) | +0x183 | ja | reg/arith | `0x19a52c: cmp $0xff,%r13` | memory | 0x19a410 | back |
| ML-KEM matrix expansion (public) | +0x1a9 | ja | reg/arith | `0x19a553: cmp $0xd00,%esi` | memory | 0x19a570 | fwd |
| ML-KEM matrix expansion (public) | +0x1b7 | je | reg/arith | `0x19a560: cmp $0xff,%r13` | arithmetic/control | 0x19a410 | back |
| ML-KEM matrix expansion (public) | +0x1d4 | ja | reg/arith | `0x19a57e: cmp $0xd00,%ecx` | memory | 0x19a520 | back |
| ML-KEM matrix expansion (public) | +0x1e7 | jb | reg/arith | `0x19a590: cmp $0x100,%r13` | arithmetic/control | 0x19a4bf | back |
| ML-KEM matrix expansion (public) | +0x1fb | jne | mem | `0x19a5a7: cmp 0x4(%rsp),%ebp` | arithmetic/control | 0x19a3fa | back |
| ML-KEM vector decode 12-bit | +0x2 | jle | reg/arith | `0x19a6f0: test %edx,%edx` | memory | 0x19a772 | fwd |
| ML-KEM vector decode 12-bit | +0x17 | je | reg/arith | `0x19a700: cmp $0x80,%rcx` | memory | 0x19a760 | fwd |
| ML-KEM vector decode 12-bit | +0x54 | ja | reg/arith | `0x19a73d: cmp $0xd00,%r11d` | arithmetic/control | 0x19a777 | fwd |
| ML-KEM vector decode 12-bit | +0x68 | jb | reg/arith | `0x19a751: cmp $0xd01,%r9d` | arithmetic/control | 0x19a700 | back |
| ML-KEM vector decode 12-bit | +0x80 | jg | reg/arith | `0x19a76e: dec %edx` | arithmetic/control | 0x19a6f4 | back |
| ML-KEM vector encode | +0x7 | js | reg/arith | `0x19a605: test %edx,%edx` | arithmetic/control | 0x19a6e0 | fwd |
| ML-KEM vector encode | +0x11 | jle | reg/arith | `0x19a60f: test %ecx,%ecx` | arithmetic/control | 0x19a6a6 | fwd |
| ML-KEM vector encode | +0x2c | jle | reg/arith | `0x19a62a: dec %eax` | arithmetic/control | 0x19a6a6 | fwd |
| ML-KEM vector encode | +0x53 | je | reg/arith | `0x19a64c: cmp $0x200,%r10` | arithmetic/control | 0x19a620 | back |
| ML-KEM vector encode | +0x59 | jb | reg/arith | `0x19a657: add %edx,%ebx` | memory | 0x19a6ac | fwd |
| ML-KEM vector encode | +0x63 | jb | reg/arith | `0x19a660: cmp $0x40,%ebx` | arithmetic/control | 0x19a640 | back |
| ML-KEM vector encode | +0x65 | jne | unknown | `?` | arithmetic/control | 0x19a680 | fwd |
| ML-KEM vector encode | +0x6a | jae | reg/arith | `0x19a667: cmp $0x40,%ecx` | memory | 0x19a6d3 | fwd |
| ML-KEM vector encode | +0x83 | jae | reg/arith | `0x19a680: cmp $0x40,%ecx` | memory | 0x19a6b9 | fwd |
| ML-KEM vector encode | +0x93 | je | reg/arith | `0x19a691: test %ecx,%ecx` | arithmetic/control | 0x19a6c6 | fwd |
| ML-KEM CBD sampling eta=2 | +0x51 | je | reg/arith | `0x19b93f: test %eax,%eax` | memory | 0x19ba81 | fwd |
| ML-KEM CBD sampling eta=2 | +0x13a | jne | reg/arith | `0x19ba24: cmp $0x80,%rax` | memory | 0x19b960 | back |
| ML-KEM CBD sampling eta=2 | +0x181 | jne | reg/arith | `0x19ba6b: cmp $0x80,%rax` | arithmetic/control | 0x19ba40 | back |
| ML-KEM CBD sampling eta=2 | +0x1d2 | jne | reg/arith | `0x19babb: cmp $0x80,%rcx` | arithmetic/control | 0x19ba90 | back |
| ML-KEM CBD sampling eta=3 | +0x71 | je | reg/arith | `0x19bb3f: test %eax,%eax` | memory | 0x19bed1 | fwd |
| ML-KEM CBD sampling eta=3 | +0x3aa | jne | reg/arith | `0x19be76: cmp $0x40,%rcx` | memory | 0x19bb70 | back |
| ML-KEM CBD sampling eta=3 | +0x3f1 | jne | reg/arith | `0x19bebb: cmp $0xc7,%rax` | arithmetic/control | 0x19be90 | back |
| ML-KEM CBD sampling eta=3 | +0x441 | jne | reg/arith | `0x19bf0b: cmp $0xc7,%rax` | arithmetic/control | 0x19bee0 | back |
| ML-KEM CBD vector sampling then NTT | +0x21 | jle | reg/arith | `0x19a79e: test %r8d,%r8d` | memory | 0x19a800 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x60 | je | reg/arith | `0x19a7de: test %eax,%eax` | call | 0x19a7f7 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x73 | jg | reg/arith | `0x19a7f1: dec %ebx` | arithmetic/control | 0x19a7c0 | back |
| ML-KEM hash H | +0x2e | je | reg/arith | `0x19c00c: test %eax,%eax` | memory | 0x19c07d | fwd |
| ML-KEM hash H | +0x49 | je | reg/arith | `0x19c027: test %eax,%eax` | arithmetic/control | 0x19c064 | fwd |
| ML-KEM hash H | +0x4e | je | reg/arith | `0x19c02b: test %rbx,%rbx` | memory | 0x19c03e | fwd |
| ML-KEM hash H | +0x56 | je | reg/arith | `0x19c033: test %rax,%rax` | memory | 0x19c03e | fwd |
| ML-KEM hash H | +0x5c | jne | mem | `0x19c038: testb $0x2,0x10(%rax)` | memory | 0x19c069 | fwd |
| ML-KEM hash G | +0x2e | je | reg/arith | `0x19bf4c: test %eax,%eax` | memory | 0x19bfbd | fwd |
| ML-KEM hash G | +0x49 | je | reg/arith | `0x19bf67: test %eax,%eax` | arithmetic/control | 0x19bfa4 | fwd |
| ML-KEM hash G | +0x4e | je | reg/arith | `0x19bf6b: test %rbx,%rbx` | memory | 0x19bf7e | fwd |
| ML-KEM hash G | +0x56 | je | reg/arith | `0x19bf73: test %rax,%rax` | memory | 0x19bf7e | fwd |
| ML-KEM hash G | +0x5c | jne | mem | `0x19bf78: testb $0x2,0x10(%rax)` | memory | 0x19bfa9 | fwd |
| ML-KEM public-key hash | +0x59 | je | reg/arith | `0x1999e7: test %eax,%eax` | memory | 0x199adb | fwd |
| ML-KEM public-key hash | +0x96 | je | reg/arith | `0x199a1f: cmp $0x200,%rsi` | memory | 0x199a70 | fwd |
| ML-KEM public-key hash | +0xa5 | jbe | reg/arith | `0x199a32: cmp $0x33,%eax` | memory | 0x199a10 | back |
| ML-KEM public-key hash | +0xb9 | je | reg/arith | `0x199a45: cmp $0x40,%r8d` | arithmetic/control | 0x199a61 | fwd |
| ML-KEM public-key hash | +0xf6 | je | reg/arith | `0x199a84: test %eax,%eax` | memory | 0x199adb | fwd |
| ML-KEM public-key hash | +0x109 | jb | reg/arith | `0x199a96: cmp %rax,%rbp` | memory | 0x199a00 | back |
| ML-KEM public-key hash | +0x123 | je | reg/arith | `0x199ab1: test %eax,%eax` | memory | 0x199adb | fwd |
| ML-KEM KDF | +0x2a | je | reg/arith | `0x19b7d8: test %eax,%eax` | memory | 0x19b81e | fwd |
| ML-KEM KDF | +0x3f | je | reg/arith | `0x19b7ed: test %eax,%eax` | memory | 0x19b81e | fwd |
| ML-KEM KDF | +0x52 | je | reg/arith | `0x19b800: test %eax,%eax` | memory | 0x19b81e | fwd |
| ML-KEM PRF | +0x2d | je | reg/arith | `0x19b85b: test %eax,%eax` | memory | 0x19b8ca | fwd |
| ML-KEM PRF | +0x46 | je | reg/arith | `0x19b874: test %eax,%eax` | arithmetic/control | 0x19b8b3 | fwd |
| ML-KEM PRF | +0x4b | je | reg/arith | `0x19b878: test %r14,%r14` | memory | 0x19b88b | fwd |
| ML-KEM PRF | +0x53 | je | reg/arith | `0x19b880: test %rax,%rax` | memory | 0x19b88b | fwd |
| ML-KEM PRF | +0x59 | jne | mem | `0x19b885: testb $0x2,0x10(%rax)` | memory | 0x19b8b8 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xa0 | je | reg/arith | `0x4a951e: test %eax,%eax` | memory | 0x4a962f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xb9 | je | reg/arith | `0x4a9537: test %eax,%eax` | memory | 0x4a962f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xd0 | je | reg/arith | `0x4a954e: test %eax,%eax` | memory | 0x4a962f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xeb | je | reg/arith | `0x4a9569: test %eax,%eax` | call+memory | 0x4a962f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x155 | je | reg/arith | `0x4a95cb: test %eax,%eax` | call+memory | 0x4a970c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x178 | je | reg/arith | `0x4a95f6: test %eax,%eax` | memory | 0x4a970c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x185 | je | reg/arith | `0x4a9602: test %rax,%rax` | arithmetic/control | 0x4a972e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x18e | je | reg/arith | `0x4a960b: test %r14,%r14` | memory | 0x4a973d | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x1a0 | jae | reg/arith | `0x4a9614: cmp $0x4,%rax` | arithmetic/control | 0x4a974f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x2d3 | jae | reg/arith | `0x4a974f: cmp $0x20,%rax` | arithmetic/control | 0x4a975b | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x31b | jne | reg/arith | `0x4a9798: cmp %rdx,%rcx` | arithmetic/control | 0x4a976c | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x354 | je | reg/arith | `0x4a97d1: cmp %rcx,%rax` | arithmetic/control | 0x4a9841 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x358 | je | reg/arith | `0x4a97d6: test $0x1c,%al` | memory | 0x4a982e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x386 | jne | reg/arith | `0x4a9803: cmp %rsi,%rcx` | arithmetic/control | 0x4a97f0 | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x3bf | jne | reg/arith | `0x4a983c: cmp %rcx,%rax` | memory | 0x4a982e | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x427 | jne | reg/arith | `0x4a98a3: cmp $0x20,%rcx` | memory | 0x4a9870 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x58 | ja | reg/arith | `0x196b30: cmp $0x7e,%rax` | memory | 0x196ed1 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xb0 | jbe | reg/arith | `0x196b8c: cmp $0x7,%r8` | memory | 0x196be7 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xf9 | jae | reg/arith | `0x196bd6: cmp %r13,%r14` | memory | 0x196bf0 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x105 | jae | reg/arith | `0x196be2: cmp %r12,%r15` | arithmetic/control | 0x196bf0 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2c0 | jne | reg/arith | `0x196d9d: cmp %r13,%r8` | memory | 0x196c30 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2d7 | ja | reg/arith | `0x196db0: cmp $0xff,%r8` | arithmetic/control | 0x196ebc | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2e4 | jae | reg/arith | `0x196dbd: cmp $0x100,%rcx` | memory | 0x196ea7 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x392 | jb | reg/arith | `0x196e6f: cmp %rbx,%r8` | arithmetic/control | 0x196db0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x39f | jne | reg/arith | `0x196e78: cmp $0x100,%rcx` | arithmetic/control | 0x196b30 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x3b2 | ja | reg/arith | `0x196e8b: cmp $0x3,%rsi` | arithmetic/control | 0x196b20 | back |
