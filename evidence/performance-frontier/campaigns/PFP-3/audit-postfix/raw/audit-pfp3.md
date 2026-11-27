# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp3-ctgrind-postfix/a/libcrypto.so.3`
- SHA-256: `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053`
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
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_sos_into` @ 0x19ecf0 | 1013 | 249 | 19 | 0 | 0 | 10 | 0 | 0 | 5 | 0 |
| Montgomery ladder carrier (ladder multiplies inlined here) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith15run_mont_ladder` @ 0x19d9a0 | 3383 | 734 | 51 | 0 | 2 | 11 | 0 | 0 | 49 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x161190 | 961 | 231 | 17 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x19f700 (carries `mod_exp_core_consttime_from_parts`) | 1693 | 430 | 42 | 0 | 2 | 4 | 0 | 0 | 20 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x5894e0 | 9817 | 2259 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x58f6b0 | 3158 | 780 | 125 | 0 | 5 | 7 | 1 | 0 | 78 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x2a5140 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x24e940 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x248390 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x248180 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| DH key agreement (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2dh3key19ossl_dh_compute_key` @ 0x58cbe0 | 1281 | 294 | 36 | 0 | 1 | 0 | 1 | 0 | 32 | 0 |
| EC wNAF multiply (verification / public-scalar core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` @ 0x58d660 | 7402 | 1577 | 183 | 4 | 34 | 5 | 2 | 0 | 106 | 0 |
| ML-KEM decapsulation (provider driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` @ 0x4060d0 | 998 | 210 | 15 | 0 | 1 | 4 | 0 | 0 | 13 | 0 |
| ML-KEM K-PKE decrypt | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11decrypt_cpa` @ 0x597260 | 2864 | 683 | 37 | 0 | 0 | 6 | 0 | 0 | 10 | 0 |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11encrypt_cpa` @ 0x597d90 | 8826 | 1816 | 45 | 0 | 6 | 38 | 2 | 0 | 16 | 0 |
| ML-KEM inverse NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith18scalar_inverse_ntt` @ 0x59af10 | 1366 | 295 | 12 | 0 | 13 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM inner product | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13inner_product` @ 0x59a180 | 2161 | 443 | 10 | 0 | 2 | 8 | 1 | 0 | 1 | 0 |
| ML-KEM matrix transpose-multiply-add | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith25matrix_mult_transpose_add` @ 0x59b470 | 2376 | 498 | 10 | 0 | 3 | 8 | 0 | 0 | 0 | 0 |
| ML-KEM matrix expansion (public) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13matrix_expand` @ 0x59aa00 | 584 | 134 | 16 | 0 | 0 | 0 | 0 | 0 | 6 | 0 |
| ML-KEM vector decode 12-bit | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith16vector_decode_12` @ 0x59ad40 | 136 | 35 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-KEM vector encode | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13vector_encode` @ 0x59ac50 | 237 | 71 | 10 | 0 | 0 | 0 | 0 | 0 | 5 | 0 |
| ML-KEM CBD sampling eta=2 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_2` @ 0x59bf00 | 413 | 93 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD sampling eta=3 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_3` @ 0x59c0a0 | 1021 | 239 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD vector sampling then NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` @ 0x59add0 | 312 | 83 | 3 | 0 | 0 | 1 | 0 | 0 | 2 | 0 |
| ML-KEM hash H | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_h` @ 0x59c560 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM hash G | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_g` @ 0x59c4a0 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM public-key hash | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13hash_h_pubkey` @ 0x59a010 | 358 | 104 | 7 | 0 | 0 | 2 | 0 | 0 | 6 | 0 |
| ML-KEM KDF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3kdf` @ 0x59bdc0 | 128 | 46 | 3 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM PRF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3prf` @ 0x59be40 | 177 | 60 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600` @ 0x408ca0 | 1554 | 341 | 16 | 0 | 1 | 1 | 0 | 0 | 9 | 0 |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith10scalar_ntt.llvm.17302346640931933067` @ 0x596e50 | 1030 | 235 | 10 | 0 | 14 | 0 | 0 | 0 | 3 | 0 |

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
| `key::decap` | `3key5decap.llvm.14923596394123754600` | 1554 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` | +0x108, +0x216, +0x300 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |
| `arith::scalar_ntt` | `5arith10scalar_ntt.llvm.17302346640931933067` | 1030 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` | +0x65 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **ML-KEM decapsulation carrier (implicit-rejection comparison + select)** recorded check: src/ml_kem/key.rs::decap is the only body of the identifier. The release DSO has no unsuffixed symbol for it; the only defined .text symbol of that identifier is the .llvm.<digits> local copy, and ossl_ml_kem_decap calls that entry directly at three sites. The copy contains the inlined CRYPTO_memcmp accumulation, the constant_time_eq_int_8 mask and the constant_time_select_8 store loop of src/ml_kem/key.rs:633-639.

- **ML-KEM forward NTT (used by re-encryption on secret-derived data)** recorded check: src/ml_kem/arith.rs::scalar_ntt has no unsuffixed out-of-line body in the release DSO; its only defined .text symbol of that identifier is the .llvm.<digits> local copy. gencbd_vector_ntt calls that entry directly, and the same single entry is the target of two further direct calls in the file (recorded in MLKEM-REJECTION.md). The loop bounds are fixed by the degree; the value-dependent reductions compile to cmovcc, which the per-function counts report.

## Comparison-result branch contract

Register taint is seeded on the XOR/OR comparison accumulation and propagated over the basic-block CFG. `public-bound` means no tracked comparison register reaches the condition, not that the branch is harmless. Memory and implicit flow are not modelled.

### ML-KEM decapsulation carrier (implicit-rejection comparison + select)

- accumulated registers: `xmm0`, `xmm1`
- accumulation loop 0x408f8c..0x408fbb: `xmm0`, `xmm1`

| kind | addr | instruction | condition source | class |
|---|---|---|---|---|
| jcc | `0x408d40` | `je 408e4f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x1af>` | `0x408d3e: test %eax,%eax` | **public-bound** |
| jcc | `0x408d59` | `je 408e4f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x1af>` | `0x408d57: test %eax,%eax` | **public-bound** |
| jcc | `0x408d70` | `je 408e4f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x1af>` | `0x408d6e: test %eax,%eax` | **public-bound** |
| jcc | `0x408d8b` | `je 408e4f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x1af>` | `0x408d89: test %eax,%eax` | **public-bound** |
| jcc | `0x408df5` | `je 408f2c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x28c>` | `0x408deb: test %eax,%eax` | **public-bound** |
| jcc | `0x408e18` | `je 408f2c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x28c>` | `0x408e16: test %eax,%eax` | **public-bound** |
| jcc | `0x408e25` | `je 408f4e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x2ae>` | `0x408e22: test %rax,%rax` | **public-bound** |
| jcc | `0x408e2e` | `je 408f5d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x2bd>` | `0x408e2b: test %r14,%r14` | **public-bound** |
| jcc | `0x408e40` | `jae 408f6f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x2cf>` | `0x408e34: cmp $0x4,%rax` | **public-bound** |
| jcc | `0x408f73` | `jae 408f7b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x2db>` | `0x408f6f: cmp $0x20,%rax` | **public-bound** |
| jcc | `0x408fbb` | `jne 408f8c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x2ec>` | `0x408fb8: cmp %rdx,%rcx` | **public-bound** |
| jcc | `0x408ff4` | `je 409061 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x3c1>` | `0x408ff1: cmp %rcx,%rax` | **public-bound** |
| jcc | `0x408ff8` | `je 40904e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x3ae>` | `0x408ff6: test $0x1c,%al` | **public-bound** |
| jcc | `0x409026` | `jne 409010 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x370>` | `0x409023: cmp %rsi,%rcx` | **public-bound** |
| jcc | `0x40905f` | `jne 40904e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x3ae>` | `0x40905c: cmp %rcx,%rax` | **public-bound** |
| setcc | `0x409065` | `setne %al` | `0x409063: test %dl,%dl` | **secret-derived** |
| cmov | `0x409086` | `cmovne %rcx,%rdx` | `0x409079: cmpl $0x0,0xa0(%rsp)` | **public-bound** |
| jcc | `0x4090c7` | `jne 409090 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.14923596394123754600+0x3f0>` | `0x4090c3: cmp $0x20,%rcx` | **public-bound** |

- secret-derived conditional jumps: 0
- undetermined conditions: 0

## Divisions

- **EC wNAF multiply (verification / public-scalar core)** `+0x770` (0x58ddd0): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0xafd` (0x58e15d): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0xb5c` (0x58e1bc): `div %esi`
- **EC wNAF multiply (verification / public-scalar core)** `+0x139d` (0x58e9fd): `div %esi`

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d368, 0x16d389, 0x16d3aa, 0x16d3c1, 0x16d413, 0x16d42a, 0x16d5b5, 0x16d6c3, 0x16d769, 0x16d928, 0x24883b, 0x24b4a4, 0x24b512, 0x24b580, 0x24b5ee, 0x2d1ccc, 0x2d3f8c, 0x3526fc, 0x35272c, 0x3c126c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x33 | jne | reg/arith | `0x19ed20: or %r9,%rax` | memory | 0x19ee40 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x4c | jne | reg/arith | `0x19ed39: cmp %rax,%rcx` | memory | 0x19ee40 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x7d | je | reg/arith | `0x19ed6a: test %r14,%r14` | memory | 0x19ee42 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xe1 | je | reg/arith | `0x19edce: cmp %rdi,%rbp` | memory | 0x19ee51 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xf4 | je | reg/arith | `0x19ede1: test %rax,%rax` | memory | 0x19eda0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x142 | jne | reg/arith | `0x19ee2f: cmp %r8,%r13` | arithmetic/control | 0x19edf0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x148 | jne | reg/arith | `0x19ee34: test $0x1,%dil` | arithmetic/control | 0x19eda0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1bd | je | reg/arith | `0x19eeaa: cmp %rdi,%rax` | memory | 0x19ef5a | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1cb | je | mem | `0x19eeb3: cmp 0x90(%rsp),%r9` | memory | 0x19f0aa | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x203 | je | reg/arith | `0x19eef0: cmp %rsi,%rbx` | memory | 0x19f08f | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x22f | jne | reg/arith | `0x19ef1c: cmp %rsi,%rdi` | memory | 0x19eef0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x23d | je | mem | `0x19ef28: cmp 0x28(%rsp),%r9` | memory | 0x19ee90 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x263 | jne | reg/arith | `0x19ef50: cmp %rax,%rbp` | arithmetic/control | 0x19ef40 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x282 | je | reg/arith | `0x19ef6f: test %rdx,%rdx` | memory | 0x19efe2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2e8 | jne | reg/arith | `0x19efd5: cmp %rsi,%r13` | arithmetic/control | 0x19efa0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2ee | jne | reg/arith | `0x19efda: test $0x1,%dil` | arithmetic/control | 0x19effd | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x367 | jae | reg/arith | `0x19f054: cmp %r14,%rcx` | arithmetic/control | 0x19f0d2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x36c | je | reg/arith | `0x19f059: cmp %r10,%rdi` | memory | 0x19f0c2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x398 | jne | reg/arith | `0x19f084: add $0xfffffffffffffff8,%r8` | arithmetic/control | 0x19f050 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e | jne | reg/arith | `0x19d9ca: shr $0x3a,%rax` | memory | 0x19e022 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4d | jbe | reg/arith | `0x19d9ea: cmp %rbx,%rdx` | call+memory | 0x19dad0 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6c | je | reg/arith | `0x19da08: cmp $0xffffffffffffffff,%r12` | memory | 0x19db9b | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8d | jne | reg/arith | `0x19da22: test %rbx,%rbx` | memory | 0x19de54 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc7 | jne | reg/arith | `0x19da65: or %al,%cl` | memory | 0x19daa8 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x106 | jne | reg/arith | `0x19daa3: cmp %rax,%rsi` | arithmetic/control | 0x19da70 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10b | je | reg/arith | `0x19daa8: test %r12,%r12` | memory | 0x19dabb | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x141 | jne | reg/arith | `0x19dade: test %rbx,%rbx` | memory | 0x19dd53 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x18c | jne | reg/arith | `0x19db28: cmp $0xffffffffffffffff,%rax` | memory | 0x19dc37 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x19c | je | reg/arith | `0x19db39: test %rbx,%rbx` | memory | 0x19dbaa | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1e6 | jne | reg/arith | `0x19db83: cmp %rax,%rbx` | memory | 0x19db50 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x22e | jne | reg/arith | `0x19dbcc: or %cl,%dl` | memory | 0x19dc10 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x26e | jne | reg/arith | `0x19dc0b: cmp %rdx,%rsi` | arithmetic/control | 0x19dbe0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x273 | je | reg/arith | `0x19dc10: test %rax,%rax` | memory | 0x19dc25 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2b5 | jne | reg/arith | `0x19dc52: test %rbx,%rbx` | call+memory | 0x19dd9c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e8 | je | mem | `0x19dc7e: cmpb $0x0,0x10(%rsp)` | memory | 0x19e597 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x321 | jne | reg/arith | `0x19dcbf: or %al,%cl` | memory | 0x19dd08 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x366 | jne | reg/arith | `0x19dd03: cmp %rax,%rsi` | arithmetic/control | 0x19dcd0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x36b | je | reg/arith | `0x19dd08: test %rdx,%rdx` | memory | 0x19dd21 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x38c | je | reg/arith | `0x19dd21: test %rbx,%rbx` | memory | 0x19dddc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x3e9 | je | mem | `0x19dd84: cmpb $0x0,0x10(%rsp)` | memory | 0x19df10 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x426 | je | mem | `0x19ddc1: cmpb $0x0,0x10(%rsp)` | memory | 0x19dfa2 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x45c | jne | reg/arith | `0x19ddfa: or %al,%cl` | memory | 0x19de38 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x496 | jne | reg/arith | `0x19de33: cmp %rax,%rsi` | arithmetic/control | 0x19de00 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x49b | je | reg/arith | `0x19de38: test %rdi,%rdi` | memory | 0x19db39 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4e2 | je | mem | `0x19de7d: cmpb $0x0,0x10(%rsp)` | memory | 0x19df5e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x510 | jne | reg/arith | `0x19deae: or %al,%cl` | memory | 0x19deec | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x54a | jne | reg/arith | `0x19dee7: cmp %rax,%rsi` | memory | 0x19deb4 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x557 | je | reg/arith | `0x19deec: test %r12,%r12` | memory | 0x19dbaa | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x57c | je | reg/arith | `0x19df18: cmp $0x1,%rbx` | memory | 0x19df39 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x5ca | je | reg/arith | `0x19df66: cmp $0x1,%rbx` | memory | 0x19df87 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x615 | je | reg/arith | `0x19dfb1: cmp $0x1,%rbx` | memory | 0x19dfda | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x666 | je | mem | `0x19e001: cmpb $0x0,0x10(%rsp)` | memory | 0x19e02e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x69f | je | reg/arith | `0x19e03b: cmp $0x1,%rbx` | memory | 0x19e05c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6fd | je | mem | `0x19e098: cmpb $0x0,0x10(%rsp)` | memory | 0x19e0a9 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x759 | je | mem | `0x19e0f4: cmpb $0x0,0x10(%rsp)` | memory | 0x19e181 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7b6 | jne | reg/arith | `0x19e153: cmp %rax,%rcx` | memory | 0x19e127 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7ef | je | reg/arith | `0x19e18b: cmp $0x1,%rbx` | memory | 0x19e1b4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x840 | je | mem | `0x19e1db: cmpb $0x0,0x10(%rsp)` | memory | 0x19e200 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x877 | je | reg/arith | `0x19e213: cmp $0x1,%rbx` | memory | 0x19e23c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8cd | je | mem | `0x19e264: cmpq $0x0,0x80(%rsp)` | memory | 0x19e435 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x930 | jae | mem | `0x19e2cb: cmp 0x78(%rsp),%rdi` | memory | 0x19e5f6 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x994 | je | reg/arith | `0x19e332: test %al,%al` | memory | 0x19e424 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9a3 | je | mem | `0x19e33a: cmpq $0x0,0x98(%rsp)` | memory | 0x19e394 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9f2 | jne | mem | `0x19e38a: cmp %rcx,0x98(%rsp)` | memory | 0x19e358 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa36 | je | reg/arith | `0x19e3d4: test %al,%al` | memory | 0x19e424 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa7c | jne | mem | `0x19e414: cmp 0x80(%rsp),%rsi` | arithmetic/control | 0x19e2b3 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xad9 | je | reg/arith | `0x19e477: test %al,%al` | memory | 0x19e505 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xbdd | jne | reg/arith | `0x19e57a: cmp %rax,%r13` | memory | 0x19e54f | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc97 | je | reg/arith | `0x19e634: test %rbx,%rbx` | memory | 0x19e651 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xcdd | je | reg/arith | `0x19e67a: test %rbx,%rbx` | memory | 0x19e697 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x1611c9: test %rbx,%rbx` | memory | 0x161220 | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x161206: cmpb $0x0,0x8(%rsp)` | memory | 0x161265 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | jne | reg/arith | `0x161215: test %rbx,%rbx` | arithmetic/control | 0x161436 | fwd |
| Montgomery multiply (allocating wrapper) | +0xb8 | je | mem | `0x161243: cmpb $0x0,0x8(%rsp)` | memory | 0x161459 | fwd |
| Montgomery multiply (allocating wrapper) | +0xe4 | jne | reg/arith | `0x161271: test %rbx,%rbx` | memory | 0x161491 | fwd |
| Montgomery multiply (allocating wrapper) | +0x12a | je | reg/arith | `0x1612b8: test %al,%al` | memory | 0x161378 | fwd |
| Montgomery multiply (allocating wrapper) | +0x143 | je | reg/arith | `0x1612d0: test %rbx,%rbx` | memory | 0x161329 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x161313: cmp %rax,%rbx` | memory | 0x1612e0 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x161363: cmp %rax,%r14` | arithmetic/control | 0x161330 | back |
| Montgomery multiply (allocating wrapper) | +0x1f3 | je | reg/arith | `0x161380: test %rbx,%rbx` | memory | 0x1613d6 | fwd |
| Montgomery multiply (allocating wrapper) | +0x236 | jne | reg/arith | `0x1613c3: cmp %rax,%rsi` | memory | 0x161390 | back |
| Montgomery multiply (allocating wrapper) | +0x286 | jne | reg/arith | `0x161413: cmp %rax,%r14` | memory | 0x1613e0 | back |
| Montgomery multiply (allocating wrapper) | +0x2a0 | je | reg/arith | `0x16142d: test %rbx,%rbx` | arithmetic/control | 0x161256 | back |
| Montgomery multiply (allocating wrapper) | +0x2d5 | je | reg/arith | `0x161461: cmp $0x1,%rbx` | memory | 0x161482 | fwd |
| Montgomery multiply (allocating wrapper) | +0x343 | je | mem | `0x1614ce: cmpb $0x0,0x8(%rsp)` | memory | 0x1614e2 | fwd |
| Montgomery multiply (allocating wrapper) | +0x35b | jne | reg/arith | `0x1614e7: cmp $0x1,%rbx` | arithmetic/control | 0x1614f5 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3a1 | je | reg/arith | `0x16152e: test %rbx,%rbx` | memory | 0x161549 | fwd |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x19f716: test %r12,%r12` | memory | 0x19f788 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x19f731: cmp $0x1,%r12` | memory | 0x19f759 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x19f73a: cmp $0x1,%r15` | memory | 0x19f75c | fwd |
| Constant-time ladder core | +0x60 | jne | reg/arith | `0x19f75c: test $0x1,%r15b` | call | 0x19f77c | fwd |
| Constant-time ladder core | +0x86 | jbe | reg/arith | `0x19f783: cmp %rbx,%r13` | memory | 0x19f79e | fwd |
| Constant-time ladder core | +0xe1 | je | mem | `0x19f7dc: cmpb $0x0,0x10(%rsp)` | memory | 0x19f7f1 | fwd |
| Constant-time ladder core | +0x102 | je | reg/arith | `0x19f7f9: cmp $0x1,%rbx` | memory | 0x19f831 | fwd |
| Constant-time ladder core | +0x154 | jae | reg/arith | `0x19f850: cmp $0x18,%rcx` | memory | 0x19f865 | fwd |
| Constant-time ladder core | +0x186 | je | reg/arith | `0x19f883: cmp %rdi,%r8` | arithmetic/control | 0x19f901 | fwd |
| Constant-time ladder core | +0x191 | jae | reg/arith | `0x19f88e: cmp %r13,%r8` | memory | 0x19f8c4 | fwd |
| Constant-time ladder core | +0x1a2 | jb | reg/arith | `0x19f89f: cmp %r13,%r8` | memory | 0x19f8d3 | fwd |
| Constant-time ladder core | +0x1b1 | jb | reg/arith | `0x19f8ae: cmp %r13,%r8` | memory | 0x19f8e4 | fwd |
| Constant-time ladder core | +0x1c0 | jb | reg/arith | `0x19f8bd: cmp %r13,%r8` | arithmetic/control | 0x19f873 | back |
| Constant-time ladder core | +0x1d1 | jae | reg/arith | `0x19f8ce: cmp %r13,%r8` | memory | 0x19f8a4 | back |
| Constant-time ladder core | +0x1e2 | jae | reg/arith | `0x19f8df: cmp %r13,%r8` | memory | 0x19f8b3 | back |
| Constant-time ladder core | +0x1f3 | jb | reg/arith | `0x19f8f0: cmp %r13,%r8` | arithmetic/control | 0x19f873 | back |
| Constant-time ladder core | +0x204 | je | reg/arith | `0x19f901: test %rax,%rax` | memory | 0x19f946 | fwd |
| Constant-time ladder core | +0x22c | je | reg/arith | `0x19f929: cmp %r8,%rax` | memory | 0x19f946 | fwd |
| Constant-time ladder core | +0x235 | jb | reg/arith | `0x19f932: cmp %r13,%r9` | memory | 0x19f91e | back |
| Constant-time ladder core | +0x244 | jne | reg/arith | `0x19f941: cmp %r8,%rax` | arithmetic/control | 0x19f92e | back |
| Constant-time ladder core | +0x249 | je | reg/arith | `0x19f946: test %r14,%r14` | memory | 0x19f9b6 | fwd |
| Constant-time ladder core | +0x252 | jne | reg/arith | `0x19f94f: test %r12,%r12` | memory | 0x19fc4d | fwd |
| Constant-time ladder core | +0x2b9 | je | reg/arith | `0x19f9b6: test %r12,%r12` | arithmetic/control | 0x19fd2e | fwd |
| Constant-time ladder core | +0x2c6 | jne | reg/arith | `0x19f9c2: shr $0x3a,%rax` | arithmetic/control | 0x19fc7b | fwd |
| Constant-time ladder core | +0x2d3 | jne | reg/arith | `0x19f9cf: shr $0x39,%rax` | call+memory | 0x19fc7b | fwd |
| Constant-time ladder core | +0x2f6 | je | reg/arith | `0x19f9f2: cmp $0xffffffffffffffff,%r14` | call+memory | 0x19fc7b | fwd |
| Constant-time ladder core | +0x334 | je | reg/arith | `0x19fa26: cmp $0xffffffffffffffff,%rbp` | memory | 0x19fbb5 | fwd |
| Constant-time ladder core | +0x34c | je | reg/arith | `0x19fa44: test %r8,%r8` | arithmetic/control | 0x19fd41 | fwd |
| Constant-time ladder core | +0x3f3 | je | mem | `0x19fade: cmpq $0xffffffffffffffff,0x10(%rsp)` | memory | 0x19fbbe | fwd |
| Constant-time ladder core | +0x437 | je | reg/arith | `0x19fb34: test %rbp,%rbp` | memory | 0x19fb50 | fwd |
| Constant-time ladder core | +0x46a | jne | reg/arith | `0x19fb68: or %al,%cl` | memory | 0x19fba7 | fwd |
| Constant-time ladder core | +0x4a5 | jne | reg/arith | `0x19fba2: cmp %rax,%rsi` | arithmetic/control | 0x19fb6e | back |
| Constant-time ladder core | +0x4aa | je | reg/arith | `0x19fba7: test %r14,%r14` | arithmetic/control | 0x19fc87 | fwd |
| Constant-time ladder core | +0x4c8 | je | reg/arith | `0x19fbc5: test %rbp,%rbp` | memory | 0x19fbe1 | fwd |
| Constant-time ladder core | +0x4fb | jne | reg/arith | `0x19fbf9: or %al,%cl` | memory | 0x19fc38 | fwd |
| Constant-time ladder core | +0x536 | jne | reg/arith | `0x19fc33: cmp %rax,%rsi` | arithmetic/control | 0x19fbff | back |
| Constant-time ladder core | +0x53b | je | reg/arith | `0x19fc38: test %r14,%r14` | memory | 0x19fc87 | fwd |
| Constant-time ladder core | +0x579 | je | mem | `0x19fc74: cmpb $0x0,0x10(%rsp)` | memory | 0x19fce5 | fwd |
| Constant-time ladder core | +0x58a | je | reg/arith | `0x19fc87: test %rbx,%rbx` | memory | 0x19f78f | back |
| Constant-time ladder core | +0x5ca | jne | reg/arith | `0x19fcc7: cmp %rax,%rsi` | memory | 0x19fc9c | back |
| Constant-time ladder core | +0x5f1 | je | reg/arith | `0x19fced: cmp $0x1,%r12` | memory | 0x19fd11 | fwd |
| Constant-time ladder core | +0x65f | je | reg/arith | `0x19fd5c: test %rbp,%rbp` | memory | 0x19fd78 | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x5894f4: test %r8,%r8` | memory | 0x58954b | fwd |
| Constant-time inversion | +0x1c | je | mem | `0x5894f9: testb $0x1,(%rcx)` | arithmetic/control | 0x58954b | fwd |
| Constant-time inversion | +0x2f | jne | reg/arith | `0x58950b: shr $0x39,%rdi` | memory | 0x58954b | fwd |
| Constant-time inversion | +0x66 | je | mem | `0x589541: cmpb $0x0,0x18(%rsp)` | memory | 0x589564 | fwd |
| Constant-time inversion | +0x90 | je | reg/arith | `0x58956c: cmp $0x1,%rbx` | memory | 0x58958d | fwd |
| Constant-time inversion | +0x104 | je | mem | `0x5895df: cmpb $0x0,0x18(%rsp)` | memory | 0x58964b | fwd |
| Constant-time inversion | +0x14e | jne | reg/arith | `0x58962b: cmp %rcx,%rbx` | memory | 0x589600 | back |
| Constant-time inversion | +0x177 | je | reg/arith | `0x589653: cmp $0x1,%rbx` | memory | 0x589674 | fwd |
| Constant-time inversion | +0x1f5 | je | mem | `0x5896d0: cmpb $0x0,0x18(%rsp)` | memory | 0x589731 | fwd |
| Constant-time inversion | +0x237 | jne | reg/arith | `0x589714: cmp %rcx,%rsi` | memory | 0x5896e9 | back |
| Constant-time inversion | +0x263 | je | mem | `0x58973e: cmpq $0x1,(%rsp)` | memory | 0x589761 | fwd |
| Constant-time inversion | +0x2d5 | je | mem | `0x5897b0: cmpb $0x0,0x18(%rsp)` | memory | 0x589840 | fwd |
| Constant-time inversion | +0x2ff | jne | reg/arith | `0x5897dd: or %cl,%dl` | memory | 0x58981f | fwd |
| Constant-time inversion | +0x339 | jne | reg/arith | `0x589816: cmp %rcx,%rsi` | memory | 0x5897eb | back |
| Constant-time inversion | +0x342 | je | reg/arith | `0x58981f: test %rax,%rax` | memory | 0x5896d7 | back |
| Constant-time inversion | +0x372 | je | mem | `0x58984d: cmpq $0x1,(%rsp)` | memory | 0x589878 | fwd |
| Constant-time inversion | +0x3e8 | je | mem | `0x5898c3: cmpb $0x0,0x18(%rsp)` | memory | 0x589955 | fwd |
| Constant-time inversion | +0x416 | jne | reg/arith | `0x5898f4: or %cl,%al` | memory | 0x589932 | fwd |
| Constant-time inversion | +0x450 | jne | reg/arith | `0x58992d: cmp %rcx,%rsi` | memory | 0x589902 | back |
| Constant-time inversion | +0x457 | je | mem | `0x589932: cmpq $0x0,(%rsp)` | memory | 0x58994c | fwd |
| Constant-time inversion | +0x483 | je | reg/arith | `0x58995f: cmp $0x1,%rbx` | memory | 0x589985 | fwd |
| Constant-time inversion | +0x4ee | je | mem | `0x5899c9: cmpb $0x0,0x18(%rsp)` | memory | 0x5899d9 | fwd |
| Constant-time inversion | +0x507 | je | reg/arith | `0x5899e3: cmp $0x1,%rbx` | memory | 0x589a09 | fwd |
| Constant-time inversion | +0x569 | je | mem | `0x589a43: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x589d2a | fwd |
| Constant-time inversion | +0x5a7 | je | mem | `0x589a81: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x589d33 | fwd |
| Constant-time inversion | +0x5e5 | je | mem | `0x589abf: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b62a | fwd |
| Constant-time inversion | +0x623 | je | mem | `0x589afd: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b633 | fwd |
| Constant-time inversion | +0x662 | je | mem | `0x589b3c: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b63c | fwd |
| Constant-time inversion | +0x6a1 | je | mem | `0x589b7b: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b645 | fwd |
| Constant-time inversion | +0x6e0 | je | mem | `0x589bba: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b64e | fwd |
| Constant-time inversion | +0x71f | je | mem | `0x589bf9: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b657 | fwd |
| Constant-time inversion | +0x75e | je | mem | `0x589c38: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b660 | fwd |
| Constant-time inversion | +0x79d | je | mem | `0x589c77: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x58b87d | fwd |
| Constant-time inversion | +0x7e0 | je | mem | `0x589cba: cmpq $0xffffffffffffffff,0x18(%rsp)` | memory | 0x58b883 | fwd |
| Constant-time inversion | +0x9fa | je | mem | `0x589ec2: cmp 0x2c8(%rsp),%rax` | memory | 0x58b669 | fwd |
| Constant-time inversion | +0xa29 | je | reg/arith | `0x589f06: test %rcx,%rcx` | memory | 0x589f65 | fwd |
| Constant-time inversion | +0xa6d | je | reg/arith | `0x589f49: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x589f68 | fwd |
| Constant-time inversion | +0xa72 | jae | reg/arith | `0x589f4f: cmp %rbx,%rcx` | memory | 0x589f5a | fwd |
| Constant-time inversion | +0xa7f | jb | reg/arith | `0x589f5c: cmp %rbx,%rcx` | arithmetic/control | 0x589f1f | back |
| Constant-time inversion | +0xaa5 | je | reg/arith | `0x589f82: test %rcx,%rcx` | memory | 0x589fde | fwd |
| Constant-time inversion | +0xae1 | je | reg/arith | `0x589fbd: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x589fde | fwd |
| Constant-time inversion | +0xae6 | jae | reg/arith | `0x589fc3: cmp %rbx,%rcx` | memory | 0x589fd3 | fwd |
| Constant-time inversion | +0xaf8 | jb | reg/arith | `0x589fd5: cmp %rbx,%rcx` | arithmetic/control | 0x589f9a | back |
| Constant-time inversion | +0xb63 | je | reg/arith | `0x58a040: test %rcx,%rcx` | memory | 0x58a13b | fwd |
| Constant-time inversion | +0xb79 | je | reg/arith | `0x58a056: test %r14,%r14` | memory | 0x58a102 | fwd |
| Constant-time inversion | +0xbe3 | je | reg/arith | `0x58a0bf: add $0xfffffffffffffffe,%rdx` | memory | 0x58a0f7 | fwd |
| Constant-time inversion | +0xbf0 | jae | reg/arith | `0x58a0cd: cmp %rbx,%r11` | memory | 0x58a0d8 | fwd |
| Constant-time inversion | +0xc10 | jb | reg/arith | `0x58a0ed: cmp %rbx,%r8` | arithmetic/control | 0x58a0a0 | back |
| Constant-time inversion | +0xc1b | je | reg/arith | `0x58a0f7: test $0x1,%r14b` | arithmetic/control | 0x58a13b | fwd |
| Constant-time inversion | +0xc49 | jae | reg/arith | `0x58a126: cmp %rbx,%rcx` | memory | 0x58a131 | fwd |
| Constant-time inversion | +0xc73 | je | reg/arith | `0x58a150: test %r8,%r8` | memory | 0x58a248 | fwd |
| Constant-time inversion | +0xc84 | je | reg/arith | `0x58a161: test %r13,%r13` | memory | 0x58a20e | fwd |
| Constant-time inversion | +0xcec | je | reg/arith | `0x58a1c8: add $0xfffffffffffffffe,%r10` | memory | 0x58a203 | fwd |
| Constant-time inversion | +0xcfb | jae | mem | `0x58a1d6: cmp 0x50(%rsp),%r14` | memory | 0x58a1e3 | fwd |
| Constant-time inversion | +0xd1d | jb | mem | `0x58a1f8: cmp 0x50(%rsp),%rax` | arithmetic/control | 0x58a1a9 | back |
| Constant-time inversion | +0xd27 | je | reg/arith | `0x58a203: test $0x1,%r13b` | arithmetic/control | 0x58a248 | fwd |
| Constant-time inversion | +0xd51 | jae | mem | `0x58a22c: cmp 0x50(%rsp),%rsi` | memory | 0x58a23e | fwd |
| Constant-time inversion | +0xde8 | je | reg/arith | `0x58a2c4: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x58a2fd | fwd |
| Constant-time inversion | +0xded | jae | reg/arith | `0x58a2ca: cmp %rbx,%rcx` | memory | 0x58a2d5 | fwd |
| Constant-time inversion | +0xdfc | jae | mem | `0x58a2d7: cmp 0x10(%rsp),%rcx` | memory | 0x58a2e9 | fwd |
| Constant-time inversion | +0xe16 | jb | reg/arith | `0x58a2f3: cmp %r8,%rcx` | arithmetic/control | 0x58a2a1 | back |
| Constant-time inversion | +0xe23 | je | mem | `0x58a2fd: cmpq $0x0,0x10(%rsp)` | memory | 0x58a401 | fwd |
| Constant-time inversion | +0xe39 | je | reg/arith | `0x58a316: test %r10,%r10` | memory | 0x58a3c4 | fwd |
| Constant-time inversion | +0xea6 | je | reg/arith | `0x58a382: add $0xfffffffffffffffe,%r11` | memory | 0x58a3b9 | fwd |
| Constant-time inversion | +0xeb3 | jae | reg/arith | `0x58a390: cmp %rbx,%r14` | memory | 0x58a39b | fwd |
| Constant-time inversion | +0xed3 | jb | reg/arith | `0x58a3b0: cmp %rbx,%rax` | arithmetic/control | 0x58a363 | back |
| Constant-time inversion | +0xedd | je | reg/arith | `0x58a3b9: test $0x1,%r10b` | arithmetic/control | 0x58a401 | fwd |
| Constant-time inversion | +0xf0a | jae | reg/arith | `0x58a3e7: cmp %rbx,%rsi` | memory | 0x58a3f7 | fwd |
| Constant-time inversion | +0xf24 | je | reg/arith | `0x58a401: test %r8,%r8` | memory | 0x58a4f9 | fwd |
| Constant-time inversion | +0xf35 | je | reg/arith | `0x58a412: test %r10,%r10` | memory | 0x58a4bf | fwd |
| Constant-time inversion | +0xf9d | je | reg/arith | `0x58a479: add $0xfffffffffffffffe,%r11` | memory | 0x58a4b4 | fwd |
| Constant-time inversion | +0xfac | jae | mem | `0x58a487: cmp 0x68(%rsp),%r14` | memory | 0x58a494 | fwd |
| Constant-time inversion | +0xfce | jb | mem | `0x58a4a9: cmp 0x68(%rsp),%rax` | arithmetic/control | 0x58a45a | back |
| Constant-time inversion | +0xfd8 | je | reg/arith | `0x58a4b4: test $0x1,%r10b` | arithmetic/control | 0x58a4f9 | fwd |
| Constant-time inversion | +0x1002 | jae | mem | `0x58a4dd: cmp 0x68(%rsp),%rsi` | memory | 0x58a4ef | fwd |
| Constant-time inversion | +0x1070 | je | reg/arith | `0x58a54c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x58a58a | fwd |
| Constant-time inversion | +0x1075 | jae | reg/arith | `0x58a552: cmp %rbx,%rcx` | memory | 0x58a562 | fwd |
| Constant-time inversion | +0x1089 | jae | mem | `0x58a564: cmp 0x10(%rsp),%rcx` | memory | 0x58a576 | fwd |
| Constant-time inversion | +0x10a3 | jb | reg/arith | `0x58a580: cmp %r8,%rcx` | arithmetic/control | 0x58a529 | back |
| Constant-time inversion | +0x10fc | je | mem | `0x58a5d3: cmpq $0x0,0x80(%rsp)` | memory | 0x58a5ee | fwd |
| Constant-time inversion | +0x113b | je | reg/arith | `0x58a618: test %rcx,%rcx` | arithmetic/control | 0x58a70e | fwd |
| Constant-time inversion | +0x1148 | je | reg/arith | `0x58a624: add $0xfffffffffffffff8,%r8` | memory | 0x58a6d2 | fwd |
| Constant-time inversion | +0x11ab | je | reg/arith | `0x58a687: add $0xfffffffffffffffe,%r9` | memory | 0x58a6c7 | fwd |
| Constant-time inversion | +0x11bd | jae | mem | `0x58a695: cmp 0x80(%rsp),%rdi` | memory | 0x58a6a5 | fwd |
| Constant-time inversion | +0x11e1 | jb | mem | `0x58a6b9: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x58a668 | back |
| Constant-time inversion | +0x11eb | je | reg/arith | `0x58a6c7: test $0x1,%r8b` | arithmetic/control | 0x58a70e | fwd |
| Constant-time inversion | +0x1214 | jae | mem | `0x58a6ec: cmp 0x80(%rsp),%rdi` | memory | 0x58a704 | fwd |
| Constant-time inversion | +0x1239 | je | reg/arith | `0x58a716: test %rdx,%rdx` | arithmetic/control | 0x58a774 | fwd |
| Constant-time inversion | +0x126d | je | reg/arith | `0x58a749: add $0xfffffffffffffff8,%rax` | memory | 0x58a774 | fwd |
| Constant-time inversion | +0x1277 | jae | mem | `0x58a74f: cmp 0x80(%rsp),%rcx` | memory | 0x58a767 | fwd |
| Constant-time inversion | +0x128d | jb | mem | `0x58a769: cmp (%rsp),%rcx` | arithmetic/control | 0x58a724 | back |
| Constant-time inversion | +0x1298 | ja | mem | `0x58a774: cmp %rdx,(%rsp)` | arithmetic/control | 0x58b99b | fwd |
| Constant-time inversion | +0x129e | jae | unknown | `?` | memory | 0x58b9c4 | fwd |
| Constant-time inversion | +0x12aa | je | mem | `0x58a784: cmpq $0x0,0x10(%rsp)` | memory | 0x58a85b | fwd |
| Constant-time inversion | +0x12d6 | jne | reg/arith | `0x58a7b3: test $0x8,%dl` | memory | 0x58a7f2 | fwd |
| Constant-time inversion | +0x12f4 | jae | mem | `0x58a7d0: cmp (%rsp),%rdi` | memory | 0x58a7e1 | fwd |
| Constant-time inversion | +0x1315 | je | reg/arith | `0x58a7f2: test %rdx,%rdx` | memory | 0x58a85b | fwd |
| Constant-time inversion | +0x1344 | je | mem | `0x58a81f: cmp 0x8(%rsp),%rax` | memory | 0x58a85b | fwd |
| Constant-time inversion | +0x1351 | jae | mem | `0x58a82d: cmp (%rsp),%rsi` | memory | 0x58a83e | fwd |
| Constant-time inversion | +0x1375 | jb | mem | `0x58a851: cmp (%rsp),%rcx` | arithmetic/control | 0x58a805 | back |
| Constant-time inversion | +0x1381 | je | mem | `0x58a85b: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x58a933 | fwd |
| Constant-time inversion | +0x138e | je | reg/arith | `0x58a86a: add $0xfffffffffffffff8,%rdx` | memory | 0x58a907 | fwd |
| Constant-time inversion | +0x13db | je | reg/arith | `0x58a8b8: cmp %rsi,%rdi` | memory | 0x58a8f8 | fwd |
| Constant-time inversion | +0x13e8 | jae | mem | `0x58a8c3: cmp 0x10(%rsp),%rdi` | memory | 0x58a8d5 | fwd |
| Constant-time inversion | +0x1411 | jb | mem | `0x58a8ec: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x58a894 | back |
| Constant-time inversion | +0x141b | je | reg/arith | `0x58a8f8: test $0x1,%dl` | arithmetic/control | 0x58a933 | fwd |
| Constant-time inversion | +0x1433 | jae | mem | `0x58a90e: cmp 0x10(%rsp),%rcx` | memory | 0x58a920 | fwd |
| Constant-time inversion | +0x1485 | je | reg/arith | `0x58a962: test %rax,%rax` | memory | 0x58a9d3 | fwd |
| Constant-time inversion | +0x14c4 | je | reg/arith | `0x58a9a0: add $0xfffffffffffffff8,%rcx` | memory | 0x58a9ce | fwd |
| Constant-time inversion | +0x14ce | jae | mem | `0x58a9a6: cmp 0x80(%rsp),%rdx` | memory | 0x58a9be | fwd |
| Constant-time inversion | +0x14e8 | jb | mem | `0x58a9c0: cmp 0x88(%rsp),%rdx` | arithmetic/control | 0x58a975 | back |
| Constant-time inversion | +0x1505 | je | reg/arith | `0x58a9e2: test %rdx,%rdx` | arithmetic/control | 0x58aa65 | fwd |
| Constant-time inversion | +0x153e | je | reg/arith | `0x58aa1a: add $0xfffffffffffffff8,%rdx` | memory | 0x58aa3e | fwd |
| Constant-time inversion | +0x1544 | jae | mem | `0x58aa20: cmp (%rsp),%rsi` | memory | 0x58aa2f | fwd |
| Constant-time inversion | +0x1557 | jb | mem | `0x58aa32: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x58a9f0 | back |
| Constant-time inversion | +0x15cc | je | reg/arith | `0x58aaa9: test %rsi,%rsi` | arithmetic/control | 0x58ab94 | fwd |
| Constant-time inversion | +0x15d9 | je | reg/arith | `0x58aab5: add $0xfffffffffffffff8,%r11` | memory | 0x58ab5d | fwd |
| Constant-time inversion | +0x163a | je | reg/arith | `0x58ab16: add $0xfffffffffffffffe,%rsi` | memory | 0x58ab52 | fwd |
| Constant-time inversion | +0x1649 | jae | mem | `0x58ab24: cmp 0x58(%rsp),%r14` | memory | 0x58ab31 | fwd |
| Constant-time inversion | +0x166b | jb | mem | `0x58ab46: cmp 0x58(%rsp),%r13` | arithmetic/control | 0x58aaf7 | back |
| Constant-time inversion | +0x1676 | je | reg/arith | `0x58ab52: test $0x1,%r11b` | arithmetic/control | 0x58ab94 | fwd |
| Constant-time inversion | +0x169d | jae | mem | `0x58ab78: cmp 0x58(%rsp),%rdi` | memory | 0x58ab8a | fwd |
| Constant-time inversion | +0x16f6 | je | reg/arith | `0x58abd2: add $0xfffffffffffffff8,%rsi` | memory | 0x58abf8 | fwd |
| Constant-time inversion | +0x16fd | jae | mem | `0x58abd8: cmp 0x58(%rsp),%rdi` | memory | 0x58abea | fwd |
| Constant-time inversion | +0x1711 | jb | mem | `0x58abed: cmp (%rsp),%rdi` | arithmetic/control | 0x58abac | back |
| Constant-time inversion | +0x171e | je | mem | `0x58abf8: cmpq $0x0,0x10(%rsp)` | memory | 0x58acbd | fwd |
| Constant-time inversion | +0x1741 | jne | reg/arith | `0x58ac1d: test $0x8,%dil` | memory | 0x58ac3b | fwd |
| Constant-time inversion | +0x174e | jae | mem | `0x58ac2a: cmp (%rsp),%rsi` | memory | 0x58ac40 | fwd |
| Constant-time inversion | +0x1775 | je | reg/arith | `0x58ac52: test %rdi,%rdi` | memory | 0x58acbd | fwd |
| Constant-time inversion | +0x17a4 | je | mem | `0x58ac7f: cmp 0x8(%rsp),%rsi` | memory | 0x58acbd | fwd |
| Constant-time inversion | +0x17b1 | jae | mem | `0x58ac8d: cmp (%rsp),%r9` | memory | 0x58ac9e | fwd |
| Constant-time inversion | +0x17d6 | jb | mem | `0x58acb2: cmp (%rsp),%r10` | arithmetic/control | 0x58ac65 | back |
| Constant-time inversion | +0x17e3 | je | mem | `0x58acbd: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x58ad9c | fwd |
| Constant-time inversion | +0x17f0 | je | reg/arith | `0x58accc: add $0xfffffffffffffff8,%r11` | memory | 0x58ad6e | fwd |
| Constant-time inversion | +0x183e | je | reg/arith | `0x58ad1b: cmp %r9,%r10` | memory | 0x58ad5e | fwd |
| Constant-time inversion | +0x184b | jae | mem | `0x58ad26: cmp 0x10(%rsp),%r10` | memory | 0x58ad38 | fwd |
| Constant-time inversion | +0x1877 | jb | mem | `0x58ad52: cmp 0x10(%rsp),%r10` | arithmetic/control | 0x58acf7 | back |
| Constant-time inversion | +0x1882 | je | reg/arith | `0x58ad5e: test $0x1,%r11b` | arithmetic/control | 0x58ad9c | fwd |
| Constant-time inversion | +0x189a | jae | mem | `0x58ad75: cmp 0x10(%rsp),%rsi` | memory | 0x58ad87 | fwd |
| Constant-time inversion | +0x18f3 | je | reg/arith | `0x58add0: test %rsi,%rsi` | arithmetic/control | 0x58ae46 | fwd |
| Constant-time inversion | +0x1928 | je | reg/arith | `0x58ae04: add $0xfffffffffffffff8,%rsi` | memory | 0x58ae46 | fwd |
| Constant-time inversion | +0x1932 | jae | mem | `0x58ae0a: cmp 0x80(%rsp),%rdi` | memory | 0x58ae22 | fwd |
| Constant-time inversion | +0x194a | jae | mem | `0x58ae25: cmp 0x40(%rsp),%rdi` | memory | 0x58ae37 | fwd |
| Constant-time inversion | +0x195f | jb | mem | `0x58ae3a: cmp 0x68(%rsp),%rdi` | arithmetic/control | 0x58addd | back |
| Constant-time inversion | +0x196f | je | mem | `0x58ae46: cmpq $0x0,0x88(%rsp)` | memory | 0x58ae61 | fwd |
| Constant-time inversion | +0x1996 | je | mem | `0x58ae70: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x58af8c | fwd |
| Constant-time inversion | +0x19a3 | je | reg/arith | `0x58ae7f: add $0xfffffffffffffff8,%rsi` | memory | 0x58af4f | fwd |
| Constant-time inversion | +0x1a1b | je | reg/arith | `0x58aef7: add $0xfffffffffffffffe,%rsi` | memory | 0x58af3e | fwd |
| Constant-time inversion | +0x1a2d | jae | mem | `0x58af05: cmp 0x88(%rsp),%r14` | memory | 0x58af15 | fwd |
| Constant-time inversion | +0x1a57 | jb | mem | `0x58af2f: cmp 0x88(%rsp),%r13` | arithmetic/control | 0x58aece | back |
| Constant-time inversion | +0x1a66 | je | mem | `0x58af3e: testb $0x1,0xa0(%rsp)` | memory | 0x58af8c | fwd |
| Constant-time inversion | +0x1a92 | jae | mem | `0x58af6a: cmp 0x88(%rsp),%rdi` | memory | 0x58af82 | fwd |
| Constant-time inversion | +0x1ae0 | je | reg/arith | `0x58afbc: add $0xfffffffffffffff8,%rsi` | memory | 0x58afe8 | fwd |
| Constant-time inversion | +0x1aea | jae | mem | `0x58afc2: cmp 0x88(%rsp),%rdi` | memory | 0x58afda | fwd |
| Constant-time inversion | +0x1b01 | jb | mem | `0x58afdd: cmp (%rsp),%rdi` | arithmetic/control | 0x58af96 | back |
| Constant-time inversion | +0x1b0e | je | mem | `0x58afe8: cmpq $0x0,0x10(%rsp)` | memory | 0x58b0ad | fwd |
| Constant-time inversion | +0x1b31 | jne | reg/arith | `0x58b00d: test $0x8,%dil` | memory | 0x58b02b | fwd |
| Constant-time inversion | +0x1b3e | jae | mem | `0x58b01a: cmp (%rsp),%rsi` | memory | 0x58b030 | fwd |
| Constant-time inversion | +0x1b65 | je | reg/arith | `0x58b042: test %rdi,%rdi` | memory | 0x58b0ad | fwd |
| Constant-time inversion | +0x1b94 | je | mem | `0x58b06f: cmp 0x8(%rsp),%rsi` | memory | 0x58b0ad | fwd |
| Constant-time inversion | +0x1ba1 | jae | mem | `0x58b07d: cmp (%rsp),%r9` | memory | 0x58b08e | fwd |
| Constant-time inversion | +0x1bc6 | jb | mem | `0x58b0a2: cmp (%rsp),%r10` | arithmetic/control | 0x58b055 | back |
| Constant-time inversion | +0x1bd3 | je | mem | `0x58b0ad: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x58b185 | fwd |
| Constant-time inversion | +0x1bdd | je | reg/arith | `0x58b0b9: add $0xfffffffffffffff8,%r12` | memory | 0x58b159 | fwd |
| Constant-time inversion | +0x1c2b | je | reg/arith | `0x58b108: cmp %rdi,%r9` | memory | 0x58b149 | fwd |
| Constant-time inversion | +0x1c38 | jae | mem | `0x58b113: cmp 0x10(%rsp),%r9` | memory | 0x58b125 | fwd |
| Constant-time inversion | +0x1c62 | jb | mem | `0x58b13d: cmp 0x10(%rsp),%r9` | arithmetic/control | 0x58b0e4 | back |
| Constant-time inversion | +0x1c6d | je | reg/arith | `0x58b149: test $0x1,%r12b` | arithmetic/control | 0x58b185 | fwd |
| Constant-time inversion | +0x1c85 | jae | mem | `0x58b160: cmp 0x10(%rsp),%rsi` | memory | 0x58b172 | fwd |
| Constant-time inversion | +0x1cab | je | mem | `0x58b185: cmpq $0x0,0x10(%rsp)` | memory | 0x58b1fe | fwd |
| Constant-time inversion | +0x1ced | je | reg/arith | `0x58b1c9: add $0xfffffffffffffff8,%rsi` | memory | 0x58b1f9 | fwd |
| Constant-time inversion | +0x1cf7 | jae | mem | `0x58b1cf: cmp 0x88(%rsp),%rdi` | memory | 0x58b1e7 | fwd |
| Constant-time inversion | +0x1d12 | jb | mem | `0x58b1ea: cmp 0x80(%rsp),%rdi` | arithmetic/control | 0x58b19c | back |
| Constant-time inversion | +0x1d27 | je | mem | `0x58b201: cmpq $0x0,0x58(%rsp)` | arithmetic/control | 0x58b26a | fwd |
| Constant-time inversion | +0x1d5d | je | reg/arith | `0x58b239: add $0xfffffffffffffff8,%rcx` | memory | 0x58b25d | fwd |
| Constant-time inversion | +0x1d63 | jae | mem | `0x58b23f: cmp (%rsp),%rsi` | memory | 0x58b24e | fwd |
| Constant-time inversion | +0x1d76 | jb | mem | `0x58b251: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x58b20f | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x58b279: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x58b37a | fwd |
| Constant-time inversion | +0x1dac | je | reg/arith | `0x58b288: add $0xfffffffffffffff8,%r10` | memory | 0x58b344 | fwd |
| Constant-time inversion | +0x1e1b | je | reg/arith | `0x58b2f7: add $0xfffffffffffffffe,%rsi` | memory | 0x58b337 | fwd |
| Constant-time inversion | +0x1e2a | jae | mem | `0x58b305: cmp 0x58(%rsp),%r14` | memory | 0x58b312 | fwd |
| Constant-time inversion | +0x1e51 | jb | mem | `0x58b32c: cmp 0x58(%rsp),%rcx` | arithmetic/control | 0x58b2ce | back |
| Constant-time inversion | +0x1e5b | je | reg/arith | `0x58b337: test $0x1,%r10b` | memory | 0x58b37a | fwd |
| Constant-time inversion | +0x1e83 | jae | mem | `0x58b35e: cmp 0x58(%rsp),%rdi` | memory | 0x58b370 | fwd |
| Constant-time inversion | +0x1ec9 | je | reg/arith | `0x58b3a5: add $0xfffffffffffffff8,%r8` | memory | 0x58b3ca | fwd |
| Constant-time inversion | +0x1ed0 | jae | mem | `0x58b3ab: cmp 0x58(%rsp),%rcx` | memory | 0x58b3bd | fwd |
| Constant-time inversion | +0x1ee3 | jb | mem | `0x58b3bf: cmp (%rsp),%rcx` | arithmetic/control | 0x58b380 | back |
| Constant-time inversion | +0x1ef0 | je | mem | `0x58b3ca: cmpq $0x0,0x10(%rsp)` | memory | 0x58b48a | fwd |
| Constant-time inversion | +0x1f16 | jne | reg/arith | `0x58b3f2: test $0x8,%sil` | memory | 0x58b421 | fwd |
| Constant-time inversion | +0x1f23 | jae | mem | `0x58b3ff: cmp (%rsp),%rsi` | memory | 0x58b410 | fwd |
| Constant-time inversion | +0x1f44 | je | reg/arith | `0x58b421: test %rdi,%rdi` | memory | 0x58b48a | fwd |
| Constant-time inversion | +0x1f73 | je | mem | `0x58b44e: cmp 0x8(%rsp),%rax` | memory | 0x58b48a | fwd |
| Constant-time inversion | +0x1f80 | jae | mem | `0x58b45c: cmp (%rsp),%rdi` | memory | 0x58b46d | fwd |
| Constant-time inversion | +0x1fa4 | jb | mem | `0x58b480: cmp (%rsp),%rcx` | arithmetic/control | 0x58b434 | back |
| Constant-time inversion | +0x1fb0 | je | mem | `0x58b48a: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x58b55f | fwd |
| Constant-time inversion | +0x1fba | je | reg/arith | `0x58b496: add $0xfffffffffffffff8,%rdx` | memory | 0x58b533 | fwd |
| Constant-time inversion | +0x2007 | je | reg/arith | `0x58b4e4: cmp %rsi,%rdi` | memory | 0x58b524 | fwd |
| Constant-time inversion | +0x2014 | jae | mem | `0x58b4ef: cmp 0x10(%rsp),%rdi` | memory | 0x58b501 | fwd |
| Constant-time inversion | +0x203d | jb | mem | `0x58b518: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x58b4c0 | back |
| Constant-time inversion | +0x2047 | je | reg/arith | `0x58b524: test $0x1,%dl` | arithmetic/control | 0x58b55f | fwd |
| Constant-time inversion | +0x205f | jae | mem | `0x58b53a: cmp 0x10(%rsp),%rcx` | memory | 0x58b54c | fwd |
| Constant-time inversion | +0x20cd | je | reg/arith | `0x58b5aa: test %rcx,%rcx` | memory | 0x589d3c | back |
| Constant-time inversion | +0x210b | je | reg/arith | `0x58b5e7: add $0xfffffffffffffff8,%rax` | memory | 0x589d3c | back |
| Constant-time inversion | +0x2119 | jae | mem | `0x58b5f1: cmp 0x88(%rsp),%rcx` | memory | 0x58b609 | fwd |
| Constant-time inversion | +0x2130 | jae | mem | `0x58b60b: cmp 0x40(%rsp),%rcx` | memory | 0x58b61d | fwd |
| Constant-time inversion | +0x2144 | jb | mem | `0x58b61f: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x58b5bc | back |
| Constant-time inversion | +0x2199 | je | reg/arith | `0x58b675: cmp $0x1,%rbx` | memory | 0x58b718 | fwd |
| Constant-time inversion | +0x21b8 | jb | reg/arith | `0x58b694: cmp $0x18,%rcx` | memory | 0x58b6fd | fwd |
| Constant-time inversion | +0x2204 | jne | reg/arith | `0x58b6e1: cmp %rdx,%rsi` | arithmetic/control | 0x58b6c9 | back |
| Constant-time inversion | +0x221b | je | reg/arith | `0x58b6f8: cmp %rsi,%rcx` | memory | 0x58b718 | fwd |
| Constant-time inversion | +0x2236 | jne | mem | `0x58b711: cmp 0x8(%rsp),%rax` | call+memory | 0x58b70a | back |
| Constant-time inversion | +0x2258 | je | reg/arith | `0x58b734: cmp $0xffffffffffffffff,%r13` | memory | 0x58b889 | fwd |
| Constant-time inversion | +0x226d | jne | mem | `0x58b748: cmp 0x38(%rsp),%rdi` | memory | 0x58b9b0 | fwd |
| Constant-time inversion | +0x2369 | je | reg/arith | `0x58b846: test %r12,%r12` | memory | 0x58b985 | fwd |
| Constant-time inversion | +0x237a | je | reg/arith | `0x58b857: test %r13,%r13` | memory | 0x589552 | back |
| Constant-time inversion | +0x248b | jne | reg/arith | `0x58b968: cmp %rax,%rsi` | memory | 0x58b93d | back |
| Constant-time inversion | +0x2558 | je | reg/arith | `0x58ba35: test %r13,%r13` | memory | 0x58ba54 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x58f6d0: test %rcx,%rcx` | memory | 0x58f744 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x58f6e0: test %rax,%rax` | memory | 0x58f738 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x58f6ec: cmp (%r15),%rcx` | memory | 0x58f73f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x58f6f5: test %ecx,%ecx` | memory | 0x58f705 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x58f6fd: test %edx,%edx` | arithmetic/control | 0x58f705 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x58f701: cmp %edx,%ecx` | call | 0x58f73f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x58f70d: test %eax,%eax` | memory | 0x58f744 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x58f719: test %rax,%rax` | memory | 0x58f872 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x58f722: cmp (%r12),%rcx` | memory | 0x58fab3 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x58f74f: test %rcx,%rcx` | memory | 0x58f850 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x58f770: cmp %rdx,%rcx` | memory | 0x58f850 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x58f779: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x58f770 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x58f78f: test %rcx,%rcx` | memory | 0x58f850 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x58f7b0: cmp %rdx,%rcx` | memory | 0x58f850 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x58f7b9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x58f7b0 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x58f7cd: test %r13,%r13` | memory | 0x58f869 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x58f7da: cmpq $0x0,0x50(%rax)` | memory | 0x58f880 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x58f7fc: test %rax,%rax` | memory | 0x58f84b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x58f817: test %rax,%rax` | call | 0x58f825 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x58f821: test %eax,%eax` | call+memory | 0x58f898 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x58f88f: test %r13,%r13` | memory | 0x58f9dd | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x58f89c: cmpq $0x0,0x50(%rax)` | memory | 0x58f9d4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x58f8c3: test %rax,%rax` | memory | 0x58fa11 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x58f8e2: test %rax,%rax` | call | 0x58f9eb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x58f8f0: test %eax,%eax` | memory | 0x58f9eb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x58f902: test %r14,%r14` | arithmetic/control | 0x58facc | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x58f90b: test %r15,%r15` | memory | 0x58fad7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x58f91e: test %rcx,%rcx` | memory | 0x58f958 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x58f927: test %rax,%rax` | memory | 0x58f958 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x58f933: cmp (%r15),%rcx` | memory | 0x58f958 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x58f93c: test %ecx,%ecx` | memory | 0x58fc1a | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x58f948: test %edx,%edx` | arithmetic/control | 0x58fc1a | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x58f950: cmp %ecx,%edx` | call | 0x58fc1a | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x58f972: test %rax,%rax` | memory | 0x58f985 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x58f97b: test %rax,%rax` | call | 0x58f985 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x58f9b6: test %rbx,%rbx` | memory | 0x58fbee | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x58f9c3: test %rcx,%rcx` | arithmetic/control | 0x58fa99 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x58fa32: test %bpl,%bpl` | memory | 0x58fa78 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x58fa3f: test %rax,%rax` | memory | 0x58fa52 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x58fa48: test %rax,%rax` | call | 0x58fa52 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x58fa83: test %rbx,%rbx` | memory | 0x58f857 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x58fa90: test %rcx,%rcx` | memory | 0x58f857 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x58fae4: test %eax,%eax` | memory | 0x58fbf6 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x58faf0: test %rax,%rax` | memory | 0x58faf9 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x58fafd: test %rax,%rax` | memory | 0x58fb06 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x58fb0a: test %rax,%rax` | memory | 0x58fb13 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x58fb18: test %rax,%rax` | memory | 0x58fb21 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x58fb26: test %rax,%rax` | memory | 0x58fb2f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x58fb34: test %rax,%rax` | memory | 0x58fb3d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x58fb46: test %rax,%rax` | memory | 0x58fb4f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x58fb58: test %rax,%rax` | memory | 0x58fb61 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x58fb6a: test %rax,%rax` | call+memory | 0x58fb73 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x58fb9b: test %rax,%rax` | memory | 0x58fc02 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x58fbb9: test %eax,%eax` | memory | 0x58fc0e | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x58fbca: test %r15,%r15` | memory | 0x58fc38 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x58fbd3: test $0xffffffff80000000,%rax` | memory | 0x58fc4b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x58fc1a: cmp %r15,%r14` | call | 0x58faec | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x58fc2b: test %eax,%eax` | arithmetic/control | 0x58faec | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x58fc56: test $0x1,%al` | memory | 0x590298 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x58fc63: test %eax,%eax` | memory | 0x58fc91 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x58fc6e: cmp %rsi,(%rdi)` | call+memory | 0x58fc9b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x58fc83: test %al,%cl` | arithmetic/control | 0x58fca4 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x58fc91: test %r15,%r15` | arithmetic/control | 0x58fcb9 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x58fc9b: test %r15,%r15` | memory | 0x58fd84 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x58fca4: cmp %rsi,(%r15)` | call | 0x58fcb9 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x58fcb1: test %al,%al` | memory | 0x58fd84 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x58fcca: test %rax,%rax` | memory | 0x58fd90 | fwd |
| ECDSA scalar ladder (driver) | +0x635 | jg | mem | `0x58fce1: cmp 0x24(%rsp),%eax` | memory | 0x58fcee | fwd |
| ECDSA scalar ladder (driver) | +0x63c | je | mem | `0x58fce7: cmpl $0x0,0x18(%r15)` | memory | 0x58fd0a | fwd |
| ECDSA scalar ladder (driver) | +0x654 | je | reg/arith | `0x58fd02: test %eax,%eax` | memory | 0x58fd9c | fwd |
| ECDSA scalar ladder (driver) | +0x672 | je | reg/arith | `0x58fd20: test %eax,%eax` | memory | 0x58fda8 | fwd |
| ECDSA scalar ladder (driver) | +0x68f | je | reg/arith | `0x58fd3d: test %eax,%eax` | memory | 0x58ff7e | fwd |
| ECDSA scalar ladder (driver) | +0x6a3 | js | mem | `0x58fd4e: cmpl $0x0,0x24(%rsp)` | memory | 0x58fdb4 | fwd |
| ECDSA scalar ladder (driver) | +0x6b5 | jae | mem | `0x58fd61: cmp 0x10(%rcx),%rax` | memory | 0x58fdb4 | fwd |
| ECDSA scalar ladder (driver) | +0x722 | je | reg/arith | `0x58fdcf: test %rax,%rax` | memory | 0x58fdec | fwd |
| ECDSA scalar ladder (driver) | +0x74f | je | reg/arith | `0x58fdfc: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x75d | jae | mem | `0x58fe0a: cmp %r15,(%rdi)` | call | 0x58fe1f | fwd |
| ECDSA scalar ladder (driver) | +0x769 | je | reg/arith | `0x58fe17: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x77b | je | reg/arith | `0x58fe28: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x784 | jae | mem | `0x58fe31: cmp %r15,(%rdi)` | call | 0x58fe46 | fwd |
| ECDSA scalar ladder (driver) | +0x790 | je | reg/arith | `0x58fe3e: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x7a2 | je | reg/arith | `0x58fe4f: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ab | jae | mem | `0x58fe58: cmp %r15,(%rdi)` | call | 0x58fe6d | fwd |
| ECDSA scalar ladder (driver) | +0x7b7 | je | reg/arith | `0x58fe65: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x7c5 | je | reg/arith | `0x58fe72: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ce | jae | mem | `0x58fe7b: cmp %r15,(%rdi)` | call | 0x58fe90 | fwd |
| ECDSA scalar ladder (driver) | +0x7da | je | reg/arith | `0x58fe88: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x7e8 | je | reg/arith | `0x58fe95: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x7f1 | jae | mem | `0x58fe9e: cmp %r15,(%rdi)` | call | 0x58feb3 | fwd |
| ECDSA scalar ladder (driver) | +0x7fd | je | reg/arith | `0x58feab: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x80b | je | reg/arith | `0x58feb8: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x814 | jae | mem | `0x58fec1: cmp %r15,(%rdi)` | call | 0x58fed6 | fwd |
| ECDSA scalar ladder (driver) | +0x820 | je | reg/arith | `0x58fece: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x832 | je | reg/arith | `0x58fedf: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x83b | jae | mem | `0x58fee8: cmp %r15,(%rdi)` | call | 0x58fefd | fwd |
| ECDSA scalar ladder (driver) | +0x847 | je | reg/arith | `0x58fef5: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x859 | je | reg/arith | `0x58ff06: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x862 | jae | mem | `0x58ff0f: cmp %r15,(%rdi)` | call | 0x58ff24 | fwd |
| ECDSA scalar ladder (driver) | +0x86e | je | reg/arith | `0x58ff1c: test %al,%al` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x880 | je | reg/arith | `0x58ff2d: test %rdi,%rdi` | memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0x88e | jae | mem | `0x58ff36: cmp %r15,(%rdi)` | call | 0x58ff50 | fwd |
| ECDSA scalar ladder (driver) | +0x89a | je | reg/arith | `0x58ff48: test %al,%al` | memory | 0x58f964 | back |
| ECDSA scalar ladder (driver) | +0x8a5 | je | mem | `0x58ff50: cmpl $0x0,0x28(%r14)` | call+memory | 0x5900b2 | fwd |
| ECDSA scalar ladder (driver) | +0x8b9 | je | reg/arith | `0x58ff67: test %al,%al` | memory | 0x58ff8a | fwd |
| ECDSA scalar ladder (driver) | +0x8e8 | jne | reg/arith | `0x58ff94: cmp $0x4,%rdx` | memory | 0x58ffdd | fwd |
| ECDSA scalar ladder (driver) | +0x922 | jne | reg/arith | `0x58ffce: cmp $0x1,%dil` | call | 0x58ffdf | fwd |
| ECDSA scalar ladder (driver) | +0x934 | je | reg/arith | `0x58ffe2: test %cl,%cl` | arithmetic/control | 0x590058 | fwd |
| ECDSA scalar ladder (driver) | +0x939 | jne | reg/arith | `0x58ffe6: test %sil,%sil` | memory | 0x590058 | fwd |
| ECDSA scalar ladder (driver) | +0x985 | je | mem | `0x59002c: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x590122 | fwd |
| ECDSA scalar ladder (driver) | +0x9cb | je | reg/arith | `0x590079: test %eax,%eax` | arithmetic/control | 0x5900f0 | fwd |
| ECDSA scalar ladder (driver) | +0x9d4 | jg | reg/arith | `0x590081: cmp $0x1,%eax` | arithmetic/control | 0x5900fc | fwd |
| ECDSA scalar ladder (driver) | +0x9d8 | jne | reg/arith | `0x590086: test %eax,%eax` | call+memory | 0x590133 | fwd |
| ECDSA scalar ladder (driver) | +0xa17 | je | reg/arith | `0x5900c4: test %rax,%rax` | call+memory | 0x5900e6 | fwd |
| ECDSA scalar ladder (driver) | +0xa2b | jne | reg/arith | `0x5900d9: test %eax,%eax` | arithmetic/control | 0x58ff5b | back |
| ECDSA scalar ladder (driver) | +0xa4f | jne | reg/arith | `0x5900fc: cmp $0x2,%eax` | call+memory | 0x590166 | fwd |
| ECDSA scalar ladder (driver) | +0xaa4 | jne | reg/arith | `0x590152: test %eax,%eax` | memory | 0x59022b | fwd |
| ECDSA scalar ladder (driver) | +0xaba | jo | mem | `0x590166: decl 0x24(%rsp)` | arithmetic/control | 0x5902a7 | fwd |
| ECDSA scalar ladder (driver) | +0xac0 | js | unknown | `?` | memory | 0x590212 | fwd |
| ECDSA scalar ladder (driver) | +0xae9 | jae | mem | `0x590195: cmp 0x10(%rcx),%rax` | memory | 0x5901b2 | fwd |
| ECDSA scalar ladder (driver) | +0xb1c | je | mem | `0x5901c6: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x5901e5 | fwd |
| ECDSA scalar ladder (driver) | +0xb4f | je | reg/arith | `0x5901fd: test %eax,%eax` | memory | 0x59026d | fwd |
| ECDSA scalar ladder (driver) | +0xb5a | jg | reg/arith | `0x590203: test %r15,%r15` | arithmetic/control | 0x590187 | back |
| ECDSA scalar ladder (driver) | +0xb89 | je | reg/arith | `0x590236: test %rax,%rax` | call+memory | 0x590254 | fwd |
| ECDSA scalar ladder (driver) | +0xba2 | je | reg/arith | `0x590250: test %eax,%eax` | call+memory | 0x590266 | fwd |
| ECDSA scalar ladder (driver) | +0xbdd | jne | reg/arith | `0x59028a: test %rax,%rax` | arithmetic/control | 0x58f977 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x2a51b7: test %rax,%rax` | memory | 0x2a5755 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x2a51d2: test %rbp,%rbp` | memory | 0x2a5755 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x2a51e2: test %rax,%rax` | call+memory | 0x2a5755 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x2a5204: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x2a5222: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x2a5240: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x2a525e: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x2a5284: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x2a52a4: test %eax,%eax` | arithmetic/control | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x2a52ac: test %r15,%r15` | memory | 0x2a52d2 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x2a52be: test %rdx,%rdx` | arithmetic/control | 0x2a52f4 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x2a52ea: test %rdx,%rdx` | memory | 0x2a5300 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x2a5303: sub $0x1,%r9` | memory | 0x2a5327 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x2a5309: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x2a5300 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x2a5320: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x2a5330 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x2a532a: sub $0x1,%r8` | arithmetic/control | 0x2a5320 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x2a5330: cmp %r9,%rdi` | memory | 0x2a5350 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x2a5340: sub $0x1,%rdi` | memory | 0x2a5352 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x2a534a: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x2a5340 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x2a536d | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x2a5365: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x2a537f: test %eax,%eax` | arithmetic/control | 0x2a5755 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x2a538c: test %r15,%r15` | memory | 0x2a539b | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x2a53b3: sub $0x1,%rdi` | memory | 0x2a53d7 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x2a53b9: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x2a53b0 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x2a53d0: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x2a53e0 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x2a53da: sub $0x1,%rsi` | arithmetic/control | 0x2a53d0 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x2a53e0: cmp %rdi,%rdx` | arithmetic/control | 0x2a53f5 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x2a53e5: sub $0x1,%rdx` | memory | 0x2a53f7 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x2a53ef: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x2a53e5 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x2a540e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x2a5406: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x2a5423: test %eax,%eax` | memory | 0x2a5755 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x2a543d: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x2a5460: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x2a547b: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x2a5495: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x2a54b7: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x2a54d1: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x2a54f4: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x2a5516: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x2a5538: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x2a555a: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x2a5574: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x2a5590: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x2a55b4: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x2a55ce: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x2a55ed: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x2a560c: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x2a562b: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x2a5645: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x2a5664: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x2a5681: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x2a56a6: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x2a56c5: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x2a56e1: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x2a56fa: test %eax,%eax` | call+memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x2a5713: test %eax,%eax` | memory | 0x2a5753 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x2a5729: test %eax,%eax` | memory | 0x2a5755 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x2a5755: test %rbx,%rbx` | memory | 0x2a5778 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x2a575e: test %rax,%rax` | memory | 0x2a5778 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x24e98b: test %rax,%rax` | memory | 0x24f3f8 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x24e9a5: cmpl $0x1,0x10(%rbp)` | memory | 0x24e9cd | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x24e9b5: test %rax,%rax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x24e9c4: cmp $0xfffffffd,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x24e9d5: testb $0x4,0xa4(%rbp)` | memory | 0x24e9f5 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x24e9de: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x24ea56 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x24e9e7: test %r13b,%r13b` | arithmetic/control | 0x24eb30 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x24e9fb: test %rax,%rax` | memory | 0x24f3f8 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x24ea29: test %rax,%rax` | arithmetic/control | 0x24ef40 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x24ea32: test %r15,%r15` | memory | 0x24ea40 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x24ea4a: test %rax,%rax` | arithmetic/control | 0x24eab8 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x24ea73: test %r15,%r15` | arithmetic/control | 0x24eb10 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x24ea7c: test %r14,%r14` | memory | 0x24ea8a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x24ea91: test %r15,%r15` | memory | 0x24eb02 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x24eaab: test %eax,%eax` | memory | 0x24eaf6 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x24ead4: test %eax,%eax` | memory | 0x24ef17 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x24eb02: test %r14,%r14` | memory | 0x24eb10 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x24eb16: or %r13b,%al` | arithmetic/control | 0x24ed42 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x24eb27: test %r15,%r15` | memory | 0x24f3f8 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x24eb36: test %rax,%rax` | memory | 0x24f3f8 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x24eb79: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x24eb87: test %rax,%rax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x24ebad: test %rax,%rax` | call+memory | 0x24f8a0 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x24ebd6: test %eax,%eax` | call+memory | 0x24f8a0 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x24ec24: test %al,0x38(%rsp)` | memory | 0x24eca3 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x24ec35: test %rax,%rax` | memory | 0x24f3f8 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x24ec5b: test %rax,%rax` | call+memory | 0x24f2f2 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x24ec95: test %ebp,%ebp` | arithmetic/control | 0x24f3fb | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x24eca5: test %ebx,%ebx` | memory | 0x24f15e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x24ecb7: test %r15b,%r15b` | call+memory | 0x24f168 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x24ecde: test %r13,%r13` | arithmetic/control | 0x24f89b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x24ecec: test %rax,%rax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x24ecfe: test %rax,%rax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x24ed0e: test %rcx,%rcx` | memory | 0x24f2ff | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x24ed26: cmpq $0x0,0x10(%rcx)` | memory | 0x24f309 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x24ed67: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x24ed85: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x24edaf: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x24edcd: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x24ee06: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x24ee28: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x24ee41: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x24ee49: test %rbx,%rbx` | memory | 0x24ee94 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x24ee58: cmpl $0x0,0x18(%rbx)` | memory | 0x24ee94 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x24ee6e: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x24ee76: cmpl $0x0,0x18(%rbx)` | memory | 0x24ee94 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x24ee8c: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x24eeaa: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x24eecc: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x24eee9: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x24ef27: test %r15,%r15` | memory | 0x24ef35 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x24ef35: test %bl,%bl` | memory | 0x24efe8 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x24ef62: test %rax,%rax` | arithmetic/control | 0x24eff0 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x24ef6b: test %r15,%r15` | memory | 0x24ef79 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x24ef83: test %rax,%rax` | arithmetic/control | 0x24ef8c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x24efa8: test %eax,%eax` | memory | 0x24efc3 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x24efd3: test %r15,%r15` | memory | 0x24efe1 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x24efe1: test %bl,%bl` | arithmetic/control | 0x24eff0 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x24effa: test %ebx,%ebx` | memory | 0x24f0eb | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x24f029: test %bl,%bl` | arithmetic/control | 0x24f151 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x24f034: cmp %r14,%r13` | memory | 0x24f0eb | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x24f068: test %rax,%rax` | arithmetic/control | 0x24f031 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x24f06d: test %r15,%r15` | memory | 0x24f07b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x24f07f: test %rax,%rax` | arithmetic/control | 0x24f08d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x24f086: test %r15,%r15` | arithmetic/control | 0x24f020 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x24f0a2: test %eax,%eax` | memory | 0x24f0c8 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x24f0ba: test %r15,%r15` | arithmetic/control | 0x24f020 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x24f0dd: test %r15,%r15` | arithmetic/control | 0x24f020 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x24f0f9: test %ebx,%ebx` | memory | 0x24f144 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x24f105: cmp 0x682264(%rip),%rax        # 8d1370 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x755a40>` | call+memory | 0x24e9de | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x24f16d: test %al,%r14b` | memory | 0x24f3ef | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x24f1a3: test %eax,%eax` | arithmetic/control | 0x24f3fb | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x24f1ab: test %rbx,%rbx` | memory | 0x24f1ce | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x24f1b0: cmpl $0x0,0x18(%rbx)` | memory | 0x24f1ce | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x24f1c6: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x24f1e3: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x24f1f1: test %rax,%rax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x24f23d: test %ebp,%ebp` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x24f245: test %rbx,%rbx` | memory | 0x24f26d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x24f24f: cmpl $0x0,0x18(%rbx)` | memory | 0x24f26d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x24f265: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x24f285: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x24f29e: test %eax,%eax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x24f2a6: cmpl $0x0,0x28(%rsp)` | memory | 0x24f5fc | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x24f2bc: test %rax,%rax` | memory | 0x24f3fb | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x24f2d2: test %rax,%rax` | memory | 0x24f509 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x24f2db: cmpq $0x0,0x10(%rax)` | memory | 0x24f509 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x24f34d: test %eax,%eax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x24f362: test %rax,%rax` | call+memory | 0x24f89b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x24f386: test %eax,%eax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x24f38e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x24f434 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x24f3e6: test %al,%r14b` | arithmetic/control | 0x24f176 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x24f3ef: test %r15b,%r15b` | arithmetic/control | 0x24f5fc | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x24f3fb: test %r12,%r12` | memory | 0x24f422 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x24f405: test %rax,%rax` | memory | 0x24f422 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x24f43d: test %rax,%rax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x24f457: test %rax,%rax` | memory | 0x24f46d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x24f45c: cmpq $0x2,0x10(%rax)` | memory | 0x24f46d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x24f4aa: test %eax,%eax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x24f4bf: test %rax,%rax` | call+memory | 0x24f89b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x24f4e3: test %eax,%eax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x24f4eb: cmpl $0x2,0x28(%rsp)` | memory | 0x24f7b3 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x24f521: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x24f53e: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x24f575: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x24f57d: cmpq $0x0,0x8(%rsp)` | memory | 0x24f5a9 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x24f58a: cmpl $0x0,0x18(%rax)` | memory | 0x24f5a9 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x24f5a1: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x24f5be: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x24f5d9: test %eax,%eax` | memory | 0x24f8b3 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x24f5e1: cmpl $0x1,0x28(%rsp)` | memory | 0x24f8cb | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x24f600: test %rdx,%rdx` | memory | 0x24f792 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x24f60d: test %rcx,%rcx` | memory | 0x24f792 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x24f61e: cmp 0x681d4b(%rip),%rax        # 8d1370 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x755a40>` | memory | 0x24f648 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x24f627: test %rax,%rax` | call+memory | 0x24f3f8 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x24f665: test %eax,%eax` | memory | 0x24f3fb | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x24f680: test %eax,%eax` | memory | 0x24f3fb | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x24f6a0: cmp %rdx,%rcx` | memory | 0x24f792 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x24f6a9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x24f6a0 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x24f6d4: test %eax,%eax` | memory | 0x24f79d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x24f6e1: cmpl $0x0,0x18(%rax)` | memory | 0x24f704 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x24f6fc: test %eax,%eax` | memory | 0x24f3fb | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x24f717: cmp %rdx,%rcx` | memory | 0x24f7a5 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x24f720: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x24f717 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x24f736: test %rax,%rax` | memory | 0x24f7ec | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x24f75b: test %rax,%rax` | call+memory | 0x24f8c3 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x24f7c1: test %rax,%rax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x24f7d6: test %rax,%rax` | memory | 0x24f7f7 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x24f7db: cmpq $0x3,0x10(%rax)` | memory | 0x24f7f7 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x24f834: test %eax,%eax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x24f845: test %rax,%rax` | call+memory | 0x24f89b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x24f865: test %eax,%eax` | memory | 0x24f89b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x24f869: cmpl $0x3,0x28(%rsp)` | memory | 0x24f3ab | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x24f8da: test %rax,%rax` | memory | 0x24f8f0 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x24f8df: cmpq $0x2,0x10(%rax)` | memory | 0x24f8f0 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x24f908: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x24f921: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x24f954: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x24f95c: cmpq $0x0,0x8(%rsp)` | memory | 0x24f988 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x24f969: cmpl $0x0,0x18(%rax)` | memory | 0x24f988 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x24f980: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x24f99d: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x24f9b8: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x24f9c0: cmpl $0x2,0x28(%rsp)` | memory | 0x24f5ec | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x24f9da: test %rax,%rax` | memory | 0x24f9f0 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x24f9df: cmpq $0x3,0x10(%rax)` | memory | 0x24f9f0 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x24fa08: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x24fa25: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x24fa5c: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x112a | je | mem | `0x24fa64: cmpq $0x0,0x8(%rsp)` | memory | 0x24fa90 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x24fa71: cmpl $0x0,0x18(%rax)` | memory | 0x24fa90 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x24fa88: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x24faa5: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x24fac0: test %eax,%eax` | memory | 0x24f8b3 | back |
| RSA CRT arms | +0x118d | je | mem | `0x24fac8: cmpl $0x3,0x28(%rsp)` | memory | 0x24f5ec | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x24867a: test %r8,%r8` | memory | 0x2487ab | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x2487a2: dec %r8` | memory | 0x248690 | back |
| DH key agreement (driver) | +0x26 | jle | reg/arith | `0x58cc01: cmp $0x2710,%eax` | memory | 0x58cc11 | fwd |
| DH key agreement (driver) | +0x39 | je | reg/arith | `0x58cc16: test %rdi,%rdi` | memory | 0x58cc3b | fwd |
| DH key agreement (driver) | +0x46 | jle | reg/arith | `0x58cc21: cmp $0x2710,%eax` | call+memory | 0x58cc3b | fwd |
| DH key agreement (driver) | +0x6b | jge | reg/arith | `0x58cc46: cmp $0x200,%eax` | call+memory | 0x58cc6c | fwd |
| DH key agreement (driver) | +0xbb | jne | mem | `0x58cc96: cmpl $0x1,0x30(%rsp)` | arithmetic/control | 0x58cca4 | fwd |
| DH key agreement (driver) | +0xe2 | je | reg/arith | `0x58ccbf: test %rax,%rax` | memory | 0x58cd42 | fwd |
| DH key agreement (driver) | +0x13f | je | reg/arith | `0x58cd1c: test %rax,%rax` | memory | 0x58ce86 | fwd |
| DH key agreement (driver) | +0x14e | je | mem | `0x58cd28: cmpq $0x0,0x78(%r12)` | memory | 0x58cd5f | fwd |
| DH key agreement (driver) | +0x159 | jne | mem | `0x58cd30: testb $0x1,0x80(%r12)` | arithmetic/control | 0x58cd8d | fwd |
| DH key agreement (driver) | +0x191 | je | reg/arith | `0x58cd6e: test %rdx,%rdx` | memory | 0x58ce73 | fwd |
| DH key agreement (driver) | +0x1a4 | jae | reg/arith | `0x58cd80: cmp $0x8,%rdx` | arithmetic/control | 0x58ce02 | fwd |
| DH key agreement (driver) | +0x1c5 | jne | reg/arith | `0x58cda2: test %rdx,%rdx` | memory | 0x58cedd | fwd |
| DH key agreement (driver) | +0x1d3 | je | reg/arith | `0x58cdab: test %rbp,%rbp` | memory | 0x58cdbe | fwd |
| DH key agreement (driver) | +0x1e9 | jne | reg/arith | `0x58cdc6: test %rdx,%rdx` | memory | 0x58cec5 | fwd |
| DH key agreement (driver) | +0x20a | je | reg/arith | `0x58cde8: test %eax,%eax` | memory | 0x58ceb8 | fwd |
| DH key agreement (driver) | +0x276 | jne | reg/arith | `0x58ce53: cmp %rsi,%rdx` | arithmetic/control | 0x58ce08 | back |
| DH key agreement (driver) | +0x27b | je | reg/arith | `0x58ce58: test %rax,%rax` | memory | 0x58ce73 | fwd |
| DH key agreement (driver) | +0x291 | jne | reg/arith | `0x58ce6e: cmp %rdx,%rax` | memory | 0x58ce63 | back |
| DH key agreement (driver) | +0x2b1 | je | reg/arith | `0x58ce89: test %rax,%rax` | memory | 0x58cea8 | fwd |
| DH key agreement (driver) | +0x2e8 | je | reg/arith | `0x58cec5: test %rbp,%rbp` | memory | 0x58cedd | fwd |
| DH key agreement (driver) | +0x305 | je | reg/arith | `0x58cee2: test %rax,%rax` | memory | 0x58ceeb | fwd |
| DH key agreement (driver) | +0x30e | je | reg/arith | `0x58ceeb: test %rdx,%rdx` | memory | 0x58cfd0 | fwd |
| DH key agreement (driver) | +0x324 | je | reg/arith | `0x58cf01: test %rax,%rax` | memory | 0x58cffc | fwd |
| DH key agreement (driver) | +0x331 | je | reg/arith | `0x58cf0e: test %rax,%rax` | call+memory | 0x58cffc | fwd |
| DH key agreement (driver) | +0x357 | je | reg/arith | `0x58cf35: test %eax,%eax` | memory | 0x58cfe7 | fwd |
| DH key agreement (driver) | +0x37a | je | reg/arith | `0x58cf57: test %rax,%rax` | memory | 0x58cff7 | fwd |
| DH key agreement (driver) | +0x390 | je | reg/arith | `0x58cf6e: test %eax,%eax` | memory | 0x58cff0 | fwd |
| DH key agreement (driver) | +0x3a6 | jle | reg/arith | `0x58cf84: test %eax,%eax` | memory | 0x58cff0 | fwd |
| DH key agreement (driver) | +0x3bf | je | reg/arith | `0x58cf96: test %eax,%eax` | memory | 0x58cff7 | fwd |
| DH key agreement (driver) | +0x3cf | jo | reg/arith | `0x58cfac: add $0x7,%eax` | memory | 0x58d0cc | fwd |
| DH key agreement (driver) | +0x422 | je | reg/arith | `0x58cfff: test %rdx,%rdx` | memory | 0x58d08c | fwd |
| DH key agreement (driver) | +0x435 | jae | reg/arith | `0x58d011: cmp $0x8,%rdx` | arithmetic/control | 0x58d01b | fwd |
| DH key agreement (driver) | +0x48f | jne | reg/arith | `0x58d06c: cmp %rsi,%rdx` | arithmetic/control | 0x58d021 | back |
| DH key agreement (driver) | +0x494 | je | reg/arith | `0x58d071: test %rax,%rax` | memory | 0x58d08c | fwd |
| DH key agreement (driver) | +0x4aa | jne | reg/arith | `0x58d087: cmp %rdx,%rax` | memory | 0x58d07c | back |
| DH key agreement (driver) | +0x4ca | je | reg/arith | `0x58d0a2: test %rax,%rax` | memory | 0x58d0c1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x37 | je | reg/arith | `0x58d68c: test %r10,%r10` | memory | 0x58d9b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x53 | je | reg/arith | `0x58d6b0: cmp %rcx,%rax` | memory | 0x58d9b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x62 | je | mem | `0x58d6b9: cmpq $0x0,(%r11,%rcx,1)` | memory | 0x58d6b0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x6b | je | reg/arith | `0x58d6c8: test %rcx,%rcx` | memory | 0x58d9b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x93 | je | reg/arith | `0x58d6f0: cmp %r9,%rdx` | memory | 0x58d9b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa2 | je | mem | `0x58d6f9: cmpq $0x0,(%rax,%r9,1)` | arithmetic/control | 0x58d6f0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xa7 | je | reg/arith | `0x58d704: cmp %r10,%r12` | arithmetic/control | 0x58d990 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbd | je | reg/arith | `0x58d71a: test %r9b,%dl` | arithmetic/control | 0x58d990 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc9 | je | reg/arith | `0x58d726: test %rsi,%rsi` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd6 | je | reg/arith | `0x58d733: test %r10,%r10` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe3 | je | reg/arith | `0x58d740: test %r9,%r9` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf0 | je | reg/arith | `0x58d74d: test %r8,%r8` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x101 | je | reg/arith | `0x58d75e: test %rdx,%rdx` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10e | je | reg/arith | `0x58d76b: test %rdx,%rdx` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11e | je | reg/arith | `0x58d77b: test %rbx,%rbx` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12e | je | reg/arith | `0x58d78b: test %rdi,%rdi` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x155 | jne | reg/arith | `0x58d7b2: or %rbx,%rdi` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x163 | jne | mem | `0x58d7bb: cmpq $0x0,0x118(%rdx)` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x171 | jne | mem | `0x58d7c9: cmpq $0x0,0x120(%rdx)` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x17f | jne | mem | `0x58d7d7: cmpq $0x0,0x128(%rdx)` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x193 | jne | mem | `0x58d7ec: cmp %rbx,0x1a8(%rdx)` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x19e | jne | mem | `0x58d7f9: cmpq $0x4,0x10(%r10)` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1e2 | jne | reg/arith | `0x58d83f: or %r10b,%dil` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x211 | jne | reg/arith | `0x58d86b: cmp $0xffff,%edx` | memory | 0x58d978 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x252 | jne | reg/arith | `0x58d8ae: cmp $0x4,%rdi` | memory | 0x58d970 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x281 | jne | reg/arith | `0x58d8db: cmp $0xffff,%esi` | memory | 0x58d970 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2db | jne | reg/arith | `0x58d937: cmp $0x4,%rdi` | memory | 0x58d970 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x30a | je | reg/arith | `0x58d964: cmp $0xffff,%esi` | call+memory | 0x58ed85 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x33a | jne | reg/arith | `0x58d997: or %r12,%rax` | memory | 0x58d9b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x343 | je | reg/arith | `0x58d9a0: cmp %r10,%rdx` | call+memory | 0x58da71 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x359 | je | reg/arith | `0x58d9b6: test %r12,%r12` | memory | 0x58da71 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x366 | je | reg/arith | `0x58d9c3: test %r15,%r15` | memory | 0x58daa7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x38d | je | reg/arith | `0x58d9db: test %rax,%rax` | memory | 0x58dac6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x398 | je | mem | `0x58d9f3: cmpq $0x0,0x10(%rax)` | memory | 0x58dac6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3b5 | je | reg/arith | `0x58da12: test %rax,%rax` | memory | 0x58daba | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3c5 | jne | mem | `0x58da22: cmp (%r15),%rcx` | memory | 0x58dac1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3e3 | je | reg/arith | `0x58da40: test %r10d,%r10d` | memory | 0x58e109 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3f0 | je | reg/arith | `0x58da4d: test %r9d,%r9d` | arithmetic/control | 0x58da57 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3f5 | jne | reg/arith | `0x58da52: cmp %r9d,%r10d` | memory | 0x58dac1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3fa | jne | mem | `0x58da57: cmp (%rdx),%rcx` | memory | 0x58dac1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x401 | je | reg/arith | `0x58da5f: test %ecx,%ecx` | arithmetic/control | 0x58e112 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x40a | jne | reg/arith | `0x58da67: cmp %ecx,%r10d` | arithmetic/control | 0x58dac1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4a5 | jb | reg/arith | `0x58db02: add %rbx,%r12` | call+memory | 0x58ed4e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4f9 | je | reg/arith | `0x58db55: cmp $0xffffffffffffffff,%r12` | call+memory | 0x58ed57 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x53f | je | reg/arith | `0x58db9c: test %r15,%r15` | memory | 0x58ddd8 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x55d | je | reg/arith | `0x58dbb5: test %rdi,%rdi` | arithmetic/control | 0x58de3b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x566 | je | reg/arith | `0x58dbc3: test %rbx,%rbx` | arithmetic/control | 0x58de3b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x56f | je | reg/arith | `0x58dbcc: test %r12,%r12` | memory | 0x58de3b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x57a | jb | mem | `0x58dbd5: add 0x58(%rsp),%r13` | memory | 0x58ed60 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x58d | je | unknown | `?` | memory | 0x58df40 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5ca | jae | mem | `0x58dc25: cmp 0x58(%rsp),%r14` | memory | 0x58dc35 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5e5 | ja | reg/arith | `0x58dc40: cmp $0x7cf,%eax` | arithmetic/control | 0x58dc80 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5f1 | ja | reg/arith | `0x58dc4c: cmp $0x31f,%eax` | arithmetic/control | 0x58dc80 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5fd | ja | reg/arith | `0x58dc58: cmp $0x12b,%eax` | arithmetic/control | 0x58dc80 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x607 | ja | reg/arith | `0x58dc64: cmp $0x45,%eax` | memory | 0x58dc80 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x635 | jb | reg/arith | `0x58dc92: add %rax,%r13` | memory | 0x58ed75 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x653 | jae | mem | `0x58dcae: cmp 0x58(%rsp),%r14` | call+memory | 0x58dcbe | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x67d | je | reg/arith | `0x58dcda: test %rax,%rax` | memory | 0x58df68 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6a6 | jne | reg/arith | `0x58dcfe: dec %r15` | memory | 0x58dc20 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x6b9 | je | reg/arith | `0x58dd11: test %r14,%r14` | memory | 0x58df5f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6cb | je | reg/arith | `0x58dd24: test %rax,%rax` | memory | 0x58e02e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6e2 | je | mem | `0x58dd3d: cmpb $0x0,0x78(%rsp)` | call+memory | 0x58e060 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x712 | je | reg/arith | `0x58dd67: test %rax,%rax` | memory | 0x58e048 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x72e | jbe | mem | `0x58dd85: cmp 0x60(%rsp),%rcx` | arithmetic/control | 0x58e168 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x73a | jo | reg/arith | `0x58dd97: mul %rsi` | memory | 0x58f208 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x74c | jae | reg/arith | `0x58dda9: cmp %rax,%rcx` | arithmetic/control | 0x58e21d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x755 | je | reg/arith | `0x58ddb2: test %rsi,%rsi` | arithmetic/control | 0x58f21d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x765 | je | reg/arith | `0x58ddc1: shr $0x20,%rax` | division | 0x58e1b8 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x784 | je | reg/arith | `0x58dddc: test %rdi,%rdi` | call+memory | 0x58de09 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7ac | je | reg/arith | `0x58de09: test %rbx,%rbx` | memory | 0x58df0a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7de | je | reg/arith | `0x58de3b: test %rdi,%rdi` | call+memory | 0x58de63 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x80b | je | reg/arith | `0x58de63: test %rbx,%rbx` | call+memory | 0x58de93 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x83a | je | reg/arith | `0x58de97: test %rdi,%rdi` | memory | 0x58dee4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x882 | jne | reg/arith | `0x58dedf: test %rdi,%rdi` | call+memory | 0x58dec0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x8af | je | reg/arith | `0x58df0c: test %r12,%r12` | call+memory | 0x58e6f0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8f9 | jne | reg/arith | `0x58df51: test %r14,%r14` | memory | 0x58dd1f | back |
| EC wNAF multiply (verification / public-scalar core) | +0x95b | je | reg/arith | `0x58dfb8: test %rdi,%rdi` | call+memory | 0x58dff4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x992 | jne | reg/arith | `0x58dfef: test %rdi,%rdi` | call+memory | 0x58dfd0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x9d6 | jne | mem | `0x58e02e: cmpb $0x0,0x128(%rsp)` | call+memory | 0x58e34c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa60 | je | reg/arith | `0x58e0bd: test %rdi,%rdi` | call+memory | 0x58e564 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xaa2 | jne | reg/arith | `0x58e0ff: test %rdi,%rdi` | arithmetic/control | 0x58e0e0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xaac | jne | mem | `0x58e109: cmp (%rdx),%rcx` | call+memory | 0x58dac1 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xac1 | jne | reg/arith | `0x58e11f: test %eax,%eax` | memory | 0x58dac6 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xadc | je | reg/arith | `0x58e139: test %r13,%r13` | arithmetic/control | 0x58f226 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xaf2 | je | reg/arith | `0x58e14e: shr $0x20,%rdx` | division | 0x58e9fb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb11 | je | reg/arith | `0x58e16d: cmp $0xffffffffffffffff,%rcx` | memory | 0x58f211 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb6f | jbe | mem | `0x58e1cb: cmp 0x10(%rcx),%rax` | call+memory | 0x58e20a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbb7 | jb | mem | `0x58e20a: add 0x58(%rsp),%rax` | memory | 0x58f282 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbcd | jae | reg/arith | `0x58e22a: cmp %rax,%r14` | memory | 0x58e31f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbf5 | jae | mem | `0x58e24b: cmp 0x48(%rsp),%r14` | memory | 0x58e280 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc0b | jb | reg/arith | `0x58e268: sub %rsi,%rax` | memory | 0x58ea7b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc57 | je | reg/arith | `0x58e2b4: test %rax,%rax` | memory | 0x58e968 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc76 | je | mem | `0x58e2d2: cmpq $0x0,(%rdi)` | memory | 0x58e9b2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xcb9 | jne | mem | `0x58e30d: cmp %r14,0x80(%rsp)` | call+memory | 0x58e24b | back |
| EC wNAF multiply (verification / public-scalar core) | +0xcf0 | je | reg/arith | `0x58e34c: cmp $0xffffffffffffffff,%r13` | memory | 0x58ed69 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd14 | je | reg/arith | `0x58e371: test %rax,%rax` | memory | 0x58e4d6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd36 | je | mem | `0x58e385: cmpq $0x0,0x88(%rsp)` | memory | 0x58e498 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd65 | je | reg/arith | `0x58e3c2: test %rcx,%rcx` | memory | 0x58f24d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd71 | je | mem | `0x58e3cb: cmpq $0x0,0x30(%rsp)` | memory | 0x58e948 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd84 | ja | reg/arith | `0x58e3e0: cmp $0x40,%rcx` | arithmetic/control | 0x58f266 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd95 | jne | reg/arith | `0x58e3f2: test %rax,%rax` | memory | 0x58e47d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xda8 | je | mem | `0x58e403: cmpq $0x0,0x50(%rax)` | memory | 0x58e5bf | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdc8 | je | reg/arith | `0x58e425: test %rax,%rax` | memory | 0x58e5af | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdea | je | reg/arith | `0x58e447: test %rax,%rax` | call | 0x58e589 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xdf7 | je | reg/arith | `0x58e455: test %eax,%eax` | memory | 0x58e589 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe12 | jne | reg/arith | `0x58e46f: test %rcx,%rcx` | arithmetic/control | 0x58e3e0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xe32 | jne | mem | `0x58e480: cmp 0x88(%rsp),%r14` | memory | 0x58e3ba | back |
| EC wNAF multiply (verification / public-scalar core) | +0xe42 | je | reg/arith | `0x58e49c: cmp %rax,%rbx` | call+memory | 0x58e701 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec8 | je | reg/arith | `0x58e525: test %rdi,%rdi` | call+memory | 0x58e564 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf02 | jne | reg/arith | `0x58e55f: test %rdi,%rdi` | memory | 0x58e540 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xfc9 | je | reg/arith | `0x58e626: test %rdi,%rdi` | call+memory | 0x58e664 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1002 | jne | reg/arith | `0x58e65f: test %rdi,%rdi` | call+memory | 0x58e640 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x102e | je | reg/arith | `0x58e68b: test %rdi,%rdi` | call+memory | 0x58e6af | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x104d | jne | reg/arith | `0x58e6aa: test %rdi,%rdi` | call+memory | 0x58e6a0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x10af | je | reg/arith | `0x58e70c: test %rax,%rax` | memory | 0x58e8b6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10c5 | je | reg/arith | `0x58e722: test %rbx,%rbx` | memory | 0x58e8c7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x10f3 | je | reg/arith | `0x58e74b: cmp %rbx,%r15` | memory | 0x58e8c7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1105 | jae | mem | `0x58e760: cmp 0x58(%rsp),%r15` | memory | 0x58e775 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1125 | je | reg/arith | `0x58e783: test %eax,%eax` | memory | 0x58ec84 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1134 | jbe | mem | `0x58e78f: cmpq $0x1,(%rax,%r15,8)` | memory | 0x58e748 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1153 | je | reg/arith | `0x58e7b1: test %eax,%eax` | memory | 0x58e92b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1164 | je | reg/arith | `0x58e7c1: test %rcx,%rcx` | arithmetic/control | 0x58f24d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1174 | ja | reg/arith | `0x58e7d0: cmp $0x40,%rcx` | arithmetic/control | 0x58f266 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1185 | jne | reg/arith | `0x58e7e2: test %rax,%rax` | memory | 0x58e748 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x119d | je | reg/arith | `0x58e7fa: test %rax,%rax` | memory | 0x58eae3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11ae | jne | mem | `0x58e80b: cmp (%rsi),%r9` | memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11c3 | je | reg/arith | `0x58e821: test %edi,%edi` | memory | 0x58e873 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11cc | je | reg/arith | `0x58e829: test %r8d,%r8d` | arithmetic/control | 0x58e837 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11d1 | jne | reg/arith | `0x58e82e: cmp %r8d,%edi` | memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11da | jne | mem | `0x58e837: cmp (%rdx),%r9` | memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11e7 | je | reg/arith | `0x58e844: test %r8d,%r8d` | arithmetic/control | 0x58e852 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11ec | jne | reg/arith | `0x58e849: cmp %r8d,%edi` | memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x11fa | jne | mem | `0x58e857: cmp (%rcx),%r9` | memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1207 | je | reg/arith | `0x58e864: test %r8d,%r8d` | arithmetic/control | 0x58e88a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x120c | je | reg/arith | `0x58e869: cmp %r8d,%edi` | arithmetic/control | 0x58e88a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1216 | jne | mem | `0x58e873: cmp (%rdx),%r9` | memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1224 | jne | mem | `0x58e881: cmp (%rcx),%r9` | call+memory | 0x58e91f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1237 | je | reg/arith | `0x58e895: test %eax,%eax` | memory | 0x58e92b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x124b | jne | reg/arith | `0x58e8a8: test %rcx,%rcx` | arithmetic/control | 0x58e7d0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1279 | je | reg/arith | `0x58e8d6: test %rax,%rax` | call+memory | 0x58ec84 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1294 | je | reg/arith | `0x58e8ee: test %eax,%eax` | memory | 0x58ead9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12aa | jbe | reg/arith | `0x58e8ff: cmp $0x7fffffff,%rax` | memory | 0x58eaef | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12ec | jae | reg/arith | `0x58e948: cmp $0x41,%rcx` | memory | 0x58f266 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13aa | je | reg/arith | `0x58ea06: cmp $0xffffffffffffffff,%rdi` | memory | 0x58f235 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13c9 | jb | reg/arith | `0x58ea25: sub $0x1,%rcx` | arithmetic/control | 0x58f241 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13d3 | jae | reg/arith | `0x58ea2f: cmp $0x41,%rdx` | memory | 0x58f25a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13e9 | jo | reg/arith | `0x58ea46: mul %rdx` | memory | 0x58f273 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13f8 | jne | mem | `0x58ea54: cmp %rax,0x28(%rcx)` | memory | 0x58ea6f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1492 | je | reg/arith | `0x58eaef: test %rax,%rax` | memory | 0x58f28e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14c6 | jle | mem | `0x58eb0e: cmpl $0x1,0x40(%rsp)` | arithmetic/control | 0x58ecbc | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14d2 | jne | reg/arith | `0x58eb2f: test %r15d,%r15d` | memory | 0x58eb4d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14e7 | je | reg/arith | `0x58eb45: test %eax,%eax` | memory | 0x58ecd3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1504 | je | mem | `0x58eb56: cmpq $0x0,0x80(%rsp)` | arithmetic/control | 0x58eb0e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x152e | je | reg/arith | `0x58eb87: test %eax,%eax` | memory | 0x58eca7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x153f | je | mem | `0x58eb97: cmp %rbx,0x80(%rsp)` | memory | 0x58eb0e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x154e | jbe | mem | `0x58ebaa: cmp %r13,(%rax,%rbx,8)` | memory | 0x58eb94 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1561 | je | reg/arith | `0x58ebbe: test %r14d,%r14d` | memory | 0x58eb94 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x156d | je | mem | `0x58ebc9: cmp %eax,0x58(%rsp)` | arithmetic/control | 0x58ebff | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1572 | jne | reg/arith | `0x58ebcf: test %r15d,%r15d` | memory | 0x58ebf0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x158a | je | reg/arith | `0x58ebe8: test %eax,%eax` | memory | 0x58e92b | back |
| EC wNAF multiply (verification / public-scalar core) | +0x15bd | je | reg/arith | `0x58ec1a: test %r15d,%r15d` | memory | 0x58eb6d | back |
| EC wNAF multiply (verification / public-scalar core) | +0x15d8 | je | reg/arith | `0x58ec31: test %eax,%eax` | memory | 0x58ec84 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x15ef | je | reg/arith | `0x58ec4c: test %rax,%rax` | call+memory | 0x58eb94 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1602 | jne | reg/arith | `0x58ec60: test %eax,%eax` | call+memory | 0x58eb94 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x165f | je | reg/arith | `0x58ecbc: test %r15d,%r15d` | memory | 0x58ece1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1686 | je | mem | `0x58ece1: cmpl $0x0,0x58(%rsp)` | memory | 0x58ed00 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x169e | je | reg/arith | `0x58ecfc: test %eax,%eax` | call+memory | 0x58ed2c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1731 | jne | reg/arith | `0x58ed85: cmp $0x1,%rcx` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x173b | jne | mem | `0x58ed97: cmpq $0x1,(%rax)` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1749 | je | mem | `0x58eda5: cmpl $0x0,0x28(%rax)` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x175a | je | reg/arith | `0x58edb7: test %rdx,%rdx` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x176b | je | reg/arith | `0x58edc8: test %rax,%rax` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x17c5 | jne | reg/arith | `0x58ee21: cmp $0x4,%rdx` | memory | 0x58d970 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x17f8 | jne | reg/arith | `0x58ee52: cmp $0xffff,%ecx` | memory | 0x58d970 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1852 | jne | reg/arith | `0x58eeae: cmp $0x4,%rax` | memory | 0x58d970 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1884 | jne | reg/arith | `0x58eedf: cmp $0xffff,%eax` | memory | 0x58d970 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1898 | jne | mem | `0x58eeea: cmpl $0x0,0x18(%r12)` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x18a7 | ja | reg/arith | `0x58ef03: cmp $0x4,%rdx` | memory | 0x58d978 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x19f8 | jne | reg/arith | `0x58f056: test %al,%al` | call+memory | 0x58d970 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1a9a | jne | reg/arith | `0x58f0f8: test %eax,%eax` | call+memory | 0x58f2d2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1b0d | je | reg/arith | `0x58f16b: test %al,%al` | call+memory | 0x58f297 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1b30 | je | reg/arith | `0x58f18e: test %al,%al` | call+memory | 0x58f297 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1b53 | je | reg/arith | `0x58f1b1: test %al,%al` | call+memory | 0x58f297 | fwd |
| ML-KEM decapsulation (provider driver) | +0x7 | je | mem | `0x4060d2: cmpq $0x0,0x50(%r8)` | arithmetic/control | 0x4062a3 | fwd |
| ML-KEM decapsulation (provider driver) | +0x1f | jne | reg/arith | `0x4060ec: or %r9b,%r10b` | memory | 0x4062a3 | fwd |
| ML-KEM decapsulation (provider driver) | +0x5c | jne | reg/arith | `0x406129: or %al,%sil` | memory | 0x40627a | fwd |
| ML-KEM decapsulation (provider driver) | +0x66 | jne | mem | `0x406132: cmp 0x28(%r15),%rcx` | memory | 0x40627a | fwd |
| ML-KEM decapsulation (provider driver) | +0x8f | je | reg/arith | `0x40615c: test %rax,%rax` | memory | 0x40627a | fwd |
| ML-KEM decapsulation (provider driver) | +0xa2 | je | reg/arith | `0x40616c: cmp $0x5ae,%ecx` | arithmetic/control | 0x40638a | fwd |
| ML-KEM decapsulation (provider driver) | +0xae | je | reg/arith | `0x406178: cmp $0x5af,%ecx` | arithmetic/control | 0x4062a4 | fwd |
| ML-KEM decapsulation (provider driver) | +0xbc | jne | reg/arith | `0x406186: cmp $0x5b0,%ecx` | call+memory | 0x406475 | fwd |
| ML-KEM decapsulation (provider driver) | +0x163 | jne | reg/arith | `0x40622c: cmp $0x1000,%r15` | memory | 0x4061e0 | back |
| ML-KEM decapsulation (provider driver) | +0x1a3 | jne | reg/arith | `0x40626c: cmp $0x627,%rcx` | arithmetic/control | 0x406240 | back |
| ML-KEM decapsulation (provider driver) | +0x26b | jne | reg/arith | `0x406334: cmp $0xc07,%rcx` | memory | 0x4062f0 | back |
| ML-KEM decapsulation (provider driver) | +0x2b3 | jne | reg/arith | `0x40637c: cmp $0x447,%rcx` | arithmetic/control | 0x406350 | back |
| ML-KEM decapsulation (provider driver) | +0x363 | jne | reg/arith | `0x40642c: cmp $0x800,%r15` | memory | 0x4063e0 | back |
| ML-KEM decapsulation (provider driver) | +0x3a3 | jne | reg/arith | `0x40646c: cmp $0x307,%rcx` | arithmetic/control | 0x406440 | back |
| ML-KEM decapsulation (provider driver) | +0x3a8 | jne | reg/arith | `0x406475: test $0x7,%bl` | memory | 0x406292 | back |
| ML-KEM K-PKE decrypt | +0x65 | js | reg/arith | `0x5972c2: test %r14,%r14` | memory | 0x597c8b | fwd |
| ML-KEM K-PKE decrypt | +0x70 | jle | reg/arith | `0x5972ce: test %ebp,%ebp` | arithmetic/control | 0x5974e5 | fwd |
| ML-KEM K-PKE decrypt | +0x84 | ja | reg/arith | `0x5972e0: cmp $0xf,%r14d` | memory | 0x597c7e | fwd |
| ML-KEM K-PKE decrypt | +0x9f | jae | reg/arith | `0x5972f7: cmp $0x20,%eax` | memory | 0x597c98 | fwd |
| ML-KEM K-PKE decrypt | +0x140 | jae | reg/arith | `0x597399: cmp $0x100,%rdx` | arithmetic/control | 0x59743b | fwd |
| ML-KEM K-PKE decrypt | +0x148 | jne | reg/arith | `0x5973a6: test %ecx,%ecx` | memory | 0x5973b6 | fwd |
| ML-KEM K-PKE decrypt | +0x169 | je | reg/arith | `0x5973c6: test %bl,%r11b` | memory | 0x5973f0 | fwd |
| ML-KEM K-PKE decrypt | +0x18b | jb | reg/arith | `0x5973e4: cmp $0x100,%rdx` | arithmetic/control | 0x5973a6 | back |
| ML-KEM K-PKE decrypt | +0x196 | jb | reg/arith | `0x5973f3: sub %eax,%r10d` | arithmetic/control | 0x597380 | back |
| ML-KEM K-PKE decrypt | +0x19d | jb | reg/arith | `0x5973fb: sub %eax,%ecx` | arithmetic/control | 0x597d83 | fwd |
| ML-KEM K-PKE decrypt | +0x1a6 | ja | reg/arith | `0x597403: cmp $0xf,%ecx` | memory | 0x597d76 | fwd |
| ML-KEM K-PKE decrypt | +0x1d5 | jb | reg/arith | `0x59742e: cmp $0x100,%rdx` | memory | 0x5973a6 | back |
| ML-KEM K-PKE decrypt | +0x24e | jne | reg/arith | `0x5974a8: cmp $0x100,%rax` | call | 0x597440 | back |
| ML-KEM K-PKE decrypt | +0x27f | jg | reg/arith | `0x5974dc: dec %r13d` | memory | 0x597360 | back |
| ML-KEM K-PKE decrypt | +0x28e | ja | reg/arith | `0x5974ea: cmp $0xf,%r15d` | memory | 0x597c7e | fwd |
| ML-KEM K-PKE decrypt | +0x2ef | jbe | reg/arith | `0x597548: cmp $0xff,%rsi` | arithmetic/control | 0x597582 | fwd |
| ML-KEM K-PKE decrypt | +0x320 | ja | reg/arith | `0x597579: cmp $0xff,%rsi` | arithmetic/control | 0x5975e2 | fwd |
| ML-KEM K-PKE decrypt | +0x324 | jne | reg/arith | `0x597582: test %ecx,%ecx` | memory | 0x597592 | fwd |
| ML-KEM K-PKE decrypt | +0x345 | jne | reg/arith | `0x5975a2: test %bl,%r11b` | arithmetic/control | 0x597560 | back |
| ML-KEM K-PKE decrypt | +0x34d | jb | reg/arith | `0x5975aa: sub %eax,%r10d` | arithmetic/control | 0x597530 | back |
| ML-KEM K-PKE decrypt | +0x354 | jb | reg/arith | `0x5975b2: sub %eax,%ecx` | arithmetic/control | 0x597d83 | fwd |
| ML-KEM K-PKE decrypt | +0x35d | jae | reg/arith | `0x5975ba: cmp $0x10,%ecx` | memory | 0x597d76 | fwd |
| ML-KEM K-PKE decrypt | +0x389 | ja | reg/arith | `0x5975e6: cmp $0x1f,%eax` | memory | 0x597d69 | fwd |
| ML-KEM K-PKE decrypt | +0x43e | jne | reg/arith | `0x597698: cmp $0x100,%rax` | call+memory | 0x597630 | back |
| ML-KEM K-PKE decrypt | +0x4fc | jne | reg/arith | `0x597756: cmp $0x100,%rax` | memory | 0x5976e0 | back |
| ML-KEM K-PKE decrypt | +0x614 | jne | reg/arith | `0x59786e: cmp $0x100,%rax` | memory | 0x5977a0 | back |
| ML-KEM K-PKE decrypt | +0x96b | jne | reg/arith | `0x597bc7: cmp $0x20,%rcx` | memory | 0x5978d0 | back |
| ML-KEM K-PKE decrypt | +0x9b2 | jne | reg/arith | `0x597c0c: cmp $0x200,%rax` | memory | 0x597be0 | back |
| ML-KEM K-PKE decrypt | +0xa0a | jne | reg/arith | `0x597c64: cmp $0x200,%rax` | arithmetic/control | 0x597c20 | back |
| ML-KEM K-PKE decrypt | +0xa66 | ja | reg/arith | `0x597cbf: cmp $0xff,%rdx` | arithmetic/control | 0x597d69 | fwd |
| ML-KEM K-PKE decrypt | +0xa6e | jne | reg/arith | `0x597ccc: test %ecx,%ecx` | memory | 0x597cdc | fwd |
| ML-KEM K-PKE decrypt | +0xa90 | je | reg/arith | `0x597ced: test %r11b,%r10b` | memory | 0x597d20 | fwd |
| ML-KEM K-PKE decrypt | +0xab5 | jbe | reg/arith | `0x597d0e: cmp $0xff,%rdx` | arithmetic/control | 0x597ccc | back |
| ML-KEM K-PKE decrypt | +0xac6 | jb | reg/arith | `0x597d23: sub %eax,%r9d` | arithmetic/control | 0x597ca7 | back |
| ML-KEM K-PKE decrypt | +0xad1 | jb | reg/arith | `0x597d2f: sub %eax,%ecx` | arithmetic/control | 0x597d83 | fwd |
| ML-KEM K-PKE decrypt | +0xad6 | jae | reg/arith | `0x597d33: cmp $0x10,%ecx` | memory | 0x597d76 | fwd |
| ML-KEM K-PKE decrypt | +0xb03 | jbe | reg/arith | `0x597d5c: cmp $0xff,%rdx` | memory | 0x597ccc | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xc3 | jle | reg/arith | `0x597e40: test %r12,%r12` | call+memory | 0x597eb4 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x103 | je | reg/arith | `0x597e91: test %eax,%eax` | call | 0x599d48 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x120 | jg | reg/arith | `0x597ead: cmp $0x1,%ebp` | arithmetic/control | 0x597e70 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x237 | jle | reg/arith | `0x597fb4: test %r14d,%r14d` | memory | 0x598cdd | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x44e | jle | reg/arith | `0x5981cf: cmp $0x1,%r12d` | memory | 0x598acc | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x4ee | jne | reg/arith | `0x598272: test $0x1,%dil` | arithmetic/control | 0x5984f0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x4f6 | jne | reg/arith | `0x598284: and %dl,%cl` | memory | 0x5984f0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x747 | jne | reg/arith | `0x5984d0: cmp $0x100,%rdx` | arithmetic/control | 0x5982a0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x843 | jne | reg/arith | `0x5985cc: cmp $0x100,%rcx` | memory | 0x598500 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x854 | je | reg/arith | `0x5985e1: cmp $0x1,%edx` | memory | 0x598170 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x9b4 | jle | reg/arith | `0x59873e: cmp $0x2,%edx` | arithmetic/control | 0x598170 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x9be | je | reg/arith | `0x59874c: test $0x1,%al` | memory | 0x598860 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xac1 | jne | reg/arith | `0x59884a: cmp $0x100,%rsi` | arithmetic/control | 0x598760 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xd31 | jne | reg/arith | `0x598aba: cmp $0x100,%rsi` | arithmetic/control | 0x598860 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xe07 | je | reg/arith | `0x598b95: test %eax,%eax` | memory | 0x598c75 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xedf | jne | reg/arith | `0x598c68: cmp $0x80,%rcx` | memory | 0x598ba0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf33 | jne | reg/arith | `0x598cbc: cmp $0x80,%rcx` | arithmetic/control | 0x598c90 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf37 | je | reg/arith | `0x598cc5: test %eax,%eax` | arithmetic/control | 0x599df5 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf47 | jg | reg/arith | `0x598cd4: dec %r14d` | memory | 0x598b10 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1062 | je | reg/arith | `0x598df0: test %al,%al` | memory | 0x598e80 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x10db | jne | reg/arith | `0x598e64: cmp $0x101,%r8` | arithmetic/control | 0x598e00 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1175 | jne | reg/arith | `0x598efe: cmp $0x108,%r9` | arithmetic/control | 0x598e90 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1179 | jo | reg/arith | `0x598f07: dec %edx` | arithmetic/control | 0x599faf | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x118f | jg | reg/arith | `0x598f1d: test %edx,%edx` | memory | 0x598df0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11a6 | ja | reg/arith | `0x598f33: cmp $0x1f,%ecx` | memory | 0x599ffd | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1359 | jne | reg/arith | `0x5990e2: cmp $0x100,%rdx` | arithmetic/control | 0x598fa0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1361 | jo | reg/arith | `0x5990ef: dec %eax` | arithmetic/control | 0x599fbc | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1370 | jg | reg/arith | `0x5990fe: test %eax,%eax` | call+memory | 0x598f90 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1424 | je | reg/arith | `0x5991b2: test %eax,%eax` | memory | 0x5992a4 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x150e | jne | reg/arith | `0x599297: cmp $0x80,%rcx` | memory | 0x5991d0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1563 | jne | reg/arith | `0x5992ec: cmp $0x80,%rcx` | arithmetic/control | 0x5992c0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1567 | je | reg/arith | `0x5992f5: test %eax,%eax` | memory | 0x599ea2 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15ff | jne | reg/arith | `0x599389: cmp $0x100,%rax` | memory | 0x599310 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1d68 | jne | reg/arith | `0x599af4: cmp $0x20,%rax` | arithmetic/control | 0x5993a0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1d71 | ja | reg/arith | `0x599afe: cmp $0x1f,%ebx` | arithmetic/control | 0x599ffd | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f10 | jne | reg/arith | `0x599c9a: cmp $0x100,%rax` | memory | 0x599b50 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f42 | je | reg/arith | `0x599ccc: cmp $0x200,%rax` | arithmetic/control | 0x599d3e | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f48 | jb | reg/arith | `0x599cd6: add %ebx,%esi` | memory | 0x599fc9 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f59 | jb | reg/arith | `0x599ce6: cmp $0x40,%esi` | arithmetic/control | 0x599cc0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f5b | jne | unknown | `?` | arithmetic/control | 0x599d10 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f60 | jae | reg/arith | `0x599ced: cmp $0x40,%ecx` | memory | 0x599ff0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f83 | jae | reg/arith | `0x599d10: cmp $0x40,%ecx` | memory | 0x599fd6 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f97 | je | reg/arith | `0x599d25: test %ecx,%ecx` | arithmetic/control | 0x599fe3 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x210c | je | reg/arith | `0x599e99: test %r14d,%r14d` | memory | 0x598d81 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x220b | jne | reg/arith | `0x599f94: cmp $0x200,%rcx` | arithmetic/control | 0x599f50 | back |
| ML-KEM inverse NTT | +0x56 | jb | reg/arith | `0x59af63: add %rsi,%rbx` | memory | 0x59b444 | fwd |
| ML-KEM inverse NTT | +0x64 | ja | reg/arith | `0x59af70: cmp $0x7e,%r8` | memory | 0x59b451 | fwd |
| ML-KEM inverse NTT | +0xb8 | jbe | reg/arith | `0x59afc4: cmp $0x7,%r8` | memory | 0x59b01f | fwd |
| ML-KEM inverse NTT | +0x101 | jae | reg/arith | `0x59b00e: cmp %r13,%r14` | memory | 0x59b030 | fwd |
| ML-KEM inverse NTT | +0x10d | jae | reg/arith | `0x59b01a: cmp %r12,%r15` | arithmetic/control | 0x59b030 | fwd |
| ML-KEM inverse NTT | +0x2fa | jne | reg/arith | `0x59b207: cmp %r13,%r8` | memory | 0x59b060 | back |
| ML-KEM inverse NTT | +0x317 | ja | reg/arith | `0x59b220: cmp $0xff,%r8` | arithmetic/control | 0x59b42f | fwd |
| ML-KEM inverse NTT | +0x324 | jae | reg/arith | `0x59b22d: cmp $0x100,%rcx` | memory | 0x59b41a | fwd |
| ML-KEM inverse NTT | +0x3b4 | jb | reg/arith | `0x59b2c1: cmp %rbx,%r8` | arithmetic/control | 0x59b220 | back |
| ML-KEM inverse NTT | +0x3c4 | jne | reg/arith | `0x59b2cd: cmp $0x100,%rcx` | arithmetic/control | 0x59af60 | back |
| ML-KEM inverse NTT | +0x3d4 | jb | reg/arith | `0x59b2dd: cmp $0x100,%rsi` | memory | 0x59af50 | back |
| ML-KEM inverse NTT | +0x4f5 | jne | reg/arith | `0x59b3ff: cmp $0x100,%rax` | arithmetic/control | 0x59b300 | back |
| ML-KEM inner product | +0x3d | jne | reg/arith | `0x59a1ba: test %bpl,%bl` | arithmetic/control | 0x59a467 | fwd |
| ML-KEM inner product | +0x46 | jne | reg/arith | `0x59a1c3: and %r11b,%al` | memory | 0x59a467 | fwd |
| ML-KEM inner product | +0x2dc | jne | reg/arith | `0x59a456: cmp $0x100,%rax` | arithmetic/control | 0x59a200 | back |
| ML-KEM inner product | +0x3d8 | jne | reg/arith | `0x59a551: cmp $0x100,%rbx` | arithmetic/control | 0x59a480 | back |
| ML-KEM inner product | +0x3e2 | jo | reg/arith | `0x59a560: dec %eax` | arithmetic/control | 0x59a9e4 | fwd |
| ML-KEM inner product | +0x3ea | jle | reg/arith | `0x59a568: test %eax,%eax` | memory | 0x59a9d5 | fwd |
| ML-KEM inner product | +0x490 | jle | reg/arith | `0x59a60e: dec %eax` | arithmetic/control | 0x59a9d5 | fwd |
| ML-KEM inner product | +0x49b | je | reg/arith | `0x59a619: test %cl,%cl` | memory | 0x59a740 | fwd |
| ML-KEM inner product | +0x5ac | jne | reg/arith | `0x59a725: cmp $0x100,%r10` | arithmetic/control | 0x59a630 | back |
| ML-KEM inner product | +0x84a | jne | reg/arith | `0x59a9c3: cmp $0x100,%r10` | arithmetic/control | 0x59a740 | back |
| ML-KEM matrix transpose-multiply-add | +0x1b | jle | reg/arith | `0x59b489: test %ecx,%ecx` | memory | 0x59bdad | fwd |
| ML-KEM matrix transpose-multiply-add | +0x14e | jle | reg/arith | `0x59b5b1: cmp $0x1,%eax` | memory | 0x59bdad | fwd |
| ML-KEM matrix transpose-multiply-add | +0x15e | je | mem | `0x59b5c9: cmpb $0x0,-0x62(%rsp)` | memory | 0x59b6d0 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x251 | jne | reg/arith | `0x59b6ba: cmp $0x100,%r8` | arithmetic/control | 0x59b5e0 | back |
| ML-KEM matrix transpose-multiply-add | +0x4f2 | jne | reg/arith | `0x59b95c: cmp $0x100,%rax` | memory | 0x59b6e0 | back |
| ML-KEM matrix transpose-multiply-add | +0x4fd | je | mem | `0x59b968: cmpl $0x1,-0x60(%rsp)` | memory | 0x59b590 | back |
| ML-KEM matrix transpose-multiply-add | +0x587 | jle | reg/arith | `0x59b9ec: cmp $0x2,%r9d` | memory | 0x59b590 | back |
| ML-KEM matrix transpose-multiply-add | +0x592 | je | mem | `0x59b9fd: cmpb $0x0,-0x61(%rsp)` | memory | 0x59bb10 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x691 | jne | reg/arith | `0x59bafa: cmp $0x100,%rdi` | arithmetic/control | 0x59ba10 | back |
| ML-KEM matrix transpose-multiply-add | +0x932 | jne | reg/arith | `0x59bd9b: cmp $0x100,%rdi` | arithmetic/control | 0x59bb20 | back |
| ML-KEM matrix expansion (public) | +0x3f | jle | reg/arith | `0x59aa3d: test %ecx,%ecx` | memory | 0x59ac01 | fwd |
| ML-KEM matrix expansion (public) | +0x6c | je | mem | `0x59aa67: cmp 0x4(%rsp),%r14d` | call+memory | 0x59abf2 | fwd |
| ML-KEM matrix expansion (public) | +0x92 | je | reg/arith | `0x59aa90: test %eax,%eax` | memory | 0x59ac27 | fwd |
| ML-KEM matrix expansion (public) | +0xad | je | reg/arith | `0x59aaab: test %eax,%eax` | memory | 0x59ac27 | fwd |
| ML-KEM matrix expansion (public) | +0x116 | je | reg/arith | `0x59ab13: test %rax,%rax` | memory | 0x59ac09 | fwd |
| ML-KEM matrix expansion (public) | +0x121 | je | mem | `0x59ab1c: cmpq $0x0,0x70(%rax)` | memory | 0x59ac12 | fwd |
| ML-KEM matrix expansion (public) | +0x131 | je | reg/arith | `0x59ab2e: test %rax,%rax` | memory | 0x59ac1b | fwd |
| ML-KEM matrix expansion (public) | +0x13e | je | reg/arith | `0x59ab3b: test %rdi,%rdi` | call+memory | 0x59ac27 | fwd |
| ML-KEM matrix expansion (public) | +0x160 | je | reg/arith | `0x59ab5e: test %eax,%eax` | arithmetic/control | 0x59ac27 | fwd |
| ML-KEM matrix expansion (public) | +0x17a | je | reg/arith | `0x59ab74: cmp $0xaa,%rax` | arithmetic/control | 0x59abe0 | fwd |
| ML-KEM matrix expansion (public) | +0x183 | ja | reg/arith | `0x59ab7c: cmp $0xff,%r13` | memory | 0x59aa60 | back |
| ML-KEM matrix expansion (public) | +0x1a9 | ja | reg/arith | `0x59aba3: cmp $0xd00,%esi` | memory | 0x59abc0 | fwd |
| ML-KEM matrix expansion (public) | +0x1b7 | je | reg/arith | `0x59abb0: cmp $0xff,%r13` | arithmetic/control | 0x59aa60 | back |
| ML-KEM matrix expansion (public) | +0x1d4 | ja | reg/arith | `0x59abce: cmp $0xd00,%ecx` | memory | 0x59ab70 | back |
| ML-KEM matrix expansion (public) | +0x1e7 | jb | reg/arith | `0x59abe0: cmp $0x100,%r13` | arithmetic/control | 0x59ab0f | back |
| ML-KEM matrix expansion (public) | +0x1fb | jne | mem | `0x59abf7: cmp 0x4(%rsp),%ebp` | arithmetic/control | 0x59aa4a | back |
| ML-KEM vector decode 12-bit | +0x2 | jle | reg/arith | `0x59ad40: test %edx,%edx` | memory | 0x59adc2 | fwd |
| ML-KEM vector decode 12-bit | +0x17 | je | reg/arith | `0x59ad50: cmp $0x80,%rcx` | memory | 0x59adb0 | fwd |
| ML-KEM vector decode 12-bit | +0x54 | ja | reg/arith | `0x59ad8d: cmp $0xd00,%r11d` | arithmetic/control | 0x59adc7 | fwd |
| ML-KEM vector decode 12-bit | +0x68 | jb | reg/arith | `0x59ada1: cmp $0xd01,%r9d` | arithmetic/control | 0x59ad50 | back |
| ML-KEM vector decode 12-bit | +0x80 | jg | reg/arith | `0x59adbe: dec %edx` | arithmetic/control | 0x59ad44 | back |
| ML-KEM vector encode | +0x7 | js | reg/arith | `0x59ac55: test %edx,%edx` | arithmetic/control | 0x59ad30 | fwd |
| ML-KEM vector encode | +0x11 | jle | reg/arith | `0x59ac5f: test %ecx,%ecx` | arithmetic/control | 0x59acf6 | fwd |
| ML-KEM vector encode | +0x2c | jle | reg/arith | `0x59ac7a: dec %eax` | arithmetic/control | 0x59acf6 | fwd |
| ML-KEM vector encode | +0x53 | je | reg/arith | `0x59ac9c: cmp $0x200,%r10` | arithmetic/control | 0x59ac70 | back |
| ML-KEM vector encode | +0x59 | jb | reg/arith | `0x59aca7: add %edx,%ebx` | memory | 0x59acfc | fwd |
| ML-KEM vector encode | +0x63 | jb | reg/arith | `0x59acb0: cmp $0x40,%ebx` | arithmetic/control | 0x59ac90 | back |
| ML-KEM vector encode | +0x65 | jne | unknown | `?` | arithmetic/control | 0x59acd0 | fwd |
| ML-KEM vector encode | +0x6a | jae | reg/arith | `0x59acb7: cmp $0x40,%ecx` | memory | 0x59ad23 | fwd |
| ML-KEM vector encode | +0x83 | jae | reg/arith | `0x59acd0: cmp $0x40,%ecx` | memory | 0x59ad09 | fwd |
| ML-KEM vector encode | +0x93 | je | reg/arith | `0x59ace1: test %ecx,%ecx` | arithmetic/control | 0x59ad16 | fwd |
| ML-KEM CBD sampling eta=2 | +0x5a | je | reg/arith | `0x59bf58: test %eax,%eax` | memory | 0x59c057 | fwd |
| ML-KEM CBD sampling eta=2 | +0x14a | jne | reg/arith | `0x59c044: cmp $0x80,%rax` | arithmetic/control | 0x59bf80 | back |
| ML-KEM CBD sampling eta=2 | +0x192 | jne | reg/arith | `0x59c08b: cmp $0x80,%rcx` | arithmetic/control | 0x59c060 | back |
| ML-KEM CBD sampling eta=3 | +0x7e | je | reg/arith | `0x59c11c: test %eax,%eax` | memory | 0x59c457 | fwd |
| ML-KEM CBD sampling eta=3 | +0x3aa | jne | reg/arith | `0x59c446: cmp $0x40,%rcx` | arithmetic/control | 0x59c140 | back |
| ML-KEM CBD sampling eta=3 | +0x3f2 | jne | reg/arith | `0x59c48b: cmp $0xc7,%rcx` | arithmetic/control | 0x59c460 | back |
| ML-KEM CBD vector sampling then NTT | +0x21 | jle | reg/arith | `0x59adee: test %r8d,%r8d` | memory | 0x59ae50 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x60 | je | reg/arith | `0x59ae2e: test %eax,%eax` | call | 0x59ae47 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x73 | jg | reg/arith | `0x59ae41: dec %ebx` | arithmetic/control | 0x59ae10 | back |
| ML-KEM hash H | +0x2e | je | reg/arith | `0x59c58c: test %eax,%eax` | memory | 0x59c5fd | fwd |
| ML-KEM hash H | +0x49 | je | reg/arith | `0x59c5a7: test %eax,%eax` | arithmetic/control | 0x59c5e4 | fwd |
| ML-KEM hash H | +0x4e | je | reg/arith | `0x59c5ab: test %rbx,%rbx` | memory | 0x59c5be | fwd |
| ML-KEM hash H | +0x56 | je | reg/arith | `0x59c5b3: test %rax,%rax` | memory | 0x59c5be | fwd |
| ML-KEM hash H | +0x5c | jne | mem | `0x59c5b8: testb $0x2,0x10(%rax)` | memory | 0x59c5e9 | fwd |
| ML-KEM hash G | +0x2e | je | reg/arith | `0x59c4cc: test %eax,%eax` | memory | 0x59c53d | fwd |
| ML-KEM hash G | +0x49 | je | reg/arith | `0x59c4e7: test %eax,%eax` | arithmetic/control | 0x59c524 | fwd |
| ML-KEM hash G | +0x4e | je | reg/arith | `0x59c4eb: test %rbx,%rbx` | memory | 0x59c4fe | fwd |
| ML-KEM hash G | +0x56 | je | reg/arith | `0x59c4f3: test %rax,%rax` | memory | 0x59c4fe | fwd |
| ML-KEM hash G | +0x5c | jne | mem | `0x59c4f8: testb $0x2,0x10(%rax)` | memory | 0x59c529 | fwd |
| ML-KEM public-key hash | +0x59 | je | reg/arith | `0x59a067: test %eax,%eax` | memory | 0x59a15b | fwd |
| ML-KEM public-key hash | +0x96 | je | reg/arith | `0x59a09f: cmp $0x200,%rsi` | memory | 0x59a0f0 | fwd |
| ML-KEM public-key hash | +0xa5 | jbe | reg/arith | `0x59a0b2: cmp $0x33,%eax` | memory | 0x59a090 | back |
| ML-KEM public-key hash | +0xb9 | je | reg/arith | `0x59a0c5: cmp $0x40,%r8d` | arithmetic/control | 0x59a0e1 | fwd |
| ML-KEM public-key hash | +0xf6 | je | reg/arith | `0x59a104: test %eax,%eax` | memory | 0x59a15b | fwd |
| ML-KEM public-key hash | +0x109 | jb | reg/arith | `0x59a116: cmp %rax,%rbp` | memory | 0x59a080 | back |
| ML-KEM public-key hash | +0x123 | je | reg/arith | `0x59a131: test %eax,%eax` | memory | 0x59a15b | fwd |
| ML-KEM KDF | +0x2a | je | reg/arith | `0x59bde8: test %eax,%eax` | memory | 0x59be2e | fwd |
| ML-KEM KDF | +0x3f | je | reg/arith | `0x59bdfd: test %eax,%eax` | memory | 0x59be2e | fwd |
| ML-KEM KDF | +0x52 | je | reg/arith | `0x59be10: test %eax,%eax` | memory | 0x59be2e | fwd |
| ML-KEM PRF | +0x2d | je | reg/arith | `0x59be6b: test %eax,%eax` | memory | 0x59beda | fwd |
| ML-KEM PRF | +0x46 | je | reg/arith | `0x59be84: test %eax,%eax` | arithmetic/control | 0x59bec3 | fwd |
| ML-KEM PRF | +0x4b | je | reg/arith | `0x59be88: test %r14,%r14` | memory | 0x59be9b | fwd |
| ML-KEM PRF | +0x53 | je | reg/arith | `0x59be90: test %rax,%rax` | memory | 0x59be9b | fwd |
| ML-KEM PRF | +0x59 | jne | mem | `0x59be95: testb $0x2,0x10(%rax)` | memory | 0x59bec8 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xa0 | je | reg/arith | `0x408d3e: test %eax,%eax` | memory | 0x408e4f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xb9 | je | reg/arith | `0x408d57: test %eax,%eax` | memory | 0x408e4f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xd0 | je | reg/arith | `0x408d6e: test %eax,%eax` | memory | 0x408e4f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xeb | je | reg/arith | `0x408d89: test %eax,%eax` | call+memory | 0x408e4f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x155 | je | reg/arith | `0x408deb: test %eax,%eax` | call+memory | 0x408f2c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x178 | je | reg/arith | `0x408e16: test %eax,%eax` | memory | 0x408f2c | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x185 | je | reg/arith | `0x408e22: test %rax,%rax` | arithmetic/control | 0x408f4e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x18e | je | reg/arith | `0x408e2b: test %r14,%r14` | memory | 0x408f5d | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x1a0 | jae | reg/arith | `0x408e34: cmp $0x4,%rax` | arithmetic/control | 0x408f6f | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x2d3 | jae | reg/arith | `0x408f6f: cmp $0x20,%rax` | arithmetic/control | 0x408f7b | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x31b | jne | reg/arith | `0x408fb8: cmp %rdx,%rcx` | arithmetic/control | 0x408f8c | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x354 | je | reg/arith | `0x408ff1: cmp %rcx,%rax` | arithmetic/control | 0x409061 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x358 | je | reg/arith | `0x408ff6: test $0x1c,%al` | memory | 0x40904e | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x386 | jne | reg/arith | `0x409023: cmp %rsi,%rcx` | arithmetic/control | 0x409010 | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x3bf | jne | reg/arith | `0x40905c: cmp %rcx,%rax` | memory | 0x40904e | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x427 | jne | reg/arith | `0x4090c3: cmp $0x20,%rcx` | memory | 0x409090 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x58 | ja | reg/arith | `0x596ea0: cmp $0x7e,%rax` | memory | 0x597241 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xb0 | jbe | reg/arith | `0x596efc: cmp $0x7,%r8` | memory | 0x596f57 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xf9 | jae | reg/arith | `0x596f46: cmp %r13,%r14` | memory | 0x596f60 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x105 | jae | reg/arith | `0x596f52: cmp %r12,%r15` | arithmetic/control | 0x596f60 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2c0 | jne | reg/arith | `0x59710d: cmp %r13,%r8` | memory | 0x596fa0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2d7 | ja | reg/arith | `0x597120: cmp $0xff,%r8` | arithmetic/control | 0x59722c | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2e4 | jae | reg/arith | `0x59712d: cmp $0x100,%rcx` | memory | 0x597217 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x392 | jb | reg/arith | `0x5971df: cmp %rbx,%r8` | arithmetic/control | 0x597120 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x39f | jne | reg/arith | `0x5971e8: cmp $0x100,%rcx` | arithmetic/control | 0x596ea0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x3b2 | ja | reg/arith | `0x5971fb: cmp $0x3,%rsi` | arithmetic/control | 0x596e90 | back |
