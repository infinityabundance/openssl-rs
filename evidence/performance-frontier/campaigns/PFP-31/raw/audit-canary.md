# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp31/k/distribution/libcrypto.so.3`
- SHA-256: `7a039deed0565a1c1507bbe584f75c54c9f59a434dd855937da2e556ab16da60`
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
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_sos_into` @ 0x503560 | 1013 | 249 | 19 | 0 | 0 | 10 | 0 | 0 | 5 | 0 |
| Montgomery ladder carrier (ladder multiplies inlined here) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith15run_mont_ladder` @ 0x502210 | 3383 | 734 | 51 | 0 | 2 | 11 | 0 | 0 | 49 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x165cb0 | 961 | 231 | 17 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x503f70 (carries `mod_exp_core_consttime_from_parts`) | 1693 | 430 | 42 | 0 | 2 | 4 | 0 | 0 | 20 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x374f90 | 9648 | 2225 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x37ac10 | 3158 | 780 | 125 | 0 | 5 | 7 | 1 | 0 | 78 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x427ab0 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x2f7ab0 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x2f66d0 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x2f64f0 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| DH key agreement (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2dh3key19ossl_dh_compute_key` @ 0x378910 | 1281 | 294 | 36 | 0 | 1 | 0 | 1 | 0 | 32 | 0 |
| EC wNAF multiply (verification / public-scalar core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` @ 0x379390 | 5396 | 1236 | 147 | 4 | 34 | 3 | 2 | 0 | 80 | 0 |
| ML-KEM decapsulation (provider driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` @ 0x2fd5c0 | 998 | 210 | 15 | 0 | 1 | 4 | 0 | 0 | 13 | 0 |
| ML-KEM K-PKE decrypt | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11decrypt_cpa` @ 0x384570 | 2864 | 683 | 37 | 0 | 0 | 6 | 0 | 0 | 10 | 0 |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith11encrypt_cpa` @ 0x3850a0 | 8922 | 1844 | 44 | 0 | 6 | 46 | 2 | 0 | 16 | 0 |
| ML-KEM inverse NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith18scalar_inverse_ntt` @ 0x3882b0 | 1366 | 295 | 12 | 0 | 13 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM inner product | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13inner_product` @ 0x3874f0 | 2209 | 455 | 11 | 0 | 2 | 12 | 1 | 0 | 1 | 0 |
| ML-KEM matrix transpose-multiply-add | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith25matrix_mult_transpose_add` @ 0x388810 | 2439 | 513 | 10 | 0 | 3 | 12 | 0 | 0 | 0 | 0 |
| ML-KEM matrix expansion (public) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13matrix_expand` @ 0x387da0 | 584 | 134 | 16 | 0 | 0 | 0 | 0 | 0 | 6 | 0 |
| ML-KEM vector decode 12-bit | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith16vector_decode_12` @ 0x3880e0 | 136 | 35 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-KEM vector encode | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13vector_encode` @ 0x387ff0 | 237 | 71 | 10 | 0 | 0 | 0 | 0 | 0 | 5 | 0 |
| ML-KEM CBD sampling eta=2 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_2` @ 0x3892e0 | 413 | 93 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD sampling eta=3 | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith5cbd_3` @ 0x389480 | 1021 | 239 | 3 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| ML-KEM CBD vector sampling then NTT | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` @ 0x388170 | 312 | 83 | 3 | 0 | 0 | 1 | 0 | 0 | 2 | 0 |
| ML-KEM hash H | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_h` @ 0x389940 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM hash G | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith6hash_g` @ 0x389880 | 180 | 59 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM public-key hash | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith13hash_h_pubkey` @ 0x387380 | 358 | 104 | 7 | 0 | 0 | 2 | 0 | 0 | 6 | 0 |
| ML-KEM KDF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3kdf` @ 0x3891a0 | 128 | 46 | 3 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| ML-KEM PRF | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith3prf` @ 0x389220 | 177 | 60 | 5 | 0 | 0 | 2 | 0 | 0 | 5 | 0 |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178` @ 0x300270 | 1458 | 321 | 16 | 0 | 0 | 0 | 0 | 0 | 11 | 0 |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith10scalar_ntt.llvm.6314407072834850591` @ 0x384160 | 1030 | 235 | 10 | 0 | 14 | 0 | 0 | 0 | 3 | 0 |

## Coverage

- expected targets: 31
- resolved uniquely and disassembled: 31
- of those, audited through a verified inline mapping: 1
  - Constant-time ladder core: intended `mod_exp_core_consttime_from_parts` -> carrier `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared`
- failed: 1
  - ML-KEM decapsulation carrier (implicit-rejection comparison + select) (`key::decap`): secret-derived-conditional-jump detail: 0x300613 je 300629 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x3b9> condition from 0x300611: test %dl,%dl

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
| `key::decap` | `3key5decap.llvm.15622672340991759178` | 1458 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key17ossl_ml_kem_decap` | +0x108, +0x216, +0x300 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |
| `arith::scalar_ntt` | `5arith10scalar_ntt.llvm.6314407072834850591` | 1030 B | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem5arith17gencbd_vector_ntt` | +0x65 | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **ML-KEM decapsulation carrier (implicit-rejection comparison + select)** recorded check: src/ml_kem/key.rs::decap is the only body of the identifier. The release DSO has no unsuffixed symbol for it; the only defined .text symbol of that identifier is the .llvm.<digits> local copy, and ossl_ml_kem_decap calls that entry directly at three sites. The copy contains the inlined CRYPTO_memcmp accumulation, the constant_time_eq_int_8 mask and the constant_time_select_8 store loop of src/ml_kem/key.rs:633-639.

- **ML-KEM forward NTT (used by re-encryption on secret-derived data)** recorded check: src/ml_kem/arith.rs::scalar_ntt has no unsuffixed out-of-line body in the release DSO; its only defined .text symbol of that identifier is the .llvm.<digits> local copy. gencbd_vector_ntt calls that entry directly, and the same single entry is the target of two further direct calls in the file (recorded in MLKEM-REJECTION.md). The loop bounds are fixed by the degree; the value-dependent reductions compile to cmovcc, which the per-function counts report.

## Comparison-result branch contract

Register taint is seeded on the XOR/OR comparison accumulation and propagated over the basic-block CFG. `public-bound` means no tracked comparison register reaches the condition, not that the branch is harmless. Memory and implicit flow are not modelled.

### ML-KEM decapsulation carrier (implicit-rejection comparison + select)

- accumulated registers: `xmm0`, `xmm1`
- accumulation loop 0x300532..0x300561: `xmm0`, `xmm1`

| kind | addr | instruction | condition source | class |
|---|---|---|---|---|
| jcc | `0x300310` | `je 300417 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x1a7>` | `0x30030e: test %eax,%eax` | **public-bound** |
| jcc | `0x300329` | `je 300417 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x1a7>` | `0x300327: test %eax,%eax` | **public-bound** |
| jcc | `0x300340` | `je 300417 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x1a7>` | `0x30033e: test %eax,%eax` | **public-bound** |
| jcc | `0x30035b` | `je 300417 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x1a7>` | `0x300359: test %eax,%eax` | **public-bound** |
| jcc | `0x3003c5` | `je 3004f3 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x283>` | `0x3003bb: test %eax,%eax` | **public-bound** |
| jcc | `0x3003e8` | `je 3004f3 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x283>` | `0x3003e6: test %eax,%eax` | **public-bound** |
| jcc | `0x3003f5` | `je 300629 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x3b9>` | `0x3003f2: test %rax,%rax` | **public-bound** |
| jcc | `0x3003fe` | `je 300615 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x3a5>` | `0x3003fb: test %r14,%r14` | **public-bound** |
| jcc | `0x300408` | `jae 300515 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x2a5>` | `0x300404: cmp $0x4,%rax` | **public-bound** |
| jcc | `0x300519` | `jae 300521 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x2b1>` | `0x300515: cmp $0x20,%rax` | **public-bound** |
| jcc | `0x300561` | `jne 300532 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x2c2>` | `0x30055e: cmp %rdx,%rcx` | **public-bound** |
| jcc | `0x30059a` | `je 300611 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x3a1>` | `0x300597: cmp %rcx,%rax` | **public-bound** |
| jcc | `0x30059e` | `je 3005fe <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x38e>` | `0x30059c: test $0x1c,%al` | **public-bound** |
| jcc | `0x3005d6` | `jne 3005c0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x350>` | `0x3005d3: cmp %rsi,%rcx` | **public-bound** |
| jcc | `0x30060f` | `jne 3005fe <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x38e>` | `0x30060c: cmp %rcx,%rax` | **public-bound** |
| jcc | `0x300613` | `je 300629 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs6ml_kem3key5decap.llvm.15622672340991759178+0x3b9>` | `0x300611: test %dl,%dl` | **secret-derived** |

- secret-derived conditional jumps: 1
- undetermined conditions: 0

## Divisions

- **EC wNAF multiply (verification / public-scalar core)** `+0x653` (0x3799e3): `div %rcx`
- **EC wNAF multiply (verification / public-scalar core)** `+0x84a` (0x379bda): `div %rsi`
- **EC wNAF multiply (verification / public-scalar core)** `+0x89d` (0x379c2d): `div %ecx`
- **EC wNAF multiply (verification / public-scalar core)** `+0x1107` (0x37a497): `div %esi`

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d248, 0x16d269, 0x16d28a, 0x16d2a1, 0x16d2f3, 0x16d30a, 0x16d495, 0x16d5a3, 0x16d649, 0x16d808, 0x25ee5c, 0x25ee8c, 0x28e31a, 0x28e3ac, 0x28e5fc, 0x2a5efc, 0x2a5f2c, 0x2f6b7b, 0x45254c, 0x454bfc

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x33 | jne | reg/arith | `0x503590: or %r9,%rax` | memory | 0x5036b0 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x4c | jne | reg/arith | `0x5035a9: cmp %rax,%rcx` | memory | 0x5036b0 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x7d | je | reg/arith | `0x5035da: test %r14,%r14` | memory | 0x5036b2 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xe1 | je | reg/arith | `0x50363e: cmp %rdi,%rbp` | memory | 0x5036c1 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0xf4 | je | reg/arith | `0x503651: test %rax,%rax` | memory | 0x503610 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x142 | jne | reg/arith | `0x50369f: cmp %r8,%r13` | arithmetic/control | 0x503660 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x148 | jne | reg/arith | `0x5036a4: test $0x1,%dil` | arithmetic/control | 0x503610 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1bd | je | reg/arith | `0x50371a: cmp %rdi,%rax` | memory | 0x5037ca | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x1cb | je | mem | `0x503723: cmp 0x90(%rsp),%r9` | memory | 0x50391a | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x203 | je | reg/arith | `0x503760: cmp %rsi,%rbx` | memory | 0x5038ff | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x22f | jne | reg/arith | `0x50378c: cmp %rsi,%rdi` | memory | 0x503760 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x23d | je | mem | `0x503798: cmp 0x28(%rsp),%r9` | memory | 0x503700 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x263 | jne | reg/arith | `0x5037c0: cmp %rax,%rbp` | arithmetic/control | 0x5037b0 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x282 | je | reg/arith | `0x5037df: test %rdx,%rdx` | memory | 0x503852 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2e8 | jne | reg/arith | `0x503845: cmp %rsi,%r13` | arithmetic/control | 0x503810 | back |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x2ee | jne | reg/arith | `0x50384a: test $0x1,%dil` | arithmetic/control | 0x50386d | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x367 | jae | reg/arith | `0x5038c4: cmp %r14,%rcx` | arithmetic/control | 0x503942 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x36c | je | reg/arith | `0x5038c9: cmp %r10,%rdi` | memory | 0x503932 | fwd |
| Montgomery multiply (SOS kernel; the schedule LADDER_SCHEDULE selects) | +0x398 | jne | reg/arith | `0x5038f4: add $0xfffffffffffffff8,%r8` | arithmetic/control | 0x5038c0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e | jne | reg/arith | `0x50223a: shr $0x3a,%rax` | memory | 0x502892 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4d | jbe | reg/arith | `0x50225a: cmp %rbx,%rdx` | call+memory | 0x502340 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6c | je | reg/arith | `0x502278: cmp $0xffffffffffffffff,%r12` | memory | 0x50240b | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8d | jne | reg/arith | `0x502292: test %rbx,%rbx` | memory | 0x5026c4 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc7 | jne | reg/arith | `0x5022d5: or %al,%cl` | memory | 0x502318 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x106 | jne | reg/arith | `0x502313: cmp %rax,%rsi` | arithmetic/control | 0x5022e0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x10b | je | reg/arith | `0x502318: test %r12,%r12` | memory | 0x50232b | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x141 | jne | reg/arith | `0x50234e: test %rbx,%rbx` | memory | 0x5025c3 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x18c | jne | reg/arith | `0x502398: cmp $0xffffffffffffffff,%rax` | memory | 0x5024a7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x19c | je | reg/arith | `0x5023a9: test %rbx,%rbx` | memory | 0x50241a | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x1e6 | jne | reg/arith | `0x5023f3: cmp %rax,%rbx` | memory | 0x5023c0 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x22e | jne | reg/arith | `0x50243c: or %cl,%dl` | memory | 0x502480 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x26e | jne | reg/arith | `0x50247b: cmp %rdx,%rsi` | arithmetic/control | 0x502450 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x273 | je | reg/arith | `0x502480: test %rax,%rax` | memory | 0x502495 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2b5 | jne | reg/arith | `0x5024c2: test %rbx,%rbx` | call+memory | 0x50260c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x2e8 | je | mem | `0x5024ee: cmpb $0x0,0x10(%rsp)` | memory | 0x502e07 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x321 | jne | reg/arith | `0x50252f: or %al,%cl` | memory | 0x502578 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x366 | jne | reg/arith | `0x502573: cmp %rax,%rsi` | arithmetic/control | 0x502540 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x36b | je | reg/arith | `0x502578: test %rdx,%rdx` | memory | 0x502591 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x38c | je | reg/arith | `0x502591: test %rbx,%rbx` | memory | 0x50264c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x3e9 | je | mem | `0x5025f4: cmpb $0x0,0x10(%rsp)` | memory | 0x502780 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x426 | je | mem | `0x502631: cmpb $0x0,0x10(%rsp)` | memory | 0x502812 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x45c | jne | reg/arith | `0x50266a: or %al,%cl` | memory | 0x5026a8 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x496 | jne | reg/arith | `0x5026a3: cmp %rax,%rsi` | arithmetic/control | 0x502670 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x49b | je | reg/arith | `0x5026a8: test %rdi,%rdi` | memory | 0x5023a9 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x4e2 | je | mem | `0x5026ed: cmpb $0x0,0x10(%rsp)` | memory | 0x5027ce | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x510 | jne | reg/arith | `0x50271e: or %al,%cl` | memory | 0x50275c | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x54a | jne | reg/arith | `0x502757: cmp %rax,%rsi` | memory | 0x502724 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x557 | je | reg/arith | `0x50275c: test %r12,%r12` | memory | 0x50241a | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x57c | je | reg/arith | `0x502788: cmp $0x1,%rbx` | memory | 0x5027a9 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x5ca | je | reg/arith | `0x5027d6: cmp $0x1,%rbx` | memory | 0x5027f7 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x615 | je | reg/arith | `0x502821: cmp $0x1,%rbx` | memory | 0x50284a | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x666 | je | mem | `0x502871: cmpb $0x0,0x10(%rsp)` | memory | 0x50289e | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x69f | je | reg/arith | `0x5028ab: cmp $0x1,%rbx` | memory | 0x5028cc | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x6fd | je | mem | `0x502908: cmpb $0x0,0x10(%rsp)` | memory | 0x502919 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x759 | je | mem | `0x502964: cmpb $0x0,0x10(%rsp)` | memory | 0x5029f1 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7b6 | jne | reg/arith | `0x5029c3: cmp %rax,%rcx` | memory | 0x502997 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x7ef | je | reg/arith | `0x5029fb: cmp $0x1,%rbx` | memory | 0x502a24 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x840 | je | mem | `0x502a4b: cmpb $0x0,0x10(%rsp)` | memory | 0x502a70 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x877 | je | reg/arith | `0x502a83: cmp $0x1,%rbx` | memory | 0x502aac | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x8cd | je | mem | `0x502ad4: cmpq $0x0,0x80(%rsp)` | memory | 0x502ca5 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x930 | jae | mem | `0x502b3b: cmp 0x78(%rsp),%rdi` | memory | 0x502e66 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x994 | je | reg/arith | `0x502ba2: test %al,%al` | memory | 0x502c94 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9a3 | je | mem | `0x502baa: cmpq $0x0,0x98(%rsp)` | memory | 0x502c04 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0x9f2 | jne | mem | `0x502bfa: cmp %rcx,0x98(%rsp)` | memory | 0x502bc8 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa36 | je | reg/arith | `0x502c44: test %al,%al` | memory | 0x502c94 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xa7c | jne | mem | `0x502c84: cmp 0x80(%rsp),%rsi` | arithmetic/control | 0x502b23 | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xad9 | je | reg/arith | `0x502ce7: test %al,%al` | memory | 0x502d75 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xbdd | jne | reg/arith | `0x502dea: cmp %rax,%r13` | memory | 0x502dbf | back |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xc97 | je | reg/arith | `0x502ea4: test %rbx,%rbx` | memory | 0x502ec1 | fwd |
| Montgomery ladder carrier (ladder multiplies inlined here) | +0xcdd | je | reg/arith | `0x502eea: test %rbx,%rbx` | memory | 0x502f07 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x165ce9: test %rbx,%rbx` | memory | 0x165d40 | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x165d26: cmpb $0x0,0x8(%rsp)` | memory | 0x165d85 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | jne | reg/arith | `0x165d35: test %rbx,%rbx` | arithmetic/control | 0x165f56 | fwd |
| Montgomery multiply (allocating wrapper) | +0xb8 | je | mem | `0x165d63: cmpb $0x0,0x8(%rsp)` | memory | 0x165f79 | fwd |
| Montgomery multiply (allocating wrapper) | +0xe4 | jne | reg/arith | `0x165d91: test %rbx,%rbx` | memory | 0x165fb1 | fwd |
| Montgomery multiply (allocating wrapper) | +0x12a | je | reg/arith | `0x165dd8: test %al,%al` | memory | 0x165e98 | fwd |
| Montgomery multiply (allocating wrapper) | +0x143 | je | reg/arith | `0x165df0: test %rbx,%rbx` | memory | 0x165e49 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x165e33: cmp %rax,%rbx` | memory | 0x165e00 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x165e83: cmp %rax,%r14` | arithmetic/control | 0x165e50 | back |
| Montgomery multiply (allocating wrapper) | +0x1f3 | je | reg/arith | `0x165ea0: test %rbx,%rbx` | memory | 0x165ef6 | fwd |
| Montgomery multiply (allocating wrapper) | +0x236 | jne | reg/arith | `0x165ee3: cmp %rax,%rsi` | memory | 0x165eb0 | back |
| Montgomery multiply (allocating wrapper) | +0x286 | jne | reg/arith | `0x165f33: cmp %rax,%r14` | memory | 0x165f00 | back |
| Montgomery multiply (allocating wrapper) | +0x2a0 | je | reg/arith | `0x165f4d: test %rbx,%rbx` | arithmetic/control | 0x165d76 | back |
| Montgomery multiply (allocating wrapper) | +0x2d5 | je | reg/arith | `0x165f81: cmp $0x1,%rbx` | memory | 0x165fa2 | fwd |
| Montgomery multiply (allocating wrapper) | +0x343 | je | mem | `0x165fee: cmpb $0x0,0x8(%rsp)` | memory | 0x166002 | fwd |
| Montgomery multiply (allocating wrapper) | +0x35b | jne | reg/arith | `0x166007: cmp $0x1,%rbx` | arithmetic/control | 0x166015 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3a1 | je | reg/arith | `0x16604e: test %rbx,%rbx` | memory | 0x166069 | fwd |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x503f86: test %r12,%r12` | memory | 0x503ff8 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x503fa1: cmp $0x1,%r12` | memory | 0x503fc9 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x503faa: cmp $0x1,%r15` | memory | 0x503fcc | fwd |
| Constant-time ladder core | +0x60 | jne | reg/arith | `0x503fcc: test $0x1,%r15b` | call | 0x503fec | fwd |
| Constant-time ladder core | +0x86 | jbe | reg/arith | `0x503ff3: cmp %rbx,%r13` | memory | 0x50400e | fwd |
| Constant-time ladder core | +0xe1 | je | mem | `0x50404c: cmpb $0x0,0x10(%rsp)` | memory | 0x504061 | fwd |
| Constant-time ladder core | +0x102 | je | reg/arith | `0x504069: cmp $0x1,%rbx` | memory | 0x5040a1 | fwd |
| Constant-time ladder core | +0x154 | jae | reg/arith | `0x5040c0: cmp $0x18,%rcx` | memory | 0x5040d5 | fwd |
| Constant-time ladder core | +0x186 | je | reg/arith | `0x5040f3: cmp %rdi,%r8` | arithmetic/control | 0x504171 | fwd |
| Constant-time ladder core | +0x191 | jae | reg/arith | `0x5040fe: cmp %r13,%r8` | memory | 0x504134 | fwd |
| Constant-time ladder core | +0x1a2 | jb | reg/arith | `0x50410f: cmp %r13,%r8` | memory | 0x504143 | fwd |
| Constant-time ladder core | +0x1b1 | jb | reg/arith | `0x50411e: cmp %r13,%r8` | memory | 0x504154 | fwd |
| Constant-time ladder core | +0x1c0 | jb | reg/arith | `0x50412d: cmp %r13,%r8` | arithmetic/control | 0x5040e3 | back |
| Constant-time ladder core | +0x1d1 | jae | reg/arith | `0x50413e: cmp %r13,%r8` | memory | 0x504114 | back |
| Constant-time ladder core | +0x1e2 | jae | reg/arith | `0x50414f: cmp %r13,%r8` | memory | 0x504123 | back |
| Constant-time ladder core | +0x1f3 | jb | reg/arith | `0x504160: cmp %r13,%r8` | arithmetic/control | 0x5040e3 | back |
| Constant-time ladder core | +0x204 | je | reg/arith | `0x504171: test %rax,%rax` | memory | 0x5041b6 | fwd |
| Constant-time ladder core | +0x22c | je | reg/arith | `0x504199: cmp %r8,%rax` | memory | 0x5041b6 | fwd |
| Constant-time ladder core | +0x235 | jb | reg/arith | `0x5041a2: cmp %r13,%r9` | memory | 0x50418e | back |
| Constant-time ladder core | +0x244 | jne | reg/arith | `0x5041b1: cmp %r8,%rax` | arithmetic/control | 0x50419e | back |
| Constant-time ladder core | +0x249 | je | reg/arith | `0x5041b6: test %r14,%r14` | memory | 0x504226 | fwd |
| Constant-time ladder core | +0x252 | jne | reg/arith | `0x5041bf: test %r12,%r12` | memory | 0x5044bd | fwd |
| Constant-time ladder core | +0x2b9 | je | reg/arith | `0x504226: test %r12,%r12` | arithmetic/control | 0x50459e | fwd |
| Constant-time ladder core | +0x2c6 | jne | reg/arith | `0x504232: shr $0x3a,%rax` | arithmetic/control | 0x5044eb | fwd |
| Constant-time ladder core | +0x2d3 | jne | reg/arith | `0x50423f: shr $0x39,%rax` | call+memory | 0x5044eb | fwd |
| Constant-time ladder core | +0x2f6 | je | reg/arith | `0x504262: cmp $0xffffffffffffffff,%r14` | call+memory | 0x5044eb | fwd |
| Constant-time ladder core | +0x334 | je | reg/arith | `0x504296: cmp $0xffffffffffffffff,%rbp` | memory | 0x504425 | fwd |
| Constant-time ladder core | +0x34c | je | reg/arith | `0x5042b4: test %r8,%r8` | arithmetic/control | 0x5045b1 | fwd |
| Constant-time ladder core | +0x3f3 | je | mem | `0x50434e: cmpq $0xffffffffffffffff,0x10(%rsp)` | memory | 0x50442e | fwd |
| Constant-time ladder core | +0x437 | je | reg/arith | `0x5043a4: test %rbp,%rbp` | memory | 0x5043c0 | fwd |
| Constant-time ladder core | +0x46a | jne | reg/arith | `0x5043d8: or %al,%cl` | memory | 0x504417 | fwd |
| Constant-time ladder core | +0x4a5 | jne | reg/arith | `0x504412: cmp %rax,%rsi` | arithmetic/control | 0x5043de | back |
| Constant-time ladder core | +0x4aa | je | reg/arith | `0x504417: test %r14,%r14` | arithmetic/control | 0x5044f7 | fwd |
| Constant-time ladder core | +0x4c8 | je | reg/arith | `0x504435: test %rbp,%rbp` | memory | 0x504451 | fwd |
| Constant-time ladder core | +0x4fb | jne | reg/arith | `0x504469: or %al,%cl` | memory | 0x5044a8 | fwd |
| Constant-time ladder core | +0x536 | jne | reg/arith | `0x5044a3: cmp %rax,%rsi` | arithmetic/control | 0x50446f | back |
| Constant-time ladder core | +0x53b | je | reg/arith | `0x5044a8: test %r14,%r14` | memory | 0x5044f7 | fwd |
| Constant-time ladder core | +0x579 | je | mem | `0x5044e4: cmpb $0x0,0x10(%rsp)` | memory | 0x504555 | fwd |
| Constant-time ladder core | +0x58a | je | reg/arith | `0x5044f7: test %rbx,%rbx` | memory | 0x503fff | back |
| Constant-time ladder core | +0x5ca | jne | reg/arith | `0x504537: cmp %rax,%rsi` | memory | 0x50450c | back |
| Constant-time ladder core | +0x5f1 | je | reg/arith | `0x50455d: cmp $0x1,%r12` | memory | 0x504581 | fwd |
| Constant-time ladder core | +0x65f | je | reg/arith | `0x5045cc: test %rbp,%rbp` | memory | 0x5045e8 | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x374fa4: test %r8,%r8` | memory | 0x374ffb | fwd |
| Constant-time inversion | +0x1c | je | mem | `0x374fa9: testb $0x1,(%rcx)` | arithmetic/control | 0x374ffb | fwd |
| Constant-time inversion | +0x2f | jne | reg/arith | `0x374fbb: shr $0x39,%rdi` | memory | 0x374ffb | fwd |
| Constant-time inversion | +0x66 | je | mem | `0x374ff1: cmpb $0x0,0x18(%rsp)` | memory | 0x375014 | fwd |
| Constant-time inversion | +0x90 | je | reg/arith | `0x37501c: cmp $0x1,%rbx` | memory | 0x37503d | fwd |
| Constant-time inversion | +0x104 | je | mem | `0x37508f: cmpb $0x0,0x18(%rsp)` | memory | 0x3750fb | fwd |
| Constant-time inversion | +0x14e | jne | reg/arith | `0x3750db: cmp %rcx,%rbx` | memory | 0x3750b0 | back |
| Constant-time inversion | +0x177 | je | reg/arith | `0x375103: cmp $0x1,%rbx` | memory | 0x375124 | fwd |
| Constant-time inversion | +0x1f5 | je | mem | `0x375180: cmpb $0x0,0x18(%rsp)` | memory | 0x3751e1 | fwd |
| Constant-time inversion | +0x237 | jne | reg/arith | `0x3751c4: cmp %rcx,%rsi` | memory | 0x375199 | back |
| Constant-time inversion | +0x263 | je | mem | `0x3751ee: cmpq $0x1,(%rsp)` | memory | 0x375211 | fwd |
| Constant-time inversion | +0x2d5 | je | mem | `0x375260: cmpb $0x0,0x18(%rsp)` | memory | 0x3752f0 | fwd |
| Constant-time inversion | +0x2ff | jne | reg/arith | `0x37528d: or %cl,%dl` | memory | 0x3752cf | fwd |
| Constant-time inversion | +0x339 | jne | reg/arith | `0x3752c6: cmp %rcx,%rsi` | memory | 0x37529b | back |
| Constant-time inversion | +0x342 | je | reg/arith | `0x3752cf: test %rax,%rax` | memory | 0x375187 | back |
| Constant-time inversion | +0x372 | je | mem | `0x3752fd: cmpq $0x1,(%rsp)` | memory | 0x375328 | fwd |
| Constant-time inversion | +0x3e8 | je | mem | `0x375373: cmpb $0x0,0x18(%rsp)` | memory | 0x375405 | fwd |
| Constant-time inversion | +0x416 | jne | reg/arith | `0x3753a4: or %cl,%al` | memory | 0x3753e2 | fwd |
| Constant-time inversion | +0x450 | jne | reg/arith | `0x3753dd: cmp %rcx,%rsi` | memory | 0x3753b2 | back |
| Constant-time inversion | +0x457 | je | mem | `0x3753e2: cmpq $0x0,(%rsp)` | memory | 0x3753fc | fwd |
| Constant-time inversion | +0x483 | je | reg/arith | `0x37540f: cmp $0x1,%rbx` | memory | 0x375435 | fwd |
| Constant-time inversion | +0x4ee | je | mem | `0x375479: cmpb $0x0,0x18(%rsp)` | memory | 0x375489 | fwd |
| Constant-time inversion | +0x507 | je | reg/arith | `0x375493: cmp $0x1,%rbx` | memory | 0x3754b9 | fwd |
| Constant-time inversion | +0x562 | je | mem | `0x3754ec: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x37578d | fwd |
| Constant-time inversion | +0x599 | je | mem | `0x375523: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x375796 | fwd |
| Constant-time inversion | +0x5d0 | je | mem | `0x37555a: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x37708d | fwd |
| Constant-time inversion | +0x607 | je | mem | `0x375591: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x377096 | fwd |
| Constant-time inversion | +0x63f | je | mem | `0x3755c9: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x37709f | fwd |
| Constant-time inversion | +0x677 | je | mem | `0x375601: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x3770a8 | fwd |
| Constant-time inversion | +0x6af | je | mem | `0x375639: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x3770b1 | fwd |
| Constant-time inversion | +0x6e7 | je | mem | `0x375671: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x3770ba | fwd |
| Constant-time inversion | +0x71f | je | mem | `0x3756a9: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x3770c3 | fwd |
| Constant-time inversion | +0x757 | je | mem | `0x3756e1: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x3772d9 | fwd |
| Constant-time inversion | +0x793 | je | mem | `0x37571d: cmpq $0xffffffffffffffff,0x18(%rsp)` | memory | 0x3772df | fwd |
| Constant-time inversion | +0x9ad | je | mem | `0x375925: cmp 0x2c8(%rsp),%rax` | memory | 0x3770cc | fwd |
| Constant-time inversion | +0x9dc | je | reg/arith | `0x375969: test %rcx,%rcx` | memory | 0x3759c8 | fwd |
| Constant-time inversion | +0xa20 | je | reg/arith | `0x3759ac: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x3759cb | fwd |
| Constant-time inversion | +0xa25 | jae | reg/arith | `0x3759b2: cmp %rbx,%rcx` | memory | 0x3759bd | fwd |
| Constant-time inversion | +0xa32 | jb | reg/arith | `0x3759bf: cmp %rbx,%rcx` | arithmetic/control | 0x375982 | back |
| Constant-time inversion | +0xa58 | je | reg/arith | `0x3759e5: test %rcx,%rcx` | memory | 0x375a41 | fwd |
| Constant-time inversion | +0xa94 | je | reg/arith | `0x375a20: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x375a41 | fwd |
| Constant-time inversion | +0xa99 | jae | reg/arith | `0x375a26: cmp %rbx,%rcx` | memory | 0x375a36 | fwd |
| Constant-time inversion | +0xaab | jb | reg/arith | `0x375a38: cmp %rbx,%rcx` | arithmetic/control | 0x3759fd | back |
| Constant-time inversion | +0xb16 | je | reg/arith | `0x375aa3: test %rcx,%rcx` | memory | 0x375b9e | fwd |
| Constant-time inversion | +0xb2c | je | reg/arith | `0x375ab9: test %r14,%r14` | memory | 0x375b65 | fwd |
| Constant-time inversion | +0xb96 | je | reg/arith | `0x375b22: add $0xfffffffffffffffe,%rdx` | memory | 0x375b5a | fwd |
| Constant-time inversion | +0xba3 | jae | reg/arith | `0x375b30: cmp %rbx,%r11` | memory | 0x375b3b | fwd |
| Constant-time inversion | +0xbc3 | jb | reg/arith | `0x375b50: cmp %rbx,%r8` | arithmetic/control | 0x375b03 | back |
| Constant-time inversion | +0xbce | je | reg/arith | `0x375b5a: test $0x1,%r14b` | arithmetic/control | 0x375b9e | fwd |
| Constant-time inversion | +0xbfc | jae | reg/arith | `0x375b89: cmp %rbx,%rcx` | memory | 0x375b94 | fwd |
| Constant-time inversion | +0xc26 | je | reg/arith | `0x375bb3: test %r8,%r8` | memory | 0x375cab | fwd |
| Constant-time inversion | +0xc37 | je | reg/arith | `0x375bc4: test %r13,%r13` | memory | 0x375c71 | fwd |
| Constant-time inversion | +0xc9f | je | reg/arith | `0x375c2b: add $0xfffffffffffffffe,%r10` | memory | 0x375c66 | fwd |
| Constant-time inversion | +0xcae | jae | mem | `0x375c39: cmp 0x50(%rsp),%r14` | memory | 0x375c46 | fwd |
| Constant-time inversion | +0xcd0 | jb | mem | `0x375c5b: cmp 0x50(%rsp),%rax` | arithmetic/control | 0x375c0c | back |
| Constant-time inversion | +0xcda | je | reg/arith | `0x375c66: test $0x1,%r13b` | arithmetic/control | 0x375cab | fwd |
| Constant-time inversion | +0xd04 | jae | mem | `0x375c8f: cmp 0x50(%rsp),%rsi` | memory | 0x375ca1 | fwd |
| Constant-time inversion | +0xd9b | je | reg/arith | `0x375d27: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x375d60 | fwd |
| Constant-time inversion | +0xda0 | jae | reg/arith | `0x375d2d: cmp %rbx,%rcx` | memory | 0x375d38 | fwd |
| Constant-time inversion | +0xdaf | jae | mem | `0x375d3a: cmp 0x10(%rsp),%rcx` | memory | 0x375d4c | fwd |
| Constant-time inversion | +0xdc9 | jb | reg/arith | `0x375d56: cmp %r8,%rcx` | arithmetic/control | 0x375d04 | back |
| Constant-time inversion | +0xdd6 | je | mem | `0x375d60: cmpq $0x0,0x10(%rsp)` | memory | 0x375e64 | fwd |
| Constant-time inversion | +0xdec | je | reg/arith | `0x375d79: test %r10,%r10` | memory | 0x375e27 | fwd |
| Constant-time inversion | +0xe59 | je | reg/arith | `0x375de5: add $0xfffffffffffffffe,%r11` | memory | 0x375e1c | fwd |
| Constant-time inversion | +0xe66 | jae | reg/arith | `0x375df3: cmp %rbx,%r14` | memory | 0x375dfe | fwd |
| Constant-time inversion | +0xe86 | jb | reg/arith | `0x375e13: cmp %rbx,%rax` | arithmetic/control | 0x375dc6 | back |
| Constant-time inversion | +0xe90 | je | reg/arith | `0x375e1c: test $0x1,%r10b` | arithmetic/control | 0x375e64 | fwd |
| Constant-time inversion | +0xebd | jae | reg/arith | `0x375e4a: cmp %rbx,%rsi` | memory | 0x375e5a | fwd |
| Constant-time inversion | +0xed7 | je | reg/arith | `0x375e64: test %r8,%r8` | memory | 0x375f5c | fwd |
| Constant-time inversion | +0xee8 | je | reg/arith | `0x375e75: test %r10,%r10` | memory | 0x375f22 | fwd |
| Constant-time inversion | +0xf50 | je | reg/arith | `0x375edc: add $0xfffffffffffffffe,%r11` | memory | 0x375f17 | fwd |
| Constant-time inversion | +0xf5f | jae | mem | `0x375eea: cmp 0x68(%rsp),%r14` | memory | 0x375ef7 | fwd |
| Constant-time inversion | +0xf81 | jb | mem | `0x375f0c: cmp 0x68(%rsp),%rax` | arithmetic/control | 0x375ebd | back |
| Constant-time inversion | +0xf8b | je | reg/arith | `0x375f17: test $0x1,%r10b` | arithmetic/control | 0x375f5c | fwd |
| Constant-time inversion | +0xfb5 | jae | mem | `0x375f40: cmp 0x68(%rsp),%rsi` | memory | 0x375f52 | fwd |
| Constant-time inversion | +0x1023 | je | reg/arith | `0x375faf: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x375fed | fwd |
| Constant-time inversion | +0x1028 | jae | reg/arith | `0x375fb5: cmp %rbx,%rcx` | memory | 0x375fc5 | fwd |
| Constant-time inversion | +0x103c | jae | mem | `0x375fc7: cmp 0x10(%rsp),%rcx` | memory | 0x375fd9 | fwd |
| Constant-time inversion | +0x1056 | jb | reg/arith | `0x375fe3: cmp %r8,%rcx` | arithmetic/control | 0x375f8c | back |
| Constant-time inversion | +0x10af | je | mem | `0x376036: cmpq $0x0,0x80(%rsp)` | memory | 0x376051 | fwd |
| Constant-time inversion | +0x10ee | je | reg/arith | `0x37607b: test %rcx,%rcx` | arithmetic/control | 0x376171 | fwd |
| Constant-time inversion | +0x10fb | je | reg/arith | `0x376087: add $0xfffffffffffffff8,%r8` | memory | 0x376135 | fwd |
| Constant-time inversion | +0x115e | je | reg/arith | `0x3760ea: add $0xfffffffffffffffe,%r9` | memory | 0x37612a | fwd |
| Constant-time inversion | +0x1170 | jae | mem | `0x3760f8: cmp 0x80(%rsp),%rdi` | memory | 0x376108 | fwd |
| Constant-time inversion | +0x1194 | jb | mem | `0x37611c: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x3760cb | back |
| Constant-time inversion | +0x119e | je | reg/arith | `0x37612a: test $0x1,%r8b` | arithmetic/control | 0x376171 | fwd |
| Constant-time inversion | +0x11c7 | jae | mem | `0x37614f: cmp 0x80(%rsp),%rdi` | memory | 0x376167 | fwd |
| Constant-time inversion | +0x11ec | je | reg/arith | `0x376179: test %rdx,%rdx` | arithmetic/control | 0x3761d7 | fwd |
| Constant-time inversion | +0x1220 | je | reg/arith | `0x3761ac: add $0xfffffffffffffff8,%rax` | memory | 0x3761d7 | fwd |
| Constant-time inversion | +0x122a | jae | mem | `0x3761b2: cmp 0x80(%rsp),%rcx` | memory | 0x3761ca | fwd |
| Constant-time inversion | +0x1240 | jb | mem | `0x3761cc: cmp (%rsp),%rcx` | arithmetic/control | 0x376187 | back |
| Constant-time inversion | +0x124b | ja | mem | `0x3761d7: cmp %rdx,(%rsp)` | arithmetic/control | 0x3773f7 | fwd |
| Constant-time inversion | +0x1251 | jae | unknown | `?` | memory | 0x377420 | fwd |
| Constant-time inversion | +0x125d | je | mem | `0x3761e7: cmpq $0x0,0x10(%rsp)` | memory | 0x3762be | fwd |
| Constant-time inversion | +0x1289 | jne | reg/arith | `0x376216: test $0x8,%dl` | memory | 0x376255 | fwd |
| Constant-time inversion | +0x12a7 | jae | mem | `0x376233: cmp (%rsp),%rdi` | memory | 0x376244 | fwd |
| Constant-time inversion | +0x12c8 | je | reg/arith | `0x376255: test %rdx,%rdx` | memory | 0x3762be | fwd |
| Constant-time inversion | +0x12f7 | je | mem | `0x376282: cmp 0x8(%rsp),%rax` | memory | 0x3762be | fwd |
| Constant-time inversion | +0x1304 | jae | mem | `0x376290: cmp (%rsp),%rsi` | memory | 0x3762a1 | fwd |
| Constant-time inversion | +0x1328 | jb | mem | `0x3762b4: cmp (%rsp),%rcx` | arithmetic/control | 0x376268 | back |
| Constant-time inversion | +0x1334 | je | mem | `0x3762be: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x376396 | fwd |
| Constant-time inversion | +0x1341 | je | reg/arith | `0x3762cd: add $0xfffffffffffffff8,%rdx` | memory | 0x37636a | fwd |
| Constant-time inversion | +0x138e | je | reg/arith | `0x37631b: cmp %rsi,%rdi` | memory | 0x37635b | fwd |
| Constant-time inversion | +0x139b | jae | mem | `0x376326: cmp 0x10(%rsp),%rdi` | memory | 0x376338 | fwd |
| Constant-time inversion | +0x13c4 | jb | mem | `0x37634f: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x3762f7 | back |
| Constant-time inversion | +0x13ce | je | reg/arith | `0x37635b: test $0x1,%dl` | arithmetic/control | 0x376396 | fwd |
| Constant-time inversion | +0x13e6 | jae | mem | `0x376371: cmp 0x10(%rsp),%rcx` | memory | 0x376383 | fwd |
| Constant-time inversion | +0x1438 | je | reg/arith | `0x3763c5: test %rax,%rax` | memory | 0x376436 | fwd |
| Constant-time inversion | +0x1477 | je | reg/arith | `0x376403: add $0xfffffffffffffff8,%rcx` | memory | 0x376431 | fwd |
| Constant-time inversion | +0x1481 | jae | mem | `0x376409: cmp 0x80(%rsp),%rdx` | memory | 0x376421 | fwd |
| Constant-time inversion | +0x149b | jb | mem | `0x376423: cmp 0x88(%rsp),%rdx` | arithmetic/control | 0x3763d8 | back |
| Constant-time inversion | +0x14b8 | je | reg/arith | `0x376445: test %rdx,%rdx` | arithmetic/control | 0x3764c8 | fwd |
| Constant-time inversion | +0x14f1 | je | reg/arith | `0x37647d: add $0xfffffffffffffff8,%rdx` | memory | 0x3764a1 | fwd |
| Constant-time inversion | +0x14f7 | jae | mem | `0x376483: cmp (%rsp),%rsi` | memory | 0x376492 | fwd |
| Constant-time inversion | +0x150a | jb | mem | `0x376495: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x376453 | back |
| Constant-time inversion | +0x157f | je | reg/arith | `0x37650c: test %rsi,%rsi` | arithmetic/control | 0x3765f7 | fwd |
| Constant-time inversion | +0x158c | je | reg/arith | `0x376518: add $0xfffffffffffffff8,%r11` | memory | 0x3765c0 | fwd |
| Constant-time inversion | +0x15ed | je | reg/arith | `0x376579: add $0xfffffffffffffffe,%rsi` | memory | 0x3765b5 | fwd |
| Constant-time inversion | +0x15fc | jae | mem | `0x376587: cmp 0x58(%rsp),%r14` | memory | 0x376594 | fwd |
| Constant-time inversion | +0x161e | jb | mem | `0x3765a9: cmp 0x58(%rsp),%r13` | arithmetic/control | 0x37655a | back |
| Constant-time inversion | +0x1629 | je | reg/arith | `0x3765b5: test $0x1,%r11b` | arithmetic/control | 0x3765f7 | fwd |
| Constant-time inversion | +0x1650 | jae | mem | `0x3765db: cmp 0x58(%rsp),%rdi` | memory | 0x3765ed | fwd |
| Constant-time inversion | +0x16a9 | je | reg/arith | `0x376635: add $0xfffffffffffffff8,%rsi` | memory | 0x37665b | fwd |
| Constant-time inversion | +0x16b0 | jae | mem | `0x37663b: cmp 0x58(%rsp),%rdi` | memory | 0x37664d | fwd |
| Constant-time inversion | +0x16c4 | jb | mem | `0x376650: cmp (%rsp),%rdi` | arithmetic/control | 0x37660f | back |
| Constant-time inversion | +0x16d1 | je | mem | `0x37665b: cmpq $0x0,0x10(%rsp)` | memory | 0x376720 | fwd |
| Constant-time inversion | +0x16f4 | jne | reg/arith | `0x376680: test $0x8,%dil` | memory | 0x37669e | fwd |
| Constant-time inversion | +0x1701 | jae | mem | `0x37668d: cmp (%rsp),%rsi` | memory | 0x3766a3 | fwd |
| Constant-time inversion | +0x1728 | je | reg/arith | `0x3766b5: test %rdi,%rdi` | memory | 0x376720 | fwd |
| Constant-time inversion | +0x1757 | je | mem | `0x3766e2: cmp 0x8(%rsp),%rsi` | memory | 0x376720 | fwd |
| Constant-time inversion | +0x1764 | jae | mem | `0x3766f0: cmp (%rsp),%r9` | memory | 0x376701 | fwd |
| Constant-time inversion | +0x1789 | jb | mem | `0x376715: cmp (%rsp),%r10` | arithmetic/control | 0x3766c8 | back |
| Constant-time inversion | +0x1796 | je | mem | `0x376720: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x3767ff | fwd |
| Constant-time inversion | +0x17a3 | je | reg/arith | `0x37672f: add $0xfffffffffffffff8,%r11` | memory | 0x3767d1 | fwd |
| Constant-time inversion | +0x17f1 | je | reg/arith | `0x37677e: cmp %r9,%r10` | memory | 0x3767c1 | fwd |
| Constant-time inversion | +0x17fe | jae | mem | `0x376789: cmp 0x10(%rsp),%r10` | memory | 0x37679b | fwd |
| Constant-time inversion | +0x182a | jb | mem | `0x3767b5: cmp 0x10(%rsp),%r10` | arithmetic/control | 0x37675a | back |
| Constant-time inversion | +0x1835 | je | reg/arith | `0x3767c1: test $0x1,%r11b` | arithmetic/control | 0x3767ff | fwd |
| Constant-time inversion | +0x184d | jae | mem | `0x3767d8: cmp 0x10(%rsp),%rsi` | memory | 0x3767ea | fwd |
| Constant-time inversion | +0x18a6 | je | reg/arith | `0x376833: test %rsi,%rsi` | arithmetic/control | 0x3768a9 | fwd |
| Constant-time inversion | +0x18db | je | reg/arith | `0x376867: add $0xfffffffffffffff8,%rsi` | memory | 0x3768a9 | fwd |
| Constant-time inversion | +0x18e5 | jae | mem | `0x37686d: cmp 0x80(%rsp),%rdi` | memory | 0x376885 | fwd |
| Constant-time inversion | +0x18fd | jae | mem | `0x376888: cmp 0x40(%rsp),%rdi` | memory | 0x37689a | fwd |
| Constant-time inversion | +0x1912 | jb | mem | `0x37689d: cmp 0x68(%rsp),%rdi` | arithmetic/control | 0x376840 | back |
| Constant-time inversion | +0x1922 | je | mem | `0x3768a9: cmpq $0x0,0x88(%rsp)` | memory | 0x3768c4 | fwd |
| Constant-time inversion | +0x1949 | je | mem | `0x3768d3: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x3769ef | fwd |
| Constant-time inversion | +0x1956 | je | reg/arith | `0x3768e2: add $0xfffffffffffffff8,%rsi` | memory | 0x3769b2 | fwd |
| Constant-time inversion | +0x19ce | je | reg/arith | `0x37695a: add $0xfffffffffffffffe,%rsi` | memory | 0x3769a1 | fwd |
| Constant-time inversion | +0x19e0 | jae | mem | `0x376968: cmp 0x88(%rsp),%r14` | memory | 0x376978 | fwd |
| Constant-time inversion | +0x1a0a | jb | mem | `0x376992: cmp 0x88(%rsp),%r13` | arithmetic/control | 0x376931 | back |
| Constant-time inversion | +0x1a19 | je | mem | `0x3769a1: testb $0x1,0xa0(%rsp)` | memory | 0x3769ef | fwd |
| Constant-time inversion | +0x1a45 | jae | mem | `0x3769cd: cmp 0x88(%rsp),%rdi` | memory | 0x3769e5 | fwd |
| Constant-time inversion | +0x1a93 | je | reg/arith | `0x376a1f: add $0xfffffffffffffff8,%rsi` | memory | 0x376a4b | fwd |
| Constant-time inversion | +0x1a9d | jae | mem | `0x376a25: cmp 0x88(%rsp),%rdi` | memory | 0x376a3d | fwd |
| Constant-time inversion | +0x1ab4 | jb | mem | `0x376a40: cmp (%rsp),%rdi` | arithmetic/control | 0x3769f9 | back |
| Constant-time inversion | +0x1ac1 | je | mem | `0x376a4b: cmpq $0x0,0x10(%rsp)` | memory | 0x376b10 | fwd |
| Constant-time inversion | +0x1ae4 | jne | reg/arith | `0x376a70: test $0x8,%dil` | memory | 0x376a8e | fwd |
| Constant-time inversion | +0x1af1 | jae | mem | `0x376a7d: cmp (%rsp),%rsi` | memory | 0x376a93 | fwd |
| Constant-time inversion | +0x1b18 | je | reg/arith | `0x376aa5: test %rdi,%rdi` | memory | 0x376b10 | fwd |
| Constant-time inversion | +0x1b47 | je | mem | `0x376ad2: cmp 0x8(%rsp),%rsi` | memory | 0x376b10 | fwd |
| Constant-time inversion | +0x1b54 | jae | mem | `0x376ae0: cmp (%rsp),%r9` | memory | 0x376af1 | fwd |
| Constant-time inversion | +0x1b79 | jb | mem | `0x376b05: cmp (%rsp),%r10` | arithmetic/control | 0x376ab8 | back |
| Constant-time inversion | +0x1b86 | je | mem | `0x376b10: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x376be8 | fwd |
| Constant-time inversion | +0x1b90 | je | reg/arith | `0x376b1c: add $0xfffffffffffffff8,%r12` | memory | 0x376bbc | fwd |
| Constant-time inversion | +0x1bde | je | reg/arith | `0x376b6b: cmp %rdi,%r9` | memory | 0x376bac | fwd |
| Constant-time inversion | +0x1beb | jae | mem | `0x376b76: cmp 0x10(%rsp),%r9` | memory | 0x376b88 | fwd |
| Constant-time inversion | +0x1c15 | jb | mem | `0x376ba0: cmp 0x10(%rsp),%r9` | arithmetic/control | 0x376b47 | back |
| Constant-time inversion | +0x1c20 | je | reg/arith | `0x376bac: test $0x1,%r12b` | arithmetic/control | 0x376be8 | fwd |
| Constant-time inversion | +0x1c38 | jae | mem | `0x376bc3: cmp 0x10(%rsp),%rsi` | memory | 0x376bd5 | fwd |
| Constant-time inversion | +0x1c5e | je | mem | `0x376be8: cmpq $0x0,0x10(%rsp)` | memory | 0x376c61 | fwd |
| Constant-time inversion | +0x1ca0 | je | reg/arith | `0x376c2c: add $0xfffffffffffffff8,%rsi` | memory | 0x376c5c | fwd |
| Constant-time inversion | +0x1caa | jae | mem | `0x376c32: cmp 0x88(%rsp),%rdi` | memory | 0x376c4a | fwd |
| Constant-time inversion | +0x1cc5 | jb | mem | `0x376c4d: cmp 0x80(%rsp),%rdi` | arithmetic/control | 0x376bff | back |
| Constant-time inversion | +0x1cda | je | mem | `0x376c64: cmpq $0x0,0x58(%rsp)` | arithmetic/control | 0x376ccd | fwd |
| Constant-time inversion | +0x1d10 | je | reg/arith | `0x376c9c: add $0xfffffffffffffff8,%rcx` | memory | 0x376cc0 | fwd |
| Constant-time inversion | +0x1d16 | jae | mem | `0x376ca2: cmp (%rsp),%rsi` | memory | 0x376cb1 | fwd |
| Constant-time inversion | +0x1d29 | jb | mem | `0x376cb4: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x376c72 | back |
| Constant-time inversion | +0x1d52 | je | mem | `0x376cdc: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x376ddd | fwd |
| Constant-time inversion | +0x1d5f | je | reg/arith | `0x376ceb: add $0xfffffffffffffff8,%r10` | memory | 0x376da7 | fwd |
| Constant-time inversion | +0x1dce | je | reg/arith | `0x376d5a: add $0xfffffffffffffffe,%rsi` | memory | 0x376d9a | fwd |
| Constant-time inversion | +0x1ddd | jae | mem | `0x376d68: cmp 0x58(%rsp),%r14` | memory | 0x376d75 | fwd |
| Constant-time inversion | +0x1e04 | jb | mem | `0x376d8f: cmp 0x58(%rsp),%rcx` | arithmetic/control | 0x376d31 | back |
| Constant-time inversion | +0x1e0e | je | reg/arith | `0x376d9a: test $0x1,%r10b` | memory | 0x376ddd | fwd |
| Constant-time inversion | +0x1e36 | jae | mem | `0x376dc1: cmp 0x58(%rsp),%rdi` | memory | 0x376dd3 | fwd |
| Constant-time inversion | +0x1e7c | je | reg/arith | `0x376e08: add $0xfffffffffffffff8,%r8` | memory | 0x376e2d | fwd |
| Constant-time inversion | +0x1e83 | jae | mem | `0x376e0e: cmp 0x58(%rsp),%rcx` | memory | 0x376e20 | fwd |
| Constant-time inversion | +0x1e96 | jb | mem | `0x376e22: cmp (%rsp),%rcx` | arithmetic/control | 0x376de3 | back |
| Constant-time inversion | +0x1ea3 | je | mem | `0x376e2d: cmpq $0x0,0x10(%rsp)` | memory | 0x376eed | fwd |
| Constant-time inversion | +0x1ec9 | jne | reg/arith | `0x376e55: test $0x8,%sil` | memory | 0x376e84 | fwd |
| Constant-time inversion | +0x1ed6 | jae | mem | `0x376e62: cmp (%rsp),%rsi` | memory | 0x376e73 | fwd |
| Constant-time inversion | +0x1ef7 | je | reg/arith | `0x376e84: test %rdi,%rdi` | memory | 0x376eed | fwd |
| Constant-time inversion | +0x1f26 | je | mem | `0x376eb1: cmp 0x8(%rsp),%rax` | memory | 0x376eed | fwd |
| Constant-time inversion | +0x1f33 | jae | mem | `0x376ebf: cmp (%rsp),%rdi` | memory | 0x376ed0 | fwd |
| Constant-time inversion | +0x1f57 | jb | mem | `0x376ee3: cmp (%rsp),%rcx` | arithmetic/control | 0x376e97 | back |
| Constant-time inversion | +0x1f63 | je | mem | `0x376eed: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x376fc2 | fwd |
| Constant-time inversion | +0x1f6d | je | reg/arith | `0x376ef9: add $0xfffffffffffffff8,%rdx` | memory | 0x376f96 | fwd |
| Constant-time inversion | +0x1fba | je | reg/arith | `0x376f47: cmp %rsi,%rdi` | memory | 0x376f87 | fwd |
| Constant-time inversion | +0x1fc7 | jae | mem | `0x376f52: cmp 0x10(%rsp),%rdi` | memory | 0x376f64 | fwd |
| Constant-time inversion | +0x1ff0 | jb | mem | `0x376f7b: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x376f23 | back |
| Constant-time inversion | +0x1ffa | je | reg/arith | `0x376f87: test $0x1,%dl` | arithmetic/control | 0x376fc2 | fwd |
| Constant-time inversion | +0x2012 | jae | mem | `0x376f9d: cmp 0x10(%rsp),%rcx` | memory | 0x376faf | fwd |
| Constant-time inversion | +0x2080 | je | reg/arith | `0x37700d: test %rcx,%rcx` | memory | 0x37579f | back |
| Constant-time inversion | +0x20be | je | reg/arith | `0x37704a: add $0xfffffffffffffff8,%rax` | memory | 0x37579f | back |
| Constant-time inversion | +0x20cc | jae | mem | `0x377054: cmp 0x88(%rsp),%rcx` | memory | 0x37706c | fwd |
| Constant-time inversion | +0x20e3 | jae | mem | `0x37706e: cmp 0x40(%rsp),%rcx` | memory | 0x377080 | fwd |
| Constant-time inversion | +0x20f7 | jb | mem | `0x377082: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x37701f | back |
| Constant-time inversion | +0x214c | je | reg/arith | `0x3770d8: cmp $0x1,%rbx` | memory | 0x37717b | fwd |
| Constant-time inversion | +0x216b | jb | reg/arith | `0x3770f7: cmp $0x18,%rcx` | memory | 0x377160 | fwd |
| Constant-time inversion | +0x21b7 | jne | reg/arith | `0x377144: cmp %rdx,%rsi` | arithmetic/control | 0x37712c | back |
| Constant-time inversion | +0x21ce | je | reg/arith | `0x37715b: cmp %rsi,%rcx` | memory | 0x37717b | fwd |
| Constant-time inversion | +0x21e9 | jne | mem | `0x377174: cmp 0x8(%rsp),%rax` | call+memory | 0x37716d | back |
| Constant-time inversion | +0x2204 | je | reg/arith | `0x377190: cmp $0xffffffffffffffff,%r12` | memory | 0x3772e5 | fwd |
| Constant-time inversion | +0x2219 | jne | mem | `0x3771a4: cmp 0x38(%rsp),%rdi` | memory | 0x37740c | fwd |
| Constant-time inversion | +0x2315 | je | reg/arith | `0x3772a2: test %r15,%r15` | memory | 0x3773e1 | fwd |
| Constant-time inversion | +0x2326 | je | reg/arith | `0x3772b3: test %r12,%r12` | memory | 0x375002 | back |
| Constant-time inversion | +0x2437 | jne | reg/arith | `0x3773c4: cmp %rax,%rsi` | memory | 0x377399 | back |
| Constant-time inversion | +0x24af | je | reg/arith | `0x37743c: test %r12,%r12` | memory | 0x37745b | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x37ac30: test %rcx,%rcx` | memory | 0x37aca4 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x37ac40: test %rax,%rax` | memory | 0x37ac98 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x37ac4c: cmp (%r15),%rcx` | memory | 0x37ac9f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x37ac55: test %ecx,%ecx` | memory | 0x37ac65 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x37ac5d: test %edx,%edx` | arithmetic/control | 0x37ac65 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x37ac61: cmp %edx,%ecx` | call | 0x37ac9f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x37ac6d: test %eax,%eax` | memory | 0x37aca4 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x37ac79: test %rax,%rax` | memory | 0x37add2 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x37ac82: cmp (%r12),%rcx` | memory | 0x37b013 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x37acaf: test %rcx,%rcx` | memory | 0x37adb0 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x37acd0: cmp %rdx,%rcx` | memory | 0x37adb0 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x37acd9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x37acd0 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x37acef: test %rcx,%rcx` | memory | 0x37adb0 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x37ad10: cmp %rdx,%rcx` | memory | 0x37adb0 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x37ad19: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x37ad10 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x37ad2d: test %r13,%r13` | memory | 0x37adc9 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x37ad3a: cmpq $0x0,0x50(%rax)` | memory | 0x37ade0 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x37ad5c: test %rax,%rax` | memory | 0x37adab | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x37ad77: test %rax,%rax` | call | 0x37ad85 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x37ad81: test %eax,%eax` | call+memory | 0x37adf8 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x37adef: test %r13,%r13` | memory | 0x37af3d | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x37adfc: cmpq $0x0,0x50(%rax)` | memory | 0x37af34 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x37ae23: test %rax,%rax` | memory | 0x37af71 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x37ae42: test %rax,%rax` | call | 0x37af4b | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x37ae50: test %eax,%eax` | memory | 0x37af4b | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x37ae62: test %r14,%r14` | arithmetic/control | 0x37b02c | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x37ae6b: test %r15,%r15` | memory | 0x37b037 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x37ae7e: test %rcx,%rcx` | memory | 0x37aeb8 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x37ae87: test %rax,%rax` | memory | 0x37aeb8 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x37ae93: cmp (%r15),%rcx` | memory | 0x37aeb8 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x37ae9c: test %ecx,%ecx` | memory | 0x37b17a | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x37aea8: test %edx,%edx` | arithmetic/control | 0x37b17a | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x37aeb0: cmp %ecx,%edx` | call | 0x37b17a | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x37aed2: test %rax,%rax` | memory | 0x37aee5 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x37aedb: test %rax,%rax` | call | 0x37aee5 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x37af16: test %rbx,%rbx` | memory | 0x37b14e | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x37af23: test %rcx,%rcx` | arithmetic/control | 0x37aff9 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x37af92: test %bpl,%bpl` | memory | 0x37afd8 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x37af9f: test %rax,%rax` | memory | 0x37afb2 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x37afa8: test %rax,%rax` | call | 0x37afb2 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x37afe3: test %rbx,%rbx` | memory | 0x37adb7 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x37aff0: test %rcx,%rcx` | memory | 0x37adb7 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x37b044: test %eax,%eax` | memory | 0x37b156 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x37b050: test %rax,%rax` | memory | 0x37b059 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x37b05d: test %rax,%rax` | memory | 0x37b066 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x37b06a: test %rax,%rax` | memory | 0x37b073 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x37b078: test %rax,%rax` | memory | 0x37b081 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x37b086: test %rax,%rax` | memory | 0x37b08f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x37b094: test %rax,%rax` | memory | 0x37b09d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x37b0a6: test %rax,%rax` | memory | 0x37b0af | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x37b0b8: test %rax,%rax` | memory | 0x37b0c1 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x37b0ca: test %rax,%rax` | call+memory | 0x37b0d3 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x37b0fb: test %rax,%rax` | memory | 0x37b162 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x37b119: test %eax,%eax` | memory | 0x37b16e | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x37b12a: test %r15,%r15` | memory | 0x37b198 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x37b133: test $0xffffffff80000000,%rax` | memory | 0x37b1ab | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x37b17a: cmp %r15,%r14` | call | 0x37b04c | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x37b18b: test %eax,%eax` | arithmetic/control | 0x37b04c | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x37b1b6: test $0x1,%al` | memory | 0x37b7f8 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x37b1c3: test %eax,%eax` | memory | 0x37b1f1 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x37b1ce: cmp %rsi,(%rdi)` | call+memory | 0x37b1fb | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x37b1e3: test %al,%cl` | arithmetic/control | 0x37b204 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x37b1f1: test %r15,%r15` | arithmetic/control | 0x37b219 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x37b1fb: test %r15,%r15` | memory | 0x37b2e4 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x37b204: cmp %rsi,(%r15)` | call | 0x37b219 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x37b211: test %al,%al` | memory | 0x37b2e4 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x37b22a: test %rax,%rax` | memory | 0x37b2f0 | fwd |
| ECDSA scalar ladder (driver) | +0x635 | jg | mem | `0x37b241: cmp 0x24(%rsp),%eax` | memory | 0x37b24e | fwd |
| ECDSA scalar ladder (driver) | +0x63c | je | mem | `0x37b247: cmpl $0x0,0x18(%r15)` | memory | 0x37b26a | fwd |
| ECDSA scalar ladder (driver) | +0x654 | je | reg/arith | `0x37b262: test %eax,%eax` | memory | 0x37b2fc | fwd |
| ECDSA scalar ladder (driver) | +0x672 | je | reg/arith | `0x37b280: test %eax,%eax` | memory | 0x37b308 | fwd |
| ECDSA scalar ladder (driver) | +0x68f | je | reg/arith | `0x37b29d: test %eax,%eax` | memory | 0x37b4de | fwd |
| ECDSA scalar ladder (driver) | +0x6a3 | js | mem | `0x37b2ae: cmpl $0x0,0x24(%rsp)` | memory | 0x37b314 | fwd |
| ECDSA scalar ladder (driver) | +0x6b5 | jae | mem | `0x37b2c1: cmp 0x10(%rcx),%rax` | memory | 0x37b314 | fwd |
| ECDSA scalar ladder (driver) | +0x722 | je | reg/arith | `0x37b32f: test %rax,%rax` | memory | 0x37b34c | fwd |
| ECDSA scalar ladder (driver) | +0x74f | je | reg/arith | `0x37b35c: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x75d | jae | mem | `0x37b36a: cmp %r15,(%rdi)` | call | 0x37b37f | fwd |
| ECDSA scalar ladder (driver) | +0x769 | je | reg/arith | `0x37b377: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x77b | je | reg/arith | `0x37b388: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x784 | jae | mem | `0x37b391: cmp %r15,(%rdi)` | call | 0x37b3a6 | fwd |
| ECDSA scalar ladder (driver) | +0x790 | je | reg/arith | `0x37b39e: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x7a2 | je | reg/arith | `0x37b3af: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x7ab | jae | mem | `0x37b3b8: cmp %r15,(%rdi)` | call | 0x37b3cd | fwd |
| ECDSA scalar ladder (driver) | +0x7b7 | je | reg/arith | `0x37b3c5: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x7c5 | je | reg/arith | `0x37b3d2: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x7ce | jae | mem | `0x37b3db: cmp %r15,(%rdi)` | call | 0x37b3f0 | fwd |
| ECDSA scalar ladder (driver) | +0x7da | je | reg/arith | `0x37b3e8: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x7e8 | je | reg/arith | `0x37b3f5: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x7f1 | jae | mem | `0x37b3fe: cmp %r15,(%rdi)` | call | 0x37b413 | fwd |
| ECDSA scalar ladder (driver) | +0x7fd | je | reg/arith | `0x37b40b: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x80b | je | reg/arith | `0x37b418: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x814 | jae | mem | `0x37b421: cmp %r15,(%rdi)` | call | 0x37b436 | fwd |
| ECDSA scalar ladder (driver) | +0x820 | je | reg/arith | `0x37b42e: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x832 | je | reg/arith | `0x37b43f: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x83b | jae | mem | `0x37b448: cmp %r15,(%rdi)` | call | 0x37b45d | fwd |
| ECDSA scalar ladder (driver) | +0x847 | je | reg/arith | `0x37b455: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x859 | je | reg/arith | `0x37b466: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x862 | jae | mem | `0x37b46f: cmp %r15,(%rdi)` | call | 0x37b484 | fwd |
| ECDSA scalar ladder (driver) | +0x86e | je | reg/arith | `0x37b47c: test %al,%al` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x880 | je | reg/arith | `0x37b48d: test %rdi,%rdi` | memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0x88e | jae | mem | `0x37b496: cmp %r15,(%rdi)` | call | 0x37b4b0 | fwd |
| ECDSA scalar ladder (driver) | +0x89a | je | reg/arith | `0x37b4a8: test %al,%al` | memory | 0x37aec4 | back |
| ECDSA scalar ladder (driver) | +0x8a5 | je | mem | `0x37b4b0: cmpl $0x0,0x28(%r14)` | call+memory | 0x37b612 | fwd |
| ECDSA scalar ladder (driver) | +0x8b9 | je | reg/arith | `0x37b4c7: test %al,%al` | memory | 0x37b4ea | fwd |
| ECDSA scalar ladder (driver) | +0x8e8 | jne | reg/arith | `0x37b4f4: cmp $0x4,%rdx` | memory | 0x37b53d | fwd |
| ECDSA scalar ladder (driver) | +0x922 | jne | reg/arith | `0x37b52e: cmp $0x1,%dil` | call | 0x37b53f | fwd |
| ECDSA scalar ladder (driver) | +0x934 | je | reg/arith | `0x37b542: test %cl,%cl` | arithmetic/control | 0x37b5b8 | fwd |
| ECDSA scalar ladder (driver) | +0x939 | jne | reg/arith | `0x37b546: test %sil,%sil` | memory | 0x37b5b8 | fwd |
| ECDSA scalar ladder (driver) | +0x985 | je | mem | `0x37b58c: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x37b682 | fwd |
| ECDSA scalar ladder (driver) | +0x9cb | je | reg/arith | `0x37b5d9: test %eax,%eax` | arithmetic/control | 0x37b650 | fwd |
| ECDSA scalar ladder (driver) | +0x9d4 | jg | reg/arith | `0x37b5e1: cmp $0x1,%eax` | arithmetic/control | 0x37b65c | fwd |
| ECDSA scalar ladder (driver) | +0x9d8 | jne | reg/arith | `0x37b5e6: test %eax,%eax` | call+memory | 0x37b693 | fwd |
| ECDSA scalar ladder (driver) | +0xa17 | je | reg/arith | `0x37b624: test %rax,%rax` | call+memory | 0x37b646 | fwd |
| ECDSA scalar ladder (driver) | +0xa2b | jne | reg/arith | `0x37b639: test %eax,%eax` | arithmetic/control | 0x37b4bb | back |
| ECDSA scalar ladder (driver) | +0xa4f | jne | reg/arith | `0x37b65c: cmp $0x2,%eax` | call+memory | 0x37b6c6 | fwd |
| ECDSA scalar ladder (driver) | +0xaa4 | jne | reg/arith | `0x37b6b2: test %eax,%eax` | memory | 0x37b78b | fwd |
| ECDSA scalar ladder (driver) | +0xaba | jo | mem | `0x37b6c6: decl 0x24(%rsp)` | arithmetic/control | 0x37b807 | fwd |
| ECDSA scalar ladder (driver) | +0xac0 | js | unknown | `?` | memory | 0x37b772 | fwd |
| ECDSA scalar ladder (driver) | +0xae9 | jae | mem | `0x37b6f5: cmp 0x10(%rcx),%rax` | memory | 0x37b712 | fwd |
| ECDSA scalar ladder (driver) | +0xb1c | je | mem | `0x37b726: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x37b745 | fwd |
| ECDSA scalar ladder (driver) | +0xb4f | je | reg/arith | `0x37b75d: test %eax,%eax` | memory | 0x37b7cd | fwd |
| ECDSA scalar ladder (driver) | +0xb5a | jg | reg/arith | `0x37b763: test %r15,%r15` | arithmetic/control | 0x37b6e7 | back |
| ECDSA scalar ladder (driver) | +0xb89 | je | reg/arith | `0x37b796: test %rax,%rax` | call+memory | 0x37b7b4 | fwd |
| ECDSA scalar ladder (driver) | +0xba2 | je | reg/arith | `0x37b7b0: test %eax,%eax` | call+memory | 0x37b7c6 | fwd |
| ECDSA scalar ladder (driver) | +0xbdd | jne | reg/arith | `0x37b7ea: test %rax,%rax` | arithmetic/control | 0x37aed7 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x427b27: test %rax,%rax` | memory | 0x4280c5 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x427b42: test %rbp,%rbp` | memory | 0x4280c5 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x427b52: test %rax,%rax` | call+memory | 0x4280c5 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x427b74: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x427b92: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x427bb0: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x427bce: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x427bf4: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x427c14: test %eax,%eax` | arithmetic/control | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x427c1c: test %r15,%r15` | memory | 0x427c42 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x427c2e: test %rdx,%rdx` | arithmetic/control | 0x427c64 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x427c5a: test %rdx,%rdx` | memory | 0x427c70 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x427c73: sub $0x1,%r9` | memory | 0x427c97 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x427c79: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x427c70 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x427c90: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x427ca0 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x427c9a: sub $0x1,%r8` | arithmetic/control | 0x427c90 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x427ca0: cmp %r9,%rdi` | memory | 0x427cc0 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x427cb0: sub $0x1,%rdi` | memory | 0x427cc2 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x427cba: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x427cb0 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x427cdd | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x427cd5: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x427cef: test %eax,%eax` | arithmetic/control | 0x4280c5 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x427cfc: test %r15,%r15` | memory | 0x427d0b | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x427d23: sub $0x1,%rdi` | memory | 0x427d47 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x427d29: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x427d20 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x427d40: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x427d50 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x427d4a: sub $0x1,%rsi` | arithmetic/control | 0x427d40 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x427d50: cmp %rdi,%rdx` | arithmetic/control | 0x427d65 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x427d55: sub $0x1,%rdx` | memory | 0x427d67 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x427d5f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x427d55 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x427d7e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x427d76: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x427d93: test %eax,%eax` | memory | 0x4280c5 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x427dad: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x427dd0: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x427deb: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x427e05: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x427e27: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x427e41: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x427e64: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x427e86: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x427ea8: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x427eca: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x427ee4: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x427f00: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x427f24: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x427f3e: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x427f5d: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x427f7c: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x427f9b: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x427fb5: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x427fd4: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x427ff1: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x428016: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x428035: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x428051: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x42806a: test %eax,%eax` | call+memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x428083: test %eax,%eax` | memory | 0x4280c3 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x428099: test %eax,%eax` | memory | 0x4280c5 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x4280c5: test %rbx,%rbx` | memory | 0x4280e8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x4280ce: test %rax,%rax` | memory | 0x4280e8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x2f7afb: test %rax,%rax` | memory | 0x2f8568 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x2f7b15: cmpl $0x1,0x10(%rbp)` | memory | 0x2f7b3d | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x2f7b25: test %rax,%rax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x2f7b34: cmp $0xfffffffd,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x2f7b45: testb $0x4,0xa4(%rbp)` | memory | 0x2f7b65 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x2f7b4e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x2f7bc6 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x2f7b57: test %r13b,%r13b` | arithmetic/control | 0x2f7ca0 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x2f7b6b: test %rax,%rax` | memory | 0x2f8568 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x2f7b99: test %rax,%rax` | arithmetic/control | 0x2f80b0 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x2f7ba2: test %r15,%r15` | memory | 0x2f7bb0 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x2f7bba: test %rax,%rax` | arithmetic/control | 0x2f7c28 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x2f7be3: test %r15,%r15` | arithmetic/control | 0x2f7c80 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x2f7bec: test %r14,%r14` | memory | 0x2f7bfa | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x2f7c01: test %r15,%r15` | memory | 0x2f7c72 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x2f7c1b: test %eax,%eax` | memory | 0x2f7c66 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x2f7c44: test %eax,%eax` | memory | 0x2f8087 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x2f7c72: test %r14,%r14` | memory | 0x2f7c80 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x2f7c86: or %r13b,%al` | arithmetic/control | 0x2f7eb2 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x2f7c97: test %r15,%r15` | memory | 0x2f8568 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x2f7ca6: test %rax,%rax` | memory | 0x2f8568 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x2f7ce9: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x2f7cf7: test %rax,%rax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x2f7d1d: test %rax,%rax` | call+memory | 0x2f8a10 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x2f7d46: test %eax,%eax` | call+memory | 0x2f8a10 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x2f7d94: test %al,0x38(%rsp)` | memory | 0x2f7e13 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x2f7da5: test %rax,%rax` | memory | 0x2f8568 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x2f7dcb: test %rax,%rax` | call+memory | 0x2f8462 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x2f7e05: test %ebp,%ebp` | arithmetic/control | 0x2f856b | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x2f7e15: test %ebx,%ebx` | memory | 0x2f82ce | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x2f7e27: test %r15b,%r15b` | call+memory | 0x2f82d8 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x2f7e4e: test %r13,%r13` | arithmetic/control | 0x2f8a0b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x2f7e5c: test %rax,%rax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x2f7e6e: test %rax,%rax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x2f7e7e: test %rcx,%rcx` | memory | 0x2f846f | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x2f7e96: cmpq $0x0,0x10(%rcx)` | memory | 0x2f8479 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x2f7ed7: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x2f7ef5: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x2f7f1f: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x2f7f3d: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x2f7f76: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x2f7f98: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x2f7fb1: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x2f7fb9: test %rbx,%rbx` | memory | 0x2f8004 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x2f7fc8: cmpl $0x0,0x18(%rbx)` | memory | 0x2f8004 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x2f7fde: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x2f7fe6: cmpl $0x0,0x18(%rbx)` | memory | 0x2f8004 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x2f7ffc: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x2f801a: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x2f803c: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x2f8059: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x2f8097: test %r15,%r15` | memory | 0x2f80a5 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x2f80a5: test %bl,%bl` | memory | 0x2f8158 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x2f80d2: test %rax,%rax` | arithmetic/control | 0x2f8160 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x2f80db: test %r15,%r15` | memory | 0x2f80e9 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x2f80f3: test %rax,%rax` | arithmetic/control | 0x2f80fc | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x2f8118: test %eax,%eax` | memory | 0x2f8133 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x2f8143: test %r15,%r15` | memory | 0x2f8151 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x2f8151: test %bl,%bl` | arithmetic/control | 0x2f8160 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x2f816a: test %ebx,%ebx` | memory | 0x2f825b | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x2f8199: test %bl,%bl` | arithmetic/control | 0x2f82c1 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x2f81a4: cmp %r14,%r13` | memory | 0x2f825b | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x2f81d8: test %rax,%rax` | arithmetic/control | 0x2f81a1 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x2f81dd: test %r15,%r15` | memory | 0x2f81eb | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x2f81ef: test %rax,%rax` | arithmetic/control | 0x2f81fd | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x2f81f6: test %r15,%r15` | arithmetic/control | 0x2f8190 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x2f8212: test %eax,%eax` | memory | 0x2f8238 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x2f822a: test %r15,%r15` | arithmetic/control | 0x2f8190 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x2f824d: test %r15,%r15` | arithmetic/control | 0x2f8190 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x2f8269: test %ebx,%ebx` | memory | 0x2f82b4 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x2f8275: cmp 0x5d30c4(%rip),%rax        # 8cb340 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x3e9aa0>` | call+memory | 0x2f7b4e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x2f82dd: test %al,%r14b` | memory | 0x2f855f | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x2f8313: test %eax,%eax` | arithmetic/control | 0x2f856b | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x2f831b: test %rbx,%rbx` | memory | 0x2f833e | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x2f8320: cmpl $0x0,0x18(%rbx)` | memory | 0x2f833e | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x2f8336: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x2f8353: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x2f8361: test %rax,%rax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x2f83ad: test %ebp,%ebp` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x2f83b5: test %rbx,%rbx` | memory | 0x2f83dd | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x2f83bf: cmpl $0x0,0x18(%rbx)` | memory | 0x2f83dd | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x2f83d5: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x2f83f5: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x2f840e: test %eax,%eax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x2f8416: cmpl $0x0,0x28(%rsp)` | memory | 0x2f876c | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x2f842c: test %rax,%rax` | memory | 0x2f856b | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x2f8442: test %rax,%rax` | memory | 0x2f8679 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x2f844b: cmpq $0x0,0x10(%rax)` | memory | 0x2f8679 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x2f84bd: test %eax,%eax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x2f84d2: test %rax,%rax` | call+memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x2f84f6: test %eax,%eax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x2f84fe: cmpl $0x1,0x28(%rsp)` | call+memory | 0x2f85a4 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x2f8556: test %al,%r14b` | arithmetic/control | 0x2f82e6 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x2f855f: test %r15b,%r15b` | arithmetic/control | 0x2f876c | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x2f856b: test %r12,%r12` | memory | 0x2f8592 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x2f8575: test %rax,%rax` | memory | 0x2f8592 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x2f85ad: test %rax,%rax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x2f85c7: test %rax,%rax` | memory | 0x2f85dd | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x2f85cc: cmpq $0x2,0x10(%rax)` | memory | 0x2f85dd | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x2f861a: test %eax,%eax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x2f862f: test %rax,%rax` | call+memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x2f8653: test %eax,%eax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x2f865b: cmpl $0x2,0x28(%rsp)` | memory | 0x2f8923 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x2f8691: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x2f86ae: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x2f86e5: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x2f86ed: cmpq $0x0,0x8(%rsp)` | memory | 0x2f8719 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x2f86fa: cmpl $0x0,0x18(%rax)` | memory | 0x2f8719 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x2f8711: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x2f872e: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x2f8749: test %eax,%eax` | memory | 0x2f8a23 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x2f8751: cmpl $0x1,0x28(%rsp)` | memory | 0x2f8a3b | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x2f8770: test %rdx,%rdx` | memory | 0x2f8902 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x2f877d: test %rcx,%rcx` | memory | 0x2f8902 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x2f878e: cmp 0x5d2bab(%rip),%rax        # 8cb340 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x3e9aa0>` | memory | 0x2f87b8 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x2f8797: test %rax,%rax` | call+memory | 0x2f8568 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x2f87d5: test %eax,%eax` | memory | 0x2f856b | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x2f87f0: test %eax,%eax` | memory | 0x2f856b | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x2f8810: cmp %rdx,%rcx` | memory | 0x2f8902 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x2f8819: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2f8810 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x2f8844: test %eax,%eax` | memory | 0x2f890d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x2f8851: cmpl $0x0,0x18(%rax)` | memory | 0x2f8874 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x2f886c: test %eax,%eax` | memory | 0x2f856b | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x2f8887: cmp %rdx,%rcx` | memory | 0x2f8915 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x2f8890: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2f8887 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x2f88a6: test %rax,%rax` | memory | 0x2f895c | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x2f88cb: test %rax,%rax` | call+memory | 0x2f8a33 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x2f8931: test %rax,%rax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x2f8946: test %rax,%rax` | memory | 0x2f8967 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x2f894b: cmpq $0x3,0x10(%rax)` | memory | 0x2f8967 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x2f89a4: test %eax,%eax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x2f89b5: test %rax,%rax` | call+memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x2f89d5: test %eax,%eax` | memory | 0x2f8a0b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x2f89d9: cmpl $0x3,0x28(%rsp)` | memory | 0x2f851b | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x2f8a4a: test %rax,%rax` | memory | 0x2f8a60 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x2f8a4f: cmpq $0x2,0x10(%rax)` | memory | 0x2f8a60 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x2f8a78: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x2f8a91: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x2f8ac4: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x2f8acc: cmpq $0x0,0x8(%rsp)` | memory | 0x2f8af8 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x2f8ad9: cmpl $0x0,0x18(%rax)` | memory | 0x2f8af8 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x2f8af0: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x2f8b0d: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x2f8b28: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x2f8b30: cmpl $0x2,0x28(%rsp)` | memory | 0x2f875c | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x2f8b4a: test %rax,%rax` | memory | 0x2f8b60 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x2f8b4f: cmpq $0x3,0x10(%rax)` | memory | 0x2f8b60 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x2f8b78: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x2f8b95: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x2f8bcc: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x112a | je | mem | `0x2f8bd4: cmpq $0x0,0x8(%rsp)` | memory | 0x2f8c00 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x2f8be1: cmpl $0x0,0x18(%rax)` | memory | 0x2f8c00 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x2f8bf8: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x2f8c15: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x2f8c30: test %eax,%eax` | memory | 0x2f8a23 | back |
| RSA CRT arms | +0x118d | je | mem | `0x2f8c38: cmpl $0x3,0x28(%rsp)` | memory | 0x2f875c | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x2f69ba: test %r8,%r8` | memory | 0x2f6aeb | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x2f6ae2: dec %r8` | memory | 0x2f69d0 | back |
| DH key agreement (driver) | +0x26 | jle | reg/arith | `0x378931: cmp $0x2710,%eax` | memory | 0x378941 | fwd |
| DH key agreement (driver) | +0x39 | je | reg/arith | `0x378946: test %rdi,%rdi` | memory | 0x37896b | fwd |
| DH key agreement (driver) | +0x46 | jle | reg/arith | `0x378951: cmp $0x2710,%eax` | call+memory | 0x37896b | fwd |
| DH key agreement (driver) | +0x6b | jge | reg/arith | `0x378976: cmp $0x200,%eax` | call+memory | 0x37899c | fwd |
| DH key agreement (driver) | +0xbb | jne | mem | `0x3789c6: cmpl $0x1,0x30(%rsp)` | arithmetic/control | 0x3789d4 | fwd |
| DH key agreement (driver) | +0xe2 | je | reg/arith | `0x3789ef: test %rax,%rax` | memory | 0x378a72 | fwd |
| DH key agreement (driver) | +0x13f | je | reg/arith | `0x378a4c: test %rax,%rax` | memory | 0x378bb6 | fwd |
| DH key agreement (driver) | +0x14e | je | mem | `0x378a58: cmpq $0x0,0x78(%r12)` | memory | 0x378a8f | fwd |
| DH key agreement (driver) | +0x159 | jne | mem | `0x378a60: testb $0x1,0x80(%r12)` | arithmetic/control | 0x378abd | fwd |
| DH key agreement (driver) | +0x191 | je | reg/arith | `0x378a9e: test %rdx,%rdx` | memory | 0x378ba3 | fwd |
| DH key agreement (driver) | +0x1a4 | jae | reg/arith | `0x378ab0: cmp $0x8,%rdx` | arithmetic/control | 0x378b32 | fwd |
| DH key agreement (driver) | +0x1c5 | jne | reg/arith | `0x378ad2: test %rdx,%rdx` | memory | 0x378c0d | fwd |
| DH key agreement (driver) | +0x1d3 | je | reg/arith | `0x378adb: test %rbp,%rbp` | memory | 0x378aee | fwd |
| DH key agreement (driver) | +0x1e9 | jne | reg/arith | `0x378af6: test %rdx,%rdx` | memory | 0x378bf5 | fwd |
| DH key agreement (driver) | +0x20a | je | reg/arith | `0x378b18: test %eax,%eax` | memory | 0x378be8 | fwd |
| DH key agreement (driver) | +0x276 | jne | reg/arith | `0x378b83: cmp %rsi,%rdx` | arithmetic/control | 0x378b38 | back |
| DH key agreement (driver) | +0x27b | je | reg/arith | `0x378b88: test %rax,%rax` | memory | 0x378ba3 | fwd |
| DH key agreement (driver) | +0x291 | jne | reg/arith | `0x378b9e: cmp %rdx,%rax` | memory | 0x378b93 | back |
| DH key agreement (driver) | +0x2b1 | je | reg/arith | `0x378bb9: test %rax,%rax` | memory | 0x378bd8 | fwd |
| DH key agreement (driver) | +0x2e8 | je | reg/arith | `0x378bf5: test %rbp,%rbp` | memory | 0x378c0d | fwd |
| DH key agreement (driver) | +0x305 | je | reg/arith | `0x378c12: test %rax,%rax` | memory | 0x378c1b | fwd |
| DH key agreement (driver) | +0x30e | je | reg/arith | `0x378c1b: test %rdx,%rdx` | memory | 0x378d00 | fwd |
| DH key agreement (driver) | +0x324 | je | reg/arith | `0x378c31: test %rax,%rax` | memory | 0x378d2c | fwd |
| DH key agreement (driver) | +0x331 | je | reg/arith | `0x378c3e: test %rax,%rax` | call+memory | 0x378d2c | fwd |
| DH key agreement (driver) | +0x357 | je | reg/arith | `0x378c65: test %eax,%eax` | memory | 0x378d17 | fwd |
| DH key agreement (driver) | +0x37a | je | reg/arith | `0x378c87: test %rax,%rax` | memory | 0x378d27 | fwd |
| DH key agreement (driver) | +0x390 | je | reg/arith | `0x378c9e: test %eax,%eax` | memory | 0x378d20 | fwd |
| DH key agreement (driver) | +0x3a6 | jle | reg/arith | `0x378cb4: test %eax,%eax` | memory | 0x378d20 | fwd |
| DH key agreement (driver) | +0x3bf | je | reg/arith | `0x378cc6: test %eax,%eax` | memory | 0x378d27 | fwd |
| DH key agreement (driver) | +0x3cf | jo | reg/arith | `0x378cdc: add $0x7,%eax` | memory | 0x378dfc | fwd |
| DH key agreement (driver) | +0x422 | je | reg/arith | `0x378d2f: test %rdx,%rdx` | memory | 0x378dbc | fwd |
| DH key agreement (driver) | +0x435 | jae | reg/arith | `0x378d41: cmp $0x8,%rdx` | arithmetic/control | 0x378d4b | fwd |
| DH key agreement (driver) | +0x48f | jne | reg/arith | `0x378d9c: cmp %rsi,%rdx` | arithmetic/control | 0x378d51 | back |
| DH key agreement (driver) | +0x494 | je | reg/arith | `0x378da1: test %rax,%rax` | memory | 0x378dbc | fwd |
| DH key agreement (driver) | +0x4aa | jne | reg/arith | `0x378db7: cmp %rdx,%rax` | memory | 0x378dac | back |
| DH key agreement (driver) | +0x4ca | je | reg/arith | `0x378dd2: test %rax,%rax` | memory | 0x378df1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x39 | je | reg/arith | `0x3793bc: test %rax,%rax` | memory | 0x379479 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x53 | je | reg/arith | `0x3793e0: cmp %rsi,%rdx` | memory | 0x379479 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x62 | je | mem | `0x3793e9: cmpq $0x0,(%rcx,%rsi,1)` | memory | 0x3793e0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x6b | je | reg/arith | `0x3793f8: test %rdx,%rdx` | memory | 0x379479 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x83 | je | reg/arith | `0x379410: cmp %rsi,%rdx` | memory | 0x379479 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8e | je | mem | `0x379415: cmpq $0x0,(%rcx,%rsi,1)` | arithmetic/control | 0x379410 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x93 | je | reg/arith | `0x379420: cmp %rax,%rbp` | arithmetic/control | 0x379442 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa3 | je | reg/arith | `0x379431: test %dl,%cl` | arithmetic/control | 0x379442 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xbc | jne | reg/arith | `0x379449: or %rbp,%rcx` | memory | 0x379479 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc4 | je | reg/arith | `0x379451: cmp %rax,%rdx` | memory | 0x379521 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec | je | reg/arith | `0x379479: test %rbp,%rbp` | memory | 0x379521 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf9 | je | reg/arith | `0x379486: test %r13,%r13` | memory | 0x37954f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x118 | je | reg/arith | `0x3794a0: test %rax,%rax` | memory | 0x37956e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x123 | je | mem | `0x3794ae: cmpq $0x0,0x10(%rax)` | memory | 0x37956e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13b | je | reg/arith | `0x3794c8: test %rax,%rax` | memory | 0x379562 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x14c | jne | mem | `0x3794d8: cmp 0x0(%r13),%rcx` | memory | 0x379569 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x164 | je | reg/arith | `0x3794f2: test %esi,%esi` | memory | 0x379b79 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x171 | je | reg/arith | `0x3794fe: test %r8d,%r8d` | arithmetic/control | 0x379508 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x176 | jne | reg/arith | `0x379503: cmp %r8d,%esi` | memory | 0x379569 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x17b | jne | mem | `0x379508: cmp (%rdx),%rcx` | memory | 0x379569 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x182 | je | reg/arith | `0x379510: test %ecx,%ecx` | arithmetic/control | 0x379b82 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x18a | jne | reg/arith | `0x379518: cmp %ecx,%esi` | arithmetic/control | 0x379569 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x21b | jb | reg/arith | `0x3795a8: add %r12,%rbp` | memory | 0x37a7c9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x27b | je | reg/arith | `0x379607: cmp $0xffffffffffffffff,%rbp` | call+memory | 0x37a7d2 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2c1 | je | reg/arith | `0x37964e: test %r13,%r13` | memory | 0x3797ce | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2d7 | je | reg/arith | `0x379664: test %rdi,%rdi` | arithmetic/control | 0x37982d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2e0 | je | reg/arith | `0x37966d: test %r14,%r14` | arithmetic/control | 0x37982d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2e9 | je | reg/arith | `0x379676: test %r12,%r12` | memory | 0x37982d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x2fc | jb | mem | `0x379687: add 0x50(%rsp),%rbx` | memory | 0x37a7db | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x319 | je | unknown | `?` | memory | 0x379920 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x34a | jae | mem | `0x3796d5: cmp 0x50(%rsp),%rbp` | memory | 0x3796e5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x365 | ja | reg/arith | `0x3796f0: cmp $0x7cf,%eax` | arithmetic/control | 0x379730 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x371 | ja | reg/arith | `0x3796fc: cmp $0x31f,%eax` | arithmetic/control | 0x379730 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x37d | ja | reg/arith | `0x379708: cmp $0x12b,%eax` | arithmetic/control | 0x379730 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x387 | ja | reg/arith | `0x379714: cmp $0x45,%eax` | memory | 0x379730 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3b6 | jb | reg/arith | `0x379743: add %rax,%r15` | memory | 0x37a7f0 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x3cf | jae | mem | `0x37975a: cmp 0x50(%rsp),%rbp` | call+memory | 0x37976a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x400 | je | reg/arith | `0x37978d: test %rax,%rax` | memory | 0x3799eb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x420 | jne | reg/arith | `0x3797a8: dec %rbx` | memory | 0x3796d0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x433 | jne | reg/arith | `0x3797bb: test %rbx,%rbx` | arithmetic/control | 0x379939 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x446 | je | reg/arith | `0x3797d3: test %rdi,%rdi` | call+memory | 0x3797fb | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x46e | je | reg/arith | `0x3797fb: test %r14,%r14` | memory | 0x3798ea | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4a0 | je | reg/arith | `0x37982d: test %rdi,%rdi` | call+memory | 0x379855 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4c8 | je | reg/arith | `0x379855: test %r14,%r14` | call+memory | 0x379880 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x4f7 | je | reg/arith | `0x379884: test %rdi,%rdi` | memory | 0x3798c4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x532 | jne | reg/arith | `0x3798bf: test %rdi,%rdi` | call+memory | 0x3798a0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x55f | je | reg/arith | `0x3798ec: test %r12,%r12` | call+memory | 0x37a160 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5a3 | je | reg/arith | `0x37992b: test %rbx,%rbx` | memory | 0x379db3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5b1 | je | reg/arith | `0x37993e: test %rax,%rax` | memory | 0x379aae | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x5c8 | je | mem | `0x379953: cmpb $0x0,0x78(%rsp)` | call+memory | 0x379ae1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x600 | je | reg/arith | `0x379985: test %rax,%rax` | memory | 0x379ac8 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x611 | jbe | reg/arith | `0x37999e: cmp %r14,%rsi` | arithmetic/control | 0x379be5 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x61d | jo | reg/arith | `0x3799aa: mul %rcx` | memory | 0x37a7fd | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x62f | jae | reg/arith | `0x3799bc: cmp %rax,%rsi` | arithmetic/control | 0x379c8c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x638 | je | reg/arith | `0x3799c5: test %rcx,%rcx` | arithmetic/control | 0x37a80f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x648 | je | reg/arith | `0x3799d4: shr $0x20,%rax` | division | 0x379c29 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6af | je | reg/arith | `0x379a3c: test %rdi,%rdi` | call+memory | 0x379a74 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x6e2 | jne | reg/arith | `0x379a6f: test %rdi,%rdi` | call+memory | 0x379a50 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x726 | jne | mem | `0x379aae: cmpb $0x0,0x90(%rsp)` | call+memory | 0x379db3 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7ac | je | reg/arith | `0x379b39: test %rdi,%rdi` | call+memory | 0x379fd4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x7e2 | jne | reg/arith | `0x379b6f: test %rdi,%rdi` | arithmetic/control | 0x379b50 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x7ec | jne | mem | `0x379b79: cmp (%rdx),%rcx` | call+memory | 0x379569 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x801 | jne | reg/arith | `0x379b8f: test %eax,%eax` | memory | 0x37956e | back |
| EC wNAF multiply (verification / public-scalar core) | +0x82c | je | reg/arith | `0x379bb9: test %rsi,%rsi` | arithmetic/control | 0x37a818 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x83f | je | reg/arith | `0x379bcb: shr $0x20,%rdx` | division | 0x37a495 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x85e | je | reg/arith | `0x379bea: cmp $0xffffffffffffffff,%rcx` | memory | 0x37a806 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8b0 | jbe | mem | `0x379c3c: cmp 0x10(%rdx),%rax` | call+memory | 0x379c79 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x8f6 | jb | mem | `0x379c79: add 0x50(%rsp),%rax` | memory | 0x37a871 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x90c | jae | reg/arith | `0x379c99: cmp %rax,%rbx` | memory | 0x379d83 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x937 | jae | mem | `0x379cbd: cmp 0x38(%rsp),%rbx` | memory | 0x379ce7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x945 | jb | reg/arith | `0x379cd2: sub %rcx,%rsi` | memory | 0x37a51d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x98d | je | reg/arith | `0x379d1a: test %rax,%rax` | memory | 0x37a3ea | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x9ad | je | mem | `0x379d39: cmpq $0x0,(%rdi)` | memory | 0x37a435 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x9ed | jne | mem | `0x379d6b: cmp %rbx,0x80(%rsp)` | call+memory | 0x379cbd | back |
| EC wNAF multiply (verification / public-scalar core) | +0xa27 | je | reg/arith | `0x379db3: cmp $0xffffffffffffffff,%r15` | memory | 0x37a7e4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa4b | je | reg/arith | `0x379dd8: test %rax,%rax` | memory | 0x379f49 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xa6d | je | mem | `0x379dec: cmpq $0x0,0x88(%rsp)` | memory | 0x379f0a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xaa0 | je | reg/arith | `0x379e2d: test %rcx,%rcx` | memory | 0x37a83c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xaac | je | mem | `0x379e36: cmpq $0x0,0x40(%rsp)` | memory | 0x37a3ca | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xac4 | ja | reg/arith | `0x379e50: cmp $0x40,%rcx` | arithmetic/control | 0x37a855 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xad5 | jne | reg/arith | `0x379e62: test %rax,%rax` | memory | 0x379eef | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xae8 | je | mem | `0x379e73: cmpq $0x0,0x50(%rax)` | memory | 0x37a02b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb08 | je | reg/arith | `0x379e95: test %rax,%rax` | memory | 0x37a01f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb2a | je | reg/arith | `0x379eb7: test %rax,%rax` | call | 0x379ff9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb37 | je | reg/arith | `0x379ec5: test %eax,%eax` | memory | 0x379ff9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xb54 | jne | reg/arith | `0x379ee1: test %rcx,%rcx` | arithmetic/control | 0x379e50 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xb74 | jne | mem | `0x379ef2: cmp 0x88(%rsp),%rbx` | memory | 0x379e20 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xb84 | je | reg/arith | `0x379f0e: cmp %rax,%r13` | call+memory | 0x37a174 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc08 | je | reg/arith | `0x379f95: test %rdi,%rdi` | call+memory | 0x379fd4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xc42 | jne | reg/arith | `0x379fcf: test %rdi,%rdi` | memory | 0x379fb0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xd0b | je | reg/arith | `0x37a098: test %rdi,%rdi` | call+memory | 0x37a0d4 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd42 | jne | reg/arith | `0x37a0cf: test %rdi,%rdi` | call+memory | 0x37a0b0 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xd6e | je | reg/arith | `0x37a0fb: test %rdi,%rdi` | call+memory | 0x37a11f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xd8d | jne | reg/arith | `0x37a11a: test %rdi,%rdi` | call+memory | 0x37a110 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xdf2 | je | reg/arith | `0x37a17f: test %rax,%rax` | memory | 0x37a32c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe08 | je | reg/arith | `0x37a195: test %r13,%r13` | memory | 0x37a347 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe35 | je | reg/arith | `0x37a1bd: cmp %r13,%rbp` | memory | 0x37a347 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe47 | jae | mem | `0x37a1d2: cmp 0x50(%rsp),%rbp` | memory | 0x37a1e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe67 | je | reg/arith | `0x37a1f5: test %eax,%eax` | memory | 0x37a476 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xe77 | jbe | mem | `0x37a202: cmpq $0x1,(%rax,%rbp,8)` | memory | 0x37a1ba | back |
| EC wNAF multiply (verification / public-scalar core) | +0xe97 | je | reg/arith | `0x37a225: test %eax,%eax` | memory | 0x37a3a9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xea9 | je | reg/arith | `0x37a236: test %rcx,%rcx` | arithmetic/control | 0x37a83c | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xeb8 | ja | reg/arith | `0x37a244: cmp $0x40,%rcx` | arithmetic/control | 0x37a855 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xec9 | jne | reg/arith | `0x37a256: test %rax,%rax` | memory | 0x37a1ba | back |
| EC wNAF multiply (verification / public-scalar core) | +0xee1 | je | reg/arith | `0x37a26e: test %rax,%rax` | memory | 0x37a58f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xef2 | jne | mem | `0x37a27f: cmp (%rsi),%r9` | memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf07 | je | reg/arith | `0x37a295: test %edi,%edi` | memory | 0x37a2e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf10 | je | reg/arith | `0x37a29d: test %r8d,%r8d` | arithmetic/control | 0x37a2ab | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf15 | jne | reg/arith | `0x37a2a2: cmp %r8d,%edi` | memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf1e | jne | mem | `0x37a2ab: cmp (%rdx),%r9` | memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf2b | je | reg/arith | `0x37a2b8: test %r8d,%r8d` | arithmetic/control | 0x37a2c6 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf30 | jne | reg/arith | `0x37a2bd: cmp %r8d,%edi` | memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf3e | jne | mem | `0x37a2cb: cmp (%rcx),%r9` | memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf4b | je | reg/arith | `0x37a2d8: test %r8d,%r8d` | arithmetic/control | 0x37a2fe | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf50 | je | reg/arith | `0x37a2dd: cmp %r8d,%edi` | arithmetic/control | 0x37a2fe | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf5a | jne | mem | `0x37a2e7: cmp (%rdx),%r9` | memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf68 | jne | mem | `0x37a2f5: cmp (%rcx),%r9` | call+memory | 0x37a39d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf7c | je | reg/arith | `0x37a30a: test %eax,%eax` | memory | 0x37a3a9 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xf91 | jne | reg/arith | `0x37a31e: test %rcx,%rcx` | arithmetic/control | 0x37a244 | back |
| EC wNAF multiply (verification / public-scalar core) | +0xfc9 | je | reg/arith | `0x37a356: test %rax,%rax` | call+memory | 0x37a476 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0xfee | je | reg/arith | `0x37a372: test %eax,%eax` | memory | 0x37a57a | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1000 | jbe | reg/arith | `0x37a384: cmp $0x7fffffff,%r14` | memory | 0x37a59b | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x103e | jae | reg/arith | `0x37a3ca: cmp $0x41,%rcx` | memory | 0x37a855 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1114 | je | reg/arith | `0x37a4a0: cmp $0xffffffffffffffff,%rdi` | memory | 0x37a827 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1133 | jb | reg/arith | `0x37a4bf: sub $0x1,%rcx` | arithmetic/control | 0x37a830 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x113d | jae | reg/arith | `0x37a4c9: cmp $0x41,%rdx` | memory | 0x37a849 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1153 | jo | reg/arith | `0x37a4e0: mul %rdx` | memory | 0x37a862 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1162 | jne | mem | `0x37a4ee: cmp %rax,0x28(%rcx)` | memory | 0x37a511 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x120e | je | reg/arith | `0x37a59b: test %r14,%r14` | arithmetic/control | 0x37a87d | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x122e | jle | mem | `0x37a5af: cmpl $0x1,0x50(%rsp)` | arithmetic/control | 0x37a73f | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1237 | jne | reg/arith | `0x37a5c4: test %r13d,%r13d` | memory | 0x37a5e7 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1251 | je | reg/arith | `0x37a5df: test %eax,%eax` | memory | 0x37a3a9 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1268 | je | mem | `0x37a5ef: cmpq $0x0,0x80(%rsp)` | arithmetic/control | 0x37a5af | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1294 | je | reg/arith | `0x37a61d: test %eax,%eax` | memory | 0x37a729 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12a5 | je | mem | `0x37a62d: cmp %r12,0x80(%rsp)` | memory | 0x37a5af | back |
| EC wNAF multiply (verification / public-scalar core) | +0x12b4 | jbe | mem | `0x37a640: cmp %rbp,(%rax,%r12,8)` | memory | 0x37a62a | back |
| EC wNAF multiply (verification / public-scalar core) | +0x12c5 | je | reg/arith | `0x37a653: test %ebx,%ebx` | arithmetic/control | 0x37a62a | back |
| EC wNAF multiply (verification / public-scalar core) | +0x12cf | je | reg/arith | `0x37a65c: cmp %eax,%r15d` | arithmetic/control | 0x37a68e | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12d4 | jne | reg/arith | `0x37a661: test %r13d,%r13d` | memory | 0x37a683 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x12ed | je | reg/arith | `0x37a67b: test %eax,%eax` | memory | 0x37a7a1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x131c | je | reg/arith | `0x37a6a9: test %r13d,%r13d` | memory | 0x37a602 | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1337 | je | reg/arith | `0x37a6c0: test %eax,%eax` | memory | 0x37a7a1 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x1352 | je | reg/arith | `0x37a6da: test %rax,%rax` | call+memory | 0x37a62a | back |
| EC wNAF multiply (verification / public-scalar core) | +0x1366 | jne | reg/arith | `0x37a6f4: test %eax,%eax` | call+memory | 0x37a62a | back |
| EC wNAF multiply (verification / public-scalar core) | +0x13b2 | je | reg/arith | `0x37a73f: test %r13d,%r13d` | memory | 0x37a756 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13c9 | je | reg/arith | `0x37a756: test %r15d,%r15d` | memory | 0x37a774 | fwd |
| EC wNAF multiply (verification / public-scalar core) | +0x13e2 | je | reg/arith | `0x37a770: test %eax,%eax` | call+memory | 0x37a7a1 | fwd |
| ML-KEM decapsulation (provider driver) | +0x7 | je | mem | `0x2fd5c2: cmpq $0x0,0x50(%r8)` | arithmetic/control | 0x2fd793 | fwd |
| ML-KEM decapsulation (provider driver) | +0x1f | jne | reg/arith | `0x2fd5dc: or %r9b,%r10b` | memory | 0x2fd793 | fwd |
| ML-KEM decapsulation (provider driver) | +0x5c | jne | reg/arith | `0x2fd619: or %al,%sil` | memory | 0x2fd76a | fwd |
| ML-KEM decapsulation (provider driver) | +0x66 | jne | mem | `0x2fd622: cmp 0x28(%r15),%rcx` | memory | 0x2fd76a | fwd |
| ML-KEM decapsulation (provider driver) | +0x8f | je | reg/arith | `0x2fd64c: test %rax,%rax` | memory | 0x2fd76a | fwd |
| ML-KEM decapsulation (provider driver) | +0xa2 | je | reg/arith | `0x2fd65c: cmp $0x5ae,%ecx` | arithmetic/control | 0x2fd87a | fwd |
| ML-KEM decapsulation (provider driver) | +0xae | je | reg/arith | `0x2fd668: cmp $0x5af,%ecx` | arithmetic/control | 0x2fd794 | fwd |
| ML-KEM decapsulation (provider driver) | +0xbc | jne | reg/arith | `0x2fd676: cmp $0x5b0,%ecx` | call+memory | 0x2fd965 | fwd |
| ML-KEM decapsulation (provider driver) | +0x163 | jne | reg/arith | `0x2fd71c: cmp $0x1000,%r15` | memory | 0x2fd6d0 | back |
| ML-KEM decapsulation (provider driver) | +0x1a3 | jne | reg/arith | `0x2fd75c: cmp $0x627,%rcx` | arithmetic/control | 0x2fd730 | back |
| ML-KEM decapsulation (provider driver) | +0x26b | jne | reg/arith | `0x2fd824: cmp $0xc07,%rcx` | memory | 0x2fd7e0 | back |
| ML-KEM decapsulation (provider driver) | +0x2b3 | jne | reg/arith | `0x2fd86c: cmp $0x447,%rcx` | arithmetic/control | 0x2fd840 | back |
| ML-KEM decapsulation (provider driver) | +0x363 | jne | reg/arith | `0x2fd91c: cmp $0x800,%r15` | memory | 0x2fd8d0 | back |
| ML-KEM decapsulation (provider driver) | +0x3a3 | jne | reg/arith | `0x2fd95c: cmp $0x307,%rcx` | arithmetic/control | 0x2fd930 | back |
| ML-KEM decapsulation (provider driver) | +0x3a8 | jne | reg/arith | `0x2fd965: test $0x7,%bl` | memory | 0x2fd782 | back |
| ML-KEM K-PKE decrypt | +0x65 | js | reg/arith | `0x3845d2: test %r14,%r14` | memory | 0x384f9b | fwd |
| ML-KEM K-PKE decrypt | +0x70 | jle | reg/arith | `0x3845de: test %ebp,%ebp` | arithmetic/control | 0x3847f5 | fwd |
| ML-KEM K-PKE decrypt | +0x84 | ja | reg/arith | `0x3845f0: cmp $0xf,%r14d` | memory | 0x384f8e | fwd |
| ML-KEM K-PKE decrypt | +0x9f | jae | reg/arith | `0x384607: cmp $0x20,%eax` | memory | 0x384fa8 | fwd |
| ML-KEM K-PKE decrypt | +0x140 | jae | reg/arith | `0x3846a9: cmp $0x100,%rdx` | arithmetic/control | 0x38474b | fwd |
| ML-KEM K-PKE decrypt | +0x148 | jne | reg/arith | `0x3846b6: test %ecx,%ecx` | memory | 0x3846c6 | fwd |
| ML-KEM K-PKE decrypt | +0x169 | je | reg/arith | `0x3846d6: test %bl,%r11b` | memory | 0x384700 | fwd |
| ML-KEM K-PKE decrypt | +0x18b | jb | reg/arith | `0x3846f4: cmp $0x100,%rdx` | arithmetic/control | 0x3846b6 | back |
| ML-KEM K-PKE decrypt | +0x196 | jb | reg/arith | `0x384703: sub %eax,%r10d` | arithmetic/control | 0x384690 | back |
| ML-KEM K-PKE decrypt | +0x19d | jb | reg/arith | `0x38470b: sub %eax,%ecx` | arithmetic/control | 0x385093 | fwd |
| ML-KEM K-PKE decrypt | +0x1a6 | ja | reg/arith | `0x384713: cmp $0xf,%ecx` | memory | 0x385086 | fwd |
| ML-KEM K-PKE decrypt | +0x1d5 | jb | reg/arith | `0x38473e: cmp $0x100,%rdx` | memory | 0x3846b6 | back |
| ML-KEM K-PKE decrypt | +0x24e | jne | reg/arith | `0x3847b8: cmp $0x100,%rax` | call | 0x384750 | back |
| ML-KEM K-PKE decrypt | +0x27f | jg | reg/arith | `0x3847ec: dec %r13d` | memory | 0x384670 | back |
| ML-KEM K-PKE decrypt | +0x28e | ja | reg/arith | `0x3847fa: cmp $0xf,%r15d` | memory | 0x384f8e | fwd |
| ML-KEM K-PKE decrypt | +0x2ef | jbe | reg/arith | `0x384858: cmp $0xff,%rsi` | arithmetic/control | 0x384892 | fwd |
| ML-KEM K-PKE decrypt | +0x320 | ja | reg/arith | `0x384889: cmp $0xff,%rsi` | arithmetic/control | 0x3848f2 | fwd |
| ML-KEM K-PKE decrypt | +0x324 | jne | reg/arith | `0x384892: test %ecx,%ecx` | memory | 0x3848a2 | fwd |
| ML-KEM K-PKE decrypt | +0x345 | jne | reg/arith | `0x3848b2: test %bl,%r11b` | arithmetic/control | 0x384870 | back |
| ML-KEM K-PKE decrypt | +0x34d | jb | reg/arith | `0x3848ba: sub %eax,%r10d` | arithmetic/control | 0x384840 | back |
| ML-KEM K-PKE decrypt | +0x354 | jb | reg/arith | `0x3848c2: sub %eax,%ecx` | arithmetic/control | 0x385093 | fwd |
| ML-KEM K-PKE decrypt | +0x35d | jae | reg/arith | `0x3848ca: cmp $0x10,%ecx` | memory | 0x385086 | fwd |
| ML-KEM K-PKE decrypt | +0x389 | ja | reg/arith | `0x3848f6: cmp $0x1f,%eax` | memory | 0x385079 | fwd |
| ML-KEM K-PKE decrypt | +0x43e | jne | reg/arith | `0x3849a8: cmp $0x100,%rax` | call+memory | 0x384940 | back |
| ML-KEM K-PKE decrypt | +0x4fc | jne | reg/arith | `0x384a66: cmp $0x100,%rax` | memory | 0x3849f0 | back |
| ML-KEM K-PKE decrypt | +0x614 | jne | reg/arith | `0x384b7e: cmp $0x100,%rax` | memory | 0x384ab0 | back |
| ML-KEM K-PKE decrypt | +0x96b | jne | reg/arith | `0x384ed7: cmp $0x20,%rcx` | memory | 0x384be0 | back |
| ML-KEM K-PKE decrypt | +0x9b2 | jne | reg/arith | `0x384f1c: cmp $0x200,%rax` | memory | 0x384ef0 | back |
| ML-KEM K-PKE decrypt | +0xa0a | jne | reg/arith | `0x384f74: cmp $0x200,%rax` | arithmetic/control | 0x384f30 | back |
| ML-KEM K-PKE decrypt | +0xa66 | ja | reg/arith | `0x384fcf: cmp $0xff,%rdx` | arithmetic/control | 0x385079 | fwd |
| ML-KEM K-PKE decrypt | +0xa6e | jne | reg/arith | `0x384fdc: test %ecx,%ecx` | memory | 0x384fec | fwd |
| ML-KEM K-PKE decrypt | +0xa90 | je | reg/arith | `0x384ffd: test %r11b,%r10b` | memory | 0x385030 | fwd |
| ML-KEM K-PKE decrypt | +0xab5 | jbe | reg/arith | `0x38501e: cmp $0xff,%rdx` | arithmetic/control | 0x384fdc | back |
| ML-KEM K-PKE decrypt | +0xac6 | jb | reg/arith | `0x385033: sub %eax,%r9d` | arithmetic/control | 0x384fb7 | back |
| ML-KEM K-PKE decrypt | +0xad1 | jb | reg/arith | `0x38503f: sub %eax,%ecx` | arithmetic/control | 0x385093 | fwd |
| ML-KEM K-PKE decrypt | +0xad6 | jae | reg/arith | `0x385043: cmp $0x10,%ecx` | memory | 0x385086 | fwd |
| ML-KEM K-PKE decrypt | +0xb03 | jbe | reg/arith | `0x38506c: cmp $0xff,%rdx` | memory | 0x384fdc | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xc3 | jle | reg/arith | `0x385150: test %r12,%r12` | call+memory | 0x3851c4 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x103 | je | reg/arith | `0x3851a1: test %eax,%eax` | call | 0x3870b8 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x120 | jg | reg/arith | `0x3851bd: cmp $0x1,%ebp` | arithmetic/control | 0x385180 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x237 | jle | reg/arith | `0x3852c4: test %r14d,%r14d` | memory | 0x38603d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x47e | jle | reg/arith | `0x38550f: cmp $0x1,%r12d` | memory | 0x385e2b | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x528 | je | reg/arith | `0x3855bc: test $0x1,%sil` | memory | 0x3856b0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x603 | jne | reg/arith | `0x38569c: cmp $0x100,%rcx` | arithmetic/control | 0x3855d0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x856 | jne | reg/arith | `0x3858ef: cmp $0x100,%rdx` | memory | 0x3856c0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x867 | je | reg/arith | `0x385904: cmp $0x1,%edx` | memory | 0x3854b0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xa04 | jle | reg/arith | `0x385a9e: cmp $0x2,%edx` | arithmetic/control | 0x3854b0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xa0e | je | reg/arith | `0x385aac: test $0x1,%al` | memory | 0x385bc0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xb11 | jne | reg/arith | `0x385baa: cmp $0x100,%rsi` | arithmetic/control | 0x385ac0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xd80 | jne | reg/arith | `0x385e19: cmp $0x100,%rsi` | arithmetic/control | 0x385bc0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xe57 | je | reg/arith | `0x385ef5: test %eax,%eax` | memory | 0x385fd5 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf2f | jne | reg/arith | `0x385fc8: cmp $0x80,%rcx` | memory | 0x385f00 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf83 | jne | reg/arith | `0x38601c: cmp $0x80,%rcx` | arithmetic/control | 0x385ff0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf87 | je | reg/arith | `0x386025: test %eax,%eax` | arithmetic/control | 0x387165 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0xf97 | jg | reg/arith | `0x386034: dec %r14d` | memory | 0x385e70 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x10b2 | je | reg/arith | `0x386150: test %al,%al` | memory | 0x3861e0 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x112b | jne | reg/arith | `0x3861c4: cmp $0x101,%r8` | arithmetic/control | 0x386160 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11d5 | jne | reg/arith | `0x38626e: cmp $0x108,%r9` | arithmetic/control | 0x386200 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11d9 | jo | reg/arith | `0x386277: dec %edx` | arithmetic/control | 0x38731f | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x11ef | jg | reg/arith | `0x38628d: test %edx,%edx` | memory | 0x386150 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1206 | ja | reg/arith | `0x3862a3: cmp $0x1f,%ecx` | memory | 0x38736d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13b9 | jne | reg/arith | `0x386452: cmp $0x100,%rdx` | arithmetic/control | 0x386310 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13c1 | jo | reg/arith | `0x38645f: dec %eax` | arithmetic/control | 0x38732c | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x13d0 | jg | reg/arith | `0x38646e: test %eax,%eax` | call | 0x386300 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x147f | je | reg/arith | `0x38651d: test %eax,%eax` | memory | 0x386614 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x156e | jne | reg/arith | `0x386607: cmp $0x80,%rcx` | memory | 0x386540 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15c3 | jne | reg/arith | `0x38665c: cmp $0x80,%rcx` | arithmetic/control | 0x386630 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x15c7 | je | reg/arith | `0x386665: test %eax,%eax` | memory | 0x387212 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x165f | jne | reg/arith | `0x3866f9: cmp $0x100,%rax` | memory | 0x386680 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dc8 | jne | reg/arith | `0x386e64: cmp $0x20,%rax` | arithmetic/control | 0x386710 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1dd1 | ja | reg/arith | `0x386e6e: cmp $0x1f,%ebx` | arithmetic/control | 0x38736d | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1f70 | jne | reg/arith | `0x38700a: cmp $0x100,%rax` | memory | 0x386ec0 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fa2 | je | reg/arith | `0x38703c: cmp $0x200,%rax` | arithmetic/control | 0x3870ae | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fa8 | jb | reg/arith | `0x387046: add %ebx,%esi` | memory | 0x387339 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fb9 | jb | reg/arith | `0x387056: cmp $0x40,%esi` | arithmetic/control | 0x387030 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fbb | jne | unknown | `?` | arithmetic/control | 0x387080 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fc0 | jae | reg/arith | `0x38705d: cmp $0x40,%ecx` | memory | 0x387360 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1fe3 | jae | reg/arith | `0x387080: cmp $0x40,%ecx` | memory | 0x387346 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x1ff7 | je | reg/arith | `0x387095: test %ecx,%ecx` | arithmetic/control | 0x387353 | fwd |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x216c | je | reg/arith | `0x387209: test %r14d,%r14d` | memory | 0x3860e1 | back |
| ML-KEM K-PKE encrypt (re-encryption / implicit reject) | +0x226b | jne | reg/arith | `0x387304: cmp $0x200,%rcx` | arithmetic/control | 0x3872c0 | back |
| ML-KEM inverse NTT | +0x56 | jb | reg/arith | `0x388303: add %rsi,%rbx` | memory | 0x3887e4 | fwd |
| ML-KEM inverse NTT | +0x64 | ja | reg/arith | `0x388310: cmp $0x7e,%r8` | memory | 0x3887f1 | fwd |
| ML-KEM inverse NTT | +0xb8 | jbe | reg/arith | `0x388364: cmp $0x7,%r8` | memory | 0x3883bf | fwd |
| ML-KEM inverse NTT | +0x101 | jae | reg/arith | `0x3883ae: cmp %r13,%r14` | memory | 0x3883d0 | fwd |
| ML-KEM inverse NTT | +0x10d | jae | reg/arith | `0x3883ba: cmp %r12,%r15` | arithmetic/control | 0x3883d0 | fwd |
| ML-KEM inverse NTT | +0x2fa | jne | reg/arith | `0x3885a7: cmp %r13,%r8` | memory | 0x388400 | back |
| ML-KEM inverse NTT | +0x317 | ja | reg/arith | `0x3885c0: cmp $0xff,%r8` | arithmetic/control | 0x3887cf | fwd |
| ML-KEM inverse NTT | +0x324 | jae | reg/arith | `0x3885cd: cmp $0x100,%rcx` | memory | 0x3887ba | fwd |
| ML-KEM inverse NTT | +0x3b4 | jb | reg/arith | `0x388661: cmp %rbx,%r8` | arithmetic/control | 0x3885c0 | back |
| ML-KEM inverse NTT | +0x3c4 | jne | reg/arith | `0x38866d: cmp $0x100,%rcx` | arithmetic/control | 0x388300 | back |
| ML-KEM inverse NTT | +0x3d4 | jb | reg/arith | `0x38867d: cmp $0x100,%rsi` | memory | 0x3882f0 | back |
| ML-KEM inverse NTT | +0x4f5 | jne | reg/arith | `0x38879f: cmp $0x100,%rax` | arithmetic/control | 0x3886a0 | back |
| ML-KEM inner product | +0x5b | jne | reg/arith | `0x387548: test %r12b,%r15b` | arithmetic/control | 0x3877fb | fwd |
| ML-KEM inner product | +0x64 | jne | reg/arith | `0x387551: and %bpl,%r8b` | arithmetic/control | 0x3877fb | fwd |
| ML-KEM inner product | +0x6d | jne | reg/arith | `0x38755a: and %r14b,%r10b` | memory | 0x3877fb | fwd |
| ML-KEM inner product | +0x300 | jne | reg/arith | `0x3877e9: cmp $0x100,%r8` | arithmetic/control | 0x387590 | back |
| ML-KEM inner product | +0x3fa | jne | reg/arith | `0x3878e3: cmp $0x100,%r14` | arithmetic/control | 0x387810 | back |
| ML-KEM inner product | +0x406 | jo | reg/arith | `0x3878f3: dec %r8d` | arithmetic/control | 0x387d84 | fwd |
| ML-KEM inner product | +0x40f | jle | reg/arith | `0x3878fc: test %r8d,%r8d` | memory | 0x387d75 | fwd |
| ML-KEM inner product | +0x4c1 | jle | reg/arith | `0x3879ae: dec %r8d` | arithmetic/control | 0x387d75 | fwd |
| ML-KEM inner product | +0x4cc | je | reg/arith | `0x3879ba: test %cl,%cl` | memory | 0x387ae0 | fwd |
| ML-KEM inner product | +0x5dc | jne | reg/arith | `0x387ac5: cmp $0x100,%r10` | arithmetic/control | 0x3879d0 | back |
| ML-KEM inner product | +0x87a | jne | reg/arith | `0x387d63: cmp $0x100,%r10` | arithmetic/control | 0x387ae0 | back |
| ML-KEM matrix transpose-multiply-add | +0x1b | jle | reg/arith | `0x388829: test %ecx,%ecx` | memory | 0x38918c | fwd |
| ML-KEM matrix transpose-multiply-add | +0x16f | jle | reg/arith | `0x388971: cmp $0x1,%eax` | memory | 0x38918c | fwd |
| ML-KEM matrix transpose-multiply-add | +0x17f | je | mem | `0x38898a: cmpb $0x0,-0x62(%rsp)` | memory | 0x388a90 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x26e | jne | reg/arith | `0x388a77: cmp $0x100,%r11` | arithmetic/control | 0x3889a0 | back |
| ML-KEM matrix transpose-multiply-add | +0x510 | jne | reg/arith | `0x388d1a: cmp $0x100,%rax` | memory | 0x388aa0 | back |
| ML-KEM matrix transpose-multiply-add | +0x51b | je | mem | `0x388d26: cmpl $0x1,-0x60(%rsp)` | memory | 0x388950 | back |
| ML-KEM matrix transpose-multiply-add | +0x5c7 | jle | reg/arith | `0x388dcc: cmp $0x2,%r9d` | memory | 0x388950 | back |
| ML-KEM matrix transpose-multiply-add | +0x5d2 | je | mem | `0x388ddd: cmpb $0x0,-0x61(%rsp)` | memory | 0x388ef0 | fwd |
| ML-KEM matrix transpose-multiply-add | +0x6d1 | jne | reg/arith | `0x388eda: cmp $0x100,%rbp` | arithmetic/control | 0x388df0 | back |
| ML-KEM matrix transpose-multiply-add | +0x971 | jne | reg/arith | `0x38917a: cmp $0x100,%rbp` | arithmetic/control | 0x388f00 | back |
| ML-KEM matrix expansion (public) | +0x3f | jle | reg/arith | `0x387ddd: test %ecx,%ecx` | memory | 0x387fa1 | fwd |
| ML-KEM matrix expansion (public) | +0x6c | je | mem | `0x387e07: cmp 0x4(%rsp),%r14d` | call+memory | 0x387f92 | fwd |
| ML-KEM matrix expansion (public) | +0x92 | je | reg/arith | `0x387e30: test %eax,%eax` | memory | 0x387fc7 | fwd |
| ML-KEM matrix expansion (public) | +0xad | je | reg/arith | `0x387e4b: test %eax,%eax` | memory | 0x387fc7 | fwd |
| ML-KEM matrix expansion (public) | +0x116 | je | reg/arith | `0x387eb3: test %rax,%rax` | memory | 0x387fa9 | fwd |
| ML-KEM matrix expansion (public) | +0x121 | je | mem | `0x387ebc: cmpq $0x0,0x70(%rax)` | memory | 0x387fb2 | fwd |
| ML-KEM matrix expansion (public) | +0x131 | je | reg/arith | `0x387ece: test %rax,%rax` | memory | 0x387fbb | fwd |
| ML-KEM matrix expansion (public) | +0x13e | je | reg/arith | `0x387edb: test %rdi,%rdi` | call+memory | 0x387fc7 | fwd |
| ML-KEM matrix expansion (public) | +0x160 | je | reg/arith | `0x387efe: test %eax,%eax` | arithmetic/control | 0x387fc7 | fwd |
| ML-KEM matrix expansion (public) | +0x17a | je | reg/arith | `0x387f14: cmp $0xaa,%rax` | arithmetic/control | 0x387f80 | fwd |
| ML-KEM matrix expansion (public) | +0x183 | ja | reg/arith | `0x387f1c: cmp $0xff,%r13` | memory | 0x387e00 | back |
| ML-KEM matrix expansion (public) | +0x1a9 | ja | reg/arith | `0x387f43: cmp $0xd00,%esi` | memory | 0x387f60 | fwd |
| ML-KEM matrix expansion (public) | +0x1b7 | je | reg/arith | `0x387f50: cmp $0xff,%r13` | arithmetic/control | 0x387e00 | back |
| ML-KEM matrix expansion (public) | +0x1d4 | ja | reg/arith | `0x387f6e: cmp $0xd00,%ecx` | memory | 0x387f10 | back |
| ML-KEM matrix expansion (public) | +0x1e7 | jb | reg/arith | `0x387f80: cmp $0x100,%r13` | arithmetic/control | 0x387eaf | back |
| ML-KEM matrix expansion (public) | +0x1fb | jne | mem | `0x387f97: cmp 0x4(%rsp),%ebp` | arithmetic/control | 0x387dea | back |
| ML-KEM vector decode 12-bit | +0x2 | jle | reg/arith | `0x3880e0: test %edx,%edx` | memory | 0x388162 | fwd |
| ML-KEM vector decode 12-bit | +0x17 | je | reg/arith | `0x3880f0: cmp $0x80,%rcx` | memory | 0x388150 | fwd |
| ML-KEM vector decode 12-bit | +0x54 | ja | reg/arith | `0x38812d: cmp $0xd00,%r11d` | arithmetic/control | 0x388167 | fwd |
| ML-KEM vector decode 12-bit | +0x68 | jb | reg/arith | `0x388141: cmp $0xd01,%r9d` | arithmetic/control | 0x3880f0 | back |
| ML-KEM vector decode 12-bit | +0x80 | jg | reg/arith | `0x38815e: dec %edx` | arithmetic/control | 0x3880e4 | back |
| ML-KEM vector encode | +0x7 | js | reg/arith | `0x387ff5: test %edx,%edx` | arithmetic/control | 0x3880d0 | fwd |
| ML-KEM vector encode | +0x11 | jle | reg/arith | `0x387fff: test %ecx,%ecx` | arithmetic/control | 0x388096 | fwd |
| ML-KEM vector encode | +0x2c | jle | reg/arith | `0x38801a: dec %eax` | arithmetic/control | 0x388096 | fwd |
| ML-KEM vector encode | +0x53 | je | reg/arith | `0x38803c: cmp $0x200,%r10` | arithmetic/control | 0x388010 | back |
| ML-KEM vector encode | +0x59 | jb | reg/arith | `0x388047: add %edx,%ebx` | memory | 0x38809c | fwd |
| ML-KEM vector encode | +0x63 | jb | reg/arith | `0x388050: cmp $0x40,%ebx` | arithmetic/control | 0x388030 | back |
| ML-KEM vector encode | +0x65 | jne | unknown | `?` | arithmetic/control | 0x388070 | fwd |
| ML-KEM vector encode | +0x6a | jae | reg/arith | `0x388057: cmp $0x40,%ecx` | memory | 0x3880c3 | fwd |
| ML-KEM vector encode | +0x83 | jae | reg/arith | `0x388070: cmp $0x40,%ecx` | memory | 0x3880a9 | fwd |
| ML-KEM vector encode | +0x93 | je | reg/arith | `0x388081: test %ecx,%ecx` | arithmetic/control | 0x3880b6 | fwd |
| ML-KEM CBD sampling eta=2 | +0x5a | je | reg/arith | `0x389338: test %eax,%eax` | memory | 0x389437 | fwd |
| ML-KEM CBD sampling eta=2 | +0x14a | jne | reg/arith | `0x389424: cmp $0x80,%rax` | arithmetic/control | 0x389360 | back |
| ML-KEM CBD sampling eta=2 | +0x192 | jne | reg/arith | `0x38946b: cmp $0x80,%rcx` | arithmetic/control | 0x389440 | back |
| ML-KEM CBD sampling eta=3 | +0x7e | je | reg/arith | `0x3894fc: test %eax,%eax` | memory | 0x389837 | fwd |
| ML-KEM CBD sampling eta=3 | +0x3aa | jne | reg/arith | `0x389826: cmp $0x40,%rcx` | arithmetic/control | 0x389520 | back |
| ML-KEM CBD sampling eta=3 | +0x3f2 | jne | reg/arith | `0x38986b: cmp $0xc7,%rcx` | arithmetic/control | 0x389840 | back |
| ML-KEM CBD vector sampling then NTT | +0x21 | jle | reg/arith | `0x38818e: test %r8d,%r8d` | memory | 0x3881f0 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x60 | je | reg/arith | `0x3881ce: test %eax,%eax` | call | 0x3881e7 | fwd |
| ML-KEM CBD vector sampling then NTT | +0x73 | jg | reg/arith | `0x3881e1: dec %ebx` | arithmetic/control | 0x3881b0 | back |
| ML-KEM hash H | +0x2e | je | reg/arith | `0x38996c: test %eax,%eax` | memory | 0x3899dd | fwd |
| ML-KEM hash H | +0x49 | je | reg/arith | `0x389987: test %eax,%eax` | arithmetic/control | 0x3899c4 | fwd |
| ML-KEM hash H | +0x4e | je | reg/arith | `0x38998b: test %rbx,%rbx` | memory | 0x38999e | fwd |
| ML-KEM hash H | +0x56 | je | reg/arith | `0x389993: test %rax,%rax` | memory | 0x38999e | fwd |
| ML-KEM hash H | +0x5c | jne | mem | `0x389998: testb $0x2,0x10(%rax)` | memory | 0x3899c9 | fwd |
| ML-KEM hash G | +0x2e | je | reg/arith | `0x3898ac: test %eax,%eax` | memory | 0x38991d | fwd |
| ML-KEM hash G | +0x49 | je | reg/arith | `0x3898c7: test %eax,%eax` | arithmetic/control | 0x389904 | fwd |
| ML-KEM hash G | +0x4e | je | reg/arith | `0x3898cb: test %rbx,%rbx` | memory | 0x3898de | fwd |
| ML-KEM hash G | +0x56 | je | reg/arith | `0x3898d3: test %rax,%rax` | memory | 0x3898de | fwd |
| ML-KEM hash G | +0x5c | jne | mem | `0x3898d8: testb $0x2,0x10(%rax)` | memory | 0x389909 | fwd |
| ML-KEM public-key hash | +0x59 | je | reg/arith | `0x3873d7: test %eax,%eax` | memory | 0x3874cb | fwd |
| ML-KEM public-key hash | +0x96 | je | reg/arith | `0x38740f: cmp $0x200,%rsi` | memory | 0x387460 | fwd |
| ML-KEM public-key hash | +0xa5 | jbe | reg/arith | `0x387422: cmp $0x33,%eax` | memory | 0x387400 | back |
| ML-KEM public-key hash | +0xb9 | je | reg/arith | `0x387435: cmp $0x40,%r8d` | arithmetic/control | 0x387451 | fwd |
| ML-KEM public-key hash | +0xf6 | je | reg/arith | `0x387474: test %eax,%eax` | memory | 0x3874cb | fwd |
| ML-KEM public-key hash | +0x109 | jb | reg/arith | `0x387486: cmp %rax,%rbp` | memory | 0x3873f0 | back |
| ML-KEM public-key hash | +0x123 | je | reg/arith | `0x3874a1: test %eax,%eax` | memory | 0x3874cb | fwd |
| ML-KEM KDF | +0x2a | je | reg/arith | `0x3891c8: test %eax,%eax` | memory | 0x38920e | fwd |
| ML-KEM KDF | +0x3f | je | reg/arith | `0x3891dd: test %eax,%eax` | memory | 0x38920e | fwd |
| ML-KEM KDF | +0x52 | je | reg/arith | `0x3891f0: test %eax,%eax` | memory | 0x38920e | fwd |
| ML-KEM PRF | +0x2d | je | reg/arith | `0x38924b: test %eax,%eax` | memory | 0x3892ba | fwd |
| ML-KEM PRF | +0x46 | je | reg/arith | `0x389264: test %eax,%eax` | arithmetic/control | 0x3892a3 | fwd |
| ML-KEM PRF | +0x4b | je | reg/arith | `0x389268: test %r14,%r14` | memory | 0x38927b | fwd |
| ML-KEM PRF | +0x53 | je | reg/arith | `0x389270: test %rax,%rax` | memory | 0x38927b | fwd |
| ML-KEM PRF | +0x59 | jne | mem | `0x389275: testb $0x2,0x10(%rax)` | memory | 0x3892a8 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xa0 | je | reg/arith | `0x30030e: test %eax,%eax` | memory | 0x300417 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xb9 | je | reg/arith | `0x300327: test %eax,%eax` | memory | 0x300417 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xd0 | je | reg/arith | `0x30033e: test %eax,%eax` | memory | 0x300417 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0xeb | je | reg/arith | `0x300359: test %eax,%eax` | call+memory | 0x300417 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x155 | je | reg/arith | `0x3003bb: test %eax,%eax` | call+memory | 0x3004f3 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x178 | je | reg/arith | `0x3003e6: test %eax,%eax` | memory | 0x3004f3 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x185 | je | reg/arith | `0x3003f2: test %rax,%rax` | arithmetic/control | 0x300629 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x18e | je | reg/arith | `0x3003fb: test %r14,%r14` | arithmetic/control | 0x300615 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x198 | jae | reg/arith | `0x300404: cmp $0x4,%rax` | arithmetic/control | 0x300515 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x2a9 | jae | reg/arith | `0x300515: cmp $0x20,%rax` | arithmetic/control | 0x300521 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x2f1 | jne | reg/arith | `0x30055e: cmp %rdx,%rcx` | arithmetic/control | 0x300532 | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x32a | je | reg/arith | `0x300597: cmp %rcx,%rax` | arithmetic/control | 0x300611 | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x32e | je | reg/arith | `0x30059c: test $0x1c,%al` | memory | 0x3005fe | fwd |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x366 | jne | reg/arith | `0x3005d3: cmp %rsi,%rcx` | arithmetic/control | 0x3005c0 | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x39f | jne | reg/arith | `0x30060c: cmp %rcx,%rax` | arithmetic/control | 0x3005fe | back |
| ML-KEM decapsulation carrier (implicit-rejection comparison + select) | +0x3a3 | je | reg/arith | `0x300611: test %dl,%dl` | call+memory | 0x300629 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x58 | ja | reg/arith | `0x3841b0: cmp $0x7e,%rax` | memory | 0x384551 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xb0 | jbe | reg/arith | `0x38420c: cmp $0x7,%r8` | memory | 0x384267 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0xf9 | jae | reg/arith | `0x384256: cmp %r13,%r14` | memory | 0x384270 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x105 | jae | reg/arith | `0x384262: cmp %r12,%r15` | arithmetic/control | 0x384270 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2c0 | jne | reg/arith | `0x38441d: cmp %r13,%r8` | memory | 0x3842b0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2d7 | ja | reg/arith | `0x384430: cmp $0xff,%r8` | arithmetic/control | 0x38453c | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x2e4 | jae | reg/arith | `0x38443d: cmp $0x100,%rcx` | memory | 0x384527 | fwd |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x392 | jb | reg/arith | `0x3844ef: cmp %rbx,%r8` | arithmetic/control | 0x384430 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x39f | jne | reg/arith | `0x3844f8: cmp $0x100,%rcx` | arithmetic/control | 0x3841b0 | back |
| ML-KEM forward NTT (used by re-encryption on secret-derived data) | +0x3b2 | ja | reg/arith | `0x38450b: cmp $0x3,%rsi` | arithmetic/control | 0x3841a0 | back |
