# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp29/a/distribution/libcrypto.so.3`
- SHA-256: `5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae`
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
| Montgomery multiply (core) | **missing** (`mont_mul_into`) | | | | | | | | | | |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x166190 | 961 | 231 | 17 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x544360 (carries `mod_exp_core_consttime_from_parts`) | 1693 | 430 | 42 | 0 | 2 | 4 | 0 | 0 | 20 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x387840 | 9648 | 2225 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x38d4c0 | 3158 | 780 | 125 | 0 | 5 | 7 | 1 | 0 | 78 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x334840 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x2c09f0 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x2bd6c0 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x2bd4e0 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |

## Coverage

- expected targets: 9
- resolved uniquely and disassembled: 8
- of those, audited through a verified inline mapping: 1
  - Constant-time ladder core: intended `mod_exp_core_consttime_from_parts` -> carrier `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared`
- failed: 1
  - Montgomery multiply (core) (`mont_mul_into`): missing

## Inline mappings declared by the inventory

A mapping is admitted only when the audit re-establishes the name derivation (`resolves_to` is `symbol` + `suffix`), the carrier's extent, a direct call from the declared caller, the wrapper's constant argument at that site, and the producer string in this DSO. It does not prove the wrapper was inlined rather than source-edited away; those are the same instructions (see the module docstring).

| target | carrier | state | caller | call site | constant | carrier extent | producer |
|---|---|---|---|---|---|---:|---|
| `mod_exp_core_consttime_from_parts` | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` | **verified, audited** | `BN_mod_exp` | +0x181 | `push $0x0` | 1693 B | `clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))` |

- **Constant-time ladder core** recorded check: mod_exp_core_consttime_from_parts(ad, pd, md, n) is the one-line forwarder to mod_exp_core_consttime_from_parts_prepared(ad, pd, md, n, None); in the release DSO its only non-test caller BN_mod_exp calls the prepared entry directly with the None tag, so no out-of-line body of the wrapper is emitted

## Divisions

- none in any audited range.

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d238, 0x16d259, 0x16d27a, 0x16d291, 0x16d2e3, 0x16d2fa, 0x16d485, 0x16d593, 0x16d639, 0x16d7f8, 0x22ac4c, 0x22ac7c, 0x264ccc, 0x264cfc, 0x29462a, 0x2946bc, 0x29490c, 0x2bdb6b, 0x35eecc, 0x36157c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x1661c9: test %rbx,%rbx` | memory | 0x166220 | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x166206: cmpb $0x0,0x8(%rsp)` | memory | 0x166265 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | jne | reg/arith | `0x166215: test %rbx,%rbx` | arithmetic/control | 0x166436 | fwd |
| Montgomery multiply (allocating wrapper) | +0xb8 | je | mem | `0x166243: cmpb $0x0,0x8(%rsp)` | memory | 0x166459 | fwd |
| Montgomery multiply (allocating wrapper) | +0xe4 | jne | reg/arith | `0x166271: test %rbx,%rbx` | memory | 0x166491 | fwd |
| Montgomery multiply (allocating wrapper) | +0x12a | je | reg/arith | `0x1662b8: test %al,%al` | memory | 0x166378 | fwd |
| Montgomery multiply (allocating wrapper) | +0x143 | je | reg/arith | `0x1662d0: test %rbx,%rbx` | memory | 0x166329 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x166313: cmp %rax,%rbx` | memory | 0x1662e0 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x166363: cmp %rax,%r14` | arithmetic/control | 0x166330 | back |
| Montgomery multiply (allocating wrapper) | +0x1f3 | je | reg/arith | `0x166380: test %rbx,%rbx` | memory | 0x1663d6 | fwd |
| Montgomery multiply (allocating wrapper) | +0x236 | jne | reg/arith | `0x1663c3: cmp %rax,%rsi` | memory | 0x166390 | back |
| Montgomery multiply (allocating wrapper) | +0x286 | jne | reg/arith | `0x166413: cmp %rax,%r14` | memory | 0x1663e0 | back |
| Montgomery multiply (allocating wrapper) | +0x2a0 | je | reg/arith | `0x16642d: test %rbx,%rbx` | arithmetic/control | 0x166256 | back |
| Montgomery multiply (allocating wrapper) | +0x2d5 | je | reg/arith | `0x166461: cmp $0x1,%rbx` | memory | 0x166482 | fwd |
| Montgomery multiply (allocating wrapper) | +0x343 | je | mem | `0x1664ce: cmpb $0x0,0x8(%rsp)` | memory | 0x1664e2 | fwd |
| Montgomery multiply (allocating wrapper) | +0x35b | jne | reg/arith | `0x1664e7: cmp $0x1,%rbx` | arithmetic/control | 0x1664f5 | fwd |
| Montgomery multiply (allocating wrapper) | +0x3a1 | je | reg/arith | `0x16652e: test %rbx,%rbx` | memory | 0x166549 | fwd |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x544376: test %r12,%r12` | memory | 0x5443e8 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x544391: cmp $0x1,%r12` | memory | 0x5443b9 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x54439a: cmp $0x1,%r15` | memory | 0x5443bc | fwd |
| Constant-time ladder core | +0x60 | jne | reg/arith | `0x5443bc: test $0x1,%r15b` | call | 0x5443dc | fwd |
| Constant-time ladder core | +0x86 | jbe | reg/arith | `0x5443e3: cmp %rbx,%r13` | memory | 0x5443fe | fwd |
| Constant-time ladder core | +0xe1 | je | mem | `0x54443c: cmpb $0x0,0x10(%rsp)` | memory | 0x544451 | fwd |
| Constant-time ladder core | +0x102 | je | reg/arith | `0x544459: cmp $0x1,%rbx` | memory | 0x544491 | fwd |
| Constant-time ladder core | +0x154 | jae | reg/arith | `0x5444b0: cmp $0x18,%rcx` | memory | 0x5444c5 | fwd |
| Constant-time ladder core | +0x186 | je | reg/arith | `0x5444e3: cmp %rdi,%r8` | arithmetic/control | 0x544561 | fwd |
| Constant-time ladder core | +0x191 | jae | reg/arith | `0x5444ee: cmp %r13,%r8` | memory | 0x544524 | fwd |
| Constant-time ladder core | +0x1a2 | jb | reg/arith | `0x5444ff: cmp %r13,%r8` | memory | 0x544533 | fwd |
| Constant-time ladder core | +0x1b1 | jb | reg/arith | `0x54450e: cmp %r13,%r8` | memory | 0x544544 | fwd |
| Constant-time ladder core | +0x1c0 | jb | reg/arith | `0x54451d: cmp %r13,%r8` | arithmetic/control | 0x5444d3 | back |
| Constant-time ladder core | +0x1d1 | jae | reg/arith | `0x54452e: cmp %r13,%r8` | memory | 0x544504 | back |
| Constant-time ladder core | +0x1e2 | jae | reg/arith | `0x54453f: cmp %r13,%r8` | memory | 0x544513 | back |
| Constant-time ladder core | +0x1f3 | jb | reg/arith | `0x544550: cmp %r13,%r8` | arithmetic/control | 0x5444d3 | back |
| Constant-time ladder core | +0x204 | je | reg/arith | `0x544561: test %rax,%rax` | memory | 0x5445a6 | fwd |
| Constant-time ladder core | +0x22c | je | reg/arith | `0x544589: cmp %r8,%rax` | memory | 0x5445a6 | fwd |
| Constant-time ladder core | +0x235 | jb | reg/arith | `0x544592: cmp %r13,%r9` | memory | 0x54457e | back |
| Constant-time ladder core | +0x244 | jne | reg/arith | `0x5445a1: cmp %r8,%rax` | arithmetic/control | 0x54458e | back |
| Constant-time ladder core | +0x249 | je | reg/arith | `0x5445a6: test %r14,%r14` | memory | 0x544616 | fwd |
| Constant-time ladder core | +0x252 | jne | reg/arith | `0x5445af: test %r12,%r12` | memory | 0x5448ad | fwd |
| Constant-time ladder core | +0x2b9 | je | reg/arith | `0x544616: test %r12,%r12` | arithmetic/control | 0x54498e | fwd |
| Constant-time ladder core | +0x2c6 | jne | reg/arith | `0x544622: shr $0x3a,%rax` | arithmetic/control | 0x5448db | fwd |
| Constant-time ladder core | +0x2d3 | jne | reg/arith | `0x54462f: shr $0x39,%rax` | call+memory | 0x5448db | fwd |
| Constant-time ladder core | +0x2f6 | je | reg/arith | `0x544652: cmp $0xffffffffffffffff,%r14` | call+memory | 0x5448db | fwd |
| Constant-time ladder core | +0x334 | je | reg/arith | `0x544686: cmp $0xffffffffffffffff,%rbp` | memory | 0x544815 | fwd |
| Constant-time ladder core | +0x34c | je | reg/arith | `0x5446a4: test %r8,%r8` | arithmetic/control | 0x5449a1 | fwd |
| Constant-time ladder core | +0x3f3 | je | mem | `0x54473e: cmpq $0xffffffffffffffff,0x10(%rsp)` | memory | 0x54481e | fwd |
| Constant-time ladder core | +0x437 | je | reg/arith | `0x544794: test %rbp,%rbp` | memory | 0x5447b0 | fwd |
| Constant-time ladder core | +0x46a | jne | reg/arith | `0x5447c8: or %al,%cl` | memory | 0x544807 | fwd |
| Constant-time ladder core | +0x4a5 | jne | reg/arith | `0x544802: cmp %rax,%rsi` | arithmetic/control | 0x5447ce | back |
| Constant-time ladder core | +0x4aa | je | reg/arith | `0x544807: test %r14,%r14` | arithmetic/control | 0x5448e7 | fwd |
| Constant-time ladder core | +0x4c8 | je | reg/arith | `0x544825: test %rbp,%rbp` | memory | 0x544841 | fwd |
| Constant-time ladder core | +0x4fb | jne | reg/arith | `0x544859: or %al,%cl` | memory | 0x544898 | fwd |
| Constant-time ladder core | +0x536 | jne | reg/arith | `0x544893: cmp %rax,%rsi` | arithmetic/control | 0x54485f | back |
| Constant-time ladder core | +0x53b | je | reg/arith | `0x544898: test %r14,%r14` | memory | 0x5448e7 | fwd |
| Constant-time ladder core | +0x579 | je | mem | `0x5448d4: cmpb $0x0,0x10(%rsp)` | memory | 0x544945 | fwd |
| Constant-time ladder core | +0x58a | je | reg/arith | `0x5448e7: test %rbx,%rbx` | memory | 0x5443ef | back |
| Constant-time ladder core | +0x5ca | jne | reg/arith | `0x544927: cmp %rax,%rsi` | memory | 0x5448fc | back |
| Constant-time ladder core | +0x5f1 | je | reg/arith | `0x54494d: cmp $0x1,%r12` | memory | 0x544971 | fwd |
| Constant-time ladder core | +0x65f | je | reg/arith | `0x5449bc: test %rbp,%rbp` | memory | 0x5449d8 | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x387854: test %r8,%r8` | memory | 0x3878ab | fwd |
| Constant-time inversion | +0x1c | je | mem | `0x387859: testb $0x1,(%rcx)` | arithmetic/control | 0x3878ab | fwd |
| Constant-time inversion | +0x2f | jne | reg/arith | `0x38786b: shr $0x39,%rdi` | memory | 0x3878ab | fwd |
| Constant-time inversion | +0x66 | je | mem | `0x3878a1: cmpb $0x0,0x18(%rsp)` | memory | 0x3878c4 | fwd |
| Constant-time inversion | +0x90 | je | reg/arith | `0x3878cc: cmp $0x1,%rbx` | memory | 0x3878ed | fwd |
| Constant-time inversion | +0x104 | je | mem | `0x38793f: cmpb $0x0,0x18(%rsp)` | memory | 0x3879ab | fwd |
| Constant-time inversion | +0x14e | jne | reg/arith | `0x38798b: cmp %rcx,%rbx` | memory | 0x387960 | back |
| Constant-time inversion | +0x177 | je | reg/arith | `0x3879b3: cmp $0x1,%rbx` | memory | 0x3879d4 | fwd |
| Constant-time inversion | +0x1f5 | je | mem | `0x387a30: cmpb $0x0,0x18(%rsp)` | memory | 0x387a91 | fwd |
| Constant-time inversion | +0x237 | jne | reg/arith | `0x387a74: cmp %rcx,%rsi` | memory | 0x387a49 | back |
| Constant-time inversion | +0x263 | je | mem | `0x387a9e: cmpq $0x1,(%rsp)` | memory | 0x387ac1 | fwd |
| Constant-time inversion | +0x2d5 | je | mem | `0x387b10: cmpb $0x0,0x18(%rsp)` | memory | 0x387ba0 | fwd |
| Constant-time inversion | +0x2ff | jne | reg/arith | `0x387b3d: or %cl,%dl` | memory | 0x387b7f | fwd |
| Constant-time inversion | +0x339 | jne | reg/arith | `0x387b76: cmp %rcx,%rsi` | memory | 0x387b4b | back |
| Constant-time inversion | +0x342 | je | reg/arith | `0x387b7f: test %rax,%rax` | memory | 0x387a37 | back |
| Constant-time inversion | +0x372 | je | mem | `0x387bad: cmpq $0x1,(%rsp)` | memory | 0x387bd8 | fwd |
| Constant-time inversion | +0x3e8 | je | mem | `0x387c23: cmpb $0x0,0x18(%rsp)` | memory | 0x387cb5 | fwd |
| Constant-time inversion | +0x416 | jne | reg/arith | `0x387c54: or %cl,%al` | memory | 0x387c92 | fwd |
| Constant-time inversion | +0x450 | jne | reg/arith | `0x387c8d: cmp %rcx,%rsi` | memory | 0x387c62 | back |
| Constant-time inversion | +0x457 | je | mem | `0x387c92: cmpq $0x0,(%rsp)` | memory | 0x387cac | fwd |
| Constant-time inversion | +0x483 | je | reg/arith | `0x387cbf: cmp $0x1,%rbx` | memory | 0x387ce5 | fwd |
| Constant-time inversion | +0x4ee | je | mem | `0x387d29: cmpb $0x0,0x18(%rsp)` | memory | 0x387d39 | fwd |
| Constant-time inversion | +0x507 | je | reg/arith | `0x387d43: cmp $0x1,%rbx` | memory | 0x387d69 | fwd |
| Constant-time inversion | +0x562 | je | mem | `0x387d9c: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x38803d | fwd |
| Constant-time inversion | +0x599 | je | mem | `0x387dd3: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x388046 | fwd |
| Constant-time inversion | +0x5d0 | je | mem | `0x387e0a: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x38993d | fwd |
| Constant-time inversion | +0x607 | je | mem | `0x387e41: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x389946 | fwd |
| Constant-time inversion | +0x63f | je | mem | `0x387e79: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x38994f | fwd |
| Constant-time inversion | +0x677 | je | mem | `0x387eb1: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x389958 | fwd |
| Constant-time inversion | +0x6af | je | mem | `0x387ee9: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x389961 | fwd |
| Constant-time inversion | +0x6e7 | je | mem | `0x387f21: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x38996a | fwd |
| Constant-time inversion | +0x71f | je | mem | `0x387f59: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x389973 | fwd |
| Constant-time inversion | +0x757 | je | mem | `0x387f91: cmpq $0xffffffffffffffff,0x18(%rsp)` | call+memory | 0x389b89 | fwd |
| Constant-time inversion | +0x793 | je | mem | `0x387fcd: cmpq $0xffffffffffffffff,0x18(%rsp)` | memory | 0x389b8f | fwd |
| Constant-time inversion | +0x9ad | je | mem | `0x3881d5: cmp 0x2c8(%rsp),%rax` | memory | 0x38997c | fwd |
| Constant-time inversion | +0x9dc | je | reg/arith | `0x388219: test %rcx,%rcx` | memory | 0x388278 | fwd |
| Constant-time inversion | +0xa20 | je | reg/arith | `0x38825c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x38827b | fwd |
| Constant-time inversion | +0xa25 | jae | reg/arith | `0x388262: cmp %rbx,%rcx` | memory | 0x38826d | fwd |
| Constant-time inversion | +0xa32 | jb | reg/arith | `0x38826f: cmp %rbx,%rcx` | arithmetic/control | 0x388232 | back |
| Constant-time inversion | +0xa58 | je | reg/arith | `0x388295: test %rcx,%rcx` | memory | 0x3882f1 | fwd |
| Constant-time inversion | +0xa94 | je | reg/arith | `0x3882d0: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x3882f1 | fwd |
| Constant-time inversion | +0xa99 | jae | reg/arith | `0x3882d6: cmp %rbx,%rcx` | memory | 0x3882e6 | fwd |
| Constant-time inversion | +0xaab | jb | reg/arith | `0x3882e8: cmp %rbx,%rcx` | arithmetic/control | 0x3882ad | back |
| Constant-time inversion | +0xb16 | je | reg/arith | `0x388353: test %rcx,%rcx` | memory | 0x38844e | fwd |
| Constant-time inversion | +0xb2c | je | reg/arith | `0x388369: test %r14,%r14` | memory | 0x388415 | fwd |
| Constant-time inversion | +0xb96 | je | reg/arith | `0x3883d2: add $0xfffffffffffffffe,%rdx` | memory | 0x38840a | fwd |
| Constant-time inversion | +0xba3 | jae | reg/arith | `0x3883e0: cmp %rbx,%r11` | memory | 0x3883eb | fwd |
| Constant-time inversion | +0xbc3 | jb | reg/arith | `0x388400: cmp %rbx,%r8` | arithmetic/control | 0x3883b3 | back |
| Constant-time inversion | +0xbce | je | reg/arith | `0x38840a: test $0x1,%r14b` | arithmetic/control | 0x38844e | fwd |
| Constant-time inversion | +0xbfc | jae | reg/arith | `0x388439: cmp %rbx,%rcx` | memory | 0x388444 | fwd |
| Constant-time inversion | +0xc26 | je | reg/arith | `0x388463: test %r8,%r8` | memory | 0x38855b | fwd |
| Constant-time inversion | +0xc37 | je | reg/arith | `0x388474: test %r13,%r13` | memory | 0x388521 | fwd |
| Constant-time inversion | +0xc9f | je | reg/arith | `0x3884db: add $0xfffffffffffffffe,%r10` | memory | 0x388516 | fwd |
| Constant-time inversion | +0xcae | jae | mem | `0x3884e9: cmp 0x50(%rsp),%r14` | memory | 0x3884f6 | fwd |
| Constant-time inversion | +0xcd0 | jb | mem | `0x38850b: cmp 0x50(%rsp),%rax` | arithmetic/control | 0x3884bc | back |
| Constant-time inversion | +0xcda | je | reg/arith | `0x388516: test $0x1,%r13b` | arithmetic/control | 0x38855b | fwd |
| Constant-time inversion | +0xd04 | jae | mem | `0x38853f: cmp 0x50(%rsp),%rsi` | memory | 0x388551 | fwd |
| Constant-time inversion | +0xd9b | je | reg/arith | `0x3885d7: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x388610 | fwd |
| Constant-time inversion | +0xda0 | jae | reg/arith | `0x3885dd: cmp %rbx,%rcx` | memory | 0x3885e8 | fwd |
| Constant-time inversion | +0xdaf | jae | mem | `0x3885ea: cmp 0x10(%rsp),%rcx` | memory | 0x3885fc | fwd |
| Constant-time inversion | +0xdc9 | jb | reg/arith | `0x388606: cmp %r8,%rcx` | arithmetic/control | 0x3885b4 | back |
| Constant-time inversion | +0xdd6 | je | mem | `0x388610: cmpq $0x0,0x10(%rsp)` | memory | 0x388714 | fwd |
| Constant-time inversion | +0xdec | je | reg/arith | `0x388629: test %r10,%r10` | memory | 0x3886d7 | fwd |
| Constant-time inversion | +0xe59 | je | reg/arith | `0x388695: add $0xfffffffffffffffe,%r11` | memory | 0x3886cc | fwd |
| Constant-time inversion | +0xe66 | jae | reg/arith | `0x3886a3: cmp %rbx,%r14` | memory | 0x3886ae | fwd |
| Constant-time inversion | +0xe86 | jb | reg/arith | `0x3886c3: cmp %rbx,%rax` | arithmetic/control | 0x388676 | back |
| Constant-time inversion | +0xe90 | je | reg/arith | `0x3886cc: test $0x1,%r10b` | arithmetic/control | 0x388714 | fwd |
| Constant-time inversion | +0xebd | jae | reg/arith | `0x3886fa: cmp %rbx,%rsi` | memory | 0x38870a | fwd |
| Constant-time inversion | +0xed7 | je | reg/arith | `0x388714: test %r8,%r8` | memory | 0x38880c | fwd |
| Constant-time inversion | +0xee8 | je | reg/arith | `0x388725: test %r10,%r10` | memory | 0x3887d2 | fwd |
| Constant-time inversion | +0xf50 | je | reg/arith | `0x38878c: add $0xfffffffffffffffe,%r11` | memory | 0x3887c7 | fwd |
| Constant-time inversion | +0xf5f | jae | mem | `0x38879a: cmp 0x68(%rsp),%r14` | memory | 0x3887a7 | fwd |
| Constant-time inversion | +0xf81 | jb | mem | `0x3887bc: cmp 0x68(%rsp),%rax` | arithmetic/control | 0x38876d | back |
| Constant-time inversion | +0xf8b | je | reg/arith | `0x3887c7: test $0x1,%r10b` | arithmetic/control | 0x38880c | fwd |
| Constant-time inversion | +0xfb5 | jae | mem | `0x3887f0: cmp 0x68(%rsp),%rsi` | memory | 0x388802 | fwd |
| Constant-time inversion | +0x1023 | je | reg/arith | `0x38885f: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x38889d | fwd |
| Constant-time inversion | +0x1028 | jae | reg/arith | `0x388865: cmp %rbx,%rcx` | memory | 0x388875 | fwd |
| Constant-time inversion | +0x103c | jae | mem | `0x388877: cmp 0x10(%rsp),%rcx` | memory | 0x388889 | fwd |
| Constant-time inversion | +0x1056 | jb | reg/arith | `0x388893: cmp %r8,%rcx` | arithmetic/control | 0x38883c | back |
| Constant-time inversion | +0x10af | je | mem | `0x3888e6: cmpq $0x0,0x80(%rsp)` | memory | 0x388901 | fwd |
| Constant-time inversion | +0x10ee | je | reg/arith | `0x38892b: test %rcx,%rcx` | arithmetic/control | 0x388a21 | fwd |
| Constant-time inversion | +0x10fb | je | reg/arith | `0x388937: add $0xfffffffffffffff8,%r8` | memory | 0x3889e5 | fwd |
| Constant-time inversion | +0x115e | je | reg/arith | `0x38899a: add $0xfffffffffffffffe,%r9` | memory | 0x3889da | fwd |
| Constant-time inversion | +0x1170 | jae | mem | `0x3889a8: cmp 0x80(%rsp),%rdi` | memory | 0x3889b8 | fwd |
| Constant-time inversion | +0x1194 | jb | mem | `0x3889cc: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x38897b | back |
| Constant-time inversion | +0x119e | je | reg/arith | `0x3889da: test $0x1,%r8b` | arithmetic/control | 0x388a21 | fwd |
| Constant-time inversion | +0x11c7 | jae | mem | `0x3889ff: cmp 0x80(%rsp),%rdi` | memory | 0x388a17 | fwd |
| Constant-time inversion | +0x11ec | je | reg/arith | `0x388a29: test %rdx,%rdx` | arithmetic/control | 0x388a87 | fwd |
| Constant-time inversion | +0x1220 | je | reg/arith | `0x388a5c: add $0xfffffffffffffff8,%rax` | memory | 0x388a87 | fwd |
| Constant-time inversion | +0x122a | jae | mem | `0x388a62: cmp 0x80(%rsp),%rcx` | memory | 0x388a7a | fwd |
| Constant-time inversion | +0x1240 | jb | mem | `0x388a7c: cmp (%rsp),%rcx` | arithmetic/control | 0x388a37 | back |
| Constant-time inversion | +0x124b | ja | mem | `0x388a87: cmp %rdx,(%rsp)` | arithmetic/control | 0x389ca7 | fwd |
| Constant-time inversion | +0x1251 | jae | unknown | `?` | memory | 0x389cd0 | fwd |
| Constant-time inversion | +0x125d | je | mem | `0x388a97: cmpq $0x0,0x10(%rsp)` | memory | 0x388b6e | fwd |
| Constant-time inversion | +0x1289 | jne | reg/arith | `0x388ac6: test $0x8,%dl` | memory | 0x388b05 | fwd |
| Constant-time inversion | +0x12a7 | jae | mem | `0x388ae3: cmp (%rsp),%rdi` | memory | 0x388af4 | fwd |
| Constant-time inversion | +0x12c8 | je | reg/arith | `0x388b05: test %rdx,%rdx` | memory | 0x388b6e | fwd |
| Constant-time inversion | +0x12f7 | je | mem | `0x388b32: cmp 0x8(%rsp),%rax` | memory | 0x388b6e | fwd |
| Constant-time inversion | +0x1304 | jae | mem | `0x388b40: cmp (%rsp),%rsi` | memory | 0x388b51 | fwd |
| Constant-time inversion | +0x1328 | jb | mem | `0x388b64: cmp (%rsp),%rcx` | arithmetic/control | 0x388b18 | back |
| Constant-time inversion | +0x1334 | je | mem | `0x388b6e: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x388c46 | fwd |
| Constant-time inversion | +0x1341 | je | reg/arith | `0x388b7d: add $0xfffffffffffffff8,%rdx` | memory | 0x388c1a | fwd |
| Constant-time inversion | +0x138e | je | reg/arith | `0x388bcb: cmp %rsi,%rdi` | memory | 0x388c0b | fwd |
| Constant-time inversion | +0x139b | jae | mem | `0x388bd6: cmp 0x10(%rsp),%rdi` | memory | 0x388be8 | fwd |
| Constant-time inversion | +0x13c4 | jb | mem | `0x388bff: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x388ba7 | back |
| Constant-time inversion | +0x13ce | je | reg/arith | `0x388c0b: test $0x1,%dl` | arithmetic/control | 0x388c46 | fwd |
| Constant-time inversion | +0x13e6 | jae | mem | `0x388c21: cmp 0x10(%rsp),%rcx` | memory | 0x388c33 | fwd |
| Constant-time inversion | +0x1438 | je | reg/arith | `0x388c75: test %rax,%rax` | memory | 0x388ce6 | fwd |
| Constant-time inversion | +0x1477 | je | reg/arith | `0x388cb3: add $0xfffffffffffffff8,%rcx` | memory | 0x388ce1 | fwd |
| Constant-time inversion | +0x1481 | jae | mem | `0x388cb9: cmp 0x80(%rsp),%rdx` | memory | 0x388cd1 | fwd |
| Constant-time inversion | +0x149b | jb | mem | `0x388cd3: cmp 0x88(%rsp),%rdx` | arithmetic/control | 0x388c88 | back |
| Constant-time inversion | +0x14b8 | je | reg/arith | `0x388cf5: test %rdx,%rdx` | arithmetic/control | 0x388d78 | fwd |
| Constant-time inversion | +0x14f1 | je | reg/arith | `0x388d2d: add $0xfffffffffffffff8,%rdx` | memory | 0x388d51 | fwd |
| Constant-time inversion | +0x14f7 | jae | mem | `0x388d33: cmp (%rsp),%rsi` | memory | 0x388d42 | fwd |
| Constant-time inversion | +0x150a | jb | mem | `0x388d45: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x388d03 | back |
| Constant-time inversion | +0x157f | je | reg/arith | `0x388dbc: test %rsi,%rsi` | arithmetic/control | 0x388ea7 | fwd |
| Constant-time inversion | +0x158c | je | reg/arith | `0x388dc8: add $0xfffffffffffffff8,%r11` | memory | 0x388e70 | fwd |
| Constant-time inversion | +0x15ed | je | reg/arith | `0x388e29: add $0xfffffffffffffffe,%rsi` | memory | 0x388e65 | fwd |
| Constant-time inversion | +0x15fc | jae | mem | `0x388e37: cmp 0x58(%rsp),%r14` | memory | 0x388e44 | fwd |
| Constant-time inversion | +0x161e | jb | mem | `0x388e59: cmp 0x58(%rsp),%r13` | arithmetic/control | 0x388e0a | back |
| Constant-time inversion | +0x1629 | je | reg/arith | `0x388e65: test $0x1,%r11b` | arithmetic/control | 0x388ea7 | fwd |
| Constant-time inversion | +0x1650 | jae | mem | `0x388e8b: cmp 0x58(%rsp),%rdi` | memory | 0x388e9d | fwd |
| Constant-time inversion | +0x16a9 | je | reg/arith | `0x388ee5: add $0xfffffffffffffff8,%rsi` | memory | 0x388f0b | fwd |
| Constant-time inversion | +0x16b0 | jae | mem | `0x388eeb: cmp 0x58(%rsp),%rdi` | memory | 0x388efd | fwd |
| Constant-time inversion | +0x16c4 | jb | mem | `0x388f00: cmp (%rsp),%rdi` | arithmetic/control | 0x388ebf | back |
| Constant-time inversion | +0x16d1 | je | mem | `0x388f0b: cmpq $0x0,0x10(%rsp)` | memory | 0x388fd0 | fwd |
| Constant-time inversion | +0x16f4 | jne | reg/arith | `0x388f30: test $0x8,%dil` | memory | 0x388f4e | fwd |
| Constant-time inversion | +0x1701 | jae | mem | `0x388f3d: cmp (%rsp),%rsi` | memory | 0x388f53 | fwd |
| Constant-time inversion | +0x1728 | je | reg/arith | `0x388f65: test %rdi,%rdi` | memory | 0x388fd0 | fwd |
| Constant-time inversion | +0x1757 | je | mem | `0x388f92: cmp 0x8(%rsp),%rsi` | memory | 0x388fd0 | fwd |
| Constant-time inversion | +0x1764 | jae | mem | `0x388fa0: cmp (%rsp),%r9` | memory | 0x388fb1 | fwd |
| Constant-time inversion | +0x1789 | jb | mem | `0x388fc5: cmp (%rsp),%r10` | arithmetic/control | 0x388f78 | back |
| Constant-time inversion | +0x1796 | je | mem | `0x388fd0: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x3890af | fwd |
| Constant-time inversion | +0x17a3 | je | reg/arith | `0x388fdf: add $0xfffffffffffffff8,%r11` | memory | 0x389081 | fwd |
| Constant-time inversion | +0x17f1 | je | reg/arith | `0x38902e: cmp %r9,%r10` | memory | 0x389071 | fwd |
| Constant-time inversion | +0x17fe | jae | mem | `0x389039: cmp 0x10(%rsp),%r10` | memory | 0x38904b | fwd |
| Constant-time inversion | +0x182a | jb | mem | `0x389065: cmp 0x10(%rsp),%r10` | arithmetic/control | 0x38900a | back |
| Constant-time inversion | +0x1835 | je | reg/arith | `0x389071: test $0x1,%r11b` | arithmetic/control | 0x3890af | fwd |
| Constant-time inversion | +0x184d | jae | mem | `0x389088: cmp 0x10(%rsp),%rsi` | memory | 0x38909a | fwd |
| Constant-time inversion | +0x18a6 | je | reg/arith | `0x3890e3: test %rsi,%rsi` | arithmetic/control | 0x389159 | fwd |
| Constant-time inversion | +0x18db | je | reg/arith | `0x389117: add $0xfffffffffffffff8,%rsi` | memory | 0x389159 | fwd |
| Constant-time inversion | +0x18e5 | jae | mem | `0x38911d: cmp 0x80(%rsp),%rdi` | memory | 0x389135 | fwd |
| Constant-time inversion | +0x18fd | jae | mem | `0x389138: cmp 0x40(%rsp),%rdi` | memory | 0x38914a | fwd |
| Constant-time inversion | +0x1912 | jb | mem | `0x38914d: cmp 0x68(%rsp),%rdi` | arithmetic/control | 0x3890f0 | back |
| Constant-time inversion | +0x1922 | je | mem | `0x389159: cmpq $0x0,0x88(%rsp)` | memory | 0x389174 | fwd |
| Constant-time inversion | +0x1949 | je | mem | `0x389183: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x38929f | fwd |
| Constant-time inversion | +0x1956 | je | reg/arith | `0x389192: add $0xfffffffffffffff8,%rsi` | memory | 0x389262 | fwd |
| Constant-time inversion | +0x19ce | je | reg/arith | `0x38920a: add $0xfffffffffffffffe,%rsi` | memory | 0x389251 | fwd |
| Constant-time inversion | +0x19e0 | jae | mem | `0x389218: cmp 0x88(%rsp),%r14` | memory | 0x389228 | fwd |
| Constant-time inversion | +0x1a0a | jb | mem | `0x389242: cmp 0x88(%rsp),%r13` | arithmetic/control | 0x3891e1 | back |
| Constant-time inversion | +0x1a19 | je | mem | `0x389251: testb $0x1,0xa0(%rsp)` | memory | 0x38929f | fwd |
| Constant-time inversion | +0x1a45 | jae | mem | `0x38927d: cmp 0x88(%rsp),%rdi` | memory | 0x389295 | fwd |
| Constant-time inversion | +0x1a93 | je | reg/arith | `0x3892cf: add $0xfffffffffffffff8,%rsi` | memory | 0x3892fb | fwd |
| Constant-time inversion | +0x1a9d | jae | mem | `0x3892d5: cmp 0x88(%rsp),%rdi` | memory | 0x3892ed | fwd |
| Constant-time inversion | +0x1ab4 | jb | mem | `0x3892f0: cmp (%rsp),%rdi` | arithmetic/control | 0x3892a9 | back |
| Constant-time inversion | +0x1ac1 | je | mem | `0x3892fb: cmpq $0x0,0x10(%rsp)` | memory | 0x3893c0 | fwd |
| Constant-time inversion | +0x1ae4 | jne | reg/arith | `0x389320: test $0x8,%dil` | memory | 0x38933e | fwd |
| Constant-time inversion | +0x1af1 | jae | mem | `0x38932d: cmp (%rsp),%rsi` | memory | 0x389343 | fwd |
| Constant-time inversion | +0x1b18 | je | reg/arith | `0x389355: test %rdi,%rdi` | memory | 0x3893c0 | fwd |
| Constant-time inversion | +0x1b47 | je | mem | `0x389382: cmp 0x8(%rsp),%rsi` | memory | 0x3893c0 | fwd |
| Constant-time inversion | +0x1b54 | jae | mem | `0x389390: cmp (%rsp),%r9` | memory | 0x3893a1 | fwd |
| Constant-time inversion | +0x1b79 | jb | mem | `0x3893b5: cmp (%rsp),%r10` | arithmetic/control | 0x389368 | back |
| Constant-time inversion | +0x1b86 | je | mem | `0x3893c0: cmpq $0x0,0x40(%rsp)` | arithmetic/control | 0x389498 | fwd |
| Constant-time inversion | +0x1b90 | je | reg/arith | `0x3893cc: add $0xfffffffffffffff8,%r12` | memory | 0x38946c | fwd |
| Constant-time inversion | +0x1bde | je | reg/arith | `0x38941b: cmp %rdi,%r9` | memory | 0x38945c | fwd |
| Constant-time inversion | +0x1beb | jae | mem | `0x389426: cmp 0x10(%rsp),%r9` | memory | 0x389438 | fwd |
| Constant-time inversion | +0x1c15 | jb | mem | `0x389450: cmp 0x10(%rsp),%r9` | arithmetic/control | 0x3893f7 | back |
| Constant-time inversion | +0x1c20 | je | reg/arith | `0x38945c: test $0x1,%r12b` | arithmetic/control | 0x389498 | fwd |
| Constant-time inversion | +0x1c38 | jae | mem | `0x389473: cmp 0x10(%rsp),%rsi` | memory | 0x389485 | fwd |
| Constant-time inversion | +0x1c5e | je | mem | `0x389498: cmpq $0x0,0x10(%rsp)` | memory | 0x389511 | fwd |
| Constant-time inversion | +0x1ca0 | je | reg/arith | `0x3894dc: add $0xfffffffffffffff8,%rsi` | memory | 0x38950c | fwd |
| Constant-time inversion | +0x1caa | jae | mem | `0x3894e2: cmp 0x88(%rsp),%rdi` | memory | 0x3894fa | fwd |
| Constant-time inversion | +0x1cc5 | jb | mem | `0x3894fd: cmp 0x80(%rsp),%rdi` | arithmetic/control | 0x3894af | back |
| Constant-time inversion | +0x1cda | je | mem | `0x389514: cmpq $0x0,0x58(%rsp)` | arithmetic/control | 0x38957d | fwd |
| Constant-time inversion | +0x1d10 | je | reg/arith | `0x38954c: add $0xfffffffffffffff8,%rcx` | memory | 0x389570 | fwd |
| Constant-time inversion | +0x1d16 | jae | mem | `0x389552: cmp (%rsp),%rsi` | memory | 0x389561 | fwd |
| Constant-time inversion | +0x1d29 | jb | mem | `0x389564: cmp 0x10(%rsp),%rsi` | arithmetic/control | 0x389522 | back |
| Constant-time inversion | +0x1d52 | je | mem | `0x38958c: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x38968d | fwd |
| Constant-time inversion | +0x1d5f | je | reg/arith | `0x38959b: add $0xfffffffffffffff8,%r10` | memory | 0x389657 | fwd |
| Constant-time inversion | +0x1dce | je | reg/arith | `0x38960a: add $0xfffffffffffffffe,%rsi` | memory | 0x38964a | fwd |
| Constant-time inversion | +0x1ddd | jae | mem | `0x389618: cmp 0x58(%rsp),%r14` | memory | 0x389625 | fwd |
| Constant-time inversion | +0x1e04 | jb | mem | `0x38963f: cmp 0x58(%rsp),%rcx` | arithmetic/control | 0x3895e1 | back |
| Constant-time inversion | +0x1e0e | je | reg/arith | `0x38964a: test $0x1,%r10b` | memory | 0x38968d | fwd |
| Constant-time inversion | +0x1e36 | jae | mem | `0x389671: cmp 0x58(%rsp),%rdi` | memory | 0x389683 | fwd |
| Constant-time inversion | +0x1e7c | je | reg/arith | `0x3896b8: add $0xfffffffffffffff8,%r8` | memory | 0x3896dd | fwd |
| Constant-time inversion | +0x1e83 | jae | mem | `0x3896be: cmp 0x58(%rsp),%rcx` | memory | 0x3896d0 | fwd |
| Constant-time inversion | +0x1e96 | jb | mem | `0x3896d2: cmp (%rsp),%rcx` | arithmetic/control | 0x389693 | back |
| Constant-time inversion | +0x1ea3 | je | mem | `0x3896dd: cmpq $0x0,0x10(%rsp)` | memory | 0x38979d | fwd |
| Constant-time inversion | +0x1ec9 | jne | reg/arith | `0x389705: test $0x8,%sil` | memory | 0x389734 | fwd |
| Constant-time inversion | +0x1ed6 | jae | mem | `0x389712: cmp (%rsp),%rsi` | memory | 0x389723 | fwd |
| Constant-time inversion | +0x1ef7 | je | reg/arith | `0x389734: test %rdi,%rdi` | memory | 0x38979d | fwd |
| Constant-time inversion | +0x1f26 | je | mem | `0x389761: cmp 0x8(%rsp),%rax` | memory | 0x38979d | fwd |
| Constant-time inversion | +0x1f33 | jae | mem | `0x38976f: cmp (%rsp),%rdi` | memory | 0x389780 | fwd |
| Constant-time inversion | +0x1f57 | jb | mem | `0x389793: cmp (%rsp),%rcx` | arithmetic/control | 0x389747 | back |
| Constant-time inversion | +0x1f63 | je | mem | `0x38979d: cmpq $0x0,0x68(%rsp)` | arithmetic/control | 0x389872 | fwd |
| Constant-time inversion | +0x1f6d | je | reg/arith | `0x3897a9: add $0xfffffffffffffff8,%rdx` | memory | 0x389846 | fwd |
| Constant-time inversion | +0x1fba | je | reg/arith | `0x3897f7: cmp %rsi,%rdi` | memory | 0x389837 | fwd |
| Constant-time inversion | +0x1fc7 | jae | mem | `0x389802: cmp 0x10(%rsp),%rdi` | memory | 0x389814 | fwd |
| Constant-time inversion | +0x1ff0 | jb | mem | `0x38982b: cmp 0x10(%rsp),%rdi` | arithmetic/control | 0x3897d3 | back |
| Constant-time inversion | +0x1ffa | je | reg/arith | `0x389837: test $0x1,%dl` | arithmetic/control | 0x389872 | fwd |
| Constant-time inversion | +0x2012 | jae | mem | `0x38984d: cmp 0x10(%rsp),%rcx` | memory | 0x38985f | fwd |
| Constant-time inversion | +0x2080 | je | reg/arith | `0x3898bd: test %rcx,%rcx` | memory | 0x38804f | back |
| Constant-time inversion | +0x20be | je | reg/arith | `0x3898fa: add $0xfffffffffffffff8,%rax` | memory | 0x38804f | back |
| Constant-time inversion | +0x20cc | jae | mem | `0x389904: cmp 0x88(%rsp),%rcx` | memory | 0x38991c | fwd |
| Constant-time inversion | +0x20e3 | jae | mem | `0x38991e: cmp 0x40(%rsp),%rcx` | memory | 0x389930 | fwd |
| Constant-time inversion | +0x20f7 | jb | mem | `0x389932: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x3898cf | back |
| Constant-time inversion | +0x214c | je | reg/arith | `0x389988: cmp $0x1,%rbx` | memory | 0x389a2b | fwd |
| Constant-time inversion | +0x216b | jb | reg/arith | `0x3899a7: cmp $0x18,%rcx` | memory | 0x389a10 | fwd |
| Constant-time inversion | +0x21b7 | jne | reg/arith | `0x3899f4: cmp %rdx,%rsi` | arithmetic/control | 0x3899dc | back |
| Constant-time inversion | +0x21ce | je | reg/arith | `0x389a0b: cmp %rsi,%rcx` | memory | 0x389a2b | fwd |
| Constant-time inversion | +0x21e9 | jne | mem | `0x389a24: cmp 0x8(%rsp),%rax` | call+memory | 0x389a1d | back |
| Constant-time inversion | +0x2204 | je | reg/arith | `0x389a40: cmp $0xffffffffffffffff,%r12` | memory | 0x389b95 | fwd |
| Constant-time inversion | +0x2219 | jne | mem | `0x389a54: cmp 0x38(%rsp),%rdi` | memory | 0x389cbc | fwd |
| Constant-time inversion | +0x2315 | je | reg/arith | `0x389b52: test %r15,%r15` | memory | 0x389c91 | fwd |
| Constant-time inversion | +0x2326 | je | reg/arith | `0x389b63: test %r12,%r12` | memory | 0x3878b2 | back |
| Constant-time inversion | +0x2437 | jne | reg/arith | `0x389c74: cmp %rax,%rsi` | memory | 0x389c49 | back |
| Constant-time inversion | +0x24af | je | reg/arith | `0x389cec: test %r12,%r12` | memory | 0x389d0b | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x38d4e0: test %rcx,%rcx` | memory | 0x38d554 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x38d4f0: test %rax,%rax` | memory | 0x38d548 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x38d4fc: cmp (%r15),%rcx` | memory | 0x38d54f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x38d505: test %ecx,%ecx` | memory | 0x38d515 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x38d50d: test %edx,%edx` | arithmetic/control | 0x38d515 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x38d511: cmp %edx,%ecx` | call | 0x38d54f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x38d51d: test %eax,%eax` | memory | 0x38d554 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x38d529: test %rax,%rax` | memory | 0x38d682 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x38d532: cmp (%r12),%rcx` | memory | 0x38d8c3 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x38d55f: test %rcx,%rcx` | memory | 0x38d660 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x38d580: cmp %rdx,%rcx` | memory | 0x38d660 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x38d589: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x38d580 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x38d59f: test %rcx,%rcx` | memory | 0x38d660 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x38d5c0: cmp %rdx,%rcx` | memory | 0x38d660 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x38d5c9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x38d5c0 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x38d5dd: test %r13,%r13` | memory | 0x38d679 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x38d5ea: cmpq $0x0,0x50(%rax)` | memory | 0x38d690 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x38d60c: test %rax,%rax` | memory | 0x38d65b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x38d627: test %rax,%rax` | call | 0x38d635 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x38d631: test %eax,%eax` | call+memory | 0x38d6a8 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x38d69f: test %r13,%r13` | memory | 0x38d7ed | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x38d6ac: cmpq $0x0,0x50(%rax)` | memory | 0x38d7e4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x38d6d3: test %rax,%rax` | memory | 0x38d821 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x38d6f2: test %rax,%rax` | call | 0x38d7fb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x38d700: test %eax,%eax` | memory | 0x38d7fb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x38d712: test %r14,%r14` | arithmetic/control | 0x38d8dc | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x38d71b: test %r15,%r15` | memory | 0x38d8e7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x38d72e: test %rcx,%rcx` | memory | 0x38d768 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x38d737: test %rax,%rax` | memory | 0x38d768 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x38d743: cmp (%r15),%rcx` | memory | 0x38d768 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x38d74c: test %ecx,%ecx` | memory | 0x38da2a | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x38d758: test %edx,%edx` | arithmetic/control | 0x38da2a | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x38d760: cmp %ecx,%edx` | call | 0x38da2a | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x38d782: test %rax,%rax` | memory | 0x38d795 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x38d78b: test %rax,%rax` | call | 0x38d795 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x38d7c6: test %rbx,%rbx` | memory | 0x38d9fe | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x38d7d3: test %rcx,%rcx` | arithmetic/control | 0x38d8a9 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x38d842: test %bpl,%bpl` | memory | 0x38d888 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x38d84f: test %rax,%rax` | memory | 0x38d862 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x38d858: test %rax,%rax` | call | 0x38d862 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x38d893: test %rbx,%rbx` | memory | 0x38d667 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x38d8a0: test %rcx,%rcx` | memory | 0x38d667 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x38d8f4: test %eax,%eax` | memory | 0x38da06 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x38d900: test %rax,%rax` | memory | 0x38d909 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x38d90d: test %rax,%rax` | memory | 0x38d916 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x38d91a: test %rax,%rax` | memory | 0x38d923 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x38d928: test %rax,%rax` | memory | 0x38d931 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x38d936: test %rax,%rax` | memory | 0x38d93f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x38d944: test %rax,%rax` | memory | 0x38d94d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x38d956: test %rax,%rax` | memory | 0x38d95f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x38d968: test %rax,%rax` | memory | 0x38d971 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x38d97a: test %rax,%rax` | call+memory | 0x38d983 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x38d9ab: test %rax,%rax` | memory | 0x38da12 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x38d9c9: test %eax,%eax` | memory | 0x38da1e | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x38d9da: test %r15,%r15` | memory | 0x38da48 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x38d9e3: test $0xffffffff80000000,%rax` | memory | 0x38da5b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x38da2a: cmp %r15,%r14` | call | 0x38d8fc | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x38da3b: test %eax,%eax` | arithmetic/control | 0x38d8fc | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x38da66: test $0x1,%al` | memory | 0x38e0a8 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x38da73: test %eax,%eax` | memory | 0x38daa1 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x38da7e: cmp %rsi,(%rdi)` | call+memory | 0x38daab | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x38da93: test %al,%cl` | arithmetic/control | 0x38dab4 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x38daa1: test %r15,%r15` | arithmetic/control | 0x38dac9 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x38daab: test %r15,%r15` | memory | 0x38db94 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x38dab4: cmp %rsi,(%r15)` | call | 0x38dac9 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x38dac1: test %al,%al` | memory | 0x38db94 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x38dada: test %rax,%rax` | memory | 0x38dba0 | fwd |
| ECDSA scalar ladder (driver) | +0x635 | jg | mem | `0x38daf1: cmp 0x24(%rsp),%eax` | memory | 0x38dafe | fwd |
| ECDSA scalar ladder (driver) | +0x63c | je | mem | `0x38daf7: cmpl $0x0,0x18(%r15)` | memory | 0x38db1a | fwd |
| ECDSA scalar ladder (driver) | +0x654 | je | reg/arith | `0x38db12: test %eax,%eax` | memory | 0x38dbac | fwd |
| ECDSA scalar ladder (driver) | +0x672 | je | reg/arith | `0x38db30: test %eax,%eax` | memory | 0x38dbb8 | fwd |
| ECDSA scalar ladder (driver) | +0x68f | je | reg/arith | `0x38db4d: test %eax,%eax` | memory | 0x38dd8e | fwd |
| ECDSA scalar ladder (driver) | +0x6a3 | js | mem | `0x38db5e: cmpl $0x0,0x24(%rsp)` | memory | 0x38dbc4 | fwd |
| ECDSA scalar ladder (driver) | +0x6b5 | jae | mem | `0x38db71: cmp 0x10(%rcx),%rax` | memory | 0x38dbc4 | fwd |
| ECDSA scalar ladder (driver) | +0x722 | je | reg/arith | `0x38dbdf: test %rax,%rax` | memory | 0x38dbfc | fwd |
| ECDSA scalar ladder (driver) | +0x74f | je | reg/arith | `0x38dc0c: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x75d | jae | mem | `0x38dc1a: cmp %r15,(%rdi)` | call | 0x38dc2f | fwd |
| ECDSA scalar ladder (driver) | +0x769 | je | reg/arith | `0x38dc27: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x77b | je | reg/arith | `0x38dc38: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x784 | jae | mem | `0x38dc41: cmp %r15,(%rdi)` | call | 0x38dc56 | fwd |
| ECDSA scalar ladder (driver) | +0x790 | je | reg/arith | `0x38dc4e: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x7a2 | je | reg/arith | `0x38dc5f: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ab | jae | mem | `0x38dc68: cmp %r15,(%rdi)` | call | 0x38dc7d | fwd |
| ECDSA scalar ladder (driver) | +0x7b7 | je | reg/arith | `0x38dc75: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x7c5 | je | reg/arith | `0x38dc82: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x7ce | jae | mem | `0x38dc8b: cmp %r15,(%rdi)` | call | 0x38dca0 | fwd |
| ECDSA scalar ladder (driver) | +0x7da | je | reg/arith | `0x38dc98: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x7e8 | je | reg/arith | `0x38dca5: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x7f1 | jae | mem | `0x38dcae: cmp %r15,(%rdi)` | call | 0x38dcc3 | fwd |
| ECDSA scalar ladder (driver) | +0x7fd | je | reg/arith | `0x38dcbb: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x80b | je | reg/arith | `0x38dcc8: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x814 | jae | mem | `0x38dcd1: cmp %r15,(%rdi)` | call | 0x38dce6 | fwd |
| ECDSA scalar ladder (driver) | +0x820 | je | reg/arith | `0x38dcde: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x832 | je | reg/arith | `0x38dcef: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x83b | jae | mem | `0x38dcf8: cmp %r15,(%rdi)` | call | 0x38dd0d | fwd |
| ECDSA scalar ladder (driver) | +0x847 | je | reg/arith | `0x38dd05: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x859 | je | reg/arith | `0x38dd16: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x862 | jae | mem | `0x38dd1f: cmp %r15,(%rdi)` | call | 0x38dd34 | fwd |
| ECDSA scalar ladder (driver) | +0x86e | je | reg/arith | `0x38dd2c: test %al,%al` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x880 | je | reg/arith | `0x38dd3d: test %rdi,%rdi` | memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0x88e | jae | mem | `0x38dd46: cmp %r15,(%rdi)` | call | 0x38dd60 | fwd |
| ECDSA scalar ladder (driver) | +0x89a | je | reg/arith | `0x38dd58: test %al,%al` | memory | 0x38d774 | back |
| ECDSA scalar ladder (driver) | +0x8a5 | je | mem | `0x38dd60: cmpl $0x0,0x28(%r14)` | call+memory | 0x38dec2 | fwd |
| ECDSA scalar ladder (driver) | +0x8b9 | je | reg/arith | `0x38dd77: test %al,%al` | memory | 0x38dd9a | fwd |
| ECDSA scalar ladder (driver) | +0x8e8 | jne | reg/arith | `0x38dda4: cmp $0x4,%rdx` | memory | 0x38dded | fwd |
| ECDSA scalar ladder (driver) | +0x922 | jne | reg/arith | `0x38ddde: cmp $0x1,%dil` | call | 0x38ddef | fwd |
| ECDSA scalar ladder (driver) | +0x934 | je | reg/arith | `0x38ddf2: test %cl,%cl` | arithmetic/control | 0x38de68 | fwd |
| ECDSA scalar ladder (driver) | +0x939 | jne | reg/arith | `0x38ddf6: test %sil,%sil` | memory | 0x38de68 | fwd |
| ECDSA scalar ladder (driver) | +0x985 | je | mem | `0x38de3c: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x38df32 | fwd |
| ECDSA scalar ladder (driver) | +0x9cb | je | reg/arith | `0x38de89: test %eax,%eax` | arithmetic/control | 0x38df00 | fwd |
| ECDSA scalar ladder (driver) | +0x9d4 | jg | reg/arith | `0x38de91: cmp $0x1,%eax` | arithmetic/control | 0x38df0c | fwd |
| ECDSA scalar ladder (driver) | +0x9d8 | jne | reg/arith | `0x38de96: test %eax,%eax` | call+memory | 0x38df43 | fwd |
| ECDSA scalar ladder (driver) | +0xa17 | je | reg/arith | `0x38ded4: test %rax,%rax` | call+memory | 0x38def6 | fwd |
| ECDSA scalar ladder (driver) | +0xa2b | jne | reg/arith | `0x38dee9: test %eax,%eax` | arithmetic/control | 0x38dd6b | back |
| ECDSA scalar ladder (driver) | +0xa4f | jne | reg/arith | `0x38df0c: cmp $0x2,%eax` | call+memory | 0x38df76 | fwd |
| ECDSA scalar ladder (driver) | +0xaa4 | jne | reg/arith | `0x38df62: test %eax,%eax` | memory | 0x38e03b | fwd |
| ECDSA scalar ladder (driver) | +0xaba | jo | mem | `0x38df76: decl 0x24(%rsp)` | arithmetic/control | 0x38e0b7 | fwd |
| ECDSA scalar ladder (driver) | +0xac0 | js | unknown | `?` | memory | 0x38e022 | fwd |
| ECDSA scalar ladder (driver) | +0xae9 | jae | mem | `0x38dfa5: cmp 0x10(%rcx),%rax` | memory | 0x38dfc2 | fwd |
| ECDSA scalar ladder (driver) | +0xb1c | je | mem | `0x38dfd6: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x38dff5 | fwd |
| ECDSA scalar ladder (driver) | +0xb4f | je | reg/arith | `0x38e00d: test %eax,%eax` | memory | 0x38e07d | fwd |
| ECDSA scalar ladder (driver) | +0xb5a | jg | reg/arith | `0x38e013: test %r15,%r15` | arithmetic/control | 0x38df97 | back |
| ECDSA scalar ladder (driver) | +0xb89 | je | reg/arith | `0x38e046: test %rax,%rax` | call+memory | 0x38e064 | fwd |
| ECDSA scalar ladder (driver) | +0xba2 | je | reg/arith | `0x38e060: test %eax,%eax` | call+memory | 0x38e076 | fwd |
| ECDSA scalar ladder (driver) | +0xbdd | jne | reg/arith | `0x38e09a: test %rax,%rax` | arithmetic/control | 0x38d787 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x3348b7: test %rax,%rax` | memory | 0x334e55 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x3348d2: test %rbp,%rbp` | memory | 0x334e55 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x3348e2: test %rax,%rax` | call+memory | 0x334e55 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x334904: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x334922: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x334940: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x33495e: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x334984: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x3349a4: test %eax,%eax` | arithmetic/control | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x3349ac: test %r15,%r15` | memory | 0x3349d2 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x3349be: test %rdx,%rdx` | arithmetic/control | 0x3349f4 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x3349ea: test %rdx,%rdx` | memory | 0x334a00 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x334a03: sub $0x1,%r9` | memory | 0x334a27 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x334a09: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x334a00 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x334a20: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x334a30 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x334a2a: sub $0x1,%r8` | arithmetic/control | 0x334a20 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x334a30: cmp %r9,%rdi` | memory | 0x334a50 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x334a40: sub $0x1,%rdi` | memory | 0x334a52 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x334a4a: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x334a40 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x334a6d | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x334a65: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x334a7f: test %eax,%eax` | arithmetic/control | 0x334e55 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x334a8c: test %r15,%r15` | memory | 0x334a9b | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x334ab3: sub $0x1,%rdi` | memory | 0x334ad7 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x334ab9: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x334ab0 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x334ad0: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x334ae0 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x334ada: sub $0x1,%rsi` | arithmetic/control | 0x334ad0 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x334ae0: cmp %rdi,%rdx` | arithmetic/control | 0x334af5 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x334ae5: sub $0x1,%rdx` | memory | 0x334af7 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x334aef: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x334ae5 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x334b0e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x334b06: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x334b23: test %eax,%eax` | memory | 0x334e55 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x334b3d: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x334b60: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x334b7b: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x334b95: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x334bb7: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x334bd1: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x334bf4: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x334c16: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x334c38: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x334c5a: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x334c74: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x334c90: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x334cb4: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x334cce: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x334ced: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x334d0c: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x334d2b: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x334d45: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x334d64: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x334d81: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x334da6: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x334dc5: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x334de1: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x334dfa: test %eax,%eax` | call+memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x334e13: test %eax,%eax` | memory | 0x334e53 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x334e29: test %eax,%eax` | memory | 0x334e55 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x334e55: test %rbx,%rbx` | memory | 0x334e78 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x334e5e: test %rax,%rax` | memory | 0x334e78 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x2c0a3b: test %rax,%rax` | memory | 0x2c14a8 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x2c0a55: cmpl $0x1,0x10(%rbp)` | memory | 0x2c0a7d | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x2c0a65: test %rax,%rax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x2c0a74: cmp $0xfffffffd,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x2c0a85: testb $0x4,0xa4(%rbp)` | memory | 0x2c0aa5 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x2c0a8e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x2c0b06 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x2c0a97: test %r13b,%r13b` | arithmetic/control | 0x2c0be0 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x2c0aab: test %rax,%rax` | memory | 0x2c14a8 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x2c0ad9: test %rax,%rax` | arithmetic/control | 0x2c0ff0 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x2c0ae2: test %r15,%r15` | memory | 0x2c0af0 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x2c0afa: test %rax,%rax` | arithmetic/control | 0x2c0b68 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x2c0b23: test %r15,%r15` | arithmetic/control | 0x2c0bc0 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x2c0b2c: test %r14,%r14` | memory | 0x2c0b3a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x2c0b41: test %r15,%r15` | memory | 0x2c0bb2 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x2c0b5b: test %eax,%eax` | memory | 0x2c0ba6 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x2c0b84: test %eax,%eax` | memory | 0x2c0fc7 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x2c0bb2: test %r14,%r14` | memory | 0x2c0bc0 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x2c0bc6: or %r13b,%al` | arithmetic/control | 0x2c0df2 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x2c0bd7: test %r15,%r15` | memory | 0x2c14a8 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x2c0be6: test %rax,%rax` | memory | 0x2c14a8 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x2c0c29: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x2c0c37: test %rax,%rax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x2c0c5d: test %rax,%rax` | call+memory | 0x2c1950 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x2c0c86: test %eax,%eax` | call+memory | 0x2c1950 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x2c0cd4: test %al,0x38(%rsp)` | memory | 0x2c0d53 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x2c0ce5: test %rax,%rax` | memory | 0x2c14a8 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x2c0d0b: test %rax,%rax` | call+memory | 0x2c13a2 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x2c0d45: test %ebp,%ebp` | arithmetic/control | 0x2c14ab | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x2c0d55: test %ebx,%ebx` | memory | 0x2c120e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x2c0d67: test %r15b,%r15b` | call+memory | 0x2c1218 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x2c0d8e: test %r13,%r13` | arithmetic/control | 0x2c194b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x2c0d9c: test %rax,%rax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x2c0dae: test %rax,%rax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x2c0dbe: test %rcx,%rcx` | memory | 0x2c13af | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x2c0dd6: cmpq $0x0,0x10(%rcx)` | memory | 0x2c13b9 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x2c0e17: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x2c0e35: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x2c0e5f: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x2c0e7d: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x2c0eb6: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x2c0ed8: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x2c0ef1: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x2c0ef9: test %rbx,%rbx` | memory | 0x2c0f44 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x2c0f08: cmpl $0x0,0x18(%rbx)` | memory | 0x2c0f44 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x2c0f1e: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x2c0f26: cmpl $0x0,0x18(%rbx)` | memory | 0x2c0f44 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x2c0f3c: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x2c0f5a: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x2c0f7c: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x2c0f99: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x2c0fd7: test %r15,%r15` | memory | 0x2c0fe5 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x2c0fe5: test %bl,%bl` | memory | 0x2c1098 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x2c1012: test %rax,%rax` | arithmetic/control | 0x2c10a0 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x2c101b: test %r15,%r15` | memory | 0x2c1029 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x2c1033: test %rax,%rax` | arithmetic/control | 0x2c103c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x2c1058: test %eax,%eax` | memory | 0x2c1073 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x2c1083: test %r15,%r15` | memory | 0x2c1091 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x2c1091: test %bl,%bl` | arithmetic/control | 0x2c10a0 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x2c10aa: test %ebx,%ebx` | memory | 0x2c119b | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x2c10d9: test %bl,%bl` | arithmetic/control | 0x2c1201 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x2c10e4: cmp %r14,%r13` | memory | 0x2c119b | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x2c1118: test %rax,%rax` | arithmetic/control | 0x2c10e1 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x2c111d: test %r15,%r15` | memory | 0x2c112b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x2c112f: test %rax,%rax` | arithmetic/control | 0x2c113d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x2c1136: test %r15,%r15` | arithmetic/control | 0x2c10d0 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x2c1152: test %eax,%eax` | memory | 0x2c1178 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x2c116a: test %r15,%r15` | arithmetic/control | 0x2c10d0 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x2c118d: test %r15,%r15` | arithmetic/control | 0x2c10d0 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x2c11a9: test %ebx,%ebx` | memory | 0x2c11f4 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x2c11b5: cmp 0x60b154(%rip),%rax        # 8cc310 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x3aaa10>` | call+memory | 0x2c0a8e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x2c121d: test %al,%r14b` | memory | 0x2c149f | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x2c1253: test %eax,%eax` | arithmetic/control | 0x2c14ab | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x2c125b: test %rbx,%rbx` | memory | 0x2c127e | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x2c1260: cmpl $0x0,0x18(%rbx)` | memory | 0x2c127e | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x2c1276: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x2c1293: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x2c12a1: test %rax,%rax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x2c12ed: test %ebp,%ebp` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x2c12f5: test %rbx,%rbx` | memory | 0x2c131d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x2c12ff: cmpl $0x0,0x18(%rbx)` | memory | 0x2c131d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x2c1315: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x2c1335: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x2c134e: test %eax,%eax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x2c1356: cmpl $0x0,0x28(%rsp)` | memory | 0x2c16ac | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x2c136c: test %rax,%rax` | memory | 0x2c14ab | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x2c1382: test %rax,%rax` | memory | 0x2c15b9 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x2c138b: cmpq $0x0,0x10(%rax)` | memory | 0x2c15b9 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x2c13fd: test %eax,%eax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x2c1412: test %rax,%rax` | call+memory | 0x2c194b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x2c1436: test %eax,%eax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x2c143e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x2c14e4 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x2c1496: test %al,%r14b` | arithmetic/control | 0x2c1226 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x2c149f: test %r15b,%r15b` | arithmetic/control | 0x2c16ac | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x2c14ab: test %r12,%r12` | memory | 0x2c14d2 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x2c14b5: test %rax,%rax` | memory | 0x2c14d2 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x2c14ed: test %rax,%rax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x2c1507: test %rax,%rax` | memory | 0x2c151d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x2c150c: cmpq $0x2,0x10(%rax)` | memory | 0x2c151d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x2c155a: test %eax,%eax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x2c156f: test %rax,%rax` | call+memory | 0x2c194b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x2c1593: test %eax,%eax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x2c159b: cmpl $0x2,0x28(%rsp)` | memory | 0x2c1863 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x2c15d1: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x2c15ee: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x2c1625: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x2c162d: cmpq $0x0,0x8(%rsp)` | memory | 0x2c1659 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x2c163a: cmpl $0x0,0x18(%rax)` | memory | 0x2c1659 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x2c1651: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x2c166e: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x2c1689: test %eax,%eax` | memory | 0x2c1963 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x2c1691: cmpl $0x1,0x28(%rsp)` | memory | 0x2c197b | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x2c16b0: test %rdx,%rdx` | memory | 0x2c1842 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x2c16bd: test %rcx,%rcx` | memory | 0x2c1842 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x2c16ce: cmp 0x60ac3b(%rip),%rax        # 8cc310 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x3aaa10>` | memory | 0x2c16f8 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x2c16d7: test %rax,%rax` | call+memory | 0x2c14a8 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x2c1715: test %eax,%eax` | memory | 0x2c14ab | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x2c1730: test %eax,%eax` | memory | 0x2c14ab | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x2c1750: cmp %rdx,%rcx` | memory | 0x2c1842 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x2c1759: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2c1750 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x2c1784: test %eax,%eax` | memory | 0x2c184d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x2c1791: cmpl $0x0,0x18(%rax)` | memory | 0x2c17b4 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x2c17ac: test %eax,%eax` | memory | 0x2c14ab | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x2c17c7: cmp %rdx,%rcx` | memory | 0x2c1855 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x2c17d0: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2c17c7 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x2c17e6: test %rax,%rax` | memory | 0x2c189c | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x2c180b: test %rax,%rax` | call+memory | 0x2c1973 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x2c1871: test %rax,%rax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x2c1886: test %rax,%rax` | memory | 0x2c18a7 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x2c188b: cmpq $0x3,0x10(%rax)` | memory | 0x2c18a7 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x2c18e4: test %eax,%eax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x2c18f5: test %rax,%rax` | call+memory | 0x2c194b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x2c1915: test %eax,%eax` | memory | 0x2c194b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x2c1919: cmpl $0x3,0x28(%rsp)` | memory | 0x2c145b | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x2c198a: test %rax,%rax` | memory | 0x2c19a0 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x2c198f: cmpq $0x2,0x10(%rax)` | memory | 0x2c19a0 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x2c19b8: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x2c19d1: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x2c1a04: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x2c1a0c: cmpq $0x0,0x8(%rsp)` | memory | 0x2c1a38 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x2c1a19: cmpl $0x0,0x18(%rax)` | memory | 0x2c1a38 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x2c1a30: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x2c1a4d: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x2c1a68: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x2c1a70: cmpl $0x2,0x28(%rsp)` | memory | 0x2c169c | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x2c1a8a: test %rax,%rax` | memory | 0x2c1aa0 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x2c1a8f: cmpq $0x3,0x10(%rax)` | memory | 0x2c1aa0 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x2c1ab8: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x2c1ad5: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x2c1b0c: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x112a | je | mem | `0x2c1b14: cmpq $0x0,0x8(%rsp)` | memory | 0x2c1b40 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x2c1b21: cmpl $0x0,0x18(%rax)` | memory | 0x2c1b40 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x2c1b38: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x2c1b55: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x2c1b70: test %eax,%eax` | memory | 0x2c1963 | back |
| RSA CRT arms | +0x118d | je | mem | `0x2c1b78: cmpl $0x3,0x28(%rsp)` | memory | 0x2c169c | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x2bd9aa: test %r8,%r8` | memory | 0x2bdadb | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x2bdad2: dec %r8` | memory | 0x2bd9c0 | back |
