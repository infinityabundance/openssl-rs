# Binary branch audit — review aid, not a proof

- DSO: `court/tmp/pfp2-fix/distribution/libcrypto.so.3`
- SHA-256: `83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f`
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
| Montgomery multiply (core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith13mont_mul_into` @ 0x3434d0 | 1041 | 260 | 24 | 0 | 0 | 6 | 0 | 0 | 13 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x161da0 | 857 | 207 | 13 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | **missing** (`mod_exp_core_consttime_from_parts`) | | | | | | | | | | |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x536cc0 | 11101 | 2380 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x45ce70 | 3135 | 767 | 124 | 0 | 5 | 7 | 1 | 0 | 76 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x205570 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x460240 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x45e6b0 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x45e520 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |

## Coverage

- expected targets: 9
- resolved uniquely and disassembled: 8
- failed: 1
  - Constant-time ladder core (`mod_exp_core_consttime_from_parts`): missing

## Divisions

- none in any audited range.

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **29**
- of those inside the audited ranges: **0**
- first addresses: 0x169138, 0x169159, 0x16917a, 0x169191, 0x1691e3, 0x1691fa, 0x169385, 0x169493, 0x169539, 0x1696f8, 0x19ce8a, 0x19cf1c, 0x19d16c, 0x36462c, 0x36465c, 0x48d2ec, 0x48f3dc, 0x4b1d44, 0x4b1db2, 0x4b1e20

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (core) | +0x52 | je | reg/arith | `0x34351f: test %r14,%r14` | memory | 0x343728 | fwd |
| Montgomery multiply (core) | +0x74 | je | mem | `0x343540: cmp (%rsp),%rdi` | memory | 0x343863 | fwd |
| Montgomery multiply (core) | +0x93 | je | reg/arith | `0x343560: cmp %rbx,%r15` | memory | 0x3437c1 | fwd |
| Montgomery multiply (core) | +0xa0 | jae | reg/arith | `0x34356d: cmp %r12,%rax` | memory | 0x3437d4 | fwd |
| Montgomery multiply (core) | +0xcb | jne | reg/arith | `0x343598: cmp %rbx,%r14` | arithmetic/control | 0x343560 | back |
| Montgomery multiply (core) | +0xd3 | jae | reg/arith | `0x3435a0: cmp %r12,%rdi` | memory | 0x343877 | fwd |
| Montgomery multiply (core) | +0xec | jne | reg/arith | `0x3435b9: cmp %r14,%r10` | memory | 0x343540 | back |
| Montgomery multiply (core) | +0xf8 | jae | reg/arith | `0x3435c5: cmp %r12,%r10` | memory | 0x3437fa | fwd |
| Montgomery multiply (core) | +0x14c | je | reg/arith | `0x343619: cmp %r14,%rax` | arithmetic/control | 0x3436ba | fwd |
| Montgomery multiply (core) | +0x155 | je | reg/arith | `0x343622: cmp %r12,%r10` | memory | 0x3438aa | fwd |
| Montgomery multiply (core) | +0x183 | je | reg/arith | `0x343650: cmp %rdi,%rbx` | memory | 0x3437e7 | fwd |
| Montgomery multiply (core) | +0x1af | jne | reg/arith | `0x34367c: cmp %rdi,%r14` | memory | 0x343650 | back |
| Montgomery multiply (core) | +0x1bd | je | mem | `0x343688: cmp 0x10(%rsp),%r10` | memory | 0x343600 | back |
| Montgomery multiply (core) | +0x1e3 | jne | reg/arith | `0x3436b0: cmp %rax,%r15` | arithmetic/control | 0x3436a0 | back |
| Montgomery multiply (core) | +0x223 | je | reg/arith | `0x3436f0: cmp %rsi,%rbx` | memory | 0x3438bd | fwd |
| Montgomery multiply (core) | +0x24c | jne | reg/arith | `0x343719: cmp %rsi,%r14` | arithmetic/control | 0x3436f0 | back |
| Montgomery multiply (core) | +0x251 | jne | reg/arith | `0x34371e: test %rbp,%rbp` | arithmetic/control | 0x34374d | fwd |
| Montgomery multiply (core) | +0x25b | je | reg/arith | `0x343728: test %r12,%r12` | memory | 0x3438d0 | fwd |
| Montgomery multiply (core) | +0x27b | je | reg/arith | `0x343748: test %rbp,%rbp` | memory | 0x3437b2 | fwd |
| Montgomery multiply (core) | +0x2a7 | jae | reg/arith | `0x343774: cmp %r12,%rdi` | arithmetic/control | 0x34389a | fwd |
| Montgomery multiply (core) | +0x2b0 | je | reg/arith | `0x34377d: cmp %rsi,%rbx` | memory | 0x343887 | fwd |
| Montgomery multiply (core) | +0x2e0 | jne | reg/arith | `0x3437ac: add $0xfffffffffffffff8,%rbp` | arithmetic/control | 0x343770 | back |
| Montgomery multiply (core) | +0x343 | je | reg/arith | `0x343810: cmp %rsi,%r12` | memory | 0x343850 | fwd |
| Montgomery multiply (core) | +0x368 | jne | reg/arith | `0x343835: cmp %rsi,%r14` | memory | 0x343810 | back |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x161dd9: test %rbx,%rbx` | memory | 0x161e3e | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x161e16: cmpb $0x0,0x8(%rsp)` | memory | 0x161e83 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | je | reg/arith | `0x161e25: test %rbx,%rbx` | arithmetic/control | 0x161e74 | fwd |
| Montgomery multiply (allocating wrapper) | +0xc6 | je | mem | `0x161e61: cmpb $0x0,0x8(%rsp)` | memory | 0x161f97 | fwd |
| Montgomery multiply (allocating wrapper) | +0xf2 | jne | reg/arith | `0x161e8f: test %rbx,%rbx` | memory | 0x161fcf | fwd |
| Montgomery multiply (allocating wrapper) | +0x148 | je | reg/arith | `0x161ee5: test %rbx,%rbx` | memory | 0x161f39 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x161f23: cmp %rax,%rbx` | memory | 0x161ef0 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x161f73: cmp %rax,%r14` | arithmetic/control | 0x161f40 | back |
| Montgomery multiply (allocating wrapper) | +0x203 | je | reg/arith | `0x161f9f: cmp $0x1,%rbx` | memory | 0x161fc0 | fwd |
| Montgomery multiply (allocating wrapper) | +0x271 | je | mem | `0x16200c: cmpb $0x0,0x8(%rsp)` | memory | 0x162082 | fwd |
| Montgomery multiply (allocating wrapper) | +0x2c6 | jne | reg/arith | `0x162063: cmp %rax,%r14` | memory | 0x162030 | back |
| Montgomery multiply (allocating wrapper) | +0x2eb | jne | reg/arith | `0x162087: cmp $0x1,%rbx` | arithmetic/control | 0x162095 | fwd |
| Montgomery multiply (allocating wrapper) | +0x331 | jne | reg/arith | `0x1620ce: test %rbx,%rbx` | call | 0x1620db | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x536cd4: test %r8,%r8` | memory | 0x536d25 | fwd |
| Constant-time inversion | +0x1f | je | mem | `0x536cdc: testb $0x1,(%rcx)` | arithmetic/control | 0x536d25 | fwd |
| Constant-time inversion | +0x32 | jne | reg/arith | `0x536cee: shr $0x39,%rax` | call+memory | 0x536d25 | fwd |
| Constant-time inversion | +0x63 | je | mem | `0x536d1e: cmpb $0x0,0x10(%rsp)` | memory | 0x536d42 | fwd |
| Constant-time inversion | +0x8e | je | reg/arith | `0x536d4a: cmp $0x1,%rbx` | memory | 0x536d6b | fwd |
| Constant-time inversion | +0xea | je | mem | `0x536da5: cmpb $0x0,0x10(%rsp)` | memory | 0x536e0e | fwd |
| Constant-time inversion | +0x136 | jne | reg/arith | `0x536df3: cmp %rax,%rbx` | memory | 0x536dc0 | back |
| Constant-time inversion | +0x15a | je | reg/arith | `0x536e16: cmp $0x1,%rbx` | memory | 0x536e37 | fwd |
| Constant-time inversion | +0x1c0 | je | mem | `0x536e7b: cmpb $0x0,0x10(%rsp)` | memory | 0x536ed7 | fwd |
| Constant-time inversion | +0x202 | jne | reg/arith | `0x536ebf: cmp %rax,%rsi` | memory | 0x536e8c | back |
| Constant-time inversion | +0x22c | je | mem | `0x536edf: cmpq $0x1,(%rsp)` | memory | 0x536f17 | fwd |
| Constant-time inversion | +0x28b | je | mem | `0x536f46: cmpb $0x0,0x10(%rsp)` | memory | 0x536fd6 | fwd |
| Constant-time inversion | +0x2b5 | jne | reg/arith | `0x536f73: or %cl,%dl` | memory | 0x536fb5 | fwd |
| Constant-time inversion | +0x2ef | jne | reg/arith | `0x536fac: cmp %rax,%rsi` | memory | 0x536f81 | back |
| Constant-time inversion | +0x2f8 | je | reg/arith | `0x536fb5: test %rax,%rax` | memory | 0x536e82 | back |
| Constant-time inversion | +0x328 | je | mem | `0x536fe3: cmpq $0x1,(%rsp)` | memory | 0x537012 | fwd |
| Constant-time inversion | +0x37e | je | mem | `0x537039: cmpb $0x0,0x10(%rsp)` | memory | 0x5370d5 | fwd |
| Constant-time inversion | +0x3b1 | jne | reg/arith | `0x53706f: or %cl,%al` | memory | 0x5370ad | fwd |
| Constant-time inversion | +0x3eb | jne | reg/arith | `0x5370a8: cmp %rax,%rsi` | memory | 0x53707d | back |
| Constant-time inversion | +0x3f2 | je | mem | `0x5370ad: cmpq $0x0,(%rsp)` | memory | 0x5370c7 | fwd |
| Constant-time inversion | +0x421 | je | reg/arith | `0x5370dd: cmp $0x1,%rbx` | memory | 0x537101 | fwd |
| Constant-time inversion | +0x46d | je | mem | `0x537128: cmpb $0x0,0x10(%rsp)` | memory | 0x53713d | fwd |
| Constant-time inversion | +0x48b | je | reg/arith | `0x537147: cmp $0x1,%rbx` | memory | 0x53716f | fwd |
| Constant-time inversion | +0x4dd | je | reg/arith | `0x537199: cmp $0xffffffffffffffff,%rax` | call+memory | 0x537716 | fwd |
| Constant-time inversion | +0x524 | je | reg/arith | `0x5371e0: cmp $0xffffffffffffffff,%rax` | call+memory | 0x537724 | fwd |
| Constant-time inversion | +0x56b | je | reg/arith | `0x537227: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538f70 | fwd |
| Constant-time inversion | +0x5b2 | je | reg/arith | `0x53726e: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538f7e | fwd |
| Constant-time inversion | +0x5fa | je | reg/arith | `0x5372b6: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538f8c | fwd |
| Constant-time inversion | +0x642 | je | reg/arith | `0x5372fe: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538f9a | fwd |
| Constant-time inversion | +0x68a | je | reg/arith | `0x537346: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538fa8 | fwd |
| Constant-time inversion | +0x6cf | je | reg/arith | `0x53738b: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538fb6 | fwd |
| Constant-time inversion | +0x714 | je | reg/arith | `0x5373d0: cmp $0xffffffffffffffff,%rax` | call+memory | 0x538fc4 | fwd |
| Constant-time inversion | +0x759 | je | reg/arith | `0x537415: cmp $0xffffffffffffffff,%rax` | call+memory | 0x539275 | fwd |
| Constant-time inversion | +0x79f | je | reg/arith | `0x53745b: cmp $0xffffffffffffffff,%rax` | memory | 0x539280 | fwd |
| Constant-time inversion | +0xb14 | je | mem | `0x5377bc: cmp 0x2b0(%rsp),%rdx` | memory | 0x538fd2 | fwd |
| Constant-time inversion | +0xbcf | je | mem | `0x537886: cmpq $0x0,0x148(%rsp)` | memory | 0x5378e8 | fwd |
| Constant-time inversion | +0xc0e | je | reg/arith | `0x5378ca: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x5378ea | fwd |
| Constant-time inversion | +0xc13 | jae | reg/arith | `0x5378d0: cmp %rbx,%rcx` | memory | 0x5378dc | fwd |
| Constant-time inversion | +0xc21 | jb | reg/arith | `0x5378de: cmp %rbx,%rcx` | arithmetic/control | 0x53789f | back |
| Constant-time inversion | +0xc33 | je | mem | `0x5378ea: cmpq $0x0,0x140(%rsp)` | memory | 0x53794f | fwd |
| Constant-time inversion | +0xc71 | je | reg/arith | `0x53792d: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x53794f | fwd |
| Constant-time inversion | +0xc76 | jae | reg/arith | `0x537933: cmp %rbx,%rcx` | memory | 0x537943 | fwd |
| Constant-time inversion | +0xc88 | jb | reg/arith | `0x537945: cmp %rbx,%rcx` | arithmetic/control | 0x537904 | back |
| Constant-time inversion | +0xcdf | je | mem | `0x537996: cmpq $0x0,0x130(%rsp)` | memory | 0x537a8e | fwd |
| Constant-time inversion | +0xcee | je | mem | `0x5379a5: cmpq $0x0,0x270(%rsp)` | memory | 0x537a58 | fwd |
| Constant-time inversion | +0xd47 | je | reg/arith | `0x537a03: add $0xfffffffffffffffe,%r8` | memory | 0x537a47 | fwd |
| Constant-time inversion | +0xd58 | jae | reg/arith | `0x537a15: cmp %rbx,%rdi` | memory | 0x537a25 | fwd |
| Constant-time inversion | +0xd81 | jb | reg/arith | `0x537a3e: cmp %rbx,%rcx` | arithmetic/control | 0x5379da | back |
| Constant-time inversion | +0xd8f | je | mem | `0x537a47: testb $0x1,0x250(%rsp)` | memory | 0x537a8e | fwd |
| Constant-time inversion | +0xdbb | jae | reg/arith | `0x537a78: cmp %rbx,%rdi` | memory | 0x537a84 | fwd |
| Constant-time inversion | +0xdd7 | je | mem | `0x537a8e: cmpq $0x0,0x150(%rsp)` | memory | 0x537ba1 | fwd |
| Constant-time inversion | +0xde6 | je | mem | `0x537a9d: cmpq $0x0,0x268(%rsp)` | memory | 0x537b5f | fwd |
| Constant-time inversion | +0xe43 | je | reg/arith | `0x537aff: add $0xfffffffffffffffe,%r8` | memory | 0x537b4e | fwd |
| Constant-time inversion | +0xe5a | jae | mem | `0x537b12: cmp 0x148(%rsp),%rdi` | memory | 0x537b27 | fwd |
| Constant-time inversion | +0xe88 | jb | mem | `0x537b40: cmp 0x148(%rsp),%rcx` | arithmetic/control | 0x537ad6 | back |
| Constant-time inversion | +0xe96 | je | mem | `0x537b4e: testb $0x1,0x248(%rsp)` | memory | 0x537ba1 | fwd |
| Constant-time inversion | +0xec7 | jae | mem | `0x537b7f: cmp 0x148(%rsp),%rdi` | memory | 0x537b97 | fwd |
| Constant-time inversion | +0xf60 | je | reg/arith | `0x537c1c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x537c64 | fwd |
| Constant-time inversion | +0xf65 | jae | reg/arith | `0x537c22: cmp %rbx,%rcx` | memory | 0x537c2e | fwd |
| Constant-time inversion | +0xf78 | jae | mem | `0x537c30: cmp 0x130(%rsp),%rcx` | memory | 0x537c48 | fwd |
| Constant-time inversion | +0xf9e | jb | mem | `0x537c56: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x537bfb | back |
| Constant-time inversion | +0xfad | je | mem | `0x537c64: cmpq $0x0,0x130(%rsp)` | memory | 0x537d65 | fwd |
| Constant-time inversion | +0xfbc | je | mem | `0x537c73: cmpq $0x0,0x270(%rsp)` | memory | 0x537d2b | fwd |
| Constant-time inversion | +0x101a | je | reg/arith | `0x537cd6: add $0xfffffffffffffffe,%r8` | memory | 0x537d1a | fwd |
| Constant-time inversion | +0x102b | jae | reg/arith | `0x537ce8: cmp %rbx,%rdi` | memory | 0x537cf8 | fwd |
| Constant-time inversion | +0x1054 | jb | reg/arith | `0x537d11: cmp %rbx,%rcx` | arithmetic/control | 0x537cad | back |
| Constant-time inversion | +0x1062 | je | mem | `0x537d1a: testb $0x1,0x250(%rsp)` | memory | 0x537d65 | fwd |
| Constant-time inversion | +0x108e | jae | reg/arith | `0x537d4b: cmp %rbx,%rdi` | memory | 0x537d5b | fwd |
| Constant-time inversion | +0x10ae | je | mem | `0x537d65: cmpq $0x0,0x150(%rsp)` | memory | 0x537e78 | fwd |
| Constant-time inversion | +0x10bd | je | mem | `0x537d74: cmpq $0x0,0x268(%rsp)` | memory | 0x537e36 | fwd |
| Constant-time inversion | +0x111a | je | reg/arith | `0x537dd6: add $0xfffffffffffffffe,%r8` | memory | 0x537e25 | fwd |
| Constant-time inversion | +0x1131 | jae | mem | `0x537de9: cmp 0x140(%rsp),%rdi` | memory | 0x537dfe | fwd |
| Constant-time inversion | +0x115f | jb | mem | `0x537e17: cmp 0x140(%rsp),%rcx` | arithmetic/control | 0x537dad | back |
| Constant-time inversion | +0x116d | je | mem | `0x537e25: testb $0x1,0x248(%rsp)` | memory | 0x537e78 | fwd |
| Constant-time inversion | +0x119e | jae | mem | `0x537e56: cmp 0x140(%rsp),%rdi` | memory | 0x537e6e | fwd |
| Constant-time inversion | +0x121f | je | reg/arith | `0x537edb: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x537f27 | fwd |
| Constant-time inversion | +0x1224 | jae | reg/arith | `0x537ee1: cmp %rbx,%rcx` | memory | 0x537ef1 | fwd |
| Constant-time inversion | +0x123b | jae | mem | `0x537ef3: cmp 0x130(%rsp),%rcx` | memory | 0x537f0b | fwd |
| Constant-time inversion | +0x1261 | jb | mem | `0x537f19: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x537eba | back |
| Constant-time inversion | +0x1270 | je | mem | `0x537f27: cmpq $0x0,0x80(%rsp)` | memory | 0x537f3f | fwd |
| Constant-time inversion | +0x1297 | je | mem | `0x537f4e: cmpq $0x0,0x118(%rsp)` | memory | 0x53806f | fwd |
| Constant-time inversion | +0x12a6 | je | mem | `0x537f5d: cmpq $0x0,0x198(%rsp)` | memory | 0x538033 | fwd |
| Constant-time inversion | +0x1307 | je | reg/arith | `0x537fc3: add $0xfffffffffffffffe,%r8` | memory | 0x53801f | fwd |
| Constant-time inversion | +0x1321 | jae | mem | `0x537fd9: cmp 0x80(%rsp),%rdi` | memory | 0x537ff1 | fwd |
| Constant-time inversion | +0x1355 | jb | mem | `0x53800d: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x537f94 | back |
| Constant-time inversion | +0x1367 | je | mem | `0x53801f: testb $0x1,0x180(%rsp)` | memory | 0x53806f | fwd |
| Constant-time inversion | +0x1398 | jae | mem | `0x538050: cmp 0x80(%rsp),%rdi` | memory | 0x538065 | fwd |
| Constant-time inversion | +0x13b8 | je | mem | `0x53806f: cmpq $0x0,0x188(%rsp)` | memory | 0x5380d3 | fwd |
| Constant-time inversion | +0x13ef | je | reg/arith | `0x5380ab: add $0xfffffffffffffff8,%rax` | memory | 0x5380d3 | fwd |
| Constant-time inversion | +0x13f9 | jae | mem | `0x5380b1: cmp 0x80(%rsp),%rcx` | memory | 0x5380c6 | fwd |
| Constant-time inversion | +0x140c | jb | mem | `0x5380c8: cmp (%rsp),%rcx` | arithmetic/control | 0x538088 | back |
| Constant-time inversion | +0x141f | ja | mem | `0x5380db: cmp %rax,(%rsp)` | arithmetic/control | 0x539429 | fwd |
| Constant-time inversion | +0x1425 | jae | unknown | `?` | memory | 0x5394e3 | fwd |
| Constant-time inversion | +0x1431 | je | mem | `0x5380eb: cmpq $0x0,0x28(%rsp)` | memory | 0x5381c0 | fwd |
| Constant-time inversion | +0x144c | jne | mem | `0x538104: testb $0x8,0xa0(%rsp)` | memory | 0x53812f | fwd |
| Constant-time inversion | +0x145a | jae | mem | `0x538116: cmp (%rsp),%rax` | memory | 0x538139 | fwd |
| Constant-time inversion | +0x149a | je | mem | `0x538151: cmpq $0x0,0xa0(%rsp)` | memory | 0x5381c0 | fwd |
| Constant-time inversion | +0x14c8 | je | mem | `0x538183: cmp 0x30(%rsp),%rax` | memory | 0x5381c0 | fwd |
| Constant-time inversion | +0x14d5 | jae | mem | `0x538191: cmp (%rsp),%rdi` | memory | 0x5381a2 | fwd |
| Constant-time inversion | +0x14fa | jb | mem | `0x5381b6: cmp (%rsp),%rcx` | arithmetic/control | 0x538169 | back |
| Constant-time inversion | +0x1509 | je | mem | `0x5381c0: cmpq $0x0,0x118(%rsp)` | memory | 0x53828f | fwd |
| Constant-time inversion | +0x1518 | je | mem | `0x5381cf: cmpq $0x0,0x198(%rsp)` | memory | 0x538263 | fwd |
| Constant-time inversion | +0x1553 | je | mem | `0x53820b: cmp 0x1b0(%rsp),%rdx` | memory | 0x53824f | fwd |
| Constant-time inversion | +0x1560 | jae | mem | `0x53821b: cmp 0x28(%rsp),%rdx` | memory | 0x53822d | fwd |
| Constant-time inversion | +0x1589 | jb | mem | `0x538244: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x5381e7 | back |
| Constant-time inversion | +0x1597 | je | mem | `0x53824f: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x53828f | fwd |
| Constant-time inversion | +0x15af | jae | mem | `0x53826a: cmp 0x28(%rsp),%rax` | memory | 0x53827c | fwd |
| Constant-time inversion | +0x15d5 | je | mem | `0x53828f: cmpq $0x0,0x28(%rsp)` | memory | 0x5382fe | fwd |
| Constant-time inversion | +0x1611 | je | reg/arith | `0x5382cd: add $0xfffffffffffffff8,%rax` | memory | 0x5382f9 | fwd |
| Constant-time inversion | +0x161b | jae | mem | `0x5382d3: cmp 0x80(%rsp),%rcx` | memory | 0x5382e8 | fwd |
| Constant-time inversion | +0x1632 | jb | mem | `0x5382ea: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x5382a5 | back |
| Constant-time inversion | +0x1646 | je | mem | `0x538300: cmpq $0x0,0x68(%rsp)` | memory | 0x538377 | fwd |
| Constant-time inversion | +0x1688 | je | reg/arith | `0x538344: add $0xfffffffffffffff8,%rax` | memory | 0x538367 | fwd |
| Constant-time inversion | +0x168e | jae | mem | `0x53834a: cmp (%rsp),%rcx` | memory | 0x538359 | fwd |
| Constant-time inversion | +0x16a0 | jb | mem | `0x53835b: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x538317 | back |
| Constant-time inversion | +0x16cf | je | mem | `0x538386: cmpq $0x0,0x110(%rsp)` | memory | 0x53849c | fwd |
| Constant-time inversion | +0x16de | je | mem | `0x538395: cmpq $0x0,0x190(%rsp)` | memory | 0x538460 | fwd |
| Constant-time inversion | +0x173e | je | reg/arith | `0x5383fa: add $0xfffffffffffffffe,%r8` | memory | 0x53844c | fwd |
| Constant-time inversion | +0x1755 | jae | mem | `0x538410: cmp 0x68(%rsp),%rdi` | memory | 0x538425 | fwd |
| Constant-time inversion | +0x1786 | jb | mem | `0x538441: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x5383cb | back |
| Constant-time inversion | +0x1794 | je | mem | `0x53844c: testb $0x1,0x178(%rsp)` | memory | 0x53849c | fwd |
| Constant-time inversion | +0x17c2 | jae | mem | `0x53847d: cmp 0x68(%rsp),%rdi` | memory | 0x538492 | fwd |
| Constant-time inversion | +0x1811 | je | reg/arith | `0x5384cd: add $0xfffffffffffffff8,%rax` | memory | 0x5384f5 | fwd |
| Constant-time inversion | +0x1818 | jae | mem | `0x5384d3: cmp 0x68(%rsp),%rcx` | memory | 0x5384e8 | fwd |
| Constant-time inversion | +0x182e | jb | mem | `0x5384ea: cmp (%rsp),%rcx` | arithmetic/control | 0x5384aa | back |
| Constant-time inversion | +0x183b | je | mem | `0x5384f5: cmpq $0x0,0x28(%rsp)` | memory | 0x5385ca | fwd |
| Constant-time inversion | +0x1856 | jne | mem | `0x53850e: testb $0x8,0xa0(%rsp)` | memory | 0x538539 | fwd |
| Constant-time inversion | +0x1864 | jae | mem | `0x538520: cmp (%rsp),%rax` | memory | 0x538543 | fwd |
| Constant-time inversion | +0x18a4 | je | mem | `0x53855b: cmpq $0x0,0xa0(%rsp)` | memory | 0x5385ca | fwd |
| Constant-time inversion | +0x18d2 | je | mem | `0x53858d: cmp 0x30(%rsp),%rax` | memory | 0x5385ca | fwd |
| Constant-time inversion | +0x18df | jae | mem | `0x53859b: cmp (%rsp),%rdi` | memory | 0x5385ac | fwd |
| Constant-time inversion | +0x1904 | jb | mem | `0x5385c0: cmp (%rsp),%rcx` | arithmetic/control | 0x538573 | back |
| Constant-time inversion | +0x1913 | je | mem | `0x5385ca: cmpq $0x0,0x110(%rsp)` | memory | 0x538699 | fwd |
| Constant-time inversion | +0x1922 | je | mem | `0x5385d9: cmpq $0x0,0x190(%rsp)` | memory | 0x53866d | fwd |
| Constant-time inversion | +0x195d | je | mem | `0x538615: cmp 0x1a8(%rsp),%rdx` | memory | 0x538659 | fwd |
| Constant-time inversion | +0x196a | jae | mem | `0x538625: cmp 0x28(%rsp),%rdx` | memory | 0x538637 | fwd |
| Constant-time inversion | +0x1993 | jb | mem | `0x53864e: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x5385f1 | back |
| Constant-time inversion | +0x19a1 | je | mem | `0x538659: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x538699 | fwd |
| Constant-time inversion | +0x19b9 | jae | mem | `0x538674: cmp 0x28(%rsp),%rax` | memory | 0x538686 | fwd |
| Constant-time inversion | +0x1a04 | je | mem | `0x5386bb: cmpq $0x0,0x1f8(%rsp)` | memory | 0x538752 | fwd |
| Constant-time inversion | +0x1a53 | je | reg/arith | `0x53870f: add $0xfffffffffffffff8,%rax` | memory | 0x538752 | fwd |
| Constant-time inversion | +0x1a5d | jae | mem | `0x538715: cmp 0x80(%rsp),%rcx` | memory | 0x53872a | fwd |
| Constant-time inversion | +0x1a74 | jae | mem | `0x53872c: cmp 0x118(%rsp),%rcx` | memory | 0x538741 | fwd |
| Constant-time inversion | +0x1a8c | jb | mem | `0x538744: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x5386de | back |
| Constant-time inversion | +0x1a9b | je | mem | `0x538752: cmpq $0x0,0x88(%rsp)` | memory | 0x53876a | fwd |
| Constant-time inversion | +0x1ac2 | je | mem | `0x538779: cmpq $0x0,0x118(%rsp)` | memory | 0x53889a | fwd |
| Constant-time inversion | +0x1ad1 | je | mem | `0x538788: cmpq $0x0,0x198(%rsp)` | memory | 0x53885e | fwd |
| Constant-time inversion | +0x1b32 | je | reg/arith | `0x5387ee: add $0xfffffffffffffffe,%r8` | memory | 0x53884a | fwd |
| Constant-time inversion | +0x1b4c | jae | mem | `0x538804: cmp 0x88(%rsp),%rdi` | memory | 0x53881c | fwd |
| Constant-time inversion | +0x1b80 | jb | mem | `0x538838: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x5387bf | back |
| Constant-time inversion | +0x1b92 | je | mem | `0x53884a: testb $0x1,0x180(%rsp)` | memory | 0x53889a | fwd |
| Constant-time inversion | +0x1bc3 | jae | mem | `0x53887b: cmp 0x88(%rsp),%rdi` | memory | 0x538890 | fwd |
| Constant-time inversion | +0x1c0f | je | reg/arith | `0x5388cb: add $0xfffffffffffffff8,%rax` | memory | 0x5388f3 | fwd |
| Constant-time inversion | +0x1c19 | jae | mem | `0x5388d1: cmp 0x88(%rsp),%rcx` | memory | 0x5388e6 | fwd |
| Constant-time inversion | +0x1c2c | jb | mem | `0x5388e8: cmp (%rsp),%rcx` | arithmetic/control | 0x5388a8 | back |
| Constant-time inversion | +0x1c39 | je | mem | `0x5388f3: cmpq $0x0,0x28(%rsp)` | memory | 0x5389c8 | fwd |
| Constant-time inversion | +0x1c54 | jne | mem | `0x53890c: testb $0x8,0xa0(%rsp)` | memory | 0x538937 | fwd |
| Constant-time inversion | +0x1c62 | jae | mem | `0x53891e: cmp (%rsp),%rax` | memory | 0x538941 | fwd |
| Constant-time inversion | +0x1ca2 | je | mem | `0x538959: cmpq $0x0,0xa0(%rsp)` | memory | 0x5389c8 | fwd |
| Constant-time inversion | +0x1cd0 | je | mem | `0x53898b: cmp 0x30(%rsp),%rax` | memory | 0x5389c8 | fwd |
| Constant-time inversion | +0x1cdd | jae | mem | `0x538999: cmp (%rsp),%rdi` | memory | 0x5389aa | fwd |
| Constant-time inversion | +0x1d02 | jb | mem | `0x5389be: cmp (%rsp),%rcx` | arithmetic/control | 0x538971 | back |
| Constant-time inversion | +0x1d11 | je | mem | `0x5389c8: cmpq $0x0,0x118(%rsp)` | memory | 0x538a97 | fwd |
| Constant-time inversion | +0x1d20 | je | mem | `0x5389d7: cmpq $0x0,0x198(%rsp)` | memory | 0x538a6b | fwd |
| Constant-time inversion | +0x1d5b | je | mem | `0x538a13: cmp 0x1b0(%rsp),%rdx` | memory | 0x538a57 | fwd |
| Constant-time inversion | +0x1d68 | jae | mem | `0x538a23: cmp 0x28(%rsp),%rdx` | memory | 0x538a35 | fwd |
| Constant-time inversion | +0x1d91 | jb | mem | `0x538a4c: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x5389ef | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x538a57: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x538a97 | fwd |
| Constant-time inversion | +0x1db7 | jae | mem | `0x538a72: cmp 0x28(%rsp),%rax` | memory | 0x538a84 | fwd |
| Constant-time inversion | +0x1ddd | je | mem | `0x538a97: cmpq $0x0,0x28(%rsp)` | memory | 0x538b06 | fwd |
| Constant-time inversion | +0x1e19 | je | reg/arith | `0x538ad5: add $0xfffffffffffffff8,%rax` | memory | 0x538b01 | fwd |
| Constant-time inversion | +0x1e23 | jae | mem | `0x538adb: cmp 0x88(%rsp),%rcx` | memory | 0x538af0 | fwd |
| Constant-time inversion | +0x1e3a | jb | mem | `0x538af2: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x538aad | back |
| Constant-time inversion | +0x1e4e | je | mem | `0x538b08: cmpq $0x0,0x68(%rsp)` | memory | 0x538b7f | fwd |
| Constant-time inversion | +0x1e90 | je | reg/arith | `0x538b4c: add $0xfffffffffffffff8,%rax` | memory | 0x538b6f | fwd |
| Constant-time inversion | +0x1e96 | jae | mem | `0x538b52: cmp (%rsp),%rcx` | memory | 0x538b61 | fwd |
| Constant-time inversion | +0x1ea8 | jb | mem | `0x538b63: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x538b1f | back |
| Constant-time inversion | +0x1ed7 | je | mem | `0x538b8e: cmpq $0x0,0x110(%rsp)` | memory | 0x538ca4 | fwd |
| Constant-time inversion | +0x1ee6 | je | mem | `0x538b9d: cmpq $0x0,0x190(%rsp)` | memory | 0x538c68 | fwd |
| Constant-time inversion | +0x1f46 | je | reg/arith | `0x538c02: add $0xfffffffffffffffe,%r8` | memory | 0x538c54 | fwd |
| Constant-time inversion | +0x1f5d | jae | mem | `0x538c18: cmp 0x68(%rsp),%rdi` | memory | 0x538c2d | fwd |
| Constant-time inversion | +0x1f8e | jb | mem | `0x538c49: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x538bd3 | back |
| Constant-time inversion | +0x1f9c | je | mem | `0x538c54: testb $0x1,0x178(%rsp)` | memory | 0x538ca4 | fwd |
| Constant-time inversion | +0x1fca | jae | mem | `0x538c85: cmp 0x68(%rsp),%rdi` | memory | 0x538c9a | fwd |
| Constant-time inversion | +0x2019 | je | reg/arith | `0x538cd5: add $0xfffffffffffffff8,%rax` | memory | 0x538cfd | fwd |
| Constant-time inversion | +0x2020 | jae | mem | `0x538cdb: cmp 0x68(%rsp),%rcx` | memory | 0x538cf0 | fwd |
| Constant-time inversion | +0x2036 | jb | mem | `0x538cf2: cmp (%rsp),%rcx` | arithmetic/control | 0x538cb2 | back |
| Constant-time inversion | +0x2043 | je | mem | `0x538cfd: cmpq $0x0,0x28(%rsp)` | memory | 0x538dd2 | fwd |
| Constant-time inversion | +0x205e | jne | mem | `0x538d16: testb $0x8,0xa0(%rsp)` | memory | 0x538d41 | fwd |
| Constant-time inversion | +0x206c | jae | mem | `0x538d28: cmp (%rsp),%rax` | memory | 0x538d4b | fwd |
| Constant-time inversion | +0x20ac | je | mem | `0x538d63: cmpq $0x0,0xa0(%rsp)` | memory | 0x538dd2 | fwd |
| Constant-time inversion | +0x20da | je | mem | `0x538d95: cmp 0x30(%rsp),%rax` | memory | 0x538dd2 | fwd |
| Constant-time inversion | +0x20e7 | jae | mem | `0x538da3: cmp (%rsp),%rdi` | memory | 0x538db4 | fwd |
| Constant-time inversion | +0x210c | jb | mem | `0x538dc8: cmp (%rsp),%rcx` | arithmetic/control | 0x538d7b | back |
| Constant-time inversion | +0x211b | je | mem | `0x538dd2: cmpq $0x0,0x110(%rsp)` | memory | 0x538ea1 | fwd |
| Constant-time inversion | +0x212a | je | mem | `0x538de1: cmpq $0x0,0x190(%rsp)` | memory | 0x538e75 | fwd |
| Constant-time inversion | +0x2165 | je | mem | `0x538e1d: cmp 0x1a8(%rsp),%rdx` | memory | 0x538e61 | fwd |
| Constant-time inversion | +0x2172 | jae | mem | `0x538e2d: cmp 0x28(%rsp),%rdx` | memory | 0x538e3f | fwd |
| Constant-time inversion | +0x219b | jb | mem | `0x538e56: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x538df9 | back |
| Constant-time inversion | +0x21a9 | je | mem | `0x538e61: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x538ea1 | fwd |
| Constant-time inversion | +0x21c1 | jae | mem | `0x538e7c: cmp 0x28(%rsp),%rax` | memory | 0x538e8e | fwd |
| Constant-time inversion | +0x2226 | je | reg/arith | `0x538ee3: test %rax,%rax` | memory | 0x537732 | back |
| Constant-time inversion | +0x226d | je | reg/arith | `0x538f29: add $0xfffffffffffffff8,%rax` | memory | 0x537732 | back |
| Constant-time inversion | +0x227b | jae | mem | `0x538f33: cmp 0x88(%rsp),%rcx` | memory | 0x538f48 | fwd |
| Constant-time inversion | +0x2292 | jae | mem | `0x538f4a: cmp 0x118(%rsp),%rcx` | memory | 0x538f5f | fwd |
| Constant-time inversion | +0x22aa | jb | mem | `0x538f62: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x538ef8 | back |
| Constant-time inversion | +0x231d | je | reg/arith | `0x538fd9: cmp $0x1,%rbx` | memory | 0x53906d | fwd |
| Constant-time inversion | +0x2337 | jb | reg/arith | `0x538ff3: cmp $0x18,%rdx` | memory | 0x53905c | fwd |
| Constant-time inversion | +0x2383 | jne | reg/arith | `0x539040: cmp %rcx,%rdx` | arithmetic/control | 0x539026 | back |
| Constant-time inversion | +0x239a | je | reg/arith | `0x539057: cmp %rdx,%rsi` | memory | 0x53906d | fwd |
| Constant-time inversion | +0x23ab | jne | mem | `0x539063: cmp 0x2b8(%rsp),%rax` | memory | 0x53905c | back |
| Constant-time inversion | +0x2414 | je | reg/arith | `0x5390d0: cmp $0xffffffffffffffff,%rax` | memory | 0x53928b | fwd |
| Constant-time inversion | +0x2431 | jne | mem | `0x5390e9: cmp 0x138(%rsp),%rdi` | memory | 0x5394c9 | fwd |
| Constant-time inversion | +0x257f | je | reg/arith | `0x53923c: test %r12,%r12` | memory | 0x539407 | fwd |
| Constant-time inversion | +0x2592 | je | mem | `0x53924d: cmpq $0x0,(%rsp)` | memory | 0x536d2d | back |
| Constant-time inversion | +0x2732 | jne | reg/arith | `0x5393ef: cmp %rax,%rsi` | memory | 0x5393c3 | back |
| Constant-time inversion | +0x2981 | je | mem | `0x53963c: cmpq $0x0,(%rsp)` | memory | 0x5396a3 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x45ce90: test %rcx,%rcx` | memory | 0x45cf04 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x45cea0: test %rax,%rax` | memory | 0x45cef8 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x45ceac: cmp (%r15),%rcx` | memory | 0x45ceff | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x45ceb5: test %ecx,%ecx` | memory | 0x45cec5 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x45cebd: test %edx,%edx` | arithmetic/control | 0x45cec5 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x45cec1: cmp %edx,%ecx` | call | 0x45ceff | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x45cecd: test %eax,%eax` | memory | 0x45cf04 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x45ced9: test %rax,%rax` | memory | 0x45d032 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x45cee2: cmp (%r12),%rcx` | memory | 0x45d273 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x45cf0f: test %rcx,%rcx` | memory | 0x45d010 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x45cf30: cmp %rdx,%rcx` | memory | 0x45d010 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x45cf39: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x45cf30 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x45cf4f: test %rcx,%rcx` | memory | 0x45d010 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x45cf70: cmp %rdx,%rcx` | memory | 0x45d010 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x45cf79: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x45cf70 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x45cf8d: test %r13,%r13` | memory | 0x45d029 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x45cf9a: cmpq $0x0,0x50(%rax)` | memory | 0x45d040 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x45cfbc: test %rax,%rax` | memory | 0x45d00b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x45cfd7: test %rax,%rax` | call | 0x45cfe5 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x45cfe1: test %eax,%eax` | call+memory | 0x45d058 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x45d04f: test %r13,%r13` | memory | 0x45d19d | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x45d05c: cmpq $0x0,0x50(%rax)` | memory | 0x45d194 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x45d083: test %rax,%rax` | memory | 0x45d1d1 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x45d0a2: test %rax,%rax` | call | 0x45d1ab | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x45d0b0: test %eax,%eax` | memory | 0x45d1ab | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x45d0c2: test %r14,%r14` | arithmetic/control | 0x45d28c | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x45d0cb: test %r15,%r15` | memory | 0x45d297 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x45d0de: test %rcx,%rcx` | memory | 0x45d118 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x45d0e7: test %rax,%rax` | memory | 0x45d118 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x45d0f3: cmp (%r15),%rcx` | memory | 0x45d118 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x45d0fc: test %ecx,%ecx` | memory | 0x45d3da | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x45d108: test %edx,%edx` | arithmetic/control | 0x45d3da | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x45d110: cmp %ecx,%edx` | call | 0x45d3da | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x45d132: test %rax,%rax` | memory | 0x45d145 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x45d13b: test %rax,%rax` | call | 0x45d145 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x45d176: test %rbx,%rbx` | memory | 0x45d3ae | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x45d183: test %rcx,%rcx` | arithmetic/control | 0x45d259 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x45d1f2: test %bpl,%bpl` | memory | 0x45d238 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x45d1ff: test %rax,%rax` | memory | 0x45d212 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x45d208: test %rax,%rax` | call | 0x45d212 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x45d243: test %rbx,%rbx` | memory | 0x45d017 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x45d250: test %rcx,%rcx` | memory | 0x45d017 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x45d2a4: test %eax,%eax` | memory | 0x45d3b6 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x45d2b0: test %rax,%rax` | memory | 0x45d2b9 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x45d2bd: test %rax,%rax` | memory | 0x45d2c6 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x45d2ca: test %rax,%rax` | memory | 0x45d2d3 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x45d2d8: test %rax,%rax` | memory | 0x45d2e1 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x45d2e6: test %rax,%rax` | memory | 0x45d2ef | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x45d2f4: test %rax,%rax` | memory | 0x45d2fd | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x45d306: test %rax,%rax` | memory | 0x45d30f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x45d318: test %rax,%rax` | memory | 0x45d321 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x45d32a: test %rax,%rax` | call+memory | 0x45d333 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x45d35b: test %rax,%rax` | memory | 0x45d3c2 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x45d379: test %eax,%eax` | memory | 0x45d3ce | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x45d38a: test %r15,%r15` | memory | 0x45d3f8 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x45d393: test $0xffffffff80000000,%rax` | memory | 0x45d40b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x45d3da: cmp %r15,%r14` | call | 0x45d2ac | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x45d3eb: test %eax,%eax` | arithmetic/control | 0x45d2ac | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x45d416: test $0x1,%al` | memory | 0x45da41 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x45d423: test %eax,%eax` | memory | 0x45d451 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x45d42e: cmp %rsi,(%rdi)` | call+memory | 0x45d45b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x45d443: test %al,%cl` | arithmetic/control | 0x45d464 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x45d451: test %r15,%r15` | arithmetic/control | 0x45d479 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x45d45b: test %r15,%r15` | memory | 0x45d547 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x45d464: cmp %rsi,(%r15)` | call | 0x45d479 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x45d471: test %al,%al` | memory | 0x45d547 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x45d48a: test %rax,%rax` | memory | 0x45d553 | fwd |
| ECDSA scalar ladder (driver) | +0x638 | jg | mem | `0x45d4a1: cmp 0x2c(%rsp),%eax` | memory | 0x45d4b0 | fwd |
| ECDSA scalar ladder (driver) | +0x63e | je | mem | `0x45d4aa: cmpl $0x0,0x18(%rbp)` | memory | 0x45d4cc | fwd |
| ECDSA scalar ladder (driver) | +0x656 | je | reg/arith | `0x45d4c4: test %eax,%eax` | memory | 0x45d55f | fwd |
| ECDSA scalar ladder (driver) | +0x674 | je | reg/arith | `0x45d4e2: test %eax,%eax` | memory | 0x45d56b | fwd |
| ECDSA scalar ladder (driver) | +0x692 | je | reg/arith | `0x45d500: test %eax,%eax` | memory | 0x45d743 | fwd |
| ECDSA scalar ladder (driver) | +0x6a6 | js | mem | `0x45d511: cmpl $0x0,0x2c(%rsp)` | memory | 0x45d577 | fwd |
| ECDSA scalar ladder (driver) | +0x6b8 | jae | mem | `0x45d524: cmp 0x10(%rcx),%rax` | memory | 0x45d577 | fwd |
| ECDSA scalar ladder (driver) | +0x725 | je | reg/arith | `0x45d592: test %rax,%rax` | memory | 0x45d5af | fwd |
| ECDSA scalar ladder (driver) | +0x752 | je | reg/arith | `0x45d5bf: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x762 | jae | mem | `0x45d5cf: cmp %rax,(%rdi)` | call | 0x45d5e4 | fwd |
| ECDSA scalar ladder (driver) | +0x76e | je | reg/arith | `0x45d5dc: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x780 | je | reg/arith | `0x45d5ed: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x789 | jae | mem | `0x45d5f6: cmp %r15,(%rdi)` | call | 0x45d60b | fwd |
| ECDSA scalar ladder (driver) | +0x795 | je | reg/arith | `0x45d603: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x7a7 | je | reg/arith | `0x45d614: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x7b0 | jae | mem | `0x45d61d: cmp %r15,(%rdi)` | call | 0x45d632 | fwd |
| ECDSA scalar ladder (driver) | +0x7bc | je | reg/arith | `0x45d62a: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x7ca | je | reg/arith | `0x45d637: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x7d3 | jae | mem | `0x45d640: cmp %r15,(%rdi)` | call | 0x45d655 | fwd |
| ECDSA scalar ladder (driver) | +0x7df | je | reg/arith | `0x45d64d: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x7ed | je | reg/arith | `0x45d65a: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x7f6 | jae | mem | `0x45d663: cmp %r15,(%rdi)` | call | 0x45d678 | fwd |
| ECDSA scalar ladder (driver) | +0x802 | je | reg/arith | `0x45d670: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x810 | je | reg/arith | `0x45d67d: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x819 | jae | mem | `0x45d686: cmp %r15,(%rdi)` | call | 0x45d69b | fwd |
| ECDSA scalar ladder (driver) | +0x825 | je | reg/arith | `0x45d693: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x837 | je | reg/arith | `0x45d6a4: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x840 | jae | mem | `0x45d6ad: cmp %r15,(%rdi)` | call | 0x45d6c2 | fwd |
| ECDSA scalar ladder (driver) | +0x84c | je | reg/arith | `0x45d6ba: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x85e | je | reg/arith | `0x45d6cb: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x867 | jae | mem | `0x45d6d4: cmp %r15,(%rdi)` | call | 0x45d6e9 | fwd |
| ECDSA scalar ladder (driver) | +0x873 | je | reg/arith | `0x45d6e1: test %al,%al` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x885 | je | reg/arith | `0x45d6f2: test %rdi,%rdi` | memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0x893 | jae | mem | `0x45d6fb: cmp %r15,(%rdi)` | call | 0x45d715 | fwd |
| ECDSA scalar ladder (driver) | +0x89f | je | reg/arith | `0x45d70d: test %al,%al` | memory | 0x45d124 | back |
| ECDSA scalar ladder (driver) | +0x8aa | je | mem | `0x45d715: cmpl $0x0,0x28(%r14)` | call+memory | 0x45d888 | fwd |
| ECDSA scalar ladder (driver) | +0x8be | je | reg/arith | `0x45d72c: test %al,%al` | memory | 0x45d74f | fwd |
| ECDSA scalar ladder (driver) | +0x8ed | jne | reg/arith | `0x45d759: cmp $0x4,%rdx` | memory | 0x45d80b | fwd |
| ECDSA scalar ladder (driver) | +0x92b | jne | reg/arith | `0x45d797: cmp $0x1,%dil` | memory | 0x45d80d | fwd |
| ECDSA scalar ladder (driver) | +0x936 | jne | reg/arith | `0x45d7a4: cmp $0xff,%al` | call+memory | 0x45d7af | fwd |
| ECDSA scalar ladder (driver) | +0x962 | je | reg/arith | `0x45d7d0: test %eax,%eax` | call+memory | 0x45d9a2 | fwd |
| ECDSA scalar ladder (driver) | +0x989 | jne | reg/arith | `0x45d7f7: test %eax,%eax` | memory | 0x45d9c6 | fwd |
| ECDSA scalar ladder (driver) | +0x99f | je | reg/arith | `0x45d80d: test %cl,%cl` | arithmetic/control | 0x45d8c6 | fwd |
| ECDSA scalar ladder (driver) | +0x9a8 | jne | reg/arith | `0x45d815: test %sil,%sil` | memory | 0x45d8c6 | fwd |
| ECDSA scalar ladder (driver) | +0x9f8 | je | mem | `0x45d85f: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x45da01 | fwd |
| ECDSA scalar ladder (driver) | +0xa2d | je | reg/arith | `0x45d89a: test %rax,%rax` | call+memory | 0x45d8bc | fwd |
| ECDSA scalar ladder (driver) | +0xa41 | jne | reg/arith | `0x45d8af: test %eax,%eax` | arithmetic/control | 0x45d720 | back |
| ECDSA scalar ladder (driver) | +0xa79 | je | reg/arith | `0x45d8e7: test %eax,%eax` | memory | 0x45d9a2 | fwd |
| ECDSA scalar ladder (driver) | +0xa83 | jo | mem | `0x45d8ef: decl 0x2c(%rsp)` | arithmetic/control | 0x45da50 | fwd |
| ECDSA scalar ladder (driver) | +0xa89 | js | unknown | `?` | memory | 0x45d9ab | fwd |
| ECDSA scalar ladder (driver) | +0xab2 | jae | mem | `0x45d91e: cmp 0x10(%rcx),%rax` | memory | 0x45d93c | fwd |
| ECDSA scalar ladder (driver) | +0xae7 | je | mem | `0x45d951: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x45d970 | fwd |
| ECDSA scalar ladder (driver) | +0xb1a | je | reg/arith | `0x45d988: test %eax,%eax` | memory | 0x45da16 | fwd |
| ECDSA scalar ladder (driver) | +0xb2a | jg | reg/arith | `0x45d993: test %rbp,%rbp` | arithmetic/control | 0x45d90f | back |
| ECDSA scalar ladder (driver) | +0xb64 | je | reg/arith | `0x45d9d1: test %rax,%rax` | call+memory | 0x45d9ef | fwd |
| ECDSA scalar ladder (driver) | +0xb7d | je | reg/arith | `0x45d9eb: test %eax,%eax` | call+memory | 0x45da0f | fwd |
| ECDSA scalar ladder (driver) | +0xbc6 | jne | reg/arith | `0x45da33: test %rax,%rax` | arithmetic/control | 0x45d137 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x2055e7: test %rax,%rax` | memory | 0x205b85 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x205602: test %rbp,%rbp` | memory | 0x205b85 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x205612: test %rax,%rax` | call+memory | 0x205b85 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x205634: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x205652: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x205670: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x20568e: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x2056b4: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x2056d4: test %eax,%eax` | arithmetic/control | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x2056dc: test %r15,%r15` | memory | 0x205702 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x2056ee: test %rdx,%rdx` | arithmetic/control | 0x205724 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x20571a: test %rdx,%rdx` | memory | 0x205730 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x205733: sub $0x1,%r9` | memory | 0x205757 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x205739: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x205730 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x205750: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x205760 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x20575a: sub $0x1,%r8` | arithmetic/control | 0x205750 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x205760: cmp %r9,%rdi` | memory | 0x205780 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x205770: sub $0x1,%rdi` | memory | 0x205782 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x20577a: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x205770 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x20579d | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x205795: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x2057af: test %eax,%eax` | arithmetic/control | 0x205b85 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x2057bc: test %r15,%r15` | memory | 0x2057cb | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x2057e3: sub $0x1,%rdi` | memory | 0x205807 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x2057e9: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x2057e0 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x205800: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x205810 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x20580a: sub $0x1,%rsi` | arithmetic/control | 0x205800 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x205810: cmp %rdi,%rdx` | arithmetic/control | 0x205825 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x205815: sub $0x1,%rdx` | memory | 0x205827 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x20581f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x205815 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x20583e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x205836: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x205853: test %eax,%eax` | memory | 0x205b85 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x20586d: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x205890: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x2058ab: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x2058c5: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x2058e7: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x205901: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x205924: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x205946: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x205968: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x20598a: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x2059a4: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x2059c0: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x2059e4: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x2059fe: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x205a1d: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x205a3c: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x205a5b: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x205a75: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x205a94: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x205ab1: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x205ad6: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x205af5: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x205b11: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x205b2a: test %eax,%eax` | call+memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x205b43: test %eax,%eax` | memory | 0x205b83 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x205b59: test %eax,%eax` | memory | 0x205b85 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x205b85: test %rbx,%rbx` | memory | 0x205ba8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x205b8e: test %rax,%rax` | memory | 0x205ba8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x46028b: test %rax,%rax` | memory | 0x460cf8 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x4602a5: cmpl $0x1,0x10(%rbp)` | memory | 0x4602cd | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x4602b5: test %rax,%rax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x4602c4: cmp $0xfffffffd,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x4602d5: testb $0x4,0xa4(%rbp)` | memory | 0x4602f5 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x4602de: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x460356 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x4602e7: test %r13b,%r13b` | arithmetic/control | 0x460430 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x4602fb: test %rax,%rax` | memory | 0x460cf8 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x460329: test %rax,%rax` | arithmetic/control | 0x460840 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x460332: test %r15,%r15` | memory | 0x460340 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x46034a: test %rax,%rax` | arithmetic/control | 0x4603b8 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x460373: test %r15,%r15` | arithmetic/control | 0x460410 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x46037c: test %r14,%r14` | memory | 0x46038a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x460391: test %r15,%r15` | memory | 0x460402 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x4603ab: test %eax,%eax` | memory | 0x4603f6 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x4603d4: test %eax,%eax` | memory | 0x460817 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x460402: test %r14,%r14` | memory | 0x460410 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x460416: or %r13b,%al` | arithmetic/control | 0x460642 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x460427: test %r15,%r15` | memory | 0x460cf8 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x460436: test %rax,%rax` | memory | 0x460cf8 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x460479: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x460487: test %rax,%rax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x4604ad: test %rax,%rax` | call+memory | 0x4611a0 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x4604d6: test %eax,%eax` | call+memory | 0x4611a0 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x460524: test %al,0x38(%rsp)` | memory | 0x4605a3 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x460535: test %rax,%rax` | memory | 0x460cf8 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x46055b: test %rax,%rax` | call+memory | 0x460bf2 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x460595: test %ebp,%ebp` | arithmetic/control | 0x460cfb | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x4605a5: test %ebx,%ebx` | memory | 0x460a5e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x4605b7: test %r15b,%r15b` | call+memory | 0x460a68 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x4605de: test %r13,%r13` | arithmetic/control | 0x46119b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x4605ec: test %rax,%rax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x4605fe: test %rax,%rax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x46060e: test %rcx,%rcx` | memory | 0x460bff | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x460626: cmpq $0x0,0x10(%rcx)` | memory | 0x460c09 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x460667: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x460685: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x4606af: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x4606cd: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x460706: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x460728: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x460741: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x460749: test %rbx,%rbx` | memory | 0x460794 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x460758: cmpl $0x0,0x18(%rbx)` | memory | 0x460794 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x46076e: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x460776: cmpl $0x0,0x18(%rbx)` | memory | 0x460794 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x46078c: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x4607aa: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x4607cc: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x4607e9: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x460827: test %r15,%r15` | memory | 0x460835 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x460835: test %bl,%bl` | memory | 0x4608e8 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x460862: test %rax,%rax` | arithmetic/control | 0x4608f0 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x46086b: test %r15,%r15` | memory | 0x460879 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x460883: test %rax,%rax` | arithmetic/control | 0x46088c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x4608a8: test %eax,%eax` | memory | 0x4608c3 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x4608d3: test %r15,%r15` | memory | 0x4608e1 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x4608e1: test %bl,%bl` | arithmetic/control | 0x4608f0 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x4608fa: test %ebx,%ebx` | memory | 0x4609eb | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x460929: test %bl,%bl` | arithmetic/control | 0x460a51 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x460934: cmp %r14,%r13` | memory | 0x4609eb | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x460968: test %rax,%rax` | arithmetic/control | 0x460931 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x46096d: test %r15,%r15` | memory | 0x46097b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x46097f: test %rax,%rax` | arithmetic/control | 0x46098d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x460986: test %r15,%r15` | arithmetic/control | 0x460920 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x4609a2: test %eax,%eax` | memory | 0x4609c8 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x4609ba: test %r15,%r15` | arithmetic/control | 0x460920 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x4609dd: test %r15,%r15` | arithmetic/control | 0x460920 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x4609f9: test %ebx,%ebx` | memory | 0x460a44 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x460a05: cmp 0x45b96c(%rip),%rax        # 8bc378 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x591788>` | call+memory | 0x4602de | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x460a6d: test %al,%r14b` | memory | 0x460cef | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x460aa3: test %eax,%eax` | arithmetic/control | 0x460cfb | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x460aab: test %rbx,%rbx` | memory | 0x460ace | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x460ab0: cmpl $0x0,0x18(%rbx)` | memory | 0x460ace | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x460ac6: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x460ae3: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x460af1: test %rax,%rax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x460b3d: test %ebp,%ebp` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x460b45: test %rbx,%rbx` | memory | 0x460b6d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x460b4f: cmpl $0x0,0x18(%rbx)` | memory | 0x460b6d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x460b65: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x460b85: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x460b9e: test %eax,%eax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x460ba6: cmpl $0x0,0x28(%rsp)` | memory | 0x460efc | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x460bbc: test %rax,%rax` | memory | 0x460cfb | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x460bd2: test %rax,%rax` | memory | 0x460e09 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x460bdb: cmpq $0x0,0x10(%rax)` | memory | 0x460e09 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x460c4d: test %eax,%eax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x460c62: test %rax,%rax` | call+memory | 0x46119b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x460c86: test %eax,%eax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x460c8e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x460d34 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x460ce6: test %al,%r14b` | arithmetic/control | 0x460a76 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x460cef: test %r15b,%r15b` | arithmetic/control | 0x460efc | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x460cfb: test %r12,%r12` | memory | 0x460d22 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x460d05: test %rax,%rax` | memory | 0x460d22 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x460d3d: test %rax,%rax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x460d57: test %rax,%rax` | memory | 0x460d6d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x460d5c: cmpq $0x2,0x10(%rax)` | memory | 0x460d6d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x460daa: test %eax,%eax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x460dbf: test %rax,%rax` | call+memory | 0x46119b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x460de3: test %eax,%eax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x460deb: cmpl $0x2,0x28(%rsp)` | memory | 0x4610b3 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x460e21: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x460e3e: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x460e75: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x460e7d: cmpq $0x0,0x8(%rsp)` | memory | 0x460ea9 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x460e8a: cmpl $0x0,0x18(%rax)` | memory | 0x460ea9 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x460ea1: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x460ebe: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x460ed9: test %eax,%eax` | memory | 0x4611b3 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x460ee1: cmpl $0x1,0x28(%rsp)` | memory | 0x4611cb | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x460f00: test %rdx,%rdx` | memory | 0x461092 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x460f0d: test %rcx,%rcx` | memory | 0x461092 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x460f1e: cmp 0x45b453(%rip),%rax        # 8bc378 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x591788>` | memory | 0x460f48 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x460f27: test %rax,%rax` | call+memory | 0x460cf8 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x460f65: test %eax,%eax` | memory | 0x460cfb | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x460f80: test %eax,%eax` | memory | 0x460cfb | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x460fa0: cmp %rdx,%rcx` | memory | 0x461092 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x460fa9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x460fa0 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x460fd4: test %eax,%eax` | memory | 0x46109d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x460fe1: cmpl $0x0,0x18(%rax)` | memory | 0x461004 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x460ffc: test %eax,%eax` | memory | 0x460cfb | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x461017: cmp %rdx,%rcx` | memory | 0x4610a5 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x461020: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x461017 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x461036: test %rax,%rax` | memory | 0x4610ec | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x46105b: test %rax,%rax` | call+memory | 0x4611c3 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x4610c1: test %rax,%rax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x4610d6: test %rax,%rax` | memory | 0x4610f7 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x4610db: cmpq $0x3,0x10(%rax)` | memory | 0x4610f7 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x461134: test %eax,%eax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x461145: test %rax,%rax` | call+memory | 0x46119b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x461165: test %eax,%eax` | memory | 0x46119b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x461169: cmpl $0x3,0x28(%rsp)` | memory | 0x460cab | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x4611da: test %rax,%rax` | memory | 0x4611f0 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x4611df: cmpq $0x2,0x10(%rax)` | memory | 0x4611f0 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x461208: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x461221: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x461254: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x46125c: cmpq $0x0,0x8(%rsp)` | memory | 0x461288 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x461269: cmpl $0x0,0x18(%rax)` | memory | 0x461288 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x461280: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x46129d: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x4612b8: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x4612c0: cmpl $0x2,0x28(%rsp)` | memory | 0x460eec | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x4612da: test %rax,%rax` | memory | 0x4612f0 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x4612df: cmpq $0x3,0x10(%rax)` | memory | 0x4612f0 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x461308: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x461325: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x46135c: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x112a | je | mem | `0x461364: cmpq $0x0,0x8(%rsp)` | memory | 0x461390 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x461371: cmpl $0x0,0x18(%rax)` | memory | 0x461390 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x461388: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x4613a5: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x4613c0: test %eax,%eax` | memory | 0x4611b3 | back |
| RSA CRT arms | +0x118d | je | mem | `0x4613c8: cmpl $0x3,0x28(%rsp)` | memory | 0x460eec | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x45e99a: test %r8,%r8` | memory | 0x45eacb | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x45eac2: dec %r8` | memory | 0x45e9b0 | back |
