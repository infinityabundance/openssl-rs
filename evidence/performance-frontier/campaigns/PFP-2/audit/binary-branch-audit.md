# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp2-recheck/distribution/libcrypto.so.3`
- SHA-256: `467527ae6a61fb217facd6f50bd1187fc25ce2dea3817d0b37c71bdd0ada9bf8`
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
| Montgomery multiply (core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith13mont_mul_into` @ 0x3e6460 | 1041 | 260 | 24 | 0 | 0 | 6 | 0 | 0 | 13 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x162380 | 857 | 207 | 13 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | **missing** (`mod_exp_core_consttime_from_parts`) | | | | | | | | | | |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x510f30 | 11101 | 2380 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x188380 | 3135 | 767 | 124 | 0 | 5 | 7 | 1 | 0 | 76 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x2a9ba0 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x18b9b0 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x189bc0 | 939 | 258 | 5 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x189a30 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |

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
- first addresses: 0x169128, 0x169149, 0x16916a, 0x169181, 0x1691d3, 0x1691ea, 0x169375, 0x169483, 0x169529, 0x1696e8, 0x1bb12c, 0x1bd0fc, 0x1e0214, 0x1e0282, 0x1e02f0, 0x1e035e, 0x2d841c, 0x2d844c, 0x3779aa, 0x377a3c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (core) | +0x52 | je | reg/arith | `0x3e64af: test %r14,%r14` | memory | 0x3e66b8 | fwd |
| Montgomery multiply (core) | +0x74 | je | mem | `0x3e64d0: cmp (%rsp),%rdi` | memory | 0x3e67f3 | fwd |
| Montgomery multiply (core) | +0x93 | je | reg/arith | `0x3e64f0: cmp %rbx,%r15` | memory | 0x3e6751 | fwd |
| Montgomery multiply (core) | +0xa0 | jae | reg/arith | `0x3e64fd: cmp %r12,%rax` | memory | 0x3e6764 | fwd |
| Montgomery multiply (core) | +0xcb | jne | reg/arith | `0x3e6528: cmp %rbx,%r14` | arithmetic/control | 0x3e64f0 | back |
| Montgomery multiply (core) | +0xd3 | jae | reg/arith | `0x3e6530: cmp %r12,%rdi` | memory | 0x3e6807 | fwd |
| Montgomery multiply (core) | +0xec | jne | reg/arith | `0x3e6549: cmp %r14,%r10` | memory | 0x3e64d0 | back |
| Montgomery multiply (core) | +0xf8 | jae | reg/arith | `0x3e6555: cmp %r12,%r10` | memory | 0x3e678a | fwd |
| Montgomery multiply (core) | +0x14c | je | reg/arith | `0x3e65a9: cmp %r14,%rax` | arithmetic/control | 0x3e664a | fwd |
| Montgomery multiply (core) | +0x155 | je | reg/arith | `0x3e65b2: cmp %r12,%r10` | memory | 0x3e683a | fwd |
| Montgomery multiply (core) | +0x183 | je | reg/arith | `0x3e65e0: cmp %rdi,%rbx` | memory | 0x3e6777 | fwd |
| Montgomery multiply (core) | +0x1af | jne | reg/arith | `0x3e660c: cmp %rdi,%r14` | memory | 0x3e65e0 | back |
| Montgomery multiply (core) | +0x1bd | je | mem | `0x3e6618: cmp 0x10(%rsp),%r10` | memory | 0x3e6590 | back |
| Montgomery multiply (core) | +0x1e3 | jne | reg/arith | `0x3e6640: cmp %rax,%r15` | arithmetic/control | 0x3e6630 | back |
| Montgomery multiply (core) | +0x223 | je | reg/arith | `0x3e6680: cmp %rsi,%rbx` | memory | 0x3e684d | fwd |
| Montgomery multiply (core) | +0x24c | jne | reg/arith | `0x3e66a9: cmp %rsi,%r14` | arithmetic/control | 0x3e6680 | back |
| Montgomery multiply (core) | +0x251 | jne | reg/arith | `0x3e66ae: test %rbp,%rbp` | arithmetic/control | 0x3e66dd | fwd |
| Montgomery multiply (core) | +0x25b | je | reg/arith | `0x3e66b8: test %r12,%r12` | memory | 0x3e6860 | fwd |
| Montgomery multiply (core) | +0x27b | je | reg/arith | `0x3e66d8: test %rbp,%rbp` | memory | 0x3e6742 | fwd |
| Montgomery multiply (core) | +0x2a7 | jae | reg/arith | `0x3e6704: cmp %r12,%rdi` | arithmetic/control | 0x3e682a | fwd |
| Montgomery multiply (core) | +0x2b0 | je | reg/arith | `0x3e670d: cmp %rsi,%rbx` | memory | 0x3e6817 | fwd |
| Montgomery multiply (core) | +0x2e0 | jne | reg/arith | `0x3e673c: add $0xfffffffffffffff8,%rbp` | arithmetic/control | 0x3e6700 | back |
| Montgomery multiply (core) | +0x343 | je | reg/arith | `0x3e67a0: cmp %rsi,%r12` | memory | 0x3e67e0 | fwd |
| Montgomery multiply (core) | +0x368 | jne | reg/arith | `0x3e67c5: cmp %rsi,%r14` | memory | 0x3e67a0 | back |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x1623b9: test %rbx,%rbx` | memory | 0x16241e | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x1623f6: cmpb $0x0,0x8(%rsp)` | memory | 0x162463 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | je | reg/arith | `0x162405: test %rbx,%rbx` | arithmetic/control | 0x162454 | fwd |
| Montgomery multiply (allocating wrapper) | +0xc6 | je | mem | `0x162441: cmpb $0x0,0x8(%rsp)` | memory | 0x162577 | fwd |
| Montgomery multiply (allocating wrapper) | +0xf2 | jne | reg/arith | `0x16246f: test %rbx,%rbx` | memory | 0x1625af | fwd |
| Montgomery multiply (allocating wrapper) | +0x148 | je | reg/arith | `0x1624c5: test %rbx,%rbx` | memory | 0x162519 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x162503: cmp %rax,%rbx` | memory | 0x1624d0 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x162553: cmp %rax,%r14` | arithmetic/control | 0x162520 | back |
| Montgomery multiply (allocating wrapper) | +0x203 | je | reg/arith | `0x16257f: cmp $0x1,%rbx` | memory | 0x1625a0 | fwd |
| Montgomery multiply (allocating wrapper) | +0x271 | je | mem | `0x1625ec: cmpb $0x0,0x8(%rsp)` | memory | 0x162662 | fwd |
| Montgomery multiply (allocating wrapper) | +0x2c6 | jne | reg/arith | `0x162643: cmp %rax,%r14` | memory | 0x162610 | back |
| Montgomery multiply (allocating wrapper) | +0x2eb | jne | reg/arith | `0x162667: cmp $0x1,%rbx` | arithmetic/control | 0x162675 | fwd |
| Montgomery multiply (allocating wrapper) | +0x331 | jne | reg/arith | `0x1626ae: test %rbx,%rbx` | call | 0x1626bb | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x510f44: test %r8,%r8` | memory | 0x510f95 | fwd |
| Constant-time inversion | +0x1f | je | mem | `0x510f4c: testb $0x1,(%rcx)` | arithmetic/control | 0x510f95 | fwd |
| Constant-time inversion | +0x32 | jne | reg/arith | `0x510f5e: shr $0x39,%rax` | call+memory | 0x510f95 | fwd |
| Constant-time inversion | +0x63 | je | mem | `0x510f8e: cmpb $0x0,0x10(%rsp)` | memory | 0x510fb2 | fwd |
| Constant-time inversion | +0x8e | je | reg/arith | `0x510fba: cmp $0x1,%rbx` | memory | 0x510fdb | fwd |
| Constant-time inversion | +0xea | je | mem | `0x511015: cmpb $0x0,0x10(%rsp)` | memory | 0x51107e | fwd |
| Constant-time inversion | +0x136 | jne | reg/arith | `0x511063: cmp %rax,%rbx` | memory | 0x511030 | back |
| Constant-time inversion | +0x15a | je | reg/arith | `0x511086: cmp $0x1,%rbx` | memory | 0x5110a7 | fwd |
| Constant-time inversion | +0x1c0 | je | mem | `0x5110eb: cmpb $0x0,0x10(%rsp)` | memory | 0x511147 | fwd |
| Constant-time inversion | +0x202 | jne | reg/arith | `0x51112f: cmp %rax,%rsi` | memory | 0x5110fc | back |
| Constant-time inversion | +0x22c | je | mem | `0x51114f: cmpq $0x1,(%rsp)` | memory | 0x511187 | fwd |
| Constant-time inversion | +0x28b | je | mem | `0x5111b6: cmpb $0x0,0x10(%rsp)` | memory | 0x511246 | fwd |
| Constant-time inversion | +0x2b5 | jne | reg/arith | `0x5111e3: or %cl,%dl` | memory | 0x511225 | fwd |
| Constant-time inversion | +0x2ef | jne | reg/arith | `0x51121c: cmp %rax,%rsi` | memory | 0x5111f1 | back |
| Constant-time inversion | +0x2f8 | je | reg/arith | `0x511225: test %rax,%rax` | memory | 0x5110f2 | back |
| Constant-time inversion | +0x328 | je | mem | `0x511253: cmpq $0x1,(%rsp)` | memory | 0x511282 | fwd |
| Constant-time inversion | +0x37e | je | mem | `0x5112a9: cmpb $0x0,0x10(%rsp)` | memory | 0x511345 | fwd |
| Constant-time inversion | +0x3b1 | jne | reg/arith | `0x5112df: or %cl,%al` | memory | 0x51131d | fwd |
| Constant-time inversion | +0x3eb | jne | reg/arith | `0x511318: cmp %rax,%rsi` | memory | 0x5112ed | back |
| Constant-time inversion | +0x3f2 | je | mem | `0x51131d: cmpq $0x0,(%rsp)` | memory | 0x511337 | fwd |
| Constant-time inversion | +0x421 | je | reg/arith | `0x51134d: cmp $0x1,%rbx` | memory | 0x511371 | fwd |
| Constant-time inversion | +0x46d | je | mem | `0x511398: cmpb $0x0,0x10(%rsp)` | memory | 0x5113ad | fwd |
| Constant-time inversion | +0x48b | je | reg/arith | `0x5113b7: cmp $0x1,%rbx` | memory | 0x5113df | fwd |
| Constant-time inversion | +0x4dd | je | reg/arith | `0x511409: cmp $0xffffffffffffffff,%rax` | call+memory | 0x511986 | fwd |
| Constant-time inversion | +0x524 | je | reg/arith | `0x511450: cmp $0xffffffffffffffff,%rax` | call+memory | 0x511994 | fwd |
| Constant-time inversion | +0x56b | je | reg/arith | `0x511497: cmp $0xffffffffffffffff,%rax` | call+memory | 0x5131e0 | fwd |
| Constant-time inversion | +0x5b2 | je | reg/arith | `0x5114de: cmp $0xffffffffffffffff,%rax` | call+memory | 0x5131ee | fwd |
| Constant-time inversion | +0x5fa | je | reg/arith | `0x511526: cmp $0xffffffffffffffff,%rax` | call+memory | 0x5131fc | fwd |
| Constant-time inversion | +0x642 | je | reg/arith | `0x51156e: cmp $0xffffffffffffffff,%rax` | call+memory | 0x51320a | fwd |
| Constant-time inversion | +0x68a | je | reg/arith | `0x5115b6: cmp $0xffffffffffffffff,%rax` | call+memory | 0x513218 | fwd |
| Constant-time inversion | +0x6cf | je | reg/arith | `0x5115fb: cmp $0xffffffffffffffff,%rax` | call+memory | 0x513226 | fwd |
| Constant-time inversion | +0x714 | je | reg/arith | `0x511640: cmp $0xffffffffffffffff,%rax` | call+memory | 0x513234 | fwd |
| Constant-time inversion | +0x759 | je | reg/arith | `0x511685: cmp $0xffffffffffffffff,%rax` | call+memory | 0x5134e5 | fwd |
| Constant-time inversion | +0x79f | je | reg/arith | `0x5116cb: cmp $0xffffffffffffffff,%rax` | memory | 0x5134f0 | fwd |
| Constant-time inversion | +0xb14 | je | mem | `0x511a2c: cmp 0x2b0(%rsp),%rdx` | memory | 0x513242 | fwd |
| Constant-time inversion | +0xbcf | je | mem | `0x511af6: cmpq $0x0,0x148(%rsp)` | memory | 0x511b58 | fwd |
| Constant-time inversion | +0xc0e | je | reg/arith | `0x511b3a: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x511b5a | fwd |
| Constant-time inversion | +0xc13 | jae | reg/arith | `0x511b40: cmp %rbx,%rcx` | memory | 0x511b4c | fwd |
| Constant-time inversion | +0xc21 | jb | reg/arith | `0x511b4e: cmp %rbx,%rcx` | arithmetic/control | 0x511b0f | back |
| Constant-time inversion | +0xc33 | je | mem | `0x511b5a: cmpq $0x0,0x140(%rsp)` | memory | 0x511bbf | fwd |
| Constant-time inversion | +0xc71 | je | reg/arith | `0x511b9d: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x511bbf | fwd |
| Constant-time inversion | +0xc76 | jae | reg/arith | `0x511ba3: cmp %rbx,%rcx` | memory | 0x511bb3 | fwd |
| Constant-time inversion | +0xc88 | jb | reg/arith | `0x511bb5: cmp %rbx,%rcx` | arithmetic/control | 0x511b74 | back |
| Constant-time inversion | +0xcdf | je | mem | `0x511c06: cmpq $0x0,0x130(%rsp)` | memory | 0x511cfe | fwd |
| Constant-time inversion | +0xcee | je | mem | `0x511c15: cmpq $0x0,0x270(%rsp)` | memory | 0x511cc8 | fwd |
| Constant-time inversion | +0xd47 | je | reg/arith | `0x511c73: add $0xfffffffffffffffe,%r8` | memory | 0x511cb7 | fwd |
| Constant-time inversion | +0xd58 | jae | reg/arith | `0x511c85: cmp %rbx,%rdi` | memory | 0x511c95 | fwd |
| Constant-time inversion | +0xd81 | jb | reg/arith | `0x511cae: cmp %rbx,%rcx` | arithmetic/control | 0x511c4a | back |
| Constant-time inversion | +0xd8f | je | mem | `0x511cb7: testb $0x1,0x250(%rsp)` | memory | 0x511cfe | fwd |
| Constant-time inversion | +0xdbb | jae | reg/arith | `0x511ce8: cmp %rbx,%rdi` | memory | 0x511cf4 | fwd |
| Constant-time inversion | +0xdd7 | je | mem | `0x511cfe: cmpq $0x0,0x150(%rsp)` | memory | 0x511e11 | fwd |
| Constant-time inversion | +0xde6 | je | mem | `0x511d0d: cmpq $0x0,0x268(%rsp)` | memory | 0x511dcf | fwd |
| Constant-time inversion | +0xe43 | je | reg/arith | `0x511d6f: add $0xfffffffffffffffe,%r8` | memory | 0x511dbe | fwd |
| Constant-time inversion | +0xe5a | jae | mem | `0x511d82: cmp 0x148(%rsp),%rdi` | memory | 0x511d97 | fwd |
| Constant-time inversion | +0xe88 | jb | mem | `0x511db0: cmp 0x148(%rsp),%rcx` | arithmetic/control | 0x511d46 | back |
| Constant-time inversion | +0xe96 | je | mem | `0x511dbe: testb $0x1,0x248(%rsp)` | memory | 0x511e11 | fwd |
| Constant-time inversion | +0xec7 | jae | mem | `0x511def: cmp 0x148(%rsp),%rdi` | memory | 0x511e07 | fwd |
| Constant-time inversion | +0xf60 | je | reg/arith | `0x511e8c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x511ed4 | fwd |
| Constant-time inversion | +0xf65 | jae | reg/arith | `0x511e92: cmp %rbx,%rcx` | memory | 0x511e9e | fwd |
| Constant-time inversion | +0xf78 | jae | mem | `0x511ea0: cmp 0x130(%rsp),%rcx` | memory | 0x511eb8 | fwd |
| Constant-time inversion | +0xf9e | jb | mem | `0x511ec6: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x511e6b | back |
| Constant-time inversion | +0xfad | je | mem | `0x511ed4: cmpq $0x0,0x130(%rsp)` | memory | 0x511fd5 | fwd |
| Constant-time inversion | +0xfbc | je | mem | `0x511ee3: cmpq $0x0,0x270(%rsp)` | memory | 0x511f9b | fwd |
| Constant-time inversion | +0x101a | je | reg/arith | `0x511f46: add $0xfffffffffffffffe,%r8` | memory | 0x511f8a | fwd |
| Constant-time inversion | +0x102b | jae | reg/arith | `0x511f58: cmp %rbx,%rdi` | memory | 0x511f68 | fwd |
| Constant-time inversion | +0x1054 | jb | reg/arith | `0x511f81: cmp %rbx,%rcx` | arithmetic/control | 0x511f1d | back |
| Constant-time inversion | +0x1062 | je | mem | `0x511f8a: testb $0x1,0x250(%rsp)` | memory | 0x511fd5 | fwd |
| Constant-time inversion | +0x108e | jae | reg/arith | `0x511fbb: cmp %rbx,%rdi` | memory | 0x511fcb | fwd |
| Constant-time inversion | +0x10ae | je | mem | `0x511fd5: cmpq $0x0,0x150(%rsp)` | memory | 0x5120e8 | fwd |
| Constant-time inversion | +0x10bd | je | mem | `0x511fe4: cmpq $0x0,0x268(%rsp)` | memory | 0x5120a6 | fwd |
| Constant-time inversion | +0x111a | je | reg/arith | `0x512046: add $0xfffffffffffffffe,%r8` | memory | 0x512095 | fwd |
| Constant-time inversion | +0x1131 | jae | mem | `0x512059: cmp 0x140(%rsp),%rdi` | memory | 0x51206e | fwd |
| Constant-time inversion | +0x115f | jb | mem | `0x512087: cmp 0x140(%rsp),%rcx` | arithmetic/control | 0x51201d | back |
| Constant-time inversion | +0x116d | je | mem | `0x512095: testb $0x1,0x248(%rsp)` | memory | 0x5120e8 | fwd |
| Constant-time inversion | +0x119e | jae | mem | `0x5120c6: cmp 0x140(%rsp),%rdi` | memory | 0x5120de | fwd |
| Constant-time inversion | +0x121f | je | reg/arith | `0x51214b: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x512197 | fwd |
| Constant-time inversion | +0x1224 | jae | reg/arith | `0x512151: cmp %rbx,%rcx` | memory | 0x512161 | fwd |
| Constant-time inversion | +0x123b | jae | mem | `0x512163: cmp 0x130(%rsp),%rcx` | memory | 0x51217b | fwd |
| Constant-time inversion | +0x1261 | jb | mem | `0x512189: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x51212a | back |
| Constant-time inversion | +0x1270 | je | mem | `0x512197: cmpq $0x0,0x80(%rsp)` | memory | 0x5121af | fwd |
| Constant-time inversion | +0x1297 | je | mem | `0x5121be: cmpq $0x0,0x118(%rsp)` | memory | 0x5122df | fwd |
| Constant-time inversion | +0x12a6 | je | mem | `0x5121cd: cmpq $0x0,0x198(%rsp)` | memory | 0x5122a3 | fwd |
| Constant-time inversion | +0x1307 | je | reg/arith | `0x512233: add $0xfffffffffffffffe,%r8` | memory | 0x51228f | fwd |
| Constant-time inversion | +0x1321 | jae | mem | `0x512249: cmp 0x80(%rsp),%rdi` | memory | 0x512261 | fwd |
| Constant-time inversion | +0x1355 | jb | mem | `0x51227d: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x512204 | back |
| Constant-time inversion | +0x1367 | je | mem | `0x51228f: testb $0x1,0x180(%rsp)` | memory | 0x5122df | fwd |
| Constant-time inversion | +0x1398 | jae | mem | `0x5122c0: cmp 0x80(%rsp),%rdi` | memory | 0x5122d5 | fwd |
| Constant-time inversion | +0x13b8 | je | mem | `0x5122df: cmpq $0x0,0x188(%rsp)` | memory | 0x512343 | fwd |
| Constant-time inversion | +0x13ef | je | reg/arith | `0x51231b: add $0xfffffffffffffff8,%rax` | memory | 0x512343 | fwd |
| Constant-time inversion | +0x13f9 | jae | mem | `0x512321: cmp 0x80(%rsp),%rcx` | memory | 0x512336 | fwd |
| Constant-time inversion | +0x140c | jb | mem | `0x512338: cmp (%rsp),%rcx` | arithmetic/control | 0x5122f8 | back |
| Constant-time inversion | +0x141f | ja | mem | `0x51234b: cmp %rax,(%rsp)` | arithmetic/control | 0x513699 | fwd |
| Constant-time inversion | +0x1425 | jae | unknown | `?` | memory | 0x513753 | fwd |
| Constant-time inversion | +0x1431 | je | mem | `0x51235b: cmpq $0x0,0x28(%rsp)` | memory | 0x512430 | fwd |
| Constant-time inversion | +0x144c | jne | mem | `0x512374: testb $0x8,0xa0(%rsp)` | memory | 0x51239f | fwd |
| Constant-time inversion | +0x145a | jae | mem | `0x512386: cmp (%rsp),%rax` | memory | 0x5123a9 | fwd |
| Constant-time inversion | +0x149a | je | mem | `0x5123c1: cmpq $0x0,0xa0(%rsp)` | memory | 0x512430 | fwd |
| Constant-time inversion | +0x14c8 | je | mem | `0x5123f3: cmp 0x30(%rsp),%rax` | memory | 0x512430 | fwd |
| Constant-time inversion | +0x14d5 | jae | mem | `0x512401: cmp (%rsp),%rdi` | memory | 0x512412 | fwd |
| Constant-time inversion | +0x14fa | jb | mem | `0x512426: cmp (%rsp),%rcx` | arithmetic/control | 0x5123d9 | back |
| Constant-time inversion | +0x1509 | je | mem | `0x512430: cmpq $0x0,0x118(%rsp)` | memory | 0x5124ff | fwd |
| Constant-time inversion | +0x1518 | je | mem | `0x51243f: cmpq $0x0,0x198(%rsp)` | memory | 0x5124d3 | fwd |
| Constant-time inversion | +0x1553 | je | mem | `0x51247b: cmp 0x1b0(%rsp),%rdx` | memory | 0x5124bf | fwd |
| Constant-time inversion | +0x1560 | jae | mem | `0x51248b: cmp 0x28(%rsp),%rdx` | memory | 0x51249d | fwd |
| Constant-time inversion | +0x1589 | jb | mem | `0x5124b4: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x512457 | back |
| Constant-time inversion | +0x1597 | je | mem | `0x5124bf: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x5124ff | fwd |
| Constant-time inversion | +0x15af | jae | mem | `0x5124da: cmp 0x28(%rsp),%rax` | memory | 0x5124ec | fwd |
| Constant-time inversion | +0x15d5 | je | mem | `0x5124ff: cmpq $0x0,0x28(%rsp)` | memory | 0x51256e | fwd |
| Constant-time inversion | +0x1611 | je | reg/arith | `0x51253d: add $0xfffffffffffffff8,%rax` | memory | 0x512569 | fwd |
| Constant-time inversion | +0x161b | jae | mem | `0x512543: cmp 0x80(%rsp),%rcx` | memory | 0x512558 | fwd |
| Constant-time inversion | +0x1632 | jb | mem | `0x51255a: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x512515 | back |
| Constant-time inversion | +0x1646 | je | mem | `0x512570: cmpq $0x0,0x68(%rsp)` | memory | 0x5125e7 | fwd |
| Constant-time inversion | +0x1688 | je | reg/arith | `0x5125b4: add $0xfffffffffffffff8,%rax` | memory | 0x5125d7 | fwd |
| Constant-time inversion | +0x168e | jae | mem | `0x5125ba: cmp (%rsp),%rcx` | memory | 0x5125c9 | fwd |
| Constant-time inversion | +0x16a0 | jb | mem | `0x5125cb: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x512587 | back |
| Constant-time inversion | +0x16cf | je | mem | `0x5125f6: cmpq $0x0,0x110(%rsp)` | memory | 0x51270c | fwd |
| Constant-time inversion | +0x16de | je | mem | `0x512605: cmpq $0x0,0x190(%rsp)` | memory | 0x5126d0 | fwd |
| Constant-time inversion | +0x173e | je | reg/arith | `0x51266a: add $0xfffffffffffffffe,%r8` | memory | 0x5126bc | fwd |
| Constant-time inversion | +0x1755 | jae | mem | `0x512680: cmp 0x68(%rsp),%rdi` | memory | 0x512695 | fwd |
| Constant-time inversion | +0x1786 | jb | mem | `0x5126b1: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x51263b | back |
| Constant-time inversion | +0x1794 | je | mem | `0x5126bc: testb $0x1,0x178(%rsp)` | memory | 0x51270c | fwd |
| Constant-time inversion | +0x17c2 | jae | mem | `0x5126ed: cmp 0x68(%rsp),%rdi` | memory | 0x512702 | fwd |
| Constant-time inversion | +0x1811 | je | reg/arith | `0x51273d: add $0xfffffffffffffff8,%rax` | memory | 0x512765 | fwd |
| Constant-time inversion | +0x1818 | jae | mem | `0x512743: cmp 0x68(%rsp),%rcx` | memory | 0x512758 | fwd |
| Constant-time inversion | +0x182e | jb | mem | `0x51275a: cmp (%rsp),%rcx` | arithmetic/control | 0x51271a | back |
| Constant-time inversion | +0x183b | je | mem | `0x512765: cmpq $0x0,0x28(%rsp)` | memory | 0x51283a | fwd |
| Constant-time inversion | +0x1856 | jne | mem | `0x51277e: testb $0x8,0xa0(%rsp)` | memory | 0x5127a9 | fwd |
| Constant-time inversion | +0x1864 | jae | mem | `0x512790: cmp (%rsp),%rax` | memory | 0x5127b3 | fwd |
| Constant-time inversion | +0x18a4 | je | mem | `0x5127cb: cmpq $0x0,0xa0(%rsp)` | memory | 0x51283a | fwd |
| Constant-time inversion | +0x18d2 | je | mem | `0x5127fd: cmp 0x30(%rsp),%rax` | memory | 0x51283a | fwd |
| Constant-time inversion | +0x18df | jae | mem | `0x51280b: cmp (%rsp),%rdi` | memory | 0x51281c | fwd |
| Constant-time inversion | +0x1904 | jb | mem | `0x512830: cmp (%rsp),%rcx` | arithmetic/control | 0x5127e3 | back |
| Constant-time inversion | +0x1913 | je | mem | `0x51283a: cmpq $0x0,0x110(%rsp)` | memory | 0x512909 | fwd |
| Constant-time inversion | +0x1922 | je | mem | `0x512849: cmpq $0x0,0x190(%rsp)` | memory | 0x5128dd | fwd |
| Constant-time inversion | +0x195d | je | mem | `0x512885: cmp 0x1a8(%rsp),%rdx` | memory | 0x5128c9 | fwd |
| Constant-time inversion | +0x196a | jae | mem | `0x512895: cmp 0x28(%rsp),%rdx` | memory | 0x5128a7 | fwd |
| Constant-time inversion | +0x1993 | jb | mem | `0x5128be: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x512861 | back |
| Constant-time inversion | +0x19a1 | je | mem | `0x5128c9: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x512909 | fwd |
| Constant-time inversion | +0x19b9 | jae | mem | `0x5128e4: cmp 0x28(%rsp),%rax` | memory | 0x5128f6 | fwd |
| Constant-time inversion | +0x1a04 | je | mem | `0x51292b: cmpq $0x0,0x1f8(%rsp)` | memory | 0x5129c2 | fwd |
| Constant-time inversion | +0x1a53 | je | reg/arith | `0x51297f: add $0xfffffffffffffff8,%rax` | memory | 0x5129c2 | fwd |
| Constant-time inversion | +0x1a5d | jae | mem | `0x512985: cmp 0x80(%rsp),%rcx` | memory | 0x51299a | fwd |
| Constant-time inversion | +0x1a74 | jae | mem | `0x51299c: cmp 0x118(%rsp),%rcx` | memory | 0x5129b1 | fwd |
| Constant-time inversion | +0x1a8c | jb | mem | `0x5129b4: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x51294e | back |
| Constant-time inversion | +0x1a9b | je | mem | `0x5129c2: cmpq $0x0,0x88(%rsp)` | memory | 0x5129da | fwd |
| Constant-time inversion | +0x1ac2 | je | mem | `0x5129e9: cmpq $0x0,0x118(%rsp)` | memory | 0x512b0a | fwd |
| Constant-time inversion | +0x1ad1 | je | mem | `0x5129f8: cmpq $0x0,0x198(%rsp)` | memory | 0x512ace | fwd |
| Constant-time inversion | +0x1b32 | je | reg/arith | `0x512a5e: add $0xfffffffffffffffe,%r8` | memory | 0x512aba | fwd |
| Constant-time inversion | +0x1b4c | jae | mem | `0x512a74: cmp 0x88(%rsp),%rdi` | memory | 0x512a8c | fwd |
| Constant-time inversion | +0x1b80 | jb | mem | `0x512aa8: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x512a2f | back |
| Constant-time inversion | +0x1b92 | je | mem | `0x512aba: testb $0x1,0x180(%rsp)` | memory | 0x512b0a | fwd |
| Constant-time inversion | +0x1bc3 | jae | mem | `0x512aeb: cmp 0x88(%rsp),%rdi` | memory | 0x512b00 | fwd |
| Constant-time inversion | +0x1c0f | je | reg/arith | `0x512b3b: add $0xfffffffffffffff8,%rax` | memory | 0x512b63 | fwd |
| Constant-time inversion | +0x1c19 | jae | mem | `0x512b41: cmp 0x88(%rsp),%rcx` | memory | 0x512b56 | fwd |
| Constant-time inversion | +0x1c2c | jb | mem | `0x512b58: cmp (%rsp),%rcx` | arithmetic/control | 0x512b18 | back |
| Constant-time inversion | +0x1c39 | je | mem | `0x512b63: cmpq $0x0,0x28(%rsp)` | memory | 0x512c38 | fwd |
| Constant-time inversion | +0x1c54 | jne | mem | `0x512b7c: testb $0x8,0xa0(%rsp)` | memory | 0x512ba7 | fwd |
| Constant-time inversion | +0x1c62 | jae | mem | `0x512b8e: cmp (%rsp),%rax` | memory | 0x512bb1 | fwd |
| Constant-time inversion | +0x1ca2 | je | mem | `0x512bc9: cmpq $0x0,0xa0(%rsp)` | memory | 0x512c38 | fwd |
| Constant-time inversion | +0x1cd0 | je | mem | `0x512bfb: cmp 0x30(%rsp),%rax` | memory | 0x512c38 | fwd |
| Constant-time inversion | +0x1cdd | jae | mem | `0x512c09: cmp (%rsp),%rdi` | memory | 0x512c1a | fwd |
| Constant-time inversion | +0x1d02 | jb | mem | `0x512c2e: cmp (%rsp),%rcx` | arithmetic/control | 0x512be1 | back |
| Constant-time inversion | +0x1d11 | je | mem | `0x512c38: cmpq $0x0,0x118(%rsp)` | memory | 0x512d07 | fwd |
| Constant-time inversion | +0x1d20 | je | mem | `0x512c47: cmpq $0x0,0x198(%rsp)` | memory | 0x512cdb | fwd |
| Constant-time inversion | +0x1d5b | je | mem | `0x512c83: cmp 0x1b0(%rsp),%rdx` | memory | 0x512cc7 | fwd |
| Constant-time inversion | +0x1d68 | jae | mem | `0x512c93: cmp 0x28(%rsp),%rdx` | memory | 0x512ca5 | fwd |
| Constant-time inversion | +0x1d91 | jb | mem | `0x512cbc: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x512c5f | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x512cc7: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x512d07 | fwd |
| Constant-time inversion | +0x1db7 | jae | mem | `0x512ce2: cmp 0x28(%rsp),%rax` | memory | 0x512cf4 | fwd |
| Constant-time inversion | +0x1ddd | je | mem | `0x512d07: cmpq $0x0,0x28(%rsp)` | memory | 0x512d76 | fwd |
| Constant-time inversion | +0x1e19 | je | reg/arith | `0x512d45: add $0xfffffffffffffff8,%rax` | memory | 0x512d71 | fwd |
| Constant-time inversion | +0x1e23 | jae | mem | `0x512d4b: cmp 0x88(%rsp),%rcx` | memory | 0x512d60 | fwd |
| Constant-time inversion | +0x1e3a | jb | mem | `0x512d62: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x512d1d | back |
| Constant-time inversion | +0x1e4e | je | mem | `0x512d78: cmpq $0x0,0x68(%rsp)` | memory | 0x512def | fwd |
| Constant-time inversion | +0x1e90 | je | reg/arith | `0x512dbc: add $0xfffffffffffffff8,%rax` | memory | 0x512ddf | fwd |
| Constant-time inversion | +0x1e96 | jae | mem | `0x512dc2: cmp (%rsp),%rcx` | memory | 0x512dd1 | fwd |
| Constant-time inversion | +0x1ea8 | jb | mem | `0x512dd3: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x512d8f | back |
| Constant-time inversion | +0x1ed7 | je | mem | `0x512dfe: cmpq $0x0,0x110(%rsp)` | memory | 0x512f14 | fwd |
| Constant-time inversion | +0x1ee6 | je | mem | `0x512e0d: cmpq $0x0,0x190(%rsp)` | memory | 0x512ed8 | fwd |
| Constant-time inversion | +0x1f46 | je | reg/arith | `0x512e72: add $0xfffffffffffffffe,%r8` | memory | 0x512ec4 | fwd |
| Constant-time inversion | +0x1f5d | jae | mem | `0x512e88: cmp 0x68(%rsp),%rdi` | memory | 0x512e9d | fwd |
| Constant-time inversion | +0x1f8e | jb | mem | `0x512eb9: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x512e43 | back |
| Constant-time inversion | +0x1f9c | je | mem | `0x512ec4: testb $0x1,0x178(%rsp)` | memory | 0x512f14 | fwd |
| Constant-time inversion | +0x1fca | jae | mem | `0x512ef5: cmp 0x68(%rsp),%rdi` | memory | 0x512f0a | fwd |
| Constant-time inversion | +0x2019 | je | reg/arith | `0x512f45: add $0xfffffffffffffff8,%rax` | memory | 0x512f6d | fwd |
| Constant-time inversion | +0x2020 | jae | mem | `0x512f4b: cmp 0x68(%rsp),%rcx` | memory | 0x512f60 | fwd |
| Constant-time inversion | +0x2036 | jb | mem | `0x512f62: cmp (%rsp),%rcx` | arithmetic/control | 0x512f22 | back |
| Constant-time inversion | +0x2043 | je | mem | `0x512f6d: cmpq $0x0,0x28(%rsp)` | memory | 0x513042 | fwd |
| Constant-time inversion | +0x205e | jne | mem | `0x512f86: testb $0x8,0xa0(%rsp)` | memory | 0x512fb1 | fwd |
| Constant-time inversion | +0x206c | jae | mem | `0x512f98: cmp (%rsp),%rax` | memory | 0x512fbb | fwd |
| Constant-time inversion | +0x20ac | je | mem | `0x512fd3: cmpq $0x0,0xa0(%rsp)` | memory | 0x513042 | fwd |
| Constant-time inversion | +0x20da | je | mem | `0x513005: cmp 0x30(%rsp),%rax` | memory | 0x513042 | fwd |
| Constant-time inversion | +0x20e7 | jae | mem | `0x513013: cmp (%rsp),%rdi` | memory | 0x513024 | fwd |
| Constant-time inversion | +0x210c | jb | mem | `0x513038: cmp (%rsp),%rcx` | arithmetic/control | 0x512feb | back |
| Constant-time inversion | +0x211b | je | mem | `0x513042: cmpq $0x0,0x110(%rsp)` | memory | 0x513111 | fwd |
| Constant-time inversion | +0x212a | je | mem | `0x513051: cmpq $0x0,0x190(%rsp)` | memory | 0x5130e5 | fwd |
| Constant-time inversion | +0x2165 | je | mem | `0x51308d: cmp 0x1a8(%rsp),%rdx` | memory | 0x5130d1 | fwd |
| Constant-time inversion | +0x2172 | jae | mem | `0x51309d: cmp 0x28(%rsp),%rdx` | memory | 0x5130af | fwd |
| Constant-time inversion | +0x219b | jb | mem | `0x5130c6: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x513069 | back |
| Constant-time inversion | +0x21a9 | je | mem | `0x5130d1: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x513111 | fwd |
| Constant-time inversion | +0x21c1 | jae | mem | `0x5130ec: cmp 0x28(%rsp),%rax` | memory | 0x5130fe | fwd |
| Constant-time inversion | +0x2226 | je | reg/arith | `0x513153: test %rax,%rax` | memory | 0x5119a2 | back |
| Constant-time inversion | +0x226d | je | reg/arith | `0x513199: add $0xfffffffffffffff8,%rax` | memory | 0x5119a2 | back |
| Constant-time inversion | +0x227b | jae | mem | `0x5131a3: cmp 0x88(%rsp),%rcx` | memory | 0x5131b8 | fwd |
| Constant-time inversion | +0x2292 | jae | mem | `0x5131ba: cmp 0x118(%rsp),%rcx` | memory | 0x5131cf | fwd |
| Constant-time inversion | +0x22aa | jb | mem | `0x5131d2: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x513168 | back |
| Constant-time inversion | +0x231d | je | reg/arith | `0x513249: cmp $0x1,%rbx` | memory | 0x5132dd | fwd |
| Constant-time inversion | +0x2337 | jb | reg/arith | `0x513263: cmp $0x18,%rdx` | memory | 0x5132cc | fwd |
| Constant-time inversion | +0x2383 | jne | reg/arith | `0x5132b0: cmp %rcx,%rdx` | arithmetic/control | 0x513296 | back |
| Constant-time inversion | +0x239a | je | reg/arith | `0x5132c7: cmp %rdx,%rsi` | memory | 0x5132dd | fwd |
| Constant-time inversion | +0x23ab | jne | mem | `0x5132d3: cmp 0x2b8(%rsp),%rax` | memory | 0x5132cc | back |
| Constant-time inversion | +0x2414 | je | reg/arith | `0x513340: cmp $0xffffffffffffffff,%rax` | memory | 0x5134fb | fwd |
| Constant-time inversion | +0x2431 | jne | mem | `0x513359: cmp 0x138(%rsp),%rdi` | memory | 0x513739 | fwd |
| Constant-time inversion | +0x257f | je | reg/arith | `0x5134ac: test %r12,%r12` | memory | 0x513677 | fwd |
| Constant-time inversion | +0x2592 | je | mem | `0x5134bd: cmpq $0x0,(%rsp)` | memory | 0x510f9d | back |
| Constant-time inversion | +0x2732 | jne | reg/arith | `0x51365f: cmp %rax,%rsi` | memory | 0x513633 | back |
| Constant-time inversion | +0x2981 | je | mem | `0x5138ac: cmpq $0x0,(%rsp)` | memory | 0x513913 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x1883a0: test %rcx,%rcx` | memory | 0x188414 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x1883b0: test %rax,%rax` | memory | 0x188408 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x1883bc: cmp (%r15),%rcx` | memory | 0x18840f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x1883c5: test %ecx,%ecx` | memory | 0x1883d5 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x1883cd: test %edx,%edx` | arithmetic/control | 0x1883d5 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x1883d1: cmp %edx,%ecx` | call | 0x18840f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x1883dd: test %eax,%eax` | memory | 0x188414 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x1883e9: test %rax,%rax` | memory | 0x188542 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x1883f2: cmp (%r12),%rcx` | memory | 0x188783 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x18841f: test %rcx,%rcx` | memory | 0x188520 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x188440: cmp %rdx,%rcx` | memory | 0x188520 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x188449: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x188440 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x18845f: test %rcx,%rcx` | memory | 0x188520 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x188480: cmp %rdx,%rcx` | memory | 0x188520 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x188489: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x188480 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x18849d: test %r13,%r13` | memory | 0x188539 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x1884aa: cmpq $0x0,0x50(%rax)` | memory | 0x188550 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x1884cc: test %rax,%rax` | memory | 0x18851b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x1884e7: test %rax,%rax` | call | 0x1884f5 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x1884f1: test %eax,%eax` | call+memory | 0x188568 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x18855f: test %r13,%r13` | memory | 0x1886ad | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x18856c: cmpq $0x0,0x50(%rax)` | memory | 0x1886a4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x188593: test %rax,%rax` | memory | 0x1886e1 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x1885b2: test %rax,%rax` | call | 0x1886bb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x1885c0: test %eax,%eax` | memory | 0x1886bb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x1885d2: test %r14,%r14` | arithmetic/control | 0x18879c | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x1885db: test %r15,%r15` | memory | 0x1887a7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x1885ee: test %rcx,%rcx` | memory | 0x188628 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x1885f7: test %rax,%rax` | memory | 0x188628 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x188603: cmp (%r15),%rcx` | memory | 0x188628 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x18860c: test %ecx,%ecx` | memory | 0x1888ea | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x188618: test %edx,%edx` | arithmetic/control | 0x1888ea | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x188620: cmp %ecx,%edx` | call | 0x1888ea | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x188642: test %rax,%rax` | memory | 0x188655 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x18864b: test %rax,%rax` | call | 0x188655 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x188686: test %rbx,%rbx` | memory | 0x1888be | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x188693: test %rcx,%rcx` | arithmetic/control | 0x188769 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x188702: test %bpl,%bpl` | memory | 0x188748 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x18870f: test %rax,%rax` | memory | 0x188722 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x188718: test %rax,%rax` | call | 0x188722 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x188753: test %rbx,%rbx` | memory | 0x188527 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x188760: test %rcx,%rcx` | memory | 0x188527 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x1887b4: test %eax,%eax` | memory | 0x1888c6 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x1887c0: test %rax,%rax` | memory | 0x1887c9 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x1887cd: test %rax,%rax` | memory | 0x1887d6 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x1887da: test %rax,%rax` | memory | 0x1887e3 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x1887e8: test %rax,%rax` | memory | 0x1887f1 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x1887f6: test %rax,%rax` | memory | 0x1887ff | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x188804: test %rax,%rax` | memory | 0x18880d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x188816: test %rax,%rax` | memory | 0x18881f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x188828: test %rax,%rax` | memory | 0x188831 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x18883a: test %rax,%rax` | call+memory | 0x188843 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x18886b: test %rax,%rax` | memory | 0x1888d2 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x188889: test %eax,%eax` | memory | 0x1888de | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x18889a: test %r15,%r15` | memory | 0x188908 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x1888a3: test $0xffffffff80000000,%rax` | memory | 0x18891b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x1888ea: cmp %r15,%r14` | call | 0x1887bc | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x1888fb: test %eax,%eax` | arithmetic/control | 0x1887bc | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x188926: test $0x1,%al` | memory | 0x188f51 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x188933: test %eax,%eax` | memory | 0x188961 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x18893e: cmp %rsi,(%rdi)` | call+memory | 0x18896b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x188953: test %al,%cl` | arithmetic/control | 0x188974 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x188961: test %r15,%r15` | arithmetic/control | 0x188989 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x18896b: test %r15,%r15` | memory | 0x188a57 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x188974: cmp %rsi,(%r15)` | call | 0x188989 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x188981: test %al,%al` | memory | 0x188a57 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x18899a: test %rax,%rax` | memory | 0x188a63 | fwd |
| ECDSA scalar ladder (driver) | +0x638 | jg | mem | `0x1889b1: cmp 0x2c(%rsp),%eax` | memory | 0x1889c0 | fwd |
| ECDSA scalar ladder (driver) | +0x63e | je | mem | `0x1889ba: cmpl $0x0,0x18(%rbp)` | memory | 0x1889dc | fwd |
| ECDSA scalar ladder (driver) | +0x656 | je | reg/arith | `0x1889d4: test %eax,%eax` | memory | 0x188a6f | fwd |
| ECDSA scalar ladder (driver) | +0x674 | je | reg/arith | `0x1889f2: test %eax,%eax` | memory | 0x188a7b | fwd |
| ECDSA scalar ladder (driver) | +0x692 | je | reg/arith | `0x188a10: test %eax,%eax` | memory | 0x188c53 | fwd |
| ECDSA scalar ladder (driver) | +0x6a6 | js | mem | `0x188a21: cmpl $0x0,0x2c(%rsp)` | memory | 0x188a87 | fwd |
| ECDSA scalar ladder (driver) | +0x6b8 | jae | mem | `0x188a34: cmp 0x10(%rcx),%rax` | memory | 0x188a87 | fwd |
| ECDSA scalar ladder (driver) | +0x725 | je | reg/arith | `0x188aa2: test %rax,%rax` | memory | 0x188abf | fwd |
| ECDSA scalar ladder (driver) | +0x752 | je | reg/arith | `0x188acf: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x762 | jae | mem | `0x188adf: cmp %rax,(%rdi)` | call | 0x188af4 | fwd |
| ECDSA scalar ladder (driver) | +0x76e | je | reg/arith | `0x188aec: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x780 | je | reg/arith | `0x188afd: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x789 | jae | mem | `0x188b06: cmp %r15,(%rdi)` | call | 0x188b1b | fwd |
| ECDSA scalar ladder (driver) | +0x795 | je | reg/arith | `0x188b13: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x7a7 | je | reg/arith | `0x188b24: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x7b0 | jae | mem | `0x188b2d: cmp %r15,(%rdi)` | call | 0x188b42 | fwd |
| ECDSA scalar ladder (driver) | +0x7bc | je | reg/arith | `0x188b3a: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x7ca | je | reg/arith | `0x188b47: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x7d3 | jae | mem | `0x188b50: cmp %r15,(%rdi)` | call | 0x188b65 | fwd |
| ECDSA scalar ladder (driver) | +0x7df | je | reg/arith | `0x188b5d: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x7ed | je | reg/arith | `0x188b6a: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x7f6 | jae | mem | `0x188b73: cmp %r15,(%rdi)` | call | 0x188b88 | fwd |
| ECDSA scalar ladder (driver) | +0x802 | je | reg/arith | `0x188b80: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x810 | je | reg/arith | `0x188b8d: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x819 | jae | mem | `0x188b96: cmp %r15,(%rdi)` | call | 0x188bab | fwd |
| ECDSA scalar ladder (driver) | +0x825 | je | reg/arith | `0x188ba3: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x837 | je | reg/arith | `0x188bb4: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x840 | jae | mem | `0x188bbd: cmp %r15,(%rdi)` | call | 0x188bd2 | fwd |
| ECDSA scalar ladder (driver) | +0x84c | je | reg/arith | `0x188bca: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x85e | je | reg/arith | `0x188bdb: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x867 | jae | mem | `0x188be4: cmp %r15,(%rdi)` | call | 0x188bf9 | fwd |
| ECDSA scalar ladder (driver) | +0x873 | je | reg/arith | `0x188bf1: test %al,%al` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x885 | je | reg/arith | `0x188c02: test %rdi,%rdi` | memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0x893 | jae | mem | `0x188c0b: cmp %r15,(%rdi)` | call | 0x188c25 | fwd |
| ECDSA scalar ladder (driver) | +0x89f | je | reg/arith | `0x188c1d: test %al,%al` | memory | 0x188634 | back |
| ECDSA scalar ladder (driver) | +0x8aa | je | mem | `0x188c25: cmpl $0x0,0x28(%r14)` | call+memory | 0x188d98 | fwd |
| ECDSA scalar ladder (driver) | +0x8be | je | reg/arith | `0x188c3c: test %al,%al` | memory | 0x188c5f | fwd |
| ECDSA scalar ladder (driver) | +0x8ed | jne | reg/arith | `0x188c69: cmp $0x4,%rdx` | memory | 0x188d1b | fwd |
| ECDSA scalar ladder (driver) | +0x92b | jne | reg/arith | `0x188ca7: cmp $0x1,%dil` | memory | 0x188d1d | fwd |
| ECDSA scalar ladder (driver) | +0x936 | jne | reg/arith | `0x188cb4: cmp $0xff,%al` | call+memory | 0x188cbf | fwd |
| ECDSA scalar ladder (driver) | +0x962 | je | reg/arith | `0x188ce0: test %eax,%eax` | call+memory | 0x188eb2 | fwd |
| ECDSA scalar ladder (driver) | +0x989 | jne | reg/arith | `0x188d07: test %eax,%eax` | memory | 0x188ed6 | fwd |
| ECDSA scalar ladder (driver) | +0x99f | je | reg/arith | `0x188d1d: test %cl,%cl` | arithmetic/control | 0x188dd6 | fwd |
| ECDSA scalar ladder (driver) | +0x9a8 | jne | reg/arith | `0x188d25: test %sil,%sil` | memory | 0x188dd6 | fwd |
| ECDSA scalar ladder (driver) | +0x9f8 | je | mem | `0x188d6f: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x188f11 | fwd |
| ECDSA scalar ladder (driver) | +0xa2d | je | reg/arith | `0x188daa: test %rax,%rax` | call+memory | 0x188dcc | fwd |
| ECDSA scalar ladder (driver) | +0xa41 | jne | reg/arith | `0x188dbf: test %eax,%eax` | arithmetic/control | 0x188c30 | back |
| ECDSA scalar ladder (driver) | +0xa79 | je | reg/arith | `0x188df7: test %eax,%eax` | memory | 0x188eb2 | fwd |
| ECDSA scalar ladder (driver) | +0xa83 | jo | mem | `0x188dff: decl 0x2c(%rsp)` | arithmetic/control | 0x188f60 | fwd |
| ECDSA scalar ladder (driver) | +0xa89 | js | unknown | `?` | memory | 0x188ebb | fwd |
| ECDSA scalar ladder (driver) | +0xab2 | jae | mem | `0x188e2e: cmp 0x10(%rcx),%rax` | memory | 0x188e4c | fwd |
| ECDSA scalar ladder (driver) | +0xae7 | je | mem | `0x188e61: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x188e80 | fwd |
| ECDSA scalar ladder (driver) | +0xb1a | je | reg/arith | `0x188e98: test %eax,%eax` | memory | 0x188f26 | fwd |
| ECDSA scalar ladder (driver) | +0xb2a | jg | reg/arith | `0x188ea3: test %rbp,%rbp` | arithmetic/control | 0x188e1f | back |
| ECDSA scalar ladder (driver) | +0xb64 | je | reg/arith | `0x188ee1: test %rax,%rax` | call+memory | 0x188eff | fwd |
| ECDSA scalar ladder (driver) | +0xb7d | je | reg/arith | `0x188efb: test %eax,%eax` | call+memory | 0x188f1f | fwd |
| ECDSA scalar ladder (driver) | +0xbc6 | jne | reg/arith | `0x188f43: test %rax,%rax` | arithmetic/control | 0x188647 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x2a9c17: test %rax,%rax` | memory | 0x2aa1b5 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x2a9c32: test %rbp,%rbp` | memory | 0x2aa1b5 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x2a9c42: test %rax,%rax` | call+memory | 0x2aa1b5 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x2a9c64: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x2a9c82: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x2a9ca0: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x2a9cbe: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x2a9ce4: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x2a9d04: test %eax,%eax` | arithmetic/control | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x2a9d0c: test %r15,%r15` | memory | 0x2a9d32 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x2a9d1e: test %rdx,%rdx` | arithmetic/control | 0x2a9d54 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x2a9d4a: test %rdx,%rdx` | memory | 0x2a9d60 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x2a9d63: sub $0x1,%r9` | memory | 0x2a9d87 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x2a9d69: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x2a9d60 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x2a9d80: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x2a9d90 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x2a9d8a: sub $0x1,%r8` | arithmetic/control | 0x2a9d80 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x2a9d90: cmp %r9,%rdi` | memory | 0x2a9db0 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x2a9da0: sub $0x1,%rdi` | memory | 0x2a9db2 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x2a9daa: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x2a9da0 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x2a9dcd | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x2a9dc5: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x2a9ddf: test %eax,%eax` | arithmetic/control | 0x2aa1b5 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x2a9dec: test %r15,%r15` | memory | 0x2a9dfb | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x2a9e13: sub $0x1,%rdi` | memory | 0x2a9e37 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x2a9e19: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x2a9e10 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x2a9e30: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x2a9e40 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x2a9e3a: sub $0x1,%rsi` | arithmetic/control | 0x2a9e30 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x2a9e40: cmp %rdi,%rdx` | arithmetic/control | 0x2a9e55 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x2a9e45: sub $0x1,%rdx` | memory | 0x2a9e57 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x2a9e4f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x2a9e45 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x2a9e6e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x2a9e66: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x2a9e83: test %eax,%eax` | memory | 0x2aa1b5 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x2a9e9d: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x2a9ec0: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x2a9edb: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x2a9ef5: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x2a9f17: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x2a9f31: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x2a9f54: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x2a9f76: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x2a9f98: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x2a9fba: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x2a9fd4: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x2a9ff0: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x2aa014: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x2aa02e: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x2aa04d: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x2aa06c: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x2aa08b: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x2aa0a5: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x2aa0c4: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x2aa0e1: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x2aa106: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x2aa125: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x2aa141: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x2aa15a: test %eax,%eax` | call+memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x2aa173: test %eax,%eax` | memory | 0x2aa1b3 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x2aa189: test %eax,%eax` | memory | 0x2aa1b5 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x2aa1b5: test %rbx,%rbx` | memory | 0x2aa1d8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x2aa1be: test %rax,%rax` | memory | 0x2aa1d8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x18b9fb: test %rax,%rax` | memory | 0x18c468 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x18ba15: cmpl $0x1,0x10(%rbp)` | memory | 0x18ba3d | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x18ba25: test %rax,%rax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x18ba34: cmp $0xfffffffd,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x18ba45: testb $0x4,0xa4(%rbp)` | memory | 0x18ba65 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x18ba4e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x18bac6 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x18ba57: test %r13b,%r13b` | arithmetic/control | 0x18bba0 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x18ba6b: test %rax,%rax` | memory | 0x18c468 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x18ba99: test %rax,%rax` | arithmetic/control | 0x18bfb0 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x18baa2: test %r15,%r15` | memory | 0x18bab0 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x18baba: test %rax,%rax` | arithmetic/control | 0x18bb28 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x18bae3: test %r15,%r15` | arithmetic/control | 0x18bb80 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x18baec: test %r14,%r14` | memory | 0x18bafa | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x18bb01: test %r15,%r15` | memory | 0x18bb72 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x18bb1b: test %eax,%eax` | memory | 0x18bb66 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x18bb44: test %eax,%eax` | memory | 0x18bf87 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x18bb72: test %r14,%r14` | memory | 0x18bb80 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x18bb86: or %r13b,%al` | arithmetic/control | 0x18bdb2 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x18bb97: test %r15,%r15` | memory | 0x18c468 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x18bba6: test %rax,%rax` | memory | 0x18c468 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x18bbe9: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x18bbf7: test %rax,%rax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x18bc1d: test %rax,%rax` | call+memory | 0x18c910 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x18bc46: test %eax,%eax` | call+memory | 0x18c910 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x18bc94: test %al,0x38(%rsp)` | memory | 0x18bd13 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x18bca5: test %rax,%rax` | memory | 0x18c468 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x18bccb: test %rax,%rax` | call+memory | 0x18c362 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x18bd05: test %ebp,%ebp` | arithmetic/control | 0x18c46b | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x18bd15: test %ebx,%ebx` | memory | 0x18c1ce | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x18bd27: test %r15b,%r15b` | call+memory | 0x18c1d8 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x18bd4e: test %r13,%r13` | arithmetic/control | 0x18c90b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x18bd5c: test %rax,%rax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x18bd6e: test %rax,%rax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x18bd7e: test %rcx,%rcx` | memory | 0x18c36f | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x18bd96: cmpq $0x0,0x10(%rcx)` | memory | 0x18c379 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x18bdd7: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x18bdf5: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x18be1f: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x18be3d: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x18be76: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x18be98: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x18beb1: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x18beb9: test %rbx,%rbx` | memory | 0x18bf04 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x18bec8: cmpl $0x0,0x18(%rbx)` | memory | 0x18bf04 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x18bede: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x18bee6: cmpl $0x0,0x18(%rbx)` | memory | 0x18bf04 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x18befc: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x18bf1a: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x18bf3c: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x18bf59: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x18bf97: test %r15,%r15` | memory | 0x18bfa5 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x18bfa5: test %bl,%bl` | memory | 0x18c058 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x18bfd2: test %rax,%rax` | arithmetic/control | 0x18c060 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x18bfdb: test %r15,%r15` | memory | 0x18bfe9 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x18bff3: test %rax,%rax` | arithmetic/control | 0x18bffc | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x18c018: test %eax,%eax` | memory | 0x18c033 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x18c043: test %r15,%r15` | memory | 0x18c051 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x18c051: test %bl,%bl` | arithmetic/control | 0x18c060 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x18c06a: test %ebx,%ebx` | memory | 0x18c15b | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x18c099: test %bl,%bl` | arithmetic/control | 0x18c1c1 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x18c0a4: cmp %r14,%r13` | memory | 0x18c15b | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x18c0d8: test %rax,%rax` | arithmetic/control | 0x18c0a1 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x18c0dd: test %r15,%r15` | memory | 0x18c0eb | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x18c0ef: test %rax,%rax` | arithmetic/control | 0x18c0fd | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x18c0f6: test %r15,%r15` | arithmetic/control | 0x18c090 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x18c112: test %eax,%eax` | memory | 0x18c138 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x18c12a: test %r15,%r15` | arithmetic/control | 0x18c090 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x18c14d: test %r15,%r15` | arithmetic/control | 0x18c090 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x18c169: test %ebx,%ebx` | memory | 0x18c1b4 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x18c175: cmp 0x72f1ec(%rip),%rax        # 8bb368 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x4f15d8>` | call+memory | 0x18ba4e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x18c1dd: test %al,%r14b` | memory | 0x18c45f | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x18c213: test %eax,%eax` | arithmetic/control | 0x18c46b | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x18c21b: test %rbx,%rbx` | memory | 0x18c23e | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x18c220: cmpl $0x0,0x18(%rbx)` | memory | 0x18c23e | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x18c236: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x18c253: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x18c261: test %rax,%rax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x18c2ad: test %ebp,%ebp` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x18c2b5: test %rbx,%rbx` | memory | 0x18c2dd | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x18c2bf: cmpl $0x0,0x18(%rbx)` | memory | 0x18c2dd | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x18c2d5: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x18c2f5: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x18c30e: test %eax,%eax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x18c316: cmpl $0x0,0x28(%rsp)` | memory | 0x18c66c | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x18c32c: test %rax,%rax` | memory | 0x18c46b | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x18c342: test %rax,%rax` | memory | 0x18c579 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x18c34b: cmpq $0x0,0x10(%rax)` | memory | 0x18c579 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x18c3bd: test %eax,%eax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x18c3d2: test %rax,%rax` | call+memory | 0x18c90b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x18c3f6: test %eax,%eax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x18c3fe: cmpl $0x1,0x28(%rsp)` | call+memory | 0x18c4a4 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x18c456: test %al,%r14b` | arithmetic/control | 0x18c1e6 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x18c45f: test %r15b,%r15b` | arithmetic/control | 0x18c66c | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x18c46b: test %r12,%r12` | memory | 0x18c492 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x18c475: test %rax,%rax` | memory | 0x18c492 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x18c4ad: test %rax,%rax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x18c4c7: test %rax,%rax` | memory | 0x18c4dd | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x18c4cc: cmpq $0x2,0x10(%rax)` | memory | 0x18c4dd | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x18c51a: test %eax,%eax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x18c52f: test %rax,%rax` | call+memory | 0x18c90b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x18c553: test %eax,%eax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x18c55b: cmpl $0x2,0x28(%rsp)` | memory | 0x18c823 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x18c591: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x18c5ae: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x18c5e5: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x18c5ed: cmpq $0x0,0x8(%rsp)` | memory | 0x18c619 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x18c5fa: cmpl $0x0,0x18(%rax)` | memory | 0x18c619 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x18c611: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x18c62e: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x18c649: test %eax,%eax` | memory | 0x18c923 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x18c651: cmpl $0x1,0x28(%rsp)` | memory | 0x18c93b | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x18c670: test %rdx,%rdx` | memory | 0x18c802 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x18c67d: test %rcx,%rcx` | memory | 0x18c802 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x18c68e: cmp 0x72ecd3(%rip),%rax        # 8bb368 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x4f15d8>` | memory | 0x18c6b8 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x18c697: test %rax,%rax` | call+memory | 0x18c468 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x18c6d5: test %eax,%eax` | memory | 0x18c46b | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x18c6f0: test %eax,%eax` | memory | 0x18c46b | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x18c710: cmp %rdx,%rcx` | memory | 0x18c802 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x18c719: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x18c710 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x18c744: test %eax,%eax` | memory | 0x18c80d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x18c751: cmpl $0x0,0x18(%rax)` | memory | 0x18c774 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x18c76c: test %eax,%eax` | memory | 0x18c46b | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x18c787: cmp %rdx,%rcx` | memory | 0x18c815 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x18c790: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x18c787 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x18c7a6: test %rax,%rax` | memory | 0x18c85c | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x18c7cb: test %rax,%rax` | call+memory | 0x18c933 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x18c831: test %rax,%rax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x18c846: test %rax,%rax` | memory | 0x18c867 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x18c84b: cmpq $0x3,0x10(%rax)` | memory | 0x18c867 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x18c8a4: test %eax,%eax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x18c8b5: test %rax,%rax` | call+memory | 0x18c90b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x18c8d5: test %eax,%eax` | memory | 0x18c90b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x18c8d9: cmpl $0x3,0x28(%rsp)` | memory | 0x18c41b | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x18c94a: test %rax,%rax` | memory | 0x18c960 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x18c94f: cmpq $0x2,0x10(%rax)` | memory | 0x18c960 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x18c978: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x18c991: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x18c9c4: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x18c9cc: cmpq $0x0,0x8(%rsp)` | memory | 0x18c9f8 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x18c9d9: cmpl $0x0,0x18(%rax)` | memory | 0x18c9f8 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x18c9f0: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x18ca0d: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x18ca28: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x18ca30: cmpl $0x2,0x28(%rsp)` | memory | 0x18c65c | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x18ca4a: test %rax,%rax` | memory | 0x18ca60 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x18ca4f: cmpq $0x3,0x10(%rax)` | memory | 0x18ca60 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x18ca78: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x18ca95: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x18cacc: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x112a | je | mem | `0x18cad4: cmpq $0x0,0x8(%rsp)` | memory | 0x18cb00 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x18cae1: cmpl $0x0,0x18(%rax)` | memory | 0x18cb00 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x18caf8: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x18cb15: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x18cb30: test %eax,%eax` | memory | 0x18c923 | back |
| RSA CRT arms | +0x118d | je | mem | `0x18cb38: cmpl $0x3,0x28(%rsp)` | memory | 0x18c65c | back |
| P-256 Montgomery reduction | +0x2e1 | je | reg/arith | `0x189e9e: test %r8,%r8` | memory | 0x189f50 | fwd |
| P-256 Montgomery reduction | +0x31e | je | reg/arith | `0x189edb: dec %r8` | memory | 0x189f2d | fwd |
| P-256 Montgomery reduction | +0x34d | jne | reg/arith | `0x189f0a: test %rcx,%rcx` | arithmetic/control | 0x189ec0 | back |
| P-256 Montgomery reduction | +0x361 | je | reg/arith | `0x189f1e: or %r14b,%bl` | arithmetic/control | 0x189ec0 | back |
| P-256 Montgomery reduction | +0x36b | jne | reg/arith | `0x189f28: dec %r8` | memory | 0x189ee0 | back |
