# Binary branch audit — review aid, not a proof

- DSO: `court/tmp/pfp0-refreeze-build/distribution/libcrypto.so.3`
- SHA-256: `6d7e282d091aedb783d0e55874ed2ce4dab8eaf219f9f5c32653ad4630953b9c`
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
| Montgomery multiply (core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith13mont_mul_into` @ 0x28cf20 | 1041 | 260 | 24 | 0 | 0 | 6 | 0 | 0 | 13 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x161cc0 | 857 | 207 | 13 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | **missing** (`mod_exp_core_consttime_from_parts`) | | | | | | | | | | |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x1904b0 | 11101 | 2380 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x1fcbc0 | 2944 | 721 | 118 | 0 | 5 | 5 | 1 | 0 | 74 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x531db0 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x205500 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |

## Coverage

- expected targets: 7
- resolved uniquely and disassembled: 6
- failed: 1
  - Constant-time ladder core (`mod_exp_core_consttime_from_parts`): missing

## Divisions

- none in any audited range.

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **29**
- of those inside the audited ranges: **0**
- first addresses: 0x169128, 0x169149, 0x16916a, 0x169181, 0x1691d3, 0x1691ea, 0x169375, 0x169483, 0x169529, 0x1696e8, 0x22a2cc, 0x22c29c, 0x22ef8c, 0x22efbc, 0x2e5c4c, 0x2e5c7c, 0x4cb1b2, 0x4cb220, 0x4cb28e, 0x4cb2fc

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (core) | +0x52 | je | reg/arith | `0x28cf6f: test %r14,%r14` | memory | 0x28d178 | fwd |
| Montgomery multiply (core) | +0x74 | je | mem | `0x28cf90: cmp (%rsp),%rdi` | memory | 0x28d2b3 | fwd |
| Montgomery multiply (core) | +0x93 | je | reg/arith | `0x28cfb0: cmp %rbx,%r15` | memory | 0x28d211 | fwd |
| Montgomery multiply (core) | +0xa0 | jae | reg/arith | `0x28cfbd: cmp %r12,%rax` | memory | 0x28d224 | fwd |
| Montgomery multiply (core) | +0xcb | jne | reg/arith | `0x28cfe8: cmp %rbx,%r14` | arithmetic/control | 0x28cfb0 | back |
| Montgomery multiply (core) | +0xd3 | jae | reg/arith | `0x28cff0: cmp %r12,%rdi` | memory | 0x28d2c7 | fwd |
| Montgomery multiply (core) | +0xec | jne | reg/arith | `0x28d009: cmp %r14,%r10` | memory | 0x28cf90 | back |
| Montgomery multiply (core) | +0xf8 | jae | reg/arith | `0x28d015: cmp %r12,%r10` | memory | 0x28d24a | fwd |
| Montgomery multiply (core) | +0x14c | je | reg/arith | `0x28d069: cmp %r14,%rax` | arithmetic/control | 0x28d10a | fwd |
| Montgomery multiply (core) | +0x155 | je | reg/arith | `0x28d072: cmp %r12,%r10` | memory | 0x28d2fa | fwd |
| Montgomery multiply (core) | +0x183 | je | reg/arith | `0x28d0a0: cmp %rdi,%rbx` | memory | 0x28d237 | fwd |
| Montgomery multiply (core) | +0x1af | jne | reg/arith | `0x28d0cc: cmp %rdi,%r14` | memory | 0x28d0a0 | back |
| Montgomery multiply (core) | +0x1bd | je | mem | `0x28d0d8: cmp 0x10(%rsp),%r10` | memory | 0x28d050 | back |
| Montgomery multiply (core) | +0x1e3 | jne | reg/arith | `0x28d100: cmp %rax,%r15` | arithmetic/control | 0x28d0f0 | back |
| Montgomery multiply (core) | +0x223 | je | reg/arith | `0x28d140: cmp %rsi,%rbx` | memory | 0x28d30d | fwd |
| Montgomery multiply (core) | +0x24c | jne | reg/arith | `0x28d169: cmp %rsi,%r14` | arithmetic/control | 0x28d140 | back |
| Montgomery multiply (core) | +0x251 | jne | reg/arith | `0x28d16e: test %rbp,%rbp` | arithmetic/control | 0x28d19d | fwd |
| Montgomery multiply (core) | +0x25b | je | reg/arith | `0x28d178: test %r12,%r12` | memory | 0x28d320 | fwd |
| Montgomery multiply (core) | +0x27b | je | reg/arith | `0x28d198: test %rbp,%rbp` | memory | 0x28d202 | fwd |
| Montgomery multiply (core) | +0x2a7 | jae | reg/arith | `0x28d1c4: cmp %r12,%rdi` | arithmetic/control | 0x28d2ea | fwd |
| Montgomery multiply (core) | +0x2b0 | je | reg/arith | `0x28d1cd: cmp %rsi,%rbx` | memory | 0x28d2d7 | fwd |
| Montgomery multiply (core) | +0x2e0 | jne | reg/arith | `0x28d1fc: add $0xfffffffffffffff8,%rbp` | arithmetic/control | 0x28d1c0 | back |
| Montgomery multiply (core) | +0x343 | je | reg/arith | `0x28d260: cmp %rsi,%r12` | memory | 0x28d2a0 | fwd |
| Montgomery multiply (core) | +0x368 | jne | reg/arith | `0x28d285: cmp %rsi,%r14` | memory | 0x28d260 | back |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x161cf9: test %rbx,%rbx` | memory | 0x161d5e | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x161d36: cmpb $0x0,0x8(%rsp)` | memory | 0x161da3 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | je | reg/arith | `0x161d45: test %rbx,%rbx` | arithmetic/control | 0x161d94 | fwd |
| Montgomery multiply (allocating wrapper) | +0xc6 | je | mem | `0x161d81: cmpb $0x0,0x8(%rsp)` | memory | 0x161eb7 | fwd |
| Montgomery multiply (allocating wrapper) | +0xf2 | jne | reg/arith | `0x161daf: test %rbx,%rbx` | memory | 0x161eef | fwd |
| Montgomery multiply (allocating wrapper) | +0x148 | je | reg/arith | `0x161e05: test %rbx,%rbx` | memory | 0x161e59 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x161e43: cmp %rax,%rbx` | memory | 0x161e10 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x161e93: cmp %rax,%r14` | arithmetic/control | 0x161e60 | back |
| Montgomery multiply (allocating wrapper) | +0x203 | je | reg/arith | `0x161ebf: cmp $0x1,%rbx` | memory | 0x161ee0 | fwd |
| Montgomery multiply (allocating wrapper) | +0x271 | je | mem | `0x161f2c: cmpb $0x0,0x8(%rsp)` | memory | 0x161fa2 | fwd |
| Montgomery multiply (allocating wrapper) | +0x2c6 | jne | reg/arith | `0x161f83: cmp %rax,%r14` | memory | 0x161f50 | back |
| Montgomery multiply (allocating wrapper) | +0x2eb | jne | reg/arith | `0x161fa7: cmp $0x1,%rbx` | arithmetic/control | 0x161fb5 | fwd |
| Montgomery multiply (allocating wrapper) | +0x331 | jne | reg/arith | `0x161fee: test %rbx,%rbx` | call | 0x161ffb | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x1904c4: test %r8,%r8` | memory | 0x190515 | fwd |
| Constant-time inversion | +0x1f | je | mem | `0x1904cc: testb $0x1,(%rcx)` | arithmetic/control | 0x190515 | fwd |
| Constant-time inversion | +0x32 | jne | reg/arith | `0x1904de: shr $0x39,%rax` | call+memory | 0x190515 | fwd |
| Constant-time inversion | +0x63 | je | mem | `0x19050e: cmpb $0x0,0x10(%rsp)` | memory | 0x190532 | fwd |
| Constant-time inversion | +0x8e | je | reg/arith | `0x19053a: cmp $0x1,%rbx` | memory | 0x19055b | fwd |
| Constant-time inversion | +0xea | je | mem | `0x190595: cmpb $0x0,0x10(%rsp)` | memory | 0x1905fe | fwd |
| Constant-time inversion | +0x136 | jne | reg/arith | `0x1905e3: cmp %rax,%rbx` | memory | 0x1905b0 | back |
| Constant-time inversion | +0x15a | je | reg/arith | `0x190606: cmp $0x1,%rbx` | memory | 0x190627 | fwd |
| Constant-time inversion | +0x1c0 | je | mem | `0x19066b: cmpb $0x0,0x10(%rsp)` | memory | 0x1906c7 | fwd |
| Constant-time inversion | +0x202 | jne | reg/arith | `0x1906af: cmp %rax,%rsi` | memory | 0x19067c | back |
| Constant-time inversion | +0x22c | je | mem | `0x1906cf: cmpq $0x1,(%rsp)` | memory | 0x190707 | fwd |
| Constant-time inversion | +0x28b | je | mem | `0x190736: cmpb $0x0,0x10(%rsp)` | memory | 0x1907c6 | fwd |
| Constant-time inversion | +0x2b5 | jne | reg/arith | `0x190763: or %cl,%dl` | memory | 0x1907a5 | fwd |
| Constant-time inversion | +0x2ef | jne | reg/arith | `0x19079c: cmp %rax,%rsi` | memory | 0x190771 | back |
| Constant-time inversion | +0x2f8 | je | reg/arith | `0x1907a5: test %rax,%rax` | memory | 0x190672 | back |
| Constant-time inversion | +0x328 | je | mem | `0x1907d3: cmpq $0x1,(%rsp)` | memory | 0x190802 | fwd |
| Constant-time inversion | +0x37e | je | mem | `0x190829: cmpb $0x0,0x10(%rsp)` | memory | 0x1908c5 | fwd |
| Constant-time inversion | +0x3b1 | jne | reg/arith | `0x19085f: or %cl,%al` | memory | 0x19089d | fwd |
| Constant-time inversion | +0x3eb | jne | reg/arith | `0x190898: cmp %rax,%rsi` | memory | 0x19086d | back |
| Constant-time inversion | +0x3f2 | je | mem | `0x19089d: cmpq $0x0,(%rsp)` | memory | 0x1908b7 | fwd |
| Constant-time inversion | +0x421 | je | reg/arith | `0x1908cd: cmp $0x1,%rbx` | memory | 0x1908f1 | fwd |
| Constant-time inversion | +0x46d | je | mem | `0x190918: cmpb $0x0,0x10(%rsp)` | memory | 0x19092d | fwd |
| Constant-time inversion | +0x48b | je | reg/arith | `0x190937: cmp $0x1,%rbx` | memory | 0x19095f | fwd |
| Constant-time inversion | +0x4dd | je | reg/arith | `0x190989: cmp $0xffffffffffffffff,%rax` | call+memory | 0x190f06 | fwd |
| Constant-time inversion | +0x524 | je | reg/arith | `0x1909d0: cmp $0xffffffffffffffff,%rax` | call+memory | 0x190f14 | fwd |
| Constant-time inversion | +0x56b | je | reg/arith | `0x190a17: cmp $0xffffffffffffffff,%rax` | call+memory | 0x192760 | fwd |
| Constant-time inversion | +0x5b2 | je | reg/arith | `0x190a5e: cmp $0xffffffffffffffff,%rax` | call+memory | 0x19276e | fwd |
| Constant-time inversion | +0x5fa | je | reg/arith | `0x190aa6: cmp $0xffffffffffffffff,%rax` | call+memory | 0x19277c | fwd |
| Constant-time inversion | +0x642 | je | reg/arith | `0x190aee: cmp $0xffffffffffffffff,%rax` | call+memory | 0x19278a | fwd |
| Constant-time inversion | +0x68a | je | reg/arith | `0x190b36: cmp $0xffffffffffffffff,%rax` | call+memory | 0x192798 | fwd |
| Constant-time inversion | +0x6cf | je | reg/arith | `0x190b7b: cmp $0xffffffffffffffff,%rax` | call+memory | 0x1927a6 | fwd |
| Constant-time inversion | +0x714 | je | reg/arith | `0x190bc0: cmp $0xffffffffffffffff,%rax` | call+memory | 0x1927b4 | fwd |
| Constant-time inversion | +0x759 | je | reg/arith | `0x190c05: cmp $0xffffffffffffffff,%rax` | call+memory | 0x192a65 | fwd |
| Constant-time inversion | +0x79f | je | reg/arith | `0x190c4b: cmp $0xffffffffffffffff,%rax` | memory | 0x192a70 | fwd |
| Constant-time inversion | +0xb14 | je | mem | `0x190fac: cmp 0x2b0(%rsp),%rdx` | memory | 0x1927c2 | fwd |
| Constant-time inversion | +0xbcf | je | mem | `0x191076: cmpq $0x0,0x148(%rsp)` | memory | 0x1910d8 | fwd |
| Constant-time inversion | +0xc0e | je | reg/arith | `0x1910ba: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x1910da | fwd |
| Constant-time inversion | +0xc13 | jae | reg/arith | `0x1910c0: cmp %rbx,%rcx` | memory | 0x1910cc | fwd |
| Constant-time inversion | +0xc21 | jb | reg/arith | `0x1910ce: cmp %rbx,%rcx` | arithmetic/control | 0x19108f | back |
| Constant-time inversion | +0xc33 | je | mem | `0x1910da: cmpq $0x0,0x140(%rsp)` | memory | 0x19113f | fwd |
| Constant-time inversion | +0xc71 | je | reg/arith | `0x19111d: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x19113f | fwd |
| Constant-time inversion | +0xc76 | jae | reg/arith | `0x191123: cmp %rbx,%rcx` | memory | 0x191133 | fwd |
| Constant-time inversion | +0xc88 | jb | reg/arith | `0x191135: cmp %rbx,%rcx` | arithmetic/control | 0x1910f4 | back |
| Constant-time inversion | +0xcdf | je | mem | `0x191186: cmpq $0x0,0x130(%rsp)` | memory | 0x19127e | fwd |
| Constant-time inversion | +0xcee | je | mem | `0x191195: cmpq $0x0,0x270(%rsp)` | memory | 0x191248 | fwd |
| Constant-time inversion | +0xd47 | je | reg/arith | `0x1911f3: add $0xfffffffffffffffe,%r8` | memory | 0x191237 | fwd |
| Constant-time inversion | +0xd58 | jae | reg/arith | `0x191205: cmp %rbx,%rdi` | memory | 0x191215 | fwd |
| Constant-time inversion | +0xd81 | jb | reg/arith | `0x19122e: cmp %rbx,%rcx` | arithmetic/control | 0x1911ca | back |
| Constant-time inversion | +0xd8f | je | mem | `0x191237: testb $0x1,0x250(%rsp)` | memory | 0x19127e | fwd |
| Constant-time inversion | +0xdbb | jae | reg/arith | `0x191268: cmp %rbx,%rdi` | memory | 0x191274 | fwd |
| Constant-time inversion | +0xdd7 | je | mem | `0x19127e: cmpq $0x0,0x150(%rsp)` | memory | 0x191391 | fwd |
| Constant-time inversion | +0xde6 | je | mem | `0x19128d: cmpq $0x0,0x268(%rsp)` | memory | 0x19134f | fwd |
| Constant-time inversion | +0xe43 | je | reg/arith | `0x1912ef: add $0xfffffffffffffffe,%r8` | memory | 0x19133e | fwd |
| Constant-time inversion | +0xe5a | jae | mem | `0x191302: cmp 0x148(%rsp),%rdi` | memory | 0x191317 | fwd |
| Constant-time inversion | +0xe88 | jb | mem | `0x191330: cmp 0x148(%rsp),%rcx` | arithmetic/control | 0x1912c6 | back |
| Constant-time inversion | +0xe96 | je | mem | `0x19133e: testb $0x1,0x248(%rsp)` | memory | 0x191391 | fwd |
| Constant-time inversion | +0xec7 | jae | mem | `0x19136f: cmp 0x148(%rsp),%rdi` | memory | 0x191387 | fwd |
| Constant-time inversion | +0xf60 | je | reg/arith | `0x19140c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x191454 | fwd |
| Constant-time inversion | +0xf65 | jae | reg/arith | `0x191412: cmp %rbx,%rcx` | memory | 0x19141e | fwd |
| Constant-time inversion | +0xf78 | jae | mem | `0x191420: cmp 0x130(%rsp),%rcx` | memory | 0x191438 | fwd |
| Constant-time inversion | +0xf9e | jb | mem | `0x191446: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x1913eb | back |
| Constant-time inversion | +0xfad | je | mem | `0x191454: cmpq $0x0,0x130(%rsp)` | memory | 0x191555 | fwd |
| Constant-time inversion | +0xfbc | je | mem | `0x191463: cmpq $0x0,0x270(%rsp)` | memory | 0x19151b | fwd |
| Constant-time inversion | +0x101a | je | reg/arith | `0x1914c6: add $0xfffffffffffffffe,%r8` | memory | 0x19150a | fwd |
| Constant-time inversion | +0x102b | jae | reg/arith | `0x1914d8: cmp %rbx,%rdi` | memory | 0x1914e8 | fwd |
| Constant-time inversion | +0x1054 | jb | reg/arith | `0x191501: cmp %rbx,%rcx` | arithmetic/control | 0x19149d | back |
| Constant-time inversion | +0x1062 | je | mem | `0x19150a: testb $0x1,0x250(%rsp)` | memory | 0x191555 | fwd |
| Constant-time inversion | +0x108e | jae | reg/arith | `0x19153b: cmp %rbx,%rdi` | memory | 0x19154b | fwd |
| Constant-time inversion | +0x10ae | je | mem | `0x191555: cmpq $0x0,0x150(%rsp)` | memory | 0x191668 | fwd |
| Constant-time inversion | +0x10bd | je | mem | `0x191564: cmpq $0x0,0x268(%rsp)` | memory | 0x191626 | fwd |
| Constant-time inversion | +0x111a | je | reg/arith | `0x1915c6: add $0xfffffffffffffffe,%r8` | memory | 0x191615 | fwd |
| Constant-time inversion | +0x1131 | jae | mem | `0x1915d9: cmp 0x140(%rsp),%rdi` | memory | 0x1915ee | fwd |
| Constant-time inversion | +0x115f | jb | mem | `0x191607: cmp 0x140(%rsp),%rcx` | arithmetic/control | 0x19159d | back |
| Constant-time inversion | +0x116d | je | mem | `0x191615: testb $0x1,0x248(%rsp)` | memory | 0x191668 | fwd |
| Constant-time inversion | +0x119e | jae | mem | `0x191646: cmp 0x140(%rsp),%rdi` | memory | 0x19165e | fwd |
| Constant-time inversion | +0x121f | je | reg/arith | `0x1916cb: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x191717 | fwd |
| Constant-time inversion | +0x1224 | jae | reg/arith | `0x1916d1: cmp %rbx,%rcx` | memory | 0x1916e1 | fwd |
| Constant-time inversion | +0x123b | jae | mem | `0x1916e3: cmp 0x130(%rsp),%rcx` | memory | 0x1916fb | fwd |
| Constant-time inversion | +0x1261 | jb | mem | `0x191709: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x1916aa | back |
| Constant-time inversion | +0x1270 | je | mem | `0x191717: cmpq $0x0,0x80(%rsp)` | memory | 0x19172f | fwd |
| Constant-time inversion | +0x1297 | je | mem | `0x19173e: cmpq $0x0,0x118(%rsp)` | memory | 0x19185f | fwd |
| Constant-time inversion | +0x12a6 | je | mem | `0x19174d: cmpq $0x0,0x198(%rsp)` | memory | 0x191823 | fwd |
| Constant-time inversion | +0x1307 | je | reg/arith | `0x1917b3: add $0xfffffffffffffffe,%r8` | memory | 0x19180f | fwd |
| Constant-time inversion | +0x1321 | jae | mem | `0x1917c9: cmp 0x80(%rsp),%rdi` | memory | 0x1917e1 | fwd |
| Constant-time inversion | +0x1355 | jb | mem | `0x1917fd: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x191784 | back |
| Constant-time inversion | +0x1367 | je | mem | `0x19180f: testb $0x1,0x180(%rsp)` | memory | 0x19185f | fwd |
| Constant-time inversion | +0x1398 | jae | mem | `0x191840: cmp 0x80(%rsp),%rdi` | memory | 0x191855 | fwd |
| Constant-time inversion | +0x13b8 | je | mem | `0x19185f: cmpq $0x0,0x188(%rsp)` | memory | 0x1918c3 | fwd |
| Constant-time inversion | +0x13ef | je | reg/arith | `0x19189b: add $0xfffffffffffffff8,%rax` | memory | 0x1918c3 | fwd |
| Constant-time inversion | +0x13f9 | jae | mem | `0x1918a1: cmp 0x80(%rsp),%rcx` | memory | 0x1918b6 | fwd |
| Constant-time inversion | +0x140c | jb | mem | `0x1918b8: cmp (%rsp),%rcx` | arithmetic/control | 0x191878 | back |
| Constant-time inversion | +0x141f | ja | mem | `0x1918cb: cmp %rax,(%rsp)` | arithmetic/control | 0x192c19 | fwd |
| Constant-time inversion | +0x1425 | jae | unknown | `?` | memory | 0x192cd3 | fwd |
| Constant-time inversion | +0x1431 | je | mem | `0x1918db: cmpq $0x0,0x28(%rsp)` | memory | 0x1919b0 | fwd |
| Constant-time inversion | +0x144c | jne | mem | `0x1918f4: testb $0x8,0xa0(%rsp)` | memory | 0x19191f | fwd |
| Constant-time inversion | +0x145a | jae | mem | `0x191906: cmp (%rsp),%rax` | memory | 0x191929 | fwd |
| Constant-time inversion | +0x149a | je | mem | `0x191941: cmpq $0x0,0xa0(%rsp)` | memory | 0x1919b0 | fwd |
| Constant-time inversion | +0x14c8 | je | mem | `0x191973: cmp 0x30(%rsp),%rax` | memory | 0x1919b0 | fwd |
| Constant-time inversion | +0x14d5 | jae | mem | `0x191981: cmp (%rsp),%rdi` | memory | 0x191992 | fwd |
| Constant-time inversion | +0x14fa | jb | mem | `0x1919a6: cmp (%rsp),%rcx` | arithmetic/control | 0x191959 | back |
| Constant-time inversion | +0x1509 | je | mem | `0x1919b0: cmpq $0x0,0x118(%rsp)` | memory | 0x191a7f | fwd |
| Constant-time inversion | +0x1518 | je | mem | `0x1919bf: cmpq $0x0,0x198(%rsp)` | memory | 0x191a53 | fwd |
| Constant-time inversion | +0x1553 | je | mem | `0x1919fb: cmp 0x1b0(%rsp),%rdx` | memory | 0x191a3f | fwd |
| Constant-time inversion | +0x1560 | jae | mem | `0x191a0b: cmp 0x28(%rsp),%rdx` | memory | 0x191a1d | fwd |
| Constant-time inversion | +0x1589 | jb | mem | `0x191a34: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x1919d7 | back |
| Constant-time inversion | +0x1597 | je | mem | `0x191a3f: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x191a7f | fwd |
| Constant-time inversion | +0x15af | jae | mem | `0x191a5a: cmp 0x28(%rsp),%rax` | memory | 0x191a6c | fwd |
| Constant-time inversion | +0x15d5 | je | mem | `0x191a7f: cmpq $0x0,0x28(%rsp)` | memory | 0x191aee | fwd |
| Constant-time inversion | +0x1611 | je | reg/arith | `0x191abd: add $0xfffffffffffffff8,%rax` | memory | 0x191ae9 | fwd |
| Constant-time inversion | +0x161b | jae | mem | `0x191ac3: cmp 0x80(%rsp),%rcx` | memory | 0x191ad8 | fwd |
| Constant-time inversion | +0x1632 | jb | mem | `0x191ada: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x191a95 | back |
| Constant-time inversion | +0x1646 | je | mem | `0x191af0: cmpq $0x0,0x68(%rsp)` | memory | 0x191b67 | fwd |
| Constant-time inversion | +0x1688 | je | reg/arith | `0x191b34: add $0xfffffffffffffff8,%rax` | memory | 0x191b57 | fwd |
| Constant-time inversion | +0x168e | jae | mem | `0x191b3a: cmp (%rsp),%rcx` | memory | 0x191b49 | fwd |
| Constant-time inversion | +0x16a0 | jb | mem | `0x191b4b: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x191b07 | back |
| Constant-time inversion | +0x16cf | je | mem | `0x191b76: cmpq $0x0,0x110(%rsp)` | memory | 0x191c8c | fwd |
| Constant-time inversion | +0x16de | je | mem | `0x191b85: cmpq $0x0,0x190(%rsp)` | memory | 0x191c50 | fwd |
| Constant-time inversion | +0x173e | je | reg/arith | `0x191bea: add $0xfffffffffffffffe,%r8` | memory | 0x191c3c | fwd |
| Constant-time inversion | +0x1755 | jae | mem | `0x191c00: cmp 0x68(%rsp),%rdi` | memory | 0x191c15 | fwd |
| Constant-time inversion | +0x1786 | jb | mem | `0x191c31: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x191bbb | back |
| Constant-time inversion | +0x1794 | je | mem | `0x191c3c: testb $0x1,0x178(%rsp)` | memory | 0x191c8c | fwd |
| Constant-time inversion | +0x17c2 | jae | mem | `0x191c6d: cmp 0x68(%rsp),%rdi` | memory | 0x191c82 | fwd |
| Constant-time inversion | +0x1811 | je | reg/arith | `0x191cbd: add $0xfffffffffffffff8,%rax` | memory | 0x191ce5 | fwd |
| Constant-time inversion | +0x1818 | jae | mem | `0x191cc3: cmp 0x68(%rsp),%rcx` | memory | 0x191cd8 | fwd |
| Constant-time inversion | +0x182e | jb | mem | `0x191cda: cmp (%rsp),%rcx` | arithmetic/control | 0x191c9a | back |
| Constant-time inversion | +0x183b | je | mem | `0x191ce5: cmpq $0x0,0x28(%rsp)` | memory | 0x191dba | fwd |
| Constant-time inversion | +0x1856 | jne | mem | `0x191cfe: testb $0x8,0xa0(%rsp)` | memory | 0x191d29 | fwd |
| Constant-time inversion | +0x1864 | jae | mem | `0x191d10: cmp (%rsp),%rax` | memory | 0x191d33 | fwd |
| Constant-time inversion | +0x18a4 | je | mem | `0x191d4b: cmpq $0x0,0xa0(%rsp)` | memory | 0x191dba | fwd |
| Constant-time inversion | +0x18d2 | je | mem | `0x191d7d: cmp 0x30(%rsp),%rax` | memory | 0x191dba | fwd |
| Constant-time inversion | +0x18df | jae | mem | `0x191d8b: cmp (%rsp),%rdi` | memory | 0x191d9c | fwd |
| Constant-time inversion | +0x1904 | jb | mem | `0x191db0: cmp (%rsp),%rcx` | arithmetic/control | 0x191d63 | back |
| Constant-time inversion | +0x1913 | je | mem | `0x191dba: cmpq $0x0,0x110(%rsp)` | memory | 0x191e89 | fwd |
| Constant-time inversion | +0x1922 | je | mem | `0x191dc9: cmpq $0x0,0x190(%rsp)` | memory | 0x191e5d | fwd |
| Constant-time inversion | +0x195d | je | mem | `0x191e05: cmp 0x1a8(%rsp),%rdx` | memory | 0x191e49 | fwd |
| Constant-time inversion | +0x196a | jae | mem | `0x191e15: cmp 0x28(%rsp),%rdx` | memory | 0x191e27 | fwd |
| Constant-time inversion | +0x1993 | jb | mem | `0x191e3e: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x191de1 | back |
| Constant-time inversion | +0x19a1 | je | mem | `0x191e49: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x191e89 | fwd |
| Constant-time inversion | +0x19b9 | jae | mem | `0x191e64: cmp 0x28(%rsp),%rax` | memory | 0x191e76 | fwd |
| Constant-time inversion | +0x1a04 | je | mem | `0x191eab: cmpq $0x0,0x1f8(%rsp)` | memory | 0x191f42 | fwd |
| Constant-time inversion | +0x1a53 | je | reg/arith | `0x191eff: add $0xfffffffffffffff8,%rax` | memory | 0x191f42 | fwd |
| Constant-time inversion | +0x1a5d | jae | mem | `0x191f05: cmp 0x80(%rsp),%rcx` | memory | 0x191f1a | fwd |
| Constant-time inversion | +0x1a74 | jae | mem | `0x191f1c: cmp 0x118(%rsp),%rcx` | memory | 0x191f31 | fwd |
| Constant-time inversion | +0x1a8c | jb | mem | `0x191f34: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x191ece | back |
| Constant-time inversion | +0x1a9b | je | mem | `0x191f42: cmpq $0x0,0x88(%rsp)` | memory | 0x191f5a | fwd |
| Constant-time inversion | +0x1ac2 | je | mem | `0x191f69: cmpq $0x0,0x118(%rsp)` | memory | 0x19208a | fwd |
| Constant-time inversion | +0x1ad1 | je | mem | `0x191f78: cmpq $0x0,0x198(%rsp)` | memory | 0x19204e | fwd |
| Constant-time inversion | +0x1b32 | je | reg/arith | `0x191fde: add $0xfffffffffffffffe,%r8` | memory | 0x19203a | fwd |
| Constant-time inversion | +0x1b4c | jae | mem | `0x191ff4: cmp 0x88(%rsp),%rdi` | memory | 0x19200c | fwd |
| Constant-time inversion | +0x1b80 | jb | mem | `0x192028: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x191faf | back |
| Constant-time inversion | +0x1b92 | je | mem | `0x19203a: testb $0x1,0x180(%rsp)` | memory | 0x19208a | fwd |
| Constant-time inversion | +0x1bc3 | jae | mem | `0x19206b: cmp 0x88(%rsp),%rdi` | memory | 0x192080 | fwd |
| Constant-time inversion | +0x1c0f | je | reg/arith | `0x1920bb: add $0xfffffffffffffff8,%rax` | memory | 0x1920e3 | fwd |
| Constant-time inversion | +0x1c19 | jae | mem | `0x1920c1: cmp 0x88(%rsp),%rcx` | memory | 0x1920d6 | fwd |
| Constant-time inversion | +0x1c2c | jb | mem | `0x1920d8: cmp (%rsp),%rcx` | arithmetic/control | 0x192098 | back |
| Constant-time inversion | +0x1c39 | je | mem | `0x1920e3: cmpq $0x0,0x28(%rsp)` | memory | 0x1921b8 | fwd |
| Constant-time inversion | +0x1c54 | jne | mem | `0x1920fc: testb $0x8,0xa0(%rsp)` | memory | 0x192127 | fwd |
| Constant-time inversion | +0x1c62 | jae | mem | `0x19210e: cmp (%rsp),%rax` | memory | 0x192131 | fwd |
| Constant-time inversion | +0x1ca2 | je | mem | `0x192149: cmpq $0x0,0xa0(%rsp)` | memory | 0x1921b8 | fwd |
| Constant-time inversion | +0x1cd0 | je | mem | `0x19217b: cmp 0x30(%rsp),%rax` | memory | 0x1921b8 | fwd |
| Constant-time inversion | +0x1cdd | jae | mem | `0x192189: cmp (%rsp),%rdi` | memory | 0x19219a | fwd |
| Constant-time inversion | +0x1d02 | jb | mem | `0x1921ae: cmp (%rsp),%rcx` | arithmetic/control | 0x192161 | back |
| Constant-time inversion | +0x1d11 | je | mem | `0x1921b8: cmpq $0x0,0x118(%rsp)` | memory | 0x192287 | fwd |
| Constant-time inversion | +0x1d20 | je | mem | `0x1921c7: cmpq $0x0,0x198(%rsp)` | memory | 0x19225b | fwd |
| Constant-time inversion | +0x1d5b | je | mem | `0x192203: cmp 0x1b0(%rsp),%rdx` | memory | 0x192247 | fwd |
| Constant-time inversion | +0x1d68 | jae | mem | `0x192213: cmp 0x28(%rsp),%rdx` | memory | 0x192225 | fwd |
| Constant-time inversion | +0x1d91 | jb | mem | `0x19223c: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x1921df | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x192247: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x192287 | fwd |
| Constant-time inversion | +0x1db7 | jae | mem | `0x192262: cmp 0x28(%rsp),%rax` | memory | 0x192274 | fwd |
| Constant-time inversion | +0x1ddd | je | mem | `0x192287: cmpq $0x0,0x28(%rsp)` | memory | 0x1922f6 | fwd |
| Constant-time inversion | +0x1e19 | je | reg/arith | `0x1922c5: add $0xfffffffffffffff8,%rax` | memory | 0x1922f1 | fwd |
| Constant-time inversion | +0x1e23 | jae | mem | `0x1922cb: cmp 0x88(%rsp),%rcx` | memory | 0x1922e0 | fwd |
| Constant-time inversion | +0x1e3a | jb | mem | `0x1922e2: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x19229d | back |
| Constant-time inversion | +0x1e4e | je | mem | `0x1922f8: cmpq $0x0,0x68(%rsp)` | memory | 0x19236f | fwd |
| Constant-time inversion | +0x1e90 | je | reg/arith | `0x19233c: add $0xfffffffffffffff8,%rax` | memory | 0x19235f | fwd |
| Constant-time inversion | +0x1e96 | jae | mem | `0x192342: cmp (%rsp),%rcx` | memory | 0x192351 | fwd |
| Constant-time inversion | +0x1ea8 | jb | mem | `0x192353: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x19230f | back |
| Constant-time inversion | +0x1ed7 | je | mem | `0x19237e: cmpq $0x0,0x110(%rsp)` | memory | 0x192494 | fwd |
| Constant-time inversion | +0x1ee6 | je | mem | `0x19238d: cmpq $0x0,0x190(%rsp)` | memory | 0x192458 | fwd |
| Constant-time inversion | +0x1f46 | je | reg/arith | `0x1923f2: add $0xfffffffffffffffe,%r8` | memory | 0x192444 | fwd |
| Constant-time inversion | +0x1f5d | jae | mem | `0x192408: cmp 0x68(%rsp),%rdi` | memory | 0x19241d | fwd |
| Constant-time inversion | +0x1f8e | jb | mem | `0x192439: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x1923c3 | back |
| Constant-time inversion | +0x1f9c | je | mem | `0x192444: testb $0x1,0x178(%rsp)` | memory | 0x192494 | fwd |
| Constant-time inversion | +0x1fca | jae | mem | `0x192475: cmp 0x68(%rsp),%rdi` | memory | 0x19248a | fwd |
| Constant-time inversion | +0x2019 | je | reg/arith | `0x1924c5: add $0xfffffffffffffff8,%rax` | memory | 0x1924ed | fwd |
| Constant-time inversion | +0x2020 | jae | mem | `0x1924cb: cmp 0x68(%rsp),%rcx` | memory | 0x1924e0 | fwd |
| Constant-time inversion | +0x2036 | jb | mem | `0x1924e2: cmp (%rsp),%rcx` | arithmetic/control | 0x1924a2 | back |
| Constant-time inversion | +0x2043 | je | mem | `0x1924ed: cmpq $0x0,0x28(%rsp)` | memory | 0x1925c2 | fwd |
| Constant-time inversion | +0x205e | jne | mem | `0x192506: testb $0x8,0xa0(%rsp)` | memory | 0x192531 | fwd |
| Constant-time inversion | +0x206c | jae | mem | `0x192518: cmp (%rsp),%rax` | memory | 0x19253b | fwd |
| Constant-time inversion | +0x20ac | je | mem | `0x192553: cmpq $0x0,0xa0(%rsp)` | memory | 0x1925c2 | fwd |
| Constant-time inversion | +0x20da | je | mem | `0x192585: cmp 0x30(%rsp),%rax` | memory | 0x1925c2 | fwd |
| Constant-time inversion | +0x20e7 | jae | mem | `0x192593: cmp (%rsp),%rdi` | memory | 0x1925a4 | fwd |
| Constant-time inversion | +0x210c | jb | mem | `0x1925b8: cmp (%rsp),%rcx` | arithmetic/control | 0x19256b | back |
| Constant-time inversion | +0x211b | je | mem | `0x1925c2: cmpq $0x0,0x110(%rsp)` | memory | 0x192691 | fwd |
| Constant-time inversion | +0x212a | je | mem | `0x1925d1: cmpq $0x0,0x190(%rsp)` | memory | 0x192665 | fwd |
| Constant-time inversion | +0x2165 | je | mem | `0x19260d: cmp 0x1a8(%rsp),%rdx` | memory | 0x192651 | fwd |
| Constant-time inversion | +0x2172 | jae | mem | `0x19261d: cmp 0x28(%rsp),%rdx` | memory | 0x19262f | fwd |
| Constant-time inversion | +0x219b | jb | mem | `0x192646: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x1925e9 | back |
| Constant-time inversion | +0x21a9 | je | mem | `0x192651: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x192691 | fwd |
| Constant-time inversion | +0x21c1 | jae | mem | `0x19266c: cmp 0x28(%rsp),%rax` | memory | 0x19267e | fwd |
| Constant-time inversion | +0x2226 | je | reg/arith | `0x1926d3: test %rax,%rax` | memory | 0x190f22 | back |
| Constant-time inversion | +0x226d | je | reg/arith | `0x192719: add $0xfffffffffffffff8,%rax` | memory | 0x190f22 | back |
| Constant-time inversion | +0x227b | jae | mem | `0x192723: cmp 0x88(%rsp),%rcx` | memory | 0x192738 | fwd |
| Constant-time inversion | +0x2292 | jae | mem | `0x19273a: cmp 0x118(%rsp),%rcx` | memory | 0x19274f | fwd |
| Constant-time inversion | +0x22aa | jb | mem | `0x192752: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x1926e8 | back |
| Constant-time inversion | +0x231d | je | reg/arith | `0x1927c9: cmp $0x1,%rbx` | memory | 0x19285d | fwd |
| Constant-time inversion | +0x2337 | jb | reg/arith | `0x1927e3: cmp $0x18,%rdx` | memory | 0x19284c | fwd |
| Constant-time inversion | +0x2383 | jne | reg/arith | `0x192830: cmp %rcx,%rdx` | arithmetic/control | 0x192816 | back |
| Constant-time inversion | +0x239a | je | reg/arith | `0x192847: cmp %rdx,%rsi` | memory | 0x19285d | fwd |
| Constant-time inversion | +0x23ab | jne | mem | `0x192853: cmp 0x2b8(%rsp),%rax` | memory | 0x19284c | back |
| Constant-time inversion | +0x2414 | je | reg/arith | `0x1928c0: cmp $0xffffffffffffffff,%rax` | memory | 0x192a7b | fwd |
| Constant-time inversion | +0x2431 | jne | mem | `0x1928d9: cmp 0x138(%rsp),%rdi` | memory | 0x192cb9 | fwd |
| Constant-time inversion | +0x257f | je | reg/arith | `0x192a2c: test %r12,%r12` | memory | 0x192bf7 | fwd |
| Constant-time inversion | +0x2592 | je | mem | `0x192a3d: cmpq $0x0,(%rsp)` | memory | 0x19051d | back |
| Constant-time inversion | +0x2732 | jne | reg/arith | `0x192bdf: cmp %rax,%rsi` | memory | 0x192bb3 | back |
| Constant-time inversion | +0x2981 | je | mem | `0x192e2c: cmpq $0x0,(%rsp)` | memory | 0x192e93 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x1fcbe0: test %rcx,%rcx` | memory | 0x1fcc54 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x1fcbf0: test %rax,%rax` | memory | 0x1fcc48 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x1fcbfc: cmp (%r15),%rcx` | memory | 0x1fcc4f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x1fcc05: test %ecx,%ecx` | memory | 0x1fcc15 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x1fcc0d: test %edx,%edx` | arithmetic/control | 0x1fcc15 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x1fcc11: cmp %edx,%ecx` | call | 0x1fcc4f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x1fcc1d: test %eax,%eax` | memory | 0x1fcc54 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x1fcc29: test %rax,%rax` | memory | 0x1fcd82 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x1fcc32: cmp (%r12),%rcx` | memory | 0x1fcfc3 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x1fcc5f: test %rcx,%rcx` | memory | 0x1fcd60 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x1fcc80: cmp %rdx,%rcx` | memory | 0x1fcd60 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x1fcc89: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x1fcc80 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x1fcc9f: test %rcx,%rcx` | memory | 0x1fcd60 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x1fccc0: cmp %rdx,%rcx` | memory | 0x1fcd60 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x1fccc9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x1fccc0 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x1fccdd: test %r13,%r13` | memory | 0x1fcd79 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x1fccea: cmpq $0x0,0x50(%rax)` | memory | 0x1fcd90 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x1fcd0c: test %rax,%rax` | memory | 0x1fcd5b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x1fcd27: test %rax,%rax` | call | 0x1fcd35 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x1fcd31: test %eax,%eax` | call+memory | 0x1fcda8 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x1fcd9f: test %r13,%r13` | memory | 0x1fceed | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x1fcdac: cmpq $0x0,0x50(%rax)` | memory | 0x1fcee4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x1fcdd3: test %rax,%rax` | memory | 0x1fcf21 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x1fcdf2: test %rax,%rax` | call | 0x1fcefb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x1fce00: test %eax,%eax` | memory | 0x1fcefb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x1fce12: test %r14,%r14` | arithmetic/control | 0x1fcfdc | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x1fce1b: test %r15,%r15` | memory | 0x1fcfe7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x1fce2e: test %rcx,%rcx` | memory | 0x1fce68 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x1fce37: test %rax,%rax` | memory | 0x1fce68 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x1fce43: cmp (%r15),%rcx` | memory | 0x1fce68 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x1fce4c: test %ecx,%ecx` | memory | 0x1fd12a | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x1fce58: test %edx,%edx` | arithmetic/control | 0x1fd12a | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x1fce60: cmp %ecx,%edx` | call | 0x1fd12a | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x1fce82: test %rax,%rax` | memory | 0x1fce95 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x1fce8b: test %rax,%rax` | call | 0x1fce95 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x1fcec6: test %rbx,%rbx` | memory | 0x1fd0fe | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x1fced3: test %rcx,%rcx` | arithmetic/control | 0x1fcfa9 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x1fcf42: test %bpl,%bpl` | memory | 0x1fcf88 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x1fcf4f: test %rax,%rax` | memory | 0x1fcf62 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x1fcf58: test %rax,%rax` | call | 0x1fcf62 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x1fcf93: test %rbx,%rbx` | memory | 0x1fcd67 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x1fcfa0: test %rcx,%rcx` | memory | 0x1fcd67 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x1fcff4: test %eax,%eax` | memory | 0x1fd106 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x1fd000: test %rax,%rax` | memory | 0x1fd009 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x1fd00d: test %rax,%rax` | memory | 0x1fd016 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x1fd01a: test %rax,%rax` | memory | 0x1fd023 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x1fd028: test %rax,%rax` | memory | 0x1fd031 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x1fd036: test %rax,%rax` | memory | 0x1fd03f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x1fd044: test %rax,%rax` | memory | 0x1fd04d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x1fd056: test %rax,%rax` | memory | 0x1fd05f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x1fd068: test %rax,%rax` | memory | 0x1fd071 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x1fd07a: test %rax,%rax` | call+memory | 0x1fd083 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x1fd0ab: test %rax,%rax` | memory | 0x1fd112 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x1fd0c9: test %eax,%eax` | memory | 0x1fd11e | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x1fd0da: test %r15,%r15` | memory | 0x1fd148 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x1fd0e3: test $0xffffffff80000000,%rax` | memory | 0x1fd15b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x1fd12a: cmp %r15,%r14` | call | 0x1fcffc | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x1fd13b: test %eax,%eax` | arithmetic/control | 0x1fcffc | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x1fd166: test $0x1,%al` | memory | 0x1fd6d2 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x1fd173: test %eax,%eax` | memory | 0x1fd1a1 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x1fd17e: cmp %rsi,(%rdi)` | call+memory | 0x1fd1ab | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x1fd193: test %al,%cl` | arithmetic/control | 0x1fd1b4 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x1fd1a1: test %r15,%r15` | arithmetic/control | 0x1fd1c9 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x1fd1ab: test %r15,%r15` | memory | 0x1fd297 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x1fd1b4: cmp %rsi,(%r15)` | call | 0x1fd1c9 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x1fd1c1: test %al,%al` | memory | 0x1fd297 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x1fd1da: test %rax,%rax` | memory | 0x1fd2a3 | fwd |
| ECDSA scalar ladder (driver) | +0x638 | jg | mem | `0x1fd1f1: cmp 0x2c(%rsp),%eax` | memory | 0x1fd200 | fwd |
| ECDSA scalar ladder (driver) | +0x63e | je | mem | `0x1fd1fa: cmpl $0x0,0x18(%rbp)` | memory | 0x1fd21c | fwd |
| ECDSA scalar ladder (driver) | +0x656 | je | reg/arith | `0x1fd214: test %eax,%eax` | memory | 0x1fd2af | fwd |
| ECDSA scalar ladder (driver) | +0x674 | je | reg/arith | `0x1fd232: test %eax,%eax` | memory | 0x1fd2bb | fwd |
| ECDSA scalar ladder (driver) | +0x692 | je | reg/arith | `0x1fd250: test %eax,%eax` | memory | 0x1fd570 | fwd |
| ECDSA scalar ladder (driver) | +0x6a6 | js | mem | `0x1fd261: cmpl $0x0,0x2c(%rsp)` | memory | 0x1fd2c7 | fwd |
| ECDSA scalar ladder (driver) | +0x6b8 | jae | mem | `0x1fd274: cmp 0x10(%rcx),%rax` | memory | 0x1fd2c7 | fwd |
| ECDSA scalar ladder (driver) | +0x725 | je | reg/arith | `0x1fd2e2: test %rax,%rax` | memory | 0x1fd2ff | fwd |
| ECDSA scalar ladder (driver) | +0x752 | je | reg/arith | `0x1fd30f: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x762 | jae | mem | `0x1fd31f: cmp %rax,(%rdi)` | call | 0x1fd334 | fwd |
| ECDSA scalar ladder (driver) | +0x76e | je | reg/arith | `0x1fd32c: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x780 | je | reg/arith | `0x1fd33d: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x789 | jae | mem | `0x1fd346: cmp %r15,(%rdi)` | call | 0x1fd35b | fwd |
| ECDSA scalar ladder (driver) | +0x795 | je | reg/arith | `0x1fd353: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x7a7 | je | reg/arith | `0x1fd364: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x7b0 | jae | mem | `0x1fd36d: cmp %r15,(%rdi)` | call | 0x1fd382 | fwd |
| ECDSA scalar ladder (driver) | +0x7bc | je | reg/arith | `0x1fd37a: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x7ca | je | reg/arith | `0x1fd387: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x7d3 | jae | mem | `0x1fd390: cmp %r15,(%rdi)` | call | 0x1fd3a5 | fwd |
| ECDSA scalar ladder (driver) | +0x7df | je | reg/arith | `0x1fd39d: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x7ed | je | reg/arith | `0x1fd3aa: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x7f6 | jae | mem | `0x1fd3b3: cmp %r15,(%rdi)` | call | 0x1fd3c8 | fwd |
| ECDSA scalar ladder (driver) | +0x802 | je | reg/arith | `0x1fd3c0: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x810 | je | reg/arith | `0x1fd3cd: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x819 | jae | mem | `0x1fd3d6: cmp %r15,(%rdi)` | call | 0x1fd3eb | fwd |
| ECDSA scalar ladder (driver) | +0x825 | je | reg/arith | `0x1fd3e3: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x837 | je | reg/arith | `0x1fd3f4: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x840 | jae | mem | `0x1fd3fd: cmp %r15,(%rdi)` | call | 0x1fd412 | fwd |
| ECDSA scalar ladder (driver) | +0x84c | je | reg/arith | `0x1fd40a: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x85e | je | reg/arith | `0x1fd41b: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x867 | jae | mem | `0x1fd424: cmp %r15,(%rdi)` | call | 0x1fd439 | fwd |
| ECDSA scalar ladder (driver) | +0x873 | je | reg/arith | `0x1fd431: test %al,%al` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x885 | je | reg/arith | `0x1fd442: test %rdi,%rdi` | memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x893 | jae | mem | `0x1fd44b: cmp %r15,(%rdi)` | call | 0x1fd465 | fwd |
| ECDSA scalar ladder (driver) | +0x89f | je | reg/arith | `0x1fd45d: test %al,%al` | memory | 0x1fce74 | back |
| ECDSA scalar ladder (driver) | +0x8aa | je | mem | `0x1fd465: cmpl $0x0,0x28(%r14)` | call+memory | 0x1fd57c | fwd |
| ECDSA scalar ladder (driver) | +0x8be | je | reg/arith | `0x1fd47c: test %al,%al` | memory | 0x1fd494 | fwd |
| ECDSA scalar ladder (driver) | +0x8ce | je | mem | `0x1fd487: cmp %rax,0x1a8(%r14)` | call+memory | 0x1fd623 | fwd |
| ECDSA scalar ladder (driver) | +0x8f7 | je | reg/arith | `0x1fd4b5: test %eax,%eax` | memory | 0x1fd5ba | fwd |
| ECDSA scalar ladder (driver) | +0x901 | jo | mem | `0x1fd4bd: decl 0x2c(%rsp)` | arithmetic/control | 0x1fd6e1 | fwd |
| ECDSA scalar ladder (driver) | +0x907 | js | unknown | `?` | memory | 0x1fd5c6 | fwd |
| ECDSA scalar ladder (driver) | +0x930 | jae | mem | `0x1fd4ec: cmp 0x10(%rcx),%rax` | memory | 0x1fd50a | fwd |
| ECDSA scalar ladder (driver) | +0x965 | je | mem | `0x1fd51f: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x1fd53e | fwd |
| ECDSA scalar ladder (driver) | +0x998 | je | reg/arith | `0x1fd556: test %eax,%eax` | memory | 0x1fd699 | fwd |
| ECDSA scalar ladder (driver) | +0x9a8 | jg | reg/arith | `0x1fd561: test %rbp,%rbp` | arithmetic/control | 0x1fd4dd | back |
| ECDSA scalar ladder (driver) | +0x9d1 | je | reg/arith | `0x1fd58e: test %rax,%rax` | call+memory | 0x1fd5b0 | fwd |
| ECDSA scalar ladder (driver) | +0x9e5 | jne | reg/arith | `0x1fd5a3: test %eax,%eax` | arithmetic/control | 0x1fd470 | back |
| ECDSA scalar ladder (driver) | +0xa2f | je | reg/arith | `0x1fd5ec: test %rax,%rax` | call+memory | 0x1fd60e | fwd |
| ECDSA scalar ladder (driver) | +0xa48 | je | reg/arith | `0x1fd606: test %eax,%eax` | call+memory | 0x1fd692 | fwd |
| ECDSA scalar ladder (driver) | +0xab3 | je | mem | `0x1fd66a: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x1fd6c4 | fwd |
| ECDSA scalar ladder (driver) | +0xaf9 | jne | reg/arith | `0x1fd6b6: test %rax,%rax` | arithmetic/control | 0x1fce87 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x531e27: test %rax,%rax` | memory | 0x5323c5 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x531e42: test %rbp,%rbp` | memory | 0x5323c5 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x531e52: test %rax,%rax` | call+memory | 0x5323c5 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x531e74: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x531e92: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x531eb0: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x531ece: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x531ef4: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x531f14: test %eax,%eax` | arithmetic/control | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x531f1c: test %r15,%r15` | memory | 0x531f42 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x531f2e: test %rdx,%rdx` | arithmetic/control | 0x531f64 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x531f5a: test %rdx,%rdx` | memory | 0x531f70 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x531f73: sub $0x1,%r9` | memory | 0x531f97 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x531f79: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x531f70 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x531f90: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x531fa0 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x531f9a: sub $0x1,%r8` | arithmetic/control | 0x531f90 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x531fa0: cmp %r9,%rdi` | memory | 0x531fc0 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x531fb0: sub $0x1,%rdi` | memory | 0x531fc2 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x531fba: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x531fb0 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x531fdd | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x531fd5: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x531fef: test %eax,%eax` | arithmetic/control | 0x5323c5 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x531ffc: test %r15,%r15` | memory | 0x53200b | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x532023: sub $0x1,%rdi` | memory | 0x532047 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x532029: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x532020 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x532040: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x532050 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x53204a: sub $0x1,%rsi` | arithmetic/control | 0x532040 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x532050: cmp %rdi,%rdx` | arithmetic/control | 0x532065 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x532055: sub $0x1,%rdx` | memory | 0x532067 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x53205f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x532055 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x53207e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x532076: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x532093: test %eax,%eax` | memory | 0x5323c5 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x5320ad: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x5320d0: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x5320eb: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x532105: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x532127: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x532141: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x532164: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x532186: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x5321a8: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x5321ca: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x5321e4: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x532200: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x532224: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x53223e: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x53225d: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x53227c: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x53229b: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x5322b5: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x5322d4: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x5322f1: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x532316: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x532335: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x532351: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x53236a: test %eax,%eax` | call+memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x532383: test %eax,%eax` | memory | 0x5323c3 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x532399: test %eax,%eax` | memory | 0x5323c5 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x5323c5: test %rbx,%rbx` | memory | 0x5323e8 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x5323ce: test %rax,%rax` | memory | 0x5323e8 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x20554b: test %rax,%rax` | memory | 0x205fb8 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x205565: cmpl $0x1,0x10(%rbp)` | memory | 0x20558d | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x205575: test %rax,%rax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x205584: cmp $0xfffffffd,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x205595: testb $0x4,0xa4(%rbp)` | memory | 0x2055b5 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x20559e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x205616 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x2055a7: test %r13b,%r13b` | arithmetic/control | 0x2056f0 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x2055bb: test %rax,%rax` | memory | 0x205fb8 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x2055e9: test %rax,%rax` | arithmetic/control | 0x205b00 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x2055f2: test %r15,%r15` | memory | 0x205600 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x20560a: test %rax,%rax` | arithmetic/control | 0x205678 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x205633: test %r15,%r15` | arithmetic/control | 0x2056d0 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x20563c: test %r14,%r14` | memory | 0x20564a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x205651: test %r15,%r15` | memory | 0x2056c2 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x20566b: test %eax,%eax` | memory | 0x2056b6 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x205694: test %eax,%eax` | memory | 0x205ad7 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x2056c2: test %r14,%r14` | memory | 0x2056d0 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x2056d6: or %r13b,%al` | arithmetic/control | 0x205902 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x2056e7: test %r15,%r15` | memory | 0x205fb8 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x2056f6: test %rax,%rax` | memory | 0x205fb8 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x205739: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x205747: test %rax,%rax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x20576d: test %rax,%rax` | call+memory | 0x206460 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x205796: test %eax,%eax` | call+memory | 0x206460 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x2057e4: test %al,0x38(%rsp)` | memory | 0x205863 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x2057f5: test %rax,%rax` | memory | 0x205fb8 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x20581b: test %rax,%rax` | call+memory | 0x205eb2 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x205855: test %ebp,%ebp` | arithmetic/control | 0x205fbb | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x205865: test %ebx,%ebx` | memory | 0x205d1e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x205877: test %r15b,%r15b` | call+memory | 0x205d28 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x20589e: test %r13,%r13` | arithmetic/control | 0x20645b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x2058ac: test %rax,%rax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x2058be: test %rax,%rax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x2058ce: test %rcx,%rcx` | memory | 0x205ebf | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x2058e6: cmpq $0x0,0x10(%rcx)` | memory | 0x205ec9 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x205927: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x205945: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x20596f: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x20598d: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x2059c6: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x2059e8: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x205a01: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x205a09: test %rbx,%rbx` | memory | 0x205a54 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x205a18: cmpl $0x0,0x18(%rbx)` | memory | 0x205a54 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x205a2e: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x205a36: cmpl $0x0,0x18(%rbx)` | memory | 0x205a54 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x205a4c: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x205a6a: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x205a8c: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x205aa9: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x205ae7: test %r15,%r15` | memory | 0x205af5 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x205af5: test %bl,%bl` | memory | 0x205ba8 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x205b22: test %rax,%rax` | arithmetic/control | 0x205bb0 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x205b2b: test %r15,%r15` | memory | 0x205b39 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x205b43: test %rax,%rax` | arithmetic/control | 0x205b4c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x205b68: test %eax,%eax` | memory | 0x205b83 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x205b93: test %r15,%r15` | memory | 0x205ba1 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x205ba1: test %bl,%bl` | arithmetic/control | 0x205bb0 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x205bba: test %ebx,%ebx` | memory | 0x205cab | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x205be9: test %bl,%bl` | arithmetic/control | 0x205d11 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x205bf4: cmp %r14,%r13` | memory | 0x205cab | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x205c28: test %rax,%rax` | arithmetic/control | 0x205bf1 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x205c2d: test %r15,%r15` | memory | 0x205c3b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x205c3f: test %rax,%rax` | arithmetic/control | 0x205c4d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x205c46: test %r15,%r15` | arithmetic/control | 0x205be0 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x205c62: test %eax,%eax` | memory | 0x205c88 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x205c7a: test %r15,%r15` | arithmetic/control | 0x205be0 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x205c9d: test %r15,%r15` | arithmetic/control | 0x205be0 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x205cb9: test %ebx,%ebx` | memory | 0x205d04 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x205cc5: cmp 0x6b1694(%rip),%rax        # 8b7360 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x641b80>` | call+memory | 0x20559e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x205d2d: test %al,%r14b` | memory | 0x205faf | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x205d63: test %eax,%eax` | arithmetic/control | 0x205fbb | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x205d6b: test %rbx,%rbx` | memory | 0x205d8e | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x205d70: cmpl $0x0,0x18(%rbx)` | memory | 0x205d8e | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x205d86: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x205da3: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x205db1: test %rax,%rax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x205dfd: test %ebp,%ebp` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x205e05: test %rbx,%rbx` | memory | 0x205e2d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x205e0f: cmpl $0x0,0x18(%rbx)` | memory | 0x205e2d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x205e25: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x205e45: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x205e5e: test %eax,%eax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x205e66: cmpl $0x0,0x28(%rsp)` | memory | 0x2061bc | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x205e7c: test %rax,%rax` | memory | 0x205fbb | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x205e92: test %rax,%rax` | memory | 0x2060c9 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x205e9b: cmpq $0x0,0x10(%rax)` | memory | 0x2060c9 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x205f0d: test %eax,%eax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x205f22: test %rax,%rax` | call+memory | 0x20645b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x205f46: test %eax,%eax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x205f4e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x205ff4 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x205fa6: test %al,%r14b` | arithmetic/control | 0x205d36 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x205faf: test %r15b,%r15b` | arithmetic/control | 0x2061bc | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x205fbb: test %r12,%r12` | memory | 0x205fe2 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x205fc5: test %rax,%rax` | memory | 0x205fe2 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x205ffd: test %rax,%rax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x206017: test %rax,%rax` | memory | 0x20602d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x20601c: cmpq $0x2,0x10(%rax)` | memory | 0x20602d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x20606a: test %eax,%eax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x20607f: test %rax,%rax` | call+memory | 0x20645b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x2060a3: test %eax,%eax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x2060ab: cmpl $0x2,0x28(%rsp)` | memory | 0x206373 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x2060e1: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x2060fe: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x206135: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x20613d: cmpq $0x0,0x8(%rsp)` | memory | 0x206169 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x20614a: cmpl $0x0,0x18(%rax)` | memory | 0x206169 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x206161: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x20617e: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x206199: test %eax,%eax` | memory | 0x206473 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x2061a1: cmpl $0x1,0x28(%rsp)` | memory | 0x20648b | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x2061c0: test %rdx,%rdx` | memory | 0x206352 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x2061cd: test %rcx,%rcx` | memory | 0x206352 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x2061de: cmp 0x6b117b(%rip),%rax        # 8b7360 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x641b80>` | memory | 0x206208 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x2061e7: test %rax,%rax` | call+memory | 0x205fb8 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x206225: test %eax,%eax` | memory | 0x205fbb | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x206240: test %eax,%eax` | memory | 0x205fbb | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x206260: cmp %rdx,%rcx` | memory | 0x206352 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x206269: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x206260 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x206294: test %eax,%eax` | memory | 0x20635d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x2062a1: cmpl $0x0,0x18(%rax)` | memory | 0x2062c4 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x2062bc: test %eax,%eax` | memory | 0x205fbb | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x2062d7: cmp %rdx,%rcx` | memory | 0x206365 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x2062e0: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x2062d7 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x2062f6: test %rax,%rax` | memory | 0x2063ac | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x20631b: test %rax,%rax` | call+memory | 0x206483 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x206381: test %rax,%rax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x206396: test %rax,%rax` | memory | 0x2063b7 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x20639b: cmpq $0x3,0x10(%rax)` | memory | 0x2063b7 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x2063f4: test %eax,%eax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x206405: test %rax,%rax` | call+memory | 0x20645b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x206425: test %eax,%eax` | memory | 0x20645b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x206429: cmpl $0x3,0x28(%rsp)` | memory | 0x205f6b | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x20649a: test %rax,%rax` | memory | 0x2064b0 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x20649f: cmpq $0x2,0x10(%rax)` | memory | 0x2064b0 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x2064c8: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x2064e1: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x206514: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x20651c: cmpq $0x0,0x8(%rsp)` | memory | 0x206548 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x206529: cmpl $0x0,0x18(%rax)` | memory | 0x206548 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x206540: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x20655d: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x206578: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x206580: cmpl $0x2,0x28(%rsp)` | memory | 0x2061ac | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x20659a: test %rax,%rax` | memory | 0x2065b0 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x20659f: cmpq $0x3,0x10(%rax)` | memory | 0x2065b0 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x2065c8: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x2065e5: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x20661c: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x112a | je | mem | `0x206624: cmpq $0x0,0x8(%rsp)` | memory | 0x206650 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x206631: cmpl $0x0,0x18(%rax)` | memory | 0x206650 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x206648: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x206665: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x206680: test %eax,%eax` | memory | 0x206473 | back |
| RSA CRT arms | +0x118d | je | mem | `0x206688: cmpl $0x3,0x28(%rsp)` | memory | 0x2061ac | back |
