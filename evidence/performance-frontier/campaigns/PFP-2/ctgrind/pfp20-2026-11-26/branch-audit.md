# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp20/distribution/libcrypto.so.3`
- SHA-256: `553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4`
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
| Montgomery multiply (core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith13mont_mul_into` @ 0x439bd0 | 1041 | 260 | 24 | 0 | 0 | 6 | 0 | 0 | 13 | 0 |
| Montgomery multiply (allocating wrapper) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_fallible` @ 0x162e20 | 857 | 207 | 13 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| Constant-time ladder core | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared` @ 0x43ba50 (carries `mod_exp_core_consttime_from_parts`) | 1693 | 430 | 42 | 0 | 2 | 4 | 0 | 0 | 20 | 0 |
| Constant-time inversion | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs21mod_inverse_consttime` @ 0x250d00 | 11101 | 2380 | 217 | 0 | 3 | 24 | 0 | 0 | 84 | 0 |
| ECDSA scalar ladder (driver) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult25ossl_ec_scalar_mul_ladder` @ 0x55abb0 | 3135 | 767 | 124 | 0 | 5 | 7 | 1 | 0 | 76 | 0 |
| EC ladder step (secret core) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl30ossl_ec_GFp_simple_ladder_step` @ 0x35c5d0 | 1609 | 424 | 61 | 0 | 0 | 0 | 0 | 0 | 45 | 0 |
| RSA CRT arms | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs3rsa4ossl16rsa_ossl_mod_exp` @ 0x55fef0 | 4517 | 1103 | 155 | 0 | 0 | 8 | 0 | 0 | 123 | 0 |
| P-256 Montgomery reduction | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x55c3f0 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x55c260 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |

## Coverage

- expected targets: 9
- resolved uniquely and disassembled: 9
- of those, audited through a verified inline mapping: 1
  - Constant-time ladder core: intended `mod_exp_core_consttime_from_parts` -> carrier `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared`
- failed: 0

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

- `cpuid` instructions in the DSO: **29**
- of those inside the audited ranges: **0**
- first addresses: 0x1690a8, 0x1690c9, 0x1690ea, 0x169101, 0x169153, 0x16916a, 0x1692f5, 0x169403, 0x1694a9, 0x169668, 0x31177c, 0x3117ac, 0x31d204, 0x31d272, 0x31d2e0, 0x31d34e, 0x3815ba, 0x38164c, 0x38189c, 0x3e4d1c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Montgomery multiply (core) | +0x52 | je | reg/arith | `0x439c1f: test %r14,%r14` | memory | 0x439e28 | fwd |
| Montgomery multiply (core) | +0x74 | je | mem | `0x439c40: cmp (%rsp),%rdi` | memory | 0x439f63 | fwd |
| Montgomery multiply (core) | +0x93 | je | reg/arith | `0x439c60: cmp %rbx,%r15` | memory | 0x439ec1 | fwd |
| Montgomery multiply (core) | +0xa0 | jae | reg/arith | `0x439c6d: cmp %r12,%rax` | memory | 0x439ed4 | fwd |
| Montgomery multiply (core) | +0xcb | jne | reg/arith | `0x439c98: cmp %rbx,%r14` | arithmetic/control | 0x439c60 | back |
| Montgomery multiply (core) | +0xd3 | jae | reg/arith | `0x439ca0: cmp %r12,%rdi` | memory | 0x439f77 | fwd |
| Montgomery multiply (core) | +0xec | jne | reg/arith | `0x439cb9: cmp %r14,%r10` | memory | 0x439c40 | back |
| Montgomery multiply (core) | +0xf8 | jae | reg/arith | `0x439cc5: cmp %r12,%r10` | memory | 0x439efa | fwd |
| Montgomery multiply (core) | +0x14c | je | reg/arith | `0x439d19: cmp %r14,%rax` | arithmetic/control | 0x439dba | fwd |
| Montgomery multiply (core) | +0x155 | je | reg/arith | `0x439d22: cmp %r12,%r10` | memory | 0x439faa | fwd |
| Montgomery multiply (core) | +0x183 | je | reg/arith | `0x439d50: cmp %rdi,%rbx` | memory | 0x439ee7 | fwd |
| Montgomery multiply (core) | +0x1af | jne | reg/arith | `0x439d7c: cmp %rdi,%r14` | memory | 0x439d50 | back |
| Montgomery multiply (core) | +0x1bd | je | mem | `0x439d88: cmp 0x10(%rsp),%r10` | memory | 0x439d00 | back |
| Montgomery multiply (core) | +0x1e3 | jne | reg/arith | `0x439db0: cmp %rax,%r15` | arithmetic/control | 0x439da0 | back |
| Montgomery multiply (core) | +0x223 | je | reg/arith | `0x439df0: cmp %rsi,%rbx` | memory | 0x439fbd | fwd |
| Montgomery multiply (core) | +0x24c | jne | reg/arith | `0x439e19: cmp %rsi,%r14` | arithmetic/control | 0x439df0 | back |
| Montgomery multiply (core) | +0x251 | jne | reg/arith | `0x439e1e: test %rbp,%rbp` | arithmetic/control | 0x439e4d | fwd |
| Montgomery multiply (core) | +0x25b | je | reg/arith | `0x439e28: test %r12,%r12` | memory | 0x439fd0 | fwd |
| Montgomery multiply (core) | +0x27b | je | reg/arith | `0x439e48: test %rbp,%rbp` | memory | 0x439eb2 | fwd |
| Montgomery multiply (core) | +0x2a7 | jae | reg/arith | `0x439e74: cmp %r12,%rdi` | arithmetic/control | 0x439f9a | fwd |
| Montgomery multiply (core) | +0x2b0 | je | reg/arith | `0x439e7d: cmp %rsi,%rbx` | memory | 0x439f87 | fwd |
| Montgomery multiply (core) | +0x2e0 | jne | reg/arith | `0x439eac: add $0xfffffffffffffff8,%rbp` | arithmetic/control | 0x439e70 | back |
| Montgomery multiply (core) | +0x343 | je | reg/arith | `0x439f10: cmp %rsi,%r12` | memory | 0x439f50 | fwd |
| Montgomery multiply (core) | +0x368 | jne | reg/arith | `0x439f35: cmp %rsi,%r14` | memory | 0x439f10 | back |
| Montgomery multiply (allocating wrapper) | +0x3c | jne | reg/arith | `0x162e59: test %rbx,%rbx` | memory | 0x162ebe | fwd |
| Montgomery multiply (allocating wrapper) | +0x7b | je | mem | `0x162e96: cmpb $0x0,0x8(%rsp)` | memory | 0x162f03 | fwd |
| Montgomery multiply (allocating wrapper) | +0x88 | je | reg/arith | `0x162ea5: test %rbx,%rbx` | arithmetic/control | 0x162ef4 | fwd |
| Montgomery multiply (allocating wrapper) | +0xc6 | je | mem | `0x162ee1: cmpb $0x0,0x8(%rsp)` | memory | 0x163017 | fwd |
| Montgomery multiply (allocating wrapper) | +0xf2 | jne | reg/arith | `0x162f0f: test %rbx,%rbx` | memory | 0x16304f | fwd |
| Montgomery multiply (allocating wrapper) | +0x148 | je | reg/arith | `0x162f65: test %rbx,%rbx` | memory | 0x162fb9 | fwd |
| Montgomery multiply (allocating wrapper) | +0x186 | jne | reg/arith | `0x162fa3: cmp %rax,%rbx` | memory | 0x162f70 | back |
| Montgomery multiply (allocating wrapper) | +0x1d6 | jne | reg/arith | `0x162ff3: cmp %rax,%r14` | arithmetic/control | 0x162fc0 | back |
| Montgomery multiply (allocating wrapper) | +0x203 | je | reg/arith | `0x16301f: cmp $0x1,%rbx` | memory | 0x163040 | fwd |
| Montgomery multiply (allocating wrapper) | +0x271 | je | mem | `0x16308c: cmpb $0x0,0x8(%rsp)` | memory | 0x163102 | fwd |
| Montgomery multiply (allocating wrapper) | +0x2c6 | jne | reg/arith | `0x1630e3: cmp %rax,%r14` | memory | 0x1630b0 | back |
| Montgomery multiply (allocating wrapper) | +0x2eb | jne | reg/arith | `0x163107: cmp $0x1,%rbx` | arithmetic/control | 0x163115 | fwd |
| Montgomery multiply (allocating wrapper) | +0x331 | jne | reg/arith | `0x16314e: test %rbx,%rbx` | call | 0x16315b | fwd |
| Constant-time ladder core | +0x19 | je | reg/arith | `0x43ba66: test %r12,%r12` | memory | 0x43bad8 | fwd |
| Constant-time ladder core | +0x35 | jne | reg/arith | `0x43ba81: cmp $0x1,%r12` | memory | 0x43baa9 | fwd |
| Constant-time ladder core | +0x3e | jne | reg/arith | `0x43ba8a: cmp $0x1,%r15` | memory | 0x43baac | fwd |
| Constant-time ladder core | +0x60 | jne | reg/arith | `0x43baac: test $0x1,%r15b` | call | 0x43bacc | fwd |
| Constant-time ladder core | +0x86 | jbe | reg/arith | `0x43bad3: cmp %rbx,%r13` | memory | 0x43baee | fwd |
| Constant-time ladder core | +0xe1 | je | mem | `0x43bb2c: cmpb $0x0,0x10(%rsp)` | memory | 0x43bb41 | fwd |
| Constant-time ladder core | +0x102 | je | reg/arith | `0x43bb49: cmp $0x1,%rbx` | memory | 0x43bb81 | fwd |
| Constant-time ladder core | +0x154 | jae | reg/arith | `0x43bba0: cmp $0x18,%rcx` | memory | 0x43bbb5 | fwd |
| Constant-time ladder core | +0x186 | je | reg/arith | `0x43bbd3: cmp %rdi,%r8` | arithmetic/control | 0x43bc51 | fwd |
| Constant-time ladder core | +0x191 | jae | reg/arith | `0x43bbde: cmp %r13,%r8` | memory | 0x43bc14 | fwd |
| Constant-time ladder core | +0x1a2 | jb | reg/arith | `0x43bbef: cmp %r13,%r8` | memory | 0x43bc23 | fwd |
| Constant-time ladder core | +0x1b1 | jb | reg/arith | `0x43bbfe: cmp %r13,%r8` | memory | 0x43bc34 | fwd |
| Constant-time ladder core | +0x1c0 | jb | reg/arith | `0x43bc0d: cmp %r13,%r8` | arithmetic/control | 0x43bbc3 | back |
| Constant-time ladder core | +0x1d1 | jae | reg/arith | `0x43bc1e: cmp %r13,%r8` | memory | 0x43bbf4 | back |
| Constant-time ladder core | +0x1e2 | jae | reg/arith | `0x43bc2f: cmp %r13,%r8` | memory | 0x43bc03 | back |
| Constant-time ladder core | +0x1f3 | jb | reg/arith | `0x43bc40: cmp %r13,%r8` | arithmetic/control | 0x43bbc3 | back |
| Constant-time ladder core | +0x204 | je | reg/arith | `0x43bc51: test %rax,%rax` | memory | 0x43bc96 | fwd |
| Constant-time ladder core | +0x22c | je | reg/arith | `0x43bc79: cmp %r8,%rax` | memory | 0x43bc96 | fwd |
| Constant-time ladder core | +0x235 | jb | reg/arith | `0x43bc82: cmp %r13,%r9` | memory | 0x43bc6e | back |
| Constant-time ladder core | +0x244 | jne | reg/arith | `0x43bc91: cmp %r8,%rax` | arithmetic/control | 0x43bc7e | back |
| Constant-time ladder core | +0x249 | je | reg/arith | `0x43bc96: test %r14,%r14` | memory | 0x43bd06 | fwd |
| Constant-time ladder core | +0x252 | jne | reg/arith | `0x43bc9f: test %r12,%r12` | memory | 0x43bf9d | fwd |
| Constant-time ladder core | +0x2b9 | je | reg/arith | `0x43bd06: test %r12,%r12` | arithmetic/control | 0x43c07e | fwd |
| Constant-time ladder core | +0x2c6 | jne | reg/arith | `0x43bd12: shr $0x3a,%rax` | arithmetic/control | 0x43bfcb | fwd |
| Constant-time ladder core | +0x2d3 | jne | reg/arith | `0x43bd1f: shr $0x39,%rax` | call+memory | 0x43bfcb | fwd |
| Constant-time ladder core | +0x2f6 | je | reg/arith | `0x43bd42: cmp $0xffffffffffffffff,%r14` | call+memory | 0x43bfcb | fwd |
| Constant-time ladder core | +0x334 | je | reg/arith | `0x43bd76: cmp $0xffffffffffffffff,%rbp` | memory | 0x43bf05 | fwd |
| Constant-time ladder core | +0x34c | je | reg/arith | `0x43bd94: test %r8,%r8` | arithmetic/control | 0x43c091 | fwd |
| Constant-time ladder core | +0x3f3 | je | mem | `0x43be2e: cmpq $0xffffffffffffffff,0x10(%rsp)` | memory | 0x43bf0e | fwd |
| Constant-time ladder core | +0x437 | je | reg/arith | `0x43be84: test %rbp,%rbp` | memory | 0x43bea0 | fwd |
| Constant-time ladder core | +0x46a | jne | reg/arith | `0x43beb8: or %al,%cl` | memory | 0x43bef7 | fwd |
| Constant-time ladder core | +0x4a5 | jne | reg/arith | `0x43bef2: cmp %rax,%rsi` | arithmetic/control | 0x43bebe | back |
| Constant-time ladder core | +0x4aa | je | reg/arith | `0x43bef7: test %r14,%r14` | arithmetic/control | 0x43bfd7 | fwd |
| Constant-time ladder core | +0x4c8 | je | reg/arith | `0x43bf15: test %rbp,%rbp` | memory | 0x43bf31 | fwd |
| Constant-time ladder core | +0x4fb | jne | reg/arith | `0x43bf49: or %al,%cl` | memory | 0x43bf88 | fwd |
| Constant-time ladder core | +0x536 | jne | reg/arith | `0x43bf83: cmp %rax,%rsi` | arithmetic/control | 0x43bf4f | back |
| Constant-time ladder core | +0x53b | je | reg/arith | `0x43bf88: test %r14,%r14` | memory | 0x43bfd7 | fwd |
| Constant-time ladder core | +0x579 | je | mem | `0x43bfc4: cmpb $0x0,0x10(%rsp)` | memory | 0x43c035 | fwd |
| Constant-time ladder core | +0x58a | je | reg/arith | `0x43bfd7: test %rbx,%rbx` | memory | 0x43badf | back |
| Constant-time ladder core | +0x5ca | jne | reg/arith | `0x43c017: cmp %rax,%rsi` | memory | 0x43bfec | back |
| Constant-time ladder core | +0x5f1 | je | reg/arith | `0x43c03d: cmp $0x1,%r12` | memory | 0x43c061 | fwd |
| Constant-time ladder core | +0x65f | je | reg/arith | `0x43c0ac: test %rbp,%rbp` | memory | 0x43c0c8 | fwd |
| Constant-time inversion | +0x17 | je | reg/arith | `0x250d14: test %r8,%r8` | memory | 0x250d65 | fwd |
| Constant-time inversion | +0x1f | je | mem | `0x250d1c: testb $0x1,(%rcx)` | arithmetic/control | 0x250d65 | fwd |
| Constant-time inversion | +0x32 | jne | reg/arith | `0x250d2e: shr $0x39,%rax` | call+memory | 0x250d65 | fwd |
| Constant-time inversion | +0x63 | je | mem | `0x250d5e: cmpb $0x0,0x10(%rsp)` | memory | 0x250d82 | fwd |
| Constant-time inversion | +0x8e | je | reg/arith | `0x250d8a: cmp $0x1,%rbx` | memory | 0x250dab | fwd |
| Constant-time inversion | +0xea | je | mem | `0x250de5: cmpb $0x0,0x10(%rsp)` | memory | 0x250e4e | fwd |
| Constant-time inversion | +0x136 | jne | reg/arith | `0x250e33: cmp %rax,%rbx` | memory | 0x250e00 | back |
| Constant-time inversion | +0x15a | je | reg/arith | `0x250e56: cmp $0x1,%rbx` | memory | 0x250e77 | fwd |
| Constant-time inversion | +0x1c0 | je | mem | `0x250ebb: cmpb $0x0,0x10(%rsp)` | memory | 0x250f17 | fwd |
| Constant-time inversion | +0x202 | jne | reg/arith | `0x250eff: cmp %rax,%rsi` | memory | 0x250ecc | back |
| Constant-time inversion | +0x22c | je | mem | `0x250f1f: cmpq $0x1,(%rsp)` | memory | 0x250f57 | fwd |
| Constant-time inversion | +0x28b | je | mem | `0x250f86: cmpb $0x0,0x10(%rsp)` | memory | 0x251016 | fwd |
| Constant-time inversion | +0x2b5 | jne | reg/arith | `0x250fb3: or %cl,%dl` | memory | 0x250ff5 | fwd |
| Constant-time inversion | +0x2ef | jne | reg/arith | `0x250fec: cmp %rax,%rsi` | memory | 0x250fc1 | back |
| Constant-time inversion | +0x2f8 | je | reg/arith | `0x250ff5: test %rax,%rax` | memory | 0x250ec2 | back |
| Constant-time inversion | +0x328 | je | mem | `0x251023: cmpq $0x1,(%rsp)` | memory | 0x251052 | fwd |
| Constant-time inversion | +0x37e | je | mem | `0x251079: cmpb $0x0,0x10(%rsp)` | memory | 0x251115 | fwd |
| Constant-time inversion | +0x3b1 | jne | reg/arith | `0x2510af: or %cl,%al` | memory | 0x2510ed | fwd |
| Constant-time inversion | +0x3eb | jne | reg/arith | `0x2510e8: cmp %rax,%rsi` | memory | 0x2510bd | back |
| Constant-time inversion | +0x3f2 | je | mem | `0x2510ed: cmpq $0x0,(%rsp)` | memory | 0x251107 | fwd |
| Constant-time inversion | +0x421 | je | reg/arith | `0x25111d: cmp $0x1,%rbx` | memory | 0x251141 | fwd |
| Constant-time inversion | +0x46d | je | mem | `0x251168: cmpb $0x0,0x10(%rsp)` | memory | 0x25117d | fwd |
| Constant-time inversion | +0x48b | je | reg/arith | `0x251187: cmp $0x1,%rbx` | memory | 0x2511af | fwd |
| Constant-time inversion | +0x4dd | je | reg/arith | `0x2511d9: cmp $0xffffffffffffffff,%rax` | call+memory | 0x251756 | fwd |
| Constant-time inversion | +0x524 | je | reg/arith | `0x251220: cmp $0xffffffffffffffff,%rax` | call+memory | 0x251764 | fwd |
| Constant-time inversion | +0x56b | je | reg/arith | `0x251267: cmp $0xffffffffffffffff,%rax` | call+memory | 0x252fb0 | fwd |
| Constant-time inversion | +0x5b2 | je | reg/arith | `0x2512ae: cmp $0xffffffffffffffff,%rax` | call+memory | 0x252fbe | fwd |
| Constant-time inversion | +0x5fa | je | reg/arith | `0x2512f6: cmp $0xffffffffffffffff,%rax` | call+memory | 0x252fcc | fwd |
| Constant-time inversion | +0x642 | je | reg/arith | `0x25133e: cmp $0xffffffffffffffff,%rax` | call+memory | 0x252fda | fwd |
| Constant-time inversion | +0x68a | je | reg/arith | `0x251386: cmp $0xffffffffffffffff,%rax` | call+memory | 0x252fe8 | fwd |
| Constant-time inversion | +0x6cf | je | reg/arith | `0x2513cb: cmp $0xffffffffffffffff,%rax` | call+memory | 0x252ff6 | fwd |
| Constant-time inversion | +0x714 | je | reg/arith | `0x251410: cmp $0xffffffffffffffff,%rax` | call+memory | 0x253004 | fwd |
| Constant-time inversion | +0x759 | je | reg/arith | `0x251455: cmp $0xffffffffffffffff,%rax` | call+memory | 0x2532b5 | fwd |
| Constant-time inversion | +0x79f | je | reg/arith | `0x25149b: cmp $0xffffffffffffffff,%rax` | memory | 0x2532c0 | fwd |
| Constant-time inversion | +0xb14 | je | mem | `0x2517fc: cmp 0x2b0(%rsp),%rdx` | memory | 0x253012 | fwd |
| Constant-time inversion | +0xbcf | je | mem | `0x2518c6: cmpq $0x0,0x148(%rsp)` | memory | 0x251928 | fwd |
| Constant-time inversion | +0xc0e | je | reg/arith | `0x25190a: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x25192a | fwd |
| Constant-time inversion | +0xc13 | jae | reg/arith | `0x251910: cmp %rbx,%rcx` | memory | 0x25191c | fwd |
| Constant-time inversion | +0xc21 | jb | reg/arith | `0x25191e: cmp %rbx,%rcx` | arithmetic/control | 0x2518df | back |
| Constant-time inversion | +0xc33 | je | mem | `0x25192a: cmpq $0x0,0x140(%rsp)` | memory | 0x25198f | fwd |
| Constant-time inversion | +0xc71 | je | reg/arith | `0x25196d: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x25198f | fwd |
| Constant-time inversion | +0xc76 | jae | reg/arith | `0x251973: cmp %rbx,%rcx` | memory | 0x251983 | fwd |
| Constant-time inversion | +0xc88 | jb | reg/arith | `0x251985: cmp %rbx,%rcx` | arithmetic/control | 0x251944 | back |
| Constant-time inversion | +0xcdf | je | mem | `0x2519d6: cmpq $0x0,0x130(%rsp)` | memory | 0x251ace | fwd |
| Constant-time inversion | +0xcee | je | mem | `0x2519e5: cmpq $0x0,0x270(%rsp)` | memory | 0x251a98 | fwd |
| Constant-time inversion | +0xd47 | je | reg/arith | `0x251a43: add $0xfffffffffffffffe,%r8` | memory | 0x251a87 | fwd |
| Constant-time inversion | +0xd58 | jae | reg/arith | `0x251a55: cmp %rbx,%rdi` | memory | 0x251a65 | fwd |
| Constant-time inversion | +0xd81 | jb | reg/arith | `0x251a7e: cmp %rbx,%rcx` | arithmetic/control | 0x251a1a | back |
| Constant-time inversion | +0xd8f | je | mem | `0x251a87: testb $0x1,0x250(%rsp)` | memory | 0x251ace | fwd |
| Constant-time inversion | +0xdbb | jae | reg/arith | `0x251ab8: cmp %rbx,%rdi` | memory | 0x251ac4 | fwd |
| Constant-time inversion | +0xdd7 | je | mem | `0x251ace: cmpq $0x0,0x150(%rsp)` | memory | 0x251be1 | fwd |
| Constant-time inversion | +0xde6 | je | mem | `0x251add: cmpq $0x0,0x268(%rsp)` | memory | 0x251b9f | fwd |
| Constant-time inversion | +0xe43 | je | reg/arith | `0x251b3f: add $0xfffffffffffffffe,%r8` | memory | 0x251b8e | fwd |
| Constant-time inversion | +0xe5a | jae | mem | `0x251b52: cmp 0x148(%rsp),%rdi` | memory | 0x251b67 | fwd |
| Constant-time inversion | +0xe88 | jb | mem | `0x251b80: cmp 0x148(%rsp),%rcx` | arithmetic/control | 0x251b16 | back |
| Constant-time inversion | +0xe96 | je | mem | `0x251b8e: testb $0x1,0x248(%rsp)` | memory | 0x251be1 | fwd |
| Constant-time inversion | +0xec7 | jae | mem | `0x251bbf: cmp 0x148(%rsp),%rdi` | memory | 0x251bd7 | fwd |
| Constant-time inversion | +0xf60 | je | reg/arith | `0x251c5c: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x251ca4 | fwd |
| Constant-time inversion | +0xf65 | jae | reg/arith | `0x251c62: cmp %rbx,%rcx` | memory | 0x251c6e | fwd |
| Constant-time inversion | +0xf78 | jae | mem | `0x251c70: cmp 0x130(%rsp),%rcx` | memory | 0x251c88 | fwd |
| Constant-time inversion | +0xf9e | jb | mem | `0x251c96: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x251c3b | back |
| Constant-time inversion | +0xfad | je | mem | `0x251ca4: cmpq $0x0,0x130(%rsp)` | memory | 0x251da5 | fwd |
| Constant-time inversion | +0xfbc | je | mem | `0x251cb3: cmpq $0x0,0x270(%rsp)` | memory | 0x251d6b | fwd |
| Constant-time inversion | +0x101a | je | reg/arith | `0x251d16: add $0xfffffffffffffffe,%r8` | memory | 0x251d5a | fwd |
| Constant-time inversion | +0x102b | jae | reg/arith | `0x251d28: cmp %rbx,%rdi` | memory | 0x251d38 | fwd |
| Constant-time inversion | +0x1054 | jb | reg/arith | `0x251d51: cmp %rbx,%rcx` | arithmetic/control | 0x251ced | back |
| Constant-time inversion | +0x1062 | je | mem | `0x251d5a: testb $0x1,0x250(%rsp)` | memory | 0x251da5 | fwd |
| Constant-time inversion | +0x108e | jae | reg/arith | `0x251d8b: cmp %rbx,%rdi` | memory | 0x251d9b | fwd |
| Constant-time inversion | +0x10ae | je | mem | `0x251da5: cmpq $0x0,0x150(%rsp)` | memory | 0x251eb8 | fwd |
| Constant-time inversion | +0x10bd | je | mem | `0x251db4: cmpq $0x0,0x268(%rsp)` | memory | 0x251e76 | fwd |
| Constant-time inversion | +0x111a | je | reg/arith | `0x251e16: add $0xfffffffffffffffe,%r8` | memory | 0x251e65 | fwd |
| Constant-time inversion | +0x1131 | jae | mem | `0x251e29: cmp 0x140(%rsp),%rdi` | memory | 0x251e3e | fwd |
| Constant-time inversion | +0x115f | jb | mem | `0x251e57: cmp 0x140(%rsp),%rcx` | arithmetic/control | 0x251ded | back |
| Constant-time inversion | +0x116d | je | mem | `0x251e65: testb $0x1,0x248(%rsp)` | memory | 0x251eb8 | fwd |
| Constant-time inversion | +0x119e | jae | mem | `0x251e96: cmp 0x140(%rsp),%rdi` | memory | 0x251eae | fwd |
| Constant-time inversion | +0x121f | je | reg/arith | `0x251f1b: add $0xfffffffffffffff8,%rax` | arithmetic/control | 0x251f67 | fwd |
| Constant-time inversion | +0x1224 | jae | reg/arith | `0x251f21: cmp %rbx,%rcx` | memory | 0x251f31 | fwd |
| Constant-time inversion | +0x123b | jae | mem | `0x251f33: cmp 0x130(%rsp),%rcx` | memory | 0x251f4b | fwd |
| Constant-time inversion | +0x1261 | jb | mem | `0x251f59: cmp 0x150(%rsp),%rcx` | arithmetic/control | 0x251efa | back |
| Constant-time inversion | +0x1270 | je | mem | `0x251f67: cmpq $0x0,0x80(%rsp)` | memory | 0x251f7f | fwd |
| Constant-time inversion | +0x1297 | je | mem | `0x251f8e: cmpq $0x0,0x118(%rsp)` | memory | 0x2520af | fwd |
| Constant-time inversion | +0x12a6 | je | mem | `0x251f9d: cmpq $0x0,0x198(%rsp)` | memory | 0x252073 | fwd |
| Constant-time inversion | +0x1307 | je | reg/arith | `0x252003: add $0xfffffffffffffffe,%r8` | memory | 0x25205f | fwd |
| Constant-time inversion | +0x1321 | jae | mem | `0x252019: cmp 0x80(%rsp),%rdi` | memory | 0x252031 | fwd |
| Constant-time inversion | +0x1355 | jb | mem | `0x25204d: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x251fd4 | back |
| Constant-time inversion | +0x1367 | je | mem | `0x25205f: testb $0x1,0x180(%rsp)` | memory | 0x2520af | fwd |
| Constant-time inversion | +0x1398 | jae | mem | `0x252090: cmp 0x80(%rsp),%rdi` | memory | 0x2520a5 | fwd |
| Constant-time inversion | +0x13b8 | je | mem | `0x2520af: cmpq $0x0,0x188(%rsp)` | memory | 0x252113 | fwd |
| Constant-time inversion | +0x13ef | je | reg/arith | `0x2520eb: add $0xfffffffffffffff8,%rax` | memory | 0x252113 | fwd |
| Constant-time inversion | +0x13f9 | jae | mem | `0x2520f1: cmp 0x80(%rsp),%rcx` | memory | 0x252106 | fwd |
| Constant-time inversion | +0x140c | jb | mem | `0x252108: cmp (%rsp),%rcx` | arithmetic/control | 0x2520c8 | back |
| Constant-time inversion | +0x141f | ja | mem | `0x25211b: cmp %rax,(%rsp)` | arithmetic/control | 0x253469 | fwd |
| Constant-time inversion | +0x1425 | jae | unknown | `?` | memory | 0x253523 | fwd |
| Constant-time inversion | +0x1431 | je | mem | `0x25212b: cmpq $0x0,0x28(%rsp)` | memory | 0x252200 | fwd |
| Constant-time inversion | +0x144c | jne | mem | `0x252144: testb $0x8,0xa0(%rsp)` | memory | 0x25216f | fwd |
| Constant-time inversion | +0x145a | jae | mem | `0x252156: cmp (%rsp),%rax` | memory | 0x252179 | fwd |
| Constant-time inversion | +0x149a | je | mem | `0x252191: cmpq $0x0,0xa0(%rsp)` | memory | 0x252200 | fwd |
| Constant-time inversion | +0x14c8 | je | mem | `0x2521c3: cmp 0x30(%rsp),%rax` | memory | 0x252200 | fwd |
| Constant-time inversion | +0x14d5 | jae | mem | `0x2521d1: cmp (%rsp),%rdi` | memory | 0x2521e2 | fwd |
| Constant-time inversion | +0x14fa | jb | mem | `0x2521f6: cmp (%rsp),%rcx` | arithmetic/control | 0x2521a9 | back |
| Constant-time inversion | +0x1509 | je | mem | `0x252200: cmpq $0x0,0x118(%rsp)` | memory | 0x2522cf | fwd |
| Constant-time inversion | +0x1518 | je | mem | `0x25220f: cmpq $0x0,0x198(%rsp)` | memory | 0x2522a3 | fwd |
| Constant-time inversion | +0x1553 | je | mem | `0x25224b: cmp 0x1b0(%rsp),%rdx` | memory | 0x25228f | fwd |
| Constant-time inversion | +0x1560 | jae | mem | `0x25225b: cmp 0x28(%rsp),%rdx` | memory | 0x25226d | fwd |
| Constant-time inversion | +0x1589 | jb | mem | `0x252284: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x252227 | back |
| Constant-time inversion | +0x1597 | je | mem | `0x25228f: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x2522cf | fwd |
| Constant-time inversion | +0x15af | jae | mem | `0x2522aa: cmp 0x28(%rsp),%rax` | memory | 0x2522bc | fwd |
| Constant-time inversion | +0x15d5 | je | mem | `0x2522cf: cmpq $0x0,0x28(%rsp)` | memory | 0x25233e | fwd |
| Constant-time inversion | +0x1611 | je | reg/arith | `0x25230d: add $0xfffffffffffffff8,%rax` | memory | 0x252339 | fwd |
| Constant-time inversion | +0x161b | jae | mem | `0x252313: cmp 0x80(%rsp),%rcx` | memory | 0x252328 | fwd |
| Constant-time inversion | +0x1632 | jb | mem | `0x25232a: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x2522e5 | back |
| Constant-time inversion | +0x1646 | je | mem | `0x252340: cmpq $0x0,0x68(%rsp)` | memory | 0x2523b7 | fwd |
| Constant-time inversion | +0x1688 | je | reg/arith | `0x252384: add $0xfffffffffffffff8,%rax` | memory | 0x2523a7 | fwd |
| Constant-time inversion | +0x168e | jae | mem | `0x25238a: cmp (%rsp),%rcx` | memory | 0x252399 | fwd |
| Constant-time inversion | +0x16a0 | jb | mem | `0x25239b: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x252357 | back |
| Constant-time inversion | +0x16cf | je | mem | `0x2523c6: cmpq $0x0,0x110(%rsp)` | memory | 0x2524dc | fwd |
| Constant-time inversion | +0x16de | je | mem | `0x2523d5: cmpq $0x0,0x190(%rsp)` | memory | 0x2524a0 | fwd |
| Constant-time inversion | +0x173e | je | reg/arith | `0x25243a: add $0xfffffffffffffffe,%r8` | memory | 0x25248c | fwd |
| Constant-time inversion | +0x1755 | jae | mem | `0x252450: cmp 0x68(%rsp),%rdi` | memory | 0x252465 | fwd |
| Constant-time inversion | +0x1786 | jb | mem | `0x252481: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x25240b | back |
| Constant-time inversion | +0x1794 | je | mem | `0x25248c: testb $0x1,0x178(%rsp)` | memory | 0x2524dc | fwd |
| Constant-time inversion | +0x17c2 | jae | mem | `0x2524bd: cmp 0x68(%rsp),%rdi` | memory | 0x2524d2 | fwd |
| Constant-time inversion | +0x1811 | je | reg/arith | `0x25250d: add $0xfffffffffffffff8,%rax` | memory | 0x252535 | fwd |
| Constant-time inversion | +0x1818 | jae | mem | `0x252513: cmp 0x68(%rsp),%rcx` | memory | 0x252528 | fwd |
| Constant-time inversion | +0x182e | jb | mem | `0x25252a: cmp (%rsp),%rcx` | arithmetic/control | 0x2524ea | back |
| Constant-time inversion | +0x183b | je | mem | `0x252535: cmpq $0x0,0x28(%rsp)` | memory | 0x25260a | fwd |
| Constant-time inversion | +0x1856 | jne | mem | `0x25254e: testb $0x8,0xa0(%rsp)` | memory | 0x252579 | fwd |
| Constant-time inversion | +0x1864 | jae | mem | `0x252560: cmp (%rsp),%rax` | memory | 0x252583 | fwd |
| Constant-time inversion | +0x18a4 | je | mem | `0x25259b: cmpq $0x0,0xa0(%rsp)` | memory | 0x25260a | fwd |
| Constant-time inversion | +0x18d2 | je | mem | `0x2525cd: cmp 0x30(%rsp),%rax` | memory | 0x25260a | fwd |
| Constant-time inversion | +0x18df | jae | mem | `0x2525db: cmp (%rsp),%rdi` | memory | 0x2525ec | fwd |
| Constant-time inversion | +0x1904 | jb | mem | `0x252600: cmp (%rsp),%rcx` | arithmetic/control | 0x2525b3 | back |
| Constant-time inversion | +0x1913 | je | mem | `0x25260a: cmpq $0x0,0x110(%rsp)` | memory | 0x2526d9 | fwd |
| Constant-time inversion | +0x1922 | je | mem | `0x252619: cmpq $0x0,0x190(%rsp)` | memory | 0x2526ad | fwd |
| Constant-time inversion | +0x195d | je | mem | `0x252655: cmp 0x1a8(%rsp),%rdx` | memory | 0x252699 | fwd |
| Constant-time inversion | +0x196a | jae | mem | `0x252665: cmp 0x28(%rsp),%rdx` | memory | 0x252677 | fwd |
| Constant-time inversion | +0x1993 | jb | mem | `0x25268e: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x252631 | back |
| Constant-time inversion | +0x19a1 | je | mem | `0x252699: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x2526d9 | fwd |
| Constant-time inversion | +0x19b9 | jae | mem | `0x2526b4: cmp 0x28(%rsp),%rax` | memory | 0x2526c6 | fwd |
| Constant-time inversion | +0x1a04 | je | mem | `0x2526fb: cmpq $0x0,0x1f8(%rsp)` | memory | 0x252792 | fwd |
| Constant-time inversion | +0x1a53 | je | reg/arith | `0x25274f: add $0xfffffffffffffff8,%rax` | memory | 0x252792 | fwd |
| Constant-time inversion | +0x1a5d | jae | mem | `0x252755: cmp 0x80(%rsp),%rcx` | memory | 0x25276a | fwd |
| Constant-time inversion | +0x1a74 | jae | mem | `0x25276c: cmp 0x118(%rsp),%rcx` | memory | 0x252781 | fwd |
| Constant-time inversion | +0x1a8c | jb | mem | `0x252784: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x25271e | back |
| Constant-time inversion | +0x1a9b | je | mem | `0x252792: cmpq $0x0,0x88(%rsp)` | memory | 0x2527aa | fwd |
| Constant-time inversion | +0x1ac2 | je | mem | `0x2527b9: cmpq $0x0,0x118(%rsp)` | memory | 0x2528da | fwd |
| Constant-time inversion | +0x1ad1 | je | mem | `0x2527c8: cmpq $0x0,0x198(%rsp)` | memory | 0x25289e | fwd |
| Constant-time inversion | +0x1b32 | je | reg/arith | `0x25282e: add $0xfffffffffffffffe,%r8` | memory | 0x25288a | fwd |
| Constant-time inversion | +0x1b4c | jae | mem | `0x252844: cmp 0x88(%rsp),%rdi` | memory | 0x25285c | fwd |
| Constant-time inversion | +0x1b80 | jb | mem | `0x252878: cmp 0x88(%rsp),%rcx` | arithmetic/control | 0x2527ff | back |
| Constant-time inversion | +0x1b92 | je | mem | `0x25288a: testb $0x1,0x180(%rsp)` | memory | 0x2528da | fwd |
| Constant-time inversion | +0x1bc3 | jae | mem | `0x2528bb: cmp 0x88(%rsp),%rdi` | memory | 0x2528d0 | fwd |
| Constant-time inversion | +0x1c0f | je | reg/arith | `0x25290b: add $0xfffffffffffffff8,%rax` | memory | 0x252933 | fwd |
| Constant-time inversion | +0x1c19 | jae | mem | `0x252911: cmp 0x88(%rsp),%rcx` | memory | 0x252926 | fwd |
| Constant-time inversion | +0x1c2c | jb | mem | `0x252928: cmp (%rsp),%rcx` | arithmetic/control | 0x2528e8 | back |
| Constant-time inversion | +0x1c39 | je | mem | `0x252933: cmpq $0x0,0x28(%rsp)` | memory | 0x252a08 | fwd |
| Constant-time inversion | +0x1c54 | jne | mem | `0x25294c: testb $0x8,0xa0(%rsp)` | memory | 0x252977 | fwd |
| Constant-time inversion | +0x1c62 | jae | mem | `0x25295e: cmp (%rsp),%rax` | memory | 0x252981 | fwd |
| Constant-time inversion | +0x1ca2 | je | mem | `0x252999: cmpq $0x0,0xa0(%rsp)` | memory | 0x252a08 | fwd |
| Constant-time inversion | +0x1cd0 | je | mem | `0x2529cb: cmp 0x30(%rsp),%rax` | memory | 0x252a08 | fwd |
| Constant-time inversion | +0x1cdd | jae | mem | `0x2529d9: cmp (%rsp),%rdi` | memory | 0x2529ea | fwd |
| Constant-time inversion | +0x1d02 | jb | mem | `0x2529fe: cmp (%rsp),%rcx` | arithmetic/control | 0x2529b1 | back |
| Constant-time inversion | +0x1d11 | je | mem | `0x252a08: cmpq $0x0,0x118(%rsp)` | memory | 0x252ad7 | fwd |
| Constant-time inversion | +0x1d20 | je | mem | `0x252a17: cmpq $0x0,0x198(%rsp)` | memory | 0x252aab | fwd |
| Constant-time inversion | +0x1d5b | je | mem | `0x252a53: cmp 0x1b0(%rsp),%rdx` | memory | 0x252a97 | fwd |
| Constant-time inversion | +0x1d68 | jae | mem | `0x252a63: cmp 0x28(%rsp),%rdx` | memory | 0x252a75 | fwd |
| Constant-time inversion | +0x1d91 | jb | mem | `0x252a8c: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x252a2f | back |
| Constant-time inversion | +0x1d9f | je | mem | `0x252a97: testb $0x1,0x180(%rsp)` | arithmetic/control | 0x252ad7 | fwd |
| Constant-time inversion | +0x1db7 | jae | mem | `0x252ab2: cmp 0x28(%rsp),%rax` | memory | 0x252ac4 | fwd |
| Constant-time inversion | +0x1ddd | je | mem | `0x252ad7: cmpq $0x0,0x28(%rsp)` | memory | 0x252b46 | fwd |
| Constant-time inversion | +0x1e19 | je | reg/arith | `0x252b15: add $0xfffffffffffffff8,%rax` | memory | 0x252b41 | fwd |
| Constant-time inversion | +0x1e23 | jae | mem | `0x252b1b: cmp 0x88(%rsp),%rcx` | memory | 0x252b30 | fwd |
| Constant-time inversion | +0x1e3a | jb | mem | `0x252b32: cmp 0x80(%rsp),%rcx` | arithmetic/control | 0x252aed | back |
| Constant-time inversion | +0x1e4e | je | mem | `0x252b48: cmpq $0x0,0x68(%rsp)` | memory | 0x252bbf | fwd |
| Constant-time inversion | +0x1e90 | je | reg/arith | `0x252b8c: add $0xfffffffffffffff8,%rax` | memory | 0x252baf | fwd |
| Constant-time inversion | +0x1e96 | jae | mem | `0x252b92: cmp (%rsp),%rcx` | memory | 0x252ba1 | fwd |
| Constant-time inversion | +0x1ea8 | jb | mem | `0x252ba3: cmp 0x28(%rsp),%rcx` | arithmetic/control | 0x252b5f | back |
| Constant-time inversion | +0x1ed7 | je | mem | `0x252bce: cmpq $0x0,0x110(%rsp)` | memory | 0x252ce4 | fwd |
| Constant-time inversion | +0x1ee6 | je | mem | `0x252bdd: cmpq $0x0,0x190(%rsp)` | memory | 0x252ca8 | fwd |
| Constant-time inversion | +0x1f46 | je | reg/arith | `0x252c42: add $0xfffffffffffffffe,%r8` | memory | 0x252c94 | fwd |
| Constant-time inversion | +0x1f5d | jae | mem | `0x252c58: cmp 0x68(%rsp),%rdi` | memory | 0x252c6d | fwd |
| Constant-time inversion | +0x1f8e | jb | mem | `0x252c89: cmp 0x68(%rsp),%rcx` | arithmetic/control | 0x252c13 | back |
| Constant-time inversion | +0x1f9c | je | mem | `0x252c94: testb $0x1,0x178(%rsp)` | memory | 0x252ce4 | fwd |
| Constant-time inversion | +0x1fca | jae | mem | `0x252cc5: cmp 0x68(%rsp),%rdi` | memory | 0x252cda | fwd |
| Constant-time inversion | +0x2019 | je | reg/arith | `0x252d15: add $0xfffffffffffffff8,%rax` | memory | 0x252d3d | fwd |
| Constant-time inversion | +0x2020 | jae | mem | `0x252d1b: cmp 0x68(%rsp),%rcx` | memory | 0x252d30 | fwd |
| Constant-time inversion | +0x2036 | jb | mem | `0x252d32: cmp (%rsp),%rcx` | arithmetic/control | 0x252cf2 | back |
| Constant-time inversion | +0x2043 | je | mem | `0x252d3d: cmpq $0x0,0x28(%rsp)` | memory | 0x252e12 | fwd |
| Constant-time inversion | +0x205e | jne | mem | `0x252d56: testb $0x8,0xa0(%rsp)` | memory | 0x252d81 | fwd |
| Constant-time inversion | +0x206c | jae | mem | `0x252d68: cmp (%rsp),%rax` | memory | 0x252d8b | fwd |
| Constant-time inversion | +0x20ac | je | mem | `0x252da3: cmpq $0x0,0xa0(%rsp)` | memory | 0x252e12 | fwd |
| Constant-time inversion | +0x20da | je | mem | `0x252dd5: cmp 0x30(%rsp),%rax` | memory | 0x252e12 | fwd |
| Constant-time inversion | +0x20e7 | jae | mem | `0x252de3: cmp (%rsp),%rdi` | memory | 0x252df4 | fwd |
| Constant-time inversion | +0x210c | jb | mem | `0x252e08: cmp (%rsp),%rcx` | arithmetic/control | 0x252dbb | back |
| Constant-time inversion | +0x211b | je | mem | `0x252e12: cmpq $0x0,0x110(%rsp)` | memory | 0x252ee1 | fwd |
| Constant-time inversion | +0x212a | je | mem | `0x252e21: cmpq $0x0,0x190(%rsp)` | memory | 0x252eb5 | fwd |
| Constant-time inversion | +0x2165 | je | mem | `0x252e5d: cmp 0x1a8(%rsp),%rdx` | memory | 0x252ea1 | fwd |
| Constant-time inversion | +0x2172 | jae | mem | `0x252e6d: cmp 0x28(%rsp),%rdx` | memory | 0x252e7f | fwd |
| Constant-time inversion | +0x219b | jb | mem | `0x252e96: cmp 0x28(%rsp),%rdx` | arithmetic/control | 0x252e39 | back |
| Constant-time inversion | +0x21a9 | je | mem | `0x252ea1: testb $0x1,0x178(%rsp)` | arithmetic/control | 0x252ee1 | fwd |
| Constant-time inversion | +0x21c1 | jae | mem | `0x252ebc: cmp 0x28(%rsp),%rax` | memory | 0x252ece | fwd |
| Constant-time inversion | +0x2226 | je | reg/arith | `0x252f23: test %rax,%rax` | memory | 0x251772 | back |
| Constant-time inversion | +0x226d | je | reg/arith | `0x252f69: add $0xfffffffffffffff8,%rax` | memory | 0x251772 | back |
| Constant-time inversion | +0x227b | jae | mem | `0x252f73: cmp 0x88(%rsp),%rcx` | memory | 0x252f88 | fwd |
| Constant-time inversion | +0x2292 | jae | mem | `0x252f8a: cmp 0x118(%rsp),%rcx` | memory | 0x252f9f | fwd |
| Constant-time inversion | +0x22aa | jb | mem | `0x252fa2: cmp 0x110(%rsp),%rcx` | arithmetic/control | 0x252f38 | back |
| Constant-time inversion | +0x231d | je | reg/arith | `0x253019: cmp $0x1,%rbx` | memory | 0x2530ad | fwd |
| Constant-time inversion | +0x2337 | jb | reg/arith | `0x253033: cmp $0x18,%rdx` | memory | 0x25309c | fwd |
| Constant-time inversion | +0x2383 | jne | reg/arith | `0x253080: cmp %rcx,%rdx` | arithmetic/control | 0x253066 | back |
| Constant-time inversion | +0x239a | je | reg/arith | `0x253097: cmp %rdx,%rsi` | memory | 0x2530ad | fwd |
| Constant-time inversion | +0x23ab | jne | mem | `0x2530a3: cmp 0x2b8(%rsp),%rax` | memory | 0x25309c | back |
| Constant-time inversion | +0x2414 | je | reg/arith | `0x253110: cmp $0xffffffffffffffff,%rax` | memory | 0x2532cb | fwd |
| Constant-time inversion | +0x2431 | jne | mem | `0x253129: cmp 0x138(%rsp),%rdi` | memory | 0x253509 | fwd |
| Constant-time inversion | +0x257f | je | reg/arith | `0x25327c: test %r12,%r12` | memory | 0x253447 | fwd |
| Constant-time inversion | +0x2592 | je | mem | `0x25328d: cmpq $0x0,(%rsp)` | memory | 0x250d6d | back |
| Constant-time inversion | +0x2732 | jne | reg/arith | `0x25342f: cmp %rax,%rsi` | memory | 0x253403 | back |
| Constant-time inversion | +0x2981 | je | mem | `0x25367c: cmpq $0x0,(%rsp)` | memory | 0x2536e3 | fwd |
| ECDSA scalar ladder (driver) | +0x23 | je | reg/arith | `0x55abd0: test %rcx,%rcx` | memory | 0x55ac44 | fwd |
| ECDSA scalar ladder (driver) | +0x33 | je | reg/arith | `0x55abe0: test %rax,%rax` | memory | 0x55ac38 | fwd |
| ECDSA scalar ladder (driver) | +0x3f | jne | mem | `0x55abec: cmp (%r15),%rcx` | memory | 0x55ac3f | fwd |
| ECDSA scalar ladder (driver) | +0x47 | je | reg/arith | `0x55abf5: test %ecx,%ecx` | memory | 0x55ac05 | fwd |
| ECDSA scalar ladder (driver) | +0x4f | je | reg/arith | `0x55abfd: test %edx,%edx` | arithmetic/control | 0x55ac05 | fwd |
| ECDSA scalar ladder (driver) | +0x53 | jne | reg/arith | `0x55ac01: cmp %edx,%ecx` | call | 0x55ac3f | fwd |
| ECDSA scalar ladder (driver) | +0x5f | je | reg/arith | `0x55ac0d: test %eax,%eax` | memory | 0x55ac44 | fwd |
| ECDSA scalar ladder (driver) | +0x6c | je | reg/arith | `0x55ac19: test %rax,%rax` | memory | 0x55ad72 | fwd |
| ECDSA scalar ladder (driver) | +0x76 | je | mem | `0x55ac22: cmp (%r12),%rcx` | memory | 0x55afb3 | fwd |
| ECDSA scalar ladder (driver) | +0xa2 | je | reg/arith | `0x55ac4f: test %rcx,%rcx` | memory | 0x55ad50 | fwd |
| ECDSA scalar ladder (driver) | +0xc3 | je | reg/arith | `0x55ac70: cmp %rdx,%rcx` | memory | 0x55ad50 | fwd |
| ECDSA scalar ladder (driver) | +0xd2 | je | mem | `0x55ac79: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x55ac70 | back |
| ECDSA scalar ladder (driver) | +0xe2 | je | reg/arith | `0x55ac8f: test %rcx,%rcx` | memory | 0x55ad50 | fwd |
| ECDSA scalar ladder (driver) | +0x103 | je | reg/arith | `0x55acb0: cmp %rdx,%rcx` | memory | 0x55ad50 | fwd |
| ECDSA scalar ladder (driver) | +0x112 | je | mem | `0x55acb9: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x55acb0 | back |
| ECDSA scalar ladder (driver) | +0x120 | je | reg/arith | `0x55accd: test %r13,%r13` | memory | 0x55ad69 | fwd |
| ECDSA scalar ladder (driver) | +0x12f | je | mem | `0x55acda: cmpq $0x0,0x50(%rax)` | memory | 0x55ad80 | fwd |
| ECDSA scalar ladder (driver) | +0x14f | je | reg/arith | `0x55acfc: test %rax,%rax` | memory | 0x55ad4b | fwd |
| ECDSA scalar ladder (driver) | +0x16a | je | reg/arith | `0x55ad17: test %rax,%rax` | call | 0x55ad25 | fwd |
| ECDSA scalar ladder (driver) | +0x173 | jne | reg/arith | `0x55ad21: test %eax,%eax` | call+memory | 0x55ad98 | fwd |
| ECDSA scalar ladder (driver) | +0x1e2 | je | reg/arith | `0x55ad8f: test %r13,%r13` | memory | 0x55aedd | fwd |
| ECDSA scalar ladder (driver) | +0x1f1 | je | mem | `0x55ad9c: cmpq $0x0,0x50(%rax)` | memory | 0x55aed4 | fwd |
| ECDSA scalar ladder (driver) | +0x216 | je | reg/arith | `0x55adc3: test %rax,%rax` | memory | 0x55af11 | fwd |
| ECDSA scalar ladder (driver) | +0x235 | je | reg/arith | `0x55ade2: test %rax,%rax` | call | 0x55aeeb | fwd |
| ECDSA scalar ladder (driver) | +0x242 | je | reg/arith | `0x55adf0: test %eax,%eax` | memory | 0x55aeeb | fwd |
| ECDSA scalar ladder (driver) | +0x255 | je | reg/arith | `0x55ae02: test %r14,%r14` | arithmetic/control | 0x55afcc | fwd |
| ECDSA scalar ladder (driver) | +0x25e | je | reg/arith | `0x55ae0b: test %r15,%r15` | memory | 0x55afd7 | fwd |
| ECDSA scalar ladder (driver) | +0x271 | je | reg/arith | `0x55ae1e: test %rcx,%rcx` | memory | 0x55ae58 | fwd |
| ECDSA scalar ladder (driver) | +0x27a | je | reg/arith | `0x55ae27: test %rax,%rax` | memory | 0x55ae58 | fwd |
| ECDSA scalar ladder (driver) | +0x286 | jne | mem | `0x55ae33: cmp (%r15),%rcx` | memory | 0x55ae58 | fwd |
| ECDSA scalar ladder (driver) | +0x28e | je | reg/arith | `0x55ae3c: test %ecx,%ecx` | memory | 0x55b11a | fwd |
| ECDSA scalar ladder (driver) | +0x29a | je | reg/arith | `0x55ae48: test %edx,%edx` | arithmetic/control | 0x55b11a | fwd |
| ECDSA scalar ladder (driver) | +0x2a2 | je | reg/arith | `0x55ae50: cmp %ecx,%edx` | call | 0x55b11a | fwd |
| ECDSA scalar ladder (driver) | +0x2c5 | je | reg/arith | `0x55ae72: test %rax,%rax` | memory | 0x55ae85 | fwd |
| ECDSA scalar ladder (driver) | +0x2ce | je | reg/arith | `0x55ae7b: test %rax,%rax` | call | 0x55ae85 | fwd |
| ECDSA scalar ladder (driver) | +0x309 | je | reg/arith | `0x55aeb6: test %rbx,%rbx` | memory | 0x55b0ee | fwd |
| ECDSA scalar ladder (driver) | +0x319 | jne | reg/arith | `0x55aec3: test %rcx,%rcx` | arithmetic/control | 0x55af99 | fwd |
| ECDSA scalar ladder (driver) | +0x38a | jne | reg/arith | `0x55af32: test %bpl,%bpl` | memory | 0x55af78 | fwd |
| ECDSA scalar ladder (driver) | +0x392 | je | reg/arith | `0x55af3f: test %rax,%rax` | memory | 0x55af52 | fwd |
| ECDSA scalar ladder (driver) | +0x39b | je | reg/arith | `0x55af48: test %rax,%rax` | call | 0x55af52 | fwd |
| ECDSA scalar ladder (driver) | +0x3d6 | je | reg/arith | `0x55af83: test %rbx,%rbx` | memory | 0x55ad57 | back |
| ECDSA scalar ladder (driver) | +0x3e3 | je | reg/arith | `0x55af90: test %rcx,%rcx` | memory | 0x55ad57 | back |
| ECDSA scalar ladder (driver) | +0x436 | je | reg/arith | `0x55afe4: test %eax,%eax` | memory | 0x55b0f6 | fwd |
| ECDSA scalar ladder (driver) | +0x443 | je | reg/arith | `0x55aff0: test %rax,%rax` | memory | 0x55aff9 | fwd |
| ECDSA scalar ladder (driver) | +0x450 | je | reg/arith | `0x55affd: test %rax,%rax` | memory | 0x55b006 | fwd |
| ECDSA scalar ladder (driver) | +0x45d | je | reg/arith | `0x55b00a: test %rax,%rax` | memory | 0x55b013 | fwd |
| ECDSA scalar ladder (driver) | +0x46b | je | reg/arith | `0x55b018: test %rax,%rax` | memory | 0x55b021 | fwd |
| ECDSA scalar ladder (driver) | +0x479 | je | reg/arith | `0x55b026: test %rax,%rax` | memory | 0x55b02f | fwd |
| ECDSA scalar ladder (driver) | +0x487 | je | reg/arith | `0x55b034: test %rax,%rax` | memory | 0x55b03d | fwd |
| ECDSA scalar ladder (driver) | +0x499 | je | reg/arith | `0x55b046: test %rax,%rax` | memory | 0x55b04f | fwd |
| ECDSA scalar ladder (driver) | +0x4ab | je | reg/arith | `0x55b058: test %rax,%rax` | memory | 0x55b061 | fwd |
| ECDSA scalar ladder (driver) | +0x4bd | je | reg/arith | `0x55b06a: test %rax,%rax` | call+memory | 0x55b073 | fwd |
| ECDSA scalar ladder (driver) | +0x4ee | je | reg/arith | `0x55b09b: test %rax,%rax` | memory | 0x55b102 | fwd |
| ECDSA scalar ladder (driver) | +0x50b | je | reg/arith | `0x55b0b9: test %eax,%eax` | memory | 0x55b10e | fwd |
| ECDSA scalar ladder (driver) | +0x51d | je | reg/arith | `0x55b0ca: test %r15,%r15` | memory | 0x55b138 | fwd |
| ECDSA scalar ladder (driver) | +0x52e | je | reg/arith | `0x55b0d3: test $0xffffffff80000000,%rax` | memory | 0x55b14b | fwd |
| ECDSA scalar ladder (driver) | +0x56d | je | reg/arith | `0x55b11a: cmp %r15,%r14` | call | 0x55afec | back |
| ECDSA scalar ladder (driver) | +0x57d | jne | reg/arith | `0x55b12b: test %eax,%eax` | arithmetic/control | 0x55afec | back |
| ECDSA scalar ladder (driver) | +0x5a8 | jne | reg/arith | `0x55b156: test $0x1,%al` | memory | 0x55b781 | fwd |
| ECDSA scalar ladder (driver) | +0x5b5 | js | reg/arith | `0x55b163: test %eax,%eax` | memory | 0x55b191 | fwd |
| ECDSA scalar ladder (driver) | +0x5c1 | jae | mem | `0x55b16e: cmp %rsi,(%rdi)` | call+memory | 0x55b19b | fwd |
| ECDSA scalar ladder (driver) | +0x5da | jne | reg/arith | `0x55b183: test %al,%cl` | arithmetic/control | 0x55b1a4 | fwd |
| ECDSA scalar ladder (driver) | +0x5e4 | jne | reg/arith | `0x55b191: test %r15,%r15` | arithmetic/control | 0x55b1b9 | fwd |
| ECDSA scalar ladder (driver) | +0x5ee | je | reg/arith | `0x55b19b: test %r15,%r15` | memory | 0x55b287 | fwd |
| ECDSA scalar ladder (driver) | +0x5f7 | jae | mem | `0x55b1a4: cmp %rsi,(%r15)` | call | 0x55b1b9 | fwd |
| ECDSA scalar ladder (driver) | +0x603 | je | reg/arith | `0x55b1b1: test %al,%al` | memory | 0x55b287 | fwd |
| ECDSA scalar ladder (driver) | +0x61d | je | reg/arith | `0x55b1ca: test %rax,%rax` | memory | 0x55b293 | fwd |
| ECDSA scalar ladder (driver) | +0x638 | jg | mem | `0x55b1e1: cmp 0x2c(%rsp),%eax` | memory | 0x55b1f0 | fwd |
| ECDSA scalar ladder (driver) | +0x63e | je | mem | `0x55b1ea: cmpl $0x0,0x18(%rbp)` | memory | 0x55b20c | fwd |
| ECDSA scalar ladder (driver) | +0x656 | je | reg/arith | `0x55b204: test %eax,%eax` | memory | 0x55b29f | fwd |
| ECDSA scalar ladder (driver) | +0x674 | je | reg/arith | `0x55b222: test %eax,%eax` | memory | 0x55b2ab | fwd |
| ECDSA scalar ladder (driver) | +0x692 | je | reg/arith | `0x55b240: test %eax,%eax` | memory | 0x55b483 | fwd |
| ECDSA scalar ladder (driver) | +0x6a6 | js | mem | `0x55b251: cmpl $0x0,0x2c(%rsp)` | memory | 0x55b2b7 | fwd |
| ECDSA scalar ladder (driver) | +0x6b8 | jae | mem | `0x55b264: cmp 0x10(%rcx),%rax` | memory | 0x55b2b7 | fwd |
| ECDSA scalar ladder (driver) | +0x725 | je | reg/arith | `0x55b2d2: test %rax,%rax` | memory | 0x55b2ef | fwd |
| ECDSA scalar ladder (driver) | +0x752 | je | reg/arith | `0x55b2ff: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x762 | jae | mem | `0x55b30f: cmp %rax,(%rdi)` | call | 0x55b324 | fwd |
| ECDSA scalar ladder (driver) | +0x76e | je | reg/arith | `0x55b31c: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x780 | je | reg/arith | `0x55b32d: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x789 | jae | mem | `0x55b336: cmp %r15,(%rdi)` | call | 0x55b34b | fwd |
| ECDSA scalar ladder (driver) | +0x795 | je | reg/arith | `0x55b343: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x7a7 | je | reg/arith | `0x55b354: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x7b0 | jae | mem | `0x55b35d: cmp %r15,(%rdi)` | call | 0x55b372 | fwd |
| ECDSA scalar ladder (driver) | +0x7bc | je | reg/arith | `0x55b36a: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x7ca | je | reg/arith | `0x55b377: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x7d3 | jae | mem | `0x55b380: cmp %r15,(%rdi)` | call | 0x55b395 | fwd |
| ECDSA scalar ladder (driver) | +0x7df | je | reg/arith | `0x55b38d: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x7ed | je | reg/arith | `0x55b39a: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x7f6 | jae | mem | `0x55b3a3: cmp %r15,(%rdi)` | call | 0x55b3b8 | fwd |
| ECDSA scalar ladder (driver) | +0x802 | je | reg/arith | `0x55b3b0: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x810 | je | reg/arith | `0x55b3bd: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x819 | jae | mem | `0x55b3c6: cmp %r15,(%rdi)` | call | 0x55b3db | fwd |
| ECDSA scalar ladder (driver) | +0x825 | je | reg/arith | `0x55b3d3: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x837 | je | reg/arith | `0x55b3e4: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x840 | jae | mem | `0x55b3ed: cmp %r15,(%rdi)` | call | 0x55b402 | fwd |
| ECDSA scalar ladder (driver) | +0x84c | je | reg/arith | `0x55b3fa: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x85e | je | reg/arith | `0x55b40b: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x867 | jae | mem | `0x55b414: cmp %r15,(%rdi)` | call | 0x55b429 | fwd |
| ECDSA scalar ladder (driver) | +0x873 | je | reg/arith | `0x55b421: test %al,%al` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x885 | je | reg/arith | `0x55b432: test %rdi,%rdi` | memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0x893 | jae | mem | `0x55b43b: cmp %r15,(%rdi)` | call | 0x55b455 | fwd |
| ECDSA scalar ladder (driver) | +0x89f | je | reg/arith | `0x55b44d: test %al,%al` | memory | 0x55ae64 | back |
| ECDSA scalar ladder (driver) | +0x8aa | je | mem | `0x55b455: cmpl $0x0,0x28(%r14)` | call+memory | 0x55b5c8 | fwd |
| ECDSA scalar ladder (driver) | +0x8be | je | reg/arith | `0x55b46c: test %al,%al` | memory | 0x55b48f | fwd |
| ECDSA scalar ladder (driver) | +0x8ed | jne | reg/arith | `0x55b499: cmp $0x4,%rdx` | memory | 0x55b54b | fwd |
| ECDSA scalar ladder (driver) | +0x92b | jne | reg/arith | `0x55b4d7: cmp $0x1,%dil` | memory | 0x55b54d | fwd |
| ECDSA scalar ladder (driver) | +0x936 | jne | reg/arith | `0x55b4e4: cmp $0xff,%al` | call+memory | 0x55b4ef | fwd |
| ECDSA scalar ladder (driver) | +0x962 | je | reg/arith | `0x55b510: test %eax,%eax` | call+memory | 0x55b6e2 | fwd |
| ECDSA scalar ladder (driver) | +0x989 | jne | reg/arith | `0x55b537: test %eax,%eax` | memory | 0x55b706 | fwd |
| ECDSA scalar ladder (driver) | +0x99f | je | reg/arith | `0x55b54d: test %cl,%cl` | arithmetic/control | 0x55b606 | fwd |
| ECDSA scalar ladder (driver) | +0x9a8 | jne | reg/arith | `0x55b555: test %sil,%sil` | memory | 0x55b606 | fwd |
| ECDSA scalar ladder (driver) | +0x9f8 | je | mem | `0x55b59f: cmpq $0xffffffffffffffff,0x230(%rsp)` | memory | 0x55b741 | fwd |
| ECDSA scalar ladder (driver) | +0xa2d | je | reg/arith | `0x55b5da: test %rax,%rax` | call+memory | 0x55b5fc | fwd |
| ECDSA scalar ladder (driver) | +0xa41 | jne | reg/arith | `0x55b5ef: test %eax,%eax` | arithmetic/control | 0x55b460 | back |
| ECDSA scalar ladder (driver) | +0xa79 | je | reg/arith | `0x55b627: test %eax,%eax` | memory | 0x55b6e2 | fwd |
| ECDSA scalar ladder (driver) | +0xa83 | jo | mem | `0x55b62f: decl 0x2c(%rsp)` | arithmetic/control | 0x55b790 | fwd |
| ECDSA scalar ladder (driver) | +0xa89 | js | unknown | `?` | memory | 0x55b6eb | fwd |
| ECDSA scalar ladder (driver) | +0xab2 | jae | mem | `0x55b65e: cmp 0x10(%rcx),%rax` | memory | 0x55b67c | fwd |
| ECDSA scalar ladder (driver) | +0xae7 | je | mem | `0x55b691: cmpq $0xffffffffffffffff,0x58(%rsp)` | call+memory | 0x55b6b0 | fwd |
| ECDSA scalar ladder (driver) | +0xb1a | je | reg/arith | `0x55b6c8: test %eax,%eax` | memory | 0x55b756 | fwd |
| ECDSA scalar ladder (driver) | +0xb2a | jg | reg/arith | `0x55b6d3: test %rbp,%rbp` | arithmetic/control | 0x55b64f | back |
| ECDSA scalar ladder (driver) | +0xb64 | je | reg/arith | `0x55b711: test %rax,%rax` | call+memory | 0x55b72f | fwd |
| ECDSA scalar ladder (driver) | +0xb7d | je | reg/arith | `0x55b72b: test %eax,%eax` | call+memory | 0x55b74f | fwd |
| ECDSA scalar ladder (driver) | +0xbc6 | jne | reg/arith | `0x55b773: test %rax,%rax` | arithmetic/control | 0x55ae77 | back |
| EC ladder step (secret core) | +0x7a | je | reg/arith | `0x35c647: test %rax,%rax` | memory | 0x35cbe5 | fwd |
| EC ladder step (secret core) | +0x95 | je | reg/arith | `0x35c662: test %rbp,%rbp` | memory | 0x35cbe5 | fwd |
| EC ladder step (secret core) | +0xa5 | je | reg/arith | `0x35c672: test %rax,%rax` | call+memory | 0x35cbe5 | fwd |
| EC ladder step (secret core) | +0xc6 | je | reg/arith | `0x35c694: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0xe4 | je | reg/arith | `0x35c6b2: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x102 | je | reg/arith | `0x35c6d0: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x120 | je | reg/arith | `0x35c6ee: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x146 | je | reg/arith | `0x35c714: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x166 | je | reg/arith | `0x35c734: test %eax,%eax` | arithmetic/control | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x16f | je | reg/arith | `0x35c73c: test %r15,%r15` | memory | 0x35c762 | fwd |
| EC ladder step (secret core) | +0x186 | jne | reg/arith | `0x35c74e: test %rdx,%rdx` | arithmetic/control | 0x35c784 | fwd |
| EC ladder step (secret core) | +0x1b2 | je | reg/arith | `0x35c77a: test %rdx,%rdx` | memory | 0x35c790 | fwd |
| EC ladder step (secret core) | +0x1c7 | jb | reg/arith | `0x35c793: sub $0x1,%r9` | memory | 0x35c7b7 | fwd |
| EC ladder step (secret core) | +0x1ce | je | mem | `0x35c799: cmpq $0x0,(%rax,%r9,8)` | arithmetic/control | 0x35c790 | back |
| EC ladder step (secret core) | +0x1e5 | jne | mem | `0x35c7b0: cmpq $0x0,(%rcx,%r8,8)` | arithmetic/control | 0x35c7c0 | fwd |
| EC ladder step (secret core) | +0x1ee | jae | reg/arith | `0x35c7ba: sub $0x1,%r8` | arithmetic/control | 0x35c7b0 | back |
| EC ladder step (secret core) | +0x1f3 | jne | reg/arith | `0x35c7c0: cmp %r9,%rdi` | memory | 0x35c7e0 | fwd |
| EC ladder step (secret core) | +0x204 | jb | reg/arith | `0x35c7d0: sub $0x1,%rdi` | memory | 0x35c7e2 | fwd |
| EC ladder step (secret core) | +0x20e | je | mem | `0x35c7da: cmp %r8,(%rax,%rdi,8)` | arithmetic/control | 0x35c7d0 | back |
| EC ladder step (secret core) | +0x210 | jb | unknown | `?` | memory | 0x35c7fd | fwd |
| EC ladder step (secret core) | +0x227 | je | reg/arith | `0x35c7f5: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x246 | je | reg/arith | `0x35c80f: test %eax,%eax` | arithmetic/control | 0x35cbe5 | fwd |
| EC ladder step (secret core) | +0x24f | je | reg/arith | `0x35c81c: test %r15,%r15` | memory | 0x35c82b | fwd |
| EC ladder step (secret core) | +0x277 | jb | reg/arith | `0x35c843: sub $0x1,%rdi` | memory | 0x35c867 | fwd |
| EC ladder step (secret core) | +0x27e | je | mem | `0x35c849: cmpq $0x0,(%rcx,%rdi,8)` | arithmetic/control | 0x35c840 | back |
| EC ladder step (secret core) | +0x295 | jne | mem | `0x35c860: cmpq $0x0,(%rax,%rsi,8)` | arithmetic/control | 0x35c870 | fwd |
| EC ladder step (secret core) | +0x29e | jae | reg/arith | `0x35c86a: sub $0x1,%rsi` | arithmetic/control | 0x35c860 | back |
| EC ladder step (secret core) | +0x2a3 | jne | reg/arith | `0x35c870: cmp %rdi,%rdx` | arithmetic/control | 0x35c885 | fwd |
| EC ladder step (secret core) | +0x2a9 | jb | reg/arith | `0x35c875: sub $0x1,%rdx` | memory | 0x35c887 | fwd |
| EC ladder step (secret core) | +0x2b3 | je | mem | `0x35c87f: cmp %rsi,(%rcx,%rdx,8)` | arithmetic/control | 0x35c875 | back |
| EC ladder step (secret core) | +0x2b5 | jb | unknown | `?` | memory | 0x35c89e | fwd |
| EC ladder step (secret core) | +0x2c8 | je | reg/arith | `0x35c896: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x2e5 | je | reg/arith | `0x35c8b3: test %eax,%eax` | memory | 0x35cbe5 | fwd |
| EC ladder step (secret core) | +0x2ff | je | reg/arith | `0x35c8cd: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x322 | je | reg/arith | `0x35c8f0: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x33d | je | reg/arith | `0x35c90b: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x357 | je | reg/arith | `0x35c925: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x379 | je | reg/arith | `0x35c947: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x393 | je | reg/arith | `0x35c961: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x3b6 | je | reg/arith | `0x35c984: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x3d8 | je | reg/arith | `0x35c9a6: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x3fa | je | reg/arith | `0x35c9c8: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x41c | je | reg/arith | `0x35c9ea: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x436 | je | reg/arith | `0x35ca04: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x452 | je | reg/arith | `0x35ca20: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x476 | je | reg/arith | `0x35ca44: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x490 | je | reg/arith | `0x35ca5e: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x4af | je | reg/arith | `0x35ca7d: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x4ce | je | reg/arith | `0x35ca9c: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x4ed | je | reg/arith | `0x35cabb: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x507 | je | reg/arith | `0x35cad5: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x526 | je | reg/arith | `0x35caf4: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x543 | je | reg/arith | `0x35cb11: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x568 | je | reg/arith | `0x35cb36: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x587 | je | reg/arith | `0x35cb55: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x5a3 | je | reg/arith | `0x35cb71: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x5bc | je | reg/arith | `0x35cb8a: test %eax,%eax` | call+memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x5d5 | je | reg/arith | `0x35cba3: test %eax,%eax` | memory | 0x35cbe3 | fwd |
| EC ladder step (secret core) | +0x5f0 | je | reg/arith | `0x35cbb9: test %eax,%eax` | memory | 0x35cbe5 | fwd |
| EC ladder step (secret core) | +0x618 | je | reg/arith | `0x35cbe5: test %rbx,%rbx` | memory | 0x35cc08 | fwd |
| EC ladder step (secret core) | +0x621 | je | reg/arith | `0x35cbee: test %rax,%rax` | memory | 0x35cc08 | fwd |
| RSA CRT arms | +0x4e | je | reg/arith | `0x55ff3b: test %rax,%rax` | memory | 0x5609a8 | fwd |
| RSA CRT arms | +0x69 | jne | mem | `0x55ff55: cmpl $0x1,0x10(%rbp)` | memory | 0x55ff7d | fwd |
| RSA CRT arms | +0x78 | je | reg/arith | `0x55ff65: test %rax,%rax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x87 | jb | reg/arith | `0x55ff74: cmp $0xfffffffd,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x9c | jne | mem | `0x55ff85: testb $0x4,0xa4(%rbp)` | memory | 0x55ffa5 | fwd |
| RSA CRT arms | +0xa5 | jne | mem | `0x55ff8e: testb $0x2,0xa4(%rbp)` | arithmetic/control | 0x560006 | fwd |
| RSA CRT arms | +0xaa | jne | reg/arith | `0x55ff97: test %r13b,%r13b` | arithmetic/control | 0x5600e0 | fwd |
| RSA CRT arms | +0xbe | je | reg/arith | `0x55ffab: test %rax,%rax` | memory | 0x5609a8 | fwd |
| RSA CRT arms | +0xec | jne | reg/arith | `0x55ffd9: test %rax,%rax` | arithmetic/control | 0x5604f0 | fwd |
| RSA CRT arms | +0xf5 | je | reg/arith | `0x55ffe2: test %r15,%r15` | memory | 0x55fff0 | fwd |
| RSA CRT arms | +0x10d | je | reg/arith | `0x55fffa: test %rax,%rax` | arithmetic/control | 0x560068 | fwd |
| RSA CRT arms | +0x136 | jne | reg/arith | `0x560023: test %r15,%r15` | arithmetic/control | 0x5600c0 | fwd |
| RSA CRT arms | +0x13f | je | reg/arith | `0x56002c: test %r14,%r14` | memory | 0x56003a | fwd |
| RSA CRT arms | +0x154 | jne | reg/arith | `0x560041: test %r15,%r15` | memory | 0x5600b2 | fwd |
| RSA CRT arms | +0x16d | je | reg/arith | `0x56005b: test %eax,%eax` | memory | 0x5600a6 | fwd |
| RSA CRT arms | +0x196 | je | reg/arith | `0x560084: test %eax,%eax` | memory | 0x5604c7 | fwd |
| RSA CRT arms | +0x1c5 | je | reg/arith | `0x5600b2: test %r14,%r14` | memory | 0x5600c0 | fwd |
| RSA CRT arms | +0x1e1 | je | reg/arith | `0x5600c6: or %r13b,%al` | arithmetic/control | 0x5602f2 | fwd |
| RSA CRT arms | +0x1ea | je | reg/arith | `0x5600d7: test %r15,%r15` | memory | 0x5609a8 | fwd |
| RSA CRT arms | +0x1f9 | je | reg/arith | `0x5600e6: test %rax,%rax` | memory | 0x5609a8 | fwd |
| RSA CRT arms | +0x23b | je | reg/arith | `0x560129: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0x24a | je | reg/arith | `0x560137: test %rax,%rax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0x270 | je | reg/arith | `0x56015d: test %rax,%rax` | call+memory | 0x560e50 | fwd |
| RSA CRT arms | +0x298 | je | reg/arith | `0x560186: test %eax,%eax` | call+memory | 0x560e50 | fwd |
| RSA CRT arms | +0x2ed | je | mem | `0x5601d4: test %al,0x38(%rsp)` | memory | 0x560253 | fwd |
| RSA CRT arms | +0x2f8 | je | reg/arith | `0x5601e5: test %rax,%rax` | memory | 0x5609a8 | fwd |
| RSA CRT arms | +0x31e | je | reg/arith | `0x56020b: test %rax,%rax` | call+memory | 0x5608a2 | fwd |
| RSA CRT arms | +0x35d | je | reg/arith | `0x560245: test %ebp,%ebp` | arithmetic/control | 0x5609ab | fwd |
| RSA CRT arms | +0x367 | jle | reg/arith | `0x560255: test %ebx,%ebx` | memory | 0x56070e | fwd |
| RSA CRT arms | +0x380 | jne | reg/arith | `0x560267: test %r15b,%r15b` | call+memory | 0x560718 | fwd |
| RSA CRT arms | +0x3a6 | je | reg/arith | `0x56028e: test %r13,%r13` | arithmetic/control | 0x560e4b | fwd |
| RSA CRT arms | +0x3af | je | reg/arith | `0x56029c: test %rax,%rax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0x3c1 | je | reg/arith | `0x5602ae: test %rax,%rax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0x3e0 | je | reg/arith | `0x5602be: test %rcx,%rcx` | memory | 0x5608af | fwd |
| RSA CRT arms | +0x3f0 | je | mem | `0x5602d6: cmpq $0x0,0x10(%rcx)` | memory | 0x5608b9 | fwd |
| RSA CRT arms | +0x429 | je | reg/arith | `0x560317: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x447 | je | reg/arith | `0x560335: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x471 | je | reg/arith | `0x56035f: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x48f | je | reg/arith | `0x56037d: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x4c8 | je | reg/arith | `0x5603b6: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x4ea | je | reg/arith | `0x5603d8: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x503 | je | reg/arith | `0x5603f1: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x516 | je | reg/arith | `0x5603f9: test %rbx,%rbx` | memory | 0x560444 | fwd |
| RSA CRT arms | +0x51c | je | mem | `0x560408: cmpl $0x0,0x18(%rbx)` | memory | 0x560444 | fwd |
| RSA CRT arms | +0x530 | je | reg/arith | `0x56041e: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x53a | je | mem | `0x560426: cmpl $0x0,0x18(%rbx)` | memory | 0x560444 | fwd |
| RSA CRT arms | +0x54e | je | reg/arith | `0x56043c: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x56c | je | reg/arith | `0x56045a: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x58e | je | reg/arith | `0x56047c: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x5b0 | je | reg/arith | `0x560499: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x5ea | je | reg/arith | `0x5604d7: test %r15,%r15` | memory | 0x5604e5 | fwd |
| RSA CRT arms | +0x5fa | jne | reg/arith | `0x5604e5: test %bl,%bl` | memory | 0x560598 | fwd |
| RSA CRT arms | +0x625 | jne | reg/arith | `0x560512: test %rax,%rax` | arithmetic/control | 0x5605a0 | fwd |
| RSA CRT arms | +0x62e | je | reg/arith | `0x56051b: test %r15,%r15` | memory | 0x560529 | fwd |
| RSA CRT arms | +0x646 | je | reg/arith | `0x560533: test %rax,%rax` | arithmetic/control | 0x56053c | fwd |
| RSA CRT arms | +0x66a | je | reg/arith | `0x560558: test %eax,%eax` | memory | 0x560573 | fwd |
| RSA CRT arms | +0x696 | je | reg/arith | `0x560583: test %r15,%r15` | memory | 0x560591 | fwd |
| RSA CRT arms | +0x6a6 | je | reg/arith | `0x560591: test %bl,%bl` | arithmetic/control | 0x5605a0 | fwd |
| RSA CRT arms | +0x6c1 | je | reg/arith | `0x5605aa: test %ebx,%ebx` | memory | 0x56069b | fwd |
| RSA CRT arms | +0x6eb | jne | reg/arith | `0x5605d9: test %bl,%bl` | arithmetic/control | 0x560701 | fwd |
| RSA CRT arms | +0x6f7 | je | reg/arith | `0x5605e4: cmp %r14,%r13` | memory | 0x56069b | fwd |
| RSA CRT arms | +0x72b | jne | reg/arith | `0x560618: test %rax,%rax` | arithmetic/control | 0x5605e1 | back |
| RSA CRT arms | +0x730 | je | reg/arith | `0x56061d: test %r15,%r15` | memory | 0x56062b | fwd |
| RSA CRT arms | +0x742 | je | reg/arith | `0x56062f: test %rax,%rax` | arithmetic/control | 0x56063d | fwd |
| RSA CRT arms | +0x749 | jne | reg/arith | `0x560636: test %r15,%r15` | arithmetic/control | 0x5605d0 | back |
| RSA CRT arms | +0x764 | je | reg/arith | `0x560652: test %eax,%eax` | memory | 0x560678 | fwd |
| RSA CRT arms | +0x77d | jne | reg/arith | `0x56066a: test %r15,%r15` | arithmetic/control | 0x5605d0 | back |
| RSA CRT arms | +0x7a0 | jne | reg/arith | `0x56068d: test %r15,%r15` | arithmetic/control | 0x5605d0 | back |
| RSA CRT arms | +0x7bb | jne | reg/arith | `0x5606a9: test %ebx,%ebx` | memory | 0x5606f4 | fwd |
| RSA CRT arms | +0x7d4 | jne | mem | `0x5606b5: cmp 0x35bcf4(%rip),%rax        # 8bc3b0 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x49caa0>` | call+memory | 0x55ff8e | back |
| RSA CRT arms | +0x830 | je | reg/arith | `0x56071d: test %al,%r14b` | memory | 0x56099f | fwd |
| RSA CRT arms | +0x865 | je | reg/arith | `0x560753: test %eax,%eax` | arithmetic/control | 0x5609ab | fwd |
| RSA CRT arms | +0x86e | je | reg/arith | `0x56075b: test %rbx,%rbx` | memory | 0x56077e | fwd |
| RSA CRT arms | +0x874 | je | mem | `0x560760: cmpl $0x0,0x18(%rbx)` | memory | 0x56077e | fwd |
| RSA CRT arms | +0x888 | je | reg/arith | `0x560776: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x8a5 | je | reg/arith | `0x560793: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x8b4 | je | reg/arith | `0x5607a1: test %rax,%rax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x8ff | je | reg/arith | `0x5607ed: test %ebp,%ebp` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x90d | je | reg/arith | `0x5607f5: test %rbx,%rbx` | memory | 0x56081d | fwd |
| RSA CRT arms | +0x913 | je | mem | `0x5607ff: cmpl $0x0,0x18(%rbx)` | memory | 0x56081d | fwd |
| RSA CRT arms | +0x927 | je | reg/arith | `0x560815: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x947 | je | reg/arith | `0x560835: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x960 | je | reg/arith | `0x56084e: test %eax,%eax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x96b | jle | mem | `0x560856: cmpl $0x0,0x28(%rsp)` | memory | 0x560bac | fwd |
| RSA CRT arms | +0x97f | je | reg/arith | `0x56086c: test %rax,%rax` | memory | 0x5609ab | fwd |
| RSA CRT arms | +0x995 | je | reg/arith | `0x560882: test %rax,%rax` | memory | 0x560ab9 | fwd |
| RSA CRT arms | +0x9a0 | je | mem | `0x56088b: cmpq $0x0,0x10(%rax)` | memory | 0x560ab9 | fwd |
| RSA CRT arms | +0xa0f | je | reg/arith | `0x5608fd: test %eax,%eax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xa25 | je | reg/arith | `0x560912: test %rax,%rax` | call+memory | 0x560e4b | fwd |
| RSA CRT arms | +0xa48 | je | reg/arith | `0x560936: test %eax,%eax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xa53 | jne | mem | `0x56093e: cmpl $0x1,0x28(%rsp)` | call+memory | 0x5609e4 | fwd |
| RSA CRT arms | +0xaa9 | jne | reg/arith | `0x560996: test %al,%r14b` | arithmetic/control | 0x560726 | back |
| RSA CRT arms | +0xab2 | je | reg/arith | `0x56099f: test %r15b,%r15b` | arithmetic/control | 0x560bac | fwd |
| RSA CRT arms | +0xabe | je | reg/arith | `0x5609ab: test %r12,%r12` | memory | 0x5609d2 | fwd |
| RSA CRT arms | +0xac8 | je | reg/arith | `0x5609b5: test %rax,%rax` | memory | 0x5609d2 | fwd |
| RSA CRT arms | +0xb00 | je | reg/arith | `0x5609ed: test %rax,%rax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xb1a | je | reg/arith | `0x560a07: test %rax,%rax` | memory | 0x560a1d | fwd |
| RSA CRT arms | +0xb21 | jb | mem | `0x560a0c: cmpq $0x2,0x10(%rax)` | memory | 0x560a1d | fwd |
| RSA CRT arms | +0xb6c | je | reg/arith | `0x560a5a: test %eax,%eax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xb82 | je | reg/arith | `0x560a6f: test %rax,%rax` | call+memory | 0x560e4b | fwd |
| RSA CRT arms | +0xba5 | je | reg/arith | `0x560a93: test %eax,%eax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xbb0 | jne | mem | `0x560a9b: cmpl $0x2,0x28(%rsp)` | memory | 0x560d63 | fwd |
| RSA CRT arms | +0xbe3 | je | reg/arith | `0x560ad1: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0xc00 | je | reg/arith | `0x560aee: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0xc37 | je | reg/arith | `0x560b25: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0xc43 | je | mem | `0x560b2d: cmpq $0x0,0x8(%rsp)` | memory | 0x560b59 | fwd |
| RSA CRT arms | +0xc4e | je | mem | `0x560b3a: cmpl $0x0,0x18(%rax)` | memory | 0x560b59 | fwd |
| RSA CRT arms | +0xc63 | je | reg/arith | `0x560b51: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0xc80 | je | reg/arith | `0x560b6e: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0xc9b | je | reg/arith | `0x560b89: test %eax,%eax` | memory | 0x560e63 | fwd |
| RSA CRT arms | +0xca6 | jne | mem | `0x560b91: cmpl $0x1,0x28(%rsp)` | memory | 0x560e7b | fwd |
| RSA CRT arms | +0xcc3 | je | reg/arith | `0x560bb0: test %rdx,%rdx` | memory | 0x560d42 | fwd |
| RSA CRT arms | +0xcd0 | je | reg/arith | `0x560bbd: test %rcx,%rcx` | memory | 0x560d42 | fwd |
| RSA CRT arms | +0xce5 | je | mem | `0x560bce: cmp 0x35b7db(%rip),%rax        # 8bc3b0 <BN_mod_exp_mont@@OPENSSL_3.0.0+0x49caa0>` | memory | 0x560bf8 | fwd |
| RSA CRT arms | +0xcf4 | je | reg/arith | `0x560bd7: test %rax,%rax` | call+memory | 0x5609a8 | back |
| RSA CRT arms | +0xd27 | je | reg/arith | `0x560c15: test %eax,%eax` | memory | 0x5609ab | back |
| RSA CRT arms | +0xd42 | je | reg/arith | `0x560c30: test %eax,%eax` | memory | 0x5609ab | back |
| RSA CRT arms | +0xd63 | je | reg/arith | `0x560c50: cmp %rdx,%rcx` | memory | 0x560d42 | fwd |
| RSA CRT arms | +0xd72 | je | mem | `0x560c59: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x560c50 | back |
| RSA CRT arms | +0xd96 | je | reg/arith | `0x560c84: test %eax,%eax` | memory | 0x560d4d | fwd |
| RSA CRT arms | +0xda5 | je | mem | `0x560c91: cmpl $0x0,0x18(%rax)` | memory | 0x560cb4 | fwd |
| RSA CRT arms | +0xdbe | je | reg/arith | `0x560cac: test %eax,%eax` | memory | 0x5609ab | back |
| RSA CRT arms | +0xdda | je | reg/arith | `0x560cc7: cmp %rdx,%rcx` | memory | 0x560d55 | fwd |
| RSA CRT arms | +0xde9 | je | mem | `0x560cd0: cmpq $0x0,(%rax,%rdx,1)` | memory | 0x560cc7 | back |
| RSA CRT arms | +0xdf9 | je | reg/arith | `0x560ce6: test %rax,%rax` | memory | 0x560d9c | fwd |
| RSA CRT arms | +0xe1e | je | reg/arith | `0x560d0b: test %rax,%rax` | call+memory | 0x560e73 | fwd |
| RSA CRT arms | +0xe84 | je | reg/arith | `0x560d71: test %rax,%rax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xe99 | je | reg/arith | `0x560d86: test %rax,%rax` | memory | 0x560da7 | fwd |
| RSA CRT arms | +0xea0 | jb | mem | `0x560d8b: cmpq $0x3,0x10(%rax)` | memory | 0x560da7 | fwd |
| RSA CRT arms | +0xef6 | je | reg/arith | `0x560de4: test %eax,%eax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xf08 | je | reg/arith | `0x560df5: test %rax,%rax` | call+memory | 0x560e4b | fwd |
| RSA CRT arms | +0xf27 | je | reg/arith | `0x560e15: test %eax,%eax` | memory | 0x560e4b | fwd |
| RSA CRT arms | +0xf33 | je | mem | `0x560e19: cmpl $0x3,0x28(%rsp)` | memory | 0x56095b | back |
| RSA CRT arms | +0xf9d | je | reg/arith | `0x560e8a: test %rax,%rax` | memory | 0x560ea0 | fwd |
| RSA CRT arms | +0xfa4 | jb | mem | `0x560e8f: cmpq $0x2,0x10(%rax)` | memory | 0x560ea0 | fwd |
| RSA CRT arms | +0xfca | je | reg/arith | `0x560eb8: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0xfe3 | je | reg/arith | `0x560ed1: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x1016 | je | reg/arith | `0x560f04: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x1022 | je | mem | `0x560f0c: cmpq $0x0,0x8(%rsp)` | memory | 0x560f38 | fwd |
| RSA CRT arms | +0x102d | je | mem | `0x560f19: cmpl $0x0,0x18(%rax)` | memory | 0x560f38 | fwd |
| RSA CRT arms | +0x1042 | je | reg/arith | `0x560f30: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x105f | je | reg/arith | `0x560f4d: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x107a | je | reg/arith | `0x560f68: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x1085 | je | mem | `0x560f70: cmpl $0x2,0x28(%rsp)` | memory | 0x560b9c | back |
| RSA CRT arms | +0x109d | je | reg/arith | `0x560f8a: test %rax,%rax` | memory | 0x560fa0 | fwd |
| RSA CRT arms | +0x10a4 | jb | mem | `0x560f8f: cmpq $0x3,0x10(%rax)` | memory | 0x560fa0 | fwd |
| RSA CRT arms | +0x10ca | je | reg/arith | `0x560fb8: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x10e7 | je | reg/arith | `0x560fd5: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x111e | je | reg/arith | `0x56100c: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x112a | je | mem | `0x561014: cmpq $0x0,0x8(%rsp)` | memory | 0x561040 | fwd |
| RSA CRT arms | +0x1135 | je | mem | `0x561021: cmpl $0x0,0x18(%rax)` | memory | 0x561040 | fwd |
| RSA CRT arms | +0x114a | je | reg/arith | `0x561038: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x1167 | je | reg/arith | `0x561055: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x1182 | je | reg/arith | `0x561070: test %eax,%eax` | memory | 0x560e63 | back |
| RSA CRT arms | +0x118d | je | mem | `0x561078: cmpl $0x3,0x28(%rsp)` | memory | 0x560b9c | back |
| P-256 Montgomery reduction | +0x2ed | je | reg/arith | `0x55c6da: test %r8,%r8` | memory | 0x55c80b | fwd |
| P-256 Montgomery reduction | +0x415 | jne | reg/arith | `0x55c802: dec %r8` | memory | 0x55c6f0 | back |
