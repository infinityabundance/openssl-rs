# Binary branch audit — review aid, not a proof

- DSO: `court/tmp/pfp5/build/distribution/libcrypto.so.3`
- SHA-256: `842efa27197ea8c408d77a8316c1dbb35a06146e0033b7df7d7f9cced88a2f47`
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
| BN fixed-window ladder (window + scan inlined) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith15run_mont_ladder` @ 0x58aba0 | 5821 | 1255 | 100 | 0 | 2 | 18 | 2 | 0 | 70 | 0 |
| BN Montgomery multiply (REDC inlined) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith17mont_mul_sos_into` @ 0x58c870 | 1013 | 249 | 19 | 0 | 0 | 10 | 0 | 0 | 5 | 0 |

## Coverage

- expected targets: 2
- resolved uniquely and disassembled: 2
- failed: 0

## Divisions

- none in any audited range.

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d258, 0x16d279, 0x16d29a, 0x16d2b1, 0x16d303, 0x16d31a, 0x16d4a5, 0x16d5b3, 0x16d659, 0x16d818, 0x21d81c, 0x21d84c, 0x30e37c, 0x31063c, 0x31b8b4, 0x31b922, 0x31b990, 0x31b9fe, 0x34290a, 0x34299c

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| BN fixed-window ladder (window + scan inlined) | +0x2b | jne | reg/arith | `0x58abc7: shr $0x3a,%rax` | memory | 0x58ae70 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x74 | jbe | reg/arith | `0x58ac11: cmp %rbx,%rdx` | call+memory | 0x58acf8 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x98 | je | reg/arith | `0x58ac34: cmp $0xffffffffffffffff,%r15` | memory | 0x58ae70 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xb8 | jne | reg/arith | `0x58ac4d: test %rbx,%rbx` | memory | 0x58afd4 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xfa | jne | reg/arith | `0x58ac93: or %al,%cl` | memory | 0x58acd9 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x137 | jne | reg/arith | `0x58acd4: cmp %rax,%rsi` | arithmetic/control | 0x58aca0 | back |
| BN fixed-window ladder (window + scan inlined) | +0x13c | je | reg/arith | `0x58acd9: test %r15,%r15` | memory | 0x58acec | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x169 | jne | reg/arith | `0x58ad06: test %rbx,%rbx` | memory | 0x58ae38 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x1a9 | jne | reg/arith | `0x58ad45: cmp $0xffffffffffffffff,%r12` | memory | 0x58adbe | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x1b6 | je | reg/arith | `0x58ad53: test %rbx,%rbx` | memory | 0x58ae78 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x206 | jne | reg/arith | `0x58ada3: cmp %rax,%rbx` | memory | 0x58ad70 | back |
| BN fixed-window ladder (window + scan inlined) | +0x238 | jne | reg/arith | `0x58add5: test %rbx,%rbx` | call+memory | 0x58af1f | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x260 | je | mem | `0x58adfb: cmpb $0x0,0x40(%rsp)` | memory | 0x58bf45 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x27a | je | reg/arith | `0x58ae17: test %rbx,%rbx` | memory | 0x58af5b | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x2ca | je | mem | `0x58ae65: cmpb $0x0,0x40(%rsp)` | memory | 0x58b08e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x2fc | jne | reg/arith | `0x58ae9a: or %cl,%dl` | memory | 0x58aee4 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x33e | jne | reg/arith | `0x58aedb: cmp %rdx,%rax` | memory | 0x58aeb0 | back |
| BN fixed-window ladder (window + scan inlined) | +0x347 | je | reg/arith | `0x58aee4: test %rsi,%rsi` | memory | 0x58af0d | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x3a9 | je | mem | `0x58af44: cmpb $0x0,0x40(%rsp)` | memory | 0x58b110 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x3db | jne | reg/arith | `0x58af79: or %al,%cl` | memory | 0x58afb8 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x416 | jne | reg/arith | `0x58afb3: cmp %rax,%rsi` | arithmetic/control | 0x58af80 | back |
| BN fixed-window ladder (window + scan inlined) | +0x41b | je | reg/arith | `0x58afb8: test %r12,%r12` | memory | 0x58ad53 | back |
| BN fixed-window ladder (window + scan inlined) | +0x45e | je | mem | `0x58aff9: cmpb $0x0,0x40(%rsp)` | memory | 0x58b0d0 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x495 | jne | reg/arith | `0x58b02e: or %al,%cl` | memory | 0x58b072 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x4d0 | jne | reg/arith | `0x58b06d: cmp %rax,%rsi` | arithmetic/control | 0x58b039 | back |
| BN fixed-window ladder (window + scan inlined) | +0x4d5 | je | reg/arith | `0x58b072: test %r15,%r15` | memory | 0x58ae78 | back |
| BN fixed-window ladder (window + scan inlined) | +0x4fa | je | reg/arith | `0x58b096: cmp $0x1,%rbx` | memory | 0x58b0b7 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x53c | je | reg/arith | `0x58b0d8: cmp $0x1,%rbx` | memory | 0x58b0f9 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x586 | je | reg/arith | `0x58b122: cmp $0x1,%rbx` | memory | 0x58b14a | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x5d6 | je | mem | `0x58b171: cmpb $0x0,0x40(%rsp)` | memory | 0x58b18e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x601 | je | reg/arith | `0x58b19d: cmp $0x1,%rbx` | memory | 0x58b1c6 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x667 | je | mem | `0x58b202: cmpb $0x0,0x40(%rsp)` | memory | 0x58b26e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x6b2 | jne | reg/arith | `0x58b24f: cmp %rax,%rsi` | memory | 0x58b224 | back |
| BN fixed-window ladder (window + scan inlined) | +0x71e | je | mem | `0x58b2b9: cmpb $0x0,0x40(%rsp)` | memory | 0x58b3c1 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x77d | jne | reg/arith | `0x58b31a: cmp %rax,%rcx` | memory | 0x58b2ee | back |
| BN fixed-window ladder (window + scan inlined) | +0x7b9 | jne | reg/arith | `0x58b357: or %al,%cl` | memory | 0x58b392 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x7f0 | jne | reg/arith | `0x58b38d: cmp %rax,%rsi` | memory | 0x58b362 | back |
| BN fixed-window ladder (window + scan inlined) | +0x7f7 | je | mem | `0x58b392: cmpq $0x0,(%rsp)` | memory | 0x58b3a9 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x816 | jne | reg/arith | `0x58b3a9: test %r13b,%r13b` | arithmetic/control | 0x58ae17 | back |
| BN fixed-window ladder (window + scan inlined) | +0x82f | je | reg/arith | `0x58b3cb: cmp $0x1,%rbx` | memory | 0x58b3f4 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x880 | je | mem | `0x58b41b: cmpb $0x0,0x40(%rsp)` | memory | 0x58b44a | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x8bb | jne | reg/arith | `0x58b457: cmp $0x1,%rbx` | memory | 0x58b46e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x901 | jne | reg/arith | `0x58b49d: shr $0x3b,%rax` | call+memory | 0x58b730 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x932 | je | reg/arith | `0x58b4ce: cmp $0xffffffffffffffff,%rax` | call+memory | 0x58b730 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x973 | je | reg/arith | `0x58b50f: cmp $0xffffffffffffffff,%rax` | memory | 0x58b739 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x988 | ja | mem | `0x58b523: cmp 0x70(%rsp),%rbx` | memory | 0x58c02d | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x9a2 | ja | reg/arith | `0x58b53f: cmp %rax,%rbx` | memory | 0x58c045 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x9f3 | jb | reg/arith | `0x58b58c: sub %r13,%rax` | memory | 0x58c06a | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xa01 | jne | mem | `0x58b599: cmp 0x80(%rsp),%rbx` | memory | 0x58c07e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xa6e | jb | mem | `0x58b605: subq $0x1,0xe0(%rsp)` | memory | 0x58b884 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xa7e | ja | mem | `0x58b619: cmp 0x70(%rsp),%rax` | memory | 0x58bfbc | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xa92 | jo | reg/arith | `0x58b62f: mul %rbx` | memory | 0x58c0ec | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xa9d | jb | mem | `0x58b638: cmp %rax,0x10(%rsp)` | memory | 0x58bfde | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xaa7 | ja | mem | `0x58b643: cmp (%rsp),%rbx` | memory | 0x58bfea | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xb08 | jne | reg/arith | `0x58b6a6: test %al,%al` | memory | 0x58b605 | back |
| BN fixed-window ladder (window + scan inlined) | +0xb3a | jne | reg/arith | `0x58b6d8: or %al,%cl` | memory | 0x58b713 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xb71 | jne | reg/arith | `0x58b70e: cmp %rax,%rsi` | memory | 0x58b6e3 | back |
| BN fixed-window ladder (window + scan inlined) | +0xb7c | je | mem | `0x58b713: cmpq $0x0,0xd0(%rsp)` | memory | 0x58b73d | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xbc5 | jne | reg/arith | `0x58b763: or %al,%cl` | memory | 0x58b79e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xbfc | jne | reg/arith | `0x58b799: cmp %rax,%rsi` | memory | 0x58b76e | back |
| BN fixed-window ladder (window + scan inlined) | +0xc07 | je | mem | `0x58b79e: cmpq $0x0,0xd8(%rsp)` | memory | 0x58b7b9 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xc66 | jae | reg/arith | `0x58b802: cmp $0x7,%rcx` | arithmetic/control | 0x58b80c | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xcad | jne | reg/arith | `0x58b84a: cmp %rcx,%rdx` | arithmetic/control | 0x58b81f | back |
| BN fixed-window ladder (window + scan inlined) | +0xcb2 | je | reg/arith | `0x58b84f: test %rax,%rax` | memory | 0x58b867 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xcc5 | jne | reg/arith | `0x58b862: cmp %rdx,%rax` | memory | 0x58b85b | back |
| BN fixed-window ladder (window + scan inlined) | +0xcec | jne | mem | `0x58b884: cmp %rbx,0xa8(%rsp)` | memory | 0x58c08f | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xd13 | je | mem | `0x58b8aa: cmpq $0x0,0x88(%rsp)` | memory | 0x58beb3 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xdfc | jae | mem | `0x58b994: cmp 0x88(%rsp),%rax` | memory | 0x58b9cf | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xe0d | jae | mem | `0x58b9a5: cmp 0x98(%rsp),%rdi` | memory | 0x58c0ff | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xe44 | jae | mem | `0x58b9dc: cmp 0x88(%rsp),%rcx` | memory | 0x58ba1b | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xe55 | jae | mem | `0x58b9ed: cmp 0x98(%rsp),%rdi` | memory | 0x58c0ff | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xe87 | jae | mem | `0x58ba1f: cmp 0x88(%rsp),%rcx` | memory | 0x58ba5e | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xe98 | jae | mem | `0x58ba30: cmp 0x98(%rsp),%rdi` | memory | 0x58c0ff | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xeca | jae | mem | `0x58ba62: cmp 0x88(%rsp),%rcx` | memory | 0x58baa1 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xedb | jae | mem | `0x58ba73: cmp 0x98(%rsp),%rdi` | memory | 0x58c0ff | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xf0d | jae | mem | `0x58baa5: cmp 0x88(%rsp),%rax` | memory | 0x58bae0 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xf1e | jae | mem | `0x58bab6: cmp 0x98(%rsp),%rdi` | memory | 0x58c0ff | fwd |
| BN fixed-window ladder (window + scan inlined) | +0xf8d | je | reg/arith | `0x58bb2b: test %al,%al` | memory | 0x58b6ae | back |
| BN fixed-window ladder (window + scan inlined) | +0xff5 | je | reg/arith | `0x58bb93: test %al,%al` | memory | 0x58bf89 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x105c | je | reg/arith | `0x58bbfa: test %al,%al` | memory | 0x58b6ae | back |
| BN fixed-window ladder (window + scan inlined) | +0x10c4 | je | reg/arith | `0x58bc62: test %al,%al` | memory | 0x58bf89 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x112b | je | reg/arith | `0x58bcc9: test %al,%al` | memory | 0x58b6ae | back |
| BN fixed-window ladder (window + scan inlined) | +0x114f | je | mem | `0x58bce6: cmpq $0x0,0xe8(%rsp)` | memory | 0x58bd06 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x118c | je | reg/arith | `0x58bd28: cmp $0x20,%rcx` | arithmetic/control | 0x58be41 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x1198 | jo | reg/arith | `0x58bd35: mul %rbx` | arithmetic/control | 0x58c0ba | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x11a4 | jb | reg/arith | `0x58bd41: add %rbx,%rsi` | memory | 0x58c0d3 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x11af | ja | mem | `0x58bd4a: cmp 0x70(%rsp),%rsi` | arithmetic/control | 0x58bf98 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x11b8 | je | reg/arith | `0x58bd55: test %r13,%r13` | memory | 0x58bd17 | back |
| BN fixed-window ladder (window + scan inlined) | +0x11c9 | jne | reg/arith | `0x58bd65: shr $0x3f,%rax` | memory | 0x58bd17 | back |
| BN fixed-window ladder (window + scan inlined) | +0x11db | je | reg/arith | `0x58bd79: test $0x1,%al` | arithmetic/control | 0x58bd81 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x1217 | jne | mem | `0x58bdaf: cmp %rax,0x80(%rsp)` | memory | 0x58bd83 | back |
| BN fixed-window ladder (window + scan inlined) | +0x1227 | je | reg/arith | `0x58bdc4: cmp %rax,%r13` | memory | 0x58bd17 | back |
| BN fixed-window ladder (window + scan inlined) | +0x1239 | je | mem | `0x58bdd0: cmpq $0x0,0xe0(%rsp)` | memory | 0x58bdfb | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x1259 | jne | reg/arith | `0x58bdf6: dec %rsi` | arithmetic/control | 0x58bde6 | back |
| BN fixed-window ladder (window + scan inlined) | +0x1262 | ja | reg/arith | `0x58bdfe: cmp $0xfffffffffffffffc,%rdx` | memory | 0x58bd17 | back |
| BN fixed-window ladder (window + scan inlined) | +0x129a | jne | reg/arith | `0x58be37: cmp %rax,%r13` | arithmetic/control | 0x58be08 | back |
| BN fixed-window ladder (window + scan inlined) | +0x12e5 | je | reg/arith | `0x58be83: test %al,%al` | memory | 0x58bf89 | fwd |
| BN fixed-window ladder (window + scan inlined) | +0x130d | jne | mem | `0x58bea4: cmpq $0x0,0xf0(%rsp)` | memory | 0x58b97d | back |
| BN fixed-window ladder (window + scan inlined) | +0x135a | je | reg/arith | `0x58bef8: test %al,%al` | call+memory | 0x58b6ae | back |
| BN fixed-window ladder (window + scan inlined) | +0x15ec | jne | reg/arith | `0x58c189: test %rbx,%rbx` | call+memory | 0x58c1bb | fwd |
| BN Montgomery multiply (REDC inlined) | +0x33 | jne | reg/arith | `0x58c8a0: or %r9,%rax` | memory | 0x58c9c0 | fwd |
| BN Montgomery multiply (REDC inlined) | +0x4c | jne | reg/arith | `0x58c8b9: cmp %rax,%rcx` | memory | 0x58c9c0 | fwd |
| BN Montgomery multiply (REDC inlined) | +0x7d | je | reg/arith | `0x58c8ea: test %r14,%r14` | memory | 0x58c9c2 | fwd |
| BN Montgomery multiply (REDC inlined) | +0xe1 | je | reg/arith | `0x58c94e: cmp %rdi,%rbp` | memory | 0x58c9d1 | fwd |
| BN Montgomery multiply (REDC inlined) | +0xf4 | je | reg/arith | `0x58c961: test %rax,%rax` | memory | 0x58c920 | back |
| BN Montgomery multiply (REDC inlined) | +0x142 | jne | reg/arith | `0x58c9af: cmp %r8,%r13` | arithmetic/control | 0x58c970 | back |
| BN Montgomery multiply (REDC inlined) | +0x148 | jne | reg/arith | `0x58c9b4: test $0x1,%dil` | arithmetic/control | 0x58c920 | back |
| BN Montgomery multiply (REDC inlined) | +0x1bd | je | reg/arith | `0x58ca2a: cmp %rdi,%rax` | memory | 0x58cada | fwd |
| BN Montgomery multiply (REDC inlined) | +0x1cb | je | mem | `0x58ca33: cmp 0x90(%rsp),%r9` | memory | 0x58cc2a | fwd |
| BN Montgomery multiply (REDC inlined) | +0x203 | je | reg/arith | `0x58ca70: cmp %rsi,%rbx` | memory | 0x58cc0f | fwd |
| BN Montgomery multiply (REDC inlined) | +0x22f | jne | reg/arith | `0x58ca9c: cmp %rsi,%rdi` | memory | 0x58ca70 | back |
| BN Montgomery multiply (REDC inlined) | +0x23d | je | mem | `0x58caa8: cmp 0x28(%rsp),%r9` | memory | 0x58ca10 | back |
| BN Montgomery multiply (REDC inlined) | +0x263 | jne | reg/arith | `0x58cad0: cmp %rax,%rbp` | arithmetic/control | 0x58cac0 | back |
| BN Montgomery multiply (REDC inlined) | +0x282 | je | reg/arith | `0x58caef: test %rdx,%rdx` | memory | 0x58cb62 | fwd |
| BN Montgomery multiply (REDC inlined) | +0x2e8 | jne | reg/arith | `0x58cb55: cmp %rsi,%r13` | arithmetic/control | 0x58cb20 | back |
| BN Montgomery multiply (REDC inlined) | +0x2ee | jne | reg/arith | `0x58cb5a: test $0x1,%dil` | arithmetic/control | 0x58cb7d | fwd |
| BN Montgomery multiply (REDC inlined) | +0x367 | jae | reg/arith | `0x58cbd4: cmp %r14,%rcx` | arithmetic/control | 0x58cc52 | fwd |
| BN Montgomery multiply (REDC inlined) | +0x36c | je | reg/arith | `0x58cbd9: cmp %r10,%rdi` | memory | 0x58cc42 | fwd |
| BN Montgomery multiply (REDC inlined) | +0x398 | jne | reg/arith | `0x58cc04: add $0xfffffffffffffff8,%r8` | arithmetic/control | 0x58cbd0 | back |
