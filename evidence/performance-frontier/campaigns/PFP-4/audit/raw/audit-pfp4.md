# Binary branch audit — review aid, not a proof

- DSO: `/work/court/tmp/pfp4-a/distribution/libcrypto.so.3`
- SHA-256: `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77`
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
| Order-inverse admission and write-back | `_RNvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base17try_inverse_order` @ 0x328230 | 906 | 208 | 10 | 0 | 1 | 0 | 0 | 0 | 12 | 0 |
| Order Fermat inverse schedule (P256Scalar, kernel inlined) | `_RNvMsj_NtNtCsfBoMNNx3tZr_10openssl_rs2ec4p256NtB5_10P256Scalar6invert` @ 0x373290 | 2307 | 515 | 2 | 0 | 0 | 0 | 0 | 0 | 3 | 0 |
| Order reduction into Montgomery form | `_RNvMsj_NtNtCsfBoMNNx3tZr_10openssl_rs2ec4p256NtB5_10P256Scalar22from_canonical_reduced` @ 0x372ea0 | 1003 | 232 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| P-256 Montgomery reduction (shared kernel) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25616mont_reduce_into` @ 0x381210 | 1086 | 296 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| P-256 x86-64 multiply (shared kernel) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25612wide_mul_x86` @ 0x381000 | 396 | 112 | 0 | 0 | 0 | 9 | 0 | 0 | 0 | 0 |
| Branchless BIGNUM normalisation (write-back) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5limbs20normalise_branchless` @ 0x311630 | 186 | 50 | 5 | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| BIGNUM write-back (declassification boundary) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4smpl16store_coordinate` @ 0x41b940 | 348 | 100 | 10 | 0 | 5 | 0 | 0 | 0 | 3 | 0 |

## Coverage

- expected targets: 7
- resolved uniquely and disassembled: 7
- failed: 0

## Divisions

- none in any audited range.

## Dispatch-looking direct calls in the audited ranges

- none.

## Whole-DSO cpuid scan

- `cpuid` instructions in the DSO: **30**
- of those inside the audited ranges: **0**
- first addresses: 0x16d2d8, 0x16d2f9, 0x16d31a, 0x16d331, 0x16d383, 0x16d39a, 0x16d525, 0x16d633, 0x16d6d9, 0x16d898, 0x1f935c, 0x1f938c, 0x26785c, 0x269b1c, 0x36e01c, 0x36e04c, 0x3816bb, 0x5263c4, 0x526432, 0x5264a0

## Conditional jumps, per branch

`src` is the nearest preceding flag-setting instruction's operand class (mem = the flags were computed against a memory operand); `guarded` is what the fall-through window touches before the next transfer. Neither is a secret-taint result.

| function | offset | jcc | src | setter | guarded | target | dir |
|---|---:|---|---|---|---|---:|---|
| Order-inverse admission and write-back | +0x12 | je | reg/arith | `0x32823f: test %rsi,%rsi` | arithmetic/control | 0x328272 | fwd |
| Order-inverse admission and write-back | +0x1a | je | reg/arith | `0x328247: test %rdx,%rdx` | call | 0x328272 | fwd |
| Order-inverse admission and write-back | +0x26 | je | reg/arith | `0x328254: test %al,%al` | memory | 0x328272 | fwd |
| Order-inverse admission and write-back | +0x3c | je | mem | `0x328267: cmpl $0x0,0x18(%r14)` | arithmetic/control | 0x328282 | fwd |
| Order-inverse admission and write-back | +0x5f | ja | reg/arith | `0x32828b: cmp $0x4,%rax` | memory | 0x328272 | back |
| Order-inverse admission and write-back | +0xa8 | ja | mem | `0x3282d4: cmpq $0x3,(%rbx)` | call | 0x32831f | fwd |
| Order-inverse admission and write-back | +0xbb | je | reg/arith | `0x3282e9: test %al,%al` | memory | 0x328397 | fwd |
| Order-inverse admission and write-back | +0xcd | ja | mem | `0x3282f1: cmpq $0x3,(%rbx)` | call | 0x328327 | fwd |
| Order-inverse admission and write-back | +0x122 | je | reg/arith | `0x32834a: add $0x4,%rdx` | memory | 0x328385 | fwd |
| Order-inverse admission and write-back | +0x151 | jne | reg/arith | `0x32837d: add $0xfffffffffffffff8,%rdx` | arithmetic/control | 0x328370 | back |
| Order Fermat inverse schedule (P256Scalar, kernel inlined) | +0x87 | jae | reg/arith | `0x373310: add $0xffffffffffffffff,%rcx` | memory | 0x373b69 | fwd |
| Order Fermat inverse schedule (P256Scalar, kernel inlined) | +0x49a | jae | reg/arith | `0x373726: bt %rcx,%rax` | memory | 0x373310 | back |
| P-256 Montgomery reduction (shared kernel) | +0x2ed | je | reg/arith | `0x3814fa: test %r8,%r8` | memory | 0x38162b | fwd |
| P-256 Montgomery reduction (shared kernel) | +0x415 | jne | reg/arith | `0x381622: dec %r8` | memory | 0x381510 | back |
| Branchless BIGNUM normalisation (write-back) | +0x7 | je | reg/arith | `0x311634: test %rax,%rax` | memory | 0x311663 | fwd |
| Branchless BIGNUM normalisation (write-back) | +0x2b | jae | reg/arith | `0x311657: cmp $0x3,%rcx` | arithmetic/control | 0x31166a | fwd |
| Branchless BIGNUM normalisation (write-back) | +0x8a | jne | reg/arith | `0x3116b7: cmp %rsi,%r8` | arithmetic/control | 0x311680 | back |
| Branchless BIGNUM normalisation (write-back) | +0x8f | je | reg/arith | `0x3116bc: test %rax,%rax` | memory | 0x3116e5 | fwd |
| Branchless BIGNUM normalisation (write-back) | +0xb3 | jne | reg/arith | `0x3116e0: cmp %r8,%rax` | memory | 0x3116d0 | back |
| BIGNUM write-back (declassification boundary) | +0x3 | je | reg/arith | `0x41b940: test %rdi,%rdi` | memory | 0x41b97f | fwd |
| BIGNUM write-back (declassification boundary) | +0x13 | jae | mem | `0x41b950: cmp %rdx,(%rdi)` | call | 0x41b982 | fwd |
| BIGNUM write-back (declassification boundary) | +0x25 | je | reg/arith | `0x41b963: test %al,%al` | memory | 0x41b9e4 | fwd |
| BIGNUM write-back (declassification boundary) | +0x32 | ja | mem | `0x41b967: cmp (%rbx),%r14` | arithmetic/control | 0x41ba78 | fwd |
| BIGNUM write-back (declassification boundary) | +0x4f | je | reg/arith | `0x41b98c: test %r14,%r14` | memory | 0x41b9ab | fwd |
| BIGNUM write-back (declassification boundary) | +0x72 | je | reg/arith | `0x41b9ab: add %r14,%rdi` | memory | 0x41b9dd | fwd |
| BIGNUM write-back (declassification boundary) | +0x95 | jae | reg/arith | `0x41b9d1: cmp $0x3,%rcx` | arithmetic/control | 0x41b9ec | fwd |
| BIGNUM write-back (declassification boundary) | +0xfa | jne | reg/arith | `0x41ba37: cmp %rsi,%rdi` | arithmetic/control | 0x41ba00 | back |
| BIGNUM write-back (declassification boundary) | +0xff | je | reg/arith | `0x41ba3c: test %rax,%rax` | memory | 0x41ba65 | fwd |
| BIGNUM write-back (declassification boundary) | +0x123 | jne | reg/arith | `0x41ba60: cmp %rdi,%rax` | memory | 0x41ba50 | back |
