# PFP-4 — binary branch audit of the order-inverse carriers

Subject: candidate DSO `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77`
(`court/tmp/pfp4-a/distribution/libcrypto.so.3`). Instrument:
`courts/phase18/timing/binary_branch_audit.py` (7 targets resolved uniquely with
complete disassembly) plus `objdump -d` over two symbol ranges the shared
exact-pointer rule cannot name. `audit/raw/audit-pfp4.md`, `audit-pfp4.stderr`,
`do-inverse-ord.asm`, `to-canonical.asm`, `audit-meta.env`.

This is a **review aid, not a proof of constant time**: the script reports the
instructions the compiler emitted; the source classification below is the
review, and BINSEC `-checkct` (T16) is the binary-level instrument that has not
been run.

## Per-function counts

| carrier | bytes | insns | jcc | cmov | setcc | div | cpuid |
|---|---:|---:|---:|---:|---:|---:|---:|
| `try_inverse_order` (admission + marshalling) | 906 | 208 | 10 | 1 | 0 | 0 | 0 |
| `P256Scalar::invert` (Fermat schedule, kernel inlined) | 2,307 | 515 | 2 | 0 | 0 | 0 | 0 |
| `from_canonical_reduced` (order reduction) | 1,003 | 232 | 0 | 0 | 0 | 0 | 0 |
| `P256Scalar::to_canonical` (manual range) | — | — | 0 | 0 | 0 | 0 | 0 |
| `ossl_ec_group_do_inverse_ord` (manual range) | 461 | — | 11 | 0 | 1 | 0 | 0 |
| shared `mont_reduce_into` (pre-existing) | 1,086 | 296 | 2 | 0 | 2 | 0 | 0 |
| shared `wide_mul_x86` (pre-existing) | 396 | 112 | 0 | 0 | 9 | 0 | 0 |
| shared `normalise_branchless` (pre-existing) | 186 | 50 | 5 | 5 | 0 | 0 | 0 |
| shared `store_coordinate` (pre-existing) | 348 | 100 | 10 | 5 | 0 | 0 | 0 |

## New carrier — every conditional transfer, classified

`P256Scalar::invert` — the only two conditional jumps are the **public
schedule**:

| offset | insn | setter | classification |
|---:|---|---|---|
| +0x87 | `jae` | `add $-1,%rcx` | fixed 256-iteration loop counter — **public** |
| +0x49a | `jae` | `bt %rcx,%rax` (rax loaded from read-only `n-2` limb) | exponent-bit test of the compile-time constant `n-2` — **public** |

No secret-limb comparison exists in the carrier; the inlined squaring and
multiplication (425 kernel operations) emit no conditional jump, cmov or setcc.

`try_inverse_order` — all ten jumps and the single cmov are on public metadata:

| offset | insn | setter | classification |
|---:|---|---|---|
| +0x12 | `je` | `test %rsi,%rsi` | `r` pointer nullness — public ABI |
| +0x1a | `je` | `test %rdx,%rdx` | `x` pointer nullness — public ABI |
| +0x26 | `je` | `test %al,%al` | `admits(group)` result (public group identity) |
| +0x3c | `je` | `cmpl $0,0x18(%r14)` | `operand.neg` (public sign metadata) |
| +0x5f | `ja` | `cmp $0x4,%rax` | `operand.d.len() > LIMBS` (public limb count) |
| +0xa8 | `ja` | `cmpq $0x3,(%rbx)` | `Vec` capacity/length bound (public metadata) |
| +0xbb | `je` | `test %al,%al` | `store_coordinate` result (public success/failure) |
| +0xcd | `ja` | `cmpq $0x3,(%rbx)` | `Vec` capacity/length bound (public metadata) |
| +0x122 | `je` | `add $0x4,%rdx` | `copy_from_slice` loop bound over the limb count |
| +0x151 | `jne` | `add $-8,%rdx` | same copy loop, back edge |
| +0x376 | `cmovne` | copy-loop condition | selects the copy pointer; loop counter is the limb count |

`from_canonical_reduced` and `P256Scalar::to_canonical` emit **no** conditional
transfer, cmov or setcc.

`ossl_ec_group_do_inverse_ord` — dispatch and fallback, all on public metadata:

| offset | insn | setter | classification |
|---:|---|---|---|
| +0x1e | `je` | `test %rax,%rax` | method's `field_inverse_mod_ord` nullness (public table) |
| +0x3b | `je` | `cmpq $0,0x90(%rdi)` | `mont_data` nullness (public group metadata) |
| +0x56 | `jne` | `test $0x1,%cl` | `Option` tag of the admission result (public) |
| +0x5f | `je` | `test %rbx,%rbx` | caller `ctx` nullness (public) |
| +0x7d | `je` | `test %rax,%rax` | `BN_CTX_get` allocation result (public) |
| +0x92 | `je` | `test %eax,%eax` | `BN_set_word` result (public) |
| +0xa6 | `je` | `test %eax,%eax` | `BN_sub` result (public) |
| +0xcc | `je` | `test %rcx,%rcx` | `BN_CTX` stack counter (public) |
| +0xff | `je` | `test %rax,%rax` | `BN_CTX` stack counter (public) |
| +0x154 | `je` | `cmpl $0x1,(%rsp)` | `RawVec::finish_grow` allocation tag (public) |
| +0x174 | `je` | `test %rax,%rax` | allocation result (public) |
| +0xe7 | `setne` | `test %eax,%eax` | normalises the public success flag |

## Shared carriers on the path (previously audited)

`mont_reduce_into` (2 jcc: fixed REDC length; 2 setcc: mask formation),
`wide_mul_x86` (9 setcc: carry/mask formation), `normalise_branchless` (5 jcc,
5 cmov) and `store_coordinate` (10 jcc, 5 cmov) are unchanged from PFP-2/PFP-20
and PFP-3. Their conditional transfers are on `Vec` lengths/capacities and the
computed normalised length, not on limb values; the PFP-20 record carries that
classification and it is reused, not re-derived here.

## Conclusion

Every `jcc`/`setcc`/`cmov` in the **new** carrier is classified **public-bound**.
No conditional transfer reads a secret limb. The schedule's only value inputs
are the compile-time constant `n-2` and the fixed iteration count. This is a
source-review classification of the emitted instructions, not a taint proof.
