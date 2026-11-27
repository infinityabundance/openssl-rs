# PFP-3 exact-symbol carrier audit

DSO `/work/court/tmp/pfp3-ctgrind-postfix/a/libcrypto.so.3` sha256 `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053`.

| family | symbol (mangled) | extent | insns | jcc | cmov | setcc | div |
|---|---|---:|---:|---:|---:|---:|---:|
| RCB complete addition (secret path) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base7rcb_addINtB4_4MontNtB4_11FieldDomainEEB8_` | 17258 | 3389 | 0 | 0 | 40 | 0 |
| Comb (table_mul: select + double + add) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base9table_mulINtB4_4MontNtB4_11FieldDomainEEB8_` | 10574 | 1619 | 2 | 0 | 2 | 0 |
| Affine export (to_affine: Fermat inversion) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base9to_affineINtB4_4MontNtB4_11FieldDomainEEB8_` | 1557 | 326 | 2 | 0 | 0 | 0 |
| Table construction (build_table) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base11build_tableINtB4_4MontNtB4_11FieldDomainEEB8_` | 2458 | 423 | 1 | 0 | 0 | 0 |
| Table advance (build_table::advance) | `_RINvNvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base11build_table7advanceINtB6_4MontNtB6_11FieldDomainEEBa_` | 771 | 168 | 1 | 0 | 0 | 0 |
| Fixed-base entry and admission (inlined into wNAF) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` | 7402 | 1577 | 183 | 34 | 5 | 4 |

## jcc rows per carrier

### RCB complete addition (secret path)

```
setcc:
   +0x11e setb %r9b src=reg/arith
   +0x13f setb %al src=reg/arith
   +0x15f setb %dl src=reg/arith
   +0x1a4 setb %r9b src=reg/arith
   +0x2ab setb %r14b src=reg/arith
   +0x2cf setb %r8b src=reg/arith
   +0x2f3 setb %r11b src=reg/arith
   +0x34c setb %cl src=reg/arith
   +0x57d setb %r9b src=reg/arith
   +0x58b setb %cl src=mem
   +0x59d setb %al src=mem
   +0x5da setb %r9b src=reg/arith
   +0x95b setb %r8b src=reg/arith
   +0xb50 setb %dl src=reg/arith
   +0xce6 setb %dl src=mem
   +0xda1 setb %r14b src=mem
   +0xe91 setb %bpl src=reg/arith
   +0xea4 setb %sil src=mem
   +0xeb0 setb %r10b src=mem
   +0xf50 setb %r11b src=reg/arith
  +0x14ef setb %al src=reg/arith
  +0x1500 setb %al src=mem
  +0x1515 setb %dil src=mem
  +0x1556 setb %r9b src=reg/arith
  +0x1b91 setb %bl src=reg/arith
  +0x1ec1 setb %bpl src=reg/arith
  +0x1ecc setb %al src=mem
  +0x1edc setb %r12b src=mem
  +0x1f29 setb %r15b src=reg/arith
  +0x2388 setb %bl src=reg/arith
  +0x2992 setb %bl src=reg/arith
  +0x2cc4 setb %bl src=reg/arith
  +0x3438 setb %dl src=reg/arith
  +0x3446 setb %dl src=mem
  +0x3458 setb %dil src=mem
  +0x348a setb %r9b src=reg/arith
  +0x3ac4 setb %r10b src=reg/arith
  +0x3adc setb %dl src=mem
  +0x3ae9 setb %dil src=mem
  +0x3b1c setb %r9b src=reg/arith
```

### Comb (table_mul: select + double + add)

```
  +0x1c38 jne   src=reg/arith  guarded=memory           dir=back target=0x576630  [0x5777f2: cmp $0x5a0,%rax]
  +0x28a4 jne   src=reg/arith  guarded=memory           dir=back target=0x575ca0  [0x578461: test %rax,%rax]
setcc:
   +0x471 setb %al src=reg/arith
   +0xa85 sete %al src=mem
```

### Affine export (to_affine: Fermat inversion)

```
    +0x74 jae   src=reg/arith  guarded=call+memory      dir=fwd  target=0x578781  [0x578580: add $0xffffffffffffffff,%rbx]
   +0x176 jae   src=reg/arith  guarded=call+memory      dir=back target=0x578580  [0x578682: bt %rbx,%rax]
```

### Table construction (build_table)

```
   +0x89f jne   src=reg/arith  guarded=memory           dir=back target=0x571550  [0x57174b: cmp $0x10,%r13]
```

### Table advance (build_table::advance)

```
   +0x27d jne   src=reg/arith  guarded=memory           dir=back target=0x580410  [0x58064a: dec %rbp]
```

### Fixed-base entry and admission (inlined into wNAF)

```
    +0x37 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d9b6  [0x58d68c: test %r10,%r10]
    +0x53 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d9b6  [0x58d6b0: cmp %rcx,%rax]
    +0x62 je    src=mem        guarded=memory           dir=back target=0x58d6b0  [0x58d6b9: cmpq $0x0,(%r11,%rcx,1)]
    +0x6b je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d9b6  [0x58d6c8: test %rcx,%rcx]
    +0x93 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d9b6  [0x58d6f0: cmp %r9,%rdx]
    +0xa2 je    src=mem        guarded=arithmetic/control dir=back target=0x58d6f0  [0x58d6f9: cmpq $0x0,(%rax,%r9,1)]
    +0xa7 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58d990  [0x58d704: cmp %r10,%r12]
    +0xbd je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58d990  [0x58d71a: test %r9b,%dl]
    +0xc9 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d726: test %rsi,%rsi]
    +0xd6 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d733: test %r10,%r10]
    +0xe3 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d740: test %r9,%r9]
    +0xf0 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d74d: test %r8,%r8]
   +0x101 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d75e: test %rdx,%rdx]
   +0x10e je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d76b: test %rdx,%rdx]
   +0x11e je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d77b: test %rbx,%rbx]
   +0x12e je    src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d78b: test %rdi,%rdi]
   +0x155 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d7b2: or %rbx,%rdi]
   +0x163 jne   src=mem        guarded=memory           dir=fwd  target=0x58d978  [0x58d7bb: cmpq $0x0,0x118(%rdx)]
   +0x171 jne   src=mem        guarded=memory           dir=fwd  target=0x58d978  [0x58d7c9: cmpq $0x0,0x120(%rdx)]
   +0x17f jne   src=mem        guarded=memory           dir=fwd  target=0x58d978  [0x58d7d7: cmpq $0x0,0x128(%rdx)]
   +0x193 jne   src=mem        guarded=memory           dir=fwd  target=0x58d978  [0x58d7ec: cmp %rbx,0x1a8(%rdx)]
   +0x19e jne   src=mem        guarded=memory           dir=fwd  target=0x58d978  [0x58d7f9: cmpq $0x4,0x10(%r10)]
   +0x1e2 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d83f: or %r10b,%dil]
   +0x211 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d978  [0x58d86b: cmp $0xffff,%edx]
   +0x252 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d970  [0x58d8ae: cmp $0x4,%rdi]
   +0x281 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d970  [0x58d8db: cmp $0xffff,%esi]
   +0x2db jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d970  [0x58d937: cmp $0x4,%rdi]
   +0x30a je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58ed85  [0x58d964: cmp $0xffff,%esi]
   +0x33a jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58d9b6  [0x58d997: or %r12,%rax]
   +0x343 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58da71  [0x58d9a0: cmp %r10,%rdx]
   +0x359 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58da71  [0x58d9b6: test %r12,%r12]
   +0x366 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58daa7  [0x58d9c3: test %r15,%r15]
   +0x38d je    src=reg/arith  guarded=memory           dir=fwd  target=0x58dac6  [0x58d9db: test %rax,%rax]
   +0x398 je    src=mem        guarded=memory           dir=fwd  target=0x58dac6  [0x58d9f3: cmpq $0x0,0x10(%rax)]
   +0x3b5 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58daba  [0x58da12: test %rax,%rax]
   +0x3c5 jne   src=mem        guarded=memory           dir=fwd  target=0x58dac1  [0x58da22: cmp (%r15),%rcx]
   +0x3e3 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e109  [0x58da40: test %r10d,%r10d]
   +0x3f0 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58da57  [0x58da4d: test %r9d,%r9d]
   +0x3f5 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58dac1  [0x58da52: cmp %r9d,%r10d]
   +0x3fa jne   src=mem        guarded=memory           dir=fwd  target=0x58dac1  [0x58da57: cmp (%rdx),%rcx]
   +0x401 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58e112  [0x58da5f: test %ecx,%ecx]
   +0x40a jne   src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58dac1  [0x58da67: cmp %ecx,%r10d]
   +0x4a5 jb    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58ed4e  [0x58db02: add %rbx,%r12]
   +0x4f9 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58ed57  [0x58db55: cmp $0xffffffffffffffff,%r12]
   +0x53f je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ddd8  [0x58db9c: test %r15,%r15]
   +0x55d je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58de3b  [0x58dbb5: test %rdi,%rdi]
   +0x566 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58de3b  [0x58dbc3: test %rbx,%rbx]
   +0x56f je    src=reg/arith  guarded=memory           dir=fwd  target=0x58de3b  [0x58dbcc: test %r12,%r12]
   +0x57a jb    src=mem        guarded=memory           dir=fwd  target=0x58ed60  [0x58dbd5: add 0x58(%rsp),%r13]
   +0x58d je    src=unknown    guarded=memory           dir=fwd  target=0x58df40  [?]
   +0x5ca jae   src=mem        guarded=memory           dir=fwd  target=0x58dc35  [0x58dc25: cmp 0x58(%rsp),%r14]
   +0x5e5 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58dc80  [0x58dc40: cmp $0x7cf,%eax]
   +0x5f1 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58dc80  [0x58dc4c: cmp $0x31f,%eax]
   +0x5fd ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58dc80  [0x58dc58: cmp $0x12b,%eax]
   +0x607 ja    src=reg/arith  guarded=memory           dir=fwd  target=0x58dc80  [0x58dc64: cmp $0x45,%eax]
   +0x635 jb    src=reg/arith  guarded=memory           dir=fwd  target=0x58ed75  [0x58dc92: add %rax,%r13]
   +0x653 jae   src=mem        guarded=call+memory      dir=fwd  target=0x58dcbe  [0x58dcae: cmp 0x58(%rsp),%r14]
   +0x67d je    src=reg/arith  guarded=memory           dir=fwd  target=0x58df68  [0x58dcda: test %rax,%rax]
   +0x6a6 jne   src=reg/arith  guarded=memory           dir=back target=0x58dc20  [0x58dcfe: dec %r15]
   +0x6b9 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58df5f  [0x58dd11: test %r14,%r14]
   +0x6cb je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e02e  [0x58dd24: test %rax,%rax]
   +0x6e2 je    src=mem        guarded=call+memory      dir=fwd  target=0x58e060  [0x58dd3d: cmpb $0x0,0x78(%rsp)]
   +0x712 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e048  [0x58dd67: test %rax,%rax]
   +0x72e jbe   src=mem        guarded=arithmetic/control dir=fwd  target=0x58e168  [0x58dd85: cmp 0x60(%rsp),%rcx]
   +0x73a jo    src=reg/arith  guarded=memory           dir=fwd  target=0x58f208  [0x58dd97: mul %rsi]
   +0x74c jae   src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58e21d  [0x58dda9: cmp %rax,%rcx]
   +0x755 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58f21d  [0x58ddb2: test %rsi,%rsi]
   +0x765 je    src=reg/arith  guarded=division         dir=fwd  target=0x58e1b8  [0x58ddc1: shr $0x20,%rax]
   +0x784 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58de09  [0x58dddc: test %rdi,%rdi]
   +0x7ac je    src=reg/arith  guarded=memory           dir=fwd  target=0x58df0a  [0x58de09: test %rbx,%rbx]
   +0x7de je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58de63  [0x58de3b: test %rdi,%rdi]
   +0x80b je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58de93  [0x58de63: test %rbx,%rbx]
   +0x83a je    src=reg/arith  guarded=memory           dir=fwd  target=0x58dee4  [0x58de97: test %rdi,%rdi]
   +0x882 jne   src=reg/arith  guarded=call+memory      dir=back target=0x58dec0  [0x58dedf: test %rdi,%rdi]
   +0x8af je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58e6f0  [0x58df0c: test %r12,%r12]
   +0x8f9 jne   src=reg/arith  guarded=memory           dir=back target=0x58dd1f  [0x58df51: test %r14,%r14]
   +0x95b je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58dff4  [0x58dfb8: test %rdi,%rdi]
   +0x992 jne   src=reg/arith  guarded=call+memory      dir=back target=0x58dfd0  [0x58dfef: test %rdi,%rdi]
   +0x9d6 jne   src=mem        guarded=call+memory      dir=fwd  target=0x58e34c  [0x58e02e: cmpb $0x0,0x128(%rsp)]
   +0xa60 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58e564  [0x58e0bd: test %rdi,%rdi]
   +0xaa2 jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x58e0e0  [0x58e0ff: test %rdi,%rdi]
   +0xaac jne   src=mem        guarded=call+memory      dir=back target=0x58dac1  [0x58e109: cmp (%rdx),%rcx]
   +0xac1 jne   src=reg/arith  guarded=memory           dir=back target=0x58dac6  [0x58e11f: test %eax,%eax]
   +0xadc je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58f226  [0x58e139: test %r13,%r13]
   +0xaf2 je    src=reg/arith  guarded=division         dir=fwd  target=0x58e9fb  [0x58e14e: shr $0x20,%rdx]
   +0xb11 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58f211  [0x58e16d: cmp $0xffffffffffffffff,%rcx]
   +0xb6f jbe   src=mem        guarded=call+memory      dir=fwd  target=0x58e20a  [0x58e1cb: cmp 0x10(%rcx),%rax]
   +0xbb7 jb    src=mem        guarded=memory           dir=fwd  target=0x58f282  [0x58e20a: add 0x58(%rsp),%rax]
   +0xbcd jae   src=reg/arith  guarded=memory           dir=fwd  target=0x58e31f  [0x58e22a: cmp %rax,%r14]
   +0xbf5 jae   src=mem        guarded=memory           dir=fwd  target=0x58e280  [0x58e24b: cmp 0x48(%rsp),%r14]
   +0xc0b jb    src=reg/arith  guarded=memory           dir=fwd  target=0x58ea7b  [0x58e268: sub %rsi,%rax]
   +0xc57 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e968  [0x58e2b4: test %rax,%rax]
   +0xc76 je    src=mem        guarded=memory           dir=fwd  target=0x58e9b2  [0x58e2d2: cmpq $0x0,(%rdi)]
   +0xcb9 jne   src=mem        guarded=call+memory      dir=back target=0x58e24b  [0x58e30d: cmp %r14,0x80(%rsp)]
   +0xcf0 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ed69  [0x58e34c: cmp $0xffffffffffffffff,%r13]
   +0xd14 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e4d6  [0x58e371: test %rax,%rax]
   +0xd36 je    src=mem        guarded=memory           dir=fwd  target=0x58e498  [0x58e385: cmpq $0x0,0x88(%rsp)]
   +0xd65 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58f24d  [0x58e3c2: test %rcx,%rcx]
   +0xd71 je    src=mem        guarded=memory           dir=fwd  target=0x58e948  [0x58e3cb: cmpq $0x0,0x30(%rsp)]
   +0xd84 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58f266  [0x58e3e0: cmp $0x40,%rcx]
   +0xd95 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58e47d  [0x58e3f2: test %rax,%rax]
   +0xda8 je    src=mem        guarded=memory           dir=fwd  target=0x58e5bf  [0x58e403: cmpq $0x0,0x50(%rax)]
   +0xdc8 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e5af  [0x58e425: test %rax,%rax]
   +0xdea je    src=reg/arith  guarded=call             dir=fwd  target=0x58e589  [0x58e447: test %rax,%rax]
   +0xdf7 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e589  [0x58e455: test %eax,%eax]
   +0xe12 jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x58e3e0  [0x58e46f: test %rcx,%rcx]
   +0xe32 jne   src=mem        guarded=memory           dir=back target=0x58e3ba  [0x58e480: cmp 0x88(%rsp),%r14]
   +0xe42 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58e701  [0x58e49c: cmp %rax,%rbx]
   +0xec8 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58e564  [0x58e525: test %rdi,%rdi]
   +0xf02 jne   src=reg/arith  guarded=memory           dir=back target=0x58e540  [0x58e55f: test %rdi,%rdi]
   +0xfc9 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58e664  [0x58e626: test %rdi,%rdi]
  +0x1002 jne   src=reg/arith  guarded=call+memory      dir=back target=0x58e640  [0x58e65f: test %rdi,%rdi]
  +0x102e je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58e6af  [0x58e68b: test %rdi,%rdi]
  +0x104d jne   src=reg/arith  guarded=call+memory      dir=back target=0x58e6a0  [0x58e6aa: test %rdi,%rdi]
  +0x10af je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e8b6  [0x58e70c: test %rax,%rax]
  +0x10c5 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e8c7  [0x58e722: test %rbx,%rbx]
  +0x10f3 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e8c7  [0x58e74b: cmp %rbx,%r15]
  +0x1105 jae   src=mem        guarded=memory           dir=fwd  target=0x58e775  [0x58e760: cmp 0x58(%rsp),%r15]
  +0x1125 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ec84  [0x58e783: test %eax,%eax]
  +0x1134 jbe   src=mem        guarded=memory           dir=back target=0x58e748  [0x58e78f: cmpq $0x1,(%rax,%r15,8)]
  +0x1153 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e92b  [0x58e7b1: test %eax,%eax]
  +0x1164 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58f24d  [0x58e7c1: test %rcx,%rcx]
  +0x1174 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58f266  [0x58e7d0: cmp $0x40,%rcx]
  +0x1185 jne   src=reg/arith  guarded=memory           dir=back target=0x58e748  [0x58e7e2: test %rax,%rax]
  +0x119d je    src=reg/arith  guarded=memory           dir=fwd  target=0x58eae3  [0x58e7fa: test %rax,%rax]
  +0x11ae jne   src=mem        guarded=memory           dir=fwd  target=0x58e91f  [0x58e80b: cmp (%rsi),%r9]
  +0x11c3 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e873  [0x58e821: test %edi,%edi]
  +0x11cc je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58e837  [0x58e829: test %r8d,%r8d]
  +0x11d1 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58e91f  [0x58e82e: cmp %r8d,%edi]
  +0x11da jne   src=mem        guarded=memory           dir=fwd  target=0x58e91f  [0x58e837: cmp (%rdx),%r9]
  +0x11e7 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58e852  [0x58e844: test %r8d,%r8d]
  +0x11ec jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58e91f  [0x58e849: cmp %r8d,%edi]
  +0x11fa jne   src=mem        guarded=memory           dir=fwd  target=0x58e91f  [0x58e857: cmp (%rcx),%r9]
  +0x1207 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58e88a  [0x58e864: test %r8d,%r8d]
  +0x120c je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58e88a  [0x58e869: cmp %r8d,%edi]
  +0x1216 jne   src=mem        guarded=memory           dir=fwd  target=0x58e91f  [0x58e873: cmp (%rdx),%r9]
  +0x1224 jne   src=mem        guarded=call+memory      dir=fwd  target=0x58e91f  [0x58e881: cmp (%rcx),%r9]
  +0x1237 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58e92b  [0x58e895: test %eax,%eax]
  +0x124b jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x58e7d0  [0x58e8a8: test %rcx,%rcx]
  +0x1279 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58ec84  [0x58e8d6: test %rax,%rax]
  +0x1294 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ead9  [0x58e8ee: test %eax,%eax]
  +0x12aa jbe   src=reg/arith  guarded=memory           dir=fwd  target=0x58eaef  [0x58e8ff: cmp $0x7fffffff,%rax]
  +0x12ec jae   src=reg/arith  guarded=memory           dir=fwd  target=0x58f266  [0x58e948: cmp $0x41,%rcx]
  +0x13aa je    src=reg/arith  guarded=memory           dir=fwd  target=0x58f235  [0x58ea06: cmp $0xffffffffffffffff,%rdi]
  +0x13c9 jb    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x58f241  [0x58ea25: sub $0x1,%rcx]
  +0x13d3 jae   src=reg/arith  guarded=memory           dir=fwd  target=0x58f25a  [0x58ea2f: cmp $0x41,%rdx]
  +0x13e9 jo    src=reg/arith  guarded=memory           dir=fwd  target=0x58f273  [0x58ea46: mul %rdx]
  +0x13f8 jne   src=mem        guarded=memory           dir=fwd  target=0x58ea6f  [0x58ea54: cmp %rax,0x28(%rcx)]
  +0x1492 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58f28e  [0x58eaef: test %rax,%rax]
  +0x14c6 jle   src=mem        guarded=arithmetic/control dir=fwd  target=0x58ecbc  [0x58eb0e: cmpl $0x1,0x40(%rsp)]
  +0x14d2 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58eb4d  [0x58eb2f: test %r15d,%r15d]
  +0x14e7 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ecd3  [0x58eb45: test %eax,%eax]
  +0x1504 je    src=mem        guarded=arithmetic/control dir=back target=0x58eb0e  [0x58eb56: cmpq $0x0,0x80(%rsp)]
  +0x152e je    src=reg/arith  guarded=memory           dir=fwd  target=0x58eca7  [0x58eb87: test %eax,%eax]
  +0x153f je    src=mem        guarded=memory           dir=back target=0x58eb0e  [0x58eb97: cmp %rbx,0x80(%rsp)]
  +0x154e jbe   src=mem        guarded=memory           dir=back target=0x58eb94  [0x58ebaa: cmp %r13,(%rax,%rbx,8)]
  +0x1561 je    src=reg/arith  guarded=memory           dir=back target=0x58eb94  [0x58ebbe: test %r14d,%r14d]
  +0x156d je    src=mem        guarded=arithmetic/control dir=fwd  target=0x58ebff  [0x58ebc9: cmp %eax,0x58(%rsp)]
  +0x1572 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x58ebf0  [0x58ebcf: test %r15d,%r15d]
  +0x158a je    src=reg/arith  guarded=memory           dir=back target=0x58e92b  [0x58ebe8: test %eax,%eax]
  +0x15bd je    src=reg/arith  guarded=memory           dir=back target=0x58eb6d  [0x58ec1a: test %r15d,%r15d]
  +0x15d8 je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ec84  [0x58ec31: test %eax,%eax]
  +0x15ef je    src=reg/arith  guarded=call+memory      dir=back target=0x58eb94  [0x58ec4c: test %rax,%rax]
  +0x1602 jne   src=reg/arith  guarded=call+memory      dir=back target=0x58eb94  [0x58ec60: test %eax,%eax]
  +0x165f je    src=reg/arith  guarded=memory           dir=fwd  target=0x58ece1  [0x58ecbc: test %r15d,%r15d]
  +0x1686 je    src=mem        guarded=memory           dir=fwd  target=0x58ed00  [0x58ece1: cmpl $0x0,0x58(%rsp)]
  +0x169e je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58ed2c  [0x58ecfc: test %eax,%eax]
  +0x1731 jne   src=reg/arith  guarded=memory           dir=back target=0x58d978  [0x58ed85: cmp $0x1,%rcx]
  +0x173b jne   src=mem        guarded=memory           dir=back target=0x58d978  [0x58ed97: cmpq $0x1,(%rax)]
  +0x1749 je    src=mem        guarded=memory           dir=back target=0x58d978  [0x58eda5: cmpl $0x0,0x28(%rax)]
  +0x175a je    src=reg/arith  guarded=memory           dir=back target=0x58d978  [0x58edb7: test %rdx,%rdx]
  +0x176b je    src=reg/arith  guarded=memory           dir=back target=0x58d978  [0x58edc8: test %rax,%rax]
  +0x17c5 jne   src=reg/arith  guarded=memory           dir=back target=0x58d970  [0x58ee21: cmp $0x4,%rdx]
  +0x17f8 jne   src=reg/arith  guarded=memory           dir=back target=0x58d970  [0x58ee52: cmp $0xffff,%ecx]
  +0x1852 jne   src=reg/arith  guarded=memory           dir=back target=0x58d970  [0x58eeae: cmp $0x4,%rax]
  +0x1884 jne   src=reg/arith  guarded=memory           dir=back target=0x58d970  [0x58eedf: cmp $0xffff,%eax]
  +0x1898 jne   src=mem        guarded=memory           dir=back target=0x58d978  [0x58eeea: cmpl $0x0,0x18(%r12)]
  +0x18a7 ja    src=reg/arith  guarded=memory           dir=back target=0x58d978  [0x58ef03: cmp $0x4,%rdx]
  +0x19f8 jne   src=reg/arith  guarded=call+memory      dir=back target=0x58d970  [0x58f056: test %al,%al]
  +0x1a9a jne   src=reg/arith  guarded=call+memory      dir=fwd  target=0x58f2d2  [0x58f0f8: test %eax,%eax]
  +0x1b0d je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58f297  [0x58f16b: test %al,%al]
  +0x1b30 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58f297  [0x58f18e: test %al,%al]
  +0x1b53 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x58f297  [0x58f1b1: test %al,%al]
cmov:
   +0x68e cmova %rax,%rcx src=reg/arith
   +0x797 cmovne %rax,%rcx src=reg/arith
   +0x7c3 cmovne %rax,%rcx src=reg/arith
   +0x7f1 cmovne %rax,%rcx src=reg/arith
   +0x81e cmovne %rax,%rcx src=reg/arith
   +0x86a cmove %r15,%rax src=reg/arith
   +0x895 cmovne %rax,%rcx src=reg/arith
   +0x8c6 cmovne %rax,%rcx src=reg/arith
   +0x919 cmove %r14,%rax src=reg/arith
   +0x93c cmove %r14,%rax src=reg/arith
   +0x97a cmove %r14,%rax src=reg/arith
   +0x99e cmove %r14,%rax src=reg/arith
   +0x9c0 cmove %r14,%rax src=reg/arith
   +0xa1d cmove %r14,%rax src=reg/arith
   +0xa43 cmove %r14,%rax src=reg/arith
   +0xa8a cmove %r14,%rax src=reg/arith
   +0xb93 cmovne %rax,%rcx src=reg/arith
   +0xc94 cmova %rax,%rcx src=reg/arith
   +0xcd0 cmovne %rax,%rcx src=reg/arith
   +0xe87 cmove %r14,%rax src=reg/arith
   +0xea9 cmove %r14,%rax src=reg/arith
   +0xeea cmove %r14,%rax src=reg/arith
   +0xf0e cmove %r14,%rax src=reg/arith
   +0xf3a cmovne %rax,%rcx src=reg/arith
   +0xf8d cmove %r14,%rax src=reg/arith
   +0xfaf cmove %r14,%rax src=reg/arith
   +0xfea cmove %r14,%rax src=reg/arith
  +0x100e cmove %r14,%rax src=reg/arith
  +0x1059 cmove %r14,%rax src=reg/arith
  +0x107d cmove %r14,%rax src=reg/arith
  +0x1319 cmovne %rax,%rcx src=reg/arith
  +0x1379 cmovne %rax,%rcx src=reg/arith
  +0x13be cmovae %rax,%rdi src=reg/arith
  +0x1447 cmovne %rax,%rcx src=reg/arith
setcc:
    +0xb0 setne %dl src=reg/arith
    +0xb6 sete %r9b src=reg/arith
   +0x1d3 setne %r10b src=reg/arith
   +0x1db setne %dil src=reg/arith
  +0x1597 sete %al src=mem
```

