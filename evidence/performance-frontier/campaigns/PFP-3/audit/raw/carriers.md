# PFP-3 exact-symbol carrier audit

DSO `/work/court/tmp/pfp3-ctgrind/a/libcrypto.so.3` sha256 `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`.

| family | symbol (mangled) | extent | insns | jcc | cmov | setcc | div |
|---|---|---:|---:|---:|---:|---:|---:|
| RCB complete addition (secret path) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base7rcb_addINtB4_4MontNtB4_11FieldDomainEEB8_` | 17258 | 3389 | 0 | 0 | 40 | 0 |
| Comb (table_mul: select + double + add) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base9table_mulINtB4_4MontNtB4_11FieldDomainEEB8_` | 10574 | 1619 | 2 | 0 | 2 | 0 |
| Affine export (to_affine: Fermat inversion) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base9to_affineINtB4_4MontNtB4_11FieldDomainEEB8_` | 1557 | 326 | 2 | 0 | 0 | 0 |
| Table construction (build_table) | `_RINvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base11build_tableINtB4_4MontNtB4_11FieldDomainEEB8_` | 2458 | 423 | 1 | 0 | 0 | 0 |
| Table advance (build_table::advance) | `_RINvNvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base11build_table7advanceINtB6_4MontNtB6_11FieldDomainEEBa_` | 771 | 168 | 1 | 0 | 0 | 0 |
| Fixed-base entry and admission (inlined into wNAF) | `_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2ec4mult16ossl_ec_wNAF_mul` | 7223 | 1525 | 186 | 33 | 5 | 4 |

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
  +0x1c38 jne   src=reg/arith  guarded=memory           dir=back target=0x229dc0  [0x22af82: cmp $0x5a0,%rax]
  +0x28a4 jne   src=reg/arith  guarded=memory           dir=back target=0x229430  [0x22bbf1: test %rax,%rax]
setcc:
   +0x471 setb %al src=reg/arith
   +0xa85 sete %al src=mem
```

### Affine export (to_affine: Fermat inversion)

```
    +0x74 jae   src=reg/arith  guarded=call+memory      dir=fwd  target=0x22bf11  [0x22bd10: add $0xffffffffffffffff,%rbx]
   +0x176 jae   src=reg/arith  guarded=call+memory      dir=back target=0x22bd10  [0x22be12: bt %rbx,%rax]
```

### Table construction (build_table)

```
   +0x89f jne   src=reg/arith  guarded=memory           dir=back target=0x224ce0  [0x224edb: cmp $0x10,%r13]
```

### Table advance (build_table::advance)

```
   +0x27d jne   src=reg/arith  guarded=memory           dir=back target=0x233ba0  [0x233dda: dec %rbp]
```

### Fixed-base entry and admission (inlined into wNAF)

```
    +0x39 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b6b  [0x24082c: test %r11,%r11]
    +0x63 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b6b  [0x240860: cmp %rcx,%rax]
    +0x72 je    src=mem        guarded=memory           dir=back target=0x240860  [0x240869: cmpq $0x0,(%rsi,%rcx,1)]
    +0x7b je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b6b  [0x240878: test %rcx,%rcx]
    +0xa3 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b6b  [0x2408a0: cmp %r9,%rdx]
    +0xb2 je    src=mem        guarded=arithmetic/control dir=back target=0x2408a0  [0x2408a9: cmpq $0x0,(%rax,%r9,1)]
    +0xb7 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240b34  [0x2408b4: cmp %r11,%r13]
    +0xcd je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240b34  [0x2408ca: test %r9b,%dl]
    +0xdf je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x2408dc: test %r15,%r15]
    +0xec je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x2408e9: test %r10,%r10]
    +0xf9 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x2408f6: test %r9,%r9]
   +0x106 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x240903: test %r8,%r8]
   +0x118 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x240915: test %rdx,%rdx]
   +0x125 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x240922: test %r11,%r11]
   +0x135 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x240932: test %rbx,%rbx]
   +0x145 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x240942: test %rdx,%rdx]
   +0x162 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x24095f: or %rbx,%rdx]
   +0x170 jne   src=mem        guarded=memory           dir=fwd  target=0x240b24  [0x240968: cmpq $0x0,0x118(%r11)]
   +0x17e jne   src=mem        guarded=memory           dir=fwd  target=0x240b24  [0x240976: cmpq $0x0,0x120(%r11)]
   +0x18c jne   src=mem        guarded=memory           dir=fwd  target=0x240b24  [0x240984: cmpq $0x0,0x128(%r11)]
   +0x1a0 jne   src=mem        guarded=memory           dir=fwd  target=0x240b24  [0x240999: cmp %rbx,0x1a8(%r11)]
   +0x1ab jne   src=mem        guarded=memory           dir=fwd  target=0x240b24  [0x2409a6: cmpq $0x4,0x10(%r10)]
   +0x1ef jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x2409ec: or %r10b,%dil]
   +0x21c jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b24  [0x240a16: cmp $0xffff,%esi]
   +0x260 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b1e  [0x240a5c: cmp $0x4,%rdi]
   +0x28f jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b1e  [0x240a89: cmp $0xffff,%esi]
   +0x2e9 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b1e  [0x240ae5: cmp $0x4,%rdi]
   +0x318 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241eea  [0x240b12: cmp $0xffff,%esi]
   +0x33e jne   src=reg/arith  guarded=memory           dir=fwd  target=0x240b6b  [0x240b3b: or %r13,%rax]
   +0x346 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240c25  [0x240b43: cmp %r11,%rdx]
   +0x36e je    src=reg/arith  guarded=memory           dir=fwd  target=0x240c25  [0x240b6b: test %r13,%r13]
   +0x37b je    src=reg/arith  guarded=memory           dir=fwd  target=0x240ff1  [0x240b78: test %r12,%r12]
   +0x39f je    src=reg/arith  guarded=memory           dir=fwd  target=0x241175  [0x240b92: test %rax,%rax]
   +0x3aa je    src=mem        guarded=memory           dir=fwd  target=0x241175  [0x240ba5: cmpq $0x0,0x10(%rax)]
   +0x3c3 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241169  [0x240bc0: test %rax,%rax]
   +0x3d4 jne   src=mem        guarded=memory           dir=fwd  target=0x241170  [0x240bd0: cmp (%r12),%rcx]
   +0x3eb je    src=reg/arith  guarded=memory           dir=fwd  target=0x241299  [0x240be9: test %esi,%esi]
   +0x3f9 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240c04  [0x240bf6: test %r8d,%r8d]
   +0x3fe jne   src=reg/arith  guarded=memory           dir=fwd  target=0x241170  [0x240bfb: cmp %r8d,%esi]
   +0x407 jne   src=mem        guarded=memory           dir=fwd  target=0x241170  [0x240c04: cmp (%rdx),%rcx]
   +0x412 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x2412a2  [0x240c10: test %ecx,%ecx]
   +0x41a jne   src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241170  [0x240c18: cmp %ecx,%esi]
   +0x472 jb    src=reg/arith  guarded=call+memory      dir=fwd  target=0x2411b7  [0x240c6f: add %r14,%r13]
   +0x4cf je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241ebc  [0x240ccb: cmp $0xffffffffffffffff,%r13]
   +0x514 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240e87  [0x240d11: test %r12,%r12]
   +0x534 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240eeb  [0x240d2c: test %rdi,%rdi]
   +0x53d je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240eeb  [0x240d3a: test %rbx,%rbx]
   +0x546 je    src=reg/arith  guarded=memory           dir=fwd  target=0x240eeb  [0x240d43: test %r13,%r13]
   +0x551 jb    src=mem        guarded=memory           dir=fwd  target=0x241ec5  [0x240d4c: add 0x58(%rsp),%r15]
   +0x569 je    src=unknown    guarded=memory           dir=fwd  target=0x241005  [?]
   +0x59a jae   src=mem        guarded=memory           dir=fwd  target=0x240da5  [0x240d95: cmp 0x58(%rsp),%r15]
   +0x5b5 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240df0  [0x240db0: cmp $0x7cf,%eax]
   +0x5c1 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240df0  [0x240dbc: cmp $0x31f,%eax]
   +0x5cd ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x240df0  [0x240dc8: cmp $0x12b,%eax]
   +0x5d7 ja    src=reg/arith  guarded=memory           dir=fwd  target=0x240df0  [0x240dd4: cmp $0x45,%eax]
   +0x606 jb    src=reg/arith  guarded=memory           dir=fwd  target=0x241eda  [0x240e03: add %rax,%rbp]
   +0x624 jae   src=mem        guarded=call+memory      dir=fwd  target=0x240e2f  [0x240e1f: cmp 0x58(%rsp),%r15]
   +0x64f je    src=reg/arith  guarded=memory           dir=fwd  target=0x2410cc  [0x240e4c: test %rax,%rax]
   +0x66e jne   src=reg/arith  guarded=memory           dir=back target=0x240d90  [0x240e66: dec %r14]
   +0x67c jne   src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241018  [0x240e79: test %r14,%r14]
   +0x694 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x240eb9  [0x240e8c: test %rdi,%rdi]
   +0x6bc je    src=reg/arith  guarded=memory           dir=fwd  target=0x240fba  [0x240eb9: test %rbx,%rbx]
   +0x6ee je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x240f13  [0x240eeb: test %rdi,%rdi]
   +0x71b je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x240f43  [0x240f13: test %rbx,%rbx]
   +0x74a je    src=reg/arith  guarded=memory           dir=fwd  target=0x240f94  [0x240f47: test %rdi,%rdi]
   +0x792 jne   src=reg/arith  guarded=call+memory      dir=back target=0x240f70  [0x240f8f: test %rdi,%rdi]
   +0x7c0 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x2418a1  [0x240fbd: test %r13,%r13]
   +0x812 je    src=reg/arith  guarded=memory           dir=fwd  target=0x2414dd  [0x24100f: test %r14,%r14]
   +0x825 je    src=reg/arith  guarded=memory           dir=fwd  target=0x2411c3  [0x24101d: test %rax,%rax]
   +0x83f je    src=mem        guarded=call+memory      dir=fwd  target=0x2411f5  [0x241037: cmpb $0x0,0x88(%rsp)]
   +0x86c je    src=reg/arith  guarded=memory           dir=fwd  target=0x2411dd  [0x241069: test %rax,%rax]
   +0x87d jbe   src=reg/arith  guarded=memory           dir=fwd  target=0x2412ff  [0x24107a: cmp %r13,%rcx]
   +0x88e jo    src=reg/arith  guarded=memory           dir=fwd  target=0x2422f5  [0x24108b: mul %rsi]
   +0x8a0 jae   src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x2413be  [0x24109d: cmp %rax,%rcx]
   +0x8a9 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x24230a  [0x2410a6: test %rsi,%rsi]
   +0x8b9 je    src=reg/arith  guarded=division         dir=fwd  target=0x241354  [0x2410b5: shr $0x20,%rax]
   +0x920 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241704  [0x24111d: test %rdi,%rdi]
   +0x962 jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x241140  [0x24115f: test %rdi,%rdi]
   +0x9b1 jae   src=reg/arith  guarded=memory           dir=back target=0x240c78  [0x2411ae: add %r14,%r13]
   +0x9cb jne   src=mem        guarded=call+memory      dir=fwd  target=0x2414e2  [0x2411c3: cmpb $0x0,0x98(%rsp)]
   +0xa54 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241704  [0x241251: test %rdi,%rdi]
   +0xa92 jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x241270  [0x24128f: test %rdi,%rdi]
   +0xa9c jne   src=mem        guarded=call+memory      dir=back target=0x241170  [0x241299: cmp (%rdx),%rcx]
   +0xab1 jne   src=reg/arith  guarded=memory           dir=back target=0x241175  [0x2412af: test %eax,%eax]
   +0xad6 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x242313  [0x2412d3: test %rsi,%rsi]
   +0xae9 je    src=reg/arith  guarded=division         dir=fwd  target=0x241ba5  [0x2412e5: shr $0x20,%rdx]
   +0xb08 je    src=reg/arith  guarded=memory           dir=fwd  target=0x2422fe  [0x241304: cmp $0xffffffffffffffff,%rdx]
   +0xb6b jbe   src=mem        guarded=call+memory      dir=fwd  target=0x2413ab  [0x241367: cmp 0x10(%rcx),%rax]
   +0xbb8 jb    src=mem        guarded=memory           dir=fwd  target=0x24236f  [0x2413ab: add 0x58(%rsp),%rax]
   +0xbce jae   src=reg/arith  guarded=memory           dir=fwd  target=0x2414b5  [0x2413cb: cmp %rax,%r14]
   +0xbf9 jae   src=mem        guarded=memory           dir=fwd  target=0x241424  [0x2413ef: cmp 0x48(%rsp),%r14]
   +0xc0f jb    src=reg/arith  guarded=memory           dir=fwd  target=0x241c47  [0x24140c: sub %rsi,%rax]
   +0xc5b je    src=reg/arith  guarded=memory           dir=fwd  target=0x241b32  [0x241458: test %rax,%rax]
   +0xc7a je    src=mem        guarded=memory           dir=fwd  target=0x241b69  [0x241476: cmpq $0x0,(%rdi)]
   +0xcaf jne   src=mem        guarded=call+memory      dir=back target=0x2413ef  [0x2414a7: cmp %r14,0x90(%rsp)]
   +0xce6 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241ece  [0x2414e2: cmp $0xffffffffffffffff,%rbp]
   +0xd0a je    src=reg/arith  guarded=memory           dir=fwd  target=0x241676  [0x241507: test %rax,%rax]
   +0xd29 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241639  [0x241526: test %rcx,%rcx]
   +0xd62 je    src=reg/arith  guarded=memory           dir=fwd  target=0x24233a  [0x24155f: test %rcx,%rcx]
   +0xd6e je    src=mem        guarded=memory           dir=fwd  target=0x241b0f  [0x241568: cmpq $0x0,0x40(%rsp)]
   +0xd84 ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x242353  [0x241580: cmp $0x40,%rcx]
   +0xd95 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x241620  [0x241592: test %rax,%rax]
   +0xda8 je    src=mem        guarded=memory           dir=fwd  target=0x241770  [0x2415a3: cmpq $0x0,0x50(%rax)]
   +0xdc8 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241764  [0x2415c5: test %rax,%rax]
   +0xdec je    src=reg/arith  guarded=call             dir=fwd  target=0x24173e  [0x2415e9: test %rax,%rax]
   +0xdf9 je    src=reg/arith  guarded=memory           dir=fwd  target=0x24173e  [0x2415f7: test %eax,%eax]
   +0xe15 jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x241580  [0x241612: test %rcx,%rcx]
   +0xe33 jne   src=reg/arith  guarded=memory           dir=back target=0x241552  [0x24162b: cmp %rcx,%r14]
   +0xe40 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x2418b6  [0x24163d: cmp %rax,%rbx]
   +0xec8 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241704  [0x2416c5: test %rdi,%rdi]
   +0xf02 jne   src=reg/arith  guarded=call+memory      dir=back target=0x2416e0  [0x2416ff: test %rdi,%rdi]
   +0xfdc je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241814  [0x2417d9: test %rdi,%rdi]
  +0x1012 jne   src=reg/arith  guarded=call+memory      dir=back target=0x2417f0  [0x24180f: test %rdi,%rdi]
  +0x103e je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x24185f  [0x24183b: test %rdi,%rdi]
  +0x105d jne   src=reg/arith  guarded=call+memory      dir=back target=0x241850  [0x24185a: test %rdi,%rdi]
  +0x10cc je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241a75  [0x2418c9: test %rax,%rax]
  +0x10d5 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241a87  [0x2418d2: test %rbx,%rbx]
  +0x10fe je    src=reg/arith  guarded=memory           dir=fwd  target=0x241a87  [0x2418fb: cmp %rbx,%r12]
  +0x1115 jae   src=mem        guarded=memory           dir=fwd  target=0x241925  [0x241910: cmp 0x58(%rsp),%r12]
  +0x1135 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241ae9  [0x241933: test %eax,%eax]
  +0x1145 jbe   src=mem        guarded=memory           dir=back target=0x2418f8  [0x241940: cmpq $0x1,(%rax,%r12,8)]
  +0x116a je    src=reg/arith  guarded=memory           dir=fwd  target=0x241ae9  [0x241968: test %eax,%eax]
  +0x117c je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x24233a  [0x241979: test %rcx,%rcx]
  +0x118c ja    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x242353  [0x241988: cmp $0x40,%rcx]
  +0x119d jne   src=reg/arith  guarded=memory           dir=back target=0x2418f8  [0x24199a: test %rax,%rax]
  +0x11b5 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241c92  [0x2419b2: test %rax,%rax]
  +0x11cb jne   src=mem        guarded=memory           dir=fwd  target=0x241add  [0x2419c8: cmp (%rsi),%r9]
  +0x11e0 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241a30  [0x2419de: test %edi,%edi]
  +0x11e9 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x2419f4  [0x2419e6: test %r8d,%r8d]
  +0x11ee jne   src=reg/arith  guarded=memory           dir=fwd  target=0x241add  [0x2419eb: cmp %r8d,%edi]
  +0x11f7 jne   src=mem        guarded=memory           dir=fwd  target=0x241add  [0x2419f4: cmp (%rdx),%r9]
  +0x1204 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241a0f  [0x241a01: test %r8d,%r8d]
  +0x1209 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x241add  [0x241a06: cmp %r8d,%edi]
  +0x1217 jne   src=mem        guarded=memory           dir=fwd  target=0x241add  [0x241a14: cmp (%rcx),%r9]
  +0x1224 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241a47  [0x241a21: test %r8d,%r8d]
  +0x1229 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241a47  [0x241a26: cmp %r8d,%edi]
  +0x1233 jne   src=mem        guarded=memory           dir=fwd  target=0x241add  [0x241a30: cmp (%rdx),%r9]
  +0x1241 jne   src=mem        guarded=call+memory      dir=fwd  target=0x241add  [0x241a3e: cmp (%rcx),%r9]
  +0x1255 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241ae9  [0x241a53: test %eax,%eax]
  +0x126a jne   src=reg/arith  guarded=arithmetic/control dir=back target=0x241988  [0x241a67: test %rcx,%rcx]
  +0x1299 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241ae9  [0x241a96: test %rax,%rax]
  +0x12bc je    src=reg/arith  guarded=memory           dir=fwd  target=0x241af8  [0x241aab: test %eax,%eax]
  +0x12cf jbe   src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241c9e  [0x241ac3: cmp $0x7fffffff,%r13]
  +0x1313 jae   src=reg/arith  guarded=memory           dir=fwd  target=0x242353  [0x241b0f: cmp $0x41,%rcx]
  +0x13b4 je    src=reg/arith  guarded=memory           dir=fwd  target=0x242322  [0x241bb0: cmp $0xffffffffffffffff,%rsi]
  +0x13d3 jb    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x24232e  [0x241bcf: sub $0x1,%rcx]
  +0x13dd jae   src=reg/arith  guarded=memory           dir=fwd  target=0x242347  [0x241bd9: cmp $0x41,%rdx]
  +0x13f6 jo    src=reg/arith  guarded=memory           dir=fwd  target=0x242360  [0x241bf3: mul %rdx]
  +0x1405 jne   src=mem        guarded=memory           dir=fwd  target=0x241c3b  [0x241c01: cmp %rax,0x28(%rcx)]
  +0x1430 jae   src=reg/arith  guarded=arithmetic/control dir=back target=0x240c78  [0x241c2d: add %r14,%r13]
  +0x14a1 je    src=reg/arith  guarded=memory           dir=fwd  target=0x24237b  [0x241c9e: test %r13,%r13]
  +0x14ca jle   src=mem        guarded=arithmetic/control dir=fwd  target=0x241e28  [0x241cb6: cmpl $0x1,0x58(%rsp)]
  +0x14d3 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x241cee  [0x241cd0: test %r12d,%r12d]
  +0x14e8 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241e3f  [0x241ce6: test %eax,%eax]
  +0x14ff je    src=mem        guarded=arithmetic/control dir=back target=0x241cb6  [0x241cf6: cmpq $0x0,0x90(%rsp)]
  +0x1526 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241e9e  [0x241d24: test %eax,%eax]
  +0x1537 je    src=mem        guarded=memory           dir=back target=0x241cb6  [0x241d2f: cmp %r15,0x90(%rsp)]
  +0x1546 jbe   src=mem        guarded=memory           dir=back target=0x241d2c  [0x241d42: cmp %rbp,(%rax,%r15,8)]
  +0x1559 je    src=reg/arith  guarded=arithmetic/control dir=back target=0x241d2c  [0x241d56: test %r14d,%r14d]
  +0x1563 je    src=reg/arith  guarded=arithmetic/control dir=fwd  target=0x241d90  [0x241d61: cmp %eax,%ebx]
  +0x1568 jne   src=reg/arith  guarded=memory           dir=fwd  target=0x241d87  [0x241d65: test %r12d,%r12d]
  +0x1581 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241e9e  [0x241d7f: test %eax,%eax]
  +0x15b3 je    src=reg/arith  guarded=memory           dir=back target=0x241d09  [0x241db0: test %r12d,%r12d]
  +0x15c9 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241e9e  [0x241dc7: test %eax,%eax]
  +0x15e4 je    src=reg/arith  guarded=call+memory      dir=back target=0x241d2c  [0x241de1: test %rax,%rax]
  +0x15f8 jne   src=reg/arith  guarded=call+memory      dir=back target=0x241d2c  [0x241df6: test %eax,%eax]
  +0x162b je    src=reg/arith  guarded=memory           dir=fwd  target=0x241e53  [0x241e28: test %r12d,%r12d]
  +0x1655 je    src=reg/arith  guarded=memory           dir=fwd  target=0x241e70  [0x241e53: test %ebx,%ebx]
  +0x166e je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x241e9e  [0x241e6c: test %eax,%eax]
  +0x16f4 jne   src=reg/arith  guarded=memory           dir=back target=0x240b24  [0x241eea: cmp $0x1,%rcx]
  +0x16fe jne   src=mem        guarded=memory           dir=back target=0x240b24  [0x241efa: cmpq $0x1,(%rax)]
  +0x170d je    src=mem        guarded=memory           dir=back target=0x240b24  [0x241f09: cmpl $0x0,0x28(%rax)]
  +0x171f je    src=reg/arith  guarded=memory           dir=back target=0x240b24  [0x241f1c: test %rsi,%rsi]
  +0x1731 je    src=reg/arith  guarded=memory           dir=back target=0x240b24  [0x241f2e: test %rax,%rax]
  +0x178b jne   src=reg/arith  guarded=memory           dir=back target=0x240b1e  [0x241f87: cmp $0x4,%rdx]
  +0x17be jne   src=reg/arith  guarded=memory           dir=back target=0x240b1e  [0x241fb8: cmp $0xffff,%ecx]
  +0x1818 jne   src=reg/arith  guarded=memory           dir=back target=0x240b1e  [0x242014: cmp $0x4,%rax]
  +0x184a jne   src=reg/arith  guarded=memory           dir=back target=0x240b1e  [0x242045: cmp $0xffff,%eax]
  +0x185c jne   src=mem        guarded=memory           dir=back target=0x240b24  [0x242050: cmpl $0x0,0x18(%r12)]
  +0x186b ja    src=reg/arith  guarded=memory           dir=back target=0x240b24  [0x242067: cmp $0x4,%rdx]
  +0x1938 je    src=reg/arith  guarded=call             dir=back target=0x240b1e  [0x242135: test $0x1,%cl]
  +0x1945 jne   src=reg/arith  guarded=call+memory      dir=back target=0x240b1e  [0x242143: test %al,%al]
  +0x19fb jne   src=reg/arith  guarded=call+memory      dir=fwd  target=0x2423bf  [0x2421f9: test %eax,%eax]
  +0x1a69 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x242384  [0x242267: test %al,%al]
  +0x1a87 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x242384  [0x242285: test %al,%al]
  +0x1aa5 je    src=reg/arith  guarded=call+memory      dir=fwd  target=0x242384  [0x2422a3: test %al,%al]
cmov:
   +0x65b cmova %rax,%r13 src=reg/arith
   +0x6a7 cmovne %rax,%rcx src=reg/arith
   +0x6d3 cmovne %rax,%rcx src=reg/arith
   +0x701 cmovne %rax,%rcx src=reg/arith
   +0x72e cmovne %rax,%rcx src=reg/arith
   +0x77a cmove %r15,%rax src=reg/arith
   +0x7a5 cmovne %rax,%rcx src=reg/arith
   +0x7d7 cmovne %rax,%rcx src=reg/arith
   +0x8dd cmove %r14,%rax src=reg/arith
   +0x901 cmove %r14,%rax src=reg/arith
   +0x94a cmove %r14,%rax src=reg/arith
   +0xa12 cmove %r14,%rax src=reg/arith
   +0xa37 cmove %r14,%rax src=reg/arith
   +0xa7a cmove %r14,%rax src=reg/arith
   +0xb94 cmovne %rax,%rcx src=reg/arith
   +0xc93 cmova %rax,%r13 src=reg/arith
   +0xcc6 cmovne %rax,%rcx src=reg/arith
   +0xe87 cmove %r14,%rax src=reg/arith
   +0xea9 cmove %r14,%rax src=reg/arith
   +0xeea cmove %r14,%rax src=reg/arith
   +0xf0e cmove %r14,%rax src=reg/arith
   +0xf30 cmove %r14,%rax src=reg/arith
   +0xf4f cmovne %rax,%rcx src=reg/arith
   +0xf9e cmove %r14,%rax src=reg/arith
   +0xfc2 cmove %r14,%rax src=reg/arith
   +0xffa cmove %r14,%rax src=reg/arith
  +0x101e cmove %r14,%rax src=reg/arith
  +0x1069 cmove %r14,%rax src=reg/arith
  +0x108d cmove %r14,%rax src=reg/arith
  +0x1343 cmovne %rax,%rcx src=reg/arith
  +0x1390 cmovne %rax,%rcx src=reg/arith
  +0x13c8 cmovae %rax,%rsi src=reg/arith
  +0x1473 cmovne %rax,%rcx src=reg/arith
setcc:
    +0xc0 setne %dl src=reg/arith
    +0xc6 sete %r9b src=reg/arith
   +0x1e0 setne %r10b src=reg/arith
   +0x1e8 setne %dil src=reg/arith
  +0x158b sete %al src=reg/arith
```

