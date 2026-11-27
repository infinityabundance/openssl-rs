
/work/court/tmp/pfp4-a/distribution/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

00000000001f10d0 <ossl_ec_group_do_inverse_ord>:
  1f10d0:	push   %rbp
  1f10d1:	push   %r15
  1f10d3:	push   %r14
  1f10d5:	push   %r13
  1f10d7:	push   %r12
  1f10d9:	push   %rbx
  1f10da:	sub    $0x18,%rsp
  1f10de:	mov    %rcx,%rbx
  1f10e1:	mov    (%rdi),%rax
  1f10e4:	mov    0x190(%rax),%rax
  1f10eb:	test   %rax,%rax
  1f10ee:	je     1f1103 <ossl_ec_group_do_inverse_ord+0x33>
  1f10f0:	mov    %rbx,%rcx
  1f10f3:	add    $0x18,%rsp
  1f10f7:	pop    %rbx
  1f10f8:	pop    %r12
  1f10fa:	pop    %r13
  1f10fc:	pop    %r14
  1f10fe:	pop    %r15
  1f1100:	pop    %rbp
  1f1101:	jmp    *%rax
  1f1103:	cmpq   $0x0,0x90(%rdi)
  1f110b:	je     1f11ef <ossl_ec_group_do_inverse_ord+0x11f>
  1f1111:	mov    %rdi,%rbp
  1f1114:	mov    %rsi,%r12
  1f1117:	mov    %rdx,%r15
  1f111a:	call   328230 <_RNvNtNtNtCsfBoMNNx3tZr_10openssl_rs2ec4p25610fixed_base17try_inverse_order>
  1f111f:	mov    %eax,%ecx
  1f1121:	mov    %edx,%eax
  1f1123:	test   $0x1,%cl
  1f1126:	jne    1f11f1 <ossl_ec_group_do_inverse_ord+0x121>
  1f112c:	test   %rbx,%rbx
  1f112f:	je     1f1200 <ossl_ec_group_do_inverse_ord+0x130>
  1f1135:	xor    %r14d,%r14d
  1f1138:	mov    %rbx,%rdi
  1f113b:	call   *0x6e13df(%rip)        # 8d2520 <BN_CTX_start@@OPENSSL_3.0.0+0x6658a0>
  1f1141:	mov    %rbx,%rdi
  1f1144:	call   *0x6e3306(%rip)        # 8d4450 <BN_CTX_get@@OPENSSL_3.0.0+0x667a60>
  1f114a:	test   %rax,%rax
  1f114d:	je     1f11c8 <ossl_ec_group_do_inverse_ord+0xf8>
  1f114f:	mov    %rax,%r13
  1f1152:	mov    $0x2,%esi
  1f1157:	mov    %rax,%rdi
  1f115a:	call   *0x6dfea8(%rip)        # 8d1008 <BN_set_word@@OPENSSL_3.0.0+0x4c60d8>
  1f1160:	test   %eax,%eax
  1f1162:	je     1f11c8 <ossl_ec_group_do_inverse_ord+0xf8>
  1f1164:	mov    0x10(%rbp),%rsi
  1f1168:	mov    %r13,%rdi
  1f116b:	mov    %r13,%rdx
  1f116e:	call   *0x6dfae4(%rip)        # 8d0c58 <BN_sub@@OPENSSL_3.0.0+0x74f4b8>
  1f1174:	test   %eax,%eax
  1f1176:	je     1f11c8 <ossl_ec_group_do_inverse_ord+0xf8>
  1f1178:	mov    0x10(%rbp),%rcx
  1f117c:	mov    0x90(%rbp),%r9
  1f1183:	mov    %r12,%rdi
  1f1186:	mov    %r15,%rsi
  1f1189:	mov    %r13,%rdx
  1f118c:	mov    %rbx,%r8
  1f118f:	call   *0x6e1de3(%rip)        # 8d2f78 <BN_mod_exp_mont_consttime@@OPENSSL_3.0.0+0x756ee8>
  1f1195:	mov    0x30(%rbx),%rcx
  1f1199:	test   %rcx,%rcx
  1f119c:	je     1f11b3 <ossl_ec_group_do_inverse_ord+0xe3>
  1f119e:	lea    -0x1(%rcx),%rdx
  1f11a2:	mov    %rdx,0x30(%rbx)
  1f11a6:	mov    0x28(%rbx),%rdx
  1f11aa:	mov    -0x8(%rdx,%rcx,8),%rcx
  1f11af:	mov    %rcx,0x18(%rbx)
  1f11b3:	xor    %ebx,%ebx
  1f11b5:	test   %eax,%eax
  1f11b7:	setne  %bl
  1f11ba:	mov    %r14,%rdi
  1f11bd:	call   *0x6dfe3d(%rip)        # 8d1000 <BN_CTX_free@@OPENSSL_3.0.0+0x6646c0>
  1f11c3:	mov    %rbx,%rax
  1f11c6:	jmp    1f11f1 <ossl_ec_group_do_inverse_ord+0x121>
  1f11c8:	mov    0x30(%rbx),%rax
  1f11cc:	test   %rax,%rax
  1f11cf:	je     1f11e6 <ossl_ec_group_do_inverse_ord+0x116>
  1f11d1:	lea    -0x1(%rax),%rcx
  1f11d5:	mov    %rcx,0x30(%rbx)
  1f11d9:	mov    0x28(%rbx),%rcx
  1f11dd:	mov    -0x8(%rcx,%rax,8),%rax
  1f11e2:	mov    %rax,0x18(%rbx)
  1f11e6:	mov    %r14,%rdi
  1f11e9:	call   *0x6dfe11(%rip)        # 8d1000 <BN_CTX_free@@OPENSSL_3.0.0+0x6646c0>
  1f11ef:	xor    %eax,%eax
  1f11f1:	add    $0x18,%rsp
  1f11f5:	pop    %rbx
  1f11f6:	pop    %r12
  1f11f8:	pop    %r13
  1f11fa:	pop    %r14
  1f11fc:	pop    %r15
  1f11fe:	pop    %rbp
  1f11ff:	ret
  1f1200:	mov    %rsp,%rdi
  1f1203:	mov    $0x8,%edx
  1f1208:	mov    $0x10,%ecx
  1f120d:	mov    $0x8,%r8d
  1f1213:	mov    $0x8,%r9d
  1f1219:	xor    %esi,%esi
  1f121b:	call   1646d0 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.12795805794241854212>
  1f1220:	cmpl   $0x1,(%rsp)
  1f1224:	je     1f11ef <ossl_ec_group_do_inverse_ord+0x11f>
  1f1226:	mov    0x8(%rsp),%r14
  1f122b:	call   *0x6e024f(%rip)        # 8d1480 <_DYNAMIC+0x1280>
  1f1231:	mov    $0x48,%edi
  1f1236:	mov    $0x8,%esi
  1f123b:	call   *0x6e054f(%rip)        # 8d1790 <_DYNAMIC+0x1590>
  1f1241:	test   %rax,%rax
  1f1244:	je     1f127f <ossl_ec_group_do_inverse_ord+0x1af>
  1f1246:	mov    %rax,%rbx
  1f1249:	movq   $0x10,(%rax)
  1f1250:	mov    %r14,0x8(%rax)
  1f1254:	xorps  %xmm0,%xmm0
  1f1257:	movups %xmm0,0x10(%rax)
  1f125b:	movq   $0x0,0x20(%rax)
  1f1263:	movq   $0x8,0x28(%rax)
  1f126b:	movups %xmm0,0x30(%rax)
  1f126f:	movq   $0x0,0x40(%rax)
  1f1277:	mov    %rax,%r14
  1f127a:	jmp    1f1138 <ossl_ec_group_do_inverse_ord+0x68>
  1f127f:	mov    $0x80,%esi
  1f1284:	mov    $0x8,%edx
  1f1289:	mov    %r14,%rdi
  1f128c:	call   *0x6e0536(%rip)        # 8d17c8 <_DYNAMIC+0x15c8>
  1f1292:	jmp    1f11ef <ossl_ec_group_do_inverse_ord+0x11f>
  1f1297:	call   *0x6e14db(%rip)        # 8d2778 <_DYNAMIC+0x2578>
