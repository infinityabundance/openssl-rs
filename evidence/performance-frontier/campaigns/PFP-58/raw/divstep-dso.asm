
artifacts/phase2/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .text:

000000000038a3d0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep>:
  38a3d0:	push   %rbp
  38a3d1:	push   %r15
  38a3d3:	push   %r14
  38a3d5:	push   %r13
  38a3d7:	push   %r12
  38a3d9:	push   %rbx
  38a3da:	sub    $0x1e8,%rsp
  38a3e1:	test   %r8,%r8
  38a3e4:	je     38a49d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcd>
  38a3ea:	mov    %r8,%rbx
  38a3ed:	mov    %rdx,%r12
  38a3f0:	movabs $0x3fffffffffffffc,%rdx
  38a3fa:	testb  $0x1,(%rcx)
  38a3fd:	sete   %al
  38a400:	add    $0x3,%rdx
  38a404:	cmp    %rdx,%r8
  38a407:	seta   %dl
  38a40a:	or     %al,%dl
  38a40c:	jne    38a49d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcd>
  38a412:	mov    %rbx,%r13
  38a415:	shl    $0x6,%r13
  38a419:	mov    $0xecb,%edx
  38a41e:	mov    %r13,%rax
  38a421:	mul    %rdx
  38a424:	jo     38a49d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcd>
  38a426:	cmp    $0xfffffffffffff789,%rax
  38a42c:	ja     38a49d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcd>
  38a42e:	mov    %rsi,0xb8(%rsp)
  38a436:	mov    %rcx,0x58(%rsp)
  38a43b:	mov    %rdi,0x88(%rsp)
  38a443:	add    $0x876,%rax
  38a449:	shr    $0x2,%rax
  38a44d:	movabs $0x4fba3d0a96bc1b69,%rcx
  38a457:	mul    %rcx
  38a45a:	mov    %rdx,%r15
  38a45d:	lea    (%rbx,%rbx,2),%rax
  38a461:	add    %rax,%rax
  38a464:	lea    0x4(%rax,%rbx,2),%rax
  38a469:	lea    0x4(%rax,%rbx,4),%r14
  38a46e:	lea    0x18(%rsp),%rdi
  38a473:	mov    $0x8,%edx
  38a478:	mov    $0x8,%r8d
  38a47e:	mov    $0x8,%r9d
  38a484:	xor    %esi,%esi
  38a486:	mov    %r14,%rcx
  38a489:	call   164eb0 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.5541607593376212649>
  38a48e:	cmpb   $0x0,0x18(%rsp)
  38a493:	je     38a4b9 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xe9>
  38a495:	mov    0x88(%rsp),%rdi
  38a49d:	movq   $0xffffffffffffffff,(%rdi)
  38a4a4:	mov    %rdi,%rax
  38a4a7:	add    $0x1e8,%rsp
  38a4ae:	pop    %rbx
  38a4af:	pop    %r12
  38a4b1:	pop    %r13
  38a4b3:	pop    %r14
  38a4b5:	pop    %r15
  38a4b7:	pop    %rbp
  38a4b8:	ret
  38a4b9:	mov    %r14,0xc8(%rsp)
  38a4c1:	shr    $0x7,%r15
  38a4c5:	mov    %r15,0x1d8(%rsp)
  38a4cd:	lea    0x1(%rbx),%rbp
  38a4d1:	lea    0x2(%rbx),%r14
  38a4d5:	mov    %r13,0x60(%rsp)
  38a4da:	mov    0x20(%rsp),%r13
  38a4df:	lea    (%rbx,%rbx,2),%r15
  38a4e3:	shl    $0x5,%r15
  38a4e7:	lea    0x38(%r15),%rdx
  38a4eb:	movq   $0x0,0x198(%rsp)
  38a4f7:	mov    %r13,%rdi
  38a4fa:	xor    %esi,%esi
  38a4fc:	call   *0x5543e6(%rip)        # 8de8e8 <memset@GLIBC_2.2.5>
  38a502:	movq   $0x0,0x38(%r13,%r15,1)
  38a50b:	lea    0x0(,%rbp,8),%rcx
  38a513:	add    %r13,%rcx
  38a516:	mov    %rcx,0x40(%rsp)
  38a51b:	lea    0x0(,%rbp,8),%rax
  38a523:	mov    %rax,0x80(%rsp)
  38a52b:	lea    (%rcx,%rbp,8),%rax
  38a52f:	mov    %rax,0xd0(%rsp)
  38a537:	lea    (%rax,%rbx,8),%rax
  38a53b:	mov    %rax,0xa0(%rsp)
  38a543:	lea    0x0(,%rbx,8),%rdx
  38a54b:	lea    (%rax,%rbx,8),%rax
  38a54f:	mov    %rax,0x128(%rsp)
  38a557:	lea    (%rax,%r14,8),%rax
  38a55b:	mov    %rax,0x78(%rsp)
  38a560:	lea    (%rax,%r14,8),%rax
  38a564:	mov    %rax,0x98(%rsp)
  38a56c:	mov    %r13,%r14
  38a56f:	lea    (%rax,%rbp,8),%r13
  38a573:	lea    0x0(%r13,%rbp,8),%rax
  38a578:	mov    %rax,0x50(%rsp)
  38a57d:	lea    (%rax,%rbx,8),%rbp
  38a581:	lea    0x0(%rbp,%rbx,8),%rax
  38a586:	mov    %rax,0x38(%rsp)
  38a58b:	mov    0x554f26(%rip),%r15        # 8df4b8 <memcpy@GLIBC_2.14>
  38a592:	mov    %r14,%rdi
  38a595:	mov    0x58(%rsp),%rsi
  38a59a:	call   *%r15
  38a59d:	mov    %r12,%rdx
  38a5a0:	cmp    %r12,%rbx
  38a5a3:	cmovb  %rbx,%rdx
  38a5a7:	shl    $0x3,%rdx
  38a5ab:	mov    0x40(%rsp),%r12
  38a5b0:	mov    %r12,%rdi
  38a5b3:	mov    0xb8(%rsp),%rsi
  38a5bb:	call   *%r15
  38a5be:	mov    %rbp,0x150(%rsp)
  38a5c6:	mov    0xd0(%rsp),%r9
  38a5ce:	lea    -0x8(,%rbx,8),%r15
  38a5d6:	shr    $0x3,%r15
  38a5da:	cmp    %r15,%rbx
  38a5dd:	mov    %r15,%r11
  38a5e0:	cmovb  %rbx,%r11
  38a5e4:	lea    (%rbx,%rbx,2),%r10
  38a5e8:	shl    $0x4,%r10
  38a5ec:	lea    0x10(%rsp),%rcx
  38a5f1:	inc    %r15
  38a5f4:	movabs $0x7fffffffffffffe,%rax
  38a5fe:	lea    0x1(%rbx),%rdi
  38a602:	mov    %rdi,%rsi
  38a605:	and    %rax,%rsi
  38a608:	mov    %rsi,0x130(%rsp)
  38a610:	mov    %edi,%esi
  38a612:	and    $0x3,%esi
  38a615:	mov    %rsi,0xf0(%rsp)
  38a61d:	cmp    %rcx,%r13
  38a620:	setb   %sil
  38a624:	lea    0x8(%rsp),%rdi
  38a629:	mov    0x50(%rsp),%rcx
  38a62e:	cmp    %rcx,%rdi
  38a631:	setb   %dil
  38a635:	and    %sil,%dil
  38a638:	mov    %dil,0x17(%rsp)
  38a63d:	mov    0x98(%rsp),%r8
  38a645:	cmp    %r9,%r8
  38a648:	setb   %sil
  38a64c:	cmp    %r13,%r12
  38a64f:	setb   %dil
  38a653:	and    %sil,%dil
  38a656:	cmp    %r12,%r8
  38a659:	mov    %r8,%r12
  38a65c:	setb   %sil
  38a660:	cmp    %r13,%r14
  38a663:	setb   %r8b
  38a667:	and    %sil,%r8b
  38a66a:	or     %dil,%r8b
  38a66d:	lea    0x10(%rsp),%rsi
  38a672:	cmp    %rsi,%r12
  38a675:	setb   %sil
  38a679:	mov    %r13,0x120(%rsp)
  38a681:	lea    0x8(%rsp),%rdi
  38a686:	cmp    %r13,%rdi
  38a689:	setb   %dil
  38a68d:	and    %sil,%dil
  38a690:	or     %r8b,%dil
  38a693:	mov    %dil,0x16(%rsp)
  38a698:	add    $0xfffffffffffffffe,%rax
  38a69c:	lea    0x1(%rbx),%rsi
  38a6a0:	and    %rsi,%rax
  38a6a3:	mov    %rax,0xf8(%rsp)
  38a6ab:	mov    %rcx,%r8
  38a6ae:	cmp    0xa0(%rsp),%rcx
  38a6b6:	setb   %sil
  38a6ba:	cmp    %rbp,%r9
  38a6bd:	setb   %dil
  38a6c1:	and    %sil,%dil
  38a6c4:	lea    0x38(%rsp),%rax
  38a6c9:	cmp    %rax,%rcx
  38a6cc:	setb   %dl
  38a6cf:	lea    0x30(%rsp),%rax
  38a6d4:	cmp    %rbp,%rax
  38a6d7:	mov    %rbp,%rcx
  38a6da:	setb   %al
  38a6dd:	and    %dl,%al
  38a6df:	or     %dil,%al
  38a6e2:	mov    %al,0x15(%rsp)
  38a6e6:	mov    %rbx,%rax
  38a6e9:	movabs $0x3fffffffffffffc,%r12
  38a6f3:	and    %r12,%rax
  38a6f6:	mov    %rax,0xb0(%rsp)
  38a6fe:	mov    %ebx,%edi
  38a700:	and    $0x3,%edi
  38a703:	mov    %r15,0x90(%rsp)
  38a70b:	and    $0xfffffffffffffffe,%r15
  38a70f:	mov    %r15,0xb8(%rsp)
  38a717:	lea    0x20(%rsp),%rsi
  38a71c:	mov    0x38(%rsp),%rbp
  38a721:	cmp    %rsi,%rbp
  38a724:	setb   %dl
  38a727:	lea    0x18(%rsp),%r15
  38a72c:	lea    0x0(,%rbx,8),%r13
  38a734:	add    %rbp,%r13
  38a737:	cmp    %r13,%r15
  38a73a:	setb   %al
  38a73d:	and    %dl,%al
  38a73f:	mov    %al,0x14(%rsp)
  38a743:	lea    0x10(%rsp),%rax
  38a748:	cmp    %rax,%rcx
  38a74b:	setb   %cl
  38a74e:	lea    0x8(%rsp),%rax
  38a753:	cmp    %rbp,%rax
  38a756:	setb   %al
  38a759:	and    %cl,%al
  38a75b:	mov    %al,0x13(%rsp)
  38a75f:	lea    (%r14,%r10,1),%rax
  38a763:	add    $0x20,%rax
  38a767:	add    $0x2,%r12
  38a76b:	and    %rbx,%r12
  38a76e:	mov    %r12,0xe8(%rsp)
  38a776:	mov    %rax,0x108(%rsp)
  38a77e:	cmp    %rax,%rbp
  38a781:	setb   %al
  38a784:	cmp    %r13,0x78(%rsp)
  38a789:	setb   %cl
  38a78c:	and    %al,%cl
  38a78e:	cmp    %rsi,%rbp
  38a791:	setb   %al
  38a794:	cmp    %r13,%r15
  38a797:	setb   %dl
  38a79a:	and    %al,%dl
  38a79c:	or     %cl,%dl
  38a79e:	mov    %dl,0x12(%rsp)
  38a7a2:	mov    0x60(%rsp),%r12
  38a7a7:	lea    (%r14,%r12,1),%rax
  38a7ab:	lea    (%rax,%r11,8),%rax
  38a7af:	add    $0x48,%rax
  38a7b3:	cmp    %rsi,%r8
  38a7b6:	setb   %cl
  38a7b9:	cmp    %rax,%r15
  38a7bc:	setb   %al
  38a7bf:	and    %cl,%al
  38a7c1:	mov    %al,0x11(%rsp)
  38a7c5:	lea    0x1(%r11),%rax
  38a7c9:	mov    %rax,0x1a8(%rsp)
  38a7d1:	and    $0x3,%eax
  38a7d4:	mov    $0x4,%ecx
  38a7d9:	cmove  %rcx,%rax
  38a7dd:	movq   $0x1,(%r9,%rbx,8)
  38a7e5:	neg    %rax
  38a7e8:	mov    %r11,0x180(%rsp)
  38a7f0:	lea    (%r11,%rax,1),%rdx
  38a7f4:	inc    %rdx
  38a7f7:	mov    %rbx,%r11
  38a7fa:	shl    $0x5,%r11
  38a7fe:	movabs $0x3ffffffffffffff0,%rax
  38a808:	mov    0x80(%rsp),%rcx
  38a810:	and    %rcx,%rax
  38a813:	mov    %rax,0x158(%rsp)
  38a81b:	imul   $0x38,%rbx,%rax
  38a81f:	add    %r14,%rax
  38a822:	add    $0x40,%rax
  38a826:	mov    %rax,0x178(%rsp)
  38a82e:	movabs $0x3fffffffffffffe0,%rax
  38a838:	and    %rcx,%rax
  38a83b:	mov    %rax,0x1c8(%rsp)
  38a843:	movabs $0x1fffffffffffffe0,%rax
  38a84d:	lea    0x0(,%rbx,8),%r15
  38a855:	and    %r15,%rax
  38a858:	mov    %rax,0xa8(%rsp)
  38a860:	mov    %rbx,%rax
  38a863:	shl    $0x4,%rax
  38a867:	add    %r14,%rax
  38a86a:	add    $0x20,%rax
  38a86e:	mov    %rax,0x48(%rsp)
  38a873:	lea    0x50(%r14,%r12,1),%rax
  38a878:	mov    %rax,0x118(%rsp)
  38a880:	lea    (%rbx,%rbx,2),%rax
  38a884:	lea    (%r14,%rax,8),%rax
  38a888:	add    $0x18,%rax
  38a88c:	mov    %rax,0x60(%rsp)
  38a891:	lea    (%rbx,%rbx,4),%rax
  38a895:	shl    $0x4,%rax
  38a899:	lea    (%rax,%r14,1),%rbp
  38a89d:	add    $0x48,%rbp
  38a8a1:	lea    0x50(%rax,%r14,1),%r12
  38a8a6:	lea    (%rbx,%rbx,8),%rax
  38a8aa:	lea    0x50(%r14,%rax,8),%rcx
  38a8af:	mov    %rcx,0xd8(%rsp)
  38a8b7:	lea    (%r14,%rax,8),%rax
  38a8bb:	add    $0x48,%rax
  38a8bf:	mov    %rax,0x110(%rsp)
  38a8c7:	mov    %rdi,0x188(%rsp)
  38a8cf:	neg    %rdi
  38a8d2:	mov    %rdi,0x160(%rsp)
  38a8da:	mov    0x40(%rsp),%rsi
  38a8df:	mov    %r13,0x68(%rsp)
  38a8e4:	lea    0x0(,%rbx,8),%rax
  38a8ec:	add    %r13,%rax
  38a8ef:	mov    %rax,0x148(%rsp)
  38a8f7:	mov    %rdx,0x1c0(%rsp)
  38a8ff:	lea    (%r8,%rdx,8),%rax
  38a903:	mov    %rax,0x1b8(%rsp)
  38a90b:	mov    %r15,0x1a0(%rsp)
  38a913:	lea    (%r15,%r15,4),%rax
  38a917:	lea    0x30(%r14,%r11,1),%rcx
  38a91c:	mov    %rcx,0x170(%rsp)
  38a924:	lea    0x18(%r14,%r11,1),%rcx
  38a929:	mov    %rcx,0x100(%rsp)
  38a931:	lea    0x40(%r14,%rax,1),%r13
  38a936:	mov    %rax,0x190(%rsp)
  38a93e:	lea    0x28(%r14,%rax,1),%rax
  38a943:	mov    %rax,0x138(%rsp)
  38a94b:	lea    (%r14,%rbx,8),%rax
  38a94f:	add    $0x18,%rax
  38a953:	mov    %rax,0x168(%rsp)
  38a95b:	imul   $0x58,%rbx,%rax
  38a95f:	mov    %rax,0x1b0(%rsp)
  38a967:	add    %r14,%rax
  38a96a:	add    $0x50,%rax
  38a96e:	mov    %rax,0xe0(%rsp)
  38a976:	lea    (%r14,%r11,1),%rax
  38a97a:	mov    %rax,0x1e0(%rsp)
  38a982:	mov    $0x1,%eax
  38a987:	mov    %rax,0x140(%rsp)
  38a98f:	mov    %r14,0x70(%rsp)
  38a994:	mov    %r11,0x1d0(%rsp)
  38a99c:	nopl   0x0(%rax)
  38a9a0:	mov    (%rsi),%rax
  38a9a3:	and    $0x1,%eax
  38a9a6:	neg    %rax
  38a9a9:	mov    %rax,0x30(%rsp)
  38a9ae:	lea    0x30(%rsp),%rax
  38a9b3:	mov    0x140(%rsp),%rdx
  38a9bb:	mov    %rdx,%rax
  38a9be:	shr    $0x3f,%rax
  38a9c2:	mov    %rax,0xc0(%rsp)
  38a9ca:	lea    0xc0(%rsp),%rax
  38a9d2:	mov    0xc0(%rsp),%rax
  38a9da:	xor    %ecx,%ecx
  38a9dc:	test   %rdx,%rdx
  38a9df:	setne  %cl
  38a9e2:	mov    %rcx,0x18(%rsp)
  38a9e7:	lea    0x18(%rsp),%rcx
  38a9ec:	xor    %ecx,%ecx
  38a9ee:	sub    0x18(%rsp),%rcx
  38a9f3:	dec    %rax
  38a9f6:	and    %rcx,%rax
  38a9f9:	and    0x30(%rsp),%rax
  38a9fe:	mov    %rax,0x8(%rsp)
  38aa03:	lea    0x8(%rsp),%rax
  38aa08:	mov    -0x8(%r9),%rax
  38aa0c:	mov    -0x8(%rsi),%rcx
  38aa10:	mov    0x130(%rsp),%rsi
  38aa18:	mov    %r14,%rdx
  38aa1b:	xor    %edi,%edi
  38aa1d:	mov    0x80(%rsp),%r9
  38aa25:	data16 cs nopw 0x0(%rax,%rax,1)
  38aa30:	mov    (%rdx,%r9,1),%r8
  38aa34:	sub    (%rdx),%r8
  38aa37:	setb   %r9b
  38aa3b:	sub    %rdi,%r8
  38aa3e:	setb   %dil
  38aa42:	mov    %r8,0x10(%rdx,%r11,1)
  38aa47:	or     %r9b,%dil
  38aa4a:	mov    0x80(%rsp),%r9
  38aa52:	mov    0x8(%rdx,%r9,1),%r8
  38aa57:	add    $0xff,%dil
  38aa5b:	sbb    0x8(%rdx),%r8
  38aa5f:	mov    %r8,0x18(%rdx,%r11,1)
  38aa64:	setb   %r8b
  38aa68:	movzbl %r8b,%edi
  38aa6c:	add    $0x10,%rdx
  38aa70:	add    $0xfffffffffffffffe,%rsi
  38aa74:	jne    38aa30 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x660>
  38aa76:	lea    0x1(%rbx),%r10
  38aa7a:	test   $0x1,%r10b
  38aa7e:	mov    0x128(%rsp),%r15
  38aa86:	je     38aaaa <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x6da>
  38aa88:	mov    (%rdx,%r9,1),%rsi
  38aa8c:	sub    (%rdx),%rsi
  38aa8f:	setb   %r9b
  38aa93:	sub    %rdi,%rsi
  38aa96:	setb   %r8b
  38aa9a:	mov    %rsi,0x10(%rdx,%r11,1)
  38aa9f:	or     %r9b,%r8b
  38aaa2:	mov    0x80(%rsp),%r9
  38aaaa:	shr    $0x3f,%rcx
  38aaae:	sar    $0x3f,%rax
  38aab2:	add    %rcx,%rax
  38aab5:	movzbl %r8b,%ecx
  38aab9:	sub    %rcx,%rax
  38aabc:	mov    %rax,0x8(%r15,%rbx,8)
  38aac1:	mov    0x30(%rsp),%rax
  38aac6:	mov    0x130(%rsp),%rsi
  38aace:	mov    %r14,%rdx
  38aad1:	xor    %ecx,%ecx
  38aad3:	mov    0x190(%rsp),%r10
  38aadb:	nopl   0x0(%rax,%rax,1)
  38aae0:	mov    (%rdx),%rdi
  38aae3:	and    %rax,%rdi
  38aae6:	add    (%rdx,%r9,1),%rdi
  38aaea:	setb   %r8b
  38aaee:	add    %rcx,%rdi
  38aaf1:	setb   %cl
  38aaf4:	mov    %rdi,0x20(%rdx,%r10,1)
  38aaf9:	or     %r8b,%cl
  38aafc:	mov    0x8(%rdx),%rdi
  38ab00:	and    %rax,%rdi
  38ab03:	add    $0xff,%cl
  38ab06:	adc    0x8(%rdx,%r9,1),%rdi
  38ab0b:	mov    %rdi,0x28(%rdx,%r10,1)
  38ab10:	setb   %cl
  38ab13:	movzbl %cl,%ecx
  38ab16:	add    $0x10,%rdx
  38ab1a:	add    $0xfffffffffffffffe,%rsi
  38ab1e:	jne    38aae0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x710>
  38ab20:	lea    0x1(%rbx),%rsi
  38ab24:	test   $0x1,%sil
  38ab28:	mov    0x98(%rsp),%rsi
  38ab30:	je     38ab59 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x789>
  38ab32:	mov    (%rdx),%r8
  38ab35:	and    %rax,%r8
  38ab38:	add    (%rdx,%r9,1),%r8
  38ab3c:	setb   %dil
  38ab40:	add    %rcx,%r8
  38ab43:	setb   %cl
  38ab46:	mov    0x190(%rsp),%r10
  38ab4e:	mov    %r8,0x20(%rdx,%r10,1)
  38ab53:	or     %dil,%cl
  38ab56:	movzbl %cl,%ecx
  38ab59:	mov    0x78(%rsp),%r8
  38ab5e:	mov    0x170(%rsp),%r10
  38ab66:	mov    0x40(%rsp),%rdi
  38ab6b:	mov    (%rdi,%rbx,8),%rdx
  38ab6f:	sar    $0x3f,%rdx
  38ab73:	mov    -0x8(%rdi),%rdi
  38ab77:	sar    $0x3f,%rdi
  38ab7b:	and    %rax,%rdi
  38ab7e:	add    %rdx,%rdi
  38ab81:	add    %rcx,%rdi
  38ab84:	mov    %rdi,0x8(%r8,%rbx,8)
  38ab89:	mov    (%r15),%rax
  38ab8c:	xor    %ecx,%ecx
  38ab8e:	cmp    $0x3,%rbx
  38ab92:	jae    38abb0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x7e0>
  38ab94:	mov    0xf0(%rsp),%r11
  38ab9c:	mov    0x100(%rsp),%r10
  38aba4:	jmp    38ac19 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x849>
  38aba6:	cs nopw 0x0(%rax,%rax,1)
  38abb0:	mov    0xf8(%rsp),%r11
  38abb8:	nopl   0x0(%rax,%rax,1)
  38abc0:	mov    -0x18(%r10,%rcx,8),%rdx
  38abc5:	shrd   $0x1,%rdx,%rax
  38abca:	mov    -0x10(%r10,%rcx,8),%rdi
  38abcf:	mov    %rax,-0x20(%r10,%rcx,8)
  38abd4:	shrd   $0x1,%rdi,%rdx
  38abd9:	mov    %rdx,-0x18(%r10,%rcx,8)
  38abde:	mov    -0x8(%r10,%rcx,8),%rdx
  38abe3:	shrd   $0x1,%rdx,%rdi
  38abe8:	mov    %rdi,-0x10(%r10,%rcx,8)
  38abed:	mov    (%r10,%rcx,8),%rax
  38abf1:	shrd   $0x1,%rax,%rdx
  38abf6:	mov    %rdx,-0x8(%r10,%rcx,8)
  38abfb:	add    $0x4,%rcx
  38abff:	cmp    %rcx,%r11
  38ac02:	jne    38abc0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x7f0>
  38ac04:	mov    0xf0(%rsp),%r11
  38ac0c:	test   %r11,%r11
  38ac0f:	mov    0x100(%rsp),%r10
  38ac17:	je     38ac39 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x869>
  38ac19:	lea    (%r10,%rcx,8),%rcx
  38ac1d:	xor    %edx,%edx
  38ac1f:	nop
  38ac20:	mov    (%rcx,%rdx,8),%rdi
  38ac24:	shrd   $0x1,%rdi,%rax
  38ac29:	mov    %rax,-0x8(%rcx,%rdx,8)
  38ac2e:	inc    %rdx
  38ac31:	mov    %rdi,%rax
  38ac34:	cmp    %rdx,%r11
  38ac37:	jne    38ac20 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x850>
  38ac39:	sarq   $1,-0x8(%r8)
  38ac3d:	mov    (%r8),%rax
  38ac40:	xor    %ecx,%ecx
  38ac42:	cmp    $0x3,%rbx
  38ac46:	jb     38aca6 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x8d6>
  38ac48:	mov    0xf8(%rsp),%r11
  38ac50:	mov    -0x18(%r13,%rcx,8),%rdx
  38ac55:	shrd   $0x1,%rdx,%rax
  38ac5a:	mov    -0x10(%r13,%rcx,8),%rdi
  38ac5f:	mov    %rax,-0x20(%r13,%rcx,8)
  38ac64:	shrd   $0x1,%rdi,%rdx
  38ac69:	mov    %rdx,-0x18(%r13,%rcx,8)
  38ac6e:	mov    -0x8(%r13,%rcx,8),%rdx
  38ac73:	shrd   $0x1,%rdx,%rdi
  38ac78:	mov    %rdi,-0x10(%r13,%rcx,8)
  38ac7d:	mov    0x0(%r13,%rcx,8),%rax
  38ac82:	shrd   $0x1,%rax,%rdx
  38ac87:	mov    %rdx,-0x8(%r13,%rcx,8)
  38ac8c:	add    $0x4,%rcx
  38ac90:	cmp    %rcx,%r11
  38ac93:	jne    38ac50 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x880>
  38ac95:	lea    0x1(%rbx),%rdx
  38ac99:	test   $0x3,%dl
  38ac9c:	mov    0xf0(%rsp),%r11
  38aca4:	je     38acd9 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x909>
  38aca6:	mov    0x138(%rsp),%rdx
  38acae:	lea    (%rdx,%rcx,8),%rcx
  38acb2:	xor    %edx,%edx
  38acb4:	data16 data16 cs nopw 0x0(%rax,%rax,1)
  38acc0:	mov    (%rcx,%rdx,8),%rdi
  38acc4:	shrd   $0x1,%rdi,%rax
  38acc9:	mov    %rax,-0x8(%rcx,%rdx,8)
  38acce:	inc    %rdx
  38acd1:	mov    %rdi,%rax
  38acd4:	cmp    %rdx,%r11
  38acd7:	jne    38acc0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x8f0>
  38acd9:	sarq   $1,-0x8(%rsi)
  38acdd:	cmpb   $0x0,0x17(%rsp)
  38ace2:	je     38acf0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x920>
  38ace4:	xor    %ecx,%ecx
  38ace6:	mov    0x178(%rsp),%r11
  38acee:	jmp    38ad6e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x99e>
  38acf0:	movq   0x8(%rsp),%xmm0
  38acf6:	pshufd $0x44,%xmm0,%xmm0
  38acfb:	movdqa %xmm0,%xmm1
  38acff:	pcmpeqd %xmm2,%xmm2
  38ad03:	pxor   %xmm2,%xmm1
  38ad07:	xor    %eax,%eax
  38ad09:	mov    0x120(%rsp),%rcx
  38ad11:	mov    0x158(%rsp),%rdx
  38ad19:	mov    0x178(%rsp),%r11
  38ad21:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38ad30:	movdqu (%r15,%rax,1),%xmm2
  38ad36:	movdqu (%r8,%rax,1),%xmm3
  38ad3c:	pand   %xmm1,%xmm3
  38ad40:	pand   %xmm0,%xmm2
  38ad44:	por    %xmm3,%xmm2
  38ad48:	movdqu %xmm2,(%rcx,%rax,1)
  38ad4d:	add    $0x10,%rax
  38ad51:	cmp    %rax,%rdx
  38ad54:	jne    38ad30 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x960>
  38ad56:	mov    0x130(%rsp),%rax
  38ad5e:	mov    %rax,%rcx
  38ad61:	lea    0x1(%rbx),%rdx
  38ad65:	cmp    %rax,%rdx
  38ad68:	je     38adea <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xa1a>
  38ad6e:	mov    %rcx,%rax
  38ad71:	test   $0x1,%bl
  38ad74:	jne    38ad9c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x9cc>
  38ad76:	mov    %rcx,%rax
  38ad79:	or     $0x1,%rax
  38ad7d:	mov    (%r8,%rcx,8),%rdx
  38ad81:	mov    (%r15,%rcx,8),%rdi
  38ad85:	xor    %rdx,%rdi
  38ad88:	and    0x8(%rsp),%rdi
  38ad8d:	xor    %rdx,%rdi
  38ad90:	mov    0x120(%rsp),%rdx
  38ad98:	mov    %rdi,(%rdx,%rcx,8)
  38ad9c:	cmp    %rcx,%rbx
  38ad9f:	mov    0x138(%rsp),%rdi
  38ada7:	lea    0x1(%rbx),%r8
  38adab:	je     38adea <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xa1a>
  38adad:	nopl   (%rax)
  38adb0:	mov    -0x8(%rdi,%rax,8),%rcx
  38adb5:	mov    -0x8(%r10,%rax,8),%rdx
  38adba:	xor    %rcx,%rdx
  38adbd:	and    0x8(%rsp),%rdx
  38adc2:	xor    %rcx,%rdx
  38adc5:	mov    %rdx,-0x8(%r11,%rax,8)
  38adca:	mov    (%rdi,%rax,8),%rcx
  38adce:	mov    (%r10,%rax,8),%rdx
  38add2:	xor    %rcx,%rdx
  38add5:	and    0x8(%rsp),%rdx
  38adda:	xor    %rcx,%rdx
  38addd:	mov    %rdx,(%r11,%rax,8)
  38ade1:	add    $0x2,%rax
  38ade5:	cmp    %rax,%r8
  38ade8:	jne    38adb0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x9e0>
  38adea:	cmp    $0x5,%rbx
  38adee:	setb   %al
  38adf1:	or     0x16(%rsp),%al
  38adf5:	test   $0x1,%al
  38adf7:	je     38ae20 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xa50>
  38adf9:	xor    %ecx,%ecx
  38adfb:	mov    0x108(%rsp),%r8
  38ae03:	mov    0x168(%rsp),%r10
  38ae0b:	lea    0x1(%rbx),%r11
  38ae0f:	jmp    38aeb1 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xae1>
  38ae14:	data16 data16 cs nopw 0x0(%rax,%rax,1)
  38ae20:	movq   0x8(%rsp),%xmm0
  38ae26:	pshufd $0x44,%xmm0,%xmm0
  38ae2b:	movdqa %xmm0,%xmm1
  38ae2f:	pcmpeqd %xmm2,%xmm2
  38ae33:	pxor   %xmm2,%xmm1
  38ae37:	xor    %eax,%eax
  38ae39:	mov    0xf8(%rsp),%rdx
  38ae41:	mov    0x108(%rsp),%r8
  38ae49:	mov    0x1c8(%rsp),%rcx
  38ae51:	mov    0x168(%rsp),%r10
  38ae59:	lea    0x1(%rbx),%r11
  38ae5d:	nopl   (%rax)
  38ae60:	movdqu -0x10(%r10,%rax,1),%xmm2
  38ae67:	movdqu (%r10,%rax,1),%xmm3
  38ae6d:	movdqu (%r14,%rax,1),%xmm4
  38ae73:	movdqu 0x10(%r14,%rax,1),%xmm5
  38ae7a:	pand   %xmm0,%xmm2
  38ae7e:	pand   %xmm0,%xmm3
  38ae82:	pand   %xmm1,%xmm4
  38ae86:	por    %xmm2,%xmm4
  38ae8a:	pand   %xmm1,%xmm5
  38ae8e:	por    %xmm3,%xmm5
  38ae92:	movdqu %xmm4,0x10(%r8,%rax,1)
  38ae99:	movdqu %xmm5,0x20(%r8,%rax,1)
  38aea0:	add    $0x20,%rax
  38aea4:	cmp    %rax,%rcx
  38aea7:	jne    38ae60 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xa90>
  38aea9:	mov    %rdx,%rcx
  38aeac:	cmp    %rdx,%r11
  38aeaf:	je     38af2c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xb5c>
  38aeb1:	mov    %rcx,%rax
  38aeb4:	test   $0x1,%bl
  38aeb7:	jne    38aedc <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xb0c>
  38aeb9:	mov    %rcx,%rax
  38aebc:	or     $0x1,%rax
  38aec0:	mov    (%r14,%rcx,8),%rdx
  38aec4:	mov    0x40(%rsp),%rdi
  38aec9:	mov    (%rdi,%rcx,8),%rdi
  38aecd:	xor    %rdx,%rdi
  38aed0:	and    0x8(%rsp),%rdi
  38aed5:	xor    %rdx,%rdi
  38aed8:	mov    %rdi,(%rsi,%rcx,8)
  38aedc:	cmp    %rcx,%rbx
  38aedf:	je     38af2c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xb5c>
  38aee1:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38aef0:	mov    (%r14,%rax,8),%rcx
  38aef4:	mov    -0x10(%r10,%rax,8),%rdx
  38aef9:	xor    %rcx,%rdx
  38aefc:	and    0x8(%rsp),%rdx
  38af01:	xor    %rcx,%rdx
  38af04:	mov    %rdx,0x10(%r8,%rax,8)
  38af09:	mov    0x8(%r14,%rax,8),%rcx
  38af0e:	mov    -0x8(%r10,%rax,8),%rdx
  38af13:	xor    %rcx,%rdx
  38af16:	and    0x8(%rsp),%rdx
  38af1b:	xor    %rcx,%rdx
  38af1e:	mov    %rdx,0x18(%r8,%rax,8)
  38af23:	add    $0x2,%rax
  38af27:	cmp    %rax,%r11
  38af2a:	jne    38aef0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xb20>
  38af2c:	cmp    $0x6,%rbx
  38af30:	mov    %r14,%rdi
  38af33:	setb   %r14b
  38af37:	mov    %r9,%rdx
  38af3a:	mov    0x554577(%rip),%r15        # 8df4b8 <memcpy@GLIBC_2.14>
  38af41:	call   *%r15
  38af44:	mov    0x40(%rsp),%rdi
  38af49:	mov    0x120(%rsp),%rsi
  38af51:	mov    0x80(%rsp),%rdx
  38af59:	call   *%r15
  38af5c:	mov    0x8(%rsp),%rax
  38af61:	or     0x15(%rsp),%r14b
  38af66:	test   $0x1,%r14b
  38af6a:	je     38afa0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xbd0>
  38af6c:	xor    %edx,%edx
  38af6e:	mov    0x70(%rsp),%r14
  38af73:	lea    0x0(,%rbx,8),%r11
  38af7b:	lea    0x1(%rbx),%rcx
  38af7f:	mov    0x40(%rsp),%rsi
  38af84:	lea    (%rsi,%rcx,8),%r9
  38af88:	mov    0x50(%rsp),%r8
  38af8d:	lea    (%r8,%rbx,8),%r10
  38af91:	mov    0xa0(%rsp),%r15
  38af99:	jmp    38b030 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xc60>
  38af9e:	xchg   %ax,%ax
  38afa0:	movq   0x30(%rsp),%xmm0
  38afa6:	pshufd $0x44,%xmm0,%xmm0
  38afab:	xor    %ecx,%ecx
  38afad:	lea    0x0(,%rbx,8),%r11
  38afb5:	lea    0x1(%rbx),%rdx
  38afb9:	mov    0x40(%rsp),%rsi
  38afbe:	lea    (%rsi,%rdx,8),%r9
  38afc2:	mov    0x50(%rsp),%r8
  38afc7:	lea    (%r8,%rbx,8),%r10
  38afcb:	mov    0x48(%rsp),%rdx
  38afd0:	mov    0xa0(%rsp),%r15
  38afd8:	mov    0xa8(%rsp),%rsi
  38afe0:	mov    0x118(%rsp),%rdi
  38afe8:	nopl   0x0(%rax,%rax,1)
  38aff0:	movdqu -0x10(%rdx,%rcx,1),%xmm1
  38aff6:	movdqu (%rdx,%rcx,1),%xmm2
  38affb:	pand   %xmm0,%xmm1
  38afff:	pand   %xmm0,%xmm2
  38b003:	movdqu %xmm1,-0x10(%rdi,%rcx,1)
  38b009:	movdqu %xmm2,(%rdi,%rcx,1)
  38b00e:	add    $0x20,%rcx
  38b012:	cmp    %rcx,%rsi
  38b015:	jne    38aff0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xc20>
  38b017:	mov    0xb0(%rsp),%rcx
  38b01f:	mov    %rcx,%rdx
  38b022:	cmp    %rcx,%rbx
  38b025:	mov    0x70(%rsp),%r14
  38b02a:	je     38b0c3 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcf3>
  38b030:	mov    %rdx,%rcx
  38b033:	cmpq   $0x0,0x188(%rsp)
  38b03c:	je     38b065 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xc95>
  38b03e:	mov    0x188(%rsp),%rsi
  38b046:	mov    %rdx,%rcx
  38b049:	nopl   0x0(%rax)
  38b050:	mov    0x30(%rsp),%rdi
  38b055:	and    (%r9,%rcx,8),%rdi
  38b059:	mov    %rdi,(%r8,%rcx,8)
  38b05d:	inc    %rcx
  38b060:	dec    %rsi
  38b063:	jne    38b050 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xc80>
  38b065:	lea    -0x1(%rbx),%rsi
  38b069:	sub    %rdx,%rsi
  38b06c:	cmp    $0x3,%rsi
  38b070:	mov    0x48(%rsp),%rsi
  38b075:	mov    0x118(%rsp),%rdi
  38b07d:	jb     38b0c3 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcf3>
  38b07f:	nop
  38b080:	mov    0x30(%rsp),%rdx
  38b085:	and    -0x10(%rsi,%rcx,8),%rdx
  38b08a:	mov    %rdx,-0x10(%rdi,%rcx,8)
  38b08f:	mov    0x30(%rsp),%rdx
  38b094:	and    -0x8(%rsi,%rcx,8),%rdx
  38b099:	mov    %rdx,-0x8(%rdi,%rcx,8)
  38b09e:	mov    0x30(%rsp),%rdx
  38b0a3:	and    (%rsi,%rcx,8),%rdx
  38b0a7:	mov    %rdx,(%rdi,%rcx,8)
  38b0ab:	mov    0x30(%rsp),%rdx
  38b0b0:	and    0x8(%rsi,%rcx,8),%rdx
  38b0b5:	mov    %rdx,0x8(%rdi,%rcx,8)
  38b0ba:	add    $0x4,%rcx
  38b0be:	cmp    %rcx,%rbx
  38b0c1:	jne    38b080 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xcb0>
  38b0c3:	lea    -0x8(,%rbx,8),%rcx
  38b0cb:	xor    %esi,%esi
  38b0cd:	test   %rcx,%rcx
  38b0d0:	je     38b1b0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xde0>
  38b0d6:	xor    %edi,%edi
  38b0d8:	mov    %r10,%r9
  38b0db:	jmp    38b12d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd5d>
  38b0dd:	nopl   (%rax)
  38b0e0:	mov    0x60(%rsp),%rsi
  38b0e5:	mov    (%rsi,%rdx,8),%rsi
  38b0e9:	mov    0x48(%rsp),%r10
  38b0ee:	mov    -0x8(%r10,%rdx,8),%r10
  38b0f3:	or     %r9b,%r8b
  38b0f6:	movzbl %r8b,%r8d
  38b0fa:	sub    %r10,%rsi
  38b0fd:	setb   %r9b
  38b101:	sub    %r8,%rsi
  38b104:	setb   %r8b
  38b108:	mov    %rsi,0x8(%rcx)
  38b10c:	or     %r9b,%r8b
  38b10f:	movzbl %r8b,%esi
  38b113:	inc    %rdi
  38b116:	lea    0x10(%rcx),%r9
  38b11a:	cmp    0xb8(%rsp),%rdi
  38b122:	mov    0x50(%rsp),%r10
  38b127:	lea    (%r10,%rbx,8),%r10
  38b12b:	je     38b180 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xdb0>
  38b12d:	mov    %r9,%rcx
  38b130:	mov    %rdi,%rdx
  38b133:	cmp    %rbx,%rdi
  38b136:	jae    38b150 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd80>
  38b138:	mov    0x60(%rsp),%rdi
  38b13d:	mov    -0x8(%rdi,%rdx,8),%rdi
  38b142:	mov    0x48(%rsp),%r8
  38b147:	mov    -0x10(%r8,%rdx,8),%r8
  38b14c:	jmp    38b155 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd85>
  38b14e:	xchg   %ax,%ax
  38b150:	xor    %edi,%edi
  38b152:	xor    %r8d,%r8d
  38b155:	sub    %r8,%rdi
  38b158:	setb   %r8b
  38b15c:	sub    %rsi,%rdi
  38b15f:	setb   %r9b
  38b163:	mov    %rdi,(%rcx)
  38b166:	lea    0x1(%rdx),%rdi
  38b16a:	cmp    %rbx,%rdi
  38b16d:	jb     38b0e0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd10>
  38b173:	xor    %esi,%esi
  38b175:	xor    %r10d,%r10d
  38b178:	jmp    38b0f3 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd23>
  38b17d:	nopl   (%rax)
  38b180:	testb  $0x1,0x90(%rsp)
  38b188:	lea    0x1(%rbx),%rdi
  38b18c:	mov    0x40(%rsp),%r9
  38b191:	lea    (%r9,%rdi,8),%r9
  38b195:	je     38b1d5 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xe05>
  38b197:	add    $0x10,%rcx
  38b19b:	add    $0x2,%rdx
  38b19f:	cmp    %rbx,%rdx
  38b1a2:	jb     38b1ba <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xdea>
  38b1a4:	xor    %edi,%edi
  38b1a6:	xor    %edx,%edx
  38b1a8:	jmp    38b1c2 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xdf2>
  38b1aa:	nopw   0x0(%rax,%rax,1)
  38b1b0:	xor    %edx,%edx
  38b1b2:	mov    %r10,%rcx
  38b1b5:	cmp    %rbx,%rdx
  38b1b8:	jae    38b1a4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xdd4>
  38b1ba:	mov    (%r15,%rdx,8),%rdi
  38b1be:	mov    (%r9,%rdx,8),%rdx
  38b1c2:	sub    %rdx,%rdi
  38b1c5:	setb   %dl
  38b1c8:	sub    %rsi,%rdi
  38b1cb:	setb   %r8b
  38b1cf:	mov    %rdi,(%rcx)
  38b1d2:	or     %dl,%r8b
  38b1d5:	incq   0x198(%rsp)
  38b1dd:	mov    $0x4,%ecx
  38b1e2:	mov    0x140(%rsp),%rdx
  38b1ea:	sub    %rdx,%rcx
  38b1ed:	add    $0x4,%rdx
  38b1f1:	and    %rax,%rcx
  38b1f4:	not    %rax
  38b1f7:	and    %rax,%rdx
  38b1fa:	or     %rcx,%rdx
  38b1fd:	mov    %rdx,0x140(%rsp)
  38b205:	movzbl %r8b,%ecx
  38b209:	neg    %rcx
  38b20c:	mov    %rcx,0x18(%rsp)
  38b211:	lea    0x18(%rsp),%rcx
  38b216:	xor    %ecx,%ecx
  38b218:	xor    %edx,%edx
  38b21a:	mov    0x58(%rsp),%r8
  38b21f:	nop
  38b220:	cmp    %rcx,%r11
  38b223:	je     38c0c6 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1cf6>
  38b229:	mov    0x18(%rsp),%rsi
  38b22e:	and    (%r8,%rcx,1),%rsi
  38b232:	add    (%r10,%rcx,1),%rsi
  38b236:	setb   %dil
  38b23a:	add    %rdx,%rsi
  38b23d:	setb   %dl
  38b240:	mov    %rsi,(%r10,%rcx,1)
  38b244:	or     %dil,%dl
  38b247:	movzbl %dl,%edx
  38b24a:	add    $0x8,%rcx
  38b24e:	cmp    %rcx,%r11
  38b251:	jne    38b220 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xe50>
  38b253:	xor    %edx,%edx
  38b255:	xor    %ecx,%ecx
  38b257:	mov    0x50(%rsp),%r8
  38b25c:	nopl   0x0(%rax)
  38b260:	cmp    %rdx,%r11
  38b263:	je     38c0cf <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1cff>
  38b269:	mov    (%r8,%rdx,1),%rsi
  38b26d:	add    (%r15,%rdx,1),%rsi
  38b271:	setb   %dil
  38b275:	add    %rcx,%rsi
  38b278:	setb   %cl
  38b27b:	mov    0x38(%rsp),%r9
  38b280:	mov    %rsi,(%r9,%rdx,1)
  38b284:	or     %dil,%cl
  38b287:	movzbl %cl,%ecx
  38b28a:	add    $0x8,%rdx
  38b28e:	cmp    %rdx,%r11
  38b291:	jne    38b260 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xe90>
  38b293:	lea    -0x8(,%rbx,8),%rdx
  38b29b:	xor    %edi,%edi
  38b29d:	test   %rdx,%rdx
  38b2a0:	je     38b390 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xfc0>
  38b2a6:	xor    %r8d,%r8d
  38b2a9:	mov    0x38(%rsp),%rdx
  38b2ae:	lea    (%rdx,%rbx,8),%r10
  38b2b2:	jmp    38b308 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xf38>
  38b2b4:	data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b2c0:	mov    0x0(%rbp,%rsi,8),%rdi
  38b2c5:	mov    0x58(%rsp),%r11
  38b2ca:	mov    0x8(%r11,%rsi,8),%r11
  38b2cf:	or     %r10b,%r9b
  38b2d2:	movzbl %r9b,%r9d
  38b2d6:	sub    %r11,%rdi
  38b2d9:	setb   %r10b
  38b2dd:	sub    %r9,%rdi
  38b2e0:	setb   %r9b
  38b2e4:	mov    %rdi,0x8(%rdx)
  38b2e8:	or     %r10b,%r9b
  38b2eb:	movzbl %r9b,%edi
  38b2ef:	inc    %r8
  38b2f2:	lea    0x10(%rdx),%r10
  38b2f6:	cmp    0xb8(%rsp),%r8
  38b2fe:	lea    0x0(,%rbx,8),%r11
  38b306:	je     38b360 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xf90>
  38b308:	mov    %r10,%rdx
  38b30b:	mov    %r8,%rsi
  38b30e:	cmp    %rbx,%r8
  38b311:	jae    38b330 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xf60>
  38b313:	mov    -0x8(%rbp,%rsi,8),%r8
  38b318:	mov    0x58(%rsp),%r9
  38b31d:	mov    (%r9,%rsi,8),%r9
  38b321:	jmp    38b336 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xf66>
  38b323:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b330:	xor    %r8d,%r8d
  38b333:	xor    %r9d,%r9d
  38b336:	sub    %r9,%r8
  38b339:	setb   %r9b
  38b33d:	sub    %rdi,%r8
  38b340:	setb   %r10b
  38b344:	mov    %r8,(%rdx)
  38b347:	lea    0x1(%rsi),%r8
  38b34b:	cmp    %rbx,%r8
  38b34e:	jb     38b2c0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xef0>
  38b354:	xor    %edi,%edi
  38b356:	xor    %r11d,%r11d
  38b359:	jmp    38b2cf <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xeff>
  38b35e:	xchg   %ax,%ax
  38b360:	testb  $0x1,0x90(%rsp)
  38b368:	mov    0x50(%rsp),%r8
  38b36d:	lea    (%r8,%rbx,8),%r10
  38b371:	je     38b3c6 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xff6>
  38b373:	add    $0x10,%rdx
  38b377:	add    $0x2,%rsi
  38b37b:	cmp    %rbx,%rsi
  38b37e:	jb     38b3a0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xfd0>
  38b380:	xor    %r8d,%r8d
  38b383:	xor    %esi,%esi
  38b385:	jmp    38b3b2 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xfe2>
  38b387:	nopw   0x0(%rax,%rax,1)
  38b390:	xor    %esi,%esi
  38b392:	mov    0x38(%rsp),%rdx
  38b397:	lea    (%rdx,%rbx,8),%rdx
  38b39b:	cmp    %rbx,%rsi
  38b39e:	jae    38b380 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xfb0>
  38b3a0:	mov    0x38(%rsp),%r8
  38b3a5:	mov    (%r8,%rsi,8),%r8
  38b3a9:	mov    0x58(%rsp),%r9
  38b3ae:	mov    (%r9,%rsi,8),%rsi
  38b3b2:	sub    %rsi,%r8
  38b3b5:	setb   %sil
  38b3b9:	sub    %rdi,%r8
  38b3bc:	setb   %r9b
  38b3c0:	mov    %r8,(%rdx)
  38b3c3:	or     %sil,%r9b
  38b3c6:	cmp    $0x4,%rbx
  38b3ca:	setb   %dl
  38b3cd:	not    %r9b
  38b3d0:	or     %cl,%r9b
  38b3d3:	movzbl %r9b,%ecx
  38b3d7:	and    $0x1,%ecx
  38b3da:	neg    %rcx
  38b3dd:	mov    %rcx,0x18(%rsp)
  38b3e2:	lea    0x18(%rsp),%rcx
  38b3e7:	or     0x14(%rsp),%dl
  38b3eb:	test   $0x1,%dl
  38b3ee:	mov    0x58(%rsp),%r8
  38b3f3:	je     38b410 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1040>
  38b3f5:	xor    %ecx,%ecx
  38b3f7:	mov    0xd8(%rsp),%r9
  38b3ff:	jmp    38b4aa <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x10da>
  38b404:	data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b410:	movq   0x18(%rsp),%xmm0
  38b416:	pshufd $0x44,%xmm0,%xmm0
  38b41b:	movdqa %xmm0,%xmm1
  38b41f:	pcmpeqd %xmm2,%xmm2
  38b423:	pxor   %xmm2,%xmm1
  38b427:	xor    %ecx,%ecx
  38b429:	mov    0xd8(%rsp),%r9
  38b431:	mov    0xe0(%rsp),%rdx
  38b439:	mov    0xa8(%rsp),%rsi
  38b441:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b450:	movdqu -0x10(%rdx,%rcx,1),%xmm2
  38b456:	movdqu (%rdx,%rcx,1),%xmm3
  38b45b:	pand   %xmm0,%xmm2
  38b45f:	pand   %xmm0,%xmm3
  38b463:	movdqu -0x10(%r12,%rcx,1),%xmm4
  38b46a:	movdqu (%r12,%rcx,1),%xmm5
  38b470:	pand   %xmm1,%xmm4
  38b474:	por    %xmm2,%xmm4
  38b478:	pand   %xmm1,%xmm5
  38b47c:	por    %xmm3,%xmm5
  38b480:	movdqu %xmm4,-0x10(%r12,%rcx,1)
  38b487:	movdqu %xmm5,(%r12,%rcx,1)
  38b48d:	add    $0x20,%rcx
  38b491:	cmp    %rcx,%rsi
  38b494:	jne    38b450 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1080>
  38b496:	mov    0xb0(%rsp),%rdx
  38b49e:	mov    %rdx,%rcx
  38b4a1:	cmp    %rdx,%rbx
  38b4a4:	je     38b52d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x115d>
  38b4aa:	mov    %rcx,%rdx
  38b4ad:	or     $0x1,%rdx
  38b4b1:	test   $0x1,%bl
  38b4b4:	je     38b4d9 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1109>
  38b4b6:	mov    0x38(%rsp),%r14
  38b4bb:	mov    (%r14,%rcx,8),%rsi
  38b4bf:	lea    (%r14,%rbx,8),%rdi
  38b4c3:	mov    (%rdi,%rcx,8),%rdi
  38b4c7:	xor    %rsi,%rdi
  38b4ca:	and    0x18(%rsp),%rdi
  38b4cf:	xor    %rsi,%rdi
  38b4d2:	mov    %rdi,(%r14,%rcx,8)
  38b4d6:	mov    %rdx,%rcx
  38b4d9:	cmp    %rdx,%rbx
  38b4dc:	mov    0xe0(%rsp),%r14
  38b4e4:	je     38b52d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x115d>
  38b4e6:	cs nopw 0x0(%rax,%rax,1)
  38b4f0:	mov    -0x8(%rbp,%rcx,8),%rdx
  38b4f5:	mov    -0x10(%r14,%rcx,8),%rsi
  38b4fa:	xor    %rdx,%rsi
  38b4fd:	and    0x18(%rsp),%rsi
  38b502:	mov    0x0(%rbp,%rcx,8),%rdi
  38b507:	xor    %rdx,%rsi
  38b50a:	mov    %rsi,-0x8(%rbp,%rcx,8)
  38b50f:	mov    -0x8(%r14,%rcx,8),%rdx
  38b514:	xor    %rdi,%rdx
  38b517:	and    0x18(%rsp),%rdx
  38b51c:	xor    %rdi,%rdx
  38b51f:	mov    %rdx,0x0(%rbp,%rcx,8)
  38b524:	add    $0x2,%rcx
  38b528:	cmp    %rcx,%rbx
  38b52b:	jne    38b4f0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1120>
  38b52d:	cmp    $0x4,%rbx
  38b531:	setb   %cl
  38b534:	or     0x13(%rsp),%cl
  38b538:	test   $0x1,%cl
  38b53b:	je     38b550 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1180>
  38b53d:	xor    %ecx,%ecx
  38b53f:	mov    0xe8(%rsp),%rdi
  38b547:	jmp    38b5dc <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x120c>
  38b54c:	nopl   0x0(%rax)
  38b550:	movq   0x8(%rsp),%xmm0
  38b556:	pshufd $0x44,%xmm0,%xmm0
  38b55b:	movq   %rax,%xmm1
  38b560:	pshufd $0x44,%xmm1,%xmm1
  38b565:	xor    %ecx,%ecx
  38b567:	mov    0xe8(%rsp),%rdi
  38b56f:	mov    0xa8(%rsp),%rdx
  38b577:	nopw   0x0(%rax,%rax,1)
  38b580:	movdqu -0x10(%r12,%rcx,1),%xmm2
  38b587:	movdqu (%r12,%rcx,1),%xmm3
  38b58d:	movdqu -0x10(%r9,%rcx,1),%xmm4
  38b594:	movdqu (%r9,%rcx,1),%xmm5
  38b59a:	pand   %xmm0,%xmm4
  38b59e:	pand   %xmm0,%xmm5
  38b5a2:	pand   %xmm1,%xmm2
  38b5a6:	por    %xmm4,%xmm2
  38b5aa:	pand   %xmm1,%xmm3
  38b5ae:	por    %xmm5,%xmm3
  38b5b2:	movdqu %xmm2,-0x10(%r9,%rcx,1)
  38b5b9:	movdqu %xmm3,(%r9,%rcx,1)
  38b5bf:	add    $0x20,%rcx
  38b5c3:	cmp    %rcx,%rdx
  38b5c6:	jne    38b580 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x11b0>
  38b5c8:	mov    0xb0(%rsp),%rdx
  38b5d0:	mov    %rdx,%rcx
  38b5d3:	cmp    %rdx,%rbx
  38b5d6:	je     38b65b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x128b>
  38b5dc:	mov    %rcx,%rdx
  38b5df:	or     $0x1,%rdx
  38b5e3:	test   $0x1,%bl
  38b5e6:	je     38b60f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x123f>
  38b5e8:	mov    0x8(%rsp),%rsi
  38b5ed:	and    (%r10,%rcx,8),%rsi
  38b5f1:	mov    0x38(%rsp),%rdi
  38b5f6:	mov    (%rdi,%rcx,8),%rdi
  38b5fa:	and    %rax,%rdi
  38b5fd:	or     %rsi,%rdi
  38b600:	mov    %rdi,(%r10,%rcx,8)
  38b604:	mov    0xe8(%rsp),%rdi
  38b60c:	mov    %rdx,%rcx
  38b60f:	cmp    %rdx,%rbx
  38b612:	mov    0x110(%rsp),%r14
  38b61a:	je     38b65b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x128b>
  38b61c:	nopl   0x0(%rax)
  38b620:	mov    0x8(%rsp),%rdx
  38b625:	and    -0x8(%r14,%rcx,8),%rdx
  38b62a:	mov    -0x8(%rbp,%rcx,8),%rsi
  38b62f:	and    %rax,%rsi
  38b632:	or     %rdx,%rsi
  38b635:	mov    %rsi,-0x8(%r14,%rcx,8)
  38b63a:	mov    0x8(%rsp),%rdx
  38b63f:	and    (%r14,%rcx,8),%rdx
  38b643:	mov    0x0(%rbp,%rcx,8),%rsi
  38b648:	and    %rax,%rsi
  38b64b:	or     %rdx,%rsi
  38b64e:	mov    %rsi,(%r14,%rcx,8)
  38b652:	add    $0x2,%rcx
  38b656:	cmp    %rcx,%rbx
  38b659:	jne    38b620 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1250>
  38b65b:	mov    (%r10),%rax
  38b65e:	and    $0x1,%eax
  38b661:	neg    %rax
  38b664:	mov    %rax,0x18(%rsp)
  38b669:	lea    0x18(%rsp),%rax
  38b66e:	lea    -0x1(%rbx),%rax
  38b672:	test   %rax,%rax
  38b675:	je     38b7d0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1400>
  38b67b:	xor    %ecx,%ecx
  38b67d:	mov    0x160(%rsp),%r14
  38b685:	jmp    38b6b0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x12e0>
  38b687:	nopw   0x0(%rax,%rax,1)
  38b690:	mov    (%r9,%rcx,8),%rdx
  38b694:	shl    $0x3f,%rdx
  38b698:	mov    -0x8(%r9,%rcx,8),%rsi
  38b69d:	shr    $1,%rsi
  38b6a0:	or     %rdx,%rsi
  38b6a3:	mov    %rsi,0x0(%rbp,%rcx,8)
  38b6a8:	mov    %rax,%rcx
  38b6ab:	cmp    %rax,%rdi
  38b6ae:	je     38b6f0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1320>
  38b6b0:	lea    0x1(%rcx),%rax
  38b6b4:	cmp    %rbx,%rax
  38b6b7:	jae    38b6d0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1300>
  38b6b9:	mov    -0x8(%r9,%rcx,8),%rax
  38b6be:	shl    $0x3f,%rax
  38b6c2:	jmp    38b6d2 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1302>
  38b6c4:	data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b6d0:	xor    %eax,%eax
  38b6d2:	mov    -0x10(%r9,%rcx,8),%rdx
  38b6d7:	shr    $1,%rdx
  38b6da:	or     %rax,%rdx
  38b6dd:	mov    %rdx,-0x8(%rbp,%rcx,8)
  38b6e2:	lea    0x2(%rcx),%rax
  38b6e6:	cmp    %rbx,%rax
  38b6e9:	jb     38b690 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x12c0>
  38b6eb:	xor    %edx,%edx
  38b6ed:	jmp    38b698 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x12c8>
  38b6ef:	nop
  38b6f0:	test   $0x1,%bl
  38b6f3:	mov    0x110(%rsp),%r9
  38b6fb:	jne    38b7e2 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1412>
  38b701:	lea    -0x1(%rbx),%rax
  38b705:	test   %rax,%rax
  38b708:	je     38b822 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1452>
  38b70e:	xor    %eax,%eax
  38b710:	xor    %ecx,%ecx
  38b712:	mov    0x100(%rsp),%r15
  38b71a:	nopw   0x0(%rax,%rax,1)
  38b720:	mov    (%r8,%rcx,8),%rdx
  38b724:	add    -0x8(%r9,%rcx,8),%rdx
  38b729:	setb   %sil
  38b72d:	add    %rax,%rdx
  38b730:	setb   %al
  38b733:	mov    %rdx,-0x8(%r15,%rcx,8)
  38b738:	or     %sil,%al
  38b73b:	mov    0x8(%r8,%rcx,8),%rdx
  38b740:	add    $0xff,%al
  38b742:	adc    (%r9,%rcx,8),%rdx
  38b746:	mov    %rdx,(%r15,%rcx,8)
  38b74a:	lea    0x2(%rcx),%rcx
  38b74e:	setb   %al
  38b751:	movzbl %al,%eax
  38b754:	cmp    %rcx,%rdi
  38b757:	jne    38b720 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1350>
  38b759:	test   $0x1,%bl
  38b75c:	mov    0x128(%rsp),%rdi
  38b764:	mov    0xa0(%rsp),%r15
  38b76c:	jne    38b82e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x145e>
  38b772:	mov    %rax,(%rdi,%rbx,8)
  38b776:	test   $0x3,%bl
  38b779:	je     38b857 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1487>
  38b77f:	xor    %ecx,%ecx
  38b781:	mov    0x78(%rsp),%rsi
  38b786:	mov    0x50(%rsp),%rdi
  38b78b:	mov    0x108(%rsp),%r8
  38b793:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b7a0:	mov    %rax,%rdx
  38b7a3:	mov    -0x38(%r13,%rcx,8),%rax
  38b7a8:	shld   $0x3f,%rax,%rdx
  38b7ad:	mov    %rdx,-0x8(%r8,%rcx,8)
  38b7b2:	dec    %rcx
  38b7b5:	cmp    %rcx,%r14
  38b7b8:	jne    38b7a0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x13d0>
  38b7ba:	add    %rbx,%rcx
  38b7bd:	jmp    38b864 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1494>
  38b7c2:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b7d0:	xor    %eax,%eax
  38b7d2:	mov    0x110(%rsp),%r9
  38b7da:	mov    0x160(%rsp),%r14
  38b7e2:	lea    0x1(%rax),%rcx
  38b7e6:	cmp    %rbx,%rcx
  38b7e9:	jae    38b800 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1430>
  38b7eb:	mov    0x8(%r10,%rax,8),%rcx
  38b7f0:	shl    $0x3f,%rcx
  38b7f4:	jmp    38b802 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1432>
  38b7f6:	cs nopw 0x0(%rax,%rax,1)
  38b800:	xor    %ecx,%ecx
  38b802:	mov    (%r10,%rax,8),%rdx
  38b806:	shr    $1,%rdx
  38b809:	or     %rcx,%rdx
  38b80c:	mov    0x38(%rsp),%rcx
  38b811:	mov    %rdx,(%rcx,%rax,8)
  38b815:	lea    -0x1(%rbx),%rax
  38b819:	test   %rax,%rax
  38b81c:	jne    38b70e <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x133e>
  38b822:	xor    %eax,%eax
  38b824:	xor    %ecx,%ecx
  38b826:	mov    0x128(%rsp),%rdi
  38b82e:	mov    (%r8,%rcx,8),%rdx
  38b832:	add    (%r10,%rcx,8),%rdx
  38b836:	setb   %sil
  38b83a:	add    %rax,%rdx
  38b83d:	setb   %al
  38b840:	mov    %rdx,(%rdi,%rcx,8)
  38b844:	or     %sil,%al
  38b847:	movzbl %al,%eax
  38b84a:	mov    %rax,(%rdi,%rbx,8)
  38b84e:	test   $0x3,%bl
  38b851:	jne    38b77f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x13af>
  38b857:	mov    %rbx,%rcx
  38b85a:	mov    0x78(%rsp),%rsi
  38b85f:	mov    0x50(%rsp),%rdi
  38b864:	lea    -0x1(%rbx),%rdx
  38b868:	cmp    $0x3,%rdx
  38b86c:	mov    0x138(%rsp),%r9
  38b874:	mov    0x1e0(%rsp),%r8
  38b87c:	jb     38b8c1 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x14f1>
  38b87e:	xchg   %ax,%ax
  38b880:	mov    0x8(%r8,%rcx,8),%rdx
  38b885:	shld   $0x3f,%rdx,%rax
  38b88a:	mov    %rax,-0x28(%r13,%rcx,8)
  38b88f:	mov    (%r8,%rcx,8),%rax
  38b893:	shld   $0x3f,%rax,%rdx
  38b898:	mov    %rdx,-0x30(%r13,%rcx,8)
  38b89d:	mov    -0x8(%r8,%rcx,8),%rdx
  38b8a2:	shld   $0x3f,%rdx,%rax
  38b8a7:	mov    %rax,-0x38(%r13,%rcx,8)
  38b8ac:	mov    -0x10(%r8,%rcx,8),%rax
  38b8b1:	shld   $0x3f,%rax,%rdx
  38b8b6:	mov    %rdx,-0x40(%r13,%rcx,8)
  38b8bb:	add    $0xfffffffffffffffc,%rcx
  38b8bf:	jne    38b880 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x14b0>
  38b8c1:	cmp    $0x4,%rbx
  38b8c5:	setb   %al
  38b8c8:	or     0x12(%rsp),%al
  38b8cc:	test   $0x1,%al
  38b8ce:	je     38b8e0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1510>
  38b8d0:	xor    %eax,%eax
  38b8d2:	jmp    38b969 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1599>
  38b8d7:	nopw   0x0(%rax,%rax,1)
  38b8e0:	movq   0x18(%rsp),%xmm0
  38b8e6:	pshufd $0x44,%xmm0,%xmm0
  38b8eb:	movdqa %xmm0,%xmm1
  38b8ef:	pcmpeqd %xmm2,%xmm2
  38b8f3:	pxor   %xmm2,%xmm1
  38b8f7:	xor    %eax,%eax
  38b8f9:	mov    0xa8(%rsp),%rcx
  38b901:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38b910:	movdqu -0x20(%r13,%rax,1),%xmm2
  38b917:	movdqu -0x10(%r13,%rax,1),%xmm3
  38b91e:	pand   %xmm0,%xmm2
  38b922:	pand   %xmm0,%xmm3
  38b926:	movdqu -0x10(%r12,%rax,1),%xmm4
  38b92d:	movdqu (%r12,%rax,1),%xmm5
  38b933:	pand   %xmm1,%xmm4
  38b937:	por    %xmm2,%xmm4
  38b93b:	pand   %xmm1,%xmm5
  38b93f:	por    %xmm3,%xmm5
  38b943:	movdqu %xmm4,-0x10(%r12,%rax,1)
  38b94a:	movdqu %xmm5,(%r12,%rax,1)
  38b950:	add    $0x20,%rax
  38b954:	cmp    %rax,%rcx
  38b957:	jne    38b910 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1540>
  38b959:	mov    0xb0(%rsp),%rcx
  38b961:	mov    %rcx,%rax
  38b964:	cmp    %rcx,%rbx
  38b967:	je     38b9dc <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x160c>
  38b969:	mov    %rax,%rcx
  38b96c:	or     $0x1,%rcx
  38b970:	test   $0x1,%bl
  38b973:	je     38b994 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x15c4>
  38b975:	mov    0x38(%rsp),%r8
  38b97a:	mov    (%r8,%rax,8),%rdx
  38b97e:	mov    (%rsi,%rax,8),%rsi
  38b982:	xor    %rdx,%rsi
  38b985:	and    0x18(%rsp),%rsi
  38b98a:	xor    %rdx,%rsi
  38b98d:	mov    %rsi,(%r8,%rax,8)
  38b991:	mov    %rcx,%rax
  38b994:	cmp    %rcx,%rbx
  38b997:	je     38b9dc <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x160c>
  38b999:	nopl   0x0(%rax)
  38b9a0:	mov    -0x8(%rbp,%rax,8),%rcx
  38b9a5:	mov    -0x8(%r9,%rax,8),%rdx
  38b9aa:	xor    %rcx,%rdx
  38b9ad:	and    0x18(%rsp),%rdx
  38b9b2:	mov    0x0(%rbp,%rax,8),%rsi
  38b9b7:	xor    %rcx,%rdx
  38b9ba:	mov    %rdx,-0x8(%rbp,%rax,8)
  38b9bf:	mov    (%r9,%rax,8),%rcx
  38b9c3:	xor    %rsi,%rcx
  38b9c6:	and    0x18(%rsp),%rcx
  38b9cb:	xor    %rsi,%rcx
  38b9ce:	mov    %rcx,0x0(%rbp,%rax,8)
  38b9d3:	add    $0x2,%rax
  38b9d7:	cmp    %rax,%rbx
  38b9da:	jne    38b9a0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x15d0>
  38b9dc:	cmpq   $0x4,0x180(%rsp)
  38b9e5:	setb   %al
  38b9e8:	mov    0x8(%rsp),%rcx
  38b9ed:	mov    %rcx,0x18(%rsp)
  38b9f2:	lea    0x18(%rsp),%rcx
  38b9f7:	or     0x11(%rsp),%al
  38b9fb:	test   $0x1,%al
  38b9fd:	je     38ba20 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1650>
  38b9ff:	xor    %eax,%eax
  38ba01:	mov    %rdi,%rcx
  38ba04:	mov    0x48(%rsp),%rsi
  38ba09:	mov    0x60(%rsp),%rdi
  38ba0e:	jmp    38baae <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x16de>
  38ba13:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38ba20:	movq   0x18(%rsp),%xmm0
  38ba26:	pshufd $0x44,%xmm0,%xmm0
  38ba2b:	movdqa %xmm0,%xmm1
  38ba2f:	pcmpeqd %xmm2,%xmm2
  38ba33:	pxor   %xmm2,%xmm1
  38ba37:	xor    %eax,%eax
  38ba39:	mov    0x48(%rsp),%rsi
  38ba3e:	mov    0x1c0(%rsp),%rcx
  38ba46:	mov    0x118(%rsp),%rdx
  38ba4e:	mov    0x60(%rsp),%rdi
  38ba53:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38ba60:	movdqu -0x8(%rdi,%rax,8),%xmm2
  38ba66:	movdqu 0x8(%rdi,%rax,8),%xmm3
  38ba6c:	pand   %xmm0,%xmm2
  38ba70:	pand   %xmm0,%xmm3
  38ba74:	movdqu -0x10(%rsi,%rax,8),%xmm4
  38ba7a:	movdqu (%rsi,%rax,8),%xmm5
  38ba7f:	pand   %xmm1,%xmm4
  38ba83:	por    %xmm2,%xmm4
  38ba87:	pand   %xmm1,%xmm5
  38ba8b:	por    %xmm3,%xmm5
  38ba8f:	movdqu %xmm4,-0x10(%rdx,%rax,8)
  38ba95:	movdqu %xmm5,(%rdx,%rax,8)
  38ba9a:	add    $0x4,%rax
  38ba9e:	cmp    %rax,%rcx
  38baa1:	jne    38ba60 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1690>
  38baa3:	mov    %rcx,%rax
  38baa6:	mov    0x1b8(%rsp),%rcx
  38baae:	lea    (%rdi,%rax,8),%rdx
  38bab2:	add    $0xfffffffffffffff8,%rdx
  38bab6:	lea    (%rsi,%rax,8),%rsi
  38baba:	add    $0xfffffffffffffff0,%rsi
  38babe:	xor    %edi,%edi
  38bac0:	cmp    %rax,%rbx
  38bac3:	je     38c0d8 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d08>
  38bac9:	inc    %rax
  38bacc:	mov    (%rsi,%rdi,1),%r8
  38bad0:	mov    (%rdx,%rdi,1),%r9
  38bad4:	xor    %r8,%r9
  38bad7:	and    0x18(%rsp),%r9
  38badc:	xor    %r8,%r9
  38badf:	mov    %r9,(%rcx,%rdi,1)
  38bae3:	lea    (%rcx,%rdi,1),%r8
  38bae7:	add    $0x8,%r8
  38baeb:	add    $0x8,%rdi
  38baef:	cmp    %r10,%r8
  38baf2:	jne    38bac0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x16f0>
  38baf4:	mov    %r15,%rdi
  38baf7:	mov    0x38(%rsp),%rsi
  38bafc:	mov    %r11,%rdx
  38baff:	mov    0x5539b2(%rip),%r14        # 8df4b8 <memcpy@GLIBC_2.14>
  38bb06:	call   *%r14
  38bb09:	mov    %r14,%rcx
  38bb0c:	lea    0x1(%rbx),%rax
  38bb10:	mov    0x40(%rsp),%r15
  38bb15:	lea    (%r15,%rax,8),%r14
  38bb19:	mov    %r14,%rdi
  38bb1c:	mov    0x50(%rsp),%rsi
  38bb21:	lea    0x0(,%rbx,8),%rdx
  38bb29:	call   *%rcx
  38bb2b:	mov    %r15,%rsi
  38bb2e:	mov    %r14,%r9
  38bb31:	mov    0x198(%rsp),%rax
  38bb39:	cmp    0x1d8(%rsp),%rax
  38bb41:	mov    0x70(%rsp),%r14
  38bb46:	mov    0x1d0(%rsp),%r11
  38bb4e:	jne    38a9a0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x5d0>
  38bb54:	mov    (%r14,%rbx,8),%rax
  38bb58:	sar    $0x3f,%rax
  38bb5c:	mov    %rax,0x8(%rsp)
  38bb61:	lea    0x8(%rsp),%rax
  38bb66:	xor    %ecx,%ecx
  38bb68:	xor    %eax,%eax
  38bb6a:	mov    0x98(%rsp),%rdi
  38bb72:	mov    0x158(%rsp),%r8
  38bb7a:	nopw   0x0(%rax,%rax,1)
  38bb80:	xor    %edx,%edx
  38bb82:	sub    (%r14,%rax,1),%rdx
  38bb86:	setb   %sil
  38bb8a:	sub    %rcx,%rdx
  38bb8d:	setb   %cl
  38bb90:	mov    %rdx,(%rdi,%rax,1)
  38bb94:	or     %sil,%cl
  38bb97:	add    $0xff,%cl
  38bb9a:	mov    0x8(%r14,%rax,1),%rcx
  38bb9f:	mov    $0x0,%edx
  38bba4:	sbb    %rcx,%rdx
  38bba7:	mov    %rdx,0x8(%rdi,%rax,1)
  38bbac:	setb   %cl
  38bbaf:	movzbl %cl,%ecx
  38bbb2:	add    $0x10,%rax
  38bbb6:	cmp    %rax,%r8
  38bbb9:	jne    38bb80 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x17b0>
  38bbbb:	lea    0x1(%rbx),%rdx
  38bbbf:	test   $0x1,%dl
  38bbc2:	lea    0x0(,%rbx,8),%r11
  38bbca:	mov    0x180(%rsp),%r15
  38bbd2:	movabs $0x3ffffffffffffffe,%r13
  38bbdc:	lea    0x18(%rsp),%r12
  38bbe1:	je     38bbee <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x181e>
  38bbe3:	neg    %rcx
  38bbe6:	sub    (%r14,%rax,1),%rcx
  38bbea:	mov    %rcx,(%rdi,%rax,1)
  38bbee:	mov    0x8(%rsp),%rax
  38bbf3:	mov    %rax,%rcx
  38bbf6:	not    %rcx
  38bbf9:	xor    %esi,%esi
  38bbfb:	xor    %r9d,%r9d
  38bbfe:	xor    %edx,%edx
  38bc00:	cmp    %rbx,%rsi
  38bc03:	jbe    38bc3f <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x186f>
  38bc05:	jmp    38bc80 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x18b0>
  38bc07:	nopw   0x0(%rax,%rax,1)
  38bc10:	mov    0xc0(%rsp),%r10
  38bc18:	mov    (%r10),%r10
  38bc1b:	and    %rcx,%r10
  38bc1e:	mov    (%r9),%r9
  38bc21:	and    %rax,%r9
  38bc24:	or     %r10,%r9
  38bc27:	xor    %r10d,%r10d
  38bc2a:	test   %rdi,%rdi
  38bc2d:	sete   %r10b
  38bc31:	xor    %r9,%r10
  38bc34:	or     %r10,%rdx
  38bc37:	mov    %r8,%r9
  38bc3a:	cmp    %rbx,%rsi
  38bc3d:	ja     38bc80 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x18b0>
  38bc3f:	cmp    $0xffffffffffffffff,%r9
  38bc43:	je     38c0fb <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d2b>
  38bc49:	lea    (%r14,%rsi,8),%r10
  38bc4d:	mov    0x98(%rsp),%rdi
  38bc55:	lea    (%rdi,%rsi,8),%rdi
  38bc59:	inc    %rsi
  38bc5c:	lea    0x1(%r9),%r8
  38bc60:	mov    %rdi,0x18(%rsp)
  38bc65:	mov    %r9,%rdi
  38bc68:	lea    0xc0(%rsp),%r9
  38bc70:	jmp    38bc89 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x18b9>
  38bc72:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  38bc80:	mov    %r9,%r8
  38bc83:	mov    %r12,%r9
  38bc86:	xor    %r10d,%r10d
  38bc89:	mov    %r10,(%r9)
  38bc8c:	mov    0x18(%rsp),%r9
  38bc91:	test   %r9,%r9
  38bc94:	jne    38bc10 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1840>
  38bc9a:	xor    %eax,%eax
  38bc9c:	test   %rdx,%rdx
  38bc9f:	setne  %al
  38bca2:	mov    %rax,0x18(%rsp)
  38bca7:	lea    0x18(%rsp),%rax
  38bcac:	mov    0x18(%rsp),%r12
  38bcb1:	lea    -0x8(,%rbx,8),%rax
  38bcb9:	test   %rax,%rax
  38bcbc:	jne    38bcdf <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x190f>
  38bcbe:	xor    %edx,%edx
  38bcc0:	xor    %ecx,%ecx
  38bcc2:	mov    0x150(%rsp),%r10
  38bcca:	mov    %r10,%rax
  38bccd:	mov    0xd0(%rsp),%r9
  38bcd5:	mov    0x58(%rsp),%r8
  38bcda:	jmp    38bd87 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x19b7>
  38bcdf:	and    0x90(%rsp),%r13
  38bce7:	xor    %edx,%edx
  38bce9:	xor    %esi,%esi
  38bceb:	mov    0x150(%rsp),%r10
  38bcf3:	mov    %r10,%r8
  38bcf6:	mov    0xd0(%rsp),%r9
  38bcfe:	jmp    38bd36 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1966>
  38bd00:	mov    0x48(%rsp),%rdx
  38bd05:	mov    -0x8(%rdx,%rcx,8),%rdx
  38bd0a:	or     %r8b,%dil
  38bd0d:	movzbl %dil,%edi
  38bd11:	neg    %rdx
  38bd14:	setb   %r8b
  38bd18:	sub    %rdi,%rdx
  38bd1b:	setb   %dil
  38bd1f:	mov    %rdx,0x8(%rax)
  38bd23:	or     %r8b,%dil
  38bd26:	movzbl %dil,%edx
  38bd2a:	inc    %rsi
  38bd2d:	lea    0x10(%rax),%r8
  38bd31:	cmp    %r13,%rsi
  38bd34:	je     38bd70 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x19a0>
  38bd36:	mov    %r8,%rax
  38bd39:	mov    %rsi,%rcx
  38bd3c:	cmp    %rbx,%rsi
  38bd3f:	jae    38bd50 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1980>
  38bd41:	mov    0x48(%rsp),%rsi
  38bd46:	mov    -0x10(%rsi,%rcx,8),%rsi
  38bd4b:	jmp    38bd52 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1982>
  38bd4d:	nopl   (%rax)
  38bd50:	xor    %esi,%esi
  38bd52:	neg    %rsi
  38bd55:	setb   %dil
  38bd59:	sub    %rdx,%rsi
  38bd5c:	setb   %r8b
  38bd60:	mov    %rsi,(%rax)
  38bd63:	lea    0x1(%rcx),%rsi
  38bd67:	cmp    %rbx,%rsi
  38bd6a:	jb     38bd00 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1930>
  38bd6c:	xor    %edx,%edx
  38bd6e:	jmp    38bd0a <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x193a>
  38bd70:	testb  $0x1,0x90(%rsp)
  38bd78:	mov    0x58(%rsp),%r8
  38bd7d:	je     38bda8 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x19d8>
  38bd7f:	add    $0x10,%rax
  38bd83:	add    $0x2,%rcx
  38bd87:	cmp    %rbx,%rcx
  38bd8a:	jae    38bd92 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x19c2>
  38bd8c:	mov    (%r9,%rcx,8),%rcx
  38bd90:	jmp    38bd94 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x19c4>
  38bd92:	xor    %ecx,%ecx
  38bd94:	neg    %rcx
  38bd97:	setb   %sil
  38bd9b:	sub    %rdx,%rcx
  38bd9e:	setb   %dil
  38bda2:	mov    %rcx,(%rax)
  38bda5:	or     %sil,%dil
  38bda8:	movzbl %dil,%eax
  38bdac:	neg    %rax
  38bdaf:	mov    %rax,0x18(%rsp)
  38bdb4:	lea    0x18(%rsp),%rax
  38bdb9:	xor    %eax,%eax
  38bdbb:	xor    %ecx,%ecx
  38bdbd:	nopl   (%rax)
  38bdc0:	cmp    %rax,%r11
  38bdc3:	je     38c0c6 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1cf6>
  38bdc9:	mov    0x18(%rsp),%rdx
  38bdce:	and    (%r8,%rax,1),%rdx
  38bdd2:	add    (%r10,%rax,1),%rdx
  38bdd6:	setb   %sil
  38bdda:	add    %rcx,%rdx
  38bddd:	setb   %cl
  38bde0:	mov    %rdx,(%r10,%rax,1)
  38bde4:	or     %sil,%cl
  38bde7:	movzbl %cl,%ecx
  38bdea:	add    $0x8,%rax
  38bdee:	cmp    %rax,%r11
  38bdf1:	jne    38bdc0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x19f0>
  38bdf3:	mov    0x8(%rsp),%rax
  38bdf8:	mov    %rax,0x18(%rsp)
  38bdfd:	lea    0x18(%rsp),%rax
  38be02:	cmp    $0x8,%r15
  38be06:	jae    38be1c <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1a4c>
  38be08:	xor    %esi,%esi
  38be0a:	mov    0x68(%rsp),%rax
  38be0f:	mov    0x148(%rsp),%rdi
  38be17:	jmp    38bf00 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1b30>
  38be1c:	mov    0x1b0(%rsp),%rcx
  38be24:	add    %r14,%rcx
  38be27:	lea    (%rcx,%r15,8),%rcx
  38be2b:	add    $0x48,%rcx
  38be2f:	cmp    %rcx,%rax
  38be32:	setb   %al
  38be35:	lea    0x20(%rsp),%rcx
  38be3a:	cmp    %rcx,0x68(%rsp)
  38be3f:	mov    0x148(%rsp),%rdi
  38be47:	jae    38be59 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1a89>
  38be49:	test   %al,%al
  38be4b:	je     38be59 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1a89>
  38be4d:	xor    %esi,%esi
  38be4f:	mov    0x68(%rsp),%rax
  38be54:	jmp    38bf00 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1b30>
  38be59:	mov    0x1a8(%rsp),%rsi
  38be61:	mov    %esi,%eax
  38be63:	and    $0x3,%eax
  38be66:	mov    $0x4,%ecx
  38be6b:	cmovne %rax,%rcx
  38be6f:	sub    %rcx,%rsi
  38be72:	movq   0x18(%rsp),%xmm0
  38be78:	pshufd $0x44,%xmm0,%xmm0
  38be7d:	mov    0x68(%rsp),%rax
  38be82:	lea    (%rax,%rsi,8),%rax
  38be86:	pcmpeqd %xmm1,%xmm1
  38be8a:	pxor   %xmm0,%xmm1
  38be8e:	xor    %ecx,%ecx
  38be90:	mov    0x48(%rsp),%rdx
  38be95:	mov    0xd8(%rsp),%r8
  38be9d:	mov    0xe0(%rsp),%r11
  38bea5:	data16 cs nopw 0x0(%rax,%rax,1)
  38beb0:	movdqu -0x10(%r8,%rcx,8),%xmm2
  38beb7:	movdqu (%r8,%rcx,8),%xmm3
  38bebd:	pand   %xmm0,%xmm2
  38bec1:	pand   %xmm0,%xmm3
  38bec5:	movdqu -0x10(%rdx,%rcx,8),%xmm4
  38becb:	movdqu (%rdx,%rcx,8),%xmm5
  38bed0:	pand   %xmm1,%xmm4
  38bed4:	por    %xmm2,%xmm4
  38bed8:	pand   %xmm1,%xmm5
  38bedc:	por    %xmm3,%xmm5
  38bee0:	movdqu %xmm4,-0x10(%r11,%rcx,8)
  38bee7:	movdqu %xmm5,(%r11,%rcx,8)
  38beed:	add    $0x4,%rcx
  38bef1:	cmp    %rcx,%rsi
  38bef4:	jne    38beb0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1ae0>
  38bef6:	cs nopw 0x0(%rax,%rax,1)
  38bf00:	cmp    %rsi,%rbx
  38bf03:	je     38c0f2 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d22>
  38bf09:	mov    (%r9,%rsi,8),%rcx
  38bf0d:	mov    (%r10,%rsi,8),%rdx
  38bf11:	inc    %rsi
  38bf14:	xor    %rcx,%rdx
  38bf17:	and    0x18(%rsp),%rdx
  38bf1c:	xor    %rcx,%rdx
  38bf1f:	mov    %rdx,(%rax)
  38bf22:	add    $0x8,%rax
  38bf26:	cmp    %rdi,%rax
  38bf29:	jne    38bf00 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1b30>
  38bf2b:	lea    0x18(%rsp),%rdi
  38bf30:	mov    $0x8,%edx
  38bf35:	mov    $0x8,%r8d
  38bf3b:	mov    $0x8,%r9d
  38bf41:	xor    %esi,%esi
  38bf43:	mov    %rbx,%rcx
  38bf46:	call   164eb0 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.5541607593376212649>
  38bf4b:	cmpl   $0x1,0x18(%rsp)
  38bf50:	jne    38bfc0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1bf0>
  38bf52:	mov    0xc8(%rsp),%rax
  38bf5a:	lea    0x0(,%rax,8),%rsi
  38bf62:	shr    $0x3d,%rax
  38bf66:	setne  %al
  38bf69:	test   %rsi,%rsi
  38bf6c:	sete   %cl
  38bf6f:	or     %al,%cl
  38bf71:	jne    38bfad <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1bdd>
  38bf73:	xor    %eax,%eax
  38bf75:	movb   $0x0,(%r14,%rax,1)
  38bf7a:	movb   $0x0,0x1(%r14,%rax,1)
  38bf80:	movb   $0x0,0x2(%r14,%rax,1)
  38bf86:	movb   $0x0,0x3(%r14,%rax,1)
  38bf8c:	movb   $0x0,0x4(%r14,%rax,1)
  38bf92:	movb   $0x0,0x5(%r14,%rax,1)
  38bf98:	movb   $0x0,0x6(%r14,%rax,1)
  38bf9e:	movb   $0x0,0x7(%r14,%rax,1)
  38bfa4:	add    $0x8,%rax
  38bfa8:	cmp    %rax,%rsi
  38bfab:	jne    38bf75 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1ba5>
  38bfad:	mov    $0x8,%edx
  38bfb2:	mov    %r14,%rdi
  38bfb5:	call   *0x55290d(%rip)        # 8de8c8 <_DYNAMIC+0x15d8>
  38bfbb:	jmp    38a495 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xc5>
  38bfc0:	mov    0x20(%rsp),%r15
  38bfc5:	cmp    $0x1,%rbx
  38bfc9:	jne    38bfdc <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1c0c>
  38bfcb:	movq   $0x0,(%r15)
  38bfd2:	lea    0x0(,%rbx,8),%rdx
  38bfda:	jmp    38c004 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1c34>
  38bfdc:	lea    0x0(,%rbx,8),%r14
  38bfe4:	lea    -0x8(%r14),%rdx
  38bfe8:	mov    %r15,%rdi
  38bfeb:	xor    %esi,%esi
  38bfed:	call   *0x5528f5(%rip)        # 8de8e8 <memset@GLIBC_2.2.5>
  38bff3:	mov    %r14,%rdx
  38bff6:	mov    0x70(%rsp),%r14
  38bffb:	movq   $0x0,-0x8(%r15,%rdx,1)
  38c004:	mov    %r15,%rdi
  38c007:	mov    0x68(%rsp),%rsi
  38c00c:	call   *0x5534a6(%rip)        # 8df4b8 <memcpy@GLIBC_2.14>
  38c012:	mov    0xc8(%rsp),%rax
  38c01a:	lea    0x0(,%rax,8),%rsi
  38c022:	shr    $0x3d,%rax
  38c026:	setne  %al
  38c029:	test   %rsi,%rsi
  38c02c:	sete   %cl
  38c02f:	or     %al,%cl
  38c031:	jne    38c06d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1c9d>
  38c033:	xor    %eax,%eax
  38c035:	movb   $0x0,(%r14,%rax,1)
  38c03a:	movb   $0x0,0x1(%r14,%rax,1)
  38c040:	movb   $0x0,0x2(%r14,%rax,1)
  38c046:	movb   $0x0,0x3(%r14,%rax,1)
  38c04c:	movb   $0x0,0x4(%r14,%rax,1)
  38c052:	movb   $0x0,0x5(%r14,%rax,1)
  38c058:	movb   $0x0,0x6(%r14,%rax,1)
  38c05e:	movb   $0x0,0x7(%r14,%rax,1)
  38c064:	add    $0x8,%rax
  38c068:	cmp    %rax,%rsi
  38c06b:	jne    38c035 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1c65>
  38c06d:	mov    $0x8,%edx
  38c072:	mov    %r14,%rdi
  38c075:	call   *0x55284d(%rip)        # 8de8c8 <_DYNAMIC+0x15d8>
  38c07b:	cmp    $0x1,%r12
  38c07f:	jne    38c0ae <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1cde>
  38c081:	mov    0x88(%rsp),%rbx
  38c089:	movq   $0xffffffffffffffff,(%rbx)
  38c090:	mov    $0x8,%edx
  38c095:	mov    %r15,%rdi
  38c098:	mov    0x1a0(%rsp),%rsi
  38c0a0:	call   *0x552822(%rip)        # 8de8c8 <_DYNAMIC+0x15d8>
  38c0a6:	mov    %rbx,%rdi
  38c0a9:	jmp    38a4a4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd4>
  38c0ae:	mov    0x88(%rsp),%rdi
  38c0b6:	mov    %rbx,(%rdi)
  38c0b9:	mov    %r15,0x8(%rdi)
  38c0bd:	mov    %rbx,0x10(%rdi)
  38c0c1:	jmp    38a4a4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0xd4>
  38c0c6:	lea    0x4e4293(%rip),%rdx        # 870360 <anon.d79d8d52ab7e0217f7483bdf0064c8d9.208.llvm.2362390186010502324+0x48>
  38c0cd:	jmp    38c0e4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d14>
  38c0cf:	lea    0x4e4272(%rip),%rdx        # 870348 <anon.d79d8d52ab7e0217f7483bdf0064c8d9.208.llvm.2362390186010502324+0x30>
  38c0d6:	jmp    38c0e4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d14>
  38c0d8:	lea    0x4e4251(%rip),%rdx        # 870330 <anon.d79d8d52ab7e0217f7483bdf0064c8d9.208.llvm.2362390186010502324+0x18>
  38c0df:	mov    0x70(%rsp),%r14
  38c0e4:	mov    %rbx,%rdi
  38c0e7:	mov    %rbx,%rsi
  38c0ea:	call   *0x553a60(%rip)        # 8dfb50 <_DYNAMIC+0x2860>
  38c0f0:	jmp    38c108 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d38>
  38c0f2:	lea    0x4e4237(%rip),%rdx        # 870330 <anon.d79d8d52ab7e0217f7483bdf0064c8d9.208.llvm.2362390186010502324+0x18>
  38c0f9:	jmp    38c0e4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7divstep19mod_inverse_divstep+0x1d14>
  38c0fb:	lea    0x4f1b46(%rip),%rdi        # 87dc48 <_RNvNvNtNtCsfBoMNNx3tZr_10openssl_rs8provider9eddsa_sig30ed25519_sigalg_query_key_types8KEYTYPES+0x10>
  38c102:	call   *0x553288(%rip)        # 8df390 <_DYNAMIC+0x20a0>
  38c108:	ud2
  38c10a:	mov    %rax,%rbx
  38c10d:	mov    0xc8(%rsp),%rdi
  38c115:	mov    %r14,%rsi
  38c118:	call   3786c0 <_RINvNtCsgxBkk5gSRhY_4core3ptr9drop_glueINtNtNtCsfBoMNNx3tZr_10openssl_rs7runtime6secret9SecretBufyEEBI_>
  38c11d:	mov    %rbx,%rdi
  38c120:	call   1610a0 <_Unwind_Resume@plt>

Disassembly of section .fini:
