
### openssl_rs::bn::solinas::redc_p384_in_place  (0x458a80, 873 bytes)

/court/tmp/pfp59/after/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

0000000000458a80 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place>:
  458a80:	48 83 fe 0d          	cmp    $0xd,%rsi
  458a84:	0f 82 57 03 00 00    	jb     458de1 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x361>
  458a8a:	55                   	push   %rbp
  458a8b:	41 57                	push   %r15
  458a8d:	41 56                	push   %r14
  458a8f:	41 55                	push   %r13
  458a91:	41 54                	push   %r12
  458a93:	53                   	push   %rbx
  458a94:	48 b8 00 00 00 00 01 	movabs $0x100000000,%rax
  458a9b:	00 00 00 
  458a9e:	48 8d 14 f5 00 00 00 	lea    0x0(,%rsi,8),%rdx
  458aa5:	00 
  458aa6:	48 89 74 24 f8       	mov    %rsi,-0x8(%rsp)
  458aab:	4c 8d 04 f5 b8 ff ff 	lea    -0x48(,%rsi,8),%r8
  458ab2:	ff 
  458ab3:	45 31 db             	xor    %r11d,%r11d
  458ab6:	48 ff c0             	inc    %rax
  458ab9:	48 89 44 24 f0       	mov    %rax,-0x10(%rsp)
  458abe:	31 c9                	xor    %ecx,%ecx
  458ac0:	eb 22                	jmp    458ae4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x64>
  458ac2:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
  458ac9:	1f 84 00 00 00 00 00 
  458ad0:	4c 09 d1             	or     %r10,%rcx
  458ad3:	4c 09 f9             	or     %r15,%rcx
  458ad6:	49 83 c0 f8          	add    $0xfffffffffffffff8,%r8
  458ada:	49 83 fb 06          	cmp    $0x6,%r11
  458ade:	0f 84 f3 01 00 00    	je     458cd7 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x257>
  458ae4:	4c 89 db             	mov    %r11,%rbx
  458ae7:	4e 8b 3c df          	mov    (%rdi,%r11,8),%r15
  458aeb:	4d 89 fc             	mov    %r15,%r12
  458aee:	4c 0f af 64 24 f0    	imul   -0x10(%rsp),%r12
  458af4:	4e 01 64 df 30       	add    %r12,0x30(%rdi,%r11,8)
  458af9:	4a 83 54 df 38 00    	adcq   $0x0,0x38(%rdi,%r11,8)
  458aff:	4e 8d 34 dd 00 00 00 	lea    0x0(,%r11,8),%r14
  458b06:	00 
  458b07:	41 0f 92 c2          	setb   %r10b
  458b0b:	45 0f b6 d2          	movzbl %r10b,%r10d
  458b0f:	49 83 fb 05          	cmp    $0x5,%r11
  458b13:	74 4b                	je     458b60 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0xe0>
  458b15:	48 8d 04 dd 40 00 00 	lea    0x40(,%rbx,8),%rax
  458b1c:	00 
  458b1d:	4d 89 c3             	mov    %r8,%r11
  458b20:	48 89 dd             	mov    %rbx,%rbp
  458b23:	4d 89 fd             	mov    %r15,%r13
  458b26:	48 39 d0             	cmp    %rdx,%rax
  458b29:	74 38                	je     458b63 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0xe3>
  458b2b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  458b30:	4c 01 54 ef 40       	add    %r10,0x40(%rdi,%rbp,8)
  458b35:	0f 92 c0             	setb   %al
  458b38:	45 31 d2             	xor    %r10d,%r10d
  458b3b:	41 88 c2             	mov    %al,%r10b
  458b3e:	48 83 fd 04          	cmp    $0x4,%rbp
  458b42:	74 0c                	je     458b50 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0xd0>
  458b44:	48 ff c5             	inc    %rbp
  458b47:	4d 85 db             	test   %r11,%r11
  458b4a:	4d 8d 5b f8          	lea    -0x8(%r11),%r11
  458b4e:	75 e0                	jne    458b30 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0xb0>
  458b50:	4e 8b 2c 37          	mov    (%rdi,%r14,1),%r13
  458b54:	eb 0d                	jmp    458b63 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0xe3>
  458b56:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  458b5d:	00 00 00 
  458b60:	4d 89 fd             	mov    %r15,%r13
  458b63:	4c 8d 5b 01          	lea    0x1(%rbx),%r11
  458b67:	4c 89 e0             	mov    %r12,%rax
  458b6a:	48 c1 e8 20          	shr    $0x20,%rax
  458b6e:	4a 8d 34 20          	lea    (%rax,%r12,1),%rsi
  458b72:	4c 89 fd             	mov    %r15,%rbp
  458b75:	48 c1 e5 20          	shl    $0x20,%rbp
  458b79:	49 39 ec             	cmp    %rbp,%r12
  458b7c:	48 19 c5             	sbb    %rax,%rbp
  458b7f:	48 83 de 00          	sbb    $0x0,%rsi
  458b83:	41 b9 00 00 00 00    	mov    $0x0,%r9d
  458b89:	4d 19 c9             	sbb    %r9,%r9
  458b8c:	4c 01 e0             	add    %r12,%rax
  458b8f:	49 83 d1 00          	adc    $0x0,%r9
  458b93:	4d 29 fd             	sub    %r15,%r13
  458b96:	4c 89 2c df          	mov    %r13,(%rdi,%rbx,8)
  458b9a:	4a 19 2c df          	sbb    %rbp,(%rdi,%r11,8)
  458b9e:	48 19 74 df 10       	sbb    %rsi,0x10(%rdi,%rbx,8)
  458ba3:	4c 19 4c df 18       	sbb    %r9,0x18(%rdi,%rbx,8)
  458ba8:	48 83 5c df 20 00    	sbbq   $0x0,0x20(%rdi,%rbx,8)
  458bae:	0f 92 c0             	setb   %al
  458bb1:	44 0f b6 f8          	movzbl %al,%r15d
  458bb5:	49 8d 46 28          	lea    0x28(%r14),%rax
  458bb9:	48 39 d0             	cmp    %rdx,%rax
  458bbc:	0f 84 0e ff ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458bc2:	4c 29 7c df 28       	sub    %r15,0x28(%rdi,%rbx,8)
  458bc7:	0f 92 c0             	setb   %al
  458bca:	45 31 ff             	xor    %r15d,%r15d
  458bcd:	41 88 c7             	mov    %al,%r15b
  458bd0:	48 83 fb 07          	cmp    $0x7,%rbx
  458bd4:	0f 84 f6 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458bda:	49 8d 46 30          	lea    0x30(%r14),%rax
  458bde:	48 39 d0             	cmp    %rdx,%rax
  458be1:	0f 84 e9 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458be7:	4c 29 7c df 30       	sub    %r15,0x30(%rdi,%rbx,8)
  458bec:	0f 92 c0             	setb   %al
  458bef:	45 31 ff             	xor    %r15d,%r15d
  458bf2:	41 88 c7             	mov    %al,%r15b
  458bf5:	48 83 fb 06          	cmp    $0x6,%rbx
  458bf9:	0f 84 d1 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458bff:	49 8d 46 38          	lea    0x38(%r14),%rax
  458c03:	48 39 d0             	cmp    %rdx,%rax
  458c06:	0f 84 c4 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c0c:	4c 29 7c df 38       	sub    %r15,0x38(%rdi,%rbx,8)
  458c11:	0f 92 c0             	setb   %al
  458c14:	45 31 ff             	xor    %r15d,%r15d
  458c17:	41 88 c7             	mov    %al,%r15b
  458c1a:	48 83 fb 05          	cmp    $0x5,%rbx
  458c1e:	0f 84 ac fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c24:	49 8d 46 40          	lea    0x40(%r14),%rax
  458c28:	48 39 d0             	cmp    %rdx,%rax
  458c2b:	0f 84 9f fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c31:	4c 29 7c df 40       	sub    %r15,0x40(%rdi,%rbx,8)
  458c36:	0f 92 c0             	setb   %al
  458c39:	45 31 ff             	xor    %r15d,%r15d
  458c3c:	41 88 c7             	mov    %al,%r15b
  458c3f:	48 83 fb 04          	cmp    $0x4,%rbx
  458c43:	0f 84 87 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c49:	49 8d 46 48          	lea    0x48(%r14),%rax
  458c4d:	48 39 d0             	cmp    %rdx,%rax
  458c50:	0f 84 7a fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c56:	4c 29 7c df 48       	sub    %r15,0x48(%rdi,%rbx,8)
  458c5b:	0f 92 c0             	setb   %al
  458c5e:	45 31 ff             	xor    %r15d,%r15d
  458c61:	41 88 c7             	mov    %al,%r15b
  458c64:	48 83 fb 03          	cmp    $0x3,%rbx
  458c68:	0f 84 62 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c6e:	49 8d 46 50          	lea    0x50(%r14),%rax
  458c72:	48 39 d0             	cmp    %rdx,%rax
  458c75:	0f 84 55 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c7b:	4c 29 7c df 50       	sub    %r15,0x50(%rdi,%rbx,8)
  458c80:	0f 92 c0             	setb   %al
  458c83:	45 31 ff             	xor    %r15d,%r15d
  458c86:	41 88 c7             	mov    %al,%r15b
  458c89:	48 83 fb 02          	cmp    $0x2,%rbx
  458c8d:	0f 84 3d fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458c93:	49 8d 46 58          	lea    0x58(%r14),%rax
  458c97:	48 39 d0             	cmp    %rdx,%rax
  458c9a:	0f 84 30 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458ca0:	4c 29 7c df 58       	sub    %r15,0x58(%rdi,%rbx,8)
  458ca5:	0f 92 c0             	setb   %al
  458ca8:	45 31 ff             	xor    %r15d,%r15d
  458cab:	41 88 c7             	mov    %al,%r15b
  458cae:	48 83 fb 01          	cmp    $0x1,%rbx
  458cb2:	0f 84 18 fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458cb8:	49 8d 46 60          	lea    0x60(%r14),%rax
  458cbc:	48 39 d0             	cmp    %rdx,%rax
  458cbf:	0f 84 0b fe ff ff    	je     458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458cc5:	31 c0                	xor    %eax,%eax
  458cc7:	4e 29 7c 37 60       	sub    %r15,0x60(%rdi,%r14,1)
  458ccc:	0f 92 c0             	setb   %al
  458ccf:	49 89 c7             	mov    %rax,%r15
  458cd2:	e9 f9 fd ff ff       	jmp    458ad0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place+0x50>
  458cd7:	4c 8b 57 30          	mov    0x30(%rdi),%r10
  458cdb:	4c 8b 4f 38          	mov    0x38(%rdi),%r9
  458cdf:	48 bd 00 00 00 00 ff 	movabs $0xffffffff00000000,%rbp
  458ce6:	ff ff ff 
  458ce9:	48 ba 00 00 00 00 01 	movabs $0x100000000,%rdx
  458cf0:	00 00 00 
  458cf3:	4c 01 ca             	add    %r9,%rdx
  458cf6:	49 39 e9             	cmp    %rbp,%r9
  458cf9:	0f 92 c0             	setb   %al
  458cfc:	41 b8 ff ff ff ff    	mov    $0xffffffff,%r8d
  458d02:	4d 39 c2             	cmp    %r8,%r10
  458d05:	48 83 da 00          	sbb    $0x0,%rdx
  458d09:	0f 92 c3             	setb   %bl
  458d0c:	08 c3                	or     %al,%bl
  458d0e:	4c 8b 5f 40          	mov    0x40(%rdi),%r11
  458d12:	4c 8b 6f 48          	mov    0x48(%rdi),%r13
  458d16:	4d 89 e8             	mov    %r13,%r8
  458d19:	49 ff c0             	inc    %r8
  458d1c:	0f 95 c0             	setne  %al
  458d1f:	80 c3 ff             	add    $0xff,%bl
  458d22:	4d 89 df             	mov    %r11,%r15
  458d25:	49 83 df fe          	sbb    $0xfffffffffffffffe,%r15
  458d29:	49 83 d8 00          	sbb    $0x0,%r8
  458d2d:	0f 92 c3             	setb   %bl
  458d30:	08 c3                	or     %al,%bl
  458d32:	0f b6 c3             	movzbl %bl,%eax
  458d35:	4c 8b 77 50          	mov    0x50(%rdi),%r14
  458d39:	4c 89 f3             	mov    %r14,%rbx
  458d3c:	48 ff c3             	inc    %rbx
  458d3f:	41 0f 95 c4          	setne  %r12b
  458d43:	48 29 c3             	sub    %rax,%rbx
  458d46:	0f 92 c0             	setb   %al
  458d49:	44 08 e0             	or     %r12b,%al
  458d4c:	0f b6 c0             	movzbl %al,%eax
  458d4f:	4c 8b 67 58          	mov    0x58(%rdi),%r12
  458d53:	4c 89 64 24 f0       	mov    %r12,-0x10(%rsp)
  458d58:	49 ff c4             	inc    %r12
  458d5b:	40 0f 94 c6          	sete   %sil
  458d5f:	49 29 c4             	sub    %rax,%r12
  458d62:	49 8d 44 2a 01       	lea    0x1(%r10,%rbp,1),%rax
  458d67:	40 0f 93 c5          	setae  %bpl
  458d6b:	40 20 f5             	and    %sil,%bpl
  458d6e:	40 0f b6 ed          	movzbl %bpl,%ebp
  458d72:	48 0b 6f 60          	or     0x60(%rdi),%rbp
  458d76:	48 09 cd             	or     %rcx,%rbp
  458d79:	48 89 e9             	mov    %rbp,%rcx
  458d7c:	48 f7 d9             	neg    %rcx
  458d7f:	48 ff cd             	dec    %rbp
  458d82:	49 21 ea             	and    %rbp,%r10
  458d85:	48 21 c8             	and    %rcx,%rax
  458d88:	4c 09 d0             	or     %r10,%rax
  458d8b:	48 89 47 30          	mov    %rax,0x30(%rdi)
  458d8f:	49 21 e9             	and    %rbp,%r9
  458d92:	48 21 ca             	and    %rcx,%rdx
  458d95:	4c 09 ca             	or     %r9,%rdx
  458d98:	48 89 57 38          	mov    %rdx,0x38(%rdi)
  458d9c:	49 21 eb             	and    %rbp,%r11
  458d9f:	49 21 cf             	and    %rcx,%r15
  458da2:	4d 09 df             	or     %r11,%r15
  458da5:	4c 89 7f 40          	mov    %r15,0x40(%rdi)
  458da9:	49 21 ed             	and    %rbp,%r13
  458dac:	49 21 c8             	and    %rcx,%r8
  458daf:	4d 09 e8             	or     %r13,%r8
  458db2:	4c 89 47 48          	mov    %r8,0x48(%rdi)
  458db6:	49 21 ee             	and    %rbp,%r14
  458db9:	48 21 cb             	and    %rcx,%rbx
  458dbc:	4c 09 f3             	or     %r14,%rbx
  458dbf:	48 89 5f 50          	mov    %rbx,0x50(%rdi)
  458dc3:	48 23 6c 24 f0       	and    -0x10(%rsp),%rbp
  458dc8:	4c 21 e1             	and    %r12,%rcx
  458dcb:	48 09 e9             	or     %rbp,%rcx
  458dce:	48 89 4f 58          	mov    %rcx,0x58(%rdi)
  458dd2:	48 8b 74 24 f8       	mov    -0x8(%rsp),%rsi
  458dd7:	5b                   	pop    %rbx
  458dd8:	41 5c                	pop    %r12
  458dda:	41 5d                	pop    %r13
  458ddc:	41 5e                	pop    %r14
  458dde:	41 5f                	pop    %r15
  458de0:	5d                   	pop    %rbp
  458de1:	48 83 fe 0d          	cmp    $0xd,%rsi
  458de5:	0f 93 c0             	setae  %al
  458de8:	c3                   	ret

### openssl_rs::bn::solinas::mont_mul_p384_fallible  (0x458df0, 681 bytes)

/court/tmp/pfp59/after/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

0000000000458df0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible>:
  458df0:	55                   	push   %rbp
  458df1:	41 57                	push   %r15
  458df3:	41 56                	push   %r14
  458df5:	41 55                	push   %r13
  458df7:	41 54                	push   %r12
  458df9:	53                   	push   %rbx
  458dfa:	48 83 ec 28          	sub    $0x28,%rsp
  458dfe:	48 83 f2 06          	xor    $0x6,%rdx
  458e02:	49 83 f0 06          	xor    $0x6,%r8
  458e06:	49 09 d0             	or     %rdx,%r8
  458e09:	74 19                	je     458e24 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x34>
  458e0b:	48 c7 07 ff ff ff ff 	movq   $0xffffffffffffffff,(%rdi)
  458e12:	48 89 f8             	mov    %rdi,%rax
  458e15:	48 83 c4 28          	add    $0x28,%rsp
  458e19:	5b                   	pop    %rbx
  458e1a:	41 5c                	pop    %r12
  458e1c:	41 5d                	pop    %r13
  458e1e:	41 5e                	pop    %r14
  458e20:	41 5f                	pop    %r15
  458e22:	5d                   	pop    %rbp
  458e23:	c3                   	ret
  458e24:	48 89 cb             	mov    %rcx,%rbx
  458e27:	49 89 f4             	mov    %rsi,%r12
  458e2a:	48 89 3c 24          	mov    %rdi,(%rsp)
  458e2e:	48 8d 7c 24 10       	lea    0x10(%rsp),%rdi
  458e33:	ba 08 00 00 00       	mov    $0x8,%edx
  458e38:	b9 0d 00 00 00       	mov    $0xd,%ecx
  458e3d:	41 b8 08 00 00 00    	mov    $0x8,%r8d
  458e43:	41 b9 08 00 00 00    	mov    $0x8,%r9d
  458e49:	31 f6                	xor    %esi,%esi
  458e4b:	e8 30 c0 d0 ff       	call   164e80 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.2820007963466305595>
  458e50:	80 7c 24 10 00       	cmpb   $0x0,0x10(%rsp)
  458e55:	74 06                	je     458e5d <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x6d>
  458e57:	48 8b 3c 24          	mov    (%rsp),%rdi
  458e5b:	eb ae                	jmp    458e0b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x1b>
  458e5d:	4c 8b 74 24 18       	mov    0x18(%rsp),%r14
  458e62:	0f 57 c0             	xorps  %xmm0,%xmm0
  458e65:	41 0f 11 46 50       	movups %xmm0,0x50(%r14)
  458e6a:	41 0f 11 46 40       	movups %xmm0,0x40(%r14)
  458e6f:	41 0f 11 46 30       	movups %xmm0,0x30(%r14)
  458e74:	41 0f 11 46 20       	movups %xmm0,0x20(%r14)
  458e79:	41 0f 11 46 10       	movups %xmm0,0x10(%r14)
  458e7e:	41 0f 11 06          	movups %xmm0,(%r14)
  458e82:	49 c7 46 60 00 00 00 	movq   $0x0,0x60(%r14)
  458e89:	00 
  458e8a:	48 8b 03             	mov    (%rbx),%rax
  458e8d:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  458e92:	48 8b 73 08          	mov    0x8(%rbx),%rsi
  458e96:	48 8b 7b 10          	mov    0x10(%rbx),%rdi
  458e9a:	4c 8b 43 18          	mov    0x18(%rbx),%r8
  458e9e:	4c 8b 4b 20          	mov    0x20(%rbx),%r9
  458ea2:	4c 8b 53 28          	mov    0x28(%rbx),%r10
  458ea6:	49 8b 6e 28          	mov    0x28(%r14),%rbp
  458eaa:	31 c9                	xor    %ecx,%ecx
  458eac:	45 31 ed             	xor    %r13d,%r13d
  458eaf:	90                   	nop
  458eb0:	4b 8b 1c ec          	mov    (%r12,%r13,8),%rbx
  458eb4:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  458eb9:	48 f7 e3             	mul    %rbx
  458ebc:	49 89 d3             	mov    %rdx,%r11
  458ebf:	49 89 c7             	mov    %rax,%r15
  458ec2:	48 89 f0             	mov    %rsi,%rax
  458ec5:	48 f7 e3             	mul    %rbx
  458ec8:	49 01 cf             	add    %rcx,%r15
  458ecb:	4f 89 3c ee          	mov    %r15,(%r14,%r13,8)
  458ecf:	4f 13 5c ee 08       	adc    0x8(%r14,%r13,8),%r11
  458ed4:	0f 92 c1             	setb   %cl
  458ed7:	44 0f b6 f9          	movzbl %cl,%r15d
  458edb:	49 01 c3             	add    %rax,%r11
  458ede:	49 11 d7             	adc    %rdx,%r15
  458ee1:	4f 89 5c ee 08       	mov    %r11,0x8(%r14,%r13,8)
  458ee6:	48 89 f8             	mov    %rdi,%rax
  458ee9:	48 f7 e3             	mul    %rbx
  458eec:	31 c9                	xor    %ecx,%ecx
  458eee:	4f 03 7c ee 10       	add    0x10(%r14,%r13,8),%r15
  458ef3:	0f 92 c1             	setb   %cl
  458ef6:	49 01 c7             	add    %rax,%r15
  458ef9:	48 11 d1             	adc    %rdx,%rcx
  458efc:	4c 89 c0             	mov    %r8,%rax
  458eff:	48 f7 e3             	mul    %rbx
  458f02:	4f 89 7c ee 10       	mov    %r15,0x10(%r14,%r13,8)
  458f07:	45 31 ff             	xor    %r15d,%r15d
  458f0a:	4b 03 4c ee 18       	add    0x18(%r14,%r13,8),%rcx
  458f0f:	41 0f 92 c7          	setb   %r15b
  458f13:	48 01 c1             	add    %rax,%rcx
  458f16:	49 11 d7             	adc    %rdx,%r15
  458f19:	4b 89 4c ee 18       	mov    %rcx,0x18(%r14,%r13,8)
  458f1e:	4c 89 c8             	mov    %r9,%rax
  458f21:	48 f7 e3             	mul    %rbx
  458f24:	31 c9                	xor    %ecx,%ecx
  458f26:	4f 03 7c ee 20       	add    0x20(%r14,%r13,8),%r15
  458f2b:	0f 92 c1             	setb   %cl
  458f2e:	49 01 c7             	add    %rax,%r15
  458f31:	48 11 d1             	adc    %rdx,%rcx
  458f34:	4c 89 d0             	mov    %r10,%rax
  458f37:	48 f7 e3             	mul    %rbx
  458f3a:	31 db                	xor    %ebx,%ebx
  458f3c:	48 01 e9             	add    %rbp,%rcx
  458f3f:	0f 92 c3             	setb   %bl
  458f42:	48 01 c1             	add    %rax,%rcx
  458f45:	48 11 d3             	adc    %rdx,%rbx
  458f48:	4f 89 7c ee 20       	mov    %r15,0x20(%r14,%r13,8)
  458f4d:	4b 89 4c ee 28       	mov    %rcx,0x28(%r14,%r13,8)
  458f52:	4b 89 5c ee 30       	mov    %rbx,0x30(%r14,%r13,8)
  458f57:	49 ff c5             	inc    %r13
  458f5a:	48 89 dd             	mov    %rbx,%rbp
  458f5d:	4c 89 d9             	mov    %r11,%rcx
  458f60:	49 83 fd 06          	cmp    $0x6,%r13
  458f64:	0f 85 46 ff ff ff    	jne    458eb0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0xc0>
  458f6a:	be 0d 00 00 00       	mov    $0xd,%esi
  458f6f:	4c 89 f7             	mov    %r14,%rdi
  458f72:	e8 09 fb ff ff       	call   458a80 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place>
  458f77:	84 c0                	test   %al,%al
  458f79:	75 6a                	jne    458fe5 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x1f5>
  458f7b:	48 8b 04 24          	mov    (%rsp),%rax
  458f7f:	48 c7 00 ff ff ff ff 	movq   $0xffffffffffffffff,(%rax)
  458f86:	b8 07 00 00 00       	mov    $0x7,%eax
  458f8b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  458f90:	41 c6 44 06 f9 00    	movb   $0x0,-0x7(%r14,%rax,1)
  458f96:	41 c6 44 06 fa 00    	movb   $0x0,-0x6(%r14,%rax,1)
  458f9c:	41 c6 44 06 fb 00    	movb   $0x0,-0x5(%r14,%rax,1)
  458fa2:	41 c6 44 06 fc 00    	movb   $0x0,-0x4(%r14,%rax,1)
  458fa8:	41 c6 44 06 fd 00    	movb   $0x0,-0x3(%r14,%rax,1)
  458fae:	41 c6 44 06 fe 00    	movb   $0x0,-0x2(%r14,%rax,1)
  458fb4:	41 c6 44 06 ff 00    	movb   $0x0,-0x1(%r14,%rax,1)
  458fba:	41 c6 04 06 00       	movb   $0x0,(%r14,%rax,1)
  458fbf:	48 83 c0 08          	add    $0x8,%rax
  458fc3:	48 83 f8 6f          	cmp    $0x6f,%rax
  458fc7:	75 c7                	jne    458f90 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x1a0>
  458fc9:	be 68 00 00 00       	mov    $0x68,%esi
  458fce:	ba 08 00 00 00       	mov    $0x8,%edx
  458fd3:	4c 89 f7             	mov    %r14,%rdi
  458fd6:	ff 15 5c 78 48 00    	call   *0x48785c(%rip)        # 8e0838 <_DYNAMIC+0x15e0>
  458fdc:	48 8b 04 24          	mov    (%rsp),%rax
  458fe0:	e9 30 fe ff ff       	jmp    458e15 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x25>
  458fe5:	48 8d 7c 24 10       	lea    0x10(%rsp),%rdi
  458fea:	ba 08 00 00 00       	mov    $0x8,%edx
  458fef:	b9 06 00 00 00       	mov    $0x6,%ecx
  458ff4:	41 b8 08 00 00 00    	mov    $0x8,%r8d
  458ffa:	41 b9 08 00 00 00    	mov    $0x8,%r9d
  459000:	31 f6                	xor    %esi,%esi
  459002:	e8 79 be d0 ff       	call   164e80 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.2820007963466305595>
  459007:	80 7c 24 10 00       	cmpb   $0x0,0x10(%rsp)
  45900c:	0f 85 69 ff ff ff    	jne    458f7b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x18b>
  459012:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
  459017:	0f 57 c0             	xorps  %xmm0,%xmm0
  45901a:	0f 11 40 20          	movups %xmm0,0x20(%rax)
  45901e:	0f 11 40 10          	movups %xmm0,0x10(%rax)
  459022:	0f 11 00             	movups %xmm0,(%rax)
  459025:	41 0f 10 46 30       	movups 0x30(%r14),%xmm0
  45902a:	41 0f 10 4e 40       	movups 0x40(%r14),%xmm1
  45902f:	41 0f 10 56 50       	movups 0x50(%r14),%xmm2
  459034:	0f 11 00             	movups %xmm0,(%rax)
  459037:	0f 11 48 10          	movups %xmm1,0x10(%rax)
  45903b:	0f 11 50 20          	movups %xmm2,0x20(%rax)
  45903f:	48 8b 0c 24          	mov    (%rsp),%rcx
  459043:	48 c7 01 06 00 00 00 	movq   $0x6,(%rcx)
  45904a:	48 89 41 08          	mov    %rax,0x8(%rcx)
  45904e:	48 c7 41 10 06 00 00 	movq   $0x6,0x10(%rcx)
  459055:	00 
  459056:	b8 07 00 00 00       	mov    $0x7,%eax
  45905b:	41 c6 44 06 f9 00    	movb   $0x0,-0x7(%r14,%rax,1)
  459061:	41 c6 44 06 fa 00    	movb   $0x0,-0x6(%r14,%rax,1)
  459067:	41 c6 44 06 fb 00    	movb   $0x0,-0x5(%r14,%rax,1)
  45906d:	41 c6 44 06 fc 00    	movb   $0x0,-0x4(%r14,%rax,1)
  459073:	41 c6 44 06 fd 00    	movb   $0x0,-0x3(%r14,%rax,1)
  459079:	41 c6 44 06 fe 00    	movb   $0x0,-0x2(%r14,%rax,1)
  45907f:	41 c6 44 06 ff 00    	movb   $0x0,-0x1(%r14,%rax,1)
  459085:	41 c6 04 06 00       	movb   $0x0,(%r14,%rax,1)
  45908a:	48 83 c0 08          	add    $0x8,%rax
  45908e:	48 83 f8 6f          	cmp    $0x6f,%rax
  459092:	75 c7                	jne    45905b <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x26b>
  459094:	e9 30 ff ff ff       	jmp    458fc9 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas22mont_mul_p384_fallible+0x1d9>

### openssl_rs::bn::solinas::mont_reduce_p384_fallible  (0x4590a0, 449 bytes)

/court/tmp/pfp59/after/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

00000000004590a0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible>:
  4590a0:	41 57                	push   %r15
  4590a2:	41 56                	push   %r14
  4590a4:	41 54                	push   %r12
  4590a6:	53                   	push   %rbx
  4590a7:	48 83 ec 18          	sub    $0x18,%rsp
  4590ab:	48 83 fa 06          	cmp    $0x6,%rdx
  4590af:	76 16                	jbe    4590c7 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0x27>
  4590b1:	48 c7 07 ff ff ff ff 	movq   $0xffffffffffffffff,(%rdi)
  4590b8:	48 89 f8             	mov    %rdi,%rax
  4590bb:	48 83 c4 18          	add    $0x18,%rsp
  4590bf:	5b                   	pop    %rbx
  4590c0:	41 5c                	pop    %r12
  4590c2:	41 5e                	pop    %r14
  4590c4:	41 5f                	pop    %r15
  4590c6:	c3                   	ret
  4590c7:	49 89 f7             	mov    %rsi,%r15
  4590ca:	49 89 d4             	mov    %rdx,%r12
  4590cd:	48 89 fb             	mov    %rdi,%rbx
  4590d0:	48 89 e7             	mov    %rsp,%rdi
  4590d3:	ba 08 00 00 00       	mov    $0x8,%edx
  4590d8:	b9 0d 00 00 00       	mov    $0xd,%ecx
  4590dd:	41 b8 08 00 00 00    	mov    $0x8,%r8d
  4590e3:	41 b9 08 00 00 00    	mov    $0x8,%r9d
  4590e9:	31 f6                	xor    %esi,%esi
  4590eb:	e8 90 bd d0 ff       	call   164e80 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.2820007963466305595>
  4590f0:	80 3c 24 00          	cmpb   $0x0,(%rsp)
  4590f4:	74 0c                	je     459102 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0x62>
  4590f6:	48 89 df             	mov    %rbx,%rdi
  4590f9:	48 c7 03 ff ff ff ff 	movq   $0xffffffffffffffff,(%rbx)
  459100:	eb b6                	jmp    4590b8 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0x18>
  459102:	4c 8b 74 24 08       	mov    0x8(%rsp),%r14
  459107:	4c 89 e2             	mov    %r12,%rdx
  45910a:	48 c1 e2 03          	shl    $0x3,%rdx
  45910e:	0f 57 c0             	xorps  %xmm0,%xmm0
  459111:	41 0f 11 46 50       	movups %xmm0,0x50(%r14)
  459116:	41 0f 11 46 40       	movups %xmm0,0x40(%r14)
  45911b:	41 0f 11 46 30       	movups %xmm0,0x30(%r14)
  459120:	41 0f 11 46 20       	movups %xmm0,0x20(%r14)
  459125:	41 0f 11 46 10       	movups %xmm0,0x10(%r14)
  45912a:	41 0f 11 06          	movups %xmm0,(%r14)
  45912e:	49 c7 46 60 00 00 00 	movq   $0x0,0x60(%r14)
  459135:	00 
  459136:	4c 89 f7             	mov    %r14,%rdi
  459139:	4c 89 fe             	mov    %r15,%rsi
  45913c:	ff 15 fe 82 48 00    	call   *0x4882fe(%rip)        # 8e1440 <memcpy@GLIBC_2.14>
  459142:	be 0d 00 00 00       	mov    $0xd,%esi
  459147:	4c 89 f7             	mov    %r14,%rdi
  45914a:	e8 31 f9 ff ff       	call   458a80 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas18redc_p384_in_place>
  45914f:	84 c0                	test   %al,%al
  459151:	75 61                	jne    4591b4 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0x114>
  459153:	48 c7 03 ff ff ff ff 	movq   $0xffffffffffffffff,(%rbx)
  45915a:	b8 07 00 00 00       	mov    $0x7,%eax
  45915f:	90                   	nop
  459160:	41 c6 44 06 f9 00    	movb   $0x0,-0x7(%r14,%rax,1)
  459166:	41 c6 44 06 fa 00    	movb   $0x0,-0x6(%r14,%rax,1)
  45916c:	41 c6 44 06 fb 00    	movb   $0x0,-0x5(%r14,%rax,1)
  459172:	41 c6 44 06 fc 00    	movb   $0x0,-0x4(%r14,%rax,1)
  459178:	41 c6 44 06 fd 00    	movb   $0x0,-0x3(%r14,%rax,1)
  45917e:	41 c6 44 06 fe 00    	movb   $0x0,-0x2(%r14,%rax,1)
  459184:	41 c6 44 06 ff 00    	movb   $0x0,-0x1(%r14,%rax,1)
  45918a:	41 c6 04 06 00       	movb   $0x0,(%r14,%rax,1)
  45918f:	48 83 c0 08          	add    $0x8,%rax
  459193:	48 83 f8 6f          	cmp    $0x6f,%rax
  459197:	75 c7                	jne    459160 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0xc0>
  459199:	be 68 00 00 00       	mov    $0x68,%esi
  45919e:	ba 08 00 00 00       	mov    $0x8,%edx
  4591a3:	4c 89 f7             	mov    %r14,%rdi
  4591a6:	ff 15 8c 76 48 00    	call   *0x48768c(%rip)        # 8e0838 <_DYNAMIC+0x15e0>
  4591ac:	48 89 d8             	mov    %rbx,%rax
  4591af:	e9 07 ff ff ff       	jmp    4590bb <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0x1b>
  4591b4:	48 89 e7             	mov    %rsp,%rdi
  4591b7:	ba 08 00 00 00       	mov    $0x8,%edx
  4591bc:	b9 06 00 00 00       	mov    $0x6,%ecx
  4591c1:	41 b8 08 00 00 00    	mov    $0x8,%r8d
  4591c7:	41 b9 08 00 00 00    	mov    $0x8,%r9d
  4591cd:	31 f6                	xor    %esi,%esi
  4591cf:	e8 ac bc d0 ff       	call   164e80 <_RNvMs5_NtCs6i54tJFfzR_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsfBoMNNx3tZr_10openssl_rs.llvm.2820007963466305595>
  4591d4:	80 3c 24 00          	cmpb   $0x0,(%rsp)
  4591d8:	0f 85 75 ff ff ff    	jne    459153 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0xb3>
  4591de:	48 8b 44 24 08       	mov    0x8(%rsp),%rax
  4591e3:	0f 57 c0             	xorps  %xmm0,%xmm0
  4591e6:	0f 11 40 20          	movups %xmm0,0x20(%rax)
  4591ea:	0f 11 40 10          	movups %xmm0,0x10(%rax)
  4591ee:	0f 11 00             	movups %xmm0,(%rax)
  4591f1:	41 0f 10 46 30       	movups 0x30(%r14),%xmm0
  4591f6:	41 0f 10 4e 40       	movups 0x40(%r14),%xmm1
  4591fb:	41 0f 10 56 50       	movups 0x50(%r14),%xmm2
  459200:	0f 11 00             	movups %xmm0,(%rax)
  459203:	0f 11 48 10          	movups %xmm1,0x10(%rax)
  459207:	0f 11 50 20          	movups %xmm2,0x20(%rax)
  45920b:	48 c7 03 06 00 00 00 	movq   $0x6,(%rbx)
  459212:	48 89 43 08          	mov    %rax,0x8(%rbx)
  459216:	48 c7 43 10 06 00 00 	movq   $0x6,0x10(%rbx)
  45921d:	00 
  45921e:	b8 07 00 00 00       	mov    $0x7,%eax
  459223:	41 c6 44 06 f9 00    	movb   $0x0,-0x7(%r14,%rax,1)
  459229:	41 c6 44 06 fa 00    	movb   $0x0,-0x6(%r14,%rax,1)
  45922f:	41 c6 44 06 fb 00    	movb   $0x0,-0x5(%r14,%rax,1)
  459235:	41 c6 44 06 fc 00    	movb   $0x0,-0x4(%r14,%rax,1)
  45923b:	41 c6 44 06 fd 00    	movb   $0x0,-0x3(%r14,%rax,1)
  459241:	41 c6 44 06 fe 00    	movb   $0x0,-0x2(%r14,%rax,1)
  459247:	41 c6 44 06 ff 00    	movb   $0x0,-0x1(%r14,%rax,1)
  45924d:	41 c6 04 06 00       	movb   $0x0,(%r14,%rax,1)
  459252:	48 83 c0 08          	add    $0x8,%rax
  459256:	48 83 f8 6f          	cmp    $0x6f,%rax
  45925a:	75 c7                	jne    459223 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0x183>
  45925c:	e9 38 ff ff ff       	jmp    459199 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas25mont_reduce_p384_fallible+0xf9>

### openssl_rs::bn::solinas::is_p384  (0x459270, 67 bytes)

/court/tmp/pfp59/after/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

0000000000459270 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas7is_p384>:
  459270:	48 83 fe 06          	cmp    $0x6,%rsi
  459274:	75 3a                	jne    4592b0 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn7solinas7is_p384+0x40>
  459276:	48 8b 47 10          	mov    0x10(%rdi),%rax
  45927a:	48 8b 4f 18          	mov    0x18(%rdi),%rcx
  45927e:	48 23 4f 20          	and    0x20(%rdi),%rcx
  459282:	48 23 4f 28          	and    0x28(%rdi),%rcx
  459286:	48 ba 00 00 00 00 ff 	movabs $0xffffffff00000000,%rdx
  45928d:	ff ff ff 
  459290:	48 33 57 08          	xor    0x8(%rdi),%rdx
  459294:	be ff ff ff ff       	mov    $0xffffffff,%esi
  459299:	48 33 37             	xor    (%rdi),%rsi
  45929c:	48 09 d6             	or     %rdx,%rsi
  45929f:	48 83 f0 fe          	xor    $0xfffffffffffffffe,%rax
  4592a3:	48 09 f0             	or     %rsi,%rax
  4592a6:	48 f7 d1             	not    %rcx
  4592a9:	48 09 c1             	or     %rax,%rcx
  4592ac:	0f 94 c0             	sete   %al
  4592af:	c3                   	ret
  4592b0:	31 c0                	xor    %eax,%eax
  4592b2:	c3                   	ret
