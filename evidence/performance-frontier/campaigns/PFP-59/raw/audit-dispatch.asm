
### openssl_rs::bn::mont::solinas384_active  (0x2a6250, 93 bytes)

/court/tmp/pfp59/after/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

00000000002a6250 <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn4mont17solinas384_active>:
  2a6250:	31 c0                	xor    %eax,%eax
  2a6252:	80 7f 7c 02          	cmpb   $0x2,0x7c(%rdi)
  2a6256:	75 54                	jne    2a62ac <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn4mont17solinas384_active+0x5c>
  2a6258:	48 b9 01 00 00 00 01 	movabs $0x100000001,%rcx
  2a625f:	00 00 00 
  2a6262:	48 39 4f 60          	cmp    %rcx,0x60(%rdi)
  2a6266:	75 44                	jne    2a62ac <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn4mont17solinas384_active+0x5c>
  2a6268:	48 83 7f 28 06       	cmpq   $0x6,0x28(%rdi)
  2a626d:	75 3d                	jne    2a62ac <_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn4mont17solinas384_active+0x5c>
  2a626f:	48 8b 47 20          	mov    0x20(%rdi),%rax
  2a6273:	48 8b 48 10          	mov    0x10(%rax),%rcx
  2a6277:	48 8b 50 20          	mov    0x20(%rax),%rdx
  2a627b:	48 23 50 18          	and    0x18(%rax),%rdx
  2a627f:	48 23 50 28          	and    0x28(%rax),%rdx
  2a6283:	48 be 00 00 00 00 ff 	movabs $0xffffffff00000000,%rsi
  2a628a:	ff ff ff 
  2a628d:	48 33 70 08          	xor    0x8(%rax),%rsi
  2a6291:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  2a6296:	48 33 38             	xor    (%rax),%rdi
  2a6299:	48 09 f7             	or     %rsi,%rdi
  2a629c:	48 83 f1 fe          	xor    $0xfffffffffffffffe,%rcx
  2a62a0:	48 09 f9             	or     %rdi,%rcx
  2a62a3:	48 f7 d2             	not    %rdx
  2a62a6:	48 09 ca             	or     %rcx,%rdx
  2a62a9:	0f 94 c0             	sete   %al
  2a62ac:	c3                   	ret
