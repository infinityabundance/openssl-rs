
/work/court/tmp/pfp4-a/distribution/libcrypto.so.3:     file format elf64-x86-64


Disassembly of section .text:

0000000000372cc0 <_RNvMsj_NtNtCsfBoMNNx3tZr_10openssl_rs2ec4p256NtB5_10P256Scalar12to_canonical>:
  372cc0:	push   %rbx
  372cc1:	sub    $0x70,%rsp
  372cc5:	mov    %rdi,%rbx
  372cc8:	xorps  %xmm0,%xmm0
  372ccb:	movaps %xmm0,0x60(%rsp)
  372cd0:	movaps %xmm0,0x50(%rsp)
  372cd5:	movaps %xmm0,0x30(%rsp)
  372cda:	movaps %xmm0,0x20(%rsp)
  372cdf:	movq   $0x0,0x40(%rsp)
  372ce8:	movups (%rsi),%xmm0
  372ceb:	movups 0x10(%rsi),%xmm1
  372cef:	movaps %xmm0,(%rsp)
  372cf3:	movaps %xmm1,0x10(%rsp)
  372cf8:	lea    0x306681(%rip),%rdx        # 679380 <anon.0dec71e70872e5073da43233f95f59cb.101.llvm.17852565183361025961>
  372cff:	lea    0x50(%rsp),%rdi
  372d04:	mov    %rsp,%rsi
  372d07:	movabs $0xccd1c8aaee00bc4f,%rcx
  372d11:	mov    $0x1,%r8d
  372d17:	call   *0x561eab(%rip)        # 8d4bc8 <_DYNAMIC+0x49c8>
  372d1d:	movb   $0x0,(%rsp)
  372d21:	movb   $0x0,0x1(%rsp)
  372d26:	movb   $0x0,0x2(%rsp)
  372d2b:	movb   $0x0,0x3(%rsp)
  372d30:	movb   $0x0,0x4(%rsp)
  372d35:	movb   $0x0,0x5(%rsp)
  372d3a:	movb   $0x0,0x6(%rsp)
  372d3f:	movb   $0x0,0x7(%rsp)
  372d44:	movb   $0x0,0x8(%rsp)
  372d49:	movb   $0x0,0x9(%rsp)
  372d4e:	movb   $0x0,0xa(%rsp)
  372d53:	movb   $0x0,0xb(%rsp)
  372d58:	movb   $0x0,0xc(%rsp)
  372d5d:	movb   $0x0,0xd(%rsp)
  372d62:	movb   $0x0,0xe(%rsp)
  372d67:	movb   $0x0,0xf(%rsp)
  372d6c:	movb   $0x0,0x10(%rsp)
  372d71:	movb   $0x0,0x11(%rsp)
  372d76:	movb   $0x0,0x12(%rsp)
  372d7b:	movb   $0x0,0x13(%rsp)
  372d80:	movb   $0x0,0x14(%rsp)
  372d85:	movb   $0x0,0x15(%rsp)
  372d8a:	movb   $0x0,0x16(%rsp)
  372d8f:	movb   $0x0,0x17(%rsp)
  372d94:	movb   $0x0,0x18(%rsp)
  372d99:	movb   $0x0,0x19(%rsp)
  372d9e:	movb   $0x0,0x1a(%rsp)
  372da3:	movb   $0x0,0x1b(%rsp)
  372da8:	movb   $0x0,0x1c(%rsp)
  372dad:	movb   $0x0,0x1d(%rsp)
  372db2:	movb   $0x0,0x1e(%rsp)
  372db7:	movb   $0x0,0x1f(%rsp)
  372dbc:	movb   $0x0,0x20(%rsp)
  372dc1:	movb   $0x0,0x21(%rsp)
  372dc6:	movb   $0x0,0x22(%rsp)
  372dcb:	movb   $0x0,0x23(%rsp)
  372dd0:	movb   $0x0,0x24(%rsp)
  372dd5:	movb   $0x0,0x25(%rsp)
  372dda:	movb   $0x0,0x26(%rsp)
  372ddf:	movb   $0x0,0x27(%rsp)
  372de4:	movb   $0x0,0x28(%rsp)
  372de9:	movb   $0x0,0x29(%rsp)
  372dee:	movb   $0x0,0x2a(%rsp)
  372df3:	movb   $0x0,0x2b(%rsp)
  372df8:	movb   $0x0,0x2c(%rsp)
  372dfd:	movb   $0x0,0x2d(%rsp)
  372e02:	movb   $0x0,0x2e(%rsp)
  372e07:	movb   $0x0,0x2f(%rsp)
  372e0c:	movb   $0x0,0x30(%rsp)
  372e11:	movb   $0x0,0x31(%rsp)
  372e16:	movb   $0x0,0x32(%rsp)
  372e1b:	movb   $0x0,0x33(%rsp)
  372e20:	movb   $0x0,0x34(%rsp)
  372e25:	movb   $0x0,0x35(%rsp)
  372e2a:	movb   $0x0,0x36(%rsp)
  372e2f:	movb   $0x0,0x37(%rsp)
  372e34:	movb   $0x0,0x38(%rsp)
  372e39:	movb   $0x0,0x39(%rsp)
  372e3e:	movb   $0x0,0x3a(%rsp)
  372e43:	movb   $0x0,0x3b(%rsp)
  372e48:	movb   $0x0,0x3c(%rsp)
  372e4d:	movb   $0x0,0x3d(%rsp)
  372e52:	movb   $0x0,0x3e(%rsp)
  372e57:	movb   $0x0,0x3f(%rsp)
  372e5c:	movb   $0x0,0x40(%rsp)
  372e61:	movb   $0x0,0x41(%rsp)
  372e66:	movb   $0x0,0x42(%rsp)
  372e6b:	movb   $0x0,0x43(%rsp)
  372e70:	movb   $0x0,0x44(%rsp)
  372e75:	movb   $0x0,0x45(%rsp)
  372e7a:	movb   $0x0,0x46(%rsp)
  372e7f:	movb   $0x0,0x47(%rsp)
  372e84:	movaps 0x50(%rsp),%xmm0
  372e89:	movaps 0x60(%rsp),%xmm1
  372e8e:	movups %xmm1,0x10(%rbx)
  372e92:	movups %xmm0,(%rbx)
  372e95:	mov    %rbx,%rax
  372e98:	add    $0x70,%rsp
  372e9c:	pop    %rbx
  372e9d:	ret
