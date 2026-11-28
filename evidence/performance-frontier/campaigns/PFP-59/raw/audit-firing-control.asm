
### pfp59_audit_canary  (0x0, 33 bytes)

/court/tmp/pfp59/canary.o:     file format elf64-x86-64


Disassembly of section .text.pfp59_audit_canary:

0000000000000000 <pfp59_audit_canary>:
   0:	48 83 e7 0f          	and    $0xf,%rdi
   4:	74 18                	je     1e <pfp59_audit_canary+0x1e>
   6:	48 8d 47 ff          	lea    -0x1(%rdi),%rax
   a:	48 8d 4f fe          	lea    -0x2(%rdi),%rcx
   e:	48 f7 e1             	mul    %rcx
  11:	48 0f a4 c2 3f       	shld   $0x3f,%rax,%rdx
  16:	48 8d 04 17          	lea    (%rdi,%rdx,1),%rax
  1a:	48 ff c8             	dec    %rax
  1d:	c3                   	ret
  1e:	31 c0                	xor    %eax,%eax
  20:	c3                   	ret

Disassembly of section .text.pfp59_audit_ct:

0000000000000000 <pfp59_audit_ct>:
   0:	48 89 f0             	mov    %rsi,%rax
   3:	48 39 f7             	cmp    %rsi,%rdi
   6:	48 0f 48 c7          	cmovs  %rdi,%rax
   a:	c3                   	ret
