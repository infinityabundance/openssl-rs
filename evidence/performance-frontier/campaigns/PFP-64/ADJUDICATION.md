# PFP-64 — POLYVAL adjudication at the shipped DSO

**Decision: POLYVAL is already table-free on the fast path and constant-pattern
on the portable path. No code change is required and none was made.** The
remaining row text ("POLYVAL remains TODO") is superseded by this record.

## 1. Identity

| | |
|---|---|
| source HEAD | `staging` `89490a1aa5c60a5eb602c409f4936608a5bd5e27` (PFP-68 commit; no source change in this batch) |
| shipped DSO | `court/tmp/pfp68/final/libcrypto.so.3` |
| DSO SHA-256 | `f53e2622112379f9a74b584a336b52cf282b7b38c83949efacb3a1a33c9ad926` |
| DSO size | 17 185 416 B |
| authority | `openssl-3.6.4-production` DSO `611e511d…`, static archive used for the POLYVAL oracle |
| instrument | `evidence/performance-frontier/campaigns/PFP-64/audit_pfp64.py` (the PFP-63 `nm -S` + `objdump -d -M intel` classifier) |
| raw | `raw/audit-after.json`, `raw/audit-after.disasm.txt` |

The DSO is the PFP-68 final distribution-shaped artefact (same SHA-256 as
`campaigns/PFP-68/raw/identity.txt`). The PFP-64 batch edited no `src/`, so this
remains the shipped DSO.

## 2. What carries POLYVAL

POLYVAL is `src/provider/cipher.rs`'s `polyval_ghash_init` / `polyval_ghash_hash`
(AES-GCM-SIV). `polyval_ghash_init` and its `mulx_ghash` helper are inlined;
`polyval_ghash_hash` is an out-of-line symbol. The field multiply is the shared
`src/modes/gcm.rs::gf_mul`, which dispatches once to `gf_mul_clmul` (PCLMULQDQ)
or `gf_mul_portable`.

## 3. Carrier counts (verbatim from `raw/audit-after.json`)

| carrier | insns | jcc | setcc | cmov | indexed memory | crypto |
|---|---:|---:|---:|---:|---:|---|
| `provider::cipher::polyval_ghash_hash` | 227 | 9 | 0 | 0 | 10 | — |
| `modes::gcm::gf_mul_clmul` | 53 | **0** | **0** | **0** | **0** | 4× `pclmul*` |
| `modes::gcm::gf_mul_portable` | 50 | 1 | 0 | 4 | 0 | — |
| `provider::cipher::aes_gcm_siv_encrypt` | 145 | 6 | 3 | 0 | 0 | — |
| `provider::cipher::aes_gcm_siv_decrypt` | 145 | 7 | 2 | 0 | 0 | — |
| `provider::cipher::aes_gcm_siv_initkey` (AES-ECB key derivation, not POLYVAL) | 377 | 53 | 6 | 9 | 2 | — |

## 4. Every conditional in the POLYVAL helper

`polyval_ghash_hash` has **no `setcc` and no `cmov`**. All nine `jcc` sites are
classified by the quantity whose flags they read:

| addr | transfer | flag provenance | classification |
|---|---|---|---|
| `0x41a131` | `jae` | `cmp r14,0x10` (`r14` = block length) | public length |
| `0x41a178` | `ja` | `add rbx,0x10; cmp rbx,r14` | public loop bound |
| `0x41a1f5` | `je` | `mov rcx,[std_detect::cache::CACHE]; test rcx,rcx` | public CPU-feature cache |
| `0x41a1fa` | `je` | `test cl,0x2` | public CPU-feature bit |
| `0x41a208` | `jne` | `mov ecx,[…DECISIONS+0x50]; test ecx,ecx` | public capability decision |
| `0x41a239` | `jne` | `test rcx,0x200000000` | public PCLMULQDQ capability bit |
| `0x41a24e` | `je` | `test rcx,0x200000000` | public capability |
| `0x41a26c` | `jbe` | `add rbx,0x10; cmp rbx,r14` | public loop bound |
| `0x41a28a` | `je` | `mov rax,[rsp+8]; test cl,0x2` | public capability |

`gf_mul_portable` has one `jcc`, the fixed 128-iteration back-edge
(`0x40e8c8 jb` after `add ecx,0xffffffff`; `ecx` starts `0x7f`), and four
`cmov` mask selections (`0x40e8a0`, `0x40e8a4`, `0x40e8b1`, `0x40e8b5`) on
`test cl,0x40` / `cmove`. `gf_mul_clmul` has none of `jcc`/`setcc`/`cmov`.

`polyval_ghash_init` / `mulx_ghash` are inlined into `aes_gcm_siv_encrypt`.
The `x^-1` conditional (`if t1 & 1 == 1`) compiles to a mask, not a transfer:

```
41a732: and eax,0x1
41a738: movabs r8,0xe100000000000000
41a742: and r8,rax
```

No `jcc`, `setcc` or `cmov` belongs to it. The six encrypt and seven decrypt
`jcc` sites are length/flag/error checks (`test rcx,rcx`,
`cmp r15,0xfffffffffffffff0`, `and …,0xf`), and the `setcc` sites are length
tests (`cmp eax,0x8`, `cmp r14,0x1000000000`, `test ebp,ebp`).

## 5. Every indexed memory operand

`polyval_ghash_hash` has ten, and **none is indexed by secret state or by the
key**:

| addr | instruction | index | classification |
|---|---|---|---|
| `0x41a17e`…`0x41a1a8` (8×) | `movzx …,BYTE PTR [r15+rbx*1-0x8…-0x1]` | `rbx` = `0x10, 0x20, …` block offset | **input bytes at a public loop index** |
| `0x41a1e3` | `xor rax,QWORD PTR [r15+rbx*1-0x10]` | `rbx` | **input word at a public loop index** |
| `0x41a223` | `movsxd rdx,DWORD PTR [rsi+rdx*4]` | `rdx` loaded from `runtime::cpu::decisions::DECISIONS` | **rodata jump table, public capability index** |

`gf_mul_clmul` and `gf_mul_portable` have **zero** indexed memory operands.
`aes_gcm_siv_encrypt` and `_decrypt` have zero. `aes_gcm_siv_initkey` has one
real indexed store (`0x41ab4c mov QWORD PTR [rbx+r14*1+0x58],rax`), where
`r14 = 0, 8, …` up to the public `ctx->keylen` at `[rbx+0x30]`; it is the
AES-ECB key-derivation loop, not POLYVAL, and its address is a public length
index. The other match is a `nop`.

## 6. Finding

* **No secret-indexed table, no secret-derived transfer, no secret-derived
  address** in the POLYVAL path at this digest.
* The fast path (`gf_mul_clmul`) is table-free: four `pclmul` operations, a
  fixed two-fold Alg9 reduction, no memory indexed by an operand.
* The portable path (`gf_mul_portable`) is constant-pattern: fixed 128
  iterations, mask-selected `v` and reduction, no address depends on an operand.
  Its four `cmov`s are **observed, not proved** to be timing-independent.
* `mulx_ghash`'s `x^-1` step is an arithmetic `and` mask; `byte_reverse16` is a
  fixed byte permutation.
* **No STOP fired**, so no fix was required and none was made. This is an
  instruction observation, not a constant-time proof; no cache-timing/dudect
  claim is made.

## 7. Correctness

* POLYVAL KAT (authority-oracle values,
  `the_polyval_helpers_match_the_authority_oracle`): **1 test, 3 checks, pass**
  (`raw/kat-unit-test.txt`).
* Authority differential: the pinned static archive's own
  `ossl_polyval_ghash_init`/`_hash` were rebuilt and executed in this batch
  (`raw/oracle-polyval.txt`); the three outputs are byte-equal to the candidate
  KAT's expected values — **3/3, 0 mismatches**.
* AES-GCM-SIV known-answer vectors (RFC 8452, mirrored in the pinned corpus):
  `CT-CIPHER` `gcm_siv` family — **50/50 pass, 0 failed**
  (`raw/ct-cipher-gcm-siv.json`).
