# PFP-65 — `STOP-AES-FALLBACK` at library scope: Camellia, ARIA, SM4

**Decision: SM4 is implemented as a constant-pattern S-box; Camellia and ARIA are
adjudicated and recorded, not implemented.** The three are *not* the same: Camellia
and ARIA are parity with the pinned authority's same path, SM4 is the one
own-weakness — the authority ships and dispatches to a table-free SM4 path, while
the crate had no table-free path at all. SM4 was therefore the strongest case and
the only one converted.

## 1. Identity

| | |
|---|---|
| source branch / HEAD | `staging` `5d14d7964c0adea5a37c9a6c00bcc14305bcf1c1`, worktree modified (not committed) |
| shipped DSO | `court/tmp/pfp68/final/libcrypto.so.3` |
| shipped DSO SHA-256 | `f53e2622112379f9a74b584a336b52cf282b7b38c83949efacb3a1a33c9ad926` |
| converted DSO | `court/tmp/pfp65/final/libcrypto.so.3` |
| converted DSO SHA-256 | `316b0adfa42135353c7115aa1880a852069020fe3923800e683ffd3fe6ffb42e` |
| authority | `forensics/authorities/src/openssl-3.6.4`; DSO `611e511d…` |
| CPU | 13th Gen Intel i9-13900K; flags `aes avx2 gfni vaes`, **no `sm4`**, no AVX-512 |
| raw | `raw/{identity,authority-path,authority-binary}.txt`, `raw/audit-{before,after}.{json,disasm.txt}`, `raw/sub_bytes.disasm.txt` |

The shipped DSO's cipher code is the current source's cipher code: `src/sm4.rs`,
`src/camellia.rs`, `src/aria.rs` and `src/cipher_tables.rs` are unchanged between the
PFP-68 source commit `c27e9373` and HEAD (the `git log` over that range is empty).
`court/tmp/pfp56/…` (`5b52e473…`) is a PFP-56 benchmark candidate from an
intermediate worktree, not the distribution artefact; the PFP-64 receipt is what
names `pfp68/final` as shipped.

**Worktree caveat.** The checkout carried pre-existing, uncommitted modifications
outside this batch (`src/bn/*`, `src/rsa/ossl.rs`, `src/dsa/ossl.rs`, `courts/…`,
`evidence/…/M-A1/…`). They were left untouched. The converted DSO was linked from
the whole worktree, so its digest is not attributable to this batch alone; the
symbol-scoped audit reads only the Camellia/ARIA/SM4 carriers, whose source is this
batch's `src/sm4.rs` plus the unchanged `src/camellia.rs` and `src/aria.rs`. No
freeze/graduation claim is made here.

## 2. Step 1 — source adjudication, per cipher

Every site below indexes a table by a **byte derived from secret data**. There is
no cipher whose tables are indexed by a public key-size or round counter.

| cipher | file:line | table | index source | where |
|---|---|---|---|---|
| Camellia | `src/camellia.rs:95,97,98,99,100,101,104,106` | `CAMELLIA_SBOX[0..3][256]` (`src/cipher_tables.rs:914`) | `t0 = s[0]^key[0]`, `t1 = s[1]^key[1]`, then bytes of `t0`/`t1` | data path and key schedule (same `feistel`, called from `ekeygen` at `162,167,178,181,264,267`; round-key setup at `392–482`) |
| ARIA | `src/aria.rs:316–319`, `328–331` | `S1/S2/X1/X2[256]` (`:73,:110,:147,:184`) | `GET_U8_BE(w,i)` — state bytes | data path; the same layers are used by the key schedule via `ARIA_SUBST_DIFF_{ODD,EVEN}` |
| ARIA | `src/aria.rs:474–498` | `X1/X2/S1/S2[256]` | `GET_U8_BE(t[i],j)` — state bytes | final round of `ossl_aria_encrypt` (the same function serves both directions on the schedule) |
| SM4 (before) | `src/sm4.rs:169–172` | `SM4_S[256]` (`:41`) | byte of `x` | `SM4_T_non_lin_sub`, used by `SM4_T_slow` and by `SM4_key_sub` (`:198–201`) |
| SM4 (before) | `src/sm4.rs:190–193` | `SM4_SBOX_T0..T3[256]` (`:64`) | byte of `x` | `SM4_T` in the six middle double-rounds |

`src/aria.rs:545` indexes `KEY_RC` by the public round counter; it is a constant
schedule and is **not** a secret-indexed site. The SM4 `CK` and Camellia `SIGMA`
constants are likewise public.

## 3. Step 2 — binary adjudication at the shipped digest

`nm -S` + `objdump -d -M intel`, ranges read from the shipped DSO. Counts are
from `raw/audit-before.json`; the instruction is a representative load, with the
index-producing instruction in the context.

| carrier | indexed loads | representative instruction | address source |
|---|---|---|---|
| `Camellia_encrypt` | 68 | `xor eax,DWORD PTR [r14+rbx*4+0x400]` | `rbx = movzx` of a `t0`/`t1` byte — **secret** |
| `Camellia_decrypt` | 68 | `xor ebp,DWORD PTR [r12+r8*4]` | state byte — **secret** |
| `Camellia_set_key` | 52 | `mov r10d,DWORD PTR [r13+rbp*4+0xc00]` | `rbp = movzx ch` — **key-schedule byte, secret** |
| `aria::ossl_aria_encrypt` | 68 | `mov r10d,DWORD PTR [r8+rdi*1]` | `rdi` from `shr r8d,0xe; and r8d,0x3fc` — **secret** |
| `aria::ossl_aria_set_encrypt_key` | 60 | `mov ecx,DWORD PTR [r11+rax*1]` | `r11` from state bits — **secret** |
| `sm4::ossl_sm4_encrypt` | 56 | `movzx eax,BYTE PTR [rax+r13*1]` (`r13=SM4_S`) | state byte — **secret** (plus `SM4_SBOX_T*` word loads) |
| `sm4::ossl_sm4_decrypt` | 56 | as above | **secret** |
| `sm4::ossl_sm4_set_key` | 24 | `movzx ebx,BYTE PTR [rbx+r10*1]` (`r10=SM4_S`) | key-schedule byte — **secret** |

All three are genuine table loads with secret-derived addresses. None was lowered
to arithmetic or a mask at this digest.

## 4. Step 3 — characterisation against the pinned authority

Authority binary and source evidence: `raw/authority-path.txt`,
`raw/authority-binary.txt`.

| cipher | authority same-path behaviour | classification |
|---|---|---|
| **Camellia** | asm `_x86_64_Camellia_encrypt`: 60 indexed loads, 56 at `*8` scale through `.LCamellia_SBOX`, indexed by state bytes; C key schedule uses the same `Camellia_SBOX`. There is no table-free Camellia path. | **PARITY** |
| **ARIA** | no `crypto/aria/asm` in 3.6.4; `ossl_aria_encrypt`: 64 scale-4 loads through `S1/S2/X1/X2`; key schedule likewise. | **PARITY** |
| **SM4** | ships/selects a **table-free** path `hw_x86_64_sm4_{set_key,encrypt,decrypt}` (`vsm4key4`/`vsm4rnds4`, constant shuffle masks) when `HWSM4_CAPABLE_X86_64`; that gate is `AVX2 && CPUID.(7,1):EAX[2]` (SM4 ISA). A direct CPUID probe in the court gives `HWSM4_CAPABLE_X86_64=0` (`raw/cpuid-sm4.txt`: AVX2=1, SM4 bit=0), so the authority's *same-path* code here is the C fallback `ossl_sm4_encrypt` (128 indexed loads). | **OWN-WEAKNESS** (design divergence: the authority has a table-free path, the crate had none); same-path binary **parity on this CPU**, recorded explicitly and **not** treated as discharge |

Parity is a finding, not a discharge. Reproducing an upstream internal weakness is
not required to reproduce upstream external semantics, but it also does not make
the crate's site safe. The SM4 own-weakness is established from the authority's
source, symbols and the CPU capability gate; the `vsm4rnds4` path was not executed
on this venue (no SM4 ISA), so no runtime trace of it is claimed.

## 5. Step 4 — implementation (SM4 only)

Files: `src/sm4/portable.rs` (new), `src/sm4.rs` (modified).

* `src/sm4/portable.rs` is `#![forbid(unsafe_code)]`, has no assembly and no
  intrinsics. It derives the ANF of the authority's `SM4_S` at compile time by the
  Möbius transform, then evaluates it as a 4-lane bitsliced XOR/AND circuit. The
  coefficient table `ANF` and the local monomial array are addressed only by
  public subset/output counters; coefficient 0/1 is expanded with
  `0u8.wrapping_sub` so there is no data-dependent branch.
* `src/sm4.rs`: `SM4_S` becomes a `const` (compile-time source of the ANF);
  `SM4_SBOX_T0..T3` and `derive_t` are now `#[cfg(test)]` references only;
  `SM4_T_non_lin_sub` calls `portable::sub_bytes`; `SM4_T` is the same
  constant-pattern transform as `SM4_T_slow`; `SM4_key_sub` keeps its rotations
  over the constant S-box.
* Exported key layout (`#[repr(C)] Sm4Key { rk: [u32; 32] }`) and every public
  symbol/signature are unchanged. Semantics are byte-identical (below).

Why SM4: it is the only own-weakness of the three, the only member for which a
table-free upstream path exists at all, and its exposure is the widest (middle-round
T-tables, outer-round byte S-box, and the key schedule all indexed by secret
bytes). The other two are parity and are scheduled rather than converted.

## 6. Correctness evidence

| check | result |
|---|---|
| official KAT | GB/T 32907-2016 / RFC 8998 vector, key=plaintext=`0123…3210`, ciphertext `681edf34d206965e86b3e94f536e4246` — passes, encrypt and decrypt. SM4 supports only the 128-bit key size, so this is "all key sizes it supports" |
| S-box exhaustive-lane differential | 3 fill patterns × 256 values × 4 lanes = **3072** inputs, `portable::sub_bytes` vs `SM4_S` reference — all equal |
| `SM4_T` differential | same 3072 plus **8192** random words against the retained `SM4_SBOX_T*` reference — all equal |
| `SM4_key_sub` differential | **8192** random words plus 256 single-lane values against `SM4_S` + rotations — all equal |
| mode/streaming tests | the full library suite below includes the EVP/provider SM4 mode tests |
| full library suite | **2585 passed / 0 failed / 56 ignored** (baseline 2581 + 4 new tests); no newly ignored test |

## 7. Post-conversion audit and firing control

`raw/audit-after.json`, `raw/sub_bytes.disasm.txt`.

| carrier | before | after |
|---|---:|---:|
| `sm4::$ossl_sm4_encrypt` | 56 | **8** |
| `sm4::$ossl_sm4_decrypt` | 56 | **8** |
| `sm4::$ossl_sm4_set_key` | 24 | **8** |
| `sm4::portable::sub_bytes` | absent | 15 |

The only SM4 rodata table left is `openssl_rs::sm4::portable::ANF` (0x800 bytes);
`SM4_S` and `SM4_SBOX_T0..T3` are **absent** from the DSO. In `sub_bytes` all 15
indexed operands are either the stack monomial array (`[rsp+rax*1+0x88]`) or
`ANF` (`[rax+rcx*1+0x100]`…`0x800`, `rcx = ANF`, `rax` a loop counter), and the
two `jcc` are `cmp …,0x100` / `add rax,0x10` loop bounds. No state or key byte
selects an address. The 8 remaining indexed operands in `ossl_sm4_{encrypt,decrypt}`
are round-key loads (`[r14+rdi*4]`, `rdi` bounds-checked against `0x1f`) and stack
spill slots indexed by the public round pointer.

**Firing control.** The detector still fires on the unchanged carriers:
Camellia (68/68/52) and ARIA (68/60) keep their secret-byte-indexed loads after
the build, and the pre-conversion SM4 counts (56/24) are the historical positive
control for the same carrier. The audit was not weakened to obtain the zero.

## 8. Recorded obligation and plan for the other two

These are **recorded, not implemented**; parity is not discharge.

* **Camellia** — sites `src/camellia.rs:95–106` (data and key schedule); table
  `src/cipher_tables.rs:914`. Plan: the four tables are one 8-bit S-box with byte
  replications/rotations, so derive a single ANF circuit from the low byte of
  `CAMELLIA_SBOX[0]` and replace the eight loads with the constant S-box plus
  arithmetic replication/rotation; retain the tables as `#[cfg(test)]`
  references and add an exhaustive lane differential. One circuit, moderately
  bounded.
* **ARIA** — sites `src/aria.rs:316–319`, `328–331`, `474–498`; tables
  `:73,:110,:147,:184`. Plan: unlike Camellia, ARIA has four distinct S-boxes
  (`SB1..SB4`); derive four ANF circuits (or one combined circuit) and replace
  the three sites; retain the tables for differential. Larger than Camellia and
  best done as its own batch.

Both remain PARITY against the authority's same path; scheduling them is an
improvement beyond external parity, not a compatibility requirement.

## 9. Memory discipline

Court cap is the §24.4 operative formula `min(4, available−8)` GiB, floor 2.
Measured `available`/swap-free before the heavy commands that were directly
preceded by a measurement; commands between measurements inherited the same 4 GiB
court (the container had `memory.max=4294967296`, `oom=0` throughout).

| command | available | swap free | cap |
|---|---:|---:|---:|
| `cargo check --lib` | 17 GiB | 2 GiB | 4 GiB |
| `cargo test --lib sm4` | 17–19 GiB (inherited) | 0–2 GiB | 4 GiB |
| `cargo clippy --all-targets` | 17–19 GiB (inherited) | 0–2 GiB | 4 GiB |
| `cargo test --lib -- --test-threads=4` | 19 GiB | 2 GiB | 4 GiB |
| `cargo build --release --lib` + link | 19 GiB | 2 GiB | 4 GiB |

One heavy command at a time; `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`.
No release `--test` build was run.

## 10. Gate

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo test --lib -- --test-threads=4` | **2585 passed / 0 failed / 56 ignored** (baseline 2581; +4 new; no new ignores) |

## 11. Residuals / NOT_RUN

* **ctgrind / dudect: `NOT_RUN` on this venue.** No constant-time claim is made.
  The claim is source-level constant pattern: no secret-dependent branch and no
  secret-indexed address in the SM4 carriers at the converted digest.
* Camellia and ARIA conversions: **NOT_IMPLEMENTED** (recorded above).
* Authority `vsm4rnds4` table-free path: not executed on this CPU (no `sm4`
  flag); the own-weakness is a source/symbol/capability finding, not a runtime
  trace of that path.
* Miri/ASan on the new portable module: **NOT_RUN**; the module forbids unsafe
  code, and its correctness is established by the differential tests above.
