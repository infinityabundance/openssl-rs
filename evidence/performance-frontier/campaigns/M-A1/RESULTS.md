# M-A1 — fixed-width native Rust specialisation of the CIOS kernel: results

**Status: admitted performance candidate at DSO `88c0c7e0…`; the generic slice
kernel remains the differential reference and the fallback.** The width
specialisation is in `src/`; nothing in the window ladder, the squaring path,
the schedule selection, the allocator seam or any `#[repr(C)]` layout changed.
The candidate is an uncommitted worktree state on `staging` `ff87f848`.

## 1. Identity

| item | value |
|---|---|
| source commit | `ff87f8488e206896ffdd82259af2fcf4ba269209` (`staging`) + uncommitted `src/bn/arith.rs` |
| `src/bn/arith.rs` sha256 (candidate) | `b548ee1533f527366099d95b907bd20237bbcc2e8208966eb9a15cf11f09809f` |
| `src/bn/arith.rs` sha256 (previous) | `3e8127cb1eb816b9db066eb52ce1535620aa9c812bec0b441c627fdb9100aea1` |
| `src` fingerprint | `28bbd83eb9b57a6ba95ad3025778ccc7eaa482714079cf03f8c48a0acf7f9235` (887 files) |
| `build_relevant_clean` | **false** — the specialisation is an uncommitted worktree change |
| toolchain | rustc 1.98.1 (48a229cea), cargo 1.98.1 (797e8a9bc), cc 12.2.0, x86_64-unknown-linux-gnu |
| profile | `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4` |

| arm | role | DSO sha256 | bytes | build id |
|---|---|---|---:|---|
| **cand** | admitted candidate (eight const-generic CIOS kernels) | `88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87` | 17,119,856 | `09e7313b…` |
| **cand2** | cand rebuilt in a fresh `CARGO_TARGET_DIR` | **identical to cand** (archive also identical, `2ec133ca…`) | 17,119,856 | identical |
| **prev** | HEAD's `src/bn/arith.rs` (generic slice kernel, CIOS) | `6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39` | 17,118,904 | `05a6b994…` |

A second clean build reproduces the candidate digest byte for byte (`cmp` of the
DSOs and the static archives). The **prev** build reproduces the PFP-6 admitted
DSO `6d002db2` exactly, so the paired comparison is against the admitted
incumbent, not a re-shaped reference.

## 2. Dispatch

`mont_mul_ladder_into` checks the public geometry once, then selects on the
modulus' limb count; everything not listed falls back to the generic slice
kernel. The accumulator is the first `ACC = N + 2` limbs of the caller's `t`
(a `SecretBuf`), so cleansing is unchanged.

| modulus limbs | kernel | `ACC` | workload that exercises it |
|---:|---|---:|---|
| 4 | `mont_mul_cios_fixed::<4, 6>` | 6 | `ecdsa256` (P-256 order) |
| 6 | `mont_mul_cios_fixed::<6, 8>` | 8 | P-384 order (not in the frozen set) |
| 9 | `mont_mul_cios_fixed::<9, 11>` | 11 | P-521 order (not in the frozen set) |
| 16 | `mont_mul_cios_fixed::<16, 18>` | 18 | `rsa2048` CRT primes |
| 32 | `mont_mul_cios_fixed::<32, 34>` | 34 | `modexp2048`, `dh-*-2048`, non-CRT RSA |
| 48 | `mont_mul_cios_fixed::<48, 50>` | 50 | `dh-*-3072` |
| 64 | `mont_mul_cios_fixed::<64, 66>` | 66 | 4096-bit (not in the frozen set) |
| 128 | `mont_mul_cios_fixed::<128, 130>` | 130 | `modexp8192` |
| other | `mont_mul_cios_into` | `n + 2` | fallback |

The CIOS schedule and the `T_i < 2m` accumulator bound are inherited verbatim:
the specialised body is the same product row, reduction row and masked final
subtraction with the same `N + 2` accumulator extent. No bound is re-derived
and no schedule, window, squaring or conversion step changed.

## 3. Correctness — per-width differential (before timing)

Population per width: two odd moduli with a non-zero top limb (a pseudorandom
one and `R - 1`, the all-ones modulus), operands from `0`, `1`, `m-1`, `m-2`, a
one-limb value, every single-non-zero-limb value (all positions for `n <= 16`,
a boundary/midpoint sample otherwise), the all-ones vector where it is below
`m`, and a deterministic random sweep reduced into `[0, m)`. Every pair runs
through the dispatch boundary and through the generic slice kernel, must be
**bit-identical**, and must also satisfy `out·R ≡ a·b (mod m)` with `out < m`
(`pfp6_assert_congruent`).

| width (limbs) | differential pairs | congruence checks | mismatches |
|---:|---:|---:|---:|

| 4 | 882 | 882 | 0 |
| 6 | 1058 | 1058 | 0 |
| 9 | 1352 | 1352 | 0 |
| 16 | 2178 | 2178 | 0 |
| 32 | 968 | 968 | 0 |
| 48 | 968 | 968 | 0 |
| 64 | 392 | 392 | 0 |
| 128 | 392 | 392 | 0 |

| both | **8,190** | **8,190** | **0** |

| fallback width (limbs) | differential pairs | mismatches |
|---|---:|---:|
| 1, 2, 3, 5, 7, 8, 13, 17, 33 | 4,603 | **0** |

The generic reference's own court still passes unchanged:
`PFP-6 CIOS differential: exhaustive=3018 sampled=7890 mismatches=0`.

## 4. Correctness — ABI transcript and repository gates

Harness `courts/performance-frontier/pfp5/pfp5_diff.c` (`04098db7…`), authority
`openssl-3.6.4-production` DSO `611e511d…`. The 150 `MX` rows are
`BN_mod_exp_mont_consttime` over 256/1024/2048/3072/8192-bit moduli; the RSA rows
cover CRT blinded, CRT unblinded and non-CRT; the two DH rows are FFDHE2048 and
MODP2048.

| subject | lines | vs authority | MX | RSA | DH |
|---|---:|---|---:|---:|---:|
| cand (specialised) | 161 | **IDENTICAL** | 150 | 8 | 2 |
| prev (generic) | 161 | **IDENTICAL** | 150 | 8 | 2 |

| gate | result |
|---|---|
| `cargo test --lib -- bn` | **161 passed, 0 failed** |
| full library suite | **2,493 passed, 0 failed, 54 ignored** (`--test-threads=4`, `CARGO_PROFILE_TEST_DEBUG=0`) |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

The ignored count is the pre-existing set; the two added tests are the M-A1
differential. Logs: `correctness/`.

## 5. Security at the candidate digest

### 5.1 ctgrind — secret exponent tainted

`bn::arith::tests::ctgrind_secret_exponent_window`: the staged exponent's limb
bytes are marked undefined and the five-bit-window ladder is run. The modulus is
four limbs, so the ladder reaches the width-4 compile-time kernel. Test binary
sha256 is in `ctgrind/meta.txt` (debug, not the DSO).

| run | errors | contexts | valgrind exit | origins |
|---|---:|---:|---:|---|
| exponent taint | **0** | **0** | 0 | **none** |
| negative control (`CTGRIND_CONTROL=1`) | 4 | 1 | 99 | `Conditional jump or move depends on uninitialised value(s)` |

### 5.2 DSO-bound base-taint probe

PFP-27's `pfp27_ladder_probe.c` (`208f430f…`), unmodified, taints the base of
`BN_mod_exp_mont_consttime` on a four-limb modulus and discards the result.

| subject | `control` | `ladder` (3 reps) |
|---|---|---|
| cand `88c0c7e0` | 0 contexts | **0, 0, 0** |
| prev `6d002db2` | 0 contexts | **0, 0, 0** |

### 5.3 Branch audit of the specialised carrier at `88c0c7e0`

All eight kernels and the generic fallback are inlined into one symbol,
`mont_mul_ladder_into` at `0x2fa7d0`, size `0x2431`; there is no out-of-line
`mont_mul_cios_fixed` symbol. `classify_widths.py` reads this digest's objdump
and aborts if a site is unclassified, a `jcc`'s nearest flag source is
arithmetic (a possible secret-derived transfer), or a class-(b) `setcc`'s first
consumer is not arithmetic.

**Totals: 40 `jcc` (40 public-bound, 0 secret-derived; 39 loop `cmp`/`test`, 1
geometry `or`), 64 `setcc` (0 public geometry, 64 secret carry/borrow flags
consumed arithmetically), 0 `cmovcc`. Secret-derived control transfers: none.**
The previous carrier at `6d002db2` (`0x58ce60`, `0x36c`) has 14 `jcc` and 18
`setcc` for context.

Rule applied to every site: a `jcc` is public-bound only if its nearest
preceding flag-setting instruction is `cmp`/`test` (or the one recorded public
length `or` at the geometry early return); a `setcc` after `add`/`adc`/`sub`/`sbb`
is a carry/borrow flag and must be first read by arithmetic, never by a
comparison or a branch. This is an enumeration and a **local dataflow review**,
not a constant-time proof. The full 104-site table is below and in
`raw/disasm/classification.{tsv,md}`.


| addr | kind | insn | class | flag source | consumed by |
|---|---|---|---|---|---|
| `0x2fa80b` | jcc | `jne` | (a) a-geom | `or %r9,%rax` | `-` |
| `0x2fa821` | jcc | `jne` | (a) a-loop | `cmp %rax,0x1f0(%rsp)` | `-` |
| `0x2fa854` | jcc | `ja` | (a) a-loop | `cmp $0x3c,%rax` | `-` |
| `0x2fa903` | setcc | `setb` | (b) b-flag | `adc %r11,%rdi` | `2fa960:add $0xff,%sil` |
| `0x2fa969` | setcc | `setb` | (b) b-flag | `adc 0x58(%rsp),%r8` | `2faa53:addb $0xff,0x58(%rsp)` |
| `0x2faa5b` | setcc | `setb` | (b) b-flag | `adc %rcx,%r8` | `2fab3b:addb $0xff,0x58(%rsp)` |
| `0x2fab4c` | setcc | `setb` | (b) b-flag | `adc %rcx,%rsi` | `2fac2d:movzbl 0x20(%rsp),%r9d` |
| `0x2fac3c` | setcc | `setb` | (b) b-flag | `adc %r8,%rcx` | `2fac4f:movzbl %dl,%r9d` |
| `0x2fac47` | setcc | `setb` | (b) b-flag | `adc $0x0,%r8` | `2fac4b:movzbl %r8b,%r8d` |
| `0x2fac70` | setcc | `setae` | (b) b-flag | `sub %r10,%rdx` | `2faca6:and %r11b,%bl` |
| `0x2fac9f` | setcc | `setae` | (b) b-flag | `sbb $0x0,%rdx` | `2faca6:and %r11b,%bl` |
| `0x2fad54` | jcc | `jne` | (a) a-loop | `cmp $0x80,%rsi` | `-` |
| `0x2fadbb` | jcc | `je` | (a) a-loop | `cmp $0x400,%r15` | `-` |
| `0x2fade0` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%rsi,8),%r9` | `2fade7:adc %rdx,%r10` |
| `0x2fadfd` | setcc | `setb` | (b) b-flag | `add (%rbx,%rsi,8),%r10` | `2fae04:adc %rdx,%r9` |
| `0x2fae16` | jcc | `jne` | (a) a-loop | `cmp $0x81,%rsi` | `-` |
| `0x2fae21` | setcc | `setb` | (b) b-flag | `add %r9,0x400(%rbx)` | `2fae24:mov %rax,0x408(%rbx)` |
| `0x2fae60` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%r9,8),%rsi` | `2fae67:adc %rdx,%r10` |
| `0x2fae76` | jcc | `je` | (a) a-loop | `cmp $0x80,%r9` | `-` |
| `0x2fae89` | setcc | `setb` | (b) b-flag | `add (%rbx,%r9,8),%r10` | `2fae90:adc %rdx,%rsi` |
| `0x2faea3` | jcc | `je` | (a) a-loop | `test %rsi,%rsi` | `-` |
| `0x2faf0d` | setcc | `setb` | (b) b-flag | `add (%rbx,%r15,8),%rcx` | `2faf14:adc %rdx,%rsi` |
| `0x2faf44` | jcc | `je` | (a) a-loop | `cmp 0x18(%rsp),%r13` | `-` |
| `0x2faf5c` | jcc | `je` | (a) a-loop | `test %rax,%rax` | `-` |
| `0x2faf6e` | setcc | `setb` | (b) b-flag | `add (%rbx,%rsi,8),%rbp` | `2faf75:adc %rdx,%r15` |
| `0x2faf8b` | setcc | `setb` | (b) b-flag | `add 0x8(%rbx,%rsi,8),%r15` | `2faf9b:adc %rdx,%rbp` |
| `0x2fafa1` | jcc | `jne` | (a) a-loop | `cmp %rsi,%r14` | `-` |
| `0x2fafa7` | jcc | `je` | (a) a-loop | `test $0x1,%dil` | `-` |
| `0x2fafb6` | setcc | `setb` | (b) b-flag | `add (%rbx,%rsi,8),%rbp` | `2fafbc:adc %rdx,%rcx` |
| `0x2fafcd` | setcc | `setb` | (b) b-flag | `add (%rbx,%rdi,8),%rbp` | `2fafd5:mov %r15,0x8(%rbx,%rdi,8)` |
| `0x2fafff` | jcc | `je` | (a) a-loop | `cmp $0x1,%rdi` | `-` |
| `0x2fb00f` | jcc | `je` | (a) a-loop | `cmp $0x2,%rdi` | `-` |
| `0x2fb02d` | setcc | `setb` | (b) b-flag | `add (%rbx,%r15,8),%rcx` | `2fb034:adc %rdx,%rbp` |
| `0x2fb04b` | setcc | `setb` | (b) b-flag | `add 0x8(%rbx,%r15,8),%rbp` | `2fb05e:adc %rdx,%rcx` |
| `0x2fb065` | jcc | `jne` | (a) a-loop | `cmp $0x1,%rax` | `-` |
| `0x2fb06d` | jcc | `jne` | (a) a-loop | `test $0x1,%al` | `-` |
| `0x2fb0db` | jcc | `je` | (a) a-loop | `cmp $0x200,%r15` | `-` |
| `0x2fb100` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%rsi,8),%r9` | `2fb107:adc %rdx,%r10` |
| `0x2fb11d` | setcc | `setb` | (b) b-flag | `add (%rbx,%rsi,8),%r10` | `2fb124:adc %rdx,%r9` |
| `0x2fb133` | jcc | `jne` | (a) a-loop | `cmp $0x41,%rsi` | `-` |
| `0x2fb13e` | setcc | `setb` | (b) b-flag | `add %r9,0x200(%rbx)` | `2fb141:mov %rax,0x208(%rbx)` |
| `0x2fb180` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%r9,8),%rsi` | `2fb187:adc %rdx,%r10` |
| `0x2fb193` | jcc | `je` | (a) a-loop | `cmp $0x40,%r9` | `-` |
| `0x2fb1a6` | setcc | `setb` | (b) b-flag | `add (%rbx,%r9,8),%r10` | `2fb1ad:adc %rdx,%rsi` |
| `0x2fb1c8` | setcc | `setb` | (b) b-flag | `sub (%r12,%rdx,8),%rsi` | `2fb1d2:or %dil,%cl` |
| `0x2fb1cf` | setcc | `setb` | (b) b-flag | `sub %rcx,%rsi` | `2fb1d2:or %dil,%cl` |
| `0x2fb1f0` | setcc | `setb` | (b) b-flag | `sbb 0x8(%r12,%rdx,8),%rdi` | `2fb1f3:movzbl %cl,%ecx` |
| `0x2fb1fa` | jcc | `jne` | (a) a-loop | `cmp $0x40,%rdx` | `-` |
| `0x2fb24d` | jcc | `jne` | (a) a-loop | `cmp $0x40,%rdi` | `-` |
| `0x2fb5a6` | setcc | `setb` | (b) b-flag | `add %rax,%rcx` | `2fb5b2:adc $0x0,%rdx` |
| `0x2fb5ae` | setcc | `setb` | (b) b-flag | `add %r12,%r15` | `2fb62b:mov %r12b,%al` |
| `0x2fb5c8` | jcc | `jne` | (a) a-loop | `cmp $0x48,%rdx` | `-` |
| `0x2fb5de` | setcc | `setae` | (b) b-flag | `sub 0x90(%rsp),%rdx` | `2fb6d8:and 0x90(%rsp),%al` |
| `0x2fb6d5` | setcc | `setae` | (b) b-flag | `sbb $0x0,%r12` | `2fb6d8:and 0x90(%rsp),%al` |
| `0x2fbeb1` | setcc | `setb` | (b) b-flag | `add %rax,%rcx` | `2fbebd:adc $0x0,%rdx` |
| `0x2fbeb9` | setcc | `setb` | (b) b-flag | `add %r10,%r12` | `2fc019:mov %r12b,%al` |
| `0x2fbed6` | jcc | `jne` | (a) a-loop | `cmp $0x80,%rdx` | `-` |
| `0x2fbf41` | setcc | `setae` | (b) b-flag | `sub 0xb0(%rsp),%rcx` | `2fc0d4:and 0xb0(%rsp),%al` |
| `0x2fc0d1` | setcc | `setae` | (b) b-flag | `sbb $0x0,%rcx` | `2fc0d4:and 0xb0(%rsp),%al` |
| `0x2fc546` | setcc | `setb` | (b) b-flag | `add %rax,%rcx` | `2fc552:adc $0x0,%r14` |
| `0x2fc54f` | setcc | `setb` | (b) b-flag | `add %rdx,%r11` | `2fc564:mov %dl,%al` |
| `0x2fc55e` | jcc | `jne` | (a) a-loop | `cmp $0x30,%r15` | `-` |
| `0x2fc58d` | setcc | `setae` | (b) b-flag | `sub 0x38(%rsp),%rdx` | `2fc5e6:and %r11b,%r14b` |
| `0x2fc5de` | setcc | `setae` | (b) b-flag | `sbb $0x0,%rdx` | `2fc5e6:and %r11b,%r14b` |
| `0x2fc71b` | jcc | `je` | (a) a-loop | `cmp $0x100,%r15` | `-` |
| `0x2fc740` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%rsi,8),%r9` | `2fc747:adc %rdx,%r10` |
| `0x2fc75d` | setcc | `setb` | (b) b-flag | `add (%rbx,%rsi,8),%r10` | `2fc764:adc %rdx,%r9` |
| `0x2fc773` | jcc | `jne` | (a) a-loop | `cmp $0x21,%rsi` | `-` |
| `0x2fc77e` | setcc | `setb` | (b) b-flag | `add %r9,0x100(%rbx)` | `2fc781:mov %rax,0x108(%rbx)` |
| `0x2fc7c0` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%r9,8),%rsi` | `2fc7c7:adc %rdx,%r10` |
| `0x2fc7d3` | jcc | `je` | (a) a-loop | `cmp $0x20,%r9` | `-` |
| `0x2fc7e6` | setcc | `setb` | (b) b-flag | `add (%rbx,%r9,8),%r10` | `2fc7ed:adc %rdx,%rsi` |
| `0x2fc808` | setcc | `setb` | (b) b-flag | `sub (%r12,%rdx,8),%rsi` | `2fc812:or %dil,%cl` |
| `0x2fc80f` | setcc | `setb` | (b) b-flag | `sub %rcx,%rsi` | `2fc812:or %dil,%cl` |
| `0x2fc830` | setcc | `setb` | (b) b-flag | `sbb 0x8(%r12,%rdx,8),%rdi` | `2fc833:movzbl %cl,%ecx` |
| `0x2fc83a` | jcc | `jne` | (a) a-loop | `cmp $0x20,%rdx` | `-` |
| `0x2fc88d` | jcc | `jne` | (a) a-loop | `cmp $0x20,%rdi` | `-` |
| `0x2fc8eb` | jcc | `je` | (a) a-loop | `cmp $0x180,%r15` | `-` |
| `0x2fc910` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%rsi,8),%r9` | `2fc917:adc %rdx,%r10` |
| `0x2fc92d` | setcc | `setb` | (b) b-flag | `add (%rbx,%rsi,8),%r10` | `2fc934:adc %rdx,%r9` |
| `0x2fc943` | jcc | `jne` | (a) a-loop | `cmp $0x31,%rsi` | `-` |
| `0x2fc94e` | setcc | `setb` | (b) b-flag | `add %r9,0x180(%rbx)` | `2fc951:mov %rax,0x188(%rbx)` |
| `0x2fc990` | setcc | `setb` | (b) b-flag | `add -0x8(%rbx,%r9,8),%rsi` | `2fc997:adc %rdx,%r10` |
| `0x2fc9a3` | jcc | `je` | (a) a-loop | `cmp $0x30,%r9` | `-` |
| `0x2fc9b6` | setcc | `setb` | (b) b-flag | `add (%rbx,%r9,8),%r10` | `2fc9bd:adc %rdx,%rsi` |
| `0x2fc9ea` | setcc | `setb` | (b) b-flag | `sub -0x8(%r12,%rdx,8),%rsi` | `2fc9f9:or %dil,%cl` |
| `0x2fc9f1` | setcc | `setb` | (b) b-flag | `sub %rcx,%rsi` | `2fc9f9:or %dil,%cl` |
| `0x2fca0c` | setcc | `setb` | (b) b-flag | `sbb (%r12,%rdx,8),%rsi` | `2fca0f:movzbl %cl,%ecx` |
| `0x2fca1a` | jcc | `jne` | (a) a-loop | `cmp $0x31,%rdx` | `-` |
| `0x2fca6d` | jcc | `jne` | (a) a-loop | `cmp $0x30,%rdi` | `-` |
| `0x2fca88` | setcc | `setb` | (b) b-flag | `sub (%r12,%rdx,8),%rsi` | `2fca92:or %dil,%cl` |
| `0x2fca8f` | setcc | `setb` | (b) b-flag | `sub %rcx,%rsi` | `2fca92:or %dil,%cl` |
| `0x2fcab0` | setcc | `setb` | (b) b-flag | `sbb 0x8(%r12,%rdx,8),%rdi` | `2fcab3:movzbl %cl,%ecx` |
| `0x2fcabd` | jcc | `jne` | (a) a-loop | `cmp $0x80,%rdx` | `-` |
| `0x2fcb10` | jcc | `jne` | (a) a-loop | `cmp $0x80,%rdi` | `-` |
| `0x2fcb25` | jcc | `je` | (a) a-loop | `test %rax,%rax` | `-` |
| `0x2fcb48` | setcc | `setb` | (b) b-flag | `sub (%r12,%rsi,8),%r8` | `2fcb57:or %r9b,%dl` |
| `0x2fcb4f` | setcc | `setb` | (b) b-flag | `sub %rdx,%r8` | `2fcb57:or %r9b,%dl` |
| `0x2fcb70` | setcc | `setb` | (b) b-flag | `sbb 0x8(%r12,%rsi,8),%r8` | `2fcb73:movzbl %dl,%edx` |
| `0x2fcb79` | jcc | `jne` | (a) a-loop | `cmp %rsi,%r14` | `-` |
| `0x2fcb7f` | jcc | `jne` | (a) a-loop | `test $0x1,%dil` | `-` |
| `0x2fcb97` | setcc | `setb` | (b) b-flag | `sub (%r12,%rsi,8),%r8` | `2fcba6:or %r9b,%dl` |
| `0x2fcb9e` | setcc | `setb` | (b) b-flag | `sub %rdx,%r8` | `2fcba6:or %r9b,%dl` |
| `0x2fcbfa` | jcc | `jne` | (a) a-loop | `cmp %r9,%rdi` | `-` |


## 6. Timing (paired against the previous build)

Instrument `bench_pfp5.c` (`ac605a5a…`), 15 interleaved repetitions, one process
per arm per repetition, order rotated, `taskset -c 1`, `--prepared`, i9-13900K,
court `openssl-rs-court-tools:1`. Statistic: median of the 15 paired
per-repetition ratios, 95 % percentile bootstrap (20,000 resamples, seed
`0x50465036`). Population frozen before execution: `population.json` sha256
`e7f61248…`. Ratio < 1 means the first-named arm is faster.


| workload | cand µs | prev µs | auth µs | cand/prev [CI95] | cand/auth [CI95] | prev/auth [CI95] |
|---|---:|---:|---:|---|---|---|
| `modexp2048` | 2413.7 | 2467.3 | 1192.6 | **0.9782** [0.9766, 0.9792] | 2.0226 [2.0209, 2.0350] | 2.0683 [2.0648, 2.0706] |
| `modexp8192` | 180810.9 | 180875.9 | 73880.5 | **0.9996** [0.9982, 1.0031] | 2.4470 [2.4447, 2.4541] | 2.4488 [2.4478, 2.4512] |
| `rsa2048` | 753.8 | 872.8 | 350.7 | **0.8646** [0.8604, 0.8671] | 2.1498 [2.1443, 2.1586] | 2.4865 [2.4835, 2.4952] |
| `dh-ffdhe2048` | 2411.2 | 2467.5 | 1191.8 | **0.9776** [0.9771, 0.9780] | 2.0227 [2.0222, 2.0252] | 2.0711 [2.0686, 2.0720] |
| `ecdsa256` | 129.8 | 131.9 | 12.7 | **0.9839** [0.9818, 0.9905] | 10.2012 [10.1870, 10.2525] | 10.3531 [10.3431, 10.3837] |
| `dh-modp2048` | 2411.5 | 2467.9 | 1191.9 | **0.9767** [0.9760, 0.9778] | 2.0230 [2.0203, 2.0244] | 2.0706 [2.0686, 2.0723] |
| `dh-synth2048` | 2413.7 | 2468.1 | 1192.6 | **0.9781** [0.9770, 0.9786] | 2.0242 [2.0209, 2.0252] | 2.0690 [2.0676, 2.0710] |
| `dh-ffdhe3072` | 8420.0 | 8481.9 | 3954.0 | **0.9923** [0.9917, 0.9934] | 2.1304 [2.1249, 2.1343] | 2.1499 [2.1412, 2.1511] |
| `dh-synth3072` | 8421.4 | 8481.5 | 3952.3 | **0.9927** [0.9923, 0.9929] | 2.1315 [2.1268, 2.1376] | 2.1500 [2.1419, 2.1530] |

The required five are the first five rows. `prev/auth` reproduces the PFP-6
admitted ratios for the four Montgomery workloads (2.068/2.449/2.487/2.071 vs
2.069/2.452/2.484/2.071), so the comparison is at the same composition; the
`ecdsa256` control drifted +1.1 % between runs. `ecdsa256` is a control in the
sense that it is not dominated by the ladder; its small movement is the
ladder's share of the operation.

### 6.1 Predicted versus measured (transfer of the M-A2 signal)

The M-A2 by-product predicted nothing at whole-operation level; the applicable
prediction used here is that the candidate should move by the paired
`cand/prev` factor from the PFP-6 incumbent:


| workload | PFP-6 cand/auth | prev/auth (this run) | cand/prev | predicted cand/auth | measured cand/auth | delta |
|---|---:|---:|---:|---:|---:|---:|
| `modexp2048` | 2.0690 | 2.0683 | 0.9782 | 2.0239 | 2.0226 | -0.06 % |
| `modexp8192` | 2.4520 | 2.4488 | 0.9996 | 2.4511 | 2.4470 | -0.17 % |
| `rsa2048` | 2.4840 | 2.4865 | 0.8646 | 2.1476 | 2.1498 | +0.11 % |
| `dh-ffdhe2048` | 2.0710 | 2.0711 | 0.9776 | 2.0246 | 2.0227 | -0.10 % |
| `ecdsa256` | 10.2400 | 10.3531 | 0.9839 | 10.0754 | 10.2012 | +1.25 % |

The prediction is met for the four Montgomery-dominated workloads (|delta| ≤
0.17 %). `ecdsa256` moves +1.25 % against the stale PFP-6 base because the
control itself drifted (this run's `prev/auth` is 10.353, not 10.24); its paired
`cand/prev` is still 0.9839.

### 6.2 Did the M-A2 signal transfer?

**Partially, and with a different magnitude.** The by-product was a standalone
kernel comparison: fixed arrays were 2.6× faster than a slice transcription at
256 bits and 1.07× at 1024. In the artefact:

- **1024-bit (16 limbs)** — the signal transferred and was **larger**: RSA
  (CRT primes) is 13.5 % faster (`cand/prev` 0.8646), where the experiment
  suggested ~6.5 %. This is the arm's clear win.
- **2048-bit (32 limbs)** — 2.2 % faster (`0.9782`).
- **3072-bit (48 limbs)** — 0.8 % faster (`0.9923`).
- **4096-bit (64 limbs)** — implemented, not isolated by the frozen workloads.
- **8192-bit (128 limbs)** — neutral (`0.9996`; the interval includes 1). The
  slice overhead is a small fraction of the `O(N²)` work at this width; the
  experiment's trend (larger relative gain at smaller widths) is exactly what
  the artefact shows, extrapolated to no measurable gain.
- **256-bit (4 limbs)** — the 2.6× by-product **did not transfer as an
  end-to-end figure**, because the frozen population has no 256-bit modexp
  workload. The nearest end-to-end signal is `ecdsa256` at 1.6 % below prev,
  and ECDSA is dominated by point arithmetic; the 4-limb kernel's own speedup is
  not isolated by this set. This is the honest shortfall: the 2.6× claim is a
  kernel microbenchmark, and this evidence does not confirm it end to end.

### 6.3 Widths that won and widths that lost

- **Won:** 16 limbs (RSA, −13.5 %), 32 limbs (2048-bit modexp/DH, −2.2 %),
  48 limbs (3072-bit DH, −0.8 %), 4 limbs (ECDSA end-to-end, −1.6 %).
- **Neutral:** 128 limbs (−0.04 %, interval includes 1).
- **No width lost.** 6/9/64 are implemented and differenced but are not isolated
  by the frozen workload set; no claim is made for their speed.

## 7. What this does not establish

- The taint is source-bound at width 4 and DSO-bound at width 4; the other
  widths rest on the structural audit. Neither is a constant-time proof, and no
  dudect-class or microarchitectural claim is made.
- The branch audit is an enumeration + local dataflow review, not a
  secret-independence proof.
- The candidate is an **uncommitted worktree state** (this task forbids
  commits): two clean builds reproduce `88c0c7e0`, but it is not reproducible
  from a commit until the change lands. `build_relevant_clean = false`.
- The venue exposes no hardware PMU; timing is a `SCOPED_OBSERVATION` with host
  noise, and the intervals are within-run (between-process spread is larger).
- No `SAFE_COMPATIBLE`, safety or compatibility conclusion is asserted beyond
  the same-digest ABI transcript.

## 8. Reproduction

```sh
export OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g
C=evidence/performance-frontier/campaigns/M-A1
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/build.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/run_kernel_differential.sh
bash docker/openssl-rs-court.sh exec bash $C/run_diff.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/run_gates.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/run_ctgrind.sh
bash docker/openssl-rs-court.sh exec bash $C/run_dso_probe.sh
bash docker/openssl-rs-court.sh exec bash $C/run_branch_audit.sh
bash docker/openssl-rs-court.sh exec bash $C/run_timing.sh
python3 $C/analyse_timing.py
python3 $C/make_results.py
```
