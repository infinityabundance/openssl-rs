# PFP-67 — `OPENSSL_ia32cap` as one capability model

- **Branch / base:** `staging`, HEAD `32fb28676aafc69f0c102887bced6763149f38d4`.
- **Candidate:** the working tree described below (not committed; the task forbids it).
- **Authority:** `openssl-3.6.4-production` (`crypto/cpuid.c:94-171`,
  `doc/man3/OPENSSL_ia32cap.pod`, `include/crypto/aes_platform.h:171,185`,
  `crypto/modes/gcm128.c:446`).
- **Venue:** `docker/openssl-rs-court.sh` (`openssl-rs-court`). Existing container:
  `Memory=4294967296` (4 GiB), `MemorySwap=4294967296` (4 GiB), verified with
  `docker inspect`. `memory.events`: `oom 0`, `oom_kill 0`.
- **No commit, no push.** No `docker/`, `.frf/`, or
  `docs/PERFORMANCE-FRONTIER-TODO.md` change.

## 1. Memory per command (cap recorded)

`free -g` before every command: **available 24–27 GiB**, **Swap free ≈ 4.2 GiB**.
Per §24.4, `cap = min(4g, available - 8g)` with floor `2g`; found value **4g** in
every case. `OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g`,
`CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`, tests `--test-threads=4`.
One heavy command at a time; no release test build; `test_sigstore_bundle` never
run. No OOM (`memory.events` `oom=0`, `oom_kill=0`).

| command | available before | cap | result |
|---|---|---|---|
| `cargo build --lib` | 26–27 GiB | 4g | ok (20.8 s) |
| `cargo test --lib --no-run` (×2) | 25 GiB | 4g | ok (26.8 s) |
| focused `runtime::cpu::` (×2) | 25–26 GiB | 4g | 5/5 pass |
| `cargo fmt --all -- --check` | 25 GiB | 4g | pass |
| `cargo clippy --all-targets -- -D warnings` (×2) | 25–26 GiB | 4g | pass |
| full `cargo test --lib -- --test-threads=4` (default) | 25–26 GiB | 4g | 2562/0/56 |
| full suite, `OPENSSL_ia32cap=0x0:0x0` (final) | 26 GiB | 4g | 2562/0/56 |
| `run_matrix.sh` (probes + child transcripts) | 24–26 GiB | 4g | 6/6 outputs agree |

## 2. Inventory (pre-change, at HEAD `32fb2867`)

| # | site | feature / LV bit | honoured the override? |
|---|---|---|---|
| 1 | `src/aes.rs:86-97` `ia32cap_aes_cleared`, `:107-118` `aes_ni_available` | AES-NI, LV0 bit 57 | **partly, and on the wrong bit**: tested `1<<25` (EDX bit 25) instead of `1<<57`; only `~`; no value-set, no FXSR knock-on, hex only |
| 2 | `src/aes.rs:285,425,490` (key expansion, `AES_encrypt`, `AES_decrypt`) | via #1 | inherits #1 |
| 3 | `src/digest/sha2.rs:212-223`, `:233-244`, call `:335` | SHA, LV1 bit 29 | **mostly**: correct bit and `~` second field; no value-set, no missing-field zeroing, hex only |
| 4 | `src/modes/gcm.rs:210-221`, `:231-242`, calls `:150,457` (`gf_mul`, batching) | PCLMULQDQ, LV0 bit 33 | **partly, and on the wrong bit**: tested `1<<1` (EDX bit 1) instead of `1<<33`; only `~`; no value-set, no FXSR knock-on |
| 5 | `src/provider/cipher.rs:11067-11070` `ia32cap_aesni`, calls `:11086,11091` | AES-NI, LV0 bit 57 | **no** — raw `__cpuid(1).ecx & (1<<25)` |
| 6 | `src/provider/cipher.rs:11079-11082` `ia32cap_avx2`, calls `:11506,12155` | AVX2, LV1 bit 5 | **no** — raw `__cpuid_count(7,0).ebx & (1<<5)` |
| 7 | `src/ec/p256.rs:921-933` `arch_supported` | BMI2/ADX, LV1 bits 8/19 | **no** — raw CPUID `& 0x80100` |
| 8 | `src/ec/curve25519.rs:158-167` `x25519_fe64_eligible` (exported), internal use `:1874` | BMI2/ADX | **no** — raw CPUID `& 0x80100` |
| 9 | `src/evp/e_aes_cbc_hmac_sha1.rs:375,385`; `_sha256.rs:353,363` | AES-NI | via #5 |
| 10 | `src/rc4.rs:54` `RC4_options` | EDX bits 20/30 (authority string) | not a CPUID read; constant `rc4(8x,int)`, recorded D213 divergence (no accelerated RC4 path exists) |
| 11 | `src/apps/info.rs`, `src/runtime/init.rs` CPUINFO / `OPENSSL_info(1008)` | n/a | still `CPUINFO: N/A` / NULL (pre-existing Phase-19 obligations, not dispatch) |
| 12 | `OPENSSL_ia32cap_loc` | n/a | **not exported** — 3.6.4 does not define it; `OPENSSL_ia32cap_P` is hidden data. Nothing to model. |
| 13 | `OPENSSL_init_crypto` | n/a | the authority calls `OPENSSL_cpuid_setup()`; this crate never forced the capability read at initialisation |

### Gaps this found

1. **AES and PCLMULQDQ were offset by 32 bits.** The first logical vector is
   `EDX:ECX`; AES is bit 57 and PCLMULQDQ bit 33, but the helpers tested bits 25
   and 1. The documented `OPENSSL_ia32cap=~0x200000000000000` did **not** disable
   AES-NI, and `~0x200000000` did **not** disable PCLMULQDQ. Only the SHA helper
   used the right bit.
2. **The value-set form was ignored** by all three helpers, including the literal
   the authority's own `RT-CPU-CAPABILITY` court drives (`0x0200000100000000`).
3. **Missing trailing fields were not zeroed**, so `OPENSSL_ia32cap=~0x0` left
   SHA/AVX2/VAES enabled where the authority zeroes LV1..LV4.
4. **The FXSR knock-on was missing**, so `~0x1000000` did not clear AES/PCLMUL/AVX.
5. **Decimal and octal were not parsed** (only `from_str_radix(..., 16)`).
6. **Provider AES-NI/AVX2, P-256 BMI2/ADX and X25519's `fe64` predicate ignored
   the variable entirely.**
7. **Three independent `OnceLock`s** read the environment three times, and no read
   happened at `OPENSSL_init_crypto`.

## 3. One capability model — `src/runtime/cpu.rs`

`runtime::cpu` is the only place `OPENSSL_ia32cap` is read and the only capability
predicate the dispatchers consult. It is transcribed from `crypto/cpuid.c:94-171`:

- `parse_u64` = `ossl_strtouint64`: `0x`/`0X` hex, leading `0` octal, otherwise
  decimal; prefix parsing; 64-bit wrapping accumulation.
- Logical vectors: LV0 = `CPUID.1 EDX:ECX`, LV1 = `CPUID.7.0 EBX:ECX`, LV2–LV4
  the remaining pairs.
- First field: `~mask` clears, `:` defers to the CPU, a literal **replaces** the
  vector. Clearing bit 24 (FXSR) additionally clears LV0 bits 33, 43, 57 and 60
  (`crypto/cpuid.c:114-124`); the value-set form does **not**.
- Extended fields: `~mask` / literal / empty-field-skip / missing-field-zero,
  exactly the loop at `crypto/cpuid.c:132-155`.
- Lazy once (`OnceLock`), forced from `ossl_init_base` via `runtime::cpu::init()`
  so the value is read at the authority's point.
- Typed queries: `has_aes` (57), `has_pclmul` (33), `has_sha` (LV1 29 **and**
  SSE4.1, the callee's actual target features), `has_avx` (60), `has_avx2` (LV1 5),
  `has_vaes` (LV1 41), `has_vpclmul` (LV1 42), `has_bmi2` (LV1 8), `has_adx`
  (LV1 19). Each is `is_x86_feature_detected!` **and** the override's permission.

### Malformed input (total; no panic, no silent enable)

| value | upstream `ossl_strtouint64` | this implementation |
|---|---|---|
| `~zz` | mask 0 → clears nothing | `Clear(0)` — same |
| `zz` | value 0 → LV0 = 0 | `Set(0)` — same |
| `~0x1fZZ` | prefix 0x1f | `Clear(0x1f)` — same |
| `09` | octal, stops at `9` → 0 | `Set(0)` — same |
| `0b101` | octal `0`, stops at `b` → 0 | `Set(0)` — same |
| `~` | mask 0, then no colon → LV1..4 zeroed | same |

**Recorded divergences** (both deliberate, not safety-weakening):

1. **Value-set may only restrict.** An override value can set a bit the CPU does
   not report; upstream would then execute the unsupported instruction and fault.
   This crate intersects every query with real detection, so an override cannot
   fabricate a capability. No legitimate consumer relies on that.
2. **Non-UTF-8 `OPENSSL_ia32cap`** is treated as absent (`std::env::var` returns
   `Err(NotUnicode)`); upstream would parse its ASCII prefix. Not reachable from a
   POSIX `setenv` through normal tooling.
3. **`has_sha` also requires SSE4.1.** The SHA-NI compression function executes
   SSE4.1 instructions, so clearing SSE4.1 alone forces the portable SHA path even
   if the SHA bit remains. The authority's asm may still run SHA-NI in that
   configuration; the output is identical and the crate cannot safely do so.

## 4. Compatibility matrix (Step 3)

Same C probe (`probe.c`) linked twice — authority static `libcrypto.a` and the
candidate's static archive — under identical environments; outputs are compared
byte-for-byte. The authority's `OPENSSL_ia32cap_P` words are `.hidden`, so the
probe links the static archive and reports them; the candidate's actual dispatch
comes from the Rust child (kernel counters). Raw files: `raw/`.

| scenario (`OPENSSL_ia32cap`) | authority bits (aes/pclmul/avx/avx2/sha/vaes/vpclmul) | candidate caps | candidate executed path | selector NULLs (auth/cand) | outputs |
|---|---|---|---|---|---|
| unset | 1/1/1/1/1/1/1 | all true | AES-NI, PCLMUL, SHA-NI | 0/0 | identical |
| `~0x200000000000000:::::` | 0/1/1/1/1/1/1 | aes false, rest true | AES portable; PCLMUL, SHA-NI | 1/1 | identical |
| `~0x200000000:::::` | 1/0/1/1/1/1/1 | pclmul false | AES-NI; PCLMUL portable; SHA-NI | 0/0 | identical |
| `:~0x20000000` | 1/1/1/1/0/1/1 | sha false | AES-NI, PCLMUL; SHA portable | 0/0 | identical |
| `~0x1000000:::::` (FXSR) | 0/0/**0**/1/1/1/1 | aes/pclmul/avx false | AES portable; PCLMUL portable; SHA-NI | 1/1 | identical |
| `0x0:0x0` (value-set) | 0/0/0/0/0/0/0 | all false | every kernel portable | 1/1 | identical |

The authority's masking and this crate's now agree in every row, including the
FXSR knock-on and the value-set form. The four `EVP_aes_*_cbc_hmac_sha*`
constructors move with the AES bit on both sides.

Raw evidence: `raw/authority_<scenario>.txt`, `raw/candidate_<scenario>.txt`,
`raw/candidate_paths_<scenario>.txt`. `run_matrix.sh` also diffs every `out.*`
line and prints `outputs agree: <scenario>`.

Known limits of this matrix: the host has every listed extension, so the
positive control could run; a host without a feature would skip that positive
assertion (the test derives it from detection). The authority's raw
`AES_encrypt` is AES-NI asm on this build, so its *low-level* path cannot be
distinguished by output; its dispatch input (the capability word) is the
observable used above. VAES/VPCLMULQDQ have no execution path in this crate;
AVX2 only selects an interleave in the stitched multiblock AAD and is
output-invariant. Those rows report the override's effect on the predicate, not
a second kernel.

## 5. Callers that ignored the override, and the change

| caller | change |
|---|---|
| `AES_encrypt` / `AES_decrypt` / key expansion (`src/aes.rs`) | dispatch on `runtime::cpu::has_aes()`; all CBC/CTR/GCM/CCM/OCB/XTS and stitched-provider block calls funnel here |
| GCM GHASH (`src/modes/gcm.rs`, `gf_mul` and `batching_enabled`) | `runtime::cpu::has_pclmul()` |
| SHA-256 compression (`src/digest/sha2.rs`) | `runtime::cpu::has_sha()` |
| Provider AES-NI capability + AVX2 AAD (`src/provider/cipher.rs`) | `has_aes()` / `has_avx2()`; the four CBC-HMAC rows and their `EVP_*` constructors now drop under a cleared AES bit |
| `src/evp/e_aes_cbc_hmac_sha1.rs`, `_sha256.rs` | `has_aes()` |
| P-256 `Arch` kernel (`src/ec/p256.rs`) | `has_bmi2() && has_adx()` |
| X25519 `x25519_fe64_eligible` (`src/ec/curve25519.rs`, exported) | `has_bmi2() && has_adx()`; returns `0x80100` / `0` as the asm does |
| `OPENSSL_init_crypto` (`src/runtime/init.rs`) | `runtime::cpu::init()` at `ossl_init_base` |

All ad-hoc helpers (`ia32cap_aes_cleared`, `ia32cap_sha_cleared`,
`ia32cap_pclmul_cleared`, `ia32cap_aesni`, `ia32cap_avx2`, both raw-CPUID
predicates) were deleted; a grep over `src/` finds no production
`is_x86_feature_detected!`, `__cpuid`, or `OPENSSL_ia32cap` read outside
`runtime/cpu.rs`.

## 6. Tests that prove it (Step 4)

`runtime::cpu::tests`:

- `the_authority_grammar_is_transcribed_exactly` — clear/value-set/defer,
  empty-field skip, missing-field zero, octal/decimal, malformed prefixes, no
  panic.
- `fxsr_clear_masks_the_xmm_only_extensions` — knock-on, and its absence for
  value-set.
- `extended_vector_bits_are_the_cpuid_bits` — LV1 8/19/29/41/42.
- `pfp67_override_forces_the_portable_arm_on_every_caller` — a child process per
  scenario; **counters inside the NI and portable kernels** (not the predicate)
  report the arm that ran. With no override: AES-NI on `AES_encrypt`,
  `AES_cbc_encrypt`, `CRYPTO_ctr128_encrypt` and `CRYPTO_gcm128_encrypt`,
  PCLMULQDQ on GCM, SHA-NI on SHA-256, and non-NULL stitched selectors. With
  `~0x200000000000000:::::` every AES caller reports zero AES-NI and portable
  work, GCM still uses PCLMUL, SHA-NI still runs, selectors are NULL. With
  `~0x200000000:::::` GCM reports zero PCLMUL and portable field work. With
  `:~0x20000000` SHA reports zero SHA-NI and portable compression. With
  `~0x1000000:::::` the FXSR knock-on clears AES and PCLMUL. With `0x0:0x0`
  everything is portable. Every output byte equals the unoverridden run.

`provider::cipher::tests::the_capability_filter_drops_a_row_whose_predicate_refuses`
was made capability-aware: it now derives the refused count from `has_aes()`
(9 ETM rows always, plus the 4 CBC-HMAC rows when AES-NI is unavailable) instead
of hard-coding this host's state. That is the test that exposed the real
observable under `OPENSSL_ia32cap=0x0:0x0`.

## 7. Gate (Step 5)

- `cargo fmt --all -- --check`: **pass**.
- `cargo clippy --all-targets -- -D warnings`: **pass**.
- `cargo test --lib -- --test-threads=4`: **2562 passed, 0 failed, 56 ignored,
  0 filtered**. Baseline was 2558/0/56; net +4 tests (5 new capability tests
  minus the one test of the deleted SHA helper), **no new `#[ignore]`**.
- Full suite with `OPENSSL_ia32cap=0x0:0x0` (every kernel portable): **2562
  passed, 0 failed, 56 ignored** — the KAT/differential suites exercise the path
  a consumer gets when it disables the extensions.
- The six-scenario authority/candidate matrix: **all six outputs agree**.

## 8. Source identity

Working-tree modifications (not committed):

```
src/aes.rs                             d9948508a8d8a7d8bf8bd18336a54eb89e3a440ffa531c9d27a38630be23878c
src/digest/sha2.rs                     167a65f59c8dfadc865b0a425a38d5fd6be2d252d1a4640b77dba838c214d6cd
src/ec/curve25519.rs                   ec86d1710ea0a8873be8924a14599299c220da5f2b27e2cb484ad2aa1368bd9e
src/ec/p256.rs                         5213829d193f8f93ed7b3cb158c0048eda10e7a760e8ca5507de19c1160d4cd6
src/evp/e_aes_cbc_hmac_sha1.rs         86c04529dae727fbfcde28d336a39b557c6614eab7e02e58fecb7faf07abd956
src/evp/e_aes_cbc_hmac_sha256.rs       2c30af162664e9c6bb11897626e701d543ccf458d0ac19573297f6b0a46cce5c
src/modes/gcm.rs                       55f23166ee9f122240a55c2465dbd53fe7da38251df801e66a40c39cb5154334
src/provider/cipher.rs                 5d81509ba3ef56d03523f7e4f0afd93f318f697370fc11d4fe170939b2f839e5
src/runtime/init.rs                    b74f16fef86f88e8d854e488c635e5f726aea43e46d0aafd907ab0d6ff6d47d3
src/runtime/mod.rs                     6f42ae687135d0bddc6d3c470aa4efd924865232c582fc6bc018ec33e0e8e1a4
src/runtime/cpu.rs (new)               70589e3607f7d5983e151e81a49708e7ae8ba8d69c954e4bad78914285d88737
evidence/.../PFP-67/probe.c            c630b44573c6caec920cf758951d445a34f5f96a279035c9068dccf5ee2d2f40
evidence/.../PFP-67/run_matrix.sh      da965915e6246e0ef1bececc6ac6b1bfff5402d3b7f2f424285bf51e8ac0bdff
```

Candidate archive used by the matrix (debug, behaviour not performance):
`target/debug/libopenssl_rs.a`
`5de9223a082238331a21df0e0334e99b4d87a228fd51f27c36f31b3210d162f9`.
Probe binaries: `court/pfp67/probe.authority`
`f48947b3b971ea30fd19ed1ee1358e7124fa2c011a5fd0d957771cd970cd9da9`,
`court/pfp67/probe.candidate`
`fe1591b5f7495c59ff63b3ff8e59eaec03001191f5df3fa0fe0b9e6c77637a50`.

## 9. What was not made to match

- `OpenSSL_version(OPENSSL_CPU_INFO)` remains `CPUINFO: N/A` and
  `OPENSSL_info(1008)` remains NULL on the candidate, while the authority reports
  `OPENSSL_ia32cap=...` and the environment string. This is the pre-existing
  Phase-19 obligation (`OBL-INIT-VERSION-CPU-INFO`,
  `OBL-INIT-INFO-CPU-SETTINGS`), not a dispatch decision, and is unchanged here.
- `RC4_options` remains the constant `rc4(8x,int)` string (D213). The authority
  derives its string from EDX bits 20/30; this crate has one RC4 implementation,
  so there is no accelerated path to select. A consumer reading the string still
  sees a divergence.
- VAES/VPCLMULQDQ queries exist but no crate path consumes them; AVX2 only
  changes a stitched-AAD interleave. The matrix records the predicate agreement,
  not an executed VAES kernel.
- The matrix's authority side observes dispatch through the capability word, not
  through disassembly; a host without the extension cannot run the positive
  control.
