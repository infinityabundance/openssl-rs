# PFP-63 — portable AES half (security remediation)

## 0. What this document is

This is the evidence bundle for the **portable half** of PFP-63: removing
secret-indexed memory and secret-dependent control flow from the AES path that
runs when the CPU has no AES-NI, and from the portable GHASH field multiply. It
does not replace the earlier PFP-63 accelerated-half receipt
(`RECEIPT.md`), which is bound to a different working-tree digest; it supersedes
that receipt's statement that the portable table path is retained in production.

No commit or push was made. All work is in the `staging` working tree.

**Working-tree caution.** The tree already contained uncommitted changes before
this batch (the GHASH aggregation carrier `GhashPowers`/`ghash_group` and related
tests in `src/modes/gcm.rs`, and earlier PFP-63 accelerated-half edits). The diff
digest in §1 is therefore the digest of the *whole* working tree, not of this
batch alone. This batch's edits are only: `src/aes.rs` (portable dispatch),
`src/aes/{portable,reference,research}.rs` (new), `src/modes/gcm.rs`
(`gf_mul_portable` masks, negative control, one test), `src/digest/tables.rs` and
`forensics/tools/gen_phase8_tables.py` (test-only gates), `examples/pfp63_bench.rs`,
and this evidence bundle. No pre-existing change was reverted.

## 1. Identity

| | |
|---|---|
| branch / HEAD | `staging` / `d0bb66fb07cb56758c015b830073bd6d323ff712` |
| working-tree diff digest | `014daece4ebaa207df8d1d79a1146b9834e999e558073d8f5af24479f7db97f0` (`raw/portable-diff.patch`) |
| release audit artefact | `target/release/examples/pfp63_bench` = `659ad8c409faafbf1fb47342e2308ddce902cfedd1634b6cd0ab5f98f6858753` |
| debug control artefact | `target/debug/deps/openssl_rs-bcfdf4d0f51f39b5` = `1744f8524de5fe9296f5ce029d3246a1b9ac2aabb6c5d31cfa38f097a06d5f1e` |
| authority / machine / toolchain | `openssl-3.6.4-production`; x86_64, 30 logical CPUs; rustc 1.98.1; court `openssl-rs-court:1` |
| source hashes | `raw/portable-identity.txt` |

The untracked `.frf/residuals/*` entries in `git status` pre-date this batch and
were not touched.

## 2. Design decision

`AES_SBOX`/`AES_INV_SBOX` indexed by state are replaced in production by a
first-party, safe-Rust, constant-pattern construction:

* the S-box is `affine(x^254)`, where `x^254` is computed by six
  square-multiply steps plus one square in GF(2^8) with the AES polynomial;
* all GF operations are fixed-shape XOR/AND networks with mask-selected
  reduction, never a table and never a conditional transfer;
* the circuit is applied **bitsliced** over all sixteen state bytes
  (`u16` planes), so one S-box evaluation is one circuit over the whole block;
* `MixColumns` uses a branch-free `xtime`; `InvMixColumns` builds `9/11/13/14`
  from the fixed `2/4/8` chain; `AddRoundKey` indexes only the public round
  counter;
* key expansion uses the same scalar S-box for `SubWord`/`RotWord`, so the
  exported schedule bytes are unchanged.

`src/aes/portable.rs` carries `#![forbid(unsafe_code)]`. `src/aes/reference.rs`
(the table reference) and `src/aes/research.rs` are `#[cfg(test)]` and also
`#![forbid(unsafe_code)]`. Only pointer extents remain in `src/aes.rs`'s existing
`unsafe fn` boundary.

The two table statics are now `#[cfg(test)]`; the generator
(`forensics/tools/gen_phase8_tables.py`) emits the same attribute, so
`gen_phase8_tables.py --check` remains the single source of truth. They are
absent from non-test builds.

## 3. Constructions evaluated

Measured in the unoptimised test profile, nanoseconds per 16 bytes of S-box work
(`raw/portable-bench-debug.txt`). All arms were first proved equal to the table.

| arm | construction | ns / 16 bytes | outcome |
|---|---|---:|---|
| table | `AES_SBOX[x]` (reference only) | 113.2 | baseline; removed from production |
| bytewise | Boolean field-exponentiation circuit, one byte at a time | 11 458.4 | correct, loses |
| composite | genuine GF((2^4)^2) tower: basis change, tower inverse, affine | 3 084.9 | correct, loses |
| **bitsliced** | the Boolean field-exponentiation circuit over the 16-byte state | **1 725.6** | **selected** |

The composite arm derives its tower constants (irreducible quadratic, a root of
the AES polynomial, and the basis inverse) from public constants at first use;
it is a real tower evaluation, not a relabelled exponentiation. It is exhausted
against the table in `aes::research::all_sbox_arms_are_exhaustively_equal_to_the_table`.
The bitsliced arm wins by about 1.8× over composite and 6.6× over bytewise in
this profile. A minimised Boyar–Peralta gate list would be smaller still and was
not implemented; this is stated as an unassessed alternative, not claimed.

## 4. Correctness before timing

### 4.1 Exhaustive S-box equivalence (mandatory cheap complete check)

All 256 inputs, forward and inverse, against the authority-derived reference
table, for the scalar and bitsliced carriers; the composite arm is also checked
over all 256 inputs.

* `aes::portable::tests::scalar_sbox_is_exhaustively_equal_to_the_reference_table`
* `aes::portable::tests::bitsliced_sbox_is_exhaustively_equal_to_the_scalar_sbox`
* `aes::portable::tests::sbox_and_its_inverse_round_trip`
* `aes::portable::tests::scalar_and_bitsliced_field_inverse_agree`
* `aes::research::all_sbox_arms_are_exhaustively_equal_to_the_table`

Result: 256/256 forward and 256/256 inverse for every arm; no mismatch.

### 4.2 Key-schedule differential

`keys_for(bits)` = all-zero, all-ones, every single-bit key, then 512 random
keys: 642 keys for AES-128, 706 for AES-192, 770 for AES-256 (2 118 per family).

* portable expansion vs table-transcribed reference expansion: exact equality of
  all `(word, round-count)` pairs;
* exported `AES_set_encrypt_key` bytes vs the reference schedule byte-swapped
  into the authority's perlasm order: exact equality;
* exported `AES_set_decrypt_key` bytes vs the reference-derived reverse/
  `InvMixColumns` transform: exact equality.

Tests: `portable_schedule_matches_reference_for_all_sizes`,
`exported_encrypt_schedule_is_byte_identical_to_reference`. `AesKey` is unchanged
(`offset_of!(rounds) == 240`, `size_of == 244` compile-time asserts).

### 4.3 KATs and mode tests

* FIPS-197 C.1/C.2/C.3: encrypt and decrypt for 128/192/256, through the public
  entry points **and** through `aes_encrypt_portable`/`aes_decrypt_portable`
  directly (`fips197_c1_c2_c3`).
* NIST GCM cases 1 and 2 at every aggregation width
  (`gcm_nist_case_1_and_2_at_every_width`, `gcm_spec_case_1`,
  `gcm_spec_case_2`).
* RFC 5649 wrap vectors and wrap/unwrap round trips unchanged.
* The crate's existing CBC/CTR/GCM mode tests pass unchanged in the full library
  suite (see §6).
* Round-trip encrypt/decrypt for all three sizes and random blocks over the same
  key population (`portable_block_matches_reference_and_round_trips`).

### 4.4 Portable GHASH equivalence

`gf_mul_portable` is now mask-selected; it is checked against both the
pre-conversion branchy transcription and the `pclmulqdq` arm over 263 operand
pairs including `0`, `1`, `2^128-1` and `R`
(`portable_ghash_multiply_matches_reference`), plus the existing
`clmul_matches_portable_gf_mul` and GHASH group tests.

## 5. Security adjudication

### 5.1 Secret-indexed-memory audit (emitted code, not source shape)

Artifact: release example `659ad8c4…`; commands and excerpts in
`raw/portable-audit.txt`.

| carrier | indexed memory operands | conditional transfers |
|---|---|---|
| `aes::portable::sub_bytes` | none | none (calls `inv_planes`) |
| `aes::portable::inv_planes` | none | one fixed-count loop back-edge |
| `aes::portable::encrypt_block` | none (all `lea ...(%r,%r,1)` lines are `xtime` shifts, not loads) | round-loop back-edge only |
| `aes::portable::add_round_key` | four `mov 0x{0,4,8,c}(%rsi,%rax,4)` schedule-word loads | none on key bytes |
| `gcm::gf_mul_portable` | none | `cmov/mask` only plus the fixed 128-count loop back-edge |

In `add_round_key`, `%rax` is the public round index supplied by the round
driver, never a key or state byte. This is the complete list of indexed loads in
the portable AES carriers. No load or address is selected by secret state. The
`AES_set_decrypt_key` schedule transform (`src/aes.rs`) was also checked: its
indexed accesses into `rd_key` use only the public loop counters `i`, `j` and
`off`; no key byte selects an address. The decrypt-schedule transform is
arithmetic on secret words, not a table.

### 5.2 Firing negative controls

The same instrument must fire on a deliberately reintroduced lookup and on the
pre-conversion GHASH control:

* `aes::reference::sub_bytes` emits `mov (%rcx,%rdx,1),%cl` — an indexed load
  from the S-box base, with the state byte as index;
* `modes::gcm::negative_control_branchy_mul` emits data-dependent `jne`/`jb`
  transfers.

Both are in `raw/portable-audit.txt` from the debug test artifact. The instrument
fires on both and does not fire on the production carriers above.

### 5.3 Leakage instrument status

`valgrind` exists only in `openssl-rs-court-tools:1`, not in the default
`openssl-rs-court:1` used for this batch; no ctgrind poison harness or dudect
harness was supplied with this task. The dynamic cache-leakage / ctgrind check is
therefore **`NOT_RUN`**, not a pass. The disassembly audit and its firing controls
are the only leakage-adjacent evidence here.

Consequently: **no constant-time claim is made.** Absence of a secret-indexed
load or a secret-dependent branch in the emitted release code is not evidence of
constant time: `cmov` latency, cache-set behaviour, port contention, compiler
version and feature dispatch are unassessed. The construction is described as
*constant-pattern*, which is exactly what was observed.

`gf_mul_portable`'s both operands, including the accumulated authentication
state `Xi`, are treated as secret-associated; no conclusion is inherited from the
`pclmulqdq` carrier.

## 6. Gate

`raw/portable-gate.txt`:

* `cargo fmt --all -- --check` — pass;
* `cargo clippy --all-targets -- -D warnings` — pass;
* `cargo test --lib -- --test-threads=4` — **2558 passed, 0 failed, 56 ignored**
  (baseline 2544 passed / 0 failed / 56 ignored; ignored count unchanged, so no
  newly ignored test). The working tree already carried 4 uncommitted GHASH
  tests before this batch; this batch adds 10 (4 in `src/aes/portable.rs`, 3 in
  `src/aes.rs`, 2 in `src/aes/research.rs`, 1 in `src/modes/gcm.rs`), so
  2544 + 4 + 10 = 2558.

Memory: `raw/portable-memory.txt`. Host `available` 27 GiB, swap free 1 GiB;
cap = min(4, 27−8) = 4 GiB, floor 2 → 4g. One heavy command at a time,
`CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`, no release `--test` build.

## 7. Performance

### 7.1 Release, same exported entry points (`raw/portable-bench-release.txt`)

| AES | hardware enc | hardware dec | portable enc | portable dec |
|---|---:|---:|---:|---:|
| 128 | 5 271.2 MB/s | 5 185.3 MB/s | 13.4 MB/s | 12.4 MB/s |
| 192 | 4 128.2 MB/s | 4 402.5 MB/s | 11.2 MB/s | 10.4 MB/s |
| 256 | 4 635.9 MB/s | 4 648.8 MB/s | 9.6 MB/s | 8.9 MB/s |

On this machine the hardware path stays in front: the **shipping** number is the
AES-NI number. The portable number is the **fallback's** number, measured because
an unmeasured fallback is assumed unusable.

### 7.2 Before/after in the same unoptimised profile (`raw/portable-bench-debug.txt`)

| AES | table enc | circuit enc | table dec | circuit dec |
|---|---:|---:|---:|---:|
| 128 | 3.7 MB/s | 0.8 MB/s | 0.9 MB/s | 0.8 MB/s |
| 192 | 3.1 MB/s | 0.7 MB/s | 0.7 MB/s | 0.7 MB/s |
| 256 | 2.7 MB/s | 0.6 MB/s | 0.6 MB/s | 0.6 MB/s |

The circuit is slower, as expected for a table-free construction: about 4.6×
slower for encryption and about 1.1× for decryption in this profile. S-box work
alone is 113.2 ns vs 1 725.6 ns per 16 bytes (≈15×). No release build of the
table reference was made: it is no longer part of the production artifact, so
§7.1 is the honest absolute fallback number and §7.2 is the only same-profile
before/after comparison.

## 8. Evidence dimensions (kept separate)

* **Proved** (within the stated domain): exhaustive 8-bit S-box equivalence for
  scalar, bitsliced and composite arms; byte-identical schedules over the
  enumerated key population; FIPS-197 C.1–C.3; `AesKey` layout by compile-time
  assert.
* **Tested**: full library suite 2558/0/56; focused AES 13 tests, GCM 27 tests;
  GHASH portable equivalence over the enumerated operand set; firing controls.
* **Observed**: release disassembly of `659ad8c4…` (no secret-indexed loads in
  the AES carriers; none in portable GHASH; only public-indexed schedule loads in
  `add_round_key`); throughput numbers above.
* **Unassessed**: dynamic cache leakage (ctgrind/dudect `NOT_RUN`); constant-time
  behaviour; other architectures, compilers and optimisation levels; a
  minimised Boyar–Peralta circuit; formal equivalence beyond the exhaustive
  8-bit domain.
* **Independently reproduced**: **not** independently reproduced. Every run in
  this bundle was executed by this batch; no second reviewer or venue repeated
  it.

## 9. Non-claims

* Not claiming constant-time AES or GHASH.
* Not claiming cache-timing resistance observed dynamically.
* Not claiming the fallback is competitive with AES-NI.
* Not claiming the hardware path changed.
* Not claiming tables are absent from test builds (they are the reference).
* Not claiming OpenSSL parity or `SAFE_COMPATIBLE` graduation.
* Not claiming independent reproduction.
* Not claiming coverage beyond x86_64 + rustc 1.98.1 + the court profiles used.

## 10. Reproduction

```text
docker/openssl-rs-court.sh exec sh -lc '
  export PATH=/usr/local/cargo/bin:$PATH; cd /work;
  cargo test --lib aes::research::pfp63_benchmarks -- --nocapture --test-threads=1;
  cargo build --release --example pfp63_bench;
  PFP63_ITERS=20000000 ./target/release/examples/pfp63_bench;
  OPENSSL_ia32cap=~0x2000000 PFP63_ITERS=2000000 ./target/release/examples/pfp63_bench;
  bash evidence/performance-frontier/campaigns/PFP-63/raw/portable-audit.sh'
```
