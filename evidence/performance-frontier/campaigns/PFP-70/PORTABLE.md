# PFP-70 — closing the table-free AES throughput gap

## 0. Scope and identity

Task: replace the slow bitsliced field-exponentiation S-box in the portable
(non-AES-NI) AES arm with a minimised Boyar–Peralta circuit, add a fixed-slice
form, measure every arm on one profile, try wider lanes, and keep the exported
`AES_KEY` bytes identical.

| | |
|---|---|
| branch / HEAD | `staging` / `b069a680` (uncommitted working tree; no commit or push made) |
| source files changed | `src/aes/portable.rs`, `src/aes/research.rs` |
| new evidence | `evidence/performance-frontier/campaigns/PFP-70/` |
| authority / machine | `openssl-3.6.4-production`; x86_64, 30 logical CPUs |
| venue | `docker/openssl-rs-court.sh exec`, image `openssl-rs-court:1` |

`AesKey` and `src/aes.rs` are unchanged. The exported schedule is untouched;
the fixed-slice key representation is derived from it per block (see §3).

## 1. The circuit: provenance and gate count

The forward S-box is the published **Boyar–Peralta–Calik** netlist
`SLP_AES_113.txt`:

* `http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt`
* paper: J. Boyar and R. Peralta, *A new combinational logic minimization
  technique with applications to cryptology*,
  <https://eprint.iacr.org/2009/191.pdf>.

It was not reconstructed from memory. The transcription follows two independent
published renditions of the same list:

1. BearSSL `src/symcipher/aes_ct.c`, `br_aes_ct_bitslice_Sbox` (which cites the
   same netlist and paper);
2. RustCrypto `aes` 0.9.4, `src/backends/fixslice/sbox.rs`
   (`sub_bytes` and `inv_sub_bytes`), whose header cites `SLP_AES_113.txt`
   directly.

Gate count, measured from the transcribed source by counting operators:

| circuit | XOR | AND | total | NOTs |
|---|---:|---:|---:|---:|
| forward `bp_sub_bytes` | 81 | 32 | **113** | 4, applied separately by `sub_bytes_nots` |
| inverse `bp_inv_sub_bytes` | 93 | 34 | 127 | 0 (true inverse) |

The forward count is exactly the published 113; the four NOTs are carried
outside the netlist, as both references do. The inverse list is the published
inverse netlist. Both are proved equal to the authority-derived table over all
256 inputs in `aes::portable::tests::boyar_peralta_sbox_is_exhaustively_equal_to_the_table`.

The netlist is generic over the lane carrier (`bp_sub_bytes::<T>`), so the same
gate list is instantiated for `u16` in production and for `u32`/`u64` in the
lane-width experiment.

## 2. Arms tried and measurements

Two profiles, both reported:

### 2.1 Same harness, same profile (unoptimised test profile)

`raw/test-profile-arms.txt`, `cargo test --lib aes::research::pfp70_benchmarks
-- --nocapture --test-threads=1`. Every arm runs through the same `block_bench`
loop, with the table reference present. MB/s:

| AES | arm | enc | dec |
|---|---|---:|---:|
| 128 | table | 3.36 | 0.91 |
| 128 | exponentiation | 0.81 | 0.80 |
| 128 | Boyar–Peralta planar | 1.44 | 1.23 |
| 128 | **fixed-slice** | **4.33** | **4.15** |
| 192 | table | 2.87 | 0.74 |
| 192 | exponentiation | 0.69 | 0.66 |
| 192 | Boyar–Peralta planar | 1.22 | 1.03 |
| 192 | **fixed-slice** | **3.62** | **3.49** |
| 256 | table | 2.46 | 0.63 |
| 256 | exponentiation | 0.59 | 0.57 |
| 256 | Boyar–Peralta planar | 1.06 | 0.90 |
| 256 | **fixed-slice** | **3.15** | **3.00** |

The unoptimised test profile is noisy run-to-run (an earlier identical run gave
fixslice 6.14 / 5.22 / 4.39 and table 3.61 / 3.23 / 2.77). The ranking was the
same in every run: fixed-slice > table > BP-planar > exponentiation. Fixed-slice
is selected by measurement.

### 2.2 Release, exported entry points, against the authority's table arm

Measured per the exported block API, same loop shape, on the same host:

| AES | portable fixslice enc | authority table enc | ratio | portable fixslice dec | authority table dec | ratio |
|---|---:|---:|---:|---:|---:|---:|
| 128 | 68.9 MB/s | 267.1 MB/s | 3.88× | 52.2 MB/s | 160.2 MB/s | 3.07× |
| 192 | 58.9 MB/s | 224.2 MB/s | 3.81× | 44.0 MB/s | 130.8 MB/s | 2.97× |
| 256 | 50.7 MB/s | 191.3 MB/s | 3.77× | 37.6 MB/s | 110.6 MB/s | 2.94× |

Portable: `raw/release-portable.txt` (`OPENSSL_ia32cap=0x0:0x0`,
`PFP63_ITERS=3000000`). Table: `raw/authority-table.txt`
(`evidence/.../PFP-70/bench_table.c`, linked against the pinned authority,
`OPENSSL_ia32cap=0x0:0x0`, C `-O2`, the same block-API loop shape as the Rust
example). The authority's low-level `AES_encrypt` is the Te/Td-table arm in this
build and its throughput is identical with and without the AES bit cleared.

**10× target: met.** The worst case is 3.88× slower than the table arm, not
10×. The comparison is cross-implementation (C `-O2` vs Rust release) but the
same machine and the same block loop.

### 2.3 Before/after (starting point preserved)

| AES | before (PFP-63) enc | after enc | factor | before dec | after dec | factor |
|---|---:|---:|---:|---:|---:|---:|
| 128 | 13.4 MB/s | 68.9 | 5.14× | 12.4 | 52.2 | 4.21× |
| 192 | 11.2 MB/s | 58.9 | 5.26× | 10.4 | 44.0 | 4.23× |
| 256 | 9.6 MB/s | 50.7 | 5.28× | 8.9 | 37.6 | 4.22× |

## 3. Key schedule handling (ABI constraint)

`AES_set_encrypt_key` / `AES_set_decrypt_key` still return the authority's exact
`AES_KEY` bytes. `portable::expand_encrypt_key` and `src/aes.rs`'s byte-swap and
decrypt transform are unchanged; `AesKey` remains `rd_key: [u32; 60]` +
`rounds: c_int` (244 bytes, offset asserts unchanged).

The fixed-slice arm needs a different internal round-key representation. It is
derived **inside the block call**, from the exported stored schedule:

1. read the 16 round-key bytes for each round in the same order
   `add_round_key` used (`rk[4*round+c].swap_bytes()`, big-endian bytes);
2. `fix_bitslice` each round key into the eight 16-bit fixed-slice words;
3. use the words directly in the round.

The conversion cost is charged to every measured block: it runs in
`portable::fix_keys` on every call, and it is visible in the emitted code
(§5). The exported schedule is never rewritten or augmented, so the ABI holds.

The fixed-slice driver applies `SubBytes`, `ShiftRows`, `MixColumns`,
`AddRoundKey` in that order each round, with `ShiftRows` explicit and
`MixColumns` as whole-word rotations in the fixed-slice layout. It is not the
fully-folded Adomnicai–Peyrin variant that moves `ShiftRows` into the key
schedule; that folding is **not claimed** here. The measured gain comes from
keeping the state in the fixed-slice representation across all rounds (no
per-round bit transpose) and from rotation-based `MixColumns`.

## 4. Correctness evidence

### 4.1 Exhaustive S-box equivalence (all 256 inputs)

`boyar_peralta_sbox_is_exhaustively_equal_to_the_table`: 256/256 forward and
256/256 inverse, against `AES_SBOX`/`AES_INV_SBOX` (authority-derived). The
fixed-slice bit layout is round-tripped in `fixslice_bitslice_round_trips`.

### 4.2 Block differential for every surviving arm

`all_arms_match_the_reference_block_for_block`: for AES-128/192/256, 32 random
keys per size and 8 random blocks per key, all three arms (exponentiation,
BP-planar, fixed-slice) match `aes::reference` in both directions: 768
encryption and 768 decryption comparisons per arm, 4 608 total, all exact.

### 4.3 Key schedule, both directions, all three sizes

Unchanged existing tests, all passing over `keys_for(bits)` =
all-zero + all-ones + every single-bit key + 512 random keys
(642 / 706 / 770 keys for 128 / 192 / 256):

* `portable_schedule_matches_reference_for_all_sizes` — portable expansion vs
  table transcription, and exported `AES_set_decrypt_key` bytes vs the
  independently transcribed decrypt transform;
* `exported_encrypt_schedule_is_byte_identical_to_reference` — exported encrypt
  schedule bytes exactly equal;
* `portable_block_matches_reference_and_round_trips`.

### 4.4 KATs and modes

FIPS-197 C.1/C.2/C.3 (`fips197_c1_c2_c3`) and the NIST GCM cases run in the
full suite; the existing CBC/CTR/GCM mode and streaming tests pass unchanged
(§6).

## 5. Re-run disassembly audit (not inherited)

`raw/audit-after.txt`, produced by `audit_pfp70.sh` on the release example with
symbol ranges read from `nm -S -C` (so layout changes do not stale it).
Artefact `target/release/examples/pfp63_bench`; the table/`AesKey` dispatch is
unchanged.

| carrier | indexed memory operands | conditional transfers |
|---|---|---|
| `portable::bp_sub_bytes::<u16>` | **none** (no memory operand at all) | none |
| `portable::bp_inv_sub_bytes::<u16>` | **none** (no memory operand at all) | none |
| `aes::aes_encrypt_portable` | only `lea` arithmetic, `nop`, and one stack-spill reload `0x50(%rsp,%r15,1)` where `%r15 = rounds` (public, loaded from `key->rounds` at `0xf0(%rdx)`) | loop-count branches only |
| `portable::fix_keys` | round-key loads `0xNN(%rsi,%rax,1)` and stores `(%rdi,%rax,1)`, `%rax` = public round offset | `cmov` on the public round count (loop-bound clamp) |
| `AES_set_encrypt_key` / `AES_set_decrypt_key` | `rd_key` indexed only by public `i/j` loop counters | public loop control |
| `AES_encrypt` / `AES_decrypt` | one jump-table dispatch load (`movslq (%rdx,%rcx,4)`), public CPU-capability dispatch; stack slots indexed by public loop counters | dispatch + loop control |

No load or address in any portable carrier is selected by a key or state byte.
The two S-box carriers contain no memory operand at all.

The instrument fires on the controls (same debug test artefact):

* `aes::reference::sub_bytes` emits `mov (%rcx,%rdx,1),%cl` — an indexed load
  from the S-box base with the state byte as index;
* `gcm::negative_control_branchy_mul` emits data-dependent `jne`/`jb`.

**No constant-time claim is made.** Absence of a secret-indexed load and of a
secret-dependent branch in these carriers is not a constant-time proof: `cmov`
latency, cache-set behaviour, port contention, compiler version and feature
dispatch are unassessed. ctgrind and dudect remain **`NOT_RUN`** on this venue
(no ctgrind poison harness or dudect harness was supplied). The construction is
described as *constant-pattern*, which is what was observed.

## 6. Gate

Commands in the court with `OPENSSL_RS_COURT_MEM=4g
OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1
CARGO_PROFILE_TEST_DEBUG=0`, one heavy command at a time:

* `cargo fmt --all -- --check` — **pass**;
* `cargo clippy --all-targets -- -D warnings` — **pass**;
* `cargo test --lib -- --test-threads=4` —
  **2569 passed, 0 failed, 56 ignored**
  (baseline 2564 / 0 / 56; this batch adds 3 tests in `portable.rs` and 2 in
  `research.rs`, i.e. +5; ignored count unchanged, so no newly ignored test);
* `OPENSSL_ia32cap=0x0:0x0 cargo test --lib -- --test-threads=4` —
  **2569 passed, 0 failed, 56 ignored** (the portable path exercised throughout).

Memory (`free -g` on the host immediately before each command): total 45 GiB,
available 18–27 GiB; swap free went from 8 GiB to 0 GiB (fully used) over the
session. Swap free was below 16 GiB throughout, so the cap is
`min(4, available − 8)` = **4 GiB** (floor 2), recorded, and every heavy command
ran with `OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g`, one at a time.
Available never fell below 18 GiB and no OOM occurred. The court image has no
`free` binary, so `raw/memory.txt` records the host measurement.

## 7. Wide-lane experiment (32-bit vs 64-bit)

The single-block exported ABI can supply exactly one block, so it cannot use
lanes wider than 16 bits. To answer the question, the same fixed-slice round was
run with two blocks in a `u32` and four blocks in a `u64`, each block in its own
16-bit sub-lane (the S-box and the linear layer are bitwise / within-lane).
`raw/wide-lane.txt`, same unoptimised profile, MB/s over all blocks processed:

| AES | `u16` × 1 | `u32` × 2 | `u64` × 4 |
|---|---:|---:|---:|
| 128 | 4.26 | 5.83 | 11.04 |
| 192 | 3.61 | 4.96 | 9.45 |
| 256 | 3.11 | 4.17 | 8.26 |

Wider lanes do help **per byte** when several blocks are available: `u64` is
about 1.9× `u32` and 2.6–2.9× the single-block `u16` form. But the exported
`AES_encrypt`/`AES_decrypt` API is one block, so the shipped path stays `u16`;
the wide forms are test-only experiments in `research.rs`. There is no target
feature requirement: the wide forms are plain integer code and sit beside the
narrower form, which remains the one that ships. A future batched mode API
(CTR/CBC bulk) is the only place the 64-bit lane could ship, and it is not part
of this task.

## 8. What is proved, tested, observed, and not claimed

* **Proved** (within the stated 8-bit domain): 256/256 forward and inverse
  S-box equivalence for the BP-Calik circuit; fixed-slice bitslice round-trip.
* **Tested**: every arm equals the table reference in both directions over 4 608
  block comparisons; exported schedules byte-identical over the 2 118-key
  population (642/706/770 by size), both directions; FIPS-197 and GCM KATs;
  full library suite 2569/0/56 twice (with and without AES-NI); firing negative
  controls.
* **Observed**: release disassembly patterns above; release throughput 68.9 /
  58.9 / 50.7 MB/s encryption, within 3.9× of the authority table arm.
* **Not claimed**: constant-time behaviour or dynamic leakage resistance
  (ctgrind/dudect `NOT_RUN`); the fully-folded Adomnicai–Peyrin key schedule;
  that the wide-lane forms ship; independence (every run was by this batch);
  behaviour beyond x86_64 + the court toolchain.
* **Refused / could not obtain**: nothing was reconstructed from memory. The BP
  gate list and the fixed-slice layout were taken from the published sources in
  §1. The only thing not attempted is the folded key schedule of §3, which is
  stated as out of scope rather than claimed.

## 9. Reproduction

```text
docker/openssl-rs-court.sh exec sh -lc '
  export PATH=/usr/local/cargo/bin:$PATH; cd /work;
  cargo fmt --all -- --check;
  cargo clippy --all-targets -- -D warnings;
  cargo test --lib -- --test-threads=4;
  OPENSSL_ia32cap=0x0:0x0 cargo test --lib -- --test-threads=4;
  cargo test --lib aes::research::pfp70_benchmarks -- --nocapture --test-threads=1;
  cargo test --lib aes::research::pfp70_wide_lane_benchmarks -- --nocapture --test-threads=1;
  cargo build --release --example pfp63_bench;
  OPENSSL_ia32cap=0x0:0x0 PFP63_ITERS=3000000 ./target/release/examples/pfp63_bench;
  bash evidence/performance-frontier/campaigns/PFP-70/audit_pfp70.sh'
```
