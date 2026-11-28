# PFP-47 — quantifying the authority's squaring advantage

**Item:** PFP-47. **No production source changed; nothing committed or pushed.**
This closes the advantage PFP-41 named but did not measure. The rejected
dedicated-squaring kernel (PFP-6) was **not** re-run.

## 0. Answer

At the operand width this crate's DH ladder actually uses — the **2048-bit
modulus, 32 limbs** — the authority's `a == b` path (`bn_sqr8x_mont`) costs
**449.2 ns** and its own multiply path (`bn_mulx4x_mont`) costs **631.2 ns**, so
the multiply is **1.401×** the squaring: the authority's squaring is **28.6 %
cheaper per call**. At the 4-limb geometry the PFP-45 text assumed, the same
comparison is **1.003×** (no advantage at all: `bn_mul_mont` only enters
`bn_sqr8x_mont` when `n >= 8` and `n % 8 == 0`).

The advantage is therefore **real and measurable at our operands**, but it is
**not a separately recoverable lever for this build**. It exists because the
authority's hand-written BMI2/ADX kernel can emit the symmetric square schedule
with two independent carry chains; our baseline-ISA kernel cannot. PFP-6 already
measured the only squaring shape our compiler produces at 2048 bits: **1.045×
the multiply** (C transcription) and **1.082× / 1.268×** the SOS/CIOS whole
operation. A schematic upper bound for a captured advantage is
`0.8333 (squaring share) × (1 − 1/1.4015) = 23.9 %` of ladder Montgomery time —
material in principle, unreachable without the ADX work PFP-41 identified. It
belongs to that item, not to a new squaring schedule.

## 1. Identity and method

| field | value |
|---|---|
| branch / HEAD | `staging`, `854a8940` |
| build-relevant dirty paths | existing worktree changes only; **PFP-47 changed none** |
| authority DSO | `forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3` sha256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| harness source | `bench_sqr.c` sha256 `83ffd7a9bcbccae0f9062cf6e611f0ba48ce303b341608797d27259174909067` |
| harness binary | `court/tmp/pfp47/bench_sqr` sha256 `9e9476f6cc1c4e9f435614bc6d9227c00c86095852509e574ec2a39ddbe709eb` |
| CPU / pinning | i9-13900K, `taskset -c 1`, one process per width |
| method | 30,000 calls/batch, 15 interleaved repetitions, median of batch means; paired ratio median with 2,000-resample bootstrap 95 % interval |

Both arms call `BN_mod_mul_montgomery` with two BIGNUMs of **equal value**:

* `sqr`: the same `BIGNUM` pointer twice → `bn_mul_mont` sees `ap == bp` and, for
  `n >= 8`, `n % 8 == 0`, enters `bn_sqr8x_mont` (authority `x86_64-mont.s:19-23`);
* `mul`: two distinct allocations with equal limbs → `ap != bp` → `bn_mul4x_mont`
  → `bn_mulx4x_mont` on this ADX-capable CPU (`x86_64-mont.s:0x15c366`).

Only pointer identity differs. The two results were compared byte for byte
before timing (`CHECK equal` on every width).

## 2. Measurement

| bits | limbs | authority sqr (ns) | authority mul (ns) | mul / sqr | 95 % CI |
|---:|---:|---:|---:|---:|---|
| 256 | 4 | 18.392 | 18.483 | **1.0032** | [0.9850, 1.0048] |
| 1024 | 16 | 125.663 | 162.634 | 1.2990 | [1.2802, 1.3750] |
| **2048** | **32** | **449.197** | **631.237** | **1.4015** | **[1.3605, 1.4104]** |
| 3072 | 48 | 990.319 | 1426.863 | 1.4379 | [1.4364, 1.4581] |
| 4096 | 64 | 1737.619 | 2547.952 | 1.4668 | [1.4654, 1.4786] |

Raw: `raw/authority-sqr-vs-mul.txt`; harness identity:
`raw/harness-identity.txt`.

The 32-limb row is the one that matters: `run_mont_ladder` squares the base at
`n = md.len()` limbs (`src/bn/arith.rs`, `run_mont_ladder*`), and the DH groups in
the preset court are 2048-bit moduli. The 4-limb row is the geometry the PFP-45
projection assumed; the authority derives **no** squaring advantage there.

## 3. Verdict

* **Measurable at our operands:** 28.6 % per squaring at 32 limbs.
* **Not recoverable from a squaring-shaped schedule on this build:** the baseline
  x86-64 kernel is `mul`+`setb`+`adc` (PFP-41: 8 arithmetic instructions/product,
  0 `mulx`/`adcx`/`adox`), and the dedicated-squaring form the compiler can emit
  measured **1.045× slower** at 2048 bits (PFP-6 `CROSSOVER.md`), 1.082× the SOS
  and 1.268× the CIOS whole operation (`PFP-6/RECEIPT.md`). Re-running it is not
  authorised and was not done.
* **Attribution:** the authority's 1.40× is the same BMI2/ADX carry-chain idiom
  as its 2.08× multiply advantage (PFP-41 §9), not an independent algorithmic
  saving. Landing it means landing the ADX kernel; until then a
  squaring-shaped schedule would be a slower kernel for the 83.33 % squaring
  share of the ladder.

## 4. Memory protocol (per heavy command)

| command | available | Swap free | cap |
|---|---:|---:|---|
| bench compile + all five widths | 19 GiB | 0 GiB | 4 GiB (court `memory.max`) |

One heavy command; `CARGO_BUILD_JOBS=1`; no test build, no release `--test`
build. Swap free was 0 GiB throughout the batch (advisory; cap = min(4,
available − 8) = 4 GiB, floor met).

## 5. Unsafe accounting

| category | content |
|---|---|
| eliminated / relocated / introduced | none (no source change) |
| hidden | 0 |
| untouched | every exported symbol, layout, allocator seam and detector |
