# PFP-5 — timing

**Venue:** the court container, no PMU, `taskset -c 1`; the result is a
`SCOPED_OBSERVATION`, not a frontier result.
**Protocol:** 15 process-level repetitions, balanced before/after order, median
of each process's five batch medians, median of the paired ratios, 95 %
percentile bootstrap interval (20,000 resamples). `prepared` mode.
**Harness:** `courts/performance-frontier/pfp5/bench_pfp5.c` (the PFP-1 workload
driver), compiled `-O2 -g`.

## 1. Candidate vs authority

| workload | candidate µs | authority µs | ratio | 95 % CI |
|---|---:|---:|---:|---|
| `modexp2048` | 2977.3 | 1190.7 | **2.501** | [2.500, 2.501] |
| `modexp8192` | 215,773.2 | 73,709.0 | **2.927** | [2.924, 2.930] |
| `dh-ffdhe2048` | 2977.9 | 1191.0 | **2.500** | [2.499, 2.502] |
| `dh-modp2048` | 2977.9 | 1191.1 | **2.500** | [2.499, 2.501] |
| `rsa2048` | 1045.4 | 350.5 | **2.982** | [2.980, 2.985] |
| `ecdsa256` (control) | 130.8 | 12.7 | 10.238 | [10.215, 10.262] |

The authoritative mapping from this table is: `modexp2048` 2.501, `modexp8192`
2.927, **RSA 2.982** and **DH 2.500**. The PFP-5 commit message transposed the
RSA and DH "before" values; `RECEIPT.md` §8 records the correction and the
correct pairing. The candidate figures in this table were never swapped.

## 2. Paired before/after at the two candidate digests

Baseline `4e6ec312` and candidate `842efa27`, both rebuilt from their source and
linked with the identical shell object and version script; one process per
library per repetition, interleaved.

| workload | baseline µs | candidate µs | speedup | 95 % CI | removed |
|---|---:|---:|---:|---|---:|
| `modexp2048` | 4914.0 | 2976.6 | **1.652** | [1.651, 1.652] | 39.5 % |
| `modexp8192` | 358,243.6 | 215,747.5 | **1.660** | [1.659, 1.662] | 39.8 % |
| `dh-ffdhe2048` | 4922.2 | 2980.6 | **1.652** | [1.651, 1.652] | 39.5 % |
| `dh-synth2048` | 4921.0 | 2978.0 | **1.652** | [1.651, 1.653] | 39.5 % |
| `dh-synth3072` | 17,017.0 | 10,304.9 | 1.653 | [1.648, 1.654] | 39.5 % |
| `dh-ffdhe3072` | 17,023.5 | 10,296.0 | 1.653 | [1.650, 1.655] | 39.5 % |
| `rsa2048` | 1601.7 | 1044.8 | **1.532** | [1.530, 1.535] | 34.7 % |
| `ecdsa256` (control) | 131.2 | 130.1 | 1.004 | [1.003, 1.009] | 0.4 % |

The base digest reproduces the stated starting ratios: base/authority is 4.13
(`modexp2048`, stated 4.20), 4.86 (`modexp8192`, stated 4.87), 4.57 (`rsa2048`,
stated 4.57) and 4.13 (DH, stated 4.13). The `modexp2048` discrepancy is 1.7 %
and is within the run-to-run spread of the two campaigns; it does not change the
decision.

## 3. Does the measured gain match the bound?

Predicted at `w = 5` (`BOUND.md` §2–3): 38.2 % removed at 2048 bits
(1.617×), 39.5 % at 8192 bits (1.654×), and 34–39 % for RSA.

| workload | predicted removed | measured removed | verdict |
|---|---:|---:|---|
| `modexp2048` | 38.2 % | **39.5 %** | met, 1.3 pp above |
| `modexp8192` | 39.5 % | **39.8 %** | met |
| DH 2048 | 38.2 % | **39.5 %** | met |
| `rsa2048` | 34–39 % | **34.7 %** | met (blinding/recombination overhead not windowable) |

The measured gain meets or slightly exceeds the arithmetic bound. The small
excess is consistent with removing per-iteration loop/select overhead in
addition to the removed multiplications; the model counts only Montgomery
multiplications and the calibrated scan.

Instruction counts (callgrind) agree: `modexp2048` total 380,171,921 →
232,973,247 (1.632× fewer), `mont_mul_sos_into` 370,768,020 → 225,476,412
(1.644× fewer); `modexp8192` total 22,417,200,193 → 13,497,383,045 (1.661×);
`rsa2048` `mont_mul_sos_into` 225,093,884 → 137,837,012 (1.634×), with the
one-time `mod_inverse_consttime` (64,617,738 → 64,617,726) unchanged.

**No timing obligation is discharged by this performance result.**
