# PFP-7 — latency and throughput at the digest

**Digest:** `6d002db2…` (unchanged — no source change was made, so the
"sequential build" *is* the current build; there is no separate candidate).
**Harness:** `harness/pfp7_rsa.c` (+ `harness/timing.sh`).
**Protocol:** 15 process repetitions per arm, arms alternated, `taskset -c 1`,
one library per process via `dlopen`; 205 calls per process. Reported per arm as
the median over repetitions; the ratio is the median of paired per-repetition
ratios with a 95 % percentile bootstrap (20,000 resamples, seed `0x50465037`).
Raw: `raw/timing/*.out`, `raw/timing/summary.txt` (two independent runs).

Three statistics are derived from the same per-call samples in each process:

* **latency** — the minimum per-call time, i.e. the steady-state operation with
  no blinding re-creation in it;
* **throughput** — `1 / mean per-call time` over the sustained loop, i.e. the
  re-creation amortised as a real cost of doing this operation repeatedly;
* **blockmed** — median of five 20-call batch means after five warm-up calls,
  which is the PFP-0/PFP-6 row statistic; it contains the re-creation in 3 of 5
  batches and is therefore the largest of the three.

## Run A

| statistic | candidate | authority | ratio | 95 % CI |
|---|---:|---:|---:|---|
| latency (min/op) | 639,655 ns | 340,430 ns | **1.8790** | [1.8760, 1.8797] |
| sustained (mean/op → throughput) | 803,075 ns → **1,245 ops/s** | 348,795 ns → **2,867 ops/s** | 2.3024 | [2.2823, 2.3064] |
| blockmed (row statistic) | 873,121 ns | 350,697 ns | **2.4897** | [2.4827, 2.4904] |

## Run B (independent)

| statistic | candidate | authority | ratio | 95 % CI |
|---|---:|---:|---:|---|
| latency | 641,681 ns | 340,410 ns | 1.8850 | [1.8841, 1.8852] |
| sustained | 828,886 ns → 1,206 ops/s | 353,290 ns → 2,831 ops/s | 2.3462 | [2.2754, 2.3854] |
| blockmed | 878,796 ns | 351,034 ns | 2.5035 | [2.4931, 2.5401] |

## Against the row's 2.484×

The row value `2.4838×` is reproduced (run A: 2.4897 [2.4827, 2.4904]; run B:
2.5035 [2.4931, 2.5401]; the 0.6 % drift between the two runs is
frequency/thermal, not a code difference — this is one digest measured twice).

The decomposition explains the composition: the *exponentiations* are 1.88×
the authority, while the *blockmed statistic* is 2.49× because it carries the
periodic blinding re-creation (5.2 ms every 32 calls = 162 µs/op, ~15× the
authority's re-creation). Reporting one number would hide which of the two the
optimisation target is. **PFP-7 is about the exponentiations, so 1.88× is the
number it would move**; the 2.48× row figure is inflated by a PFP-1/blinding
property.

## Blinding on/off

| | blinded | unblinded | difference |
|---|---:|---:|---:|
| candidate, median/op | 645,702 ns | 639,208 ns | 6.5 µs (1.0 %) |
| authority, median/op | 344,302 ns | 340,377 ns | 3.9 µs |

Blinding's per-operation convert/invert is unchanged in effect and cheap; its
*re-creation* is the expensive part, and it is periodic (measured: outliers at
call indices 0, 32, 64, 96, 128 of 5.19–5.32 ms; `BN_BLINDING_COUNTER = 32`).

## Whether the bound was met

PFP-7 predicted **no gain from interleaving** (measured ILP probe: 1.113×
[1.110, 1.115] *slower* on this build, slower in every run; `BOUND.md` §2.3) and
implemented nothing, so there is no new digest to measure. The prediction that stands is the refusal: the delivered state is
exactly the sequential build, at 1.88× the authority on the exponentiations. If
interleaving had been implemented at the measured fused ratio, the operation
would have been ≈ 10 % slower.
