# PFP-5 — the bound, the profile, and the decision

**Item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-5.
**Claim class:** `SCOPED_OBSERVATION` on the court venue (no PMU exposed).
**Baseline digest:** `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77`
(`staging` `a005a33c4`, source `src/bn/arith.rs` sha256
`06005795079c9957ba2b35c6816c423b507f427705842284aa9c23d0e0759a1c`).
**Candidate digest:** `842efa27197ea8c408d77a8316c1dbb35a06146e0033b7df7d7f9cced88a2f47`.

---

## 1. Profile of the bit-at-a-time ladder (digest `4e6ec312`)

Callgrind instruction counts, one process per workload, `prepared` mode, three
operations per process (the `CHECK` call, one warm-up and one timed batch of one
call), so the totals are *per three operations*; the reported split is the
fraction and the old/new ratio, both of which are three-operation quantities.

| workload | total instructions | `mont_mul_sos_into` | share | other |
|---|---:|---:|---:|---|
| `modexp2048` | 380,171,921 | 370,768,020 | 97.53 % | 2.47 % |
| `modexp8192` | 22,417,200,193 | 22,225,963,716 | 99.15 % | 0.85 % |
| `dh-ffdhe2048` | 380,450,886 | 370,768,020 | 97.45 % | 2.55 % |
| `dh-modp2048` | 380,451,774 | 370,768,020 | 97.45 % | 2.55 % |
| `rsa2048` | 314,475,001 | 225,093,884 | 71.58 % | 28.42 % |

`rsa2048` additionally spends 64,617,738 instructions (20.55 %) in
`bn::limbs::mod_inverse_consttime` — the **one-time** RSA blinding-parameter
construction, amortised over the timed loop and therefore smaller per steady-state
operation; the remaining BIGNUM/BN_CTX overhead is 7.87 %.

### Split inside the constant-time ladder

`run_mont_ladder` performs, for `bits = 64 * width`:

* exactly `bits` squarings (`mont_mul_into(&base, &base, …)`);
* exactly `bits` multiplications (`mont_mul_ladder_into(&acc, &base, …)`);
* three conversions: base `ad·R²·R⁻¹`, `R = R²·R⁻¹`, and the final `acc·1`;
* `R² = 2^(128n) mod m` by fixed-pattern doubling (`pow2_mod_consttime`), and
  `n0` by Newton iteration — precomputation, once per call.

Because `LADDER_DEDICATED_SQUARING = false`, a squaring and a multiplication are
the **same** kernel, so the two halves cost the same per operation:

| component | share of Montgomery operations |
|---|---:|
| squarings | 50.0 % (`n` of `2n`) |
| multiplications | 50.0 % (`n` of `2n`) |
| conversions | ≈ 0.05 % (2 of `2n+2`) |
| reduction outside Montgomery | **0** — the base is below `R`, so the fold is a Montgomery multiply; there is no division |
| allocation | 18 allocator entries per operation in the baseline (`WORKLOADS.json`; PFP-0); the window adds exactly 2 (the `2^w`-row table and the selected row), both still sub-0.1 % of wall at 2048 bits |
| precomputation (`R²`, `n0`) | once per call, sub-0.1 % at 2048 bits |

## 2. Fixed-window operation arithmetic (including the scan)

A left-to-right fixed window of width `w` over a `bits`-bit exponent:

* `windows = ceil(bits / w)`; a multiplication per window → `windows`;
* exactly `w` squarings per window → `windows · w ≈ bits`;
* a `2^w`-entry table built by successive multiplication → `2^w − 2`;
* a **full masked scan** per window: all `2^w` rows × `n` limbs, assembled with
  and/or under an all-ones/all-zeros `constant_time_eq_s` mask. Modelled at
  three instructions per limb-select and calibrated against the measured
  `mont_mul_sos_into` cost (30,170 instructions at `n = 32`, scaling as `n²`),
  the scan is `S(w) = 2^w · ceil(N/w) · n · 3 / (30170 · (n/32)²)` Montgomery-mul
  equivalents. It is independent of `N` for fixed `w`: 26.1 (`w=4`), 41.8
  (`w=5`), 69.7 (`w=6`) at `N=2048`, and 26.1 / 41.7 / 69.5 at `N=8192`.

Baseline = `2N + 2` Montgomery multiplications. Window = `ceil(N/w)·w +
ceil(N/w) + (2^w − 2) + S(w) + 2`.

**N = 2048**

| w | squares | main mult | precompute | scan | total (mont muls) | speedup | removed |
|---|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2048 | 512 | 14 | 26.1 | 2602.1 | 1.575 | 36.5 % |
| 5 | 2050 | 410 | 30 | 41.8 | 2533.8 | 1.617 | 38.2 % |
| 6 | 2052 | 342 | 62 | 69.7 | 2527.7 | 1.621 | 38.3 % |

**N = 8192**

| w | squares | main mult | precompute | scan | total (mont muls) | speedup | removed |
|---|---:|---:|---:|---:|---:|---:|---:|
| 4 | 8192 | 2048 | 14 | 26.1 | 10282.1 | 1.594 | 37.3 % |
| 5 | 8195 | 1639 | 30 | 41.7 | 9907.7 | 1.654 | 39.5 % |
| 6 | 8196 | 1366 | 62 | 69.5 | 9695.5 | 1.690 | 40.8 % |

`w = 5` is admitted: it is within 0.3 % of the best at `N=2048` and within 2 % of
the best at `N=8192`, with a smaller table and scan than `w = 6`.

## 3. The Amdahl bound

A window can at most remove the **multiplication half** of the ladder: the `N`
squarings, the conversions and the precomputation remain. With zero precompute
and zero scan the ceiling is `N / (2N + 2) ≈ 49.98 %` of Montgomery work; with
the counted scan and precompute at `w = 5` it is `(2N − (N + N/w + 30 + S))/2N`,
i.e. **38.2 % at 2048 bits and 39.5 % at 8192 bits** of Montgomery work.

Since Montgomery work is 96.7–99.2 % of wall on `modexp`/DH, the wall-clock
bound is 37–39 %; on RSA the same Montgomery fraction applies per steady-state
operation (the blinding inverse is one-time), so the bound is 34–39 %. Every
affected bound is far above the 10 % refusal threshold.

## 4. Decision

**PROCEED.** The removable fraction is 38.2 % (`modexp2048`), 39.5 %
(`modexp8192`), 34–39 % (RSA) and 38.2 % (DH) — not a case where the window's
mul-count reduction is swamped by the irreducible squaring half, the precompute
or the masked scan. The measured result (§`TIMING.md`) removes 39.5 %, 39.8 %,
34.7 % and 39.5 %, matching the bound.
