#!/usr/bin/env python3
"""make_results.py — assemble RESULTS.md's generated tables from the evidence.

Reads raw/disasm/classification.tsv and timing/raw/timing-summary.json and
writes RESULTS.md. The narrative is fixed text; every number in the tables is
read from the recorded files (the per-width counts are the test's printed
output, quoted verbatim).
"""
import csv
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

PER_WIDTH = [
    (4, 882), (6, 1058), (9, 1352), (16, 2178),
    (32, 968), (48, 968), (64, 392), (128, 392),
]

TIMING_ORDER = [
    "modexp2048", "modexp8192", "rsa2048", "dh-ffdhe2048", "ecdsa256",
    "dh-modp2048", "dh-synth2048", "dh-ffdhe3072", "dh-synth3072",
]

PREVIOUS = {
    "modexp2048": 2.069, "modexp8192": 2.452, "rsa2048": 2.484,
    "dh-ffdhe2048": 2.071, "ecdsa256": 10.24,
}


def audit_table():
    rows = list(csv.DictReader(open(os.path.join(HERE, "raw/disasm/classification.tsv")),
                               delimiter="\t"))
    out = ["| addr | kind | insn | class | flag source | consumed by |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        out.append("| `0x%s` | %s | `%s` | (%s) %s | `%s` | `%s` |"
                   % (r["addr"], r["kind"], r["insn"], r["class"], r["sub"],
                      r["flag_source"], r["consumed"]))
    return "\n".join(out)


def timing_table():
    d = json.load(open(os.path.join(HERE, "timing/raw/timing-summary.json")))
    out = ["| workload | cand µs | prev µs | auth µs | cand/prev [CI95] | cand/auth [CI95] | prev/auth [CI95] |",
           "|---|---:|---:|---:|---|---|---|"]
    for w in TIMING_ORDER:
        r = d["workloads"][w]
        a = r["absolute_us"]
        cp, ca, pa = r["cand_over_prev"], r["cand_over_auth"], r["prev_over_auth"]
        out.append("| `%s` | %.1f | %.1f | %.1f | **%.4f** [%.4f, %.4f] | %.4f [%.4f, %.4f] | %.4f [%.4f, %.4f] |"
                   % (w, a["cand"], a["prev"], a["auth"],
                      cp["median_ratio"], cp["ci95"][0], cp["ci95"][1],
                      ca["median_ratio"], ca["ci95"][0], ca["ci95"][1],
                      pa["median_ratio"], pa["ci95"][0], pa["ci95"][1]))
    return "\n".join(out)


def transfer_table():
    d = json.load(open(os.path.join(HERE, "timing/raw/timing-summary.json")))
    out = ["| workload | PFP-6 cand/auth | prev/auth (this run) | cand/prev | predicted cand/auth | measured cand/auth | delta |",
           "|---|---:|---:|---:|---:|---:|---:|"]
    for w in ["modexp2048", "modexp8192", "rsa2048", "dh-ffdhe2048", "ecdsa256"]:
        r = d["workloads"][w]
        prevfig = PREVIOUS[w]
        cp = r["cand_over_prev"]["median_ratio"]
        ca = r["cand_over_auth"]["median_ratio"]
        pa = r["prev_over_auth"]["median_ratio"]
        pred = prevfig * cp
        delta = (ca - pred) / pred * 100.0
        out.append("| `%s` | %.4f | %.4f | %.4f | %.4f | %.4f | %+.2f %% |"
                   % (w, prevfig, pa, cp, pred, ca, delta))
    return "\n".join(out)


NARRATIVE = """# M-A1 — fixed-width native Rust specialisation of the CIOS kernel: results

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
"""

NARRATIVE2 = """
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

"""

NARRATIVE3 = """
## 6. Timing (paired against the previous build)

Instrument `bench_pfp5.c` (`ac605a5a…`), 15 interleaved repetitions, one process
per arm per repetition, order rotated, `taskset -c 1`, `--prepared`, i9-13900K,
court `openssl-rs-court-tools:1`. Statistic: median of the 15 paired
per-repetition ratios, 95 % percentile bootstrap (20,000 resamples, seed
`0x50465036`). Population frozen before execution: `population.json` sha256
`e7f61248…`. Ratio < 1 means the first-named arm is faster.

"""

NARRATIVE4 = """
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

"""

NARRATIVE5 = """
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
"""


def main():
    lines = [NARRATIVE]
    for n, cases in PER_WIDTH:
        lines.append("| %d | %d | %d | 0 |" % (n, cases, cases))
    lines.append(NARRATIVE2)
    lines.append(audit_table())
    lines.append("")
    lines.append(NARRATIVE3)
    lines.append(timing_table())
    lines.append(NARRATIVE4)
    lines.append(transfer_table())
    lines.append(NARRATIVE5)
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write("\n".join(lines))
    print("wrote RESULTS.md")


if __name__ == "__main__":
    main()
