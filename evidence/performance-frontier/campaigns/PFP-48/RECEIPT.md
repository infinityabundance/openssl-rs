# PFP-48 receipt — the whole DSO under `-C target-feature=+bmi2`

**Decision: instruction count is not the lever.** Building the *entire* release
DSO with `-C target-feature=+bmi2` reproduces the PFP-46 static bound (mulx
replaces mulq; 10.5–27.9 % fewer instructions per limb product; zero `adcx` /
`adox`), removes the non-inlinable `#[target_feature]` wrapper confound (the
kernel now inlines directly into `mont_mul_ladder_into`, whose only calls are
`memset`), and still buys **no latency** — every workload is equal or slower,
with modexp-2048 reproducibly ≈2.4 % slower. This is a build-configuration
experiment: **no source was modified.**

## 1. Identity (S = frozen source)

| field | value |
|---|---|
| branch / HEAD | `staging`, `af0a5a40ba4ad40732257b64a9aece26d13d6026` |
| `src` tree | `0181f90193fd0de86d26cd714e701380340ee432` |
| `src/bn/arith.rs` | `2d0f42cce3c93a78babb8e96d89e854a570ba51ea4d338d3ab615bec2906e992` |
| source change vs PFP-46 parent | `git diff --stat 4fcd2cc4 af0a5a40 -- src Cargo.toml Cargo.lock build.rs` → **empty** (PFP-46 landed evidence only) |
| rustc / cargo / cc | 1.98.1 (48a229cea) / 1.98.1 / Debian 12.2.0-14+deb12u1 |
| target | `x86_64-unknown-linux-gnu`; CPU i9-13900K (bmi2 + adx present) |
| profile | `release` (`--release --lib --offline`), the campaign DSO path |

**Exact flag string:** baseline `RUSTFLAGS=""`; variant
`RUSTFLAGS="-C target-feature=+bmi2"` applied to the whole crate. Both link with
the same `artifacts/phase2/shell/libcrypto.shell.rs` + `libcrypto.ld` shell.

| artefact | SHA-256 | size |
|---|---|---|
| baseline (portable) `court/tmp/pfp48/portable/libcrypto.so.3` | `033f7fbf925b7451c016c1d1c1a78bfc31895de1ee0ada677fdfe7718837680b` | 17116976 |
| variant (+bmi2) `court/tmp/pfp48/bmi2/libcrypto.so.3` | `b7aded1b82a50827fb93819c1767e7ffde3c222a934defd14d28a4fc0a429808` | 17100976 |

These are **byte-identical** to PFP-46 step-1's static-bound builds
(`raw/step1/build-inputs-{portable,bmi2}.txt`, same source hash), i.e. the
result is exactly reproducible across sessions. PFP-46 step 1 built this same
whole-crate pair but only counted instructions; PFP-46's *latency* run used the
later **dispatched** DSO (`b890760c…`) whose wrappers were the confound. PFP-48
times the whole-crate pair.

## 2. Static disassembly (`raw/opcodes.txt`, `raw/symbols.txt`, `raw/counts.txt`)

Whole-symbol opcode census of `mont_mul_ladder_into`:

```
portable: mulq=102 mulx=0   adcx=0 adox=0 imul=12   (2196 insns)
bmi2:     mulq=0   mulx=121 adcx=0 adox=0 imul=12   (1911 insns, −13.0%)
```

* **`mulx` appears** (121), replacing every `mulq`. **`adcx` / `adox` do not
  appear** — expected: `+bmi2` does not enable ADX, matching PFP-41's warning.
* **The wrapper call is gone/inlined.** `nm` finds only
  `mont_mul_ladder_into` in both DSMs — no `mont_mul_cios_fixed` and no
  `mont_mul_cios_bmi2_*` wrapper symbols. The only `call` instructions inside
  the variant ladder body are five `memset@GLIBC` (accumulator zeroing). So the
  PFP-46 "out-of-line wrapper ate the gain" confound is removed.

Instr/limb-product, same `count_per_product` instrument as PFP-41/46
(`2·N·N` products; tight back-edge loop body body/mul):

| width | portable | +bmi2 | Δ |
|---|---:|---:|---:|
| n=16 | 8.24 | 5.94 | **−27.9 %** |
| n=32 (RSA-2048, DH-2048, modexp-2048) | 9.50 / 13.75 | 8.50 / 9.80 | **−10.5 % / −28.7 %** |
| n=128 (modexp-8192) | 9.50 / 13.75 | 8.50 / 10.00 | **−10.5 % / −27.3 %** |
| n=4 (full arm region) | 422 insns | 322 insns | −23.7 % |

This reproduces PFP-46's 10.5 % (n=32) and 27.9 % (n=16) figures exactly, on the
same source and build path.

## 3. Correctness — VARIANT DSO, verbatim

In-crate PFP-6 differential sets, compiled under `RUSTFLAGS="-C target-feature=+bmi2"`
(`raw/tests/differential-tests.txt`):

```
PFP-6 kernel congruence: sos=7890 cios=7890 sqr=254 mismatches=0
PFP-6 CIOS differential: exhaustive=3018 sampled=7890 mismatches=0
PFP-6 squaring differential: exhaustive=144 sampled=254 mismatches=0
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 2568 filtered out
```

C ABI transcript against the authority (`raw/differential/`):

```
ABI before: 161 lines IDENTICAL to authority
ABI variant: 161 lines IDENTICAL to authority
ABI authority lines: 161
ABI MX=150 RSA=8 DH=2
```

DH 30-row keygen court, variant vs authority with baseline as old-arm witness:

```
MATRIX rows=30 mismatches=0
```

(Every row reported `old==new`.)

Full library suite under the flag (`raw/tests/full-suite.txt`):

```
test result: ok. 2516 passed; 0 failed; 56 ignored; 0 measured; 0 filtered out; finished in 135.68s
```

Equal to the campaign floor (2516/0/56). No test changed behaviour under the
flag.

## 4. Timing — paired, alternating, `taskset -c 1`

One process per arm per repetition, arm order alternated; median of paired
after/before ratios. 5 reps modexp/RSA, 15 reps DH. Two independent sessions.

**Session 1** (`raw/timing/session1/`):

| workload | before µs | variant µs | ratio |
|---|---:|---:|---:|
| modexp-2048 | 2410.330 | 2463.691 | **1.0236** |
| modexp-8192 | 175056.518 | 177923.735 | **1.0163** |
| RSA-2048 | 637.546 | 638.800 | **1.0036** |
| DH shared secret ffdhe2048 | 335.751 | 340.554 | **1.0215** |
| DH keygen ffdhe2048 | 458.641 | 459.686 | **1.0116** |

**Session 2** (`raw/timing/session2/`):

| workload | before µs | variant µs | ratio |
|---|---:|---:|---:|
| modexp-2048 | 2406.050 | 2465.747 | **1.0241** |
| modexp-8192 | 175026.207 | 177829.494 | **1.0164** |
| RSA-2048 | 636.393 | 637.340 | **1.0020** |
| DH shared secret ffdhe2048 | 333.354 | 341.756 | **1.0163** |
| DH keygen ffdhe2048 | 454.049 | 461.604 | **1.0154** |

Ratio > 1 means the variant is **slower**. No workload is faster. modexp-2048
and modexp-8192 reproduce their regressions to 0.1 %. (Session-1 DH contains
two scheduler outliers — 0.716 and 1.660 in the shared-secret per-rep list —
but its median agrees with the outlier-free session 2 at ≈1.02.)

**Noise band:** campaign controls are 0.2–0.5 %; the decision bar is ~1.5 %.

* modexp-2048 **+2.4 %** — above the bar, real regression.
* modexp-8192 **+1.6 %** — above the bar, reproducible both sessions.
* RSA-2048 **+0.2–0.4 %** — inside the control noise band (flat).
* DH shared secret **+1.6–2.2 %** — above the bar.
* DH keygen **+1.2–1.5 %** — at/above the bar.

## 5. Verdict

**Instruction count is not the lever.** With the wrapper call removed (whole-DSO
`+bmi2`, kernel inlined, 121 `mulx`, 10.5–28 % fewer instructions per product),
there is still no speedup: the variant is equal-or-slower on all five workloads,
and modexp-2048 is reproducibly ~2.4 % slower. The static win does not become
cycles, because the loop is bound by the single `add`/`adc` carry dependency
chain — and `+bmi2` alone leaves that chain in place (zero `adcx`/`adox`; the
disassembly still shows `mulx` feeding `add`/`adc`/`setb`). Together with
PFP-46's dispatched result, the "the call ate the gain" alternative is now
closed: neither the dispatched form nor the inline whole-crate form helps.

**Implication for M-A3..M-A7.** They are the only remaining route, and they must
attack the **carry chain**, not the multiply encoding: only an ADX double-chain
kernel (`adcx`+`adox`, requiring `+adx` and hand-structured carry separation)
changes the dependency graph. Any such work is a per-target artefact.

## 6. Scope — per-target artefact

A whole-crate `-C target-feature=+bmi2` build is a **per-target artefact**: it is
valid only on CPUs that provide BMI2, and it changes the codegen of the entire
crate, not just the kernel. **This evidence does not transfer to the portable
artefact.** Even had it paid, it could only ship as a separate dispatch-selected
DSO (runtime `is_x86_feature_detected!("bmi2")`), never as the default portable
build.

## 7. Memory protocol (court `openssl-rs-court`, cgroup `memory.max=4 GiB`)

| command | host `available` | `Swap free` | cap |
|---|---:|---:|---:|
| build (baseline + variant) | 25 GiB | 10 GiB | 4 GiB |
| ABI transcript + DH court | 25 GiB | 10 GiB | 4 GiB |
| PFP-6 differentials + full suite | 25 GiB | 10 GiB | 4 GiB |
| timing session 1 | 26 GiB | 9 GiB | 4 GiB |
| timing session 2 | 26 GiB | 9 GiB | 4 GiB |

`available ≥ 16 GiB` held throughout; cap = `min(4, available − 8) = 4 GiB`.
`CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`, tests `--test-threads=4`,
no release `--test` build. The DSO digests are unchanged between the correctness
runs and both timing sessions (`raw/timing/*/run-meta.env`).
