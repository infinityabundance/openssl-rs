# PFP-6 admission — CIOS as the constant-time ladder's default schedule

**State: ADMITTED at DSO `6d002db2…`.** The named ladder constant
`LADDER_SCHEDULE` selects `MontSchedule::Cios`; the SOS reference is retained and
is still reachable through `mont_mul_fallible` / `MontSchedule::Sos` for the
differential court and as the fallback. Every acceptance gate below ran at the
one candidate digest `6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39`.

The decision is the measured re-evaluation's own result: at the PFP-5 five-bit
window composition the CIOS operation measured **0.8274 [0.8232, 0.8347]** of SOS
at 2048 bits and **0.8379 [0.8376, 0.8383]** at 8192 (`REEVALUATION.md` §4.2,
DSO `ca0ae538`). This record admits that lever and re-establishes every safety
and correctness gate at the resulting default digest rather than transferring the
earlier per-kernel result.

## 1. The change

One functional line in `src/bn/arith.rs`:

```
-const LADDER_SCHEDULE: MontSchedule = MontSchedule::Sos;
+const LADDER_SCHEDULE: MontSchedule = MontSchedule::Cios;
```

The surrounding doc comments were corrected to describe the new default and the
retained SOS reference; the `#[cfg_attr(not(test), allow(dead_code))]` on
`MontSchedule::Cios` was removed because CIOS is now constructed by the default
constant. Nothing else changed: the five-bit window, the squaring path
(`LADDER_DEDICATED_SQUARING` stays `false`), the conversion sites
(`mont_mul_fallible` remains SOS), the geometry checks, the `CRYPTO_*` seam, every
`#[repr(C)]` layout and the three unsafe lints are untouched. No `unsafe` was
added.

`git diff --stat` at the admission source: `src/bn/arith.rs | 30 ++++++++-------`
(17 insertions, 13 deletions, docs plus the one constant). `AGENTS.md` is
untouched.

## 2. Identity and reproducibility

| item | value |
|---|---|
| source commit | `dedb67a5fe7d567a046def6402388d043b50d571` (`staging`) + uncommitted `src/bn/arith.rs` |
| `src/bn/arith.rs` sha256 | `3e8127cb1eb816b9db066eb52ce1535620aa9c812bec0b441c627fdb9100aea1` |
| `src` fingerprint | `7428126955278fe950c1a19066e0f22c6d7f1647740d0c74c0b1f7273c37c819` (887 files) |
| `build_relevant_clean` | **false** — the CIOS constant is an uncommitted worktree change |
| toolchain | rustc 1.98.1 (48a229cea), cargo 1.98.1 (797e8a9bc), cc 12.2.0, x86_64-unknown-linux-gnu |
| profile | `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4` |
| shell / version script | `efa0fbce…` / `75fb6eff…` |
| `Cargo.lock` | `95e8fd83…` |

| arm | role | DSO sha256 | bytes | build id |
|---|---|---|---:|---|
| **cand** | admitted default, `LADDER_SCHEDULE = Cios` | `6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39` | 17,118,904 | `05a6b994…` |
| **cand2** | cand rebuilt in a fresh `CARGO_TARGET_DIR` | **identical to cand** (archive also identical, `c01b2b1f…`) | 17,118,904 | identical |
| **ref** | one-line twin, `LADDER_SCHEDULE = Sos` | `f3d716028e9022e769bcd05fd4fe84cb1bd5e680c32744933b0c27974d80fb3c` | 17,111,048 | `2633aeb3…` |

A second clean build reproduces the admitted digest byte for byte (`cmp` of the
DSOs and the static archives). The source was restored to `Cios` after the twin
was built, and the `src` fingerprint was re-checked identical.

## 3. Correctness

Run in the order the task requires; any mismatch would have stopped the batch.

### 3.1 Per-kernel differential (`cargo test --lib -- pfp6`, 4/4 pass)

| check | cases | mismatches |
|---|---:|---:|
| SOS satisfies `out·R ≡ a·b (mod m)`, `out < m` | 7,890 | 0 |
| **CIOS satisfies the congruence** | 7,890 | 0 |
| dedicated squaring satisfies the congruence | 254 | 0 |
| **CIOS vs SOS, exhaustive one-limb range** | 3,018 | 0 |
| **CIOS vs SOS, sampled 64–1024 bits** | 7,890 | 0 |
| squaring vs SOS, exhaustive | 144 | 0 |
| squaring vs SOS, sampled | 254 | 0 |

The congruence checks give CIOS independent evidence; the CIOS-vs-SOS counts give
the bit-for-bit cross-check. Log: `correctness/pfp6.log`.

### 3.2 ABI transcript — 161 lines against the authority

Harness `courts/performance-frontier/pfp5/pfp5_diff.c` (`04098db7…`), authority
`openssl-3.6.4-production` DSO `611e511d…`:

| subject | lines | vs authority | MX | RSA | DH |
|---|---:|---|---:|---:|---:|
| cand (CIOS) | 161 | **IDENTICAL** | 150 | 8 | 2 |
| ref (SOS) | 161 | **IDENTICAL** | 150 | 8 | 2 |

The 150 `MX` rows are `BN_mod_exp_mont_consttime` over 256/1024/2048/3072/8192-bit
moduli; the RSA rows cover CRT blinded, CRT unblinded (`RSA_blinding_off`) and
non-CRT, plus private-decrypt round trips; the two DH rows are FFDHE2048 and
MODP2048. Log: `differential/raw/{authority,cand,ref}.txt`, `summary.txt`,
`identity.txt`.

### 3.3 Repository gates

| check | result |
|---|---|
| `cargo test --lib -- bn` | **159 passed, 0 failed** (plus the `recp.rs` subprocess re-invocation line) |
| full library suite | **2,491 passed, 0 failed, 54 ignored** (`--test-threads=4`, `CARGO_PROFILE_TEST_DEBUG=0`) |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

The ignored count is the pre-existing set; no test was added, removed, weakened
or newly ignored. Logs: `correctness/{bn,suite,fmt,clippy}.log`, `gates.env`.

## 4. Security at the admitted digest

### 4.1 ctgrind — secret exponent tainted

`bn::arith::tests::ctgrind_secret_exponent_window`: the staged exponent's limb
bytes are marked undefined and the five-bit-window ladder is run; memcheck must
report no conditional jump and no secret-derived address inside
`run_mont_ladder_window` / `select_window_digit`. Test binary
`5509e5cd…` (debug, `CARGO_PROFILE_TEST_DEBUG=0`; not the DSO).

| run | errors | contexts | valgrind exit | origins |
|---|---:|---:|---:|---|
| exponent taint | **0** | **0** | 0 | **none** |
| negative control (`CTGRIND_CONTROL=1`) | 4 | 1 | 99 | `Conditional jump or move depends on uninitialised value(s)` |

The control firing is the instrument's sensitivity check. The taint is
source-bound; it is not a constant-time proof (`ctgrind/`).

### 4.2 DSO-bound kernel-taint probe

PFP-27's `pfp27_ladder_probe.c` (`208f430f…`) run unchanged against the admitted
DSO: it taints the *base* of `BN_mod_exp_mont_consttime`, which the CIOS kernel
multiplies on every ladder call, and discards the result without inspection.

| subject | `control` | `ladder` (3 reps) |
|---|---|---|
| cand (CIOS) `6d002db2` | 0 contexts | **0, 0, 0** |
| ref (SOS) `f3d71602` | 0 contexts | **0, 0, 0** |

This is artefact-bound evidence that the CIOS path is silent under a tainted
operand; it complements, and does not replace, the source-bound exponent taint.

### 4.3 Branch audit of the CIOS carrier at `6d002db2`

Carrier `mont_mul_ladder_into` at `0x58ce60`, size `0x36c` (the CIOS body is
inlined; `mont_mul_cios_into` has no out-of-line symbol, and `mont_sqr_into` is
absent from both artefacts because dedicated squaring is disabled).
`classify_cios.py` reads this digest's objdump and aborts if a site is
unclassified, a mapped site is absent, a flag source is not the nearest preceding
flag-setting instruction, or a class-(b) flag lacks the recorded arithmetic
consumer.

**Totals: 14 `jcc` (14 public-bound, 0 secret-derived), 18 `setcc` (3 public
geometry flags, 15 secret carry/borrow flags), 0 `cmovcc`. Secret-derived control
transfers: none.**

| addr | kind | insn | class | depends on | consumed by |
|---|---|---|---|---|---|
| `0x58ce93` | jcc | `jne` | (a) geometry | five length words xor/or | — |
| `0x58cea9` | setcc | `sete` | (a) geometry | `t.len == 2n+1` | — |
| `0x58ceac` | setcc | `setne` | (a) geometry | `t.len != 2n+1` | public early-return `jne` |
| `0x58ceb2` | setcc | `sete` | (a) geometry | `n == 0` | public early-return `or` |
| `0x58ceb7` | jcc | `jne` | (a) geometry | `!(t.len == 2n+1) \|\| n == 0` | — |
| `0x58cef7` | jcc | `jb` | (a) loop | `n < 2` | — |
| `0x58cf3d` | setcc | `setb` | (b) flag | carry of `acc[j] + a[j]*b[i]` | `adc %rdx,%rsi` |
| `0x58cf6e` | jcc | `je` | (a) loop | b-pointer vs `b_end` | — |
| `0x58cf83` | jcc | `je` | (a) loop | `n - 1 == 0` | — |
| `0x58cf9e` | setcc | `setb` | (b) flag | carry of the product row | `adc %rdx,%r10` |
| `0x58cfbb` | setcc | `setb` | (b) flag | carry of the second product-row limb | `adc %rdx,%rsi` |
| `0x58cfd1` | jcc | `jne` | (a) loop | `j < n & ~1` | — |
| `0x58cfd7` | jcc | `je` | (a) loop | `n` odd | — |
| `0x58cfe6` | setcc | `setb` | (b) flag | carry of the tail product limb | `adc %rdx,%rcx` |
| `0x58cffc` | setcc | `setb` | (b) flag | carry into `acc[n+1]` | `mov` store |
| `0x58d02a` | jcc | `je` | (a) loop | `n == 2` | — |
| `0x58d03e` | setcc | `setb` | (b) flag | carry of the reduction row | `adc %rdx,%r10` |
| `0x58d05c` | setcc | `setb` | (b) flag | carry of the second reduction-row limb | `adc %rdx,%rcx` |
| `0x58d076` | jcc | `jne` | (a) loop | reduction-loop count | — |
| `0x58d07e` | jcc | `jne` | (a) loop | `n - 1` odd | — |
| `0x58d0a5` | setcc | `setb` | (b) flag | carry of `acc[n] += carry` (`n == 1`) | `add $0xff,%sil` |
| `0x58d0a9` | setcc | `setb` | (b) flag | same carry, second read | `movzbl` store |
| `0x58d0cb` | setcc | `setb` | (b) flag | carry of `u*m[0] + acc[0]` | `movzbl` |
| `0x58d0f3` | jcc | `jne` | (a) loop | `n == 1` | — |
| `0x58d118` | setcc | `setb` | (b) flag | borrow of `acc[j] - m[j]` | `or %r11b,%cl` |
| `0x58d11f` | setcc | `setb` | (b) flag | borrow of `(d1 - borrow)` | `add $0xff,%cl` |
| `0x58d13f` | setcc | `setb` | (b) flag | borrow of the `sbb` pair | `movzbl` |
| `0x58d148` | jcc | `jne` | (a) loop | `j < n & ~1` | — |
| `0x58d14e` | jcc | `je` | (a) loop | `n` odd | — |
| `0x58d158` | setcc | `setb` | (b) flag | borrow of the tail limb | `or %r10b,%cl` |
| `0x58d15f` | setcc | `setb` | (b) flag | borrow of the tail limb, second read | `movzbl` |
| `0x58d1b9` | jcc | `jne` | (a) loop | `j < n` mask-select | — |

The conditional subtraction is present as arithmetic in the artefact:
`xor $1` / `or` / `neg` / `dec` produce two masks consumed by `and`/`or`
(`0x58d16c`–`0x58d1bb`), not a branch. Every class-(b) `setcc` is read only by
`adc`/`add`/`or`/`mov`/`movzbl` in the same carrier; none is read by a `jcc`.
This is an enumeration and dataflow audit of the artefact, not a constant-time
proof. Full per-site data: `raw/disasm/classification.{tsv,md}`.

For context, the SOS reference twin's `mont_mul_sos_into` (`0x58c870`, `0x3f5`)
has 19 `jcc`, 10 `setcc`, 0 `cmovcc`; the window driver `run_mont_ladder`
(`0x58af00`, `0x1626`) enumerates 100 `jcc`, 18 `setcc`, 2 `cmovcc`. Those two are
enumerated only; their per-site classification is not re-derived here, and no
secret-independence claim is made for them in this record.

## 5. Timing at the admitted digest

Instrument `bench_pfp5.c` (`ac605a5a…`), 15 interleaved repetitions, one process
per arm per repetition, `taskset -c 1`, `--prepared`, i9-13900K, court
`openssl-rs-court-tools:1`. Statistic: median of the 15 paired per-repetition
ratios, 95 % percentile bootstrap (20,000 resamples, seed `0x50465036`).
Population frozen before execution: `population.json` sha256 `4b8d401b…`.
Ratio < 1 means the first-named arm is faster. Raw: `timing/raw/`, summary
`timing/raw/timing-summary.json`.

| workload | cand µs | ref µs | auth µs | **cand/ref** [95 % CI] | cand/auth | ref/auth |
|---|---:|---:|---:|---|---:|---:|
| `modexp2048` | 2,469.6 | 2,985.3 | 1,192.9 | **0.8267** [0.8242, 0.8292] | 2.0690 | 2.5011 |
| `modexp8192` | 180,858.9 | 215,940.3 | 73,763.2 | **0.8375** [0.8371, 0.8379] | 2.4516 | 2.9275 |
| `rsa2048` | 873.3 | 1,045.2 | 351.3 | **0.8357** [0.8340, 0.8373] | 2.4838 | 2.9781 |
| `dh-ffdhe2048` | 2,469.0 | 2,985.2 | 1,191.6 | **0.8272** [0.8256, 0.8280] | 2.0709 | 2.5052 |
| `dh-modp2048` | 2,468.4 | 2,982.1 | 1,192.0 | **0.8276** [0.8265, 0.8294] | 2.0691 | 2.5012 |
| `ecdsa256` (control) | 132.4 | 130.5 | 12.8 | 1.0109 [1.0103, 1.0150] | 10.3661 | 10.2294 |

The control is not on the changed path; its 1.5 % movement is the same
control-noise band PFP-6 recorded earlier (≤1.2 %), not a result.

### 5.1 Against PFP-5's record

PFP-5's candidate/authority ratios (read from `PFP-5/TIMING.md` §1 and
`RESULTS.json`): `modexp2048` 2.501, `modexp8192` 2.927, `rsa2048` 2.982, DH
2.500, `ecdsa256` 10.238. If CIOS is admitted the candidate should move by the
measured `cand/ref` factor:

| workload | PFP-5 ratio | × predicted cand/ref | = predicted cand/auth | **measured cand/auth** | difference |
|---|---:|---:|---:|---:|---:|
| `modexp2048` | 2.501 | 0.8274 | 2.0692 | **2.0690** | −0.01 % |
| `modexp8192` | 2.927 | 0.8379 | 2.4525 | **2.4516** | −0.04 % |
| `rsa2048` | 2.982 | 0.8356 | 2.4918 | **2.4838** | −0.32 % |
| `dh-ffdhe2048` | 2.500 | 0.8265 | 2.0663 | **2.0709** | +0.22 % |
| `ecdsa256` | 10.238 | 1 (control) | 10.238 | 10.3661 | +1.25 % |

The reference twin reproduces PFP-5's candidate/authority ratios
(`ref/auth` 2.5011, 2.9275, 2.9781, 2.5052), so the comparison is at the same
composition, not a re-based one.

### 5.2 Predicted versus measured — receipt

The selection comparison predicted **0.827–0.838** (`REEVALUATION.md` §4.2:
0.8274 at 2048, 0.8379 at 8192, 0.8356 RSA, 0.827 DH).

| workload | predicted cand/ref | **measured cand/ref** | verdict |
|---|---:|---:|---|
| `modexp2048` | 0.8274 | **0.8267** | met |
| `modexp8192` | 0.8379 | **0.8375** | met |
| `rsa2048` | 0.8356 | **0.8357** | met |
| `dh-ffdhe2048` | 0.8265 | **0.8272** | met |
| `dh-modp2048` | 0.8282 | **0.8276** | met |

**The measured gain matches the 0.827–0.838 the selection comparison predicted.**
Every interval excludes 1 and lies inside the predicted band (within run-to-run
spread). No blinding, fault check or constant-time property was traded: the
change is a schedule constant, and §4 re-establishes the taint and branch evidence
at the resulting digest.

## 6. What this does not establish

* The taint at §4.1 is source-bound; §4.2 is DSO-bound but taints the base, not
  the exponent. Neither is a constant-time proof, and no dudect-class or
  microarchitectural claim is made.
* The branch audit is an enumeration + dataflow review of the artefact, not a
  secret-independence proof; the memcheck probes are the dynamic evidence.
* The candidate is an **uncommitted worktree state** (this task forbids commits):
  two clean builds reproduce `6d002db2`, but it is not reproducible from a commit
  until the change lands. `build_relevant_clean = false`.
* FIOS and almost-Montgomery remain **OPEN** for the reasons already recorded in
  `REEVALUATION.md` §9: FIOS is a CIOS-internal interleaving with a smaller
  expected delta over the now-admitted CIOS and needs its own bound proof,
  per-kernel differential and branch audit; almost-Montgomery changes the
  canonicality contract and the representation the window induction relies on,
  so it needs its own bound/ownership analysis. Neither is on this row's critical
  path now that CIOS is admitted.
* The venue exposes no PMU; the timing is a `SCOPED_OBSERVATION`.
* No safety-compatibility (`SAFE_COMPATIBLE`) conclusion is asserted.

## 7. Reproduction

```sh
export OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g
C=evidence/performance-frontier/campaigns/PFP-6/admission-2026-11-27
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/build.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/run_kernel_differential.sh
bash docker/openssl-rs-court.sh exec bash $C/run_diff.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/run_gates.sh
bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 bash $C/run_ctgrind.sh
bash docker/openssl-rs-court.sh exec bash $C/run_dso_probe.sh
bash docker/openssl-rs-court.sh exec bash $C/run_branch_audit.sh
bash docker/openssl-rs-court.sh exec bash $C/run_timing.sh
python3 $C/analyse_admission.py
```
