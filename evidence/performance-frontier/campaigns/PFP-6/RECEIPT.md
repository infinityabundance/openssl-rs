# PFP-6 receipt — squaring re-evaluated at the PFP-5 composition

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-6.
**Claim class:** `SCOPED_OBSERVATION` on the court venue; no PMU.
**State:** **PARTIAL.** The composition is measured in the artefact and the
final selection is unchanged and re-audited, but FIOS/almost-Montgomery are not
evaluated, the candidate is an uncommitted worktree, and there is no DSO-bound
taint at the new digest.
**Decision:** `LADDER_DEDICATED_SQUARING` stays **false**. The dedicated
squaring kernel loses to SOS and to CIOS for the squaring role at this mix.

## 1. What changed since the earlier negative

The earlier PFP-6 negative (`CROSSOVER.md`, 2026-11-26) was a **per-kernel C
transcription**: `mont_sqr` was 1.045× the time of `mont_mul_for_sqr` at 2048
bits, measured in isolation. PFP-5 then changed the operation mix; the windowed
ladder now performs **2,050 squarings and 410 multiplications** at 2048 bits
(83.33 % squarings), versus the old bit-at-a-time 50/50. The question is no
longer "is the squaring kernel faster in isolation?" but "does it help a whole
operation when 83 % of the Montgomery work is squaring?".

Measured in the crate's release DSO, at that mix, it does not:

| comparison | `modexp2048` | `modexp8192` | `rsa2048` | DH 2048 |
|---|---:|---:|---:|---:|
| dedicated / SOS (B/A) | **1.0822** [1.0766, 1.0831] | **1.0048** [1.0026, 1.0051] | **1.1174** [1.1168, 1.1218] | **1.0825** [1.0780, 1.0843] |
| dedicated / CIOS (D/C) | **1.2628** [1.2574, 1.2677] | **1.1323** [1.1320, 1.1331] | **1.2963** [1.2957, 1.2975] | **1.2678** [1.2619, 1.2718] |
| CIOS / SOS (C/A) | **0.8274** [0.8232, 0.8347] | **0.8379** [0.8376, 0.8383] | **0.8356** [0.8342, 0.8363] | **0.8265** [0.8212, 0.8281] |

The earlier negative and this one agree in direction, but they are not the same
measurement and the magnitudes do not transfer: the earlier figure is a
per-kernel C wall-time ratio; these are whole-operation crate-DSO ratios at the
PFP-5 mix. Dedicated squaring is not rescued by the new mix; it is applied to
more operations and costs more in the whole operation. **CIOS is the better
squaring role** (17 % faster than SOS overall), but admitting CIOS is a
separate measured default change and is not done here.

## 2. Composition, from the code and the profile

| workload | kernel calls/op | squarings/op | multiply role/op | main-loop share |
|---|---:|---:|---:|---:|
| `modexp2048` | 2,491 | **2,050** | 441 | **83.33 %** |
| `modexp8192` | 9,865 | **8,195** | 1,670 | **83.33 %** |

Callgrind shows the squaring role as five 410/op arcs (2048) and five
1,639/op arcs (8192); the multiply role is the remaining window multiplies,
30 table multiplies and one conversion. `mont_mul_sos_into` is 96.78 % / 99.15 %
of program Ir at the two widths. See `REEVALUATION.md` §3.

## 3. Identity

| item | value |
|---|---|
| source | `staging` `76652a46dcfb388656d964010268685ca032dff1` + uncommitted `src/bn/arith.rs` doc correction (`66bd6c4c…2e83`); `build_relevant_clean=false` |
| source tree | `142e4fe9…4f9e`, 887 files, fingerprint `52671fca…1a65` |
| toolchain | rustc 1.98.1 (48a229cea), cargo 1.98.1, cc 12.2.0, x86_64 |
| **A (default)** | **`661384603e0b661af384997676d8e88843f2b307b6abf73f56d472b03d888630`**, 17,113,432 B |
| A2 | identical DSO and archive to A (fresh target dir) |
| B (dedicated squaring) | `5c0e0d90e9caf95f140fe98d386bab18e27072e78038a0ba3827706b4b900484` |
| C (CIOS) | `ca0ae5387d81f42de6dd2207d0794840eb38b8cab1d4015d91d4aa4239569159` |
| D (CIOS + dedicated) | `a24c0aa2e9e09e1335445421c744809585bb680915b16108546f9b5f20ab1197` |
| authority | OpenSSL 3.6.4 production `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| harness | `bench_pfp5.c` `ac605a5a…36f9c`, unmodified; `pfp5_diff.c` `04098db7…eb63` |

## 4. Safety and correctness evidence

| check | result |
|---|---|
| 161-line ABI transcript vs authority | **161/161 identical** for A, B, C and D (MX 150, RSA 8, DH 2) |
| PFP-6 per-kernel tests | pass in the full suite; no test weakened or newly ignored |
| ctgrind, secret exponent tainted | **0 errors / 0 contexts** (source-bound debug test; `CARGO_PROFILE_TEST_DEBUG=0`, recorded) |
| branch audit at `66138460` | `run_mont_ladder` 100 jcc / 0 div / 2 cmov / 18 setcc / 0 cpuid; `mont_mul_sos_into` 19 / 0 / 0 / 10 / 0; **0 secret-derived entries** |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| full library suite | **2,491 passed, 0 failed, 54 ignored** |

The audit counts, addresses and sizes are identical to PFP-5's `842efa27` audit;
the per-site classification (public loop/geometry bounds; `setcc` carry/borrow
data writes, none reaching control) applies to the same emitted functions. The
audit is a review aid, not a proof; the taint is source-bound.

## 5. Unsafe accounting

| category | content |
|---|---|
| eliminated | none (this batch is a measurement and a documentation correction) |
| relocated | none |
| hidden | **0** |
| newly introduced unsafe | **0**; the source change is a doc comment, and the experimental patches were restored |
| retained obligations | the C-ABI lifetime/concurrency preconditions; the branch audit is a review aid; ctgrind is source-bound; the candidate is uncommitted |
| untouched | the `CRYPTO_*` seam, every `#[repr(C)]` layout, every exported symbol/signature, the three unsafe lints, `AGENTS.md` |

## 6. Selection and next step

`LADDER_SCHEDULE = Sos`, `LADDER_DEDICATED_SQUARING = false`,
`LADDER_WINDOW_BITS = Some(5)` — unchanged. **CIOS measured 0.827× the SOS
operation** at the new mix and is the obvious next default decision, but it is
not admitted here: it needs a window-aware CIOS branch audit and a DSO-bound
taint at its own digest, plus the same API-row evidence it now has.

## 7. Residuals (stated, not deferred)

1. FIOS and almost-Montgomery were not evaluated (`PFP6-FIOS-ALMOST-MONT`); the
   reason is in `REEVALUATION.md` §9.
2. The candidate is an uncommitted worktree (`PFP6-DIRTY-CANDIDATE`); A/A2
   reproduce it, but it is not reproducible from a commit.
3. There is no DSO-bound ctgrind at `66138460`; the source-bound test and the
   PFP-27 DSO-bound result are recorded as different scopes.
4. A branch audit is not a constant-time proof, and absence of a detected
   transfer is not proof of constant-time behaviour.
5. No timing obligation is discharged: T23, T24 and T29 remain open.
