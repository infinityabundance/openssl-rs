# PFP-7 receipt — RSA CRT dual engine, a measured refusal

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-7.
**Claim class:** `SCOPED_OBSERVATION` on the court venue (no PMU exposed).
**State:** **DONE as a measured refusal.** The bound does not support scalar
interleaving of the two CRT halves; the sequential path stays; no source changed,
so there is no new digest to certify and nothing to graduate.

## 1. Identity

| item | value |
|---|---|
| source | `staging` `05ee177a3d0d6e7ef7a80e466a1cba5b6ea765c2`, build-relevant tree **clean** |
| DSO | **`6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39`** (17,118,904 B, build-id `05a6b994`) |
| archive | `c01b2b1f4070ce4fbca329f2ca1057c51ca352f18e5c93879839d9f05027f489` (45,028,870 B) |
| rebuild | 2/2 independent clean builds agree byte for byte on archive and DSO (`raw/identity/two-builds.txt`) |
| authority | OpenSSL 3.6.4 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| build inputs | `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4`, rustc/cargo 1.98.1, x86_64-unknown-linux-gnu |
| machine | i9-13900K, `adx avx2 bmi2 vaes vpclmulqdq`, **no `avx512f` / `avx512ifma`** |
| identity record | `raw/identity/identity.json` (`42930c69…`) |

The digest is the PFP-6 CIOS-admitted artefact, here reproduced from a clean
commit. PFP-7 adds no commit and no worktree change; `git status` for `src`,
`Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml` is empty.

## 2. Predicted versus measured

| prediction (from the bound) | measured | verdict |
|---|---|---|
| the two exponentiations are ~89–91 % of the private operation | 89.4 % of instructions; 577 µs of the 645.7 µs refresh-free op | met |
| a perfect dual-issue interleave could reach 1.30× the kernel (IPC 6.0) → 1.26× the op (20.6 % wall) — and only there | attained IPC is 4.62; the fused loop costs 1.113× [1.110, 1.115] per multiplication (1.018× on the ADX build), slower in every run | **the ceiling is not attainable; the attainable bound is 0.91×** |
| interleaving therefore cannot deliver a material gain | measured 1.02–1.14× slower, never faster; no change implemented | met (refusal) |
| a corrupted CRT half or recombination is caught by the result check | 3/3 DETECTED with blinding on and off; controls return the expected wrong values | met |
| the deterministic and malformed surfaces are unchanged | 4,185 transcript lines byte-identical, including 16 zero-length synthetic answers | met |
| no secret-derived transfer is introduced | no interleaved carrier exists; 0 taint sites in any ladder carrier; CIOS 14 jcc / 18 setcc / 0 cmov, all public | met (vacuous for interleaving) |
| IFMA cannot be evaluated on this machine | no `avx512f`/`avx512ifma` | recorded **NOT_APPLICABLE_HARDWARE** |

## 3. The refusal arithmetic

* Two CRT halves = 89.4 % of the operation; 2,524 Montgomery multiplications,
  6,457 instructions each, 255.8 ns each in situ = 1,399 cycles at the measured
  5.470 GHz → IPC **4.62** of a 6-wide machine.
* Issue-width floor: 6,457 / 6 = 1,076 cycles → **1.30×** on the kernel,
  **1.26×** on the operation (20.6 % wall). That is the only positive bound and
  it needs IPC 6.0.
* Direct measurement of the fused shape at the same instruction mix
  (transcription validated to 0.2 % against the DSO kernel, and
  `CHECK fused_equals_sequential=1`): single ≈ 255 ns, two sequential ≈ 255 ns,
  **fused 283 ns** per multiplication → **1.1132×** [1.1102, 1.1151] slower, and
  1.0183× [1.0111, 1.0341] on the ADX/BMI2 build; an earlier campaign read
  1.1436 (baseline) and 1.0559 (native). It is slower in every run and faster in
  none. The attainable wall change is `0.894·1.1132 + 0.106 = 1.101` → **0.91×**
  (0.89× at the earlier campaign's ratio).
* A bound that is positive only at an unattainable IPC and negative at the
  achievable one does not support the change.

## 4. What was protected (unchanged, and verified unchanged)

Blinding lifecycle, the result check, implicit rejection and the padding surface
are unchanged because **no code changed**, and each was measured at the digest:

* **Fault injection** (`FAULT-INJECTION.md`): `dmp1+1`, `dmq1+1` and `iqmp+1`
  are each detected (output equals the clean signature because the check rejects
  and the tail falls back to `d`), with blinding on and off; the `+badD` controls
  return `m^(d+1) mod n`, proving the detection is what saves the result.
* **Differential** (`DIFFERENTIAL.md`): 4,185 lines per side, byte-identical,
  over CRT/non-CRT × blinded/unblinded × {NO_PADDING, PKCS#1, OAEP} × 4,096
  malformed blocks (16 zero-length synthetic answers).
* **Timing** (`TIMING.md`): latency 1.879×/1.885×, sustained throughput
  2.302×/2.346×, row statistic 2.4897× [2.4827, 2.4904] and 2.5035×
  [2.4931, 2.5401] versus the authority; 1,245/1,206 ops·s⁻¹ against
  2,867/2,831. The 2.484× row figure is reproduced and decomposed: the
  exponentiations are 1.88× and the periodic blinding re-creation (5.2 ms every
  32 calls = 162 µs/op) is what raises the composite ratio.

## 5. Unsafe accounting

| category | content |
|---|---|
| eliminated | none (no change) |
| relocated | none |
| hidden | **0** — nothing new is assumed |
| newly introduced unsafe ops | **0**; the three unsafe lints, the `CRYPTO_*` seam, every `#[repr(C)]` layout and every exported symbol are untouched |
| retained obligations | the C-ABI lifetime/concurrency preconditions of `rsa_ossl_mod_exp`; ctgrind's source-bound status (PFP-21); the branch audit is a review aid, not a constant-time proof |

## 6. Gates at `05ee177a3` / `6d002db2`

| gate | result |
|---|---|
| `cargo test --lib -- rsa --test-threads=4` | 132 passed, 0 failed, 1 ignored |
| `cargo test --lib -- --test-threads=4` | **2,491 passed, 0 failed, 54 ignored** |
| `cargo fmt --all -- --check` | clean (rc 0) |
| `cargo clippy --all-targets -- -D warnings` | clean (rc 0) |
| differential | IDENTICAL (4,185 lines) |
| fault matrix | PASS (no undetected case) |
| ctgrind | 96,668/112 and 97,546/106; 0 ladder-carrier sites; control fires |
| branch audit | 14 jcc / 18 setcc / 0 cmov (CIOS), 0 secret-derived; driver 100/18/2 (2 public `cmovb`) |

Raw logs: `raw/suite/`.

## 7. Residuals and follow-ups (not PFP-7 deliverables)

* **`PFP7-IFMA-NOT-APPLICABLE`** — the radix-2^52 AVX512IFMA pairing cannot be
  built or measured on this hardware. Not a negative result; not evaluable here.
* **`PFP7-HAND-ASM`** — hand-scheduled ADX assembly (`rsaz`-shaped) is a
  different change class and needs its own bound; the ADX compiler build shows
  no headroom, and the measured fused scalar shape is a loss.
* **`PFP7-BLINDING-REFRESH`** — the 5.2 ms / 32-op `mod_inverse_consttime`
  re-creation is a PFP-1/blinding-substrate cost that inflates the row's ratio
  from 1.88× to 2.48×. It is measured here and belongs to the blinding arm, not
  to this one.
* **`PFP7-SAFE-COMPATIBLE`** — not asserted; this is a performance arm.

## 8. Files

New: `evidence/performance-frontier/campaigns/PFP-7/` —
`BOUND.md`, `DIFFERENTIAL.md`, `FAULT-INJECTION.md`, `TAINT.md`, `AUDIT.md`,
`TIMING.md`, `RECEIPT.md`, `harness/` (11 files), `raw/` (profile, ilp, identity,
diff, fault, taint, audit, timing, suite).
Changed: `docs/PERFORMANCE-FRONTIER-TODO.md` (PFP-7 row),
`evidence/performance-frontier/admission/ARMS.json` (PFP-7 arm, `EXPERIMENT`).
No `src/`, `Cargo.*`, `build.rs` or `docker/` change.
