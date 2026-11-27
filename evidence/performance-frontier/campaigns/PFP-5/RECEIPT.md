# PFP-5 receipt — fixed-window BN exponentiation

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-5.
**Claim class:** `SCOPED_OBSERVATION` on the court venue; no PMU.
**State:** **DONE** — the bound supported the change, the ladder is replaced, the
audit is clean, every gate passes, and the measured gain meets the bound.

## 1. Identity

| item | value |
|---|---|
| baseline source | `staging` `a005a33c482f47850a72661a363e7186bde42c5c` |
| baseline DSO | `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77` |
| candidate source | worktree on top of `a005a33c4` (`src/bn/arith.rs`, `src/rsa/ossl.rs` tests) |
| candidate DSO | **`842efa27197ea8c408d77a8316c1dbb35a06146e0033b7df7d7f9cced88a2f47`** |
| candidate archive | `a6be79a74bfa8485b7e86ffda6019dc7b30b08f2836152a809f3abd31dc8791a` |
| clean-build agreement | **3/3** fresh builds (three different target dirs) produce the same archive and DSO |
| authority | OpenSSL 3.6.4 production `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| build inputs | rustc/cargo 1.98.1, release, `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4`, x86-64 |

An earlier build of an **intermediate** source state produced `4424d507`; it is
superseded. The final source is reproducible: three clean builds agree, and the
`4e6ec312` baseline was reproduced from `git archive a005a33c4`.

## 2. Decision and bound

The profile found Montgomery work at 97.5 % (`modexp2048`), 99.2 %
(`modexp8192`), 97.5 % (DH) and 71.6 % (RSA, with a one-time 20.6 % blinding
inverse). A window can remove at most the multiplication half; at `w = 5` the
counted bound (squarings + `ceil(N/w)` multiplications + `2^w−2` precompute +
the masked-scan cost + conversions) is **38.2 % removed at 2048 bits** and
**39.5 % at 8192 bits**, far above the 10 % refusal threshold. **Proceeded.**

## 3. Change

`run_mont_ladder` keeps its setup and, when `LADDER_WINDOW_BITS = Some(5)`,
dispatches to `run_mont_ladder_window`: a `2^w`-entry Montgomery table built by
fixed successive multiplication, `ceil(64·width/w)` windows processed most
significant first, a fixed `w` squarings per window and one multiplication per
window, and digit selection by a **full masked scan** of every table row
(`constant_time_eq_s` mask, public addresses, bitwise AND/OR). `None` retains the
bit-at-a-time reference verbatim.

## 4. Unsafe accounting

| category | content |
|---|---|
| eliminated | the `n` per-bit multiplications (≈ half the Montgomery operations) |
| relocated | none |
| hidden | **0** |
| newly introduced unsafe ops | **0** in release code (the new code is safe Rust over `SecretBuf`); the two ctgrind tests use the existing `VALGRIND_MAKE_*` and FFI patterns with `SAFETY` notes |
| retained obligations | the C-ABI lifetime/concurrency preconditions; `ctgrind`'s source-bound status (DSO-level taint is PFP-21); the branch audit is a review aid |
| untouched | the `CRYPTO_*` seam, every `#[repr(C)]` layout, every exported symbol/signature, the three unsafe lints |

## 5. Blinding and compatibility

Blinding sits above the ladder: RSA converts the input before `rsa_mod_exp` and
inverts after; DH uses no blinding factor around the constant-time exponent. The
window exponentiates the same input to the same exponent and does not interact
with blinding. The authority differential is byte-identical for CRT and non-CRT
RSA, blinding on and off, and both recorded DH groups.

## 6. Safety and correctness evidence

| check | result |
|---|---|
| in-crate window vs bit-at-a-time vs variable-time oracle | 3,420 + 1,140 comparisons, 0 mismatches (≤256 bits) |
| in-crate large moduli (1024/2048/3072) window vs reference | 65 comparisons, 0 mismatches |
| authority DSO differential (modexp 256–8192, RSA arms, DH groups) | 161/161 lines identical, 0 mismatches |
| ctgrind, secret exponent (window path) | **0 errors / 0 contexts** |
| ctgrind, RSA secret exponents + key | 96,821 / 112 contexts, **0 window contexts**; baseline moduli-only 96,659 / 112 |
| binary branch audit at `842efa27` | `run_mont_ladder` 100 jcc / 0 div / 2 cmov / 18 setcc / 0 cpuid; `mont_mul_sos_into` 19 / 0 / 0 / 10 / 0; secret-derived entries **0** |
| `cargo test --lib -- bn` | 159 passed, 0 failed |
| full library suite | 2,491 passed, 0 failed, 54 ignored |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

## 7. Predicted versus measured

| workload | predicted removed | measured removed | measured speedup | new candidate/authority |
|---|---:|---:|---:|---:|
| `modexp2048` | 38.2 % | **39.5 %** | 1.652× | 2.501× (was 4.20× stated / 4.13× base) |
| `modexp8192` | 39.5 % | **39.8 %** | 1.660× | 2.927× (was 4.87×) |
| DH 2048 | 38.2 % | **39.5 %** | 1.652× | 2.500× (was 4.13×) |
| `rsa2048` | 34–39 % | **34.7 %** | 1.532× | 2.982× (was 4.57×) |
| `ecdsa256` (control) | — | 0.4 % | 1.004× | unchanged, not on the affected path |

The measured gain meets the bound. Instruction counts agree (1.63–1.66× fewer
Montgomery instructions).

## 8. Correction — RSA and DH transposed in the commit message (2026-11-27)

The PFP-5 commit (`76652a46d`) lists the candidate/authority figures as
"2.501x, 2.927x, 2.982x and 2.500x, against 4.20, 4.87, 4.13 and 4.57 before".
That pairs the last two candidate values with the *wrong* "before" values: the
candidate list is in the order `modexp2048`, `modexp8192`, RSA, DH, while the
"before" list is in the order `modexp2048`, `modexp8192`, DH, RSA. RSA and DH
are transposed. The commit message cannot be rewritten; this record is the
authoritative mapping, read from `TIMING.md` §1.

| workload | candidate/authority | before (base / stated) |
|---|---:|---:|
| `modexp2048` | **2.501** | 4.13 / 4.20 |
| `modexp8192` | **2.927** | 4.86 / 4.87 |
| `rsa2048` | **2.982** | **4.57** |
| DH (`dh-ffdhe2048`, `dh-modp2048`) | **2.500** | **4.13** |

RSA is 2.982× (was 4.57×), not 2.982× against 4.13×; DH is 2.500× (was
4.13×), not 2.500× against 4.57×. No measurement changes; only the pairing in
the commit prose was wrong.

## 9. What this receipt does not establish

* It is not a frontier result (no PMU).
* It does not establish constant-time behaviour; ctgrind covers control flow and
  addresses only, and is source-bound rather than DSO-bound.
* It discharges **no** timing obligation.
* The 8192-bit bit-at-a-time comparison is covered only at the authority level,
  not in the debug suite.
