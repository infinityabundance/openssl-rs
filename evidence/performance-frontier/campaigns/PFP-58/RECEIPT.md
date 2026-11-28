# PFP-58 — divstep transfer removal, composite preconditions, and admission

**Decision: ADMIT.** Both admission conditions were met: (a) the release
`libcrypto.so.3` carries no secret-derived `jcc`/`cmov` in the fixed-step loop,
with the ctgrind firing control firing in the same run; (b) the end-to-end RSA
private operation through the 32-call blinding refresh is **6.85 % / 6.67 %**
faster across two measurement runs. The odd-modulus blinding inverse now calls
`bn::divstep::mod_inverse_divstep`; the even-modulus arm and the 32-call refresh
schedule are unchanged.

## 1. Identity

| item | value |
|---|---|
| branch / HEAD | `staging`, `8dfb154081ef737fa1ef5e53f6b59b92dffca915` |
| working tree | dirty before this task; our files `src/bn/divstep.rs`, `src/bn/divstep/tests.rs`, `src/bn/blinding.rs`, `src/bn/mod.rs` |
| shipped DSO | `artifacts/phase2/libcrypto.so.3` sha256 `8fc08a5d774a25bd9461d180e803eb331689049730f4c12c60d08b600e88eea1` |
| release staticlib | `target/release/libopenssl_rs.a` sha256 `705be2c53c96be1a48acf15ac859488b2ca5304cf2b58471f79d2737aafaf533` |
| file hashes | in `raw/build-identity.txt` |
| release profile | opt-level 3, codegen-units 16, overflow-checks true, debug 0, no LTO |
| ctgrind build | test profile overrides: opt-level 3, cgu 16, debug-assertions off, overflow-checks on |
| instruments | valgrind 3.19.0 memcheck (ctgrind technique), objdump/nm, Phase-2 linker courts |

The DSO was built by `forensics/tools/build_phase2.sh`; all eleven Phase-2 ABI
courts passed (`artifacts/phase2/COURTS.json all_pass=True`). The divstep symbol
The divstep symbol in the DSO (`openssl_rs::bn::divstep::mod_inverse_divstep`, size `0x1d55`) is
**instruction-identical** to the audited release staticlib symbol after
normalising branch-target addresses. It is reachable: the DSO has one call site,
`0x43de23 -> 0x38a3d0`, inside
`openssl_rs::bn::blinding::create_param_impl` (the RSA blinding refresh).

## 2. STEP 1 — the transfer, removed and proved

### What was removed

PFP-10 found one context per divstep. At release-like codegen it compiled to a
real branch on the secret `delta`:

```
cmpq $0x0, 0x150(%rsp)     # delta
jle  ...                   # secret-derived conditional transfer
```

The source already expressed the decision as masks; the optimiser recognised
`ct_positive_mask` as `delta > 0` and lowered the select to a branch. The fix is
to put value barriers **between** the arithmetic and its use, so the mask
components are opaque when they are combined:

* `ct_is_zero_mask`: `black_box((x | -x) >> 63)` before the `- 1`.
* `ct_positive_mask`: `black_box(delta >> 63)` for the sign component, then the
  zero component above, then pure `!sign & !zero`.

`g_odd`/parity, the `>= m` correction, the modular halving and the final sign
selection were already masked arithmetic and remain so. No `if`, no early exit,
and no loop count depends on a secret: the count is
`floor((3787*64*L)/1644)` from the limb count (`591`/`2360`/`4718`), computed
from public geometry with `checked_mul`/`checked_add`.

### ctgrind evidence (same instrument, same run)

Raw logs: `raw/ctgrind-before-barriers.log`, `raw/ctgrind-after-barriers.log`,
`raw/ctgrind-final.log`.

| run | case | result |
|---|---|---|
| before barriers | `mod_inverse_divstep_with_mask` (order, 591 steps) | **1 context / 3543 errors**, at the `delta` branch |
| firing control | `ctgrind_control_canary` | **4 contexts / 4 errors** — instrument sensitive |
| after barriers, final source | all three divstep cases | **0 contexts** |
| final source, same run | `ctgrind_control_canary` | **4 contexts** |

The final run reports `ERROR SUMMARY: 4 errors from 4 contexts`; all four are the
canary. The control fires in the same valgrind process as the silent divstep
cases.

### Release-artifact audit

Raw disassembly: `raw/divstep-dso.asm` (shipped DSO), `raw/divstep-integrated.asm`
(release staticlib), classification in `raw/audit-classification.tsv` and
`raw/audit-summary.txt`.

| opcode | count | classification |
|---|---:|---|
| `jmp` | 38 | unconditional; not a conditional transfer |
| `setb` | 71 | carry/borrow mask bit from `overflowing_add/sub`; secret data bit, no control transfer |
| `je` | 48 | public loop/geometry/allocation checks + the one authorised no-inverse declassification |
| `jne` | 47 | public loop/geometry/allocation checks |
| `jae` / `jb` / `ja` / `jbe` | 11 / 9 / 2 / 1 | public slice and length bounds |
| `setne` | 4 | delta==0 mask materialisation (secret, 1/step); Option/allocation tags and length checks (public) |
| `sete` | 4 | modulus parity (public), loop index `i == 0` (public), length checks (public) |
| `seta` | 1 | length-overflow check (public) |
| `cmovb` | 2 | min of public lengths/pointers |
| `cmove` / `cmovne` | 1 / 1 | public loop-index remainder |
| `jo` | 1 | public `checked_mul` overflow in the iteration bound |

**Inside the fixed-step loop: 0 secret-derived `jcc`, 0 secret-derived `cmov`,
0 secret-derived addresses.** The one secret-derived `setcc` is the `delta == 0`
mask materialisation; it is not a control transfer. Across the whole symbol
there is **1 secret-derived `jcc` per inversion**, the wrapper's
`if invertible == 0` no-inverse result. That is the same authorised
declassification the baseline `mod_inverse_consttime` performs, not a per-step
transfer; it is reported here explicitly rather than hidden.

`dudect` is **NOT_RUN** on this venue. No constant-time claim is made from
source inspection; the claim is limited to what the audit observed above.

## 3. STEP 2 — composite-modulus preconditions

`mod_inverse_divstep_with_mask` requires:

* `m` odd and `m > 1` (an empty or even `m` is refused);
* `0 <= a < m` (a wider `a` is silently truncated by the fixed-width buffer);
* **primality is not required for correctness.** The recurrence computes
  `gcd(a,m)` and `v*a == ±gcd(a,m) (mod m)` for any positive odd `m`; when the
  gcd is one, `v` is the inverse. The mask is the invertibility verdict, so a
  composite modulus is handled like a prime one: `gcd != 1` yields an all-zeros
  mask and `None`, which is the ordinary retry answer.

The published half-delta bound also assumes only `0 <= g <= f <= M` with odd
`M` above its verified floor, not primality; here `f = m`, `g = a`.

The RSA blinding caller satisfies these: the modulus `n = p*q` is odd and
greater than one (the `n == 1` case is rejected earlier), and the factor is
drawn by `BN_priv_rand_range_ex(A, n)`, so `0 <= A < n`. A non-coprime draw
returns the mask/`None` and the existing retry loop runs, preserving the
authority's schedule. The check is exercised over composite moduli by
`composite_moduli_match_the_gcd_oracle` (1024- and 2048-bit composites,
invertible and non-invertible corners, random population, differential against
`mod_inverse_consttime_with_mask`, and the round trip `a*a^-1 == 1 (mod m)`).

## 4. STEP 3 — measurements on the right workload

Method: release-like test profile, one process, paired repetitions, real
`n = p*q` from `RSA_generate_key_ex` (not MODP primes), 15 repetitions. Raw
samples: `raw/inverse-composite.tsv`, `raw/inverse-composite-run2.tsv`,
`raw/e2e-refresh.tsv`, `raw/e2e-refresh-run2.tsv`.

### Composite inversion, paired against the fixed-iteration GCD

| run | bits | GCD median (ns) | divstep median (ns) | ratio div/gcd (median) | range |
|---|---:|---:|---:|---:|---|
| 1 | 1024 | 596,542 | 227,889 | **0.3817** | 0.3706–0.4115 |
| 1 | 2048 | 2,231,444 | 891,910 | **0.3998** | 0.3895–0.4038 |
| 2 | 1024 | 598,191 | 227,458 | **0.3813** | 0.3722–0.3894 |
| 2 | 2048 | 2,206,118 | 890,689 | **0.4054** | 0.3988–0.4141 |

### End-to-end RSA private operation through the blinding refresh

Paired 320-call blocks (ten refreshes each), alternating the two inverses in one
process and one key.

| run | GCD median (ns/op) | divstep median (ns/op) | ratio gcd/div | reduction | range |
|---|---:|---:|---:|---:|---|
| 1 | 609,328 | 567,457 | 1.0735 | **6.85 %** | 1.0717–1.0761 |
| 2 | 611,366 | 570,441 | 1.0715 | **6.67 %** | 1.0626–1.0826 |

Refresh outliers in the per-call series were at indices `0, 32, 64` in run 1 and
at `0, 32, 64` among additional scheduler noise in run 2: the **32-call refresh
schedule is unchanged**. The CRT result check, its fallback, padding and
implicit-rejection paths are untouched.

## 5. STEP 4 — admission

* (a) Clean branch audit with a firing control: **YES** (0 secret `jcc`/`cmov`
  in the loop; 4/4 canary contexts in the same run; shipped-DSO disassembly
  instruction-identical to the audited object).
* (b) Measured end-to-end RSA improvement: **YES** (6.85 % and 6.67 % across two
  paired runs, tight ranges).

Admission is therefore on both conditions, not on the inversion microbenchmark
alone. The prototype is no longer a prototype: `int_bn_mod_inverse` calls it for
odd moduli.

## 6. Gate

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --all-targets -- -D warnings` | pass |
| `cargo test --lib -- --test-threads=4` | **2588 passed, 0 failed, 56 ignored** (baseline 2585; +3 new tests, no newly ignored) |
| Phase-2 ABI courts | all pass |
| composite correctness | pass (1024/2048, corners + random, round trip, single mismatch STOP not triggered) |

## 7. Memory and safety

Every heavy command ran in the court container capped at 4 GiB
(`memory.max=4294967296`, `oom_kill=0`), one at a time. `free -g` before each:
available 18–20 GiB; swap free 0; cap `min(4, available-8) = 4 GiB`, recorded.
No OOM. The build used `CARGO_BUILD_JOBS=1`; the test gate used
`--test-threads=4`.

**Zero new unsafe in library/product code.** `src/bn/divstep.rs` contains no
`unsafe`. The ctgrind test uses the crate's pre-existing valgrind client-request
pattern, and the measurement tests use the crate's existing RSA FFI entry
points; both are `#[cfg(test)]`.

## 8. Residual obligations

* The authorised no-inverse declassification remains a secret-derived branch
  once per inversion, identical in role to the baseline; it is not per-step and
  is not hidden.
* `dudect` NOT_RUN; no statistical-timing claim is made.
* The ctgrind binary is the release-like test-profile build; the shipped-DSO
  claim rests on the instruction-identical disassembly plus that source build,
  not on running valgrind against the linked DSO.
* The working tree was already dirty (other PFP work); the hashes above bind
  the evidence to the observed tree, not to a clean commit.
