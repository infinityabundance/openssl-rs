# PFP-11 — per-curve field representation, reduction and scalar strategy

**Item.** P-384, P-521, X25519 and Ed25519, each with its own field
representation, reduction and scalar strategy; P-521 uses its Mersenne
structure rather than Montgomery. Acceptance: per-curve differential and
timing evidence; no shared assumption carried over from P-256.

**Candidate.** `staging` at `dcf49b408e49b5197eb0a20035f423fc7f605649`
(`src` tree `eb5cf87f7aab4529463cc1eaed0a3b56f2fcc96d`, zero build-relevant
working-tree changes). Candidate DSO
`dbf3d0a427ad9a63eb9b724f1434e2b48a3a005242e60e450cf49db922653e3a`
(archive `e3a5652904a8952b756055bcc5e155085b3d5f707bc61d3b517de0eae9d80deb`,
build id `ec3c97cfe3a75d5c50ee64836593a2eeaabad8a2`). Authority
`openssl-3.6.4-production` DSO
`611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.
Harness source `a92b64f4b3de50e76caba32810daeadf31d888dc82d7a7c3aaa8897db462f835`,
binary `8fd79af139a5002e0fa55b86ca005a4f20970a82f76af56a7465e411ba72de62`
(all timing and differential results below are from these).

**Decision in one line.** The P-521 field-multiply share is **82.65 %**
(sign) / **74.03 %** (verify), so an ideal specialised field/reduction clears
the 10 % threshold many times over; reduction alone is **≈45 %** of sign. The
implementation is nevertheless **refused**, because the batch's two hard
constraints — *zero new unsafe* and *dispatch only on an exact group identity
with a proven fallback* — are jointly unsatisfiable on this path without new
unsafe reads of `EcGroup`/`BIGNUM` or a `#[repr(C)]` layout change. §7 states
the proof obligation precisely. The other three curves are recorded as
non-selected refusals with their arithmetic.

---

## 1. What each curve actually uses today

Established by source reading, not by the P-256 engine. `openssl-rs` has a
dedicated P-256 engine (`src/ec/p256/`) and a `fixed_base::admits` predicate;
none of the four curves below inherits it.

| curve | module | field representation | reduction | scalar multiplication | today |
|---|---|---|---|---|---|
| **P-384** | `src/ec/mont.rs`, `src/bn/mont.rs`, `src/bn/arith.rs` | Montgomery, radix 2^64, 6 limbs, `R = 2^384`; stored in a `BIGNUM` (`ec/mont.rs:109-115`, `bn/mont.rs:75`) | **fused CIOS REDC**, `mont_mul_cios_fixed::<6,8>` (`bn/arith.rs:2102`); dedicated squaring `mont_sqr_into` (`bn/arith.rs:2122`). Generic BIGNUM division is **not** on this path. | `ossl_ec_wNAF_mul` (`ec/mult.rs:739`); secret scalar → Montgomery ladder `ossl_ec_scalar_mul_ladder` (`ec/mult.rs:315`, called at `:787-790`); verify → windowed public double-scalar wNAF. Point add/dbl are Jacobian (`ec/smpl.rs:991`, `:1232`), ladder step `ec/smpl.rs:2368`. | generic Montgomery BIGNUM EC |
| **P-521** | same | Montgomery, radix 2^64, **9 limbs**, `R = 2^576` | fused CIOS REDC, `mont_mul_cios_fixed::<9,11>` (`bn/arith.rs:2103`). `BN_nist_mod_521` (`bn/nist.rs:143`, the Mersenne fold) exists but is **unreachable** from this path: `BN_nist_mod_func` has no in-crate caller (`bn/nist.rs:164`), because the admitted build defines `OPENSSL_BN_ASM_MONT` and `ec_cvt.c` takes the Montgomery arm (`ec/cvt.rs:55-58`). | identical to P-384 | generic Montgomery BIGNUM EC; **p = 2^521−1 is not exploited** |
| **X25519** | `src/ec/curve25519.rs` | `Fe64 = [u64;4]`, radix 2^64, modulus `2^256−38` (`curve25519.rs:78-80`); fallback `Fe51 = [u64;5]`, radix 2^51 (`:79`) | `fe64_fold` — `low + 38·high`, two fixed folds (`:178-205`); production path selected by `x25519_fe64_eligible` (BMI2+ADX, `:158-167`) | fixed 255-iteration Montgomery ladder with `cswap`, `x25519_scalar_mulx` (`:1819-1869`); `Fe51` fallback `:1881-1931`; scalar reduction `x25519_sc_reduce` (masked long division, `:1745`) | **already curve-specific** |
| **Ed25519** | `src/ec/curve25519.rs` | `Fe = [i32;10]`, radix 2^25.5 (`:78`), modulus `2^255−19` | `fe_conv` (19-coefficient convolution) + `fe_reduce` (carry chain folding `2^255 ≡ 19`, `:1098-1157`) | sign: fixed-base comb `ge_scalarmult_base` (`:1558`); verify: `ge_double_scalarmult_vartime` (`:1644`); scalar arithmetic `sc_muladd` (`:1761`) + `x25519_sc_reduce` | **already curve-specific** |

The P-384/P-521 group is selected by `curve_list_method` returning `None`
(`ec/curve.rs:242-248`) → `EC_GROUP_new_curve_GFp` (`ec/curve.rs:437-438`) →
`EC_GFp_mont_method` (`ec/cvt.rs:73`). The P-256 fixed-base predicate is
consulted (`p256::fixed_base::try_fixed_base_mul`, `ec/mult.rs:787`) but
refuses: it executes 488 instructions (0.00 %) in the P-521 sign profile — a
direct observation that no P-256 assumption is carried over.

**Answer to the P-521 question.** Reduction is **not** generic BIGNUM
division. It is the reduction half of the fused 9-limb Montgomery CIOS kernel.
The Mersenne fold exists (`BN_nist_mod_521`) but does not run on the EC path.

---

## 2. Timing (same instrument, one digest, pinned authority)

Instrument: `bench_pfp11.c`, one `libcrypto.so.3` per process
(`dlopen(RTLD_NOW|RTLD_LOCAL)`), one process = one independent repetition,
`taskset -c 1`, 15 repetitions, 5 timed batches per process, warm-up
`iters/4`. ECDSA uses a 32-byte digest (`0x44494700` operand source);
Ed25519's digest is fixed by the algorithm. Ratio = cand/auth (>1 = candidate
slower); interval is a 95 % percentile bootstrap over the 15 paired ratios.
Noise floor is the authority arm's own relative half-range
`(max−min)/median` over its 15 process medians.

| operation | cand µs | auth µs | ratio | 95 % CI | noise floor |
|---|---:|---:|---:|---|---:|
| ECDSA sign P-384 | 1273.471 | 390.189 | **3.260** | [3.255, 3.270] | 0.0145 |
| ECDSA verify P-384 | 916.343 | 332.009 | **2.758** | [2.750, 2.768] | 0.0228 |
| ECDSA sign P-521 | 2505.227 | 935.395 | **2.679** | [2.674, 2.688] | 0.0127 |
| ECDSA verify P-521 | 1776.624 | 746.486 | **2.381** | [2.370, 2.391] | 0.0205 |
| X25519 derive | 32.239 | 19.603 | **1.640** | [1.633, 1.647] | 0.3083 |
| Ed25519 sign | 67.383 | 18.276 | **3.693** | [3.662, 3.695] | 0.0309 |
| Ed25519 verify | 242.696 | 58.177 | **4.170** | [4.163, 4.190] | 0.0330 |

The X25519 authority noise floor is 31 % (a ~20 µs operation on a shared
host), so its ratio is reported with that floor even though the paired CI is
narrow. All other floors are ≤3.3 %.

**Differential (per curve).** `run_diff.py`, one vector per class where it
applies:

| population | cases | result |
|---|---:|---|
| ECDSA P-384: priv ∈ {1,2,3, 4 pseudorandom full-width, q−1, q−2} × digest ∈ {0, 2^256−1, 2× random, 2^512−1, 2^528−1} | 48 | 0 public-key/digest mismatches; **96 cross-signature verifications** (48 each direction) PASS |
| ECDSA P-521: same classes | 48 | 0 mismatches; **96 cross-verifications** PASS |
| Ed25519: seed ∈ {0, all-ones, 6 random} × msg ∈ {0, 1, 64, 64-all-ones} | 32 | public key and signature **byte-identical** to the authority, 0 mismatches |
| X25519: 6×6 private/peer pairs incl. all-zero and all-ones | 36 | shared secret (or agreed derive failure) byte-identical, 0 mismatches |

This exercises the PFP-22 classes that apply: order boundaries (q−1, q−2),
zero, low limb occupancy (1,2,3), maximal limb occupancy (full-width random),
and digests above the order (2^512−1, 2^528−1). A single mismatch would have
been a STOP; none occurred.

---

## 3. Attribution (callgrind, one digest)

Instrument: valgrind 3.19.0 `--tool=callgrind` on the exact candidate DSO,
`callgrind_annotate --inclusive=no` (disjoint self-cost partition). Shares are
**instructions**, not cycles. `other` holds point glue, startup, hashing, RNG
and the dynamic loader.

| operation | field mul/sqr/reduce | inversion | field add/sub | scalar/order | alloc/memory | other |
|---|---:|---:|---:|---:|---:|---:|
| ECDSA sign P-384 | 48.06 | 0.00 | 3.31 | 0.42 | 32.29 | 15.92 |
| ECDSA verify P-384 | 45.52 | 0.01 | 3.46 | 0.95 | 31.41 | 18.66 |
| ECDSA sign P-521 | **61.86** | 0.00 | 2.58 | 0.22 | 24.08 | 11.27 |
| ECDSA verify P-521 | **59.00** | 0.00 | 2.74 | 0.70 | 23.66 | 13.89 |
| Ed25519 sign | 75.32 | 0.11 | 0.00 | 0.00 | 4.12 | 20.46 |
| Ed25519 verify | 91.02 | 0.04 | 0.00 | 0.00 | 1.44 | 7.50 |
| X25519 derive | 58.32 | 0.02 | 0.00 | 0.00 | 7.22 | 34.44 |

Self-cost understates inversion because an inversion's multiplications execute
inside the shared Montgomery carrier. The **inclusive** shares are the right
Amdahl input:

| operation | field-multiply subtree | field inversion (Fermat) | order inverse |
|---|---:|---:|---:|
| ECDSA sign P-384 | **78.28 %** | 2.83 % | 1.32 % |
| ECDSA verify P-384 | **70.57 %** | 5.16 % | 1.72 % |
| ECDSA sign P-521 | **82.65 %** | 4.21 % | 1.96 % |
| ECDSA verify P-521 | **74.03 %** | 7.77 % | 2.59 % |
| Ed25519 sign | **75.32 %** (fe_conv+fe_reduce) | — | — |
| Ed25519 verify | **91.02 %** | — | — |
| X25519 derive | **58.32 %** (Fe51 fallback) | — | — |

**P-521 reduction share.** The 82.65 % field-multiply subtree splits into
`ossl_ec_GFp_mont_field_mul` 53.58 % and `ossl_ec_GFp_mont_field_sqr` 29.21 %
(sign). In the CIOS multiplication each of 9 outer steps performs 9 product
multiplications and 9 reduction multiplications (50 % reduction); the
dedicated Comba squaring performs 45 product and 81 reduction multiplications
(64.3 % reduction). Weighted:
`(53.58·0.50 + 29.21·0.643) / 82.79 = 0.550`.
So **reduction limb-multiplication alone is ≈ 45.5 % of P-521 sign and
≈ 41.3 % of verify**. This counts the REDC multiplications only; REDC carry
and add work makes total reduction larger, not smaller. It is not a measured
constant — it is arithmetic on the measured mul/sqr split.

A Mersenne REDC is unusually cheap here for a structural reason: for
`p = 2^521−1`, `p ≡ −1 (mod 2^64)`, so the Montgomery `n0 = −p^{-1} mod 2^64`
is **1**. In the REDC step `t += u·p` with `u = t[i]`, and
`u·p = u·2^521 − u`; the `−u` cancels `t[i]` exactly and the `+u·2^521` is a
9-bit shift into two limbs. The reduction becomes carry/add only, no
multiplication.

**Instrument caveats recorded, not hidden.**
1. Under valgrind, CPUID leaf 7 EBX reports `ADX=0` (`valgrind` masks it;
   native is `0x219c27eb`, valgrind `0x000427aa`). The X25519 profile therefore
   took the `Fe51` fallback, not the production `Fe64` path. The timing run is
   native and uses `Fe64`; the X25519 attribution is a fallback profile.
2. Released Rust symbols carry no DWARF, so callgrind resolves by symbol table.
   A 10.34 % `fe_conv` entry in the X25519 profile is treated as
   symbol-resolution noise; no source call path from the `Fe51` ladder reaches
   `fe_conv`.
3. Instruction shares are not cycle shares; allocation (`alloc/memory`) has
   disproportionate cycle cost and is reported separately.

---

## 4. Amdahl, per curve

`f` = attributable field-arithmetic share (inclusive field multiply for
ECDSA; the field category for the 25519 curves). `reduction` = `f` × the
reduction fraction derived above. `ceiling` = `f` (an infinitely fast field
removes exactly that share). `s_for_10` = smallest field speedup that clears a
10 % end-to-end reduction: `s = f/(f−0.10)`. `s_halfred` / `e2e_halfred` =
field speedup and end-to-end reduction if half the reduction work is removed.

| operation | f | reduction share | ceiling | s for 10 % | s half-red | e2e half-red | clears 10 %? |
|---|---:|---:|---:|---:|---:|---:|---|
| ECDSA sign P-384 | 78.32 % | 43.08 % | 78.32 % | 1.146× | 1.379× | 21.5 % | **yes** |
| ECDSA verify P-384 | 70.54 % | 38.80 % | 70.54 % | 1.165× | 1.379× | 19.4 % | **yes** |
| ECDSA sign P-521 | **82.65 %** | **45.46 %** | **82.65 %** | **1.138×** | 1.379× | **22.7 %** | **yes** |
| ECDSA verify P-521 | 74.03 % | 40.72 % | 74.03 % | 1.156× | 1.379× | 20.4 % | **yes** |
| Ed25519 sign | 75.32 % | 6.03 % | 75.32 % | 1.153× | 1.042× | 3.0 % | field yes; **reduction only no** |
| Ed25519 verify | 91.02 % | 7.28 % | 91.02 % | 1.123× | 1.042× | 3.6 % | field yes; **reduction only no** |
| X25519 derive | 58.32 % | n/a (fused) | 58.32 % | 1.207× | ≈1.176× | ≈8.7 % | field yes; **reduction-only no** |

Every curve has a field-specialisation ceiling above 10 %. For P-521 the
reduction component alone is ≈45 %, so even a reduction-only specialisation
clears 10 % with room to spare. The binding constraint is therefore not
Amdahl.

---

## 5. Decision per curve

- **P-521 — highest value; performance-admissible, implementation refused.**
  Largest absolute cost (2.505 ms sign / 1.777 ms verify), highest ECDSA field
  share (82.65 % / 74.03 %), and the only curve for which the queue item's
  "Mersenne rather than Montgomery" is both meaningful and unimplemented.
  A reduction-only fold has a 45.5 % sign / 41.3 % verify ceiling. **Refused**
  under §7's unsatisfiability, not because the ceiling is too low.
- **P-384 — refused (not selected + same blocker).** Field share
  78.32 % / 70.54 %, reduction 43.1 % / 38.8 %; ceiling clears. Not selected
  because P-521 has the larger absolute cost and the Mersenne clause does not
  apply: `p = 2^384−2^128−2^96+2^32−1` is Solinas, not Mersenne, so the
  shift-only REDC trick (`n0 = 1`) is unavailable. A Solinas reduction
  (`BN_nist_mod_384`, `bn/nist.rs:125`) exists but is off-path for the same
  reason as P-521's.
- **X25519 — refused (already curve-specific).** Field share 58.32 % in the
  `Fe51` fallback profile (production is `Fe64`, which valgrind cannot select).
  Field ceiling clears, but the curve already has its own representation
  (2^256−38 / 2^51), fold reduction and fixed 255-step ladder; the remaining
  work is optimising an existing kernel, not supplying a missing
  representation. Reduction is fused into multiply, so a reduction-only
  specialisation would not clear 10 %.
- **Ed25519 — refused (already curve-specific).** Field share 75.32 % sign /
  91.02 % verify, but reduction is only ≈6-7 % of the field work
  (`fe_reduce` vs `fe_conv`). A reduction-only specialisation has a 6.0-7.3 %
  ceiling — **below 10 %**. A multiplication specialisation would clear, but
  the field is already a dedicated 2^25.5 implementation with its own comb and
  double-scalar routines.

---

## 6. Why no curve was implemented — the exact blocker

The item imposes two hard constraints on any fast arm:

1. *Safe Rust, zero new unsafe*; if unsafe is unavoidable, stop and report.
2. *Dispatch only on an exact group/curve identity match, mirroring
   `fixed_base::admits`; a modified curve parameter or a foreign method must
   fall back, and a test must prove the fast arm is not entered.*

On the P-521 EC path the only object that reaches the Montgomery kernel is
`MontCtx` (`ec/mont.rs:109-135`), which carries the modulus, `R²`, `R`, `n0`
and `ri` — **not** `a`, `b`, the generator, the order or the cofactor. It is
therefore insufficient to decide `admits`. The objects that carry those
parameters are `EcGroup` (`*const EcGroup`) and `BIGNUM` (`*const BigNum`).

- Deciding at the EC layer (`ossl_ec_GFp_mont_field_mul`, `ec/mont.rs:326`, or
  a new method-table entry) requires **new unsafe reads** of `EcGroup` members
  and `BIGNUM` limbs. The existing function's `# Safety` contract already
  asserts those pointers are live, but the operations are new, so the batch's
  "zero new unsafe" condition is violated.
- Deciding inside the **safe** arithmetic layer (`bn::arith`, where the kernel
  could be written with no unsafe at all) can only key on the modulus. That
  arm would also run for a custom `EC_GROUP_new_curve_GFp` group with a
  modified `a`/`b`/generator or a foreign method on the same `p`. That is
  exactly the case constraint 2 requires to fall back, and no test could
  truthfully prove non-entry.
- Adding an admission flag to `EcGroup` is barred by `#[repr(C)]` layout
  preservation (AGENTS §6).

`(1) ∧ (2)` is therefore unsatisfiable for this fast arm without new unsafe.
Per the item's own instruction, the batch stops and reports rather than
implement with new unsafe or weaken the dispatch contract.

**What would unblock it.** Put the admission flag in the opaque, non-repr(C)
`MontCtx`, set/cleared by the full `admits` predicate at
`EC_GROUP_set_generator`/`EC_GROUP_copy`, and let the safe kernel dispatch on
that flag inside `BN_mod_mul_montgomery`. The predicate remains one audited
unsafe function at the existing C ABI boundary (the `p256::fixed_base::admits`
pattern), the arithmetic interior stays safe slice code, and modified
parameters/foreign methods are testably refused. That is a separate, audited
change with its own negative-control and branch-audit evidence; it is not
claimed here.

---

## 7. Residual obligations

1. **Implementation of P-521 Mersenne REDC** — `REFUSED`, blocker above.
   Performance ceiling 82.65 % sign / 74.03 % verify; reduction-only
   45.46 % / 40.72 %.
2. **Differential for an implemented fast arm** — `NOT_RUN` (no arm); the
   current-implementation differential above is `PASS`.
3. **Branch audit of a fast carrier** — `NOT_RUN` (no carrier). The current
   carriers were not re-audited because no source changed.
4. **Constant-time claim for a P-521 fold** — `NOT_RUN` (no fold). The shift
   REDC with `n0 = 1` is branchless by construction, but construction is not
   evidence; it was not implemented, so no timing or branch claim is made.
5. **X25519 production-path attribution** — `PARTIAL`: callgrind only reaches
   the `Fe51` fallback under valgrind's masked ADX; the native timing is
   `Fe64`. A production-path instruction profile needs a CPUID-override build
   or hardware performance counters.
6. **Callgrind symbol resolution** — `PARTIAL`: release symbols lack DWARF;
   one X25519 `fe_conv` attribution is unexplained (caveat 3.2).
7. **P-384 Solinas/NIST path** — not examined beyond establishing it is
   off-path; a Solinas engine remains a separate item.
8. **Ed25519 multiplication optimisation** — not attempted; only the
   reduction ceiling (6-7 %) was bounded.
