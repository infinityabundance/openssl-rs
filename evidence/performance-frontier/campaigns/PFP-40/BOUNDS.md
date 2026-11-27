# PFP-40 — RSA blinding re-creation: the bound, the gap, and the decision

**Item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-40 (RSA blinding re-creation).
**Branch / HEAD:** `staging`, `82a044343351b83b0cf688c63aa4e59ebc61b556`.
**Authority:** OpenSSL 3.6.4 (`forensics/authorities/src/openssl-3.6.4`).
**Instrument:** callgrind 3.19.0 (`--toggle-collect` inclusive attribution), plus a
direct wall probe on the two constant-time entry points.
**Identity of the profiled candidate:** release distribution DSO
`c466ee139f2845fbfb09bb5bcdccf0a4a7f18e3cad0c400073422d55eead1d93`, built from the
clean tree at the HEAD above (`cargo build --release --lib --offline`,
`CARGO_BUILD_JOBS=1`), with the PFP-7/PFP-6 shell + version script.

All numbers below are **pre-change** and were taken at this HEAD before any edit.
The change prototyped in §7 is *not* certified: see §8.

---

## 1. The refresh, isolated

`BN_BLINDING_update` re-creates the factor when its use counter reaches
`BN_BLINDING_COUNTER = 32` (`src/bn/blinding.rs:70`, authority `bn_blind.c:14`).
Per-call wall timestamps (PFP-7 harness, 205 calls) show the re-creation as outliers
at call indices `0, 32, 64, 96, 128, 160, 192` of **5.04–5.15 ms**, against a steady
op of **515.5 µs** (15-rep median). Subtracting the steady op:

```
whole refresh = 5,150,070 ns (index 32) − 523,707 ns = 4,626,363 ns  ≈ 4.63 ms
```

Callgrind run: one process, 66 `RSA_private_encrypt(RSA_NO_PADDING)` calls;
`--toggle-collect="*create_param_impl*"` collects exactly the three constructor calls
(setup + refresh at 32 + refresh at 64).

| quantity | candidate | authority |
|---|---:|---:|
| calls collected | 3 | 3 |
| total instructions | 359,390,142 | 12,907,538 |
| **per refresh (Ir)** | **119,796,714** | **4,302,513** |
| ratio | **27.85×** | 1× |

## 2. Attribution of the refresh

Method: (i) callgrind inclusive instruction counts, which partition the toggle total
exactly; (ii) a direct wall probe (`probe/pfp40_probe.c`) driving
`BN_mod_inverse` and `BN_mod_exp_mont` with the same geometry the refresh uses
(the modulus carries `BN_FLG_CONSTTIME`, the Montgomery context is precomputed).
Wall figures are medians of 60 calls, `taskset -c 1`.

| component | candidate Ir | share | candidate wall | authority wall | ratio |
|---|---:|---:|---:|---:|---:|
| (b) modular inversion (`limbs::mod_inverse_consttime`, fixed-iteration binary EEA) | 66,115,275 | **55.19 %** | **2,215,369 ns** (47.1 %) | 195,368 ns | 11.3× |
| (d) exponentiation (`BN_mod_exp_mont` → const-time ladder) | 53,338,919 | **44.52 %** | **2,487,616 ns** (52.9 %) | 48,057 ns | 51.8× |
| (a) random draw (`BN_priv_rand_range_ex`) | 275,038 | 0.23 % | 8,058 ns (0.17 %) | 1,086 ns | 7.4× |
| (c) allocation, cleansing, Montgomery conversions, bookkeeping | 67,482 | 0.06 % | remainder | remainder | — |
| **total** | **119,796,714** | 100 % | **≈4,703,000 ns** vs 4,626,363 ns observed whole refresh (±1.7 %) | 244,511 ns | 27.9× |

Read this as **worst case: inversion is the larger instruction share (55 %), but on
wall time the exponentiation is the larger cost (53 %)** — the const-time ladder has
the lower IPC. Allocation/cleansing is negligible (≤0.06 % of instructions):
there is **no per-call allocation gap**. The RNG draw is 0.17 % of the refresh:
there is **no draw-size gap** either.

## 3. Authority attribution (same instrument)

Callgrind `--toggle-collect="BN_BLINDING_create_param"`, 3 calls:

| component | authority Ir | share |
|---|---:|---:|
| `int_bn_mod_inverse` (Euclid via constant-time `BN_div`) | 8,666,801 | 67.15 % |
| `BN_mod_exp_mont` → `BN_mod_exp_mont_consttime` | 4,048,725 | 31.37 % |
| random + conversions + bookkeeping | ≈192,000 | 1.5 % |

## 4. The two source-level differences (with lines)

**(D1) The inverse algorithm differs by design.** The authority's
`int_bn_mod_inverse` (`crypto/bn/bn_gcd.c:197`) dispatches to
`bn_mod_inverse_no_branch` (`:21`), whose outer loop is `while (!BN_is_zero(B))`
(`:82`) — a **data-dependent iteration count** built on constant-time `BN_div`.
Its 2.89 M Ir / 195 µs per refresh comes from that early-terminating Euclid.
Our `int_bn_mod_inverse` (`src/bn/blinding.rs:799-832`) always calls
`limbs::mod_inverse_consttime`, a **fixed 2·64·n + 2 = 4,098-iteration** binary
extended GCD at 2048 bits (PFP-10 §2), which is the deliberate stronger property:
the work does not depend on the secret factor. **We must not adopt the authority's
terminator**: it would introduce a secret-dependent control-flow dependence on the
blinding factor, which the item forbids. This half is a safety property, not slack.

**(D2) The re-blinding exponentiation runs 32× too wide.** The authority's
`BN_BLINDING_create_param` calls `ret->bn_mod_exp` (= `BN_mod_exp_mont`,
`crypto/bn/bn_blind.c:288-294`), which dispatches to
`BN_mod_exp_mont_consttime` (`bn_exp.c:331-335`); the fixed-top body sizes its
ladder from `bits = p->top * BN_BITS2` — the exponent's **whole-limb** length,
chosen deliberately so that zero top bits are not revealed
(`bn_exp.c:633-637`). For RSA's `e = 65537` that is **one limb (64 bits)**.

Our `src/bn/mont.rs::bn_mod_exp_mont_impl` (`:1029-1068` before this batch) sized
the same fixed-pattern ladder from `md.len()` — the **modulus** width, 32 limbs
(2048 bits) — because a generic `BN_mod_exp_mont` may carry a secret exponent whose
length must not leak. On the blinding path the exponent is the public exponent, so
this is 32× more ladder than the authority runs. That is the gap.

The other suspects are excluded by §2: per-call allocation is ≤0.06 %, the RNG draw
difference is ~7 µs, and the Montgomery conversions are included in the ≤0.06 %
remainder with the bookkeeping.

## 5. The Amdahl ceiling

Baseline sustained op (15 paired reps, median): **683,887 ns**; authority
**349,040 ns** (1.9593×). Refresh amortised over 32 calls: 4,626,363 / 32 =
**144,574 ns/op**. Latency (min, refresh-free) is **515,480 ns** and does not
contain the refresh.

**(i) Whole ceiling — if the refresh fell to the authority's cost.** Authority
inverse + exponentiation + draw = 195,368 + 48,057 + 1,086 = **244,511 ns** per
32 calls. Saving = (4,626,363 − 244,511)/32 = **136,933 ns/op**.

```
new sustained = 683,887 − 136,933 = 546,954 ns
speedup       = 683,887 / 546,954 = 1.250×   (throughput)
latency       = 1.000×                        (the refresh is not in the min)
```

**(ii) Safe subset — only D2 (the exponentiation).** New refresh =
4,626,363 − 2,487,616 + 48,057 = **2,186,804 ns**. Saving = 76,237 ns/op.

```
new sustained = 683,887 − 76,237 = 607,650 ns
speedup       = 683,887 / 607,650 = 1.126×   (throughput)
latency       = 1.000×
```

The full ceiling is **1.25× throughput**, but it is only reachable by trading away
the fixed-iteration constant-time inverse (D1), which is refused. The reachable
safe subset is **1.126× throughput, 0 % latency**.

## 6. Decision

* **D1 (inversion, 47 % wall / 55 % instructions) — REFUSED.** Adopting the
  authority's `bn_mod_inverse_no_branch` would make the *number of iterations*
  depend on the secret blinding factor. The fixed-iteration binary EEA is the
  safety property the crate chose; it is not slack to be recovered.
* **D2 (exponentiation, 53 % wall / 45 % instructions) — IMPLEMENTED as the safe
  subset.** The exponent is the RSA public exponent; its whole-limb length is
  public (the authority declassifies exactly `p->top`). The same fixed-pattern
  kernel runs with `width = pd.len()` limbs instead of `md.len()` limbs, so the
  secret base never selects the schedule. Expected ~1.126× throughput, 0 %
  latency, per §5(ii).
* **The 32-call schedule, the result check and its fallback, padding and implicit
  rejection are untouched.**
* **No constant-time claim is made about the exponent**: its limb length is
  observable by construction on this path (as in the authority). The ladder
  remains constant-pattern in the secret base; no new secret-dependent branch on
  the blinding factor is introduced.

## 7. The prototype (present in the working tree, uncommitted)

* `src/bn/mont.rs`: `LadderWidth { Modulus, Policy {..}, PublicExponent }`;
  `BN_mod_exp_mont` keeps `Modulus`, the DH policy keeps `Policy`, and only the
  crate-visible `bn_mod_exp_mont_impl` is called with `PublicExponent`
  (`width = pd.len().max(1)`). **No new `unsafe` declaration and no new unsafe
  operation**: the existing audited body is reused, with its visibility widened to
  `pub(crate)` and a `# Safety` section added.
* `src/bn/blinding.rs`: `create_param_impl` selects `PublicExponent` only when the
  effective hook is the crate's own `BN_mod_exp_mont`
  (`core::ptr::fn_addr_eq`), inside the existing `unsafe` block; any
  method-supplied hook is still honoured verbatim.
* Tests added: `the_public_exponent_ladder_matches_the_modulus_width_ladder`
  (mont.rs; ladder at 1/2/modulus limb widths vs the variable-time oracle and vs
  the modulus-width ladder) and `the_scheduled_recreation_still_yields_a_cancelling_pair`
  (blinding.rs; 40 round trips across the 32-call re-creation, Montgomery branch).

## 8. Gate status — NOT CERTIFIED

`cargo check --lib` and `cargo fmt --all -- --check` passed while the memory floor
was met (available 18 GiB, swap free 17 GiB). The mandatory heavy gate —
`cargo clippy --all-targets -- -D warnings`, the two new tests, the full
`cargo test --lib`, and the post-change RSA latency re-measurement — was **not
run**: `free -g` then reported **available 21–23 GiB, Swap free 14 GiB**, below the
item's mandated 16 GiB swap-free floor. Per the instruction, no heavy command was
started. Correctness of the prototype is therefore **uncertified**, and it is left
uncommitted. See `RECEIPT.md` §gate.
