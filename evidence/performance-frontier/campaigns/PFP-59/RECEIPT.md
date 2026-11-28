# PFP-59 — P-384 Solinas Montgomery reduction: admission and measurement

**Decision: ADMIT.** P-384 ECDSA is **1.155× faster on sign** and **1.133× on
verify** (paired, same instrument, median of 15 per-repetition ratios), moving
cand/auth from **3.191 → 2.762** (sign) and **2.718 → 2.400** (verify). The
recorded baselines this is measured against are **3.260 / 2.758**; the HEAD arm
here reproduces them within 2.1 % / 1.4 %. P-521 does not move (0.999× /
1.000×). P-256 moves 1.6 % faster with no P-256 code change and never enters
the new kernel (code-layout effect, recorded below, not claimed as neutral).
The differential is exact: 48/48 P-384 cases and 96/96 cross-verifications
against the authority, 0 mismatches; the in-crate generic path agrees on 5 476
product pairs and 131 reduction inputs. The branch audit classifies every
`jcc`/`setcc`/`cmov` in the carrier as public, with the firing control firing in
the same run.

## 1. Identity

| item | value |
|---|---|
| branch / HEAD | `staging`, `a222c3d6c603babbb2e54bef3405e07367b24c0b` |
| P-384 source (new) | `src/bn/solinas.rs`, `src/ec/p384.rs` |
| P-384 source (changed) | `src/bn/mod.rs`, `src/bn/mont.rs`, `src/ec/mod.rs`, `src/ec/mont.rs`, `src/ec/lib.rs` |
| before arm source | `git archive HEAD` (clean HEAD; the working tree's unrelated edits are `#[cfg(test)]`-only) |
| after arm source | working tree (release build ignores `#[cfg(test)]`) |
| before DSO | `fa498a922f78fa9078672f8ee047df1a1e69ee052fdd77adc00021e783232b57`, 17 186 936 B |
| after DSO | `3f64590e9a178f824f997fa372f4503715ca5bec452a2fce4005e6629446e4d4`, 17 195 504 B |
| authority | `openssl-3.6.4-production`, `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| harness | PFP-11's unmodified `bench_pfp11.c` (`a92b64f4…`) and `bench_p256.c` (`0ff3dc49…`) |
| profile | release, opt-level 3, debug 0, no LTO, `CARGO_BUILD_JOBS=1` |
| machine | i9-13900K, `taskset -c 1` |

Build and artefact hashes: `raw/build/`. Timing processes: `raw/timing/`
(450 `RESULT` processes + `run-meta.env`). Differential processes:
`raw/differential/`.

## 2. Reduction bound and its proof

`p = 2^384 - 2^128 - 2^96 + 2^32 - 1`, `R = 2^384`, `B = 2^64`, `n = 6`.
Write `c = R - p = 2^128 + 2^96 - 2^32 + 1` (129 bits, three limbs
`[0xFFFFFFFF00000001, 0xFFFFFFFF, 1]`). Then

```text
p ≡ -(2^32 - 1) (mod B),   (2^32 - 1)(2^32 + 1) = B - 1
⇒ n0 = -p^-1 ≡ 2^32 + 1 (mod B) = 0x0000000100000001
⇒ u = (t_i << 32) + t_i            (a shift and an add, not a multiply)
⇒ u·p·B^i = u·B^(6+i) - u·c·B^i    (c sparse: two shifts, one subtract)
```

**Fold count: exactly 6 radix-`B` word steps**, one per public limb. The kernel
is a word REDC; the step count is the public width, never a value-dependent fold
count. `u·c` is four limbs built from shifts and adds (`mul_c`), and `u·B^(6+i)`
is one word at a fixed limb.

**Bound.** The input contract is the generic kernel's, `T < p·R`. Every caller
establishes it: `BN_mod_mul_montgomery` passes `a, b < p`, so `T = a·b < p^2 <
p·R`; `BN_to_montgomery` passes `rr = R^2 mod p < p` times an `R`-bounded input,
so `T < p·R`; `BN_from_montgomery` is routed here only for `T < R < p·R`.
Under that contract `k = Σ u_i·B^i < B^6 = R`, hence

```text
T + k·p < p·R + R·p = 2·p·R < 2^769
```

so the intermediate accumulator is below 769 bits. The fixed `ACC_LIMBS = 13`
(832 bits) holds it with spare carrying room and `t[12]` (the limb above the
six-word result) is 0 or 1. The residue `W = (T + k·p)/R` satisfies

```text
W < 2p < 2^385
```

and **one masked conditional subtraction** closes it canonically in `[0, p)`.
A single fold pass is sufficient; the six fixed steps are what make the high
limb no larger than one.

**Retained caller obligation.** The width check establishes only `a, b < R`;
two non-canonical six-limb operands give `a·b < 2^768 > p·R` and would violate
the bound undetected. This is the same retained obligation as the P-521 arm and
is not enforceable at run time without branching on secret field data.

No secret-dependent branch, index or loop bound exists in the source: fixed
limb shifts, fixed-range carry/borrow propagation, full-width mask select.

## 3. Admission — the PFP-11 mechanism, reused, not duplicated

There is **one** admission field on `MontCtx` and **one** setter. PFP-11's
`mersenne521: bool` became `special: SpecialReduction { None, Mersenne521,
Solinas384 }`; the protocol is unchanged:

* `BN_MONT_CTX_copy` copies `special`; `mont_set` clears it on every modulus
  (re)preparation; `new_mont` starts at `None`.
* `EC_GROUP_set_generator` clears it **first**, so every failure path leaves the
  fast arm refused, and at the successful tail writes the verdict of the
  audited predicates once:
  `p521::admits → Mersenne521`, else `p384::admits → Solinas384`, else `None`.
* `ec::mont::set_group_special_reduction` is reached only through
  `mont_field_data`, which checks the method identity (`field_mul ==
  ossl_ec_GFp_mont_field_mul`) **before** interpreting `field_data1`
  (`B-EC-MONT-FIELD-DATA1`). A foreign method's slot is never read or written.
* `solinas384_active` re-checks the flag **and** the prepared modulus (`is_p384`)
  and `n0 == 2^32 + 1` before the kernel; the dispatch is on public limb counts.

`ec::p384::admits` is the one audited unsafe predicate. It compares, from
`_EC_NIST_PRIME_384_DATA`: the Montgomery method, `p`, the order, cofactor 1,
`a`, `b`, and the affine generator `(Gx, Gy)` in the stored Montgomery form. The
Montgomery encoding used for the comparison is `x·2^384 mod p = x·c mod p`,
implemented independently of the kernel and checked against the group's stored
values by `the_encoding_matches_the_stored_montgomery_form`.

Tests (all pass) prove a **modified generator**, a **modified order**, a
**different curve sharing the same `p`**, and a **foreign method** each leave
the flag clear and never enter the kernel (thread-local probe count unchanged),
including the sentinel case where `field_data1` is a non-`MontCtx` object.
Copy-after-admission, curve-change reset, allocation-failure and
order-Montgomery-failure paths are also covered (`src/ec/p384.rs`).

## 4. Correctness evidence

**In-crate generic oracle** (`src/bn/solinas.rs`, all pass):

| check | count |
|---|---|
| product pairs vs `arith::mont_mul_fallible` (zero, 1, 2, 3, p−1, p−2, low-limb-zero, maximal occupancy, top-only, p, 64 pseudorandom; all cross pairs) | **5 476** (74 × 74), 0 mismatches |
| REDC inputs vs generic (max limbs, p, p+1, 128 pseudorandom, non-canonical `T < 2^384`) | **131**, 0 mismatches |
| `(p−1)^2 ≡ 1`, wider-input refusal, `p + c = 2^384`, `p·n0 ≡ −1` | pass |

**Against the authority** (`raw/differential/diff-after.json`):

| workload | cases | mismatches | cross-verifications |
|---|---|---|---|
| P-384 ECDSA (order q−1/q−2, zero/low occupancy, full-width pseudorandom, digests above q) | 48 | **0** | **96/96** (48 each direction) |
| P-521 ECDSA (control) | 48 | 0 | 96/96 |
| Ed25519 | 32 | 0 | — |
| X25519 | 36 | 0 | — |

Public key and signature bytes match the authority and each side verifies the
other's signature on every P-384 case. No mismatch occurred (a mismatch would
be a STOP).

## 5. Branch audit

Instrument: `audit59.py` on the shipped after DSO, one row per
`jcc`/`setcc`/`cmovcc`, raw listing and TSV in `raw/audit-solinas.asm` /
`raw/audit-classification.tsv`, summary `raw/audit-summary.txt`.

| carrier | jcc | setcc | cmov | secret-derived | verdict |
|---|---|---|---|---|---|
| `bn::solinas` (4 symbols: `redc_p384_in_place`, `mont_mul_p384_fallible`, `mont_reduce_p384_fallible`, `is_p384`) | 35 | 26 | 0 | **0** | **PASS** |
| `mont::solinas384_active` (dispatch) | 3 | 1 | 0 | **0** | **PASS** |

The 35 `jcc` are: 21 immediate-bound comparisons (fixed loop ranges / public
lengths), 9 slice-end pointer comparisons (`%rdx = 8·slice_len`, derived at
entry from the public length), 1 countdown loop counter, 1 length test
(`a.len() == 6 && b.len() == 6`), 1 allocation-success discriminant, 2
structural returns of `redc` (which depends only on the public scratch length).
Each of the 14 register-vs-register rows is manually adjudicated with its
reason in `raw/audit-manual.tsv`; the 3 dispatch rows in
`raw/audit-dispatch-manual.tsv`. The 26 `setcc` materialise carry/borrow bits
as data (`add/adc/setb`, `sub/sbb/setb`), they do not transfer control. No
conditional move is emitted. No index or address is derived from a limb value:
all indexed loads/stores use loop induction variables.

**Firing control** (`raw/audit-firing-control.*`): the same classifier on a
canary built with the same rustc and `-O` (`canary.rs`, a loop count taken from
its argument) reports **1 jcc + 1 cmov, review=2, verdict=STOP**, so the
instrument is sensitive on the same run in which the carrier clears.

**Not claimed:** this is a static audit of one build. ctgrind and dudect are
`NOT_RUN` on this venue; no constant-time claim is made.

## 6. Timing — paired, same instrument

15 independent process repetitions per arm and operation, order rotated,
`taskset -c 1`; ratio = arm/authority per repetition, the figure is the median
of the 15 paired ratios. Full data `raw/timing/`, analysis `raw/timing.json`,
summary `raw/timing-summary.txt`.

| operation | recorded | before | after | speedup | after 95 % CI | auth noise floor |
|---|---|---|---|---|---|---|
| P-384 ECDSA sign | 3.260 | 3.1911 | **2.7620** | **1.1554×** | [2.7521, 2.7712] | 0.0207 |
| P-384 ECDSA verify | 2.758 | 2.7180 | **2.3997** | **1.1326×** | [2.3850, 2.4062] | 0.0329 |
| P-521 ECDSA sign | — | 1.8656 | 1.8674 | 0.9990× | [1.8615, 1.8693] | 0.0117 |
| P-521 ECDSA verify | — | 1.7449 | 1.7457 | 0.9996× | [1.7373, 1.7630] | 0.0587 |
| P-256 ECDSA (sign+verify) | — | 13.0008 | 12.7985 | 1.0158× | [12.7714, 12.8164] | 0.0102 |

P-521 is unchanged within noise. **P-256 is 1.6 % faster, not neutral**: its CI
does not overlap the before CI. No P-256 code path changed and the probe proves
P-256 never enters the P-384 kernel, so this is a code-layout/link-order effect
of an 8.5 KiB larger DSO, reported rather than absorbed into a "no move" claim.
It is not a P-256 semantic change and not attributed to the new kernel.

## 7. Gate

| item | result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo test --lib -- --test-threads=4` | **2606 passed, 0 failed, 56 ignored** in 123.89 s |

The task baseline is 2588 passed / 0 failed / 56 ignored; the delta is exactly
the **18** new tests (5 `bn::solinas`, 13 `ec::p384`). No test was newly
ignored and none was removed. `test_sigstore_bundle` was not run; no release
`--test` build was made.

## 8. Memory

`free -g` immediately before every heavy command. Observed host `available`:
19, 19, 18, 19, 19, 18, 19, 19, 18 GiB; **swap free 0–1 GiB (< 16)**, so
`cap = min(4, available − 8) = 4 GiB` on every command. The `openssl-rs-court`
container was already running at exactly **4 GiB memory / 4 GiB swap**
(`docker inspect`, matching the cap); it was reused, with a declared peak below
2 GiB, well under half of `available`. `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`, one heavy command at a time, no command above
the cap, no OOM. `docker/` was not modified.

## 9. Refusals and residuals

* **ctgrind / dudect — `NOT_RUN`** on this venue. No branch-audit result is
  promoted to a constant-time claim; §5 is a static classification.
* **`ecp_nistp384` authority backend** is compiled out of this profile, so the
  comparison is against the authority's generic Montgomery path.
* **Accumulator canonicality** relies on the documented `T < p·R` caller
  obligation; it is not enforced at run time (enforcing it would branch on
  secret operands). Recorded as retained, not discharged.
* The kernel exports nothing and introduces no unsafe operation; all of it is
  safe Rust over fixed public extents. The only new unsafe surface is the
  audited `admits` predicate at the existing C ABI boundary and the existing
  method-gated setter, both matching PFP-11.
