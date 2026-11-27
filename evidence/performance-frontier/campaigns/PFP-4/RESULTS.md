# PFP-4 — the order inversion replaced, at digest `4e6ec312`

This file records the implementation the W3 bound ([`BOUND.md`](BOUND.md))
deferred and the design sketch ([`DESIGN.md`](DESIGN.md)) described. The
pipeline conversion (scalar arithmetic, `s` expression, export) remains
**refused by the bound** and was not attempted; only the order inversion was
replaced. `k·G` (85.8 % of signing wall time) remains PFP-3/W5 territory.

## 1. Identity

| item | value |
|---|---|
| branch / head | `staging`, `5ac6fddc53f5ca2a63912f51c07188b9b63f71dd` |
| working-tree build-relevant changes | `src/ec/lib.rs`, `src/ec/p256.rs`, `src/ec/p256/fixed_base.rs`, `src/ec/p256/tests.rs` |
| source-tree fingerprint | `4e05841492051be7ca3655196af353b642f6753df11152ae7f0141135815b2ca` (887 files) |
| candidate DSO | `court/tmp/pfp4-a/distribution/libcrypto.so.3` (and `pfp4-b`) |
| candidate SHA-256 | `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77` |
| candidate build-id | `f38d4d5ce9641bebfd302db772d4802f269e0ed1` |
| archive SHA-256 | `10bb388a2f46c5199ef69f331b181f9ced3dfc3cb31639ff2aafc76eaaba9aa0` |
| authority DSO SHA-256 | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| before (PFP-3) DSO | `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` |

Two independent clean builds from fresh `CARGO_TARGET_DIR`s (`build_pfp4.sh a`
and `b`) produced the **same** DSO digest and build-id. Records:
`build/raw/build-inputs-a.txt`, `build/raw/build-inputs-b.txt`.

## 2. Design

`k⁻¹ mod n` is Fermat exponentiation over the **public** compile-time constant
`n-2` (`ORDER_MINUS_2`, `src/ec/p256.rs`), in the order domain:

* `P256Scalar::invert` runs 256 squarings and one multiplication on each set bit
  of `n-2` (169 set bits → 425 kernel operations), MSB first.
* Every operation is the existing audited `Mont<OrderDomain>` kernel
  (`P256Scalar::mul`/`sqr`), the same fixed-width 4-limb Montgomery
  multiplication and REDC the field engine uses.
* `0` maps to `0` (`0^(n-2) = 0`), exactly as the generic Fermat path.
* A non-canonical operand is reduced modulo `n` by
  `P256Scalar::from_canonical_reduced` (one masked subtraction; a four-limb
  value is below `2n`).
* Admission is exactly PFP-3's predicate: `fixed_base::admits` (prime, `a`,
  `b`, order, cofactor, tracked generator and plain-ladder method). The hook is
  in `ec_field_inverse_mod_ord` (`src/ec/lib.rs`), **after** its `mont_data`
  null check, so every failure answer is preserved. Any other group, generator,
  curve, method, negative operand or wider-than-four-limb operand keeps the
  generic `bn_mod_exp_mont_fixed_top` path.
* `try_inverse_order` copies the operand limbs out before writing the result, so
  the signing call's aliased `r == x == k` is safe.

### Why it is branch-free in the secret

The exponent `n-2` is a compile-time constant, so the square/multiply schedule
is a **public constant**: the branch on an exponent bit (`bt` + `jae`, see the
audit) and the fixed 256-iteration count reveal nothing about `k`. The secret
base only ever enters the kernel's fixed-pattern multiplications. The
admission/marshalling branches are on public metadata — pointer nullness, the
public group identity (`admits`), the operand's sign, limb count and `Vec`
capacity — never on a limb value. This is the same discipline PFP-3 applied to
`p-2` in `fixed_base::invert`.

## 3. Correctness gates

| gate | result |
|---|---|
| in-crate scalar Fermat test vs an independent `bn::limbs` oracle | **4,108 cases, 0 mismatches** (4,096 nonce-shaped + 12 edge/limb/top-zero) |
| in-crate `k · k⁻¹ ≡ 1 (mod n)` | **4,107 round-trips** (the one zero case maps to zero, as the generic path does) |
| BigNum-level vs the existing generic `bn_mod_exp_mont_fixed_top` body | **4,096 cases, 0 mismatches**, including non-canonical operands and the aliased `r == x` call |
| DSO `sign-ex` — supplied-nonce signatures, defining equation + `ECDSA_sign_ex` DER | **4,096/4,096**, `s·k = m + r·d (mod n)` for each, DER identical to the authority |
| DSO `sign-rand` — shipped `ECDSA_do_sign` with deterministic nonces, exercising the new inverse | **4,096/4,096** signatures byte-identical to the authority (r and s) |
| cross-verification both directions, both modes | **4,096/4,096 each**, one public key |
| `ECDSA_sign_ex`, supplied nonces, custom methods, retries, error surfaces | `ECDSA_sign_ex` DER equals `ECDSA_do_sign_ex` per case; supplied nonces unchanged; modified generator/order/curve/foreign-method groups still refused by `admits` (existing refusal tests, now also assert the inverse arm refuses); retries and error sites unchanged |
| `cargo test --lib -- ec` | **649 passed, 0 failed, 13 ignored** |
| full library suite | **2,487 passed, 0 failed, 54 ignored** |
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --all-targets -- -D warnings` | pass |

The DSO courts are byte-bound to the candidate and authority digests and prove
the mapped file by `realpath`/`dev`/`ino`/`size` against `stat(2)`.
Records: `differential/raw/comparison.tsv`, `cross-verification.tsv`,
`identity-check.tsv`, `run-meta.env`.

## 4. Constant-time evidence

**ctgrind** (`ctgrind/CTGRIND.md`, `ctgrind/raw/`), three repetitions per
population, `valgrind-3.19.0 memcheck --num-callers=24`:

| subject / mode | errors | contexts | engine-on-path | origin-in-engine |
|---|---:|---:|---:|---:|
| candidate `control` | 0 | 0 | 0 | 0 |
| candidate `sign` (d tainted) | 123 | 120 | 0 | 0 |
| candidate `sign-nonce` (d **and** RAND output tainted) | 123 | 120 | **0** | **0** |
| before `sign` / `sign-nonce` (generic inverse) | 122 | 119 | 0 | 0 |
| sensitivity `83f67826` `mul-g-fixed` | 1605–1615 | 196–207 | **4 per rep** | 0 |

The `sign-nonce` RAND callback marks its output undefined, so the hash-to-nonce
chain and the nonce handed to the inverse are secret-derived; the pre-existing
nonce-rejection branch is observed in `bn::rand` (class C). No context anywhere
in the stack contains a P-256 engine frame, let alone originates in one, so no
secret-derived transfer is attributed to the new carrier. The sensitivity
control still reports four engine-on-path contexts on the P-256 ladder, so the
zero is not vacuous. ctgrind does not prove constant time, and a branchless path
produces no context either way; the structural argument and the binary audit
below carry the rest.

**Binary branch audit** (`audit/AUDIT.md`, `audit/raw/`) — seven targets resolved
uniquely with complete disassembly, plus the two bodies the shared exact-pointer
rule cannot name (`P256Scalar::to_canonical`, `ossl_ec_group_do_inverse_ord`)
disassembled by symbol range:

* `P256Scalar::invert`: **2 jcc, 0 cmov, 0 setcc**. Both are the public schedule:
  the fixed 256-iteration counter and the `bt %rcx,%rax` test of the constant
  `n-2` limb loaded from read-only data.
* `try_inverse_order`: **10 jcc, 1 cmov, 0 setcc**. All on pointer nullness, the
  `admits` result, `neg`, the limb count `<= 4`, `Vec` capacity/len and the
  `copy_from_slice` loop counter; the single `cmovne` is in that copy loop.
* `from_canonical_reduced`: **0 jcc, 0 cmov, 0 setcc**; `to_canonical` (manual):
  none; `ossl_ec_group_do_inverse_ord` (manual): 15 jcc and 1 `setne`, all on the
  method-column nullness, `mont_data`, allocation/return tags and the `ctx` stack
  counter — public ABI/dispatch metadata, no limb value.
* Shared, previously audited carriers on the path: `mont_reduce_into` (2 jcc,
  2 setcc), `wide_mul_x86` (9 setcc), `normalise_branchless` (5 jcc, 5 cmov),
  `store_coordinate` (10 jcc, 5 cmov) — all on lengths/capacities, not values.

Every `jcc`/`setcc`/`cmov` in the new carrier is therefore classified
public-bound; none reads a secret limb.

## 5. Timing — what the bound predicted versus what was measured

`timing-4e6ec312/` (the PFP-3 harness, analyser, 15 balanced repetitions,
`taskset -c 1`, median of paired ratios, percentile bootstrap), candidate
`4e6ec312` against authority `611e511d`:

| workload | candidate µs | authority µs | ratio | 95 % CI |
|---|---:|---:|---:|---:|
| `ecdsa256` | 130.957 | 12.752 | **10.28×** | **[10.26, 10.31]** |

The previous (PFP-3) result at `ecbefb7d` was **10.58× [10.55, 10.62]**
(candidate 134.485 µs). Replacing the inversion therefore improved `ecdsa256`
by **0.30×** (candidate ~3.5 µs, 2.6 %), and the ratio is outside the old
interval.

**Shortfall, stated plainly.** The bound's realistic expectation for this change
was ≈9.9× (halving the inversion), and its absolute ceiling for a complete
inversion elimination was 9.24×; the task's reference figure was about 9.1×.
**10.28× misses all three.** The measured decomposition explains it: the new
inverse costs roughly 14 µs, not the ~7 µs the design extrapolated from the
*field* inverse's 7.34 % callgrind share. `P256Scalar` uses the portable
`Mont<OrderDomain>` schoolbook/REDC kernel (425 operations), not the `Arch`
ADX kernel, and the generic fixed-top ladder it replaces costs only ~17 µs, so
the attainable saving is ~3 µs, not ~10 µs. The design's inference from
instruction share to wall time did not hold; this record does not claim
otherwise. The pipeline conversion remains refused by the bound (0.45 %), and
`k·G` remains the frontier.

## 6. Decision

**DONE** by the stated PFP-4 criteria: the inversion is replaced, the branch
audit is clean and every correctness gate passes at one candidate digest. The
timing result is recorded as an improvement that falls short of the bound, not
as a victory. The pipeline conversion stays refused; `k·G` is unchanged.
