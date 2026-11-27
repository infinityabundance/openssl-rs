# PFP-43 — bounds, the width decision, and the proposed PFP-45

This document states the two admissible repairs for the refusal at
`src/bn/arith.rs:2486-2497` (before), their iteration counts and cost, the
decision taken, and the declassification each would require. The measurement
and identity are in [`RECEIPT.md`](RECEIPT.md).

**A is implemented. B is not implemented and is proposed as PFP-45 (text
only).**

---

## 1. The refusal, and what "the exponent" is

`DH_generate_key` with a caller-supplied private key calls
`ossl_dh_generate_public_key` → the method table's `bn_mod_exp` =
`dh_bn_mod_exp` (`src/dh/key.rs:411`) → `bn_mod_exp_mont_policy`
(`src/bn/mont.rs:881`). `dh_policy_limbs` (`src/dh/key.rs:443`) supplies the
group's declared bound: `dh->length`, else the named group's RFC 7919 key
length, in 64-bit limbs.

For the court's `long_2400bit` preset, `x = int("ab" * 300, 16)` is 2400 bits =
38 limbs. Against the 2048-bit `ffdhe2048` / `modp2048` moduli (32 limbs):

| quantity | value |
|---|---:|
| exponent limbs `pd.len()` | 38 |
| modulus limbs `md.len()` | 32 |
| group policy (`ffdhe2048`, 225 bits) | 4 |
| exponent bits | 2400 |

The old code clamped the width to the modulus (`32`) and then refused because
`38 > 32`, so it returned `None`, `DH_generate_key` returned 0, and no public
key was written. The authority scans all 2400 exponent bits and returns
`g^x mod p`.

## 2. Candidate A — widen the ladder to cover the exponent (implemented)

### 2.1 Mechanism

Bind the width **once**, before the ladder:

```
width = (policy == 0 ? md.len() : min(policy, md.len())).max(pd.len())
```

* in policy (`pd.len() <= policy <= md.len()`): `width == policy` — the PFP-8
  schedule, computationally identical;
* policy wider than the modulus: still clamped to `md.len()` unless the
  exponent itself needs more;
* out of policy (and, for 2048-bit moduli, wider than the modulus):
  `width == pd.len()`, so the ladder covers every exponent limb.

`resolved_width == 0` keeps the old "no declaration" sentinel (delegate to the
modulus-width entry point). `pd.len() > resolved_width` remains a defensive
refusal, unreachable from the resolver.

### 2.2 Iteration count and cost

| path | width | iterations | measured |
|---|---:|---:|---:|
| conforming `ffdhe2048` key | 4 | 256 | PFP-8 baseline |
| 2400-bit key, 2048-bit modulus | 38 | 2432 | 2971–3046 µs |
| authority, same key | — | ~2048 bit steps | 1416–1448 µs |

The task's prior reference point — the 2039-bit modulus-width fallback — was
2455.9 µs against the authority's 1220.6 µs, i.e. ≈2.0×. The widened path is
2432 iterations at a ladder that PFP-8 measured at ≈1.99× the authority per
equal-length operation; measured **2.08–2.09×** the authority.

**A repairs compatibility. It does not win the row**, and this document does not
claim otherwise.

### 2.3 Declassification

The width depends on `pd.len()` — the private exponent's normalised **limb
count**, a length, never a limb value. This was already read by the old code as
the admission decision; A moves it to a single point, `resolve_ladder_width`
(`src/bn/arith.rs:2455`), called at `src/bn/mont.rs:970`, and makes the ladder
interior width-only.

Threat model: for a conforming key there is no new channel (width == policy).
For an out-of-policy key — a configuration the caller chose — the operation's
duration reveals at most the key's limb count to a timing observer. No secret
value changes the schedule. Accepted; ctgrind and a branch audit are **not run**
in this batch, so no constant-time claim is made.

---

## 3. Candidate B — reduce the secret exponent mod the subgroup order (proposed)

### 3.1 Argument

For a group where `g` has order dividing `q`, `g^q ≡ 1 (mod p)`, so

```
g^x ≡ g^(x mod q) (mod p).
```

For the safe-prime named groups (ffdhe*, modp*), `q = (p-1)/2` and `g = 2`
generates the order-`q` subgroup, so the reduction is exact. `x mod q` is at
most `len(q)` bits: 256 bits = 4 limbs for ffdhe2048, i.e. the same 256
iterations as the conforming policy path.

### 3.2 Gate (public, and must be explicit)

The reduction is correct **only** if `ord(g) | q`. It must be gated by a public
predicate, not assumed:

* a one-time `g^q mod p == 1` check — exactly the check `DH_check` already
  performs (`src/dh/check.rs:333-339`); or
* a named-group whitelist whose `q` is the RFC 7919/5114 order.

For a caller-supplied explicit group the gate must run before any reduction;
if it fails, the code must fall back to A (or refuse), **never silently
reduce**. The gate result is public configuration and may be cached on the key
object.

### 3.3 Cost

| path | limbs | iterations | projected |
|---|---:|---:|---:|
| B, `x mod q` over ffdhe2048 | 4 | 256 | ≈344 µs (PFP-8 256-iteration figure) |
| A, widened | 38 | 2432 | 2971 µs |
| authority | — | ~2048 | 1419 µs |

Projected ≈0.24× the authority and ≈8.6× faster than A; the projection is not a
measurement and must be re-run.

### 3.4 What B adds

* a new **constant-time variable-width secret reduction** `x mod q` — the
  schedule must depend only on public geometry (`q`'s limb count), not on `x`;
  a fixed-iteration Montgomery/Barrett reduction, not a division;
* the reduced exponent's length is a function of `q` (public), so the ladder
  width becomes the policy width again and the covering-width fallback is
  deleted;
* it does not remove A's declassification by itself — it makes the width
  independent of `x` for gated groups, and the gate is what earns that.

### 3.5 Proposed PFP-45 text (for the TODO ledger, not applied here)

> **PFP-45 — reduce the DH secret exponent modulo the subgroup order.** With A
> landed, an out-of-policy key is computed but at 2432 iterations (≈2.09× the
> authority). Because `g^q ≡ 1 (mod p)` for every group where `ord(g) | q`, the
> exponent can be reduced to `x mod q` before the ladder: 4 limbs / 256
> iterations for ffdhe2048, projected ≈344 µs (≈0.24× the authority) and ≈8.6×
> faster than A, and it deletes the covering-width fallback. Acceptance:
> (1) a *public* gate that `ord(g) | q` — the existing `g^q mod p == 1` check or
> a named-group whitelist — runs before any reduction and falls back to A (never
> silently reduces) when it fails; (2) a constant-time variable-width
> `x mod q` whose schedule depends only on `q`'s public limb count; (3) the
> reduced width is the policy width, independent of `x`; (4) timing measured and
> a constant-time claim supported by a branch audit and ctgrind, not by source
> inspection. **Do not implement until the gate and the constant-time reduction
> are both proved; a wrong gate changes the key, which is worse than a slow
> correct one.**

---

## 4. Residual obligation and where the length classification lives

| item | location / state |
|---|---|
| width classification | `resolve_ladder_width`, `src/bn/arith.rs:2455` |
| single call site | `bn_mod_exp_mont_impl`, `src/bn/mont.rs:970` |
| policy function | `mod_exp_core_consttime_policy`, `src/bn/arith.rs:2494` — no width derivation from `pd` |
| residual channel | exponent limb count for out-of-policy keys (`PFP43-LENGTH-DECLASSIFICATION`, OPEN) |
| retained deviation | `BN_mod_exp_mont_consttime` still refuses a wider exponent (`PFP43-CONSTTIME-API`, OPEN) |
| object-field option | rejected: `Dh` is `#[repr(C)]`, 208-byte asserted layout (`PFP43-DH-FIELD`, RESOLVED) |

## 5. Decision

**Implement A only.** A is a bounded compatibility repair with a single, named
declassification and a measured cost that does not win the row. B is a real
optimisation but needs a correctness gate and a new constant-time reduction;
it is recorded, with its gate and cost, as PFP-45 and not implemented.
