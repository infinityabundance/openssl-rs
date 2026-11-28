# PFP-52 — the DH ladder width is bound at ingestion (verdict: CONFIRMED, in our favour)

```yaml
task:            PFP-52
subject:         does the authority re-derive the constant-time schedule per call
verdict:         CONFIRMED — a security divergence in our favour, not retracted
source_identity: HEAD c1a100a8 (branch staging), worktree uncommitted
src_fingerprint: 47b0ee362fa36f538c029325f1a7d40dfd03e2f215f8031b6f8d6e6a3042ff74
authority:       forensics/authorities/src/openssl-3.6.4
candidate_dso:   5b52e4736a7c5bb23f6cf0e3962cfd333ad941a6e62aa7a9033712c0ea50e65c
```

## 1. The authority re-derives the schedule from mutable object state

The chain, with the pinned authority's own coordinates:

| file:line | what it establishes |
|---|---|
| `crypto/dh/dh_lib.c:267-276` | `DH_set0_key` stores the caller's `priv_key` **pointer** (`dh->priv_key = priv_key`); it does not copy the `BIGNUM`. |
| `crypto/dh/dh_key.c:85-87` | `DH_compute_key` calls `dh->meth->bn_mod_exp(dh, z, pub_key, dh->priv_key, dh->params.p, ctx)`, i.e. the stored pointer, on every call. |
| `crypto/bn/bn_exp.c:1146-1154` | `BN_mod_exp_mont_consttime` forwards to `bn_mod_exp_mont_fixed_top`. |
| `crypto/bn/bn_exp.c:626` | `top = m->top;` (the modulus). |
| `crypto/bn/bn_exp.c:633-637` | `/* Use all bits stored in \|p\| ... */ bits = p->top * BN_BITS2;` — the ladder length is the **exponent's `top` at call time**. |
| `crypto/bn/bn_lib.c:414-424` | `BN_set_word` writes `a->top = (w ? 1 : 0)`. Any caller that still points at the `BIGNUM` can therefore change the next call's schedule. |

`p` is `const BIGNUM *` in C, but that only constrains `BN_mod_exp_mont_consttime`; it does not stop the object's owner from mutating the object between calls. No copy is taken by `DH_set0_key`.

## 2. Concrete counterexample

Install a 2048-bit private exponent (`top = 32`) with `DH_set0_key(dh, NULL, priv)`:

* first `DH_compute_key`: authority `bits = 32 * 64 = 2048` iterations;
* caller retains `priv` and calls `BN_set_word(priv, 1)` (`top` becomes 1; the same object is `dh->priv_key`);
* second `DH_compute_key`: authority `bits = 1 * 64 = 64` iterations.

The same DH object, on the same stored pointer, chooses a 32x shorter constant-time schedule purely from caller-mutable object state.

## 3. Our behaviour (strictly stronger)

* `DH_set0_key` captures `priv_limbs` once, from the slot it actually holds
  (`src/dh/object.rs:701-709`).
* `dh_bn_mod_exp` reads that stored count, never a per-call length read
  (`src/dh/key.rs:420-438`).
* `resolve_ladder_width(policy, md.len(), stored)` returns
  `max(policy, modulus, stored)` (`src/bn/arith.rs:2523-2534`).
* The ladder kernel consults no exponent metadata after staging
  (`src/bn/arith.rs:2563-2597`, `2622-2637`).

For the counterexample, our resolved width is `max(4, 32, 32) = 32` on **both**
calls: 2048 iterations before and after the mutation. The mutated *value* is
still honoured (the second result is `peer_pub^1 mod p`), so this is a schedule
binding, not a stale-value cache.

## 4. Test proving it

`src/dh/key.rs::tests::mutating_the_exponent_after_set0_key_cannot_change_the_resolved_schedule`

* installs 256 bytes of `0xab` (2048 bits, 32 limbs);
* asserts `priv_limbs == 32` and the first `DH_compute_key` ladder is `[2048]`;
* calls `BN_set_word(priv_key, 1)` through the retained pointer;
* asserts `priv_limbs` is still 32, the second ladder is still `[2048]`, the
  variable-time core is not entered, and the returned shared secret equals the
  padded peer public key (the mutated value is used).

The observation is the deterministic iteration count, not wall-clock.
Supporting arm tests: `src/bn/mont.rs::tests::ladder_width_arms_resolve_to_pinned_iteration_counts`
(`Policy` in-policy = 256, out-of-policy = 2432) and
`src/dh/key.rs::tests::a_conforming_dh_private_key_runs_the_policy_width` (256).

## 5. Result

CONFIRMED. The claim is evidence, not rhetoric: the authority's schedule is a
per-call function of `p->top` (`bn_exp.c:637`), reachable through the pointer
`DH_set0_key` stores, and ours is fixed from the ingestion-bound length. No
retraction; no OpenSSL compatibility is lost for any call that does not mutate a
handed-over exponent underneath a live DH object.
