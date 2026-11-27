# PFP-3 — constant-time taint and binary branch audit at `04611380…`

**Status: STOP.** Both instruments now exist at the digest and both find the
same defect: the fixed-base admission contains **one secret-derived conditional
transfer**. The PFP-3 row cannot be `DONE` and the arm cannot be `CANDIDATE`
until it is removed or shown not to depend on the secret in the admitted
population.

## The finding

`src/ec/p256/fixed_base.rs`, `try_fixed_base_mul`:

```rust
if ct_ge(&k, &ORDER_MODULUS) != 0 {
    return None;
}
```

`ct_ge` is branchless, but its result is a function of the secret scalar `k`,
and `return None` is a conditional jump on it. In the release DSO the
instruction is `je` at `ossl_ec_wNAF_mul+0x1938` (file vaddr `0x242138`,
condition `test $0x1,%cl`); `try_fixed_base_mul` is inlined into the `ec::mult`
driver, so the frame is named `ossl_ec_wNAF_mul`, not a `::ec::p256::` frame.

* ctgrind (`mul-g-fixed`, four limb values of `k` tainted): **1 context per
  repetition**, `Conditional jump or move depends on uninitialised value(s)`,
  origins attributed by `--track-origins=yes` to the harness's `mark_bn_values`
  taint. engine-on-path 0, engine-origin 0 — the fixed-base code is inlined,
  so the classifier's frame is the driver.
* branch audit: the exact same `je` is in the carrier rows; the RCB add/double
  and comb carriers have **0 secret-derived jcc** (see below).
* mutation control: the comb is load-bearing (2.05× instructions, 1.96× wall
  versus the admission-off fallback), so this is not a dead-code artefact.

For the admitted population (`k < n`, always true for a generated nonce) the
branch is never taken, so the observable leak is the (always-false) predicate,
not the scalar bits. That does not make it a constant-time path: the task and
the standing standard forbid a secret-dependent early exit, so it is recorded as
a STOP rather than argued away.

## The rest of the new code is branch-bound in public data

| carrier | jcc | cmov | setcc | classification |
|---|---:|---:|---:|---|
| `rcb_add` | 0 | 0 | 40 | branch-free; setcc are carry/borrow masks |
| `table_mul` (comb) | 2 | 0 | 2 | fixed loop counters |
| `to_affine` (invert) | 2 | 0 | 0 | loop + public exponent bit |
| `build_table` | 1 | 0 | 0 | public table loop |
| `advance` | 1 | 0 | 0 | public doubling loop |

The single secret-derived transfer is enumerated above. The audit's shared
inventory resolves 31/31 and exits 0; the five generic carriers are admitted by
an exact-symbol driver that imports the auditor's own disassembler and
byte-coverage check (see `audit/AUDIT.md`).

## PFP-3's three original audit targets, now answered at the artefact

1. **Scalar-metadata admission branch** — `neg` and `d.len()` are not tainted
   by the harness and are read from the `BIGNUM` header; the audit shows no
   tainted branch from them. **Resolved public-bound.**
2. **If-conversion of the masked select** — `table_mul` has 2 jcc (loop
   counters); `rcb_add` has 0 jcc; the mask fold is not lowered to a branch.
   **Resolved branch-free.**
3. **Fixed-size write-back** — `to_affine` is 2 public jcc; `store_coordinate`
   does not appear as a secret-dependent context. **Resolved.**

The one item those three did not name is the `ct_ge` range check — the audit
found it.

## What remains before a pass

Remove the secret-dependent admission early exit, or establish that the branch
predicate is independent of the secret for the admitted population without
branching on a secret-derived value (e.g. move the in-range requirement to a
caller that already classifies it as public validity input). That is a `src/`
change and is out of scope for this verification batch; the defect is reported,
not repaired. Evidence: `ctgrind/pfp3-2026-11-27/CTGRIND.md`,
`audit/AUDIT.md`, `mutation/MUTATION.md`.
