# PFP-3 — DSO-level ctgrind at `04611380…`

**Result: STOP.** The fixed-base path carries **one secret-derived conditional
transfer**: a `je` at `ossl_ec_wNAF_mul+0x1938` (file vaddr `0x242138`) whose
condition is the `ct_ge(k, n)` admission check. Engine-on-path contexts are 0
and engine-origin contexts are 0, but that is *not* a clean result: the branch
is in the fixed-base code inlined into the `ec::mult` driver, so the classifier
attributes its frame to `ossl_ec_wNAF_mul`, not to a `::ec::p256::` frame.

## Harness and populations

The harness is `pfp3_dso_ct.c` (`ea18ec93…`, binary `5840dbd5…`): the PFP-21
source with the taint verification, loader identity (`LOADED`/`MAPS`/`FOREIGN`
against `stat(2)`), negative control and every existing population unchanged,
plus **one** population:

* `mul-g-fixed` — `EC_POINT_mul(group, r, k, NULL, NULL, ctx)`, the call form
  `ossl_ec_wNAF_mul` enters the fixed-base arm from (`scalar != NULL`,
  `num == 0`). The four limb *values* of `k` are marked undefined exactly as in
  `mul-g`; the length and `neg` metadata stay defined.

Why the added population is required: the PFP-21 `mul-g`/`mul-p` populations use
the **variable-base** form (`EC_POINT_mul(…, NULL, point, k, …)`); they cannot
reach `try_fixed_base_mul`. `sign` reaches the comb (through
`ecdsa_sign_setup`'s `k·G`) but taints only `d`, not the library-generated
nonce. No existing population taints the scalar *and* takes the fixed-base form.

The classifier is `PFP-2/ctgrind/repro-2026-11-26/attribute.py`, unchanged.

Three repetitions per tainted population, one control; `valgrind-3.19.0
memcheck --num-callers=24`.

## Populations at `04611380` (candidate)

| population | errors per rep | contexts per rep | engine-on-path | engine-origin |
|---|---|---|---|---|
| `control` (negative) | 0 | 0 | 0 | 0 |
| `mul-g` (variable base) | 3621 / 3606 / 3670 | 200 / 197 / 233 | 0 | 0 |
| `mul-p` | 3660 / 3621 / 3635 | 228 / 201 / 217 | 0 | 0 |
| **`mul-g-fixed`** | **1 / 1 / 1** | **1 / 1 / 1** | **0** | **0** |
| `mul-g-bytes` | 3632 / 3597 / 3646 | 209 / 186 / 225 | 0 | 0 |
| `sign` | 123 / 123 / 123 | 120 / 120 / 120 | 0 | 0 |
| `sign-ex` | 24 / 24 / 24 | 24 / 24 / 24 | 0 | 0 |
| `sign-ex-k` | 33017 / 32968 / 33017 | 450 / 417 / 449 | 0 | 0 |

The `mul-g`/`mul-p` residue is the pre-existing generic `BIGNUM`/ladder traffic
(origins `BN_nnmod`, `limbs::divide_fallible`, `limbs::mul_fallible`, …), not the
engine. `mul-g-fixed` reduces that to a single context because the comb keeps
the scalar in registers and fixed-width field kernels.

## The one context, and why it is a STOP

```
Conditional jump or move depends on uninitialised value(s)
   at 0x507C138: openssl_rs::ec::mult::ossl_ec_wNAF_mul
   ...
 Uninitialised value was created by a client request
   at mark_bn_values (pfp3_dso_ct.c)
```

Base from the same process: `dli_fbase=0x4e3a000`; so the instruction is at
file vaddr `0x242138` = `ossl_ec_wNAF_mul+0x1938`, inside the function's
`0x1c37`-byte extent. Disassembly:

```
242135: f6 c1 01        test   $0x1,%cl
242138: 0f 84 e0 e9 ff ff je     240b1e <ossl_ec_wNAF_mul+0x31e>
```

The preceding `sar`/`shld`/`adc` sequence is a 256-bit comparison against the
order's top limb; `cl`'s low bit is the `ct_ge(k, ORDER_MODULUS)` result. The
source is `src/ec/p256/fixed_base.rs`:

```rust
if ct_ge(&k, &ORDER_MODULUS) != 0 {
    return None;
}
```

`ct_ge` is branchless, but its **result** is secret-derived and the `return None`
is a conditional jump on it. This is a secret-dependent early exit: for the
admitted population it is always not-taken, but the control flow is a function
of the secret scalar. It is not one of the three targets `TAINT-AUDIT.md`
enumerated (those are metadata/ladder/write-back), which is exactly why the
audit was mandatory. **A secret-derived conditional transfer is a STOP.**

## Sensitivity control (the instrument sees engine code)

`mul-g-fixed` on the pre-PFP-20 artefact `83f67826` (same call shape, same
taint, old ladder): **engine-on-path = 4 per repetition** (187/199/198
contexts), so this harness on this call shape does see engine code. It predates
the comb and therefore cannot exercise the new carrier; that limit is stated,
not papered over. The mutation control (`../mutation/MUTATION.md`) separately
proves the comb — not a ladder fallback — executes on the candidate.

## Identity

Candidate `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`,
rebuilt from clean commit `289f111877ce7aa9a9a76d25bf76357f57ed6582`. Every
run checked `LOADED` realpath/dev/ino/size against `stat(2)` and `FOREIGN
libcrypto=0`; both digests were re-checked after the run. Records:
`raw/run-meta.env`, `raw/valgrind-exits.tsv`, `raw/record.txt`,
`raw/ctgrind-record.json`, `attrib/`.
