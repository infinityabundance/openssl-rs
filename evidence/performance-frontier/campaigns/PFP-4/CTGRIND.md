# PFP-4 — DSO-level ctgrind on signing with the private scalar and nonce tainted

**Result.** The new order-inverse carrier contributes **zero** secret-derived
contexts. The instrument is live (the sensitivity control reports engine code),
and the tainted nonce demonstrably reaches the signing path (the pre-existing
nonce-rejection branch in `bn::rand` is observed). ctgrind is a taint run, not
a constant-time proof; a branchless path emits no context in either direction,
so the source schedule argument and the binary audit in
[`../AUDIT.md`](../AUDIT.md) carry the positive claim.

## Subjects

| subject | DSO SHA-256 |
|---|---|
| candidate (PFP-4) | `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77` |
| before (PFP-3, generic order inverse) | `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` |
| sensitivity (pre-PFP-20, old ladder) | `83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f` |

Harness `pfp4_dso_ct.c` (PFP-3's harness plus one population); valgrind
`3.19.0 memcheck --num-callers=24`; three repetitions per tainted population,
one control; every run proves `LOADED` realpath/dev/ino/size against `stat(2)`
and `FOREIGN libcrypto=0`; both digests re-checked after the run.

## Populations

* `control` — no taint. Negative control: **0 errors** on both subjects.
* `sign` — the private scalar `d`'s four limb **values** are marked undefined
  (the PFP-3 `mark_bn_values`, layout-verified against the BIGNUM's own export).
* `sign-nonce` — `d` tainted **and** the installed deterministic `RAND_METHOD`
  marks its output undefined after filling it. The library's own
  hash-to-nonce chain (`ossl_bn_gen_dsa_nonce_fixed_top`), the generated `k` and
  the input to `ec_field_inverse_mod_ord` are therefore all secret-derived.

## Counts

| subject / mode | errors per rep | contexts | engine-on-path | origin-in-engine |
|---|---|---:|---:|---:|
| candidate `control` | 0 | 0 | 0 | 0 |
| candidate `sign` | 123 | 120 | 0 | 0 |
| candidate `sign-nonce` | 123 | 120 | **0** | **0** |
| before `sign` | 122 | 119 | 0 | 0 |
| before `sign-nonce` | 122 | 119 | 0 | 0 |
| sensitivity `mul-g-fixed` | 1605 / 1605 / 1615 | 196 / 198 / 207 | **4 / 4 / 4** | 0 |

`engine-on-path` is the PFP-2 classifier's "a `::ec::p256::` frame appears
anywhere in the stack"; `origin-in-engine` is the top frame being P-256 code.
Both are zero for every candidate signing run. The `sign-nonce` contexts
originate in the pre-existing generic nonce generation (most commonly
`bn::rand::ossl_bn_gen_dsa_nonce_fixed_top` and the generic `BIGNUM` helpers),
which is class C in the classifier and is unchanged by PFP-4.

## What this does and does not show

* It shows that tainting the nonce source is observable in the nonce
  generation, so the nonce is tainted at the point the inverse consumes it, and
  that no P-256 engine frame then appears in any context.
* The RAND-then-hash path keeps the nonce's limb **count** defined (the generator
  pins the top byte to `0xff`), so the admission's `neg`/limb-count branches are
  on defined metadata, not tainted values — the same convention PFP-3 uses.
* It does **not** prove constant time: Memcheck cannot distinguish a `cmov` from
  a branch, and a branchless path produces no context. The two-branch schedule
  and the public exponent test are established by the disassembly in
  [`../AUDIT.md`](../AUDIT.md).
* The sensitivity control exercises the P-256 ladder (`mul-g-fixed`), not the new
  inverse. It proves the classifier recognises P-256 engine frames, so the
  zero on the inverse is not vacuous at the level of the instrument. A dedicated
  branchy-inverse mutant was not built; that is recorded as a limitation.

Raw records: `raw/valgrind-exits.tsv`, `raw/engine-origins.tsv`,
`raw/attrib-summary.jsonl`, `attrib/*.summary.json`, `raw/run-meta.env`.
