# PFP-3 — DSO-level ctgrind after the branch-free admission

**Result: PASS on the constant-time conjunct.** The fixed-base path carries
**zero** secret-derived contexts. The pre-fix artefact reported exactly one
(`je` at `ossl_ec_wNAF_mul+0x1938`, the `ct_ge(k, n)` admission early exit).
The instrument, the harness source, the taint populations and the attribution
classifier are unchanged; only the candidate digest and the fixed-base admission
changed.

## Harness and populations

Identical to `../pfp3-2026-11-27/`: `pfp3_dso_ct.c` source
`ea18ec93bb961328d6c268b4fc1307e0489c01ea62f0a1c33ba962fafa85771d`, rebuilt in
the court to binary `c89d64d892b941e8d148b9662e2adc6781e054adb8bda637914c95820d5fb732`,
the PFP-21 taint verification, loader identity (`LOADED`/`MAPS`/`FOREIGN` against
`stat(2)`), negative control, the eight populations and the PFP-2 attribution
classifier unchanged. `valgrind-3.19.0 memcheck --num-callers=24`; three
repetitions per tainted population, one control.

`mul-g-fixed` is `EC_POINT_mul(group, r, k, NULL, NULL, ctx)` with the four limb
*values* of `k` marked undefined and the length/`neg` metadata defined — the same
population and taint as the pre-fix record.

## Populations at `ecbefb7d` (candidate)

| population | errors per rep | contexts per rep | engine-on-path | engine-origin |
|---|---|---|---|---|
| `control` (negative) | 0 | 0 | 0 | 0 |
| `mul-g` (variable base) | 3645 / 3631 / 3606 | 225 / 209 / 196 | 0 | 0 |
| `mul-p` | 3596 / 3606 / 3670 | 186 / 197 / 236 | 0 | 0 |
| **`mul-g-fixed`** | **0 / 0 / 0** | **0 / 0 / 0** | **0** | **0** |
| `mul-g-bytes` | 3661 / 3636 / 3607 | 228 / 216 / 197 | 0 | 0 |
| `sign` | 122 / 122 / 122 | 119 / 119 / 119 | 0 | 0 |
| `sign-ex` | 24 / 24 / 24 | 24 / 24 / 24 | 0 | 0 |
| `sign-ex-k` | 33042 / 33007 / 32978 | 460 / 442 / 427 | 0 | 0 |

The `mul-g`/`mul-p` residue is the same pre-existing generic `BIGNUM`/ladder
traffic as before (origins `BN_nnmod`, `limbs::divide_fallible`,
`limbs::mul_fallible`, …), not the fixed-base engine. `mul-g-fixed` collapses to
zero because the comb keeps the scalar in registers and the admission is now a
masked select, not a branch.

## Before / after on the same population

| artefact | `mul-g-fixed` errors | contexts | secret-derived transfer |
|---|---|---:|---|
| `04611380` (pre-fix) | 1 / 1 / 1 | 1 / 1 / 1 | `je` at `wNAF+0x1938`, `ct_ge(k,n)` |
| **`ecbefb7d` (post-fix)** | **0 / 0 / 0** | **0 / 0 / 0** | **none** |

## Sensitivity control (the instrument still sees engine code)

`mul-g-fixed` on the pre-PFP-20 artefact `83f67826` (same call shape, same taint,
old ladder): errors 1595 / 1615 / 1615, contexts 187 / 206 / 204,
**engine-on-path = 4 per repetition**. The harness therefore still reports
engine code on this call shape, so the zero on the candidate is not vacuous.

## Identity

Candidate `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053`,
rebuilt from `staging` `f8d5c4b33cf751a0dd805fa7cf0d730915e1d073` with the
uncommitted `src/ec/p256/fixed_base.rs` branch-free admission; two fresh-target
builds reproduce the DSO. Every run checked `LOADED` realpath/dev/ino/size
against `stat(2)` and `FOREIGN libcrypto=0`; both digests were re-checked after
the run. Records: `raw/run-meta.env`, `raw/valgrind-exits.tsv`, `raw/record.txt`,
`raw/ctgrind-record.json`, `attrib/`.
