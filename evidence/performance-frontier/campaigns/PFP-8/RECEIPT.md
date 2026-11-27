# PFP-8 receipt — DH prepared-group optimisation (measured refusal)

```yaml
task_id:            PFP-8
title:              DH prepared-group (generator-table) optimisation
phase:              performance frontier
stage_branch:       staging (this batch is forbidden to commit/push)
source_identity:
  source_sha:       b2cca665bea652c2c821205d516b28f3277f4ed1
  src_tree:         05a4a56b7a4b2db3cee76e8db37fa286f1cd89d9
  arith_sha256:     b548ee1533f527366099d95b907bd20237bbcc2e8208966eb9a15cf11f09809f
  candidate_dso:    88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87
  candidate_archive: 2ec133ca3fc74f4ca0c0b93a68a0d769679f8b63e9ddac3ca8383c7feb9dff93
  repro:             two fresh CARGO_TARGET_DIR builds agree byte for byte (build/variants.txt)
authority:
  dso_sha256:       611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
  source:           forensics/authorities/src/openssl-3.6.4
decision:           REFUSE — no source changed
```

## 1. Bound and arithmetic

The profile at `88c0c7e0` (callgrind, `ffdhe2048`, 2,491 CIOS calls per
exponentiation, 21,186 Ir/call) puts the per-call table build at **1.19 %** of
the exponentiation (635,580 / 53,334,930 Ir; 30 of 2,491 calls). A generator
table can only move that build, and only for key generation. For `w = 5, 6, 7, 8`
the precompute share is 1.18 %, 2.42 %, 4.77 %, 8.89 %; the best prepared window
(`w = 6`) is 2.21 % faster than the admitted `w = 5` baseline, and `w = 8` is
2.02 % *slower* because the masked scan grows. The shared secret's base is the
peer's public value, so no generator table can be reused: **0 %**. The DH-exchange
bound is about 0.6 %. Every figure is below the 10 % threshold, so the item is a
measured refusal. A positional comb would help key generation only; its build and
footprint are recorded in `BOUND.md` §4 and it is not implemented.

## 2. Change

No `src/` change. No prepared table, no comb, no generator-2 doubling. The
worktree `src` is exactly `b2cca665`; the DSO is the M-A1 artefact.

## 3. Unsafe accounting

| category | content |
|---|---|
| eliminated | none (no source change) |
| relocated | none |
| hidden | **0** |
| removed / introduced | 0 / 0 unsafe ops |

## 4. Compatibility

| check | result |
|---|---|
| shared secret vs authority, 3 groups × 2 exponent widths | 6/6 identical |
| shared secret, named vs explicitly-loaded group | 6/6 identical |
| key generation cross-verified through `g^priv` | 6/6 identical |
| malformed-peer return codes (7 values × 3 groups) | 21/21 identical |
| **keygen with a caller-supplied private key** | **STOP: `PFP8-KEYGEN-PRESET-PRIV`** |

`PFP8-KEYGEN-PRESET-PRIV`: the candidate returns 0 and computes no public key for
a `DH_generate_key` on a caller-supplied `priv_key`; the authority returns 0 and
computes it. Cause recorded in `DIFFERENTIAL.md`; pre-existing, not repaired in
this refusal batch.

## 5. Safety evidence

| check | result |
|---|---|
| ctgrind, secret exponent tainted | **0 errors / 0 contexts**, origins none; control 4/1 |
| `mont_mul_ladder_into` audit | 40 jcc public; 64 setcc class-b carry/borrow consumed arithmetically; 0 cmovcc; **0 secret-derived** |
| `run_mont_ladder` audit | 97 jcc public; 15 setcc (14 public, 1 `bt` secret-bit → `setb` data); 2 public cmovcc; **0 secret-derived** |
| Miri / sanitizers / Kani | NOT_RUN (no ownership, alias or unsafe change) |

Neither instrument is a constant-time proof; the audit is a review aid.

## 6. Predicted versus measured

| quantity | predicted | measured |
|---|---:|---:|
| table-build share | 1.19 % | 1.19 % |
| best prepared-window improvement | 2.21 % (`w = 6`) | not implemented (refusal) |
| shared-secret improvement | 0 % | 0 % (1.9876×, unchanged) |

## 7. Timing at one digest

| workload | cand/auth | cand/prev |
|---|---:|---:|
| keygen, `ffdhe2048` | **14.8226× [14.4048, 14.9716]** | 0.9811 [0.9757, 0.9937] |
| shared secret, 2048-bit exponent | **1.9876× [1.9514, 2.0940]** | 0.9833 [0.9715, 0.9880] |
| shared secret, 225-bit exponent | **14.0395× [13.7525, 14.4492]** | 0.9787 [0.9680, 0.9906] |

The recorded 2.02× is inside the shared-secret interval. The 14× rows are the
fixed-width ladder policy (`PFP8-WIDTH-POLICY`), not this item's removable cost.

## 8. Repository gates

| gate | result |
|---|---|
| `cargo test --lib -- dh` | 77 passed, 0 failed, 2 ignored |
| full `cargo test --lib` | 2,493 passed, 0 failed, 54 ignored |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

## 9. Row state and arms

* `docs/PERFORMANCE-FRONTIER-TODO.md` PFP-8: **DONE (measured refusal)** — the
  bound did not support the change, the arithmetic is recorded, and the STOP
  finding is named.
* `evidence/performance-frontier/admission/ARMS.json`: PFP-8 added as
  **`EXPERIMENT`** (a refused optimisation with no candidate change), with open
  obligations `PFP8-REFUSED-TABLE-BUILD`, `PFP8-KEYGEN-PRESET-PRIV`,
  `PFP8-WIDTH-POLICY`, `PFP8-SAFE-COMPATIBLE`.

## 10. What this receipt does not establish

* It is not a frontier result: one venue, no PMU.
* It does not establish constant-time behaviour; ctgrind is source-bound and the
  audit is a review aid.
* It does not repair `PFP8-KEYGEN-PRESET-PRIV` or `PFP8-WIDTH-POLICY`.
* It asserts no `SAFE_COMPATIBLE` graduation.
