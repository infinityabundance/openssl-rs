# PFP-3 conversion receipt

- **Source identity.** `staging` commit
  `289f111877ce7aa9a9a76d25bf76357f57ed6582`, tree `11a5d18f…`, clean
  (`build_relevant_status` empty). `src/**/*.rs` fingerprint
  `ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a`
  (887 files), unchanged before and after the rebuild.
- **Artefact.** Distribution DSO
  `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`
  (17,128,536 bytes, build-id `5a70df9f12a1ada45b0a250fb97019afcb55ebe7`),
  reproduced from the clean commit into a fresh target dir; archive
  `6c2133c07f8ec7363e09c192674008c4532dc606fbe317aaf7cd953abd6bea7b`; authority
  `611e511d…`. The earlier working-tree caveat is resolved by the commit.
- **Authority contract.** OpenSSL 3.6.4 `ossl_ec_wNAF_mul`'s fixed-base arm
  (`scalar != NULL`, `num == 0`), which the authority sends to
  `ossl_ec_scalar_mul_ladder`. The new arm runs only for the standard P-256
  group; otherwise the ladder is unchanged.
- **Ownership before/after.** Before: the secret scalar crosses the `BIGNUM`
  ladder. After: on the admitted path the scalar is four limbs consumed by a
  fixed-width comb; the table is public generator data derived from the tracked
  `EC_CURVE_DATA`, cached once.
- **Unsafe — eliminated / relocated / hidden.** eliminated: per-step `BIGNUM`
  traffic on the admitted path; relocated: no new raw-pointer boundary (same
  pointers `ossl_ec_scalar_mul_ladder` already holds); **hidden: 0**.
- **Boundary size.** One `unsafe fn` entry point + one `unsafe fn` admission
  predicate, both `pub(crate)`.
- **Obligations discharged.**
  * admission refusal for modified generator/order, foreign method, different
    curve (probe-verified);
  * 4,096-scalar DSO differential of `k·G` (0 mismatches) and 4,096 `k·P`
    (0 mismatches), 256+256 ECDSA cross-verifications;
  * rebuild reproducibility from the clean commit;
  * **mutation control at the artefact**: admission-off DSO `e4b2cb6e…` is
    correct on 4,096 points yet costs 2.05× instructions / 1.96× wall, so the
    comb is load-bearing (`mutation/MUTATION.md`);
  * **timing at the digest**: `ecdsa256` 10.64× [10.61, 10.67], `ecdh` 6.79×
    [4.69, 6.90] (`timing-04611380/REPORT.md`);
  * **ctgrind + branch audit at the digest**: run and cross-agreeing.
- **Obligations retained — STOP at `04611380` (historical).**
  * The fixed-base admission contained one **secret-derived conditional
    transfer**: `je` at `ossl_ec_wNAF_mul+0x1938`, the `ct_ge(k, n)` early
    exit. ctgrind reported it as the only secret-dependent context of
    `mul-g-fixed`; the branch audit reproduced it exactly.
  * That STOP is **resolved at `ecbefb7d`** (2026-11-27) by the branch-free
    admission described in [`POST-FIX.md`](POST-FIX.md): the in-range mask is
    folded into the scalar the comb consumes (`reduced = k - (n & mask)`), so
    the decision is exact and arithmetic. ctgrind `mul-g-fixed` is
    **0/0/0** contexts (was 1/1/1), the sensitivity control still fires, and
    the branch audit has no admission-mask jcc (186 → 183).
  * T23/T24/T29 and `PFP3-P34-COVERAGE` remain open as before;
    `PFP3-CT-BRANCH` is removed from the arm's open set.
- **Compatibility tested.** DSO-bound: 4,096 `k·G`, 4,096 `k·P`, 256+256 ECDSA
  cross-verifications, 0 mismatches; in-crate 4,096 fixed-vs-variable, 0
  mismatches; `cargo test --lib -- p256` 29 passed / 0 failed; `fmt` clean.
- **Does every remaining unsafe op have an explicit validity contract?** Yes for
  the new boundary; the safety inventory is unchanged.
- **Divergence classification.** No observable-behaviour deviation on the tested
  population. The performance change is an implementation strategy, not a
  semantics change. The admission branch was a constant-time defect in the
  candidate, not a reproduced authority behaviour, and it is removed at
  `ecbefb7d`.
- **Honest state.** `DONE` at `ecbefb7d` per the PFP-3 acceptance conjuncts
  (clean audit, zero taint on the path, every correctness block, timing at one
  digest); the arm is `CANDIDATE`. The pre-fix receipt at `04611380` remains
  `STOP` (`PARTIAL`) as the historical record.
