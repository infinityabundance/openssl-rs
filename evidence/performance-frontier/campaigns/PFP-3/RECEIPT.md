# PFP-3 conversion receipt

- **Source identity.** `staging` HEAD `b0ada60ebd72432daaef68d8ee6d7cd5245f7895`
  plus working-tree changes (`src/ec/mult.rs`, `src/ec/p256.rs` modified;
  `src/ec/p256/fixed_base.rs` added). `src` fingerprint
  `ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a`.
  Not committed; not pushed.
- **Artefact.** Distribution DSO
  `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`
  (17,128,536 bytes, build-id `5a70df9f12a1ada45b0a250fb97019afcb55ebe7`),
  reproduced byte-for-byte by two independent clean builds (same archive sha256
  `6c2133c0…`). Authority `openssl-3.6.4-production`
  `611e511d…`.
- **Authority contract.** OpenSSL 3.6.4 `ossl_ec_wNAF_mul`'s fixed-base arm
  (`scalar * G`, `num == 0`) which the authority itself sends to
  `ossl_ec_scalar_mul_ladder`. The new arm runs only when the group is exactly
  the standard P-256 group; otherwise the ladder is unchanged.
- **Ownership before/after.** Before: the secret scalar crosses the `BIGNUM`
  ladder for 256 steps. After: on the admitted path the scalar is read into four
  limbs and consumed by a fixed-width comb; the table is public generator data
  derived from the tracked `EC_CURVE_DATA`, cached once.
- **Unsafe — eliminated / relocated / hidden.**
  * eliminated: per-bit coordinate conversions and the ladder's per-step
    `BIGNUM` traffic on the admitted path;
  * relocated: no new raw-pointer boundary; the entry point takes the same
    pointers `ossl_ec_scalar_mul_ladder` already holds and every dereference is
    covered by the existing `# Safety` contract of the caller;
  * **hidden: 0.** The one new `unsafe fn` (`try_fixed_base_mul`) states its
    pointer contract and its admission precondition; `admits` states the group
    contract. No new `unsafe` block lacks a `SAFETY:` comment.
- **Unsafe ops removed vs relocated.** 0 removed, 0 relocated by this batch;
  the batch adds no new category of unsafe operation beyond the existing
  coordinate write-back (`store_coordinate`), reused.
- **Boundary size.** One `unsafe fn` entry point + one `unsafe fn` admission
  predicate; both are `pub(crate)`.
- **Obligations discharged.** Admission-precondition refusal for modified
  generator, modified order, foreign method, different curve (probe-verified:
  the fast arm is not entered); 4,096-scalar authority differential of `k·G`;
  fixed/variable-base equivalence; exceptional-case completeness; two-build
  reproducibility.
- **Obligations retained.** Timing at this digest (`NOT_RUN`); ctgrind
  (`NOT_RUN`); binary branch audit (`NOT_RUN`); the three audit targets named in
  `TAINT-AUDIT.md`; T23/T24/T29 remain open as for PFP-2.
- **Compatibility tested.** DSO-bound: 4,096 `k·G`, 4,096 `k·P`, 256+256 ECDSA
  cross-verifications, 0 mismatches; full library suite 2,484 passed / 0 failed /
  54 ignored; `fmt` and `clippy -D warnings` clean.
- **Does every remaining unsafe op have an explicit validity contract?** Yes for
  the new boundary; the safety inventory of the crate is unchanged.
- **Divergence classification.** No deviation from the authority's observable
  behaviour on the tested population. The performance change is an
  implementation strategy, not a semantics change.
- **Honest state.** `PARTIAL`. The acceptance clause that is not met is the
  constant-time audit at this digest (and the timing measurement, which cannot be
  identity-bound without a commit). No speed or constant-time claim is made.
