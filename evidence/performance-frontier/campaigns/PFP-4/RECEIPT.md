# PFP-4 conversion receipt — W3 bound, no implementation

- **Source identity.** `staging` `0f8904d69` (docs-only; the `src/` tree equals
  `49809764f`, the PFP-3 branch-free admission). No source file was changed by
  this batch: `src/**/*.rs` is untouched, the `CRYPTO_*` seam and every
  `#[repr(C)]` layout are unchanged, and no `unsafe` operation was added.
- **Subject.** The PFP-3 post-fix distribution DSO
  `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053`
  (`court/tmp/pfp3-d/distribution/libcrypto.so.3`), the **same digest** as the
  PFP-3 timing record (`ecdsa256` 10.58× [10.55, 10.62]). Authority
  `611e511d…`. The profiling harness proves the mapped file by
  `dladdr`/`stat` (`dev_ino_match=1 size_match=1`).
- **Authority contract.** OpenSSL 3.6.4's P-256 signing pipeline
  (`ecdsa_sign_setup` + `ossl_ecdsa_simple_sign_sig`): nonce draw, `k·G`,
  affine `x`, `r = x mod n`, `k⁻¹ = k^(n−2) mod n` via `bn_mod_exp_mont_fixed_top`,
  `s = (m + r·d)·k⁻¹ mod n`, DER export. The W3 analysis does not change it; it
  measures it.
- **Ownership before / after.** Before and after: identical. Nothing was
  converted.
- **Unsafe — eliminated / relocated / hidden.** 0 / 0 / **0**. No code change.
- **Boundary size.** No new boundary. The design sketch
  ([`DESIGN.md`](DESIGN.md)) would reuse the existing `P256Scalar` and PFP-3's
  `admits`; it is not implemented.
- **Obligations discharged.** The W3 profiling obligation, at one digest:
  * wall decomposition (`profile/profile-wall.txt`): `sign` 134.307 µs,
    `k·G` 115.193 µs (**85.77 %**), outside-`k·G` **14.23 %**;
  * independent instruction attribution (`profile/callgrind-sign.out`):
    `k·G` 80.93 %, order inverse 15.91 %, nonce 2.39 %, `s` expression + export
    **0.48 %**;
  * Amdahl: the entire non-`k·G` fraction is bounded by **1.166×** (best ratio
    **9.07×**); the PFP-4 scalar/reduction/expression/export subset is bounded
    by **1.005×**.
- **Obligations retained / NOT_RUN (with the gate that would run them).**
  * 4,096 deterministic-nonce signatures vs the authority — **NOT_RUN**: no
    implementation exists to test (would be Task 3.1).
  * Defining-equation and round-trip — **NOT_RUN**: same reason (Task 3.2–3.3).
  * `cargo test --lib -- ec`, full library suite, `fmt`, `clippy -D warnings` —
    **NOT_RUN**: no source change; the last recorded run is PFP-3's 2,484
    passed / 0 failed / 54 ignored at the same `src` tree.
  * New-digest rebuild, DSO digest, reproducibility — **NOT_RUN**: no new
    binary; the profiled digest `ecbefb7d` is PFP-3's two-independent-clean-build
    digest.
  * ctgrind on signing with the private scalar and nonce marked secret —
    **NOT_RUN**: no new carrier (Task 4.2).
  * Binary branch audit over new carriers — **NOT_RUN**: no new carrier
    (Task 4.3).
  * `ecdsa256` at a new digest vs 10.58× [10.55, 10.62] — **NOT_RUN**: no new
    digest; the bound says the change cannot move the ratio beyond 9.07× at the
    absolute ceiling (Task 4.4).
- **Compatibility tested.** Nothing to test: no behaviour changed. The harness
  reproduced the PFP-3 public key `03b1c46f…` and derived `r` at the same DSO.
- **Does every remaining unsafe op have an explicit validity contract?** Yes —
  the inventory is unchanged from PFP-3, because no unsafe operation was added.
- **Divergence classification.** None: this batch changes no implementation. The
  finding is a *performance* finding (the dominant cost is `k·G`, not scalar
  arithmetic), recorded so the programme does not spend effort where the bound
  forbids a gain.
- **Arm register.** A `PFP-4` **`EXPERIMENT`** arm is recorded honestly in
  `evidence/performance-frontier/admission/ARMS.json`: it names the profiled
  digest and carries the bound as its description, with `measurement`,
  `differential_courts` and `constant_time_audit` **null**, because no PFP-4
  candidate exists and nothing was measured as a candidate. It is not a
  `CANDIDATE`; a candidate needs a measurement, a differential court and a clean
  binary audit at one digest, and this batch produced none of those.

## Decision

**PARTIAL.** The W3 rule is the reason: the entire non-`k·G` remainder is
14.2 % and the PFP-4 arithmetic is 0.45 %, so the pipeline conversion cannot
move `ecdsa256`. The only material remainder is the order inversion (≈12.7 %
wall), recorded as a separate follow-up. `k·G` (85.8 %) remains the frontier and
belongs to PFP-3/W5.
