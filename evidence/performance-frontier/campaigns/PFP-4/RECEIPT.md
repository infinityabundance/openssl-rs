# PFP-4 conversion receipt — order inversion replaced at `4e6ec312`

- **Source identity.** `staging` `5ac6fddc53f5ca2a63912f51c07188b9b63f71dd`
  with four uncommitted build-relevant files:
  `src/ec/lib.rs`, `src/ec/p256.rs`, `src/ec/p256/fixed_base.rs`,
  `src/ec/p256/tests.rs`. Source-tree fingerprint
  `4e05841492051be7ca3655196af353b642f6753df11152ae7f0141135815b2ca` (887 files),
  unchanged across the build. The campaign does not commit.
- **Candidate.** Distribution DSO SHA-256
  `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77`, build-id
  `f38d4d5ce9641bebfd302db772d4802f269e0ed1`, archive
  `10bb388a2f46c5199ef69f331b181f9ced3dfc3cb31639ff2aafc76eaaba9aa0`. **Two
  independent clean builds** (`build_pfp4.sh a` and `b`, fresh target dirs)
  produced the identical digest and build-id. Authority
  `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.
- **Authority contract.** OpenSSL 3.6.4 signing: `k⁻¹ = k^(n−2) mod n` via
  `bn_mod_exp_mont_fixed_top` (Fermat, fixed-top), then
  `s = (m + r·d)·k⁻¹ mod n` and DER export. The replaced component is exactly
  that Fermat inverse; the `s` expression and export are untouched.
- **Ownership before / after.** Unchanged. The new code adds a compile-time
  exponent constant and a fixed-width residue value (`P256Scalar`), which owns
  no allocation and cleanses on `Drop`. No ownership, borrow or lifetime
  obligation changed.
- **Unsafe — eliminated / relocated / hidden.** 0 / 0 / **0**. One new audited
  boundary was added: `unsafe fn try_inverse_order` with a `# Safety` contract
  (live group; live `BIGNUM`s; `r` may alias `x`). Its body has three raw
  dereferences, each with a `SAFETY:` comment; the operand is copied out before
  the write, so the signing call's `r == x == k` aliasing is sound.
  `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks` and `missing_safety_doc`
  remain enforced, and `cargo clippy --all-targets -- -D warnings` passes.
- **Boundary size.** One new function on the existing `admits`
  (`src/ec/p256/fixed_base.rs`) and `store_coordinate` (`src/ec/smpl.rs`)
  contracts; the kernel and domain types are reused unchanged. The `CRYPTO_*`
  seam and every `#[repr(C)]` layout are untouched.
- **Obligations discharged.**
  * Inverse correctness: 4,108 in-crate cases vs an independent `bn::limbs`
    Fermat oracle (0 mismatches), 4,107 `k·k⁻¹ ≡ 1 (mod n)` round-trips,
    4,096 BigNum-level cases vs the generic `bn_mod_exp_mont_fixed_top` body
    (0 mismatches, including non-canonical operands and the aliased call).
  * DSO differential at the candidate digest: 4,096 supplied-nonce `sign-ex`
    signatures with the defining equation checked for each and `ECDSA_sign_ex`
    DER equal to `ECDSA_do_sign_ex`, and 4,096 `sign-rand` signatures through the
    shipped `ECDSA_do_sign` with deterministic nonces (which exercises the new
    inverse). Both modes are byte-identical to the authority and cross-verify
    4,096/4,096 in both directions under one public key.
  * T27 (`bn::arith::mod_add_reduced_ct` at the `s = s + m` site) is unchanged;
    the `s` expression and export were not touched.
  * Constant-time: ctgrind with the private scalar tainted and with the
    private scalar **and** the nonce source tainted reports 0 engine-on-path and
    0 engine-origin contexts; the sensitivity control reports 4 engine-on-path
    contexts per repetition. The branch audit classifies every `jcc`/`setcc`/
    `cmov` in the new carrier as public-bound; `invert` has exactly two
    conditional jumps, the fixed loop counter and the public exponent-bit test.
  * `cargo test --lib -- ec`: 649 passed, 0 failed, 13 ignored. Full library:
    2,487 passed, 0 failed, 54 ignored. `fmt` and `clippy -D warnings` pass.
  * `ecdsa256` measured at the candidate digest: **10.28× [10.26, 10.31]**,
    candidate 130.957 µs vs authority 12.752 µs.
- **Obligations retained / NOT_RUN (and why).**
  * The timing target was **not met**. The bound's realistic expectation was
    ≈9.9× (halving the inversion) and its absolute ceiling 9.24×; the task's
    reference was ≈9.1×. 10.28× improves the PFP-3 10.58× [10.55, 10.62] by
    0.30× (candidate ~3.5 µs faster) but misses the bound. The measured inverse
    costs ~14 µs, not the ~7 µs the design extrapolated from the field inverse's
    callgrind share; `P256Scalar` uses the portable `Mont<OrderDomain>`
    schoolbook/REDC kernel (425 operations), and the generic ladder it replaces
    costs only ~17 µs. Recorded as a shortfall, not a success.
  * BINSEC `-checkct` was **NOT_RUN**; the branch audit is a source-review
    classification of emitted instructions, not a binary taint proof.
  * A dedicated branchy-inverse mutation control was **NOT_RUN**; the
    sensitivity control exercises the P-256 ladder rather than the inverse.
    This is recorded as a limitation of the ctgrind evidence.
- **Compatibility tested.** `ECDSA_do_sign` and `ECDSA_do_sign_ex`/
  `ECDSA_sign_ex` with supplied nonces are byte-identical to the authority over
  4,096 cases each; the same public key is derived; custom methods, modified
  generators/orders/curves and foreign methods still fail `admits` and keep the
  generic inverse (the existing refusal tests now also assert the inverse arm
  refuses). Retries and error-site coordinates are untouched; the hook runs
  after `mont_data` nullness, so the generic failure answer is preserved.
- **Does every remaining unsafe op have an explicit validity contract?** Yes.
  The one new `unsafe fn` states provenance/aliasing/liveness; every new raw
  dereference carries `SAFETY:`. The reused kernel and write-back retain PFP-2/
  PFP-20/PFP-3 contracts.
- **Divergence classification.** No behavioural divergence was found at the
  candidate digest. The deliberate performance divergence is recorded above;
  the pipeline conversion remains refused by the W3 bound (0.45 % of wall) and
  was not attempted. `k·G` is unchanged.
- **Arm register.** The `PFP-4` arm in
  `evidence/performance-frontier/admission/ARMS.json` is updated to name the
  candidate `4e6ec312`, its measurement (`ecdsa256` 10.28×), the differential
  courts, and the ctgrind-plus-audit record, with the honest shortfall and the
  remaining open obligations. It is not `SAFE_COMPATIBLE`; the consumer
  dependency closure is not discharged.

## Decision

**DONE** by the stated criteria: the inversion is replaced, the audit is clean
and every correctness gate passes at one candidate digest. The performance
shortfall against the bound is recorded honestly (10.28× measured versus the
≈9.1× reference / 9.24× ceiling). The pipeline conversion stays refused by the
bound. Evidence: [`RESULTS.md`](RESULTS.md), [`AUDIT.md`](AUDIT.md),
[`CTGRIND.md`](CTGRIND.md), `build/`, `differential/`, `ctgrind/`, `audit/`,
`timing-4e6ec312/`.
