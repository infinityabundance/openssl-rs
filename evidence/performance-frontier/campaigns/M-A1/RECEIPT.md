# M-A1 — conversion / performance receipt

```yaml
task_id:            M-A1
title:              Fixed-width native Rust specialisation of the CIOS kernel
phase:              performance frontier (multi-accumulator arithmetic)
stage_branch:       staging (not committed — this batch is forbidden to commit/push)
source_identity:
  parent_sha:       ff87f8488e206896ffdd82259af2fcf4ba269209
  result_sha:       uncommitted worktree change to src/bn/arith.rs
  candidate_dso:    88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87
  previous_dso:     6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39
authority_contract: >
  The CIOS Montgomery multiply a*b*R^-1 mod m for an odd modulus m with a
  non-zero top limb, at the OpenSSL BN_mod_exp_mont_consttime /
  BN_mod_mul_montgomery ABI boundary; the 161-line pfp5_diff transcript against
  openssl-3.6.4-production DSO 611e511d is the compatibility witness.

ownership_before: >
  Unchanged from PFP-6: ladder scratch (accumulator t, difference diff, product,
  base) lives in caller-owned SecretBufs allocated once before the loop; the
  generic kernel borrows slices; Drop cleanses.
ownership_after: >
  Identical ownership. The specialised kernel borrows the same caller buffers
  (the accumulator is the first N+2 limbs of the same SecretBuf t, converted to
  &mut [Limb; ACC]); no new allocation, adoption, alias, copy of secret state or
  release path. Cleansing-on-Drop is preserved.

mechanisms:
  - name: compile-time CIOS width specialisation on the ladder path
    eliminated:
      - runtime-length inner-loop trip counts for the eight specialised widths
      - slice bounds checks the compiler could not prove for a runtime n
    relocated: []
    hidden: 0

unsafe_ops:
  removed: 0
  retained: 0 (this batch adds no unsafe and touches no unsafe site; the
              arith.rs FFI entry points and their contracts are unchanged)
  introduced: 0

boundary: >
  No boundary changed. The C ABI façade, the SecretBuf owners, the
  CRYPTO_* seam and every #[repr(C)] layout are untouched. The new code is safe
  Rust; the only fallible surface is the existing fail-closed length check.

obligations:
  discharged:
    - geometry fails closed at the dispatch boundary (mont_geometry_ok), and the
      per-width TryFrom conversions cannot see a different length
    - each specialised width is bit-identical to the generic slice kernel over
      the recorded population (8,190 pairs) and satisfies the defining
      congruence
    - the 161-line ABI transcript is identical to the authority at the
      candidate digest
    - no jcc in the carrier has an arithmetic flag source; no class-(b) setcc
      is first consumed by a comparison or branch
  retained:
    - constant-time behaviour is not proven; ctgrind is source-bound at width 4
      and the DSO probe is base-bound at width 4. Widths 6/9/16/32/48/64/128
      rest on the structural audit.
    - the branch audit is enumeration + local dataflow, not a proof.
    - the timing is one venue's scoped observation.
  introduced:
    - the dispatch table and the ACC constants must stay aligned with the
      kernel instantiations; a new width must be added in one place and its
      ACC checked (the kernel guards ACC >= N+2 and t.len() >= ACC)
    - secret state now resides in fixed-size borrows of the same SecretBuf; the
      extents are compile-time constants but the cleansing contract is the
      caller's unchanged one.

compatibility_delta: >
  161 lines, IDENTICAL to the authority for both the candidate and the previous
  build (150 MX, 8 RSA, 2 DH). No behavioural divergence recorded.

safety_checks:
  per_width_differential: 8,190 pairs, 0 mismatches; 4,603 fallback pairs, 0
  congruence:             every differential pair also checks out*R == a*b (mod m), out < m
  abi_transcript:         IDENTICAL at both digests
  repository_gates:       bn 161 pass; suite 2,493 pass / 54 ignored; fmt clean; clippy clean
  ctgrind:                exponent taint 0 errors / 0 contexts (origins none); control 4/1
  dso_probe:              0 contexts on cand and prev, 3 reps each
  branch_audit:           40 jcc public, 64 setcc carry/borrow consumed arithmetically, 0 cmov, 0 secret-derived
  miri_sanitizer_kani:    NOT_RUN (not claimed; no aliasing/ownership change and no new unsafe)

boundary_scope_ids:
  - MA1-DISPATCH: mont_mul_ladder_into (Cios arm) -> mont_mul_cios_dispatch -> mont_mul_cios_fixed::<N,ACC>
  - MA1-CARRIER: mont_mul_ladder_into at 0x2fa7d0, size 0x2431 (all widths inlined)

graduation: >
  Not applicable: this is a performance arm, not an unsafe-conversion batch. No
  SAFETY_DISCHARGED or SAFE_COMPATIBLE conclusion is asserted. The code adds no
  unsafe operation and removes no safety obligation.

residuals:
  - id: MA1-128-NEUTRAL
    disposition: recorded negative/neutral result — the 128-limb specialisation is 0.9996 of prev (interval includes 1); keep it (it loses nothing) and make no speed claim.
  - id: MA1-256-NOT-ISOLATED
    disposition: the 2.6x standalone by-product is not reproduced end to end; no 256-bit modexp workload exists and ECDSA is point-dominated. Recorded, not claimed.
  - id: MA1-6-9-64-NOT-ISOLATED
    disposition: implemented and differenced; not exercised by the frozen workload set. No speed claim.
  - id: MA1-UNCOMMITTED
    disposition: two clean builds reproduce 88c0c7e0, but the candidate is not reproducible from a commit until the change lands.
  - id: MA1-TIMING-SCOPE
    disposition: one venue, no PMU; SCOPED_OBSERVATION only.
```

## Notes

- Every number above is read from `raw/`, `correctness/`, `differential/`,
  `ctgrind/`, `dso-probe/`, `raw/disasm/` and `timing/raw/` in this directory;
  the exact commands are in §8 of `RESULTS.md`.
- The mechanism eliminates the runtime-length loop shape, not an unsafe
  operation. `hidden = 0` for the mechanisms this batch touches.
- The register entry is `evidence/performance-frontier/admission/ARMS.json`
  (`arm_id` `M-A1`), which passes
  `python3 forensics/tools/performance_admission.py check`.
