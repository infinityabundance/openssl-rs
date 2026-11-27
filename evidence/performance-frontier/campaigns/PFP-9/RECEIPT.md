# PFP-9 receipt — architecture-specialised backends and per-target evidence

```yaml
task_id:      PFP-9
title:        Architecture-specialised backends and per-target evidence
state:        PARTIAL
stage_branch: staging
source_head:  dd05d3f4
source_change: documentation, Python validator, tests and evidence only; src/ untouched
agent:        no commit, no push
```

## 1. What was added

| file | role |
|---|---|
| `docs/KERNEL-VERIFICATION.md` | the PFP-9 output: provenance decision, per-kernel table, no-inheritance rule, limits, proof status |
| `forensics/performance/KERNELS.json` | machine-readable per-kernel table (`openssl-rs/performance/kernel-register/v1`) |
| `forensics/tools/kernel_verification.py` | validator, 21 refusal codes, self-test, `check`/`rules`/`self-test` commands |
| `forensics/tools/tests/test_kernel_verification.py` | 22 tests, 0 failures |
| `docs/PERFORMANCE-FRONTIER-TODO.md` | PFP-9 row moved to `PARTIAL` with exactly what is and is not established |
| `docs/PERFORMANCE-FRONTIER.md` | §14 layout names the checker |
| `evidence/performance-frontier/campaigns/PFP-9/RECEIPT.md` | this receipt |

`AGENTS.md` is **untouched**.

## 2. The kernel inventory

Eleven kernels are enumerated. Each record carries source identity, target,
artefact digest, artefact/source binding, differential court, audit result and
digest, an explicit proof status, and the targets for which no evidence exists.

| kernel | evidence binding | proof |
|---|---|---|
| `bn-cias-mont` — CIOS Montgomery (generic slice) | MIXED (audit/ABI artefact; exchange taint source) | `NO_PROOF` |
| `bn-cias-fixed` — CIOS fixed-width 4/6/9/16/32/48/64/128 | MIXED (width 4 taint source; audit artefact) | `NO_PROOF` |
| `bn-mont-sos` — SOS reference | MIXED (audit at `842efa27`; differential/ABI at `6d002db2`) | `NO_PROOF` |
| `bn-mont-sqr` — dedicated Comba squaring | MIXED (differential/ABI; no audit) | `NO_PROOF` |
| `bn-window-ladder` — window + full masked scan | MIXED (audit artefact; taint source) | `NO_PROOF` |
| `p256-field-mont` — P-256 field engine, Mont | ARTEFACT (`553e1b8c`) | `NO_PROOF` |
| `p256-field-arch` — P-256 `mulx`/`adcx`, Solinas | SOURCE (test binary, no DSO) | `NO_PROOF` |
| `p256-fixed-comb` — fixed-base comb and table | ARTEFACT (`ecbefb7d`) | `NO_PROOF` |
| `p256-order-inverse` — `k^(n-2) mod n` | ARTEFACT (`4e6ec312`) | `NO_PROOF` |
| `dh-width-policy` — DH declared-width ladder | MIXED (audit at `6302e05a`; repair differential at `e3ef3d84`, no audit) | `NO_PROOF` |
| `rsa-crt` — sequential CRT path | ARTEFACT (`6d002db2`) | `NO_PROOF` |

Counts by the strongest evidence record: **4 artefact-bound**, **6 mixed**
(artefact audit or ABI transcript plus source-bound taint/differential), **1
source-bound**. **All 11 are `NO_PROOF`.** No field is blank and no proof is
implied.

## 3. The provenance decision

`PFP9-PROVENANCE-PORTABLE-RUST-1`: every kernel ships as the first-party portable
Rust representation that has its own differential court and binary audit at a
named artefact digest, with the portable reference retained as oracle and
fallback. No third-party assembly enters the custodian boundary. The one
architecture-specialised arm implemented (`p256::Arch`, `mulx`/`adcx`) is
compiled but not selected because it lost to portable Mont (`mul` 61.793 vs
20.662 ns; ladder 422.821 vs 224.423 ns). §8's recommended fiat-crypto +
`s2n-bignum`-grade route is recorded as the intended direction, not adopted.
What invalidates the decision: a compiler change, a target or target-feature
change, a new measurement or a regression, a source/owner/precondition change,
a new backend or contract change, or an instrument change.

## 4. The no-inheritance rule and its enforcement

Rule: evidence for one target, profile, compiler or artefact never transfers to
another; a claim citing a different identity is refused. The checker enforces:

| code | negative control |
|---|---|
| `KV_EVIDENCE_DIGEST_MISMATCH` | evidence digest changed away from the campaign's |
| `KV_TARGET_MISMATCH` | evidence target changed |
| `KV_PROFILE_MISMATCH` | evidence profile changed |
| `KV_AUDIT_DIGEST_MISMATCH` | audit digest changed away from the evidence artefact |
| `KV_CT_CLAIM_WITHOUT_COURT` | differential removed from a constant-time claim |
| `KV_CT_CLAIM_WITHOUT_AUDIT` | audit removed from a constant-time claim; also the real SOS-at-`6d002db2` and DH-preset-at-`e3ef3d84` cases |
| `KV_CLAIM_IDENTITY_MISMATCH` | claim target changed |
| `KV_SOURCE_BOUND_CT_CLAIM` | constant-time claim on `p256-field-arch` source-bound evidence |
| `KV_PROOF_ABSENT` | proof blanked |
| `KV_NO_EVIDENCE_TARGETS_ABSENT` | no-evidence list emptied |
| `KV_NO_EVIDENCE_TARGET_UNDECLARED` | AArch64/AVX-512 arm removed |
| `KV_UNKNOWN_CAMPAIGN` / `KV_CLAIM_UNKNOWN_KERNEL` / `KV_CLAIM_UNKNOWN_EVIDENCE` | dangling campaign/kernel/evidence reference |
| `KV_DUPLICATE_ID` / `KV_SCHEMA` | duplicate id / wrong schema |
| `KV_JSON_MALFORMED` / `KV_JSON_DUPLICATE_KEY` / `KV_JSON_NON_FINITE` | bad JSON, duplicate key, NaN/Infinity |
| `KV_DOC_KERNEL_MISSING` / `KV_DOC_NO_INHERITANCE_MISSING` | document omits a kernel or the rule |

Non-vacuity: a complete artefact-bound register with a constant-time claim is
accepted; a source-bound entry is accepted only when the claim is not a
constant-time claim; removing the audit from the accepted entry makes it refuse.
The self-test runs **19 register controls (3 positive) plus 2 document controls**
across **21 refusal codes**.

The checker is a separate command; it is **not** wired into
`forensics/tools/docs_consistency.py`, following the existing convention of
`performance_classification.py` and `performance_admission.py`.

## 5. Limits, stated in the document and not inherited

* **AArch64** (`aarch64`), **AVX-512/IFMA** (`avx512f`, `avx512ifma`): 
  `NOT_APPLICABLE_HARDWARE`. **AVX2** and hand-written **ADX/BMI2**: `NOT_RUN`.
  The machine has no AArch64 target and no AVX-512; **PFP-9 cannot fully close
  on this hardware.**
* **No PMU.** Every timing result remains `SCOPED_OBSERVATION`.
* **No proof.** Every kernel is `NO_PROOF`; the audits are review aids, ctgrind
  is a taint run, and Kani/Miri/BINSEC/dudect were `NOT_RUN` for these kernels.
* **Source-bound evidence is labelled.** The PFP-5/6/8 exponent taint and the
  PFP-2 kernel-selection measurement are source-bound; they do not become
  artefact evidence.
* **Rejected arms are named with their campaign references** so they are not
  re-litigated silently: dedicated squaring (PFP-6), CRT interleaving (PFP-7),
  reduced radix (M-A2), Karatsuba (PFP-6), P-256 Solinas/Arch (PFP-2), DH
  generator table (PFP-8), AVX-512/IFMA (PFP-7, `NOT_APPLICABLE_HARDWARE`).
* **Open residues carried forward:** T23/T24/T29, PFP-2 write-back
  declassification, PFP-8 wide-preset residual, PFP-4 timing shortfall, and the
  uncommitted-worktree status of several candidates.

## 6. Verification run

| check | result |
|---|---|
| `python3 forensics/tools/kernel_verification.py self-test` | ok: 19 controls, 21 codes, 2 document controls, 3 positive controls |
| `python3 forensics/tools/kernel_verification.py check` | 1 register accepted, 0 refused |
| `python3 -m unittest forensics.tools.tests.test_kernel_verification` | 22 tests, 0 failures |
| `python3 -m unittest forensics.tools.tests.test_performance_admission forensics.tools.tests.test_performance_classification` | see the run log; no change to either register |
| Rust suite / clippy | **NOT_RUN** — `src/` is unchanged; the recorded PFP-8 preset-priv baseline is 2,499 passed / 0 failed / 54 ignored, not re-run here |

This receipt does not establish that any cited court or audit ran, that any
measurement is true, or that any kernel is constant time. It records a bound,
enforced register of what exists and what does not.
