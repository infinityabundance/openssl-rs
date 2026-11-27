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
| `forensics/tools/kernel_verification.py` | validator, 30 refusal codes, self-test, `check`/`rules`/`self-test` commands |
| `forensics/tools/tests/test_kernel_verification.py` | 47 tests, 0 failures |
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

### 3.1 Correction (2026-11-27) — the `p256::Arch` attribution

The record carried this attribution:

> `p256::Arch` is "the only direct measurement this project has of
> hand-scheduled carry chains against safe Rust, and safe Rust won by about
> three times".

It is wrong in three independent ways; the text above is retained unchanged.

1. **Not hand-scheduled.** `wide_mul_x86` (`src/ec/p256.rs:1046`) is a
   schoolbook double loop over `_mulx_u64` (line 1054) and `_addcarry_u64`
   (lines 1056, 1058, 1061, 1063). Each carry is a returned `u8` added back as
   a scalar; there is no `_addcarryx_u64`, no `adcx`/`adox`, no assembly and
   no hand scheduling. The release DSO `court/tmp/pfp4-a/distribution/
   libcrypto.so.3` shows 16 `mulx`, 15 `adc`, 0 `adcx`, 0 `adox`. The
   inventory label above ("`mulx`/`adcx`") is also wrong: it is
   `mulx`/`adc`.
2. **Mixed variables.** `Arch` is `mulx` **plus Solinas reduction**; the
   portable winner is `Mont` (Montgomery). The controlled pair is `Arch` vs
   portable `Solinas`: 61.793 vs 82.885 ns on `mul`, so `mulx` **won by
   25.4 %** (ladder 422.821 vs 538.076, 21.4 %). The ~3× is `Arch` vs `Mont`
   (61.793 vs 20.662 ns, 2.991×) and belongs to the Solinas reduction, not to
   carry chains.
3. **Per-call cost.** `wide_mul_x86` is `unsafe #[target_feature]` and cannot
   inline into `Arch::wide_mul_into`; both `Arch::mul` and `::sqr` contain one
   out-of-line `call` to it per field multiply (disassembly of the same
   release DSO). This is measured, not a hypothesis.

**Hand-written ADX with paired `adcx`/`adox` chains has NOT been measured;
`NOT_RUN`.** The requested `mulx`-plus-Montgomery-inlined comparison is
already answered by **PFP-48** (whole crate `+bmi2`, kernel inlined, `mulq` 0,
`mulx` 121, 0 `adcx`/`adox`, every workload equal or slower, modexp-2048
≈2.4 % slower). PFP-48 does not answer the hand-paired ADCX/ADOX question,
which remains open. See `docs/KERNEL-VERIFICATION.md` §5.3.1 for the full
record, including the PFP-41 n=16 confirmation. The
`forensics/performance/KERNELS.json` descriptions in
`provenance_decision.decision`, `provenance_decision.rejected_arms[1].arm` and
the `p256-field-arch` kernel label carry the same old description; they are
superseded by this section, and the register now carries a `correction` object
that says so beside the retained old text.

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
| `python3 forensics/tools/kernel_verification.py self-test` | ok: 28 controls, 30 refusal codes, 2 document controls, 3 positive controls |
| `python3 forensics/tools/kernel_verification.py check` | 1 register accepted, 0 refused |
| `python3 -m unittest forensics.tools.tests.test_kernel_verification` | 47 tests, 0 failures |
| `python3 forensics/tools/docs_consistency.py` | ok: 20 hand-written claims agree; the kernel register is wired |
| `python3 -m unittest forensics.tools.tests.test_earned_trust` | 28 tests, 0 failures |
| Rust suite / clippy | **NOT_RUN** — `src/` is unchanged; the recorded PFP-8 preset-priv baseline is 2,499 passed / 0 failed / 54 ignored, not re-run here |

This receipt does not establish that any cited court or audit ran, that any
measurement is true, or that any kernel is constant time. It records a bound,
enforced register of what exists and what does not.

## 7. Assurance migration (PFP-49)

The Boolean is gone. Each kernel now carries an `assurance` list; a claim names
the dimensions it relies on. The migration is from the evidence actually on
disk, and it is deliberately lower than the old `constant_time: true` where the
stronger class would have required trusting a declared digest.

| kernel | old claim | new class | why |
|---|---|---|---|
| `bn-cias-mont` | `PFP-6-CIOS` `true` | `SOURCE_TAINT_TESTED` | exponent ctgrind 0/0 with a firing control (4/1); the DSO is not tracked, so no `ARTEFACT_AUDITED` claim |
| `bn-cias-fixed` | `M-A1-FIXED` `true` | `SOURCE_TAINT_TESTED` | width-4 taint 0/0, control 4/1; widths 6–128 are structural only |
| `bn-mont-sos` | `PFP-5-SOS` `true` | `SOURCE_REVIEWED` | the PFP-5 taint has no firing control, and the audit at `842efa27` is not the `6d002db2` evidence |
| `bn-mont-sqr` | no claim (`NOT_SHIPPED`) | `UNASSESSED` | the dedicated-squaring carrier was never audited or tainted |
| `bn-window-ladder` | `PFP-5-WINDOW` `true` | `SOURCE_REVIEWED` | taint 0/0 but no firing control in either the PFP-5 or the re-evaluation record |
| `p256-field-mont` | `PFP-2-FIELD` `true` | `SOURCE_REVIEWED` | DSO ctgrind 0/0 with a firing sensitivity control, but the DSO is not tracked; no independent subject hash, so no `ARTEFACT_*` claim |
| `p256-field-arch` | no claim | `UNASSESSED` | source-bound test binary only; no audit and no taint |
| `p256-fixed-comb` | `PFP-3-COMB` `true` | `SOURCE_REVIEWED` | DSO ctgrind 0/0/0 with a firing control, but the DSO is not tracked; no subject hash |
| `p256-order-inverse` | `PFP-4-INVERSE` `true` | `SOURCE_REVIEWED` | DSO ctgrind 0/0 with a firing control; BINSEC and the dedicated mutation control are `NOT_RUN`; DSO untracked |
| `dh-width-policy` | `PFP-8-WIDTH` `true`; `PFP-8-PRESET` `false` | `SOURCE_TAINT_TESTED` (evidence 0), `SOURCE_REVIEWED` (evidence 1), preset claim `[]` | policy taint 0/0, control 4/1; the STOP is a compatibility divergence, not a taint finding. The repair's ctgrind was not re-run at `e3ef3d84` |
| `rsa-crt` | `PFP-7-RSA` `true` | `UNASSESSED` | ctgrind reports 96,668/112 and 97,546/106 with findings outside the ladder carriers; the CRT path is not established clean, so no taint-tested class is claimed |

Three kernels hold `SOURCE_TAINT_TESTED` for their clean, controlled,
source-bound taint dimension; six artefact-taint records are downgraded to
`SOURCE_REVIEWED` because their DSO is not tracked and the checker cannot hash
the subject; three are `UNASSESSED`. No claim asserts an `ARTEFACT_*`,
`STATISTICALLY_TESTED`, `MACHINE_CHECKED` or `INDEPENDENTLY_REPRODUCED`
dimension. The register is therefore not an unverified source of authority: it
records what the checkable evidence supports, and the missing dimensions are
visible as absent, not implied.
