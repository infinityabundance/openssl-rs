# Kernel verification — per-kernel provenance, proof status and the constant-time obligation

**Item:** PFP-9, *Architecture-specialised backends* (`docs/PERFORMANCE-FRONTIER-TODO.md`).
**Status: `PARTIAL` on this hardware.** The x86-64 per-kernel provenance and the
no-inheritance rule are recorded and machine-enforced. The AArch64 and
AVX-512/IFMA arms are `NOT_APPLICABLE_HARDWARE`, so the row **cannot be fully
closed on this machine**. No kernel has a proof: every proof field is
`NO_PROOF`.

The machine-readable form of the per-kernel table is
`forensics/performance/KERNELS.json`; it is validated by
`forensics/tools/kernel_verification.py`. This document renders that table and
states the decision, the rule and the limits. Neither the register nor this
document is a constant-time proof, a performance classification above
`SCOPED_OBSERVATION`, or a `SAFE_COMPATIBLE` conclusion.

---

## 1. Hardware reality, stated first

Measured on this machine (`/proc/cpuinfo`, `uname -m`, `perf_event_paranoid`,
`/sys/bus/event_source/devices`):

| property | value |
|---|---|
| architecture | `x86_64` only; no AArch64 target or cross toolchain |
| CPU | 13th Gen Intel(R) Core(TM) i9-13900K |
| features present | `adx`, `bmi2`, `avx2`, `vaes`, `vpclmulqdq`, `sha_ni` |
| features absent | **`avx512f`, `avx512ifma`** |
| PMU | **not exposed**: `perf_event_paranoid=2`, no hardware `cpu`/`pmu` event source, `perf stat` reports `<not supported>` for `instructions`/`cycles` |
| toolchain | rustc/cargo 1.98.1 (`48a229cea`), `x86_64-unknown-linux-gnu`, release profile |

Consequences, not omissions:

* the **AArch64** arm (`mul`/`umulh`, NEON, DIT) is `NOT_APPLICABLE_HARDWARE` —
  the missing feature is `aarch64`;
* the **AVX-512/IFMA** arm (`avx512f`, `avx512ifma`, radix-2<sup>52</sup>) is
  `NOT_APPLICABLE_HARDWARE` — the missing features are `avx512f` and
  `avx512ifma`;
* the **AVX2** arm has hardware (`avx2` is present) but no admitted or measured
  backend, so it is `NOT_RUN`, not `NOT_APPLICABLE_HARDWARE`;
* a **PMU-based** dimension is `NOT_RUN`; every timing row remains
  `SCOPED_OBSERVATION` on a virtualised venue;
* the row **cannot close** here. Closing it requires an AArch64 machine and an
  AVX-512/IFMA machine (and a PMU if the claim is a frontier claim).

`sha_ni`, `vaes` and `vpclmulqdq` are present but PFP-9 touched no symmetric
kernel; those belong to PFP-12 and are not claimed here.

---

## 2. The provenance decision (§8 restated as a decision)

**Decision `PFP9-PROVENANCE-PORTABLE-RUST-1` (2026-11-27).** Every performance
kernel ships as the **first-party portable Rust representation that has its own
differential court and binary audit at a named artefact digest**, with the
portable reference retained as oracle and fallback. No third-party assembly
(`s2n-bignum`, fiat-crypto or CryptOpt output) enters the custodian boundary in
this row. The one architecture-specialised arm implemented — the P-256 `Arch`
kernel (`mulx`/`adcx`, requiring BMI2 and ADX) — is compiled but **not
selected**, because it lost to the portable Montgomery kernel on the admitted
venue.

### 2.1 What ships, and why, against the measured alternatives

| kernel family | shipped representation | measured alternative | campaign and result |
|---|---|---|---|
| BN Montgomery | CIOS generic slice kernel + fixed-width const-generic variants (4/6/9/16/32/48/64/128 limbs); SOS retained as reference/fallback | SOS reference; Comba; CIOS-vs-SOS | PFP-6: CIOS is 0.8267× the SOS operation at 2048 bits and 0.8375× at 8192 (`admission-2026-11-27/`); Comba is 1.07–1.19× slower (`CROSSOVER.md`) |
| BN exponentiation | five-bit window with a full masked table scan | bit-at-a-time ladder | PFP-5: predicted removal 38.2 % at 2048 bits and 39.5 % at 8192, measured 39.5 % and 39.8 %; 161/161 authority transcript lines identical (`DIFFERENTIAL.md`, `RECEIPT.md` §7) |
| BN squaring | reuse the multiply | dedicated Comba squaring | PFP-6 re-evaluation: dedicated squaring is 1.0822× [1.0766, 1.0831] slower at 2048 bits (`REEVALUATION.md`); `LADDER_DEDICATED_SQUARING = false` |
| BN product | schoolbook | Karatsuba | PFP-6: no crossover in 256–4096 bits; Karatsuba is 1.017–1.536× slower (`CROSSOVER.md`) |
| BN radix | radix-2<sup>64</sup> | reduced radix 2<sup>52</sup> deferred carry | M-A2: 3.41–3.44× slower at 256 bits, 1.37–1.40× slower at 1024 bits (`RESULTS.md`) |
| P-256 field | `Mont` (Montgomery, schoolbook + REDC) | `Solinas` (portable nine-fold Solinas), `Arch` (`mulx`/`adcx` + Solinas) | PFP-2 kernel measurement: `mul` 20.662 ns (Mont) vs 82.885 (Solinas) vs 61.793 (Arch); ladder 224.423 vs 538.076 vs 422.821 (`kernels/summary.json`). The measurement is **source-bound** (test binary); the admitted engine's differential and audit are artefact-bound at `553e1b8c` |
| P-256 `k·G` | 16-entry comb derived at first use from the tracked generator, 15-entry masked full scan per column | Jacobian `a = -3` formulas (reference only) | PFP-3: RCB complete formulas 14M/14M/1792 vs Jacobian 11M+5S/3M+5S/1408; Jacobian is 21.4 % cheaper but not complete and routes exceptional cases on a secret-dependent branch, so the complete arm is admitted (`RECEIPT.md`) |
| P-256 order inverse | `k^(n−2) mod n` over the public constant `n−2` in `Mont<OrderDomain>` | generic `bn_mod_exp_mont_fixed_top` | PFP-4: 425 kernel operations, 0 engine-on-path contexts; the timing target was missed (10.28× vs the ≈9.1× reference), recorded as a shortfall (`RECEIPT.md`) |
| DH ladder width | group's public declared private-key bound (`dh->length`, else RFC 7919 key length), `ceil(N/64)` limbs | modulus width | PFP-8: keygen 14.6981× → 2.6323×, shared secret 13.9578× → 1.9651× where the exponentiation dominates (`WIDTH-POLICY.md`) |
| RSA CRT | two **sequential** constant-time exponentiations | scalar interleaving | PFP-7: fused 1.1132× [1.1102, 1.1151] slower per multiplication; attainable wall change 0.91×; refused (`RECEIPT.md`) |
| RSA / BN IFMA | none | radix-2<sup>52</sup> AVX-512IFMA pairing | PFP-7: `NOT_APPLICABLE_HARDWARE` — no `avx512f`, no `avx512ifma` |

> **Correction (2026-11-27).** The `Arch` cell above and the "lost to Mont"
> framing are superseded by §5.3.1. The implementation uses `mulx` + `adc`
> (not `adcx`), and the controlled comparison is `Arch` against portable
> `Solinas`, not `Arch` against `Mont`. The old text is retained unchanged.

### 2.2 Relation to the §8 recommendation

`docs/PERFORMANCE-FRONTIER.md` §8 recommends fiat-crypto Rust as the portable
reference and oracle, an `s2n-bignum`-grade assembly fast path (adopted or
written and proved), and constant time as a **separate** obligation discharged
on the built DSO. That recommendation is **recorded as the intended direction,
not adopted**:

* it is a decision for the project principal, not for an agent;
* no fiat-crypto, CryptOpt or `s2n-bignum` code is in the tree;
* the current decision is the conservative prerequisite for that route: the
  portable implementation is the oracle and the shipped representation, and
  every kernel carries its own differential and audit at a named digest;
* adopting a third-party or architecture-specific fast path would add a new
  custodian boundary and would require its own per-kernel differential, binary
  audit and constant-time evidence at its own digest. None exists.

### 2.3 What invalidates the decision

1. **A compiler or toolchain change.** The branch audits and the emitted
   instruction streams are specific to rustc 1.98.1 (`48a229cea`) and the
   recorded flags. A different compiler invalidates the audit evidence.
2. **A target or target-feature change.** AArch64, AVX-512/IFMA, AVX2 or a
   hand-written ADX/BMI2 backend needs its own measurement, differential and
   audit. Evidence never transfers.
3. **A new measurement or a measured regression.** A new digest supersedes the
   old evidence; a regression of the selected arm reopens the selection.
4. **A source change to a kernel, its `Domain`, its owner, or a precondition it
   relies on** (for example the `T < m·R` induction or the lazy-representation
   argument).
5. **A new backend or a change to the `FieldKernel`, `MontSchedule` or
   representation contract.**
6. **A change to an evidence instrument** (ctgrind, the binary branch audit, or
   this checker).

---

## 3. Per-kernel table

Each row is a kernel the campaigns touched or admitted. `binding` distinguishes
**artefact-bound** evidence (a named distribution DSO) from **source-bound**
evidence (a test binary or a source review). A `MIXED` row means the audit or
ABI transcript is artefact-bound while the taint run is source-bound. Full
records, including the exact case counts, are in
`forensics/performance/KERNELS.json`.

| kernel (`id`) | source identity | target | artefact sha256 | binding | differential court | audit result (digest) | proof | ships |
|---|---|---|---|---|---|---|---|---|
| CIOS Montgomery (`bn-cias-mont`) | `dedb67a5f` + one-constant `src/bn/arith.rs` (`3e8127cb…`); base arith work committed at `20972901d`, selection uncommitted | x86-64 i9-13900K, rustc 1.98.1 release | `6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39` | MIXED | PFP-6 congruence + CIOS-vs-SOS, 0 mismatches; 161/161 ABI lines (PASS) | `mont_mul_ladder_into` 14 jcc / 18 setcc / 0 cmov, 0 secret-derived (`6d002db2…`) | `NO_PROOF` | CIOS is the ladder default; SOS is the fallback |
| CIOS fixed widths (`bn-cias-fixed`) | `ff87f848` + `src/bn/arith.rs` (`b548ee15…`) | x86-64 i9-13900K, rustc 1.98.1 release | `88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87` | MIXED | M-A1 8,190 per-width + 4,603 fallback pairs, 0 mismatches; 161/161 ABI lines (PASS) | 40 jcc / 64 setcc / 0 cmov, 0 secret-derived (`88c0c7e0…`) | `NO_PROOF` | shipped; widths 6/9/16/32/48/64/128 rest on the structural audit, ctgrind/probe are width 4 |
| SOS reference (`bn-mont-sos`) | PFP-6 `dedb67a5f` + arith; PFP-5 `a005a33c4` + arith | x86-64 | `6d002db2…` (differential); `842efa27…` (audit) | MIXED | PFP-6 SOS congruence 7,890 + SQR-vs-SOS 144/254, 0 mismatches; PFP-5 4,625 comparisons, 0 (PASS) | `mont_mul_sos_into` 19 jcc / 0 div / 0 cmov / 10 setcc, 0 secret-derived — **at `842efa27…`, not `6d002db2…`** | `NO_PROOF` | reference and fallback |
| dedicated squaring (`bn-mont-sqr`) | `76652a46d` + doc-only arith (`66bd6c4c…`) | x86-64 i9-13900K, rustc 1.98.1 release | `661384603e0b661af384997676d8e88843f2b307b6abf73f56d472b03d888630` | MIXED (differential source/ABI; no audit) | SQR congruence 254 + SQR-vs-SOS 144/254, 0 mismatches; A/B/C/D ABI 161/161 (PASS) | **none for the squaring carrier** | `NO_PROOF` | `NOT_SHIPPED` (measured loss) |
| window ladder + scan (`bn-window-ladder`) | `a005a33c4` + arith; `76652a46d` + doc-only arith | x86-64 | `842efa27…` (PASS); `66138460…` (re-audit) | MIXED | PFP-5 3,420 + 1,140 + 65 comparisons, 0 mismatches; 161/161 ABI lines (PASS) | `run_mont_ladder` 100 jcc / 0 div / 2 cmov / 18 setcc, 0 secret-derived (`842efa27…`); identical counts at `66138460…` | `NO_PROOF` | shipped |
| P-256 field engine, Mont (`p256-field-mont`) | `c1d25e10d` (committed) | x86-64 release | `553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4` | ARTEFACT | PFP-22 16,434 cases/subject, nine classes, 0 mismatches (PASS) | DSO ctgrind 0 engine-on-path / 0 engine-origin; branch audit 9/9 exit 0 (`553e1b8c…`) | `NO_PROOF` | shipped default |
| P-256 field engine, Arch (`p256-field-arch`) | PFP-2 engine source | x86-64, test binary | **none — source-bound** | SOURCE | PFP-2 48 cases × 3 kernels (144 comparisons), 0 disagreements (PASS) | **none** (never selected) | `NO_PROOF` | `NOT_SHIPPED`; capability-gated, measured loss |
| P-256 fixed-base comb (`p256-fixed-comb`) | `f8d5c4b33` + `src/ec/p256/fixed_base.rs` | x86-64 release | `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` | ARTEFACT | 4,096 `k·G` + 4,096 `k·P`, 0 mismatches; 256+256 ECDSA cross-verify (PASS) | `mul-g-fixed` 0 errors / 0 contexts; 31/31 + six carriers, no admission-mask jcc (`ecbefb7d…`) | `NO_PROOF` | shipped for the standard P-256 group only |
| P-256 order inverse (`p256-order-inverse`) | `5ac6fddc5` + four uncommitted `src/ec` files | x86-64 release | `4e6ec312313b3f1ef68ec9c0c4fc698a76f334ee9da38a6fcdfa7d8945c53e77` | ARTEFACT | 4,108 + 4,107 + 4,096 in-crate; 4,096 + 4,096 DSO signatures byte-identical (PASS) | 0 engine-on-path / 0 engine-origin; `invert` two public jcc; BINSEC and inverse mutation control `NOT_RUN` (`4e6ec312…`) | `NO_PROOF` | shipped under PFP-3's admission predicate |
| DH width policy (`dh-width-policy`) | `20b655ba9` + `src/{bn/arith,bn/mont,dh/key}.rs`; repair `983437d2` + `src/dh/key.rs` → `dd05d3f4` | x86-64 i9-13900K, rustc 1.98.1 release | `6302e05a14e47b74bd546f03e7509e234a2884511ddec5c3f9a7f4382bd9a25b`; repair `e3ef3d84166a65408e5c89eaa4cc444a2c9208fea5e2acb1c272b6a0b612b187` | MIXED | 103/103 prepared-path comparisons, 0 mismatches, **STOP `PFP8-KEYGEN-PRESET-PRIV`**; repair 45/45, 0 mismatches, residual wide preset (PASS/PASS_WITH_RESIDUAL) | `mont_mul_ladder_into` 40/64/0; `run_mont_ladder` 100/18/2; `bn_mod_exp_mont_impl` 61/4/3; `dh_bn_mod_exp` 3; 0 secret-derived — **at `6302e05a…`, not regenerated for `e3ef3d84…`** | `NO_PROOF` | shipped |
| RSA CRT (`rsa-crt`) | `05ee177a3` (clean) | x86-64 i9-13900K, rustc 1.98.1 release | `6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39` | ARTEFACT | 4,185 lines byte-identical; fault matrix detects `dmp1+1`, `dmq1+1`, `iqmp+1` (PASS) | ctgrind 96,668/112 and 97,546/106, 0 ladder-carrier sites; CIOS 14/18/0, driver 100/18/2 (`6d002db2…`) | `NO_PROOF` | sequential; interleaving refused |

### 3.1 Targets with no evidence, per kernel

`N/A_HW` = `NOT_APPLICABLE_HARDWARE` with the missing feature named; `NOT_RUN` =
the hardware exists but no backend or no evidence was produced. The absent PMU is
a separate limit (§1, §5.2): no timing row here is a PMU measurement.

| kernel | AArch64 | AVX-512/IFMA | AVX2 | ADX/BMI2 |
|---|---|---|---|---|
| `bn-cias-mont` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no backend | `NOT_RUN` — no hand-written backend |
| `bn-cias-fixed` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no backend | `NOT_RUN` — no hand-written backend |
| `bn-mont-sos` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no backend | `NOT_RUN` — no hand-written backend |
| `bn-mont-sqr` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no backend; not shipped | `NOT_RUN` — no backend; not shipped |
| `bn-window-ladder` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no backend | `NOT_RUN` — no hand-written backend |
| `p256-field-mont` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no variant | measured-rejected `Arch`, see below |
| `p256-field-arch` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no variant | `NOT_RUN` — source-bound only; no artefact differential or audit |
| `p256-fixed-comb` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no variant | `NOT_RUN` — no variant |
| `p256-order-inverse` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no variant | `NOT_RUN` — no variant |
| `dh-width-policy` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` | `NOT_RUN` — no backend | `NOT_RUN` — no backend |
| `rsa-crt` | `N/A_HW` — `aarch64` | `N/A_HW` — `avx512f`, `avx512ifma` (IFMA pairing) | `NOT_RUN` — no backend | `NOT_RUN` — no hand-written backend; the ADX build measured only the fused transcription |

### 3.2 Assurance dimensions, not a Boolean (PFP-49)

The register no longer carries `constant_time: true`. Each kernel records an
`assurance` list; each entry names one dimension it can support, binds that
dimension to an evidence record (`evidence` index) and a subject, and states
what was assumed. The classes are complementary, not a ladder, so a kernel may
hold several at once:

| class | additional conjunct the checker requires |
|---|---|
| `UNASSESSED` | nothing is asserted; the scope records why |
| `SOURCE_REVIEWED` | a source identity plus a non-empty written invariant argument (`scope` and `assumptions`), an instrument and an existing `evidence_path` |
| `SOURCE_TAINT_TESTED` | the above plus taint evidence bound to that source identity and a **firing negative control** with an existing evidence path |
| `ARTEFACT_AUDITED` | an artefact subject the checker **hashes itself**, an `ARTEFACT`-bound record, and an audit whose structured `verdict` is `PASS` and whose digest is that subject |
| `ARTEFACT_TAINT_TESTED` | the hashable subject plus `ARTEFACT`-bound taint evidence and a firing negative control |
| `STATISTICALLY_TESTED` | the hashable subject plus a declared experiment (sample count, statistic, threshold, environment) and a result |
| `MACHINE_CHECKED` | a named mechanised tool plus a harness path that exists and a digest the checker re-hashes; a prose proof string is refused |
| `INDEPENDENTLY_REPRODUCED` | a reproduction record naming a party distinct from the producer |

`PASS_WITH_STOP` and `PASS_WITH_RESIDUAL` are admissible only at
`SOURCE_REVIEWED` or below; every stronger dimension must be a clean `PASS`.
A claim names the classes it relies on (`assurance: [...]`); an empty list is a
claim with no assurance dimension, which is a recorded absence, not a pass.

The PFP-49 migration is deliberately conservative. No distribution DSO is
tracked in the repository, so `ARTEFACT_*`, `STATISTICALLY_TESTED`,
`MACHINE_CHECKED` and `INDEPENDENTLY_REPRODUCED` cannot be claimed without
trusting a declared digest. Three kernels hold `SOURCE_TAINT_TESTED`
(`bn-cias-mont`, `bn-cias-fixed`, and the width-policy record of
`dh-width-policy`); the artefact-bound taint records that cannot be re-hashed
are recorded as `SOURCE_REVIEWED` with that limitation in their scope; and
`bn-mont-sqr`, `p256-field-arch` and `rsa-crt` are `UNASSESSED`. The RSA CRT
taint findings outside the ladder carriers are not presented as a clean result.
The per-entry reasoning is in
`evidence/performance-frontier/campaigns/PFP-9/RECEIPT.md` §7.

---

## 4. The no-inheritance rule

**Rule.** Evidence for one target, profile, compiler or artefact never transfers
to another. Each kernel's differential court and audit are bound to the exact
`(target, profile, compiler, source, artefact sha256)` recorded in
`forensics/performance/KERNELS.json`. A claim that cites evidence from a
different identity is refused by `forensics/tools/kernel_verification.py`.

Three consequences that are recorded rather than argued away:

* **A taint run is not a binary audit.** The PFP-5/PFP-6/PFP-8 secret-exponent
  ctgrind readings are source-bound (test binary). The DSO-level ctgrind at
  `553e1b8c` is artefact-bound and does not transfer to any other digest.
* **A digest match is not a source-to-binary refinement claim.** Two clean
  builds reproducing `6d002db2` establish reproducibility of the bytes, not a
  refinement proof.
* **The same DSO can have more than one recorded source identity.** PFP-6 built
  `6d002db2` from `dedb67a5f` plus an uncommitted change; PFP-7 reproduced the
  same digest from clean `05ee177a3`. A claim picks one recorded identity; it
  may not mix the two.

### 4.1 Worked refusals (each is a self-test control)

| claim | identity cited | why it is refused |
|---|---|---|
| SOS artefact-level claim at `6d002db2` | `mont_mul_sos_into` audit at `842efa27` | the audit is at another artefact; the `6d002db2` base-taint probe is not an audit (`KV_CT_CLAIM_WITHOUT_AUDIT`) |
| DH preset-repair artefact-level claim at `e3ef3d84` | branch audit at `6302e05a` | the differential is artefact-bound at `e3ef3d84`, but the audit was not regenerated there (`KV_CT_CLAIM_WITHOUT_AUDIT`) |
| P-256 `Arch` artefact-level claim | source-bound kernel measurement | no artefact digest and no audit (`KV_SOURCE_BOUND_CT_CLAIM`) |
| P-256 comb claim at the pre-fix `04611380` | post-fix differential at `ecbefb7d` | the pre-fix artefact had a secret-derived `je`; the post-fix evidence does not transfer backwards |
| a claim naming a different target or profile from its kernel | kernel evidence record | `KV_TARGET_MISMATCH`, `KV_PROFILE_MISMATCH`, `KV_CLAIM_IDENTITY_MISMATCH` |
| an audit whose digest differs from its evidence record | any kernel | `KV_AUDIT_DIGEST_MISMATCH` |

Historical STOPs remain visible: `PFP3-CT-BRANCH` at `04611380`,
`PFP8-KEYGEN-PRESET-PRIV` at `6302e05a`, and the PFP-4 timing shortfall. They
are not inherited forward as passes.

---

## 5. Limits

### 5.1 Source-bound versus artefact-bound, per kernel

| kernel | differential | audit | taint / probe |
|---|---|---|---|
| `bn-cias-mont` | source-bound in-crate + artefact-bound ABI transcript | artefact-bound `6d002db2` | source-bound exponent taint + artefact-bound base probe |
| `bn-cias-fixed` | source-bound in-crate + artefact-bound ABI transcript | artefact-bound `88c0c7e0` | source-bound width-4 + artefact-bound width-4 base probe |
| `bn-mont-sos` | source-bound in-crate + artefact-bound ABI transcript | artefact-bound `842efa27` (**not** `6d002db2`) | artefact-bound base probe at `6d002db2` (not an audit) |
| `bn-mont-sqr` | source-bound in-crate + artefact-bound ABI transcript | none | source-bound |
| `bn-window-ladder` | source-bound in-crate + artefact-bound ABI transcript | artefact-bound `842efa27`, re-audited at `66138460` | source-bound |
| `p256-field-mont` | artefact-bound `553e1b8c` | artefact-bound `553e1b8c` | artefact-bound `553e1b8c` |
| `p256-field-arch` | source-bound | none | none |
| `p256-fixed-comb` | artefact-bound `ecbefb7d` | artefact-bound `ecbefb7d` | artefact-bound `ecbefb7d` |
| `p256-order-inverse` | artefact-bound `4e6ec312` | artefact-bound `4e6ec312` | artefact-bound `4e6ec312` |
| `dh-width-policy` | artefact-bound `6302e05a` and `e3ef3d84` | artefact-bound `6302e05a` only | source-bound |
| `rsa-crt` | artefact-bound `6d002db2` | artefact-bound `6d002db2` | artefact-bound `6d002db2` |

### 5.2 No PMU, and what that costs

The court exposes no PMU. Every timing figure in these campaigns is a
`SCOPED_OBSERVATION` on a virtualised venue, not a frontier result. Callgrind
instruction counts are a substitute, not retired-instruction or cycle evidence.
A frontier claim requires bare metal with hardware counters, pinned frequency,
turbo and SMT disabled, core isolation, and the microcode and kernel recorded —
on every platform the claim covers.

### 5.3 Rejected arms (named so they are not re-litigated silently)

* **Dedicated squaring** — PFP-6 `REEVALUATION.md` §3–4 and `RECORD.md`: slower
  than reusing the multiply at the PFP-5 window mix (`B/A` 1.0822 at 2048 bits,
  1.0048 at 8192). `LADDER_DEDICATED_SQUARING` stays false.
* **RSA CRT interleaving** — PFP-7 `RECEIPT.md` §3: fused 1.1132×
  [1.1102, 1.1151] slower per multiplication; the only positive ceiling needs
  IPC 6.0; attainable wall change 0.91×.
* **Reduced radix (2<sup>52</sup> deferred carry)** — M-A2 `RESULTS.md` §4:
  3.41–3.44× slower at 256 bits, 1.37–1.40× at 1024 bits; smaller radices add
  limb products and were rejected by the same trend.
* **Karatsuba** — PFP-6 `CROSSOVER.md`: no crossover in 256–4096 bits; the
  transcription also branches on data.
* **P-256 Solinas and Arch kernels** — PFP-2 `kernels/summary.json`: Solinas is
  4.01× slower on `mul`, Arch is 2.99× slower on `mul` and 1.88× slower on the
  ladder than Mont.
* **DH prepared generator table** — PFP-8 `RECEIPT.md`: the best prepared
  window is 2.21 % faster, below the 10 % threshold; the shared secret is 0 %.
* **AVX-512/IFMA pairing** — PFP-7 `BOUND.md`: `NOT_APPLICABLE_HARDWARE`, not a
  negative result.

#### 5.3.1 Correction (2026-11-27) — the `p256::Arch` attribution

The record carried this attribution:

> `p256::Arch` is "the only direct measurement this project has of
> hand-scheduled carry chains against safe Rust, and safe Rust won by about
> three times".

That sentence is **wrong in three independent ways**. It is quoted here rather
than deleted; `docs/PERFORMANCE-FRONTIER-TODO.md` (PFP-50) records the same
sentence as the claim under correction. The PFP-2 numbers themselves are not
in dispute; what they are taken to mean was wrong.

**(1) It is not hand-scheduled.** `src/ec/p256.rs:1046` `wide_mul_x86` is a
Rust schoolbook double loop over two intrinsics:

```rust
out.fill(0);
for i in 0..LIMBS {
    let mut carry = 0u64;
    for j in 0..LIMBS {
        let mut hi = 0u64;
        let lo = _mulx_u64(a[i], b[j], &mut hi);
        let mut lo1 = 0u64;
        let c1 = _addcarry_u64(0, lo, out[i + j], &mut lo1);
        let mut lo2 = 0u64;
        let c2 = _addcarry_u64(0, lo1, carry, &mut lo2);
        out[i + j] = lo2;
        let mut hi1 = 0u64;
        let _ = _addcarry_u64(0, hi, c1 as u64, &mut hi1);
        let mut hi2 = 0u64;
        let _ = _addcarry_u64(0, hi1, c2 as u64, &mut hi2);
        carry = hi2;
    }
    out[i + LIMBS] = carry;
}
```

Two distinct intrinsics, five call sites: `_mulx_u64` once (line 1054) and
`_addcarry_u64` four times (lines 1056, 1058, 1061, 1063). Each carry is the
`u8` returned by `_addcarry_u64`, materialised and added back as a scalar
(`c1 as u64`, `c2 as u64`). There is no `_addcarryx_u64`, no `adcx`/`adox`
pairing, no inline assembly and no hand scheduling; LLVM schedules the loop.
Disassembly of the release DSO `court/tmp/pfp4-a/distribution/libcrypto.so.3`
shows `wide_mul_x86` containing **16 `mulx`, 15 `adc`, 0 `adcx` and 0 `adox`**.
The `adx` target feature is declared on the function but is not exercised by
the code. (The source doc comments at `src/ec/p256.rs:19`, `:946` and `:1033`
still say `mulx`/`adcx` and "two `addcarry` chains"; they are inaccurate and
are left unchanged because this batch makes no production source change.)

**(2) It mixes two variables.** The table compares `Arch` (`mulx` **plus
Solinas reduction**) with `Mont` (Montgomery multiplication and REDC). The
controlled pair is `Arch` against portable `Solinas`, which shares the same
reduction and differs only in the multiply:

| pair | `mul` | ladder | ratio and direction |
|---|---:|---:|---|
| `Arch` / `Solinas` | 61.793 / 82.885 ns | 422.821 / 538.076 ns | `Arch` is **25.4 %** faster on `mul` (1.341×) and **21.4 %** faster on the ladder (1.273×) |
| `Arch` / `Mont` | 61.793 / 20.662 ns | 422.821 / 224.423 ns | `Arch` is **2.991×** slower on `mul` and **1.884×** slower on the ladder |

On the controlled pair the `mulx` multiply **won by about 25 %**. The ~3× loss
belongs to the **Solinas reduction choice** (shared by `Arch` and `Solinas`,
absent from `Mont`), not to carry chains.

**(3) There is a per-call cost.** `wide_mul_x86` is
`unsafe #[target_feature(enable = "bmi2,adx")]` (line 1045) and is called from
`Arch::wide_mul_into` (line 970), a caller without those features; Rust does
not inline such a callee into such a caller. In the same release DSO,
`<Arch as FieldKernel<FieldDomain>>::mul` (`0x3c24d0`) and `::sqr` (`0x3c2b60`)
each contain exactly one `call` to `wide_mul_x86` (symbol at `0x381000`), which
is emitted out of line; the PFP-2 binary audit independently records that
symbol as a 396-byte / 112-instruction function with no calls of its own. The
call therefore occurs once per field multiply on a ~20 ns operation. This is
**measured in the emitted code, not a hypothesis**. (The DSO is an existing
release build of the same source range, `court/tmp/pfp4-a`, not a fresh HEAD
rebuild; the no-inline rule is a language property and the symbol shape is
also recorded by the PFP-2 audit.)

**What remains unmeasured.** **Hand-written ADX with paired `adcx`/`adox`
carry chains has NOT been measured. `NOT_RUN`.** The sentence as written would
close off that untested route, which is why it is superseded rather than merely
reworded.

**The `mulx`-plus-Montgomery experiment is already answered by PFP-48.** The
reviewer's requested experiment — "`mulx` plus Montgomery, inlined, against the
current portable Montgomery kernel" — was run as **PFP-48**: the whole crate
built with `-C target-feature=+bmi2`, so the CIOS Montgomery kernel inlines into
`mont_mul_ladder_into`. Static disassembly: `mulq` **0**, `mulx` **121**,
`adcx` **0**, `adox` **0** (1,911 instructions, −13.0 %). Timing: every workload
equal or slower — `modexp-2048` ×1.0236/×1.0241, `modexp-8192` ×1.0163/×1.0164,
RSA-2048 ×1.0036/×1.0020, DH shared ×1.0215/×1.0163, DH keygen ×1.0116/×1.0154.
PFP-48 answers the **`mulx`-plus-Montgomery-inlined** question; it does **not**
answer the hand-paired ADCX/ADOX question, which remains open (`NOT_RUN`). The
experiment must not be duplicated.

**Corrected interpretation.** The data supports: the ~3× loss in the P-256
table belongs to the Solinas reduction choice, and on the controlled pair the
`mulx` multiply won by about 25 %. It does not support any statement about
hand-scheduled or paired carry chains.

#### 5.3.2 PFP-41 denominator confirmation (2026-11-27)

RSA-2048 CRT must be scored at the **1024-bit operand width (n = 16)**, because
the two CRT halves operate on half-length operands; a full 2048-bit multiply is
n = 32. `evidence/performance-frontier/campaigns/PFP-41/AUDIT.md` reports the
two separately — n = 16: **4,679** instructions (9.14/product); n = 32:
**21,163** instructions (10.33/product) — and its §2 records that the CRT halves
take the n = 16 arm. The RSA-relevant figure is therefore the **n = 16** one.
The audit's headline does not conflate them: it explicitly identifies the
6,457-figure normalisation as "an n=16 count ÷ an n=32 product count" and calls
the "2048-bit" attribution a category error.

### 5.4 Proof status

Every kernel is **`NO_PROOF`**. There is no mechanised functional-correctness
proof and no machine-checked constant-time proof for any kernel. The recorded
bounds (`T < m·R`, the CIOS `T_i < 2m` invariant, the lazy-representation
argument, the Solinas lane bound, the REDC bound) are prose arguments beside
the code, not proofs. The branch audits are enumeration plus local dataflow
review; ctgrind is a taint run; neither is a proof. Kani, Miri (beyond focused
runs), BINSEC `-checkct` and a dudect campaign were **`NOT_RUN`** for these
kernels. A proof would need at least: a mechanised functional-correctness proof
of the kernel, a machine-checked constant-time argument for the emitted code
(or an object-code proof in the `s2n-bignum` style), and a binding from the
proof to the exact source and artefact identity.

The `proof` field is now `NO_PROOF` or `MACHINE_CHECKED`. `MACHINE_CHECKED` is
accepted only when the kernel also carries a `MACHINE_CHECKED` assurance entry
whose harness path exists and hashes to its declared digest; any other string
is refused as an unbound prose claim.

---

## 6. Enforcement

`forensics/tools/kernel_verification.py` validates
`forensics/performance/KERNELS.json` and the kernel names in this document.

```
python3 forensics/tools/kernel_verification.py check
python3 forensics/tools/kernel_verification.py rules
python3 forensics/tools/kernel_verification.py self-test
```

The refusal codes are:

| code | refused |
|---|---|
| `KV_JSON_MALFORMED` / `KV_JSON_DUPLICATE_KEY` / `KV_JSON_NON_FINITE` | unreadable register |
| `KV_SCHEMA` | malformed or wrong-schema entry |
| `KV_DUPLICATE_ID` | duplicate campaign, kernel or claim id |
| `KV_UNKNOWN_CAMPAIGN` | evidence names no registered campaign |
| `KV_EVIDENCE_DIGEST_MISMATCH` | evidence digest differs from the campaign's |
| `KV_TARGET_MISMATCH` | kernel target differs from the artefact's |
| `KV_PROFILE_MISMATCH` | kernel profile differs from the artefact's |
| `KV_AUDIT_DIGEST_MISMATCH` | audit inherited from another digest |
| `KV_PROOF_ABSENT` | proof field blank |
| `KV_NO_EVIDENCE_TARGETS_ABSENT` | no no-evidence target list |
| `KV_NO_EVIDENCE_TARGET_UNDECLARED` | AArch64 / AVX-512/IFMA not declared |
| `KV_CLAIM_UNKNOWN_KERNEL` / `KV_CLAIM_UNKNOWN_EVIDENCE` | claim cites an absent kernel or evidence index |
| `KV_CLAIM_IDENTITY_MISMATCH` | claim cites across target, profile or artefact |
| `KV_CT_CLAIM_WITHOUT_COURT` | constant-time claim with no differential court |
| `KV_CT_CLAIM_WITHOUT_AUDIT` | constant-time claim with no binary audit |
| `KV_SOURCE_BOUND_CT_CLAIM` | constant-time claim on source-bound evidence |
| `KV_ASSURANCE_CLASS_ABSENT` | a claim names an assurance class its kernel does not hold at the cited evidence |
| `KV_ASSURANCE_BINDING_MISMATCH` | an artefact-level class cites evidence that is not purely artefact-bound |
| `KV_AUDIT_VERDICT_NOT_PASS` | an audit record has no structured `PASS` verdict |
| `KV_ASSURANCE_TAINT_ABSENT` | a taint-tested class has no taint evidence bound to its subject |
| `KV_ASSURANCE_NO_FIRING_CONTROL` | taint evidence is claimed without a firing negative control |
| `KV_PROOF_UNBOUND` | the proof field is neither `NO_PROOF` nor a bound `MACHINE_CHECKED` entry |
| `KV_ASSURANCE_OUTCOME_INADMISSIBLE` | `PASS_WITH_STOP` / `PASS_WITH_RESIDUAL` above `SOURCE_REVIEWED` |
| `KV_ARTEFACT_SUBJECT_MISMATCH` | an artefact subject is absent or does not hash to its declared digest |
| `KV_ASSURANCE_INCOMPLETE` | an assurance entry is missing a required field or its evidence path |
| `KV_DOC_KERNEL_MISSING` / `KV_DOC_NO_INHERITANCE_MISSING` | this document does not name a kernel or the rule |

A claim with an empty `assurance` list asserts no dimension; that is a recorded
absence, not a pass. A kernel whose assurance is only `UNASSESSED` is likewise
a recorded absence.

The checker is wired into the gate. `forensics/tools/docs_consistency.py` calls
`kernel_verification.check_root(REPO_ROOT)`, and release-gate item 6 runs
`docs_consistency.py`, so a register the standalone `check` refuses also refuses
the release gate. The `check` CLI remains available for a local run. (The
earlier text that described the checker as a separate command is superseded by
PFP-49, which found that separation to be a gate gap.)

---

## 7. What this document does not establish

* It is not a constant-time proof, a performance classification above
  `SCOPED_OBSERVATION`, or a `SAFE_COMPATIBLE` conclusion.
* It does not claim an AArch64 or AVX-512/IFMA result. Those arms are
  `NOT_APPLICABLE_HARDWARE` and the row **cannot close** on this machine.
* It does not claim a PMU measurement.
* It does not claim that a cited court or audit ran: it checks that the record
  is bound and internally consistent. The instruments must still have run, and
  their own records carry the case counts and limits.
* It does not resolve the open timing obligations (T23, T24, T29), the
  PFP-2 write-back declassification, the PFP-8 wide-preset residual, the PFP-4
  timing shortfall, or the uncommitted-worktree status of several candidates.
