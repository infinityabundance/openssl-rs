# Phase 25 — the memory-safety stratum: seal

**STATUS: derived.** This document is **generated** by `forensics/tools/ms_seal.py` from the
committed Phase-25 evidence planes; it is not hand-written, so it cannot drift from them.
`forensics/tools/evidence_determinism.py` re-runs `ms_seal.py` and byte-compares this file.
The stratum's obligation ledger is
`forensics/phase25-obligations.json` — `owned` 22, `implemented`
22, `open_in_this_stratum` 0; the
seal is the last of its twenty-two contract units and the `MS-SEAL` court row is the last of
`artifacts/phase25/COURTS.json`.

## The bounded claim

> the memory-safety-relevant trusted computing base of the exact admitted candidate has been exhaustively inventoried over its first-party shipped source/build surface; unsafe operations are mapped to their safety contracts, Phase-22 reachability, Phase-24 downstream usage and available dynamic/formal evidence, with no unexplained reachable unsafe site in the claimed profile.

It is **not** "no memory-safety bug can exist" and it is **not** "100% memory safe". A
passing seal is an **instrument** plus an **observation record**: the court passes while the
atlas carries open residuals, and the seal records those residuals, the withheld parity claim
and the non-claims as findings, so a green seal is never read as the property it does not
carry (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 3.8). This seal records
`passed = false` because
183 externally reachable site(s) carry tool state
`UNSUPPORTED`, and a tool state of `UNSUPPORTED` is never `PASS` (section 3.6).

- Authority: the admitted venue `openssl-rs-court:1`; the frozen
  candidate is `openssl-rs 0.0.27 (reconstructing openssl-3.6.4-production)`, not live HEAD.
- Court results: `artifacts/phase25/COURTS.json` — 21 Phase-25 courts,
  `all_pass` true, `summary` `pass` 21 of 21, `pending_courts`
  empty. No court is FRF-declarable: each reads committed evidence and stages no
  `artifacts/phase25/probes/<probe>.{authority,candidate}` pair.
- Obligation ledger: `forensics/phase25-obligations.json` — `owned` 22,
  `implemented` 22, `open_in_this_stratum`
  0. Its unit is `memory-safety contract`, a non-export unit.
- Derived state: `forensics/phase-state.json`, phase 25, from artefact existence. It owns no
  exported symbol, so its `atlas_owned` count is 0 and it registers no provider row.

## 1. The courts

One row per landed Phase-25 court (25.0 through 25.20). The verdict is the court's own
re-derived verdict and the finding count is its own, so the row is a re-derivation, not a
reading of `artifacts/phase25/COURTS.json` (which the runner deletes and rewrites). Each
court's committed artefact **evidence** digest is carried by the machine artefact
`artifacts/phase25/summary.json`, whose `courts[].artefact_sha256` is that artefact's
`body_hash` (its evidence digest), not its file digest -- the file digest moves with the
build product the derived planes carry (docs/DECISIONS.md D30), so binding it would make
this seal irreproducible across machines. It is deliberately not restated here, because this
document's own digest is what `forensics/phase-state.json` records as the phase's
`seal_sha256`, and rendering a digest here would form a digest cycle the pipeline could not
reproduce.

| court | unit | verdict | finding(s) | control | artefact |
|---|---|---|---|---|---|
| `MS-CONSTITUTION` | `constitution` | pass | 0 | honest |
 `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` |
| `MS-SOURCE-CENSUS` | `source-census` | pass | 3 | honest |
 `artifacts/phase25/source-census.json` |
| `MS-NON-RUST-TCB` | `non-rust-tcb` | pass | 3 | honest |
 `artifacts/phase25/non-rust-tcb.json` |
| `MS-SAFETY-OBLIGATIONS` | `safety-obligations` | pass | 3 | honest |
 `artifacts/phase25/safety-obligations.json` |
| `MS-OWNERSHIP-PLANES` | `ownership-planes` | pass | 8 | honest |
 `artifacts/phase25/ownership-planes.json` |
| `MS-PHASE22-CROSSWALK` | `phase22-crosswalk` | pass | 4 | honest |
 `artifacts/phase25/phase22-crosswalk.json` |
| `MS-PHASE24-CROSSWALK` | `phase24-crosswalk` | pass | 5 | honest |
 `artifacts/phase25/phase24-crosswalk.json` |
| `MS-EXPOSURE-CLASSIFICATION` | `exposure-classification` | pass | 5 | honest |
 `artifacts/phase25/exposure.json` |
| `MS-UNSAFE-REDUCTION` | `unsafe-reduction` | pass | 3 | honest |
 `artifacts/phase25/unsafe-reduction.json` |
| `MS-MIRI` | `miri` | pass | 4 | honest |
 `artifacts/phase25/miri.json` |
| `MS-ASAN-MSMAN` | `asan-msan` | pass | 0 | honest |
 `artifacts/phase25/asan-msan.json` |
| `MS-TSAN` | `tsan` | pass | 1 | honest |
 `artifacts/phase25/tsan.json` |
| `MS-KANI` | `kani` | pass | 0 | honest |
 `artifacts/phase25/kani.json` |
| `MS-PHASE18-FUZZ-CROSSWALK` | `phase18-fuzz-crosswalk` | pass | 5 | honest |
 `artifacts/phase25/phase18-fuzz-crosswalk.json` |
| `MS-PHASE24-SAFETY-COVERAGE` | `phase24-safety-coverage` | pass | 5 | honest |
 `artifacts/phase25/phase24-safety-coverage.json` |
| `MS-HISTORICAL-CVE` | `historical-cve-census` | pass | 5 | honest |
 `artifacts/phase25/historical-cves.json` |
| `MS-CVE-REPLAY` | `cve-replay` | pass | 4 | honest |
 `artifacts/phase25/cve-replay/index.json` |
| `MS-MECHANISM-RECONCILIATION` | `mechanism-reconciliation` | pass | 5 | honest |
 `artifacts/phase25/mechanisms.json` |
| `MS-RED-TEAM` | `red-team` | pass | 6 | honest |
 `artifacts/phase25/red-team.json` |
| `MS-CLEAN-REGEN` | `clean-regeneration` | pass | 18 | honest |
 `artifacts/phase25/regeneration.json` |
| `MS-FRF-CLOSURE` | `frf-gemel-closure` | pass | 6 | honest |
 `forensics/atlas/phase25/frf-closure.json` |

## 2. The residual census

Every residual the committed planes carry, classified from
`memory_safety_schemas.RESIDUAL_CLASSES` and disposed from `RESIDUAL_DISPOSITIONS`:

- total 495 residual(s): 484 schema record(s) plus
  11 light cross-check leftover(s);
- 484 disposed, 450 open, 0
  undisposed.

By class:

- `evidence_missing`: 390
- `evidence_not_reproducible`: 1
- `historical_cve_unreplayed`: 4
- `join_evidence_missing`: 65
- `mechanism_unreconciled`: 4
- `out_of_scope`: 20
- `tool_not_reachable`: 4
- `tool_unsupported`: 6
- `unexplained_reachable_unsafe`: 1

By disposition:

- `classified`: 1
- `open`: 450
- `preserved`: 33

## 3. The open items

The leftovers the seal does not resolve, named rather than smoothed to a zero:

- **census-geiger-unavailable** (`tool_unsupported`, open): the cargo-geiger cross-check is unavailable
- **census-unresolved-reachability** (`evidence_missing`, open): 18756 census site(s) have no resolved Phase-22 authority mapping and 17747 site(s) are UNKNOWN_REACHABILITY
- **cve-replay-unknown** (`cve_replay_unknown`, open): 4 historical CVE(s) the public ABI cannot express
- **externally-reachable-fail** (`unexplained_reachable_unsafe`, classified): 5 externally reachable site(s) carry tool state FAIL (each dispositioned in its plane)
- **externally-reachable-unsupported** (`tool_unsupported`, open): 183 externally reachable site(s) carry tool state UNSUPPORTED
- **mechanism-reconciliation-open** (`mechanism_unreconciled`, open): 3 HIDDEN and 1 UNRESOLVED mechanism(s)
- **res-tsan-default-libctx-race** (`product_residual`, open): a TSan data race on the default OSSL_LIB_CTX namemap counter
- **rt-phase22-unwitnessed-external** (`red_team_inconclusive`, open): an inconclusive attack over 1009 site(s); an inconclusive attack is not a pass

## 4. Parity

`PARITY_VERIFIED` is **WITHHELD**. docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md requires PARITY_VERIFIED to be withheld: the stratum's courts stage no artifacts/phase25/probes/<probe>.{authority,candidate} pair, so no Phase-25 court is FRF-declarable and no parity between an authority and the candidate is declared here. A memory-safety inventory is not a parity claim.

## 5. The non-claims

- safe Rust does not prove protocol correctness: memory safety is not behavioural correctness, and a sound unsafe site is not a correct protocol
- unsafe Rust is not inherently vulnerable: an unsafe operation with a discharged contract is a sound operation, so an unsafe site is not a defect
- unsafe LOC is not a vulnerability count: lines of unsafe code are a secondary projection of the compiler-derived census, and a count is not a risk
- Miri, ASan and TSan are not exhaustive: a tool that instruments a target records what it observed, and NOT_REACHABLE and UNSUPPORTED are not clean results
- Kani does not prove unsupported or concurrent whole-program behaviour: a proof is only as wide as the harness that expresses it
- historical CVE extinction does not predict a future CVE count: replaying the past is not a statement about an unmeasured future
- compatibility is not security: passing the compatibility strata is not memory safety
- memory safety is not cryptographic correctness: a sound implementation can still be cryptographically wrong
- absence of a crash is not structural proof: a run that did not crash is not a proof that no path can
- Miri, the sanitizers and Kani are complementary evidence, not whole-program proofs: each covers the profile, harness and schedule it ran, and none of them proves the candidate
- matching transcripts are not memory-safety proofs: a differential replay matching the authority is evidence about behaviour, not a proof about memory
- a green instrument is not a proof of absence: a passing court records that the instrument ran and its control was honest, not that no unsafe path exists
- the bounded claim is not a claim that no bug can exist: it is a statement about the inventory of a fixed candidate's first-party surface in the claimed profile

## 6. The two axes

`measurement_state` (the instrument ran) and `property_status` (what is claimed) are
deliberately distinct. This seal's court passes as an instrument while its property is
**NOT_CLAIMED**, and its claim is `complete = false`.
For every count in this document, read
`artifacts/phase25/summary.json` and `docs/SEAL-CENSUS.md`; this seal cites the court records
rather than restating their arithmetic (D97).

