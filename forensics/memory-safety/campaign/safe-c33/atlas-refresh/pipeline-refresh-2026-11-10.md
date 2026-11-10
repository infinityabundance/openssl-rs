# Evidence-pipeline refresh — 2026-11-10

**Kind:** evidence commit (`E`). Candidate source `S` is unchanged.

| | |
|---|---|
| `S` (source candidate) | `9cdb2da99` (`stage/p25/element7-s2b`) |
| build-relevant diff vs `S` | **none** — `src/`, `Cargo.toml`, `Cargo.lock`, `build.rs` byte-identical |
| candidate artefacts | unchanged; `artifacts/phase2/install/lib/libcrypto.so.3` = `1c03ec0a8925f43d…` |
| FRF venue | `debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132`, glibc 2.41, frf 0.1.86, gemel 0.12.0 |

No crate rebuild was performed or required: the source is identical to build
commit `b8bba9555`, so the element-7 address-bound witnesses remain valid.

## Why this refresh was necessary

`static gates` failed at *Evidence determinism* because
`forensics/tools/prerequisite_gate.py` reported **846**
`unwired_function_in_the_current_stratum` findings plus one
`blocking_dependencies` finding (`OSSL_provider_init -> phase 13`).

The cause was not the source. `forensics/phase-state.json` had flipped 23 phases
from `complete` to `in-progress`, because `phase_state.py` requires each phase's
sensitivity-backed FRF claim to record the **current** candidate identity and the
FRF claims recorded `0.0.27` while `Cargo.toml` says `0.0.45`. With the phases
`in-progress`, 846 names that are legitimately modelled differently were being
reported as failures instead of as the non-failing "sealed census".

The version stamp is **generated metadata**: `gen_frf_courts.py` writes
`version_or_commit` from `Cargo.toml` at generation time, and its `--check` mode
reported 143 `differs:` lines. Regeneration — not hand-editing — is the repair.

## What was regenerated, and the observed result

1. **FRF manifests** — `python3 forensics/tools/gen_frf_courts.py`
   (`wrote 286 file(s) for 143 court(s)`), then `--check` → `ok: 286 file(s) match
   the table (143 courts)`. Diff: 143 manifests, one line each
   (`0.0.27` → `0.0.45`); fixtures byte-identical.
2. **ABI court manifest** — `forensics/frf/courts/openssl-abi-surface/manifest.yaml`
   is the one court the generator does not emit; its `version_or_commit` was
   hand-corrected `0.0.2` → `0.0.45` (that single field, nothing else). No claim,
   receipt or residual under `.frf/` was edited by hand.
3. **FRF re-observation** — `bash forensics/frf/run_courts.sh` in the FRF venue:
   `EXIT=0`; 147 court runs and 147 challenges; **0 refusals**;
   `verified: 1197 object(s) … replay_ready: yes`. Claims now record `0.0.45`
   (`0.0.27` count: 0).
4. **Phase-17 downstream corpus** — `courts/phase17/downstream/run_all.sh --build`
   re-measured all six programs at `0.0.45` (`functional=True`, 16/16 concurrency).
   `RT-DOWNSTREAM-CORPUS` now `pass`, `problems: []`.
   `downstream-corpus` contract unit: `implemented`. Phase 17: **complete**.
5. **Phase 21** — the committed `named_source_shape.divergences: 14` was stale;
   the authority-derived value is **27** (read from `forensics/prerequisites.json`,
   27 divergence rows). Regenerated.
6. **Phase 23** — `RT-SECURITY-LINEAGE`/`MULTITRACK-SEAL` failed on stale planes
   (33 problems: 32 *"evidence 'docs/SECURITY_DIVERGENCE_POLICY.md' is not
   content-addressed"*). Regenerated with their own generators
   (`security_lineage.py`, `compat_matrix.py`) → **17/17 pass**.
7. **Unsafe-footprint atlas** — committed `sources_sha256 90860dc0…` (877 files)
   was stale; regenerated → `79602e58…`, 878 files (the added file is
   `src/evp/legacy_digest_callback_surface.rs`, B48).

### Gate movement

| gate | before | after |
|---|---|---|
| `prerequisite_gate.py` findings | 846 + 1 blocker | **0** |
| `blocking_dependencies` | `OSSL_provider_init -> phase 13` | **none** |
| phase-state complete / in-progress | 3 / 23 | **19 / 7** |

## What is still failing — recorded, not masked

The following are **substantive**, not staleness. None was re-based, waived or
edited to pass.

1. **Phase 18 `HOSTILE-BOUNDARY-REGISTER` — the unsafe-site ratchet is firing.**
   Core modules grew **52,943 → 56,239 (+3,296)** since the ceilings were recorded
   at `47325f882` (2026-10-05). Largest deltas: ssl +904, evp +769, provider +454,
   x509 +293, bn +187. Two writers of this document measured the growth's
   composition so the decision is evidence-based rather than assumed:
   - declarations (`unsafe fn`/`impl`/`trait`/`extern`) = **707 (21.5%)**;
   - `unsafe { }` blocks = **2,589 (78.5%)**, and this is *mechanically forced*:
     `unsafe_op_in_unsafe_fn = "deny"` (`Cargo.toml:158`, `src/lib.rs:59`) makes
     every operation inside each new `unsafe fn` body an explicit block;
   - `unsafe extern` grew only **+36**, so this is **not** new ABI export surface;
   - `undocumented_unsafe_blocks = "deny"` and `missing_safety_doc = "deny"`
     (`Cargo.toml:164-165`) force block-level `SAFETY:` documentation: 13,982
     blocks measured across provider/ssl/evp with 8 (0.06%) lexical misses, all
     multi-line-expression artefacts, not lint violations.

   The ceilings are documented as *"the measurements … at the Phase 18
   hostile-hardening revision"*, i.e. a baseline pinned to a revision. Advancing
   that baseline is the designed maintenance action, but it is a **safety-baseline
   decision**, so it is deliberately **not** taken in this commit. It requires a
   per-module justification plus an independent adversarial reviewer (§15), and
   the standing caveat that a `SAFETY:` comment proves presence, not discharge.
2. **Phase 20** — `RT-CUSTODIAN-RESIDUALS` (43 over-bound modules carry no
   disposition; downstream of the phase-18 ratchet) and
   `CUSTODIAN-BOUNDARY-REGISTER` (authored snapshot 6517/63994/58845 vs live
   6516/64003/62458). No generator exists for the register.
3. **Phase 24** — 5 courts need real `--measure` rebuild entry points
   (`RT-HIGH-VALUE-TIER`, `RT-CANDIDATE-FREEZE` identity_hash disagreement,
   `RT-P1000-RUN` 35 vs 307 recipe-backed families,
   `RT-BLOCKER-LEVERAGE`, `DOWNSTREAM-1000-SEAL` 967/1000 DROP_IN_NOT_APPLICABLE).
   Not generated here: fabricating them would be exactly the manufactured green
   result the campaign forbids.
4. **Phase 25** — 7 MS-* courts fail at seal-point scale:
   `MS-SOURCE-CENSUS` 47,205 problems, `MS-OWNERSHIP-PLANES` 584,
   `MS-UNSAFE-REDUCTION` 9, `MS-MIRI` 8, `MS-SEAL` 6,
   `MS-EXPOSURE-CLASSIFICATION` 2, `MS-NON-RUST-TCB` 1
   (`src/runtime/err_variadic.c` recorded `source_sha256` does not match disk).
   AGENTS.md §6 defers full Phase-25 forensic regeneration to seal points.

## Negative evidence preserved

- **Environment reproducibility gap (downstream corpus).** A bare
  `run_all.sh --build` in a fresh court container fails: `git.https` needs
  `fcgiwrap`/`spawn-fcgi`, the OpenSSH harness needs
  `make regress-unit-binaries`, and it needs an authority-linked build at
  `/court/openssh-auth`. Those three provisions live only in the running
  container's `/court` scratch and are **not** in the pinned image. A fresh
  container therefore cannot reproduce the passing corpus without them. This is
  an infrastructure task (AGENTS.md §6: `docker/` is out of conversion scope),
  not a conversion defect — recorded here rather than silently relied upon.
- **Latent bug in `ms_seal`.** `ms_seal._load()` raises `NotDriven`, but
  `phase25_courts.py`'s caller catches only `(OSError, ValueError, KeyError)`, and
  `MS-SEAL` is computed before `write_json(OUT, doc)`. The missing-registry
  crash was masked only because `artifacts/phase25/COURTS.json` had never been
  committed. The tolerance defect remains.
- **Claim-set consolidation.** The re-observation replaced a 21-claim store
  (17 per-partition runtime claims) with the runner's 5-claim set (runtime, abi,
  dgst, inventory, baseline). The 17 were a superseded partition of the same 143
  runtime courts, not distinct evidence; `run_courts.sh` is authoritative for
  claim shape and claims one runtime claim over all 143 receipts.

## Not claimed

This commit does **not** discharge any safety obligation, does not advance any
`SAFE_DISCHARGED` or `SAFE_COMPATIBLE` state, and does not make the required CI
gates pass. Both required checks remain red: `static gates` (evidence
determinism, blocked by the artefacts whose own courts still fail) and
`every active stratum's courts` (phases 18, 20, 24, 25 above).
