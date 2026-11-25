# PFP-0 re-freeze at staging `2e9c4c5cf` — scoped observation

**Campaign:** `PFP-0-refreeze-2e9c4c5cf`
**Result class:** `SCOPED_OBSERVATION` (not a frontier result, not a candidate)
**Protocol:** the unchanged PFP-0 harness, `courts/phase18/timing/run_bench_api.sh`,
implementing `docs/PERFORMANCE-METHODOLOGY.md`
**Claims record:** `evidence/performance-frontier/claims/PFP-0-refreeze-2e9c4c5cf.claim.json`
**Raw samples:** `evidence/performance-frontier/campaigns/PFP-0-refreeze-2e9c4c5cf/raw/` (146 files, hashed in `raw/SAMPLES.sha256`)
**Analysed result:** `evidence/performance-frontier/campaigns/PFP-0-refreeze-2e9c4c5cf/results.json`

---

## 1. Why this campaign exists

The published PFP-0 and PFP-1 numbers are bound to candidates
`c9a0fdd58429ef13ca9b25ddccbc84a832787277` (DSO `13996603…`) and
`91ac573c0a8e1bc11371718e5f2a6022c55c9535` plus a patch (DSO `596f4833…`).
Neither commit is an ancestor of staging `2e9c4c5cf`, which is 2,633 commits
away. A measurement at this head therefore cannot be differenced against those
figures: the candidate identity, the optimiser input and the code under test all
differ. This campaign establishes a **new basis at a named identity**. It does
not overturn, edit or re-interpret the historical records.

## 2. Source identity

| field | value |
|---|---|
| branch | `staging` |
| source HEAD | `2e9c4c5cff6c431cc44352a475b011fd92df5b93` |
| build-relevant worktree | clean for `src`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml` (the runner refuses otherwise) |
| build recipe | `cargo build --release --lib --offline`, fresh `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS=4` |
| toolchain | as recorded in `build-identity.json` |
| instrument files changed | none; the harness, probe, runner and analyser are used as they are committed at this head |

## 3. Frozen artefacts

| artefact | path | size (bytes) | SHA-256 | build-id |
|---|---|---:|---|---|
| crate archive | `court/tmp/pfp0-refreeze-build/target/release/libopenssl_rs.a` | 44 832 768 | `0ff2f6e6c1a6442d85536efe2b1ded4ae56fd83ae0f8e4d23688af34e1244842` | n/a (archive) |
| **benchmarked candidate** — distribution DSO | `court/tmp/pfp0-refreeze-build/distribution/libcrypto.so.3` | 17 008 472 | `6d7e282d091aedb783d0e55874ed2ce4dab8eaf219f9f5c32653ad4630953b9c` | `2f9022bfe7da74152eb4af47bf93a7e6c38d3708` |
| measurement-only DSO | `court/tmp/pfp0-refreeze-build/measurement/libcrypto.so.3` | 17 384 832 | `3ff3ac59b28e6eacc3641d4fed2c3f7165e3856120e88056148701ebb39709b6` | `1c77671fcdb8cff839feda4b2e5860d26461e9df` |
| compatibility authority | `forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3` | 7 295 816 | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` | `5b4871ce9d78edeafc96f143d7d6697d943ad804` |

The authority is the same file PFP-0 recorded at digest `611e511d…`; it was
hashed before the run. No substitute comparator was used, and no comparator was
substituted with a different build and described as the same one.

The candidate DSO is not committed (`court/tmp` is scratch); the digest and
build-id are, and the recipe in `build-identity.json` reproduces it.

## 4. Instrument identity

| component | SHA-256 |
|---|---|
| `courts/phase18/timing/bench_api.c` | `e1add483b9bee3158e93e2f7d84296441bb2fc5d715cbf27cfd13f80cfde263f` |
| `courts/phase18/timing/alloc_probe.c` | `76b432fd428322e75f068c2d70569a281671207469348628012a389bdae1f446` |
| `courts/phase18/timing/run_bench_api.sh` | `653994bf2e8eba9b39bdd64c73b518a8d86aca048e2ddea2c47b69c5924ebf44` |
| `courts/performance-frontier/baseline/analyse_bench_api.py` | `5182354dfa750d8d0e8949790163f6a02f1f8aad7a6276765d8f1fce5d1d9ab7` |
| `courts/performance-frontier/baseline/extract_dh_fixtures.py` | `bbff92ec3d06e948434a8ffa871d60fef43cdc7b8abb5b61bf02490e6413384b` |
| `courts/performance-frontier/baseline/build_identity.py` | `86dc69de2159521e46736c436fd0e54b6e2790141478306963463de505af5e41` |
| `courts/performance-frontier/baseline/emit_shell.py` | `5290bc716600f2ec95d3975437023b370997d43188fb98edb21fb05cb2b5a7d4` |

The harness, probe and runner digests are identical to PFP-0's. The **analyser
digest is not**: HEAD's revision adds population, ordering and identity refusals.
`bootstrap_median_ci` and `sign_test_p` are byte-identical to the PFP-0 revision,
so the reported statistic and interval are unchanged, but the instrument
identity is not identical and is recorded as such.

Repetitions: **15** measured pairs plus one unrecorded warm-up pair, balanced
pseudo-random order (seed `0x50465030`, realised order in `raw/run-order.tsv`),
each process pinned with `taskset -c 1`. Statistic: **median of the 15 paired
per-repetition ratios** `candidate_us / authority_us`; uncertainty is a percentile
bootstrap (20 000 resamples, seed `0x50465030`), with a Bonferroni family-wise
interval and Holm-Bonferroni over two-sided sign tests. Every process proved
which DSO it mapped (LOADED realpath/device/inode/size against `stat(2)`), and
the realised workload population was matched to `WORKLOADS.json` by identifier.

## 5. Measured table

Subject halves are the median of five timed batch means per process; the
campaign statistic is the median of the 15 paired ratios. `n = 15` pairs per row.

| workload | candidate µs | authority µs | ratio | 95% CI | family-wise CI | rel. MAD c/a | allocs c/a |
|---|---:|---:|---:|---|---|---:|---:|
| `modexp2048` | 5 641.812 | 1 203.678 | 4.688 | [4.650, 4.715] | [4.622, 4.720] | 0.00122 / 0.00612 | 18.0 / 5.0 |
| `modexp8192` | 363 615.887 | 73 775.916 | 4.928 | [4.921, 4.934] | [4.921, 4.936] | 0.00059 / 0.00060 | 18.0 / 5.0 |
| `dh-synth2048` | 5 534.965 | 1 193.699 | 4.630 | [4.625, 4.639] | [4.614, 4.642] | 0.00185 / 0.00126 | 22.0 / 8.0 |
| `dh-synth3072` | 18 901.247 | 3 963.471 | 4.769 | [4.753, 4.781] | [4.747, 4.782] | 0.00182 / 0.00177 | 22.0 / 8.0 |
| `dh-ffdhe2048` | 5 526.014 | 1 191.710 | 4.634 | [4.631, 4.643] | [4.631, 4.653] | 0.00109 / 0.00029 | 22.0 / 8.0 |
| `dh-ffdhe3072` | 18 913.140 | 3 973.748 | 4.760 | [4.739, 4.780] | [4.737, 4.781] | 0.00119 / 0.00366 | 22.0 / 8.0 |
| `dh-modp2048` | 5 526.160 | 1 191.458 | 4.640 | [4.635, 4.645] | [4.630, 4.646] | 0.00156 / 0.00028 | 22.0 / 8.0 |
| `rsa2048` | 1 877.568 | 353.580 | 5.329 | [5.281, 5.348] | [5.262, 5.364] | 0.00195 / 0.00638 | 164.2 / 19.0 |
| `ecdsa256` | 446.311 | 12.722 | 35.040 | [34.662, 35.120] | [34.569, 35.150] | 0.00312 / 0.00165 | 273.4 / 29.0 |

Correctness evidence inside the instrument: the 15 repetitions each produced
`CHECK` lines identical to the authority's for all nine workloads, and ECDSA
signatures were exchanged in both directions at repetitions 00, 03, 06, 09, 12
and 14 (12/12 verified, identical public key). Allocation counts are
`malloc_class_per_op`; the unified `allocs_per_op` is identical, so this probe
observed no `aligned_alloc`, `posix_memalign` or `memalign` in these operations.

## 6. What this establishes and what it does not

**Establishes.** At candidate DSO `6d7e282d…` against authority DSO
`611e511d…`, on this virtualised court, with the recorded instrument, the nine
paired ratios above, with their bootstrap intervals, from 15 paired repetitions
whose identity, population and correctness checks all passed.

**Does not establish.** It does not discharge T23, T24, T29 or any timing
obligation; it says nothing about constant-time behaviour; it is not a frontier,
competitive or parity claim; it does not measure throughput, tails, scaling,
memory or energy; and it carries no differential court and no passing binary
branch audit at this digest.

**Not comparable to PFP-0/PFP-1.** No delta between these ratios and the
historical PFP-0/PFP-1 figures is computed or presented anywhere in this
campaign. `results.json` contains a `discrepancies` array that the analyser
emits automatically against the `previous_reported` fields frozen in
`WORKLOADS.json`; those figures are bound to other candidates, and that array is
**not** used for any conclusion here and must not be read as a trend. The same
file also carries the harness's hard-coded `campaign: "PFP-0"` label; the
directory name, this receipt and the claim record are what identify the
candidate actually measured.

## 7. Binary branch audit attempt

`courts/phase18/timing/binary_branch_audit.py --expect-sha256 6d7e282d… ` was run
against the built distribution DSO. It exited **1** (fail-closed):
`REFUSED target="Constant-time ladder core" symbol="mod_exp_core_consttime_from_parts" reason=missing`
— 1 of 7 inventory targets was refused. The symbol exists in `src/bn/arith.rs`
but is not a separate symbol in this DSO; the built object carries
`_RNvNtNtCsfBoMNNx3tZr_10openssl_rs2bn5arith42mod_exp_core_consttime_from_parts_prepared`,
so the inventory does not cover this DSO's symbol population. The report is
retained as `binary-branch-audit.md` / `binary-branch-audit.stderr` and is **not**
a gate result.

## 8. Venue and resource record

| item | value |
|---|---|
| venue class | `VIRTUALISED_COURT`, `pmu_exposed: false` |
| court | `openssl-rs-court-tools:1`, container `openssl-rs-court`, cgroup `memory.max` 8 589 934 592 bytes |
| PMU observation | `cpuid.1 hypervisor_present=1`, `cpuid.0A num_general_counters=0`, `cpu_event_source=absent`, `perf stat -e cycles` → `<not supported>` |
| host `available` before the run | 26 GiB; cap = min(8 GiB, 26 − 16) = 8 GiB |
| court cgroup `memory.peak` after the campaign | 3 131 699 200 bytes (≈ 2.92 GiB), about 36 % of the cap; no incident, no OOM event |
| wall time | 225.0 s total (build, link, harness build, 16 timed pairs, allocation pass, analysis); the 34 logged processes (2 warm-up, 30 measured timing, 2 allocation) span 195.4 s (candidate 164.1 s, authority 30.8 s) |
| parallelism | `CARGO_BUILD_JOBS=4`; one heavy command at a time |

## 9. Validation run

```
python3 forensics/tools/performance_classification.py check
OK .../claims/PFP-0-refreeze-2e9c4c5cf.claim.json
OK .../claims/PFP-0.claim.json
OK .../claims/PFP-1.claim.json
performance-classification: 3 record(s) accepted, 0 refused
```

## 10. Files written

| path | purpose |
|---|---|
| `evidence/performance-frontier/campaigns/PFP-0-refreeze-2e9c4c5cf/` | this campaign: `raw/` (samples + `SAMPLES.sha256`), `results.json`, `build-identity.json`, `preregistration.json`, `venue.txt`, `cross-verification.tsv`, `fixtures/`, `binary-branch-audit.md`, `binary-branch-audit.stderr` |
| `evidence/performance-frontier/claims/PFP-0-refreeze-2e9c4c5cf.claim.json` | the claim record at `SCOPED_OBSERVATION` |
| `evidence/performance-frontier/admission/ARMS.json` | one new `EXPERIMENT` arm |
| `forensics/tools/tests/test_performance_admission.py` | the committed-register test located its arm by id instead of asserting the register holds exactly one arm |

No file under `src/`, `docker/` or `AGENTS.md` was touched. The historical
PFP-0 and PFP-1 records and receipts were not modified.

**Known consequence: two frozen scans now require a re-freeze.**
`evidence/a11/SCAN.json` and `evidence/a16/INVENTORY.json` each freeze a digest
for `evidence/performance-frontier/admission/ARMS.json` (`18d29f8e…`). Adding an
arm changes that member, and both freeze verifiers refuse on a changed member.
Observed after the edit:

```
python3 forensics/tools/harden.py scan --frozen evidence/a11/SCAN.json
scan: code=PH_REFUSED_POPULATION_DRIFT changed: evidence/performance-frontier/admission/ARMS.json:
  sha256 f4803073ed5ff3378d294a109a056c12fa1a62f77e68f089a9d8b618471a396d != frozen 18d29f8e…
exit=1

python3 forensics/tools/sigstore_bundle.py inventory
PH_REFUSED_POPULATION_DRIFT: changed: … ARMS.json: sha256 f4803073… != declared 18d29f8e… outcome=NOT_RUN
exit=1
```

This is drift, not a defect in either validator: a frozen population member
changed after the freeze. The remedy is a deliberate A11/A16 re-freeze bound to
the commit that contains this campaign, and it was not performed here — a
re-freeze binds `baseCommit`, and this session does not commit. Until the
orchestrator performs it, both scans are `NOT_RUN`, not passing. The new claim
record and the new campaign files are *additions* and are reported by the freeze
verifiers as `NEW_SINCE_RECORD`, which is growth, not drift.

The register's `producer.inputs` was left as the PFP-19 record of the tool's
inputs; the new arm carries its own digest-bound references
(`measurement.record`, `constant_time_audit.reference`) so nothing it cites is
unbound.
