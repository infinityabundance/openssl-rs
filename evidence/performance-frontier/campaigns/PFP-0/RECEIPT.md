# PFP-0 receipt — performance baseline reconstruction

**Campaign:** `PFP-0`
**Result class:** `SCOPED_OBSERVATION` (not a frontier result)
**Protocol:** `docs/PERFORMANCE-METHODOLOGY.md` (preregistered)
**Raw samples:** `evidence/performance-frontier/campaigns/PFP-0/raw/`
**Analysed result:** `evidence/performance-frontier/campaigns/PFP-0/results.json`

---

## 1. Source identity

| field | value |
|---|---|
| repository branch | `staging` |
| source HEAD at start | `c9a0fdd58429ef13ca9b25ddccbc84a832787277` |
| build-relevant worktree at start | clean for `src/`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml` |
| harness worktree | the tracked harness files below were modified/added for this campaign; their digests are in `build-identity.json` |
| build recipe | `cargo build --release --lib --offline`, fresh `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS=4` |
| toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`, `cc (Debian 12.2.0-14+deb12u1) 12.2.0` |

The library identity is `S = c9a0fdd58` plus the harness digests recorded in
`build-identity.json`. The orchestrator's evidence commit makes that binding
durable; no source file was changed by this campaign.

Memory guard: `free -g` reported 29 GiB available before the campaign and 28 GiB
immediately before the measured run; the court cgroup was capped at 6 GiB
(`memory.max = 6 442 450 944`), and the build and the benchmark ran sequentially,
one heavy command at a time. `CARGO_BUILD_JOBS=4`; the harness was pinned with
`taskset -c 1`.

---

## 2. Frozen artefacts

| artefact | path | size (bytes) | SHA-256 | build-id |
|---|---|---:|---|---|
| crate archive | `court/tmp/pfp0-build/target/release/libopenssl_rs.a` | 44 824 264 | `f8f605857d99bab19623b3302317867d801ec53b8af7b89175c6772dbdda4f1e` | n/a (archive) |
| **benchmarked candidate** — distribution DSO | `court/tmp/pfp0-build/distribution/libcrypto.so.3` | 17 005 192 | `139966033ac9e935efc76290a9df9e91441aa2ea9f183a00089eb95e32093c0c` | `39bfc4588d3fa6cbee2b9821663fd669d7651b33` |
| measurement-only DSO | `court/tmp/pfp0-build/measurement/libcrypto.so.3` | 17 381 552 | `85395dcf7b7670503dc617b45801a85877b5884f543120a0fca711ca6c7a240a` | `77bbdedc819b0ab7bd66eb7c8e064e4a05ffc803` |
| compatibility authority | `forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3` | 7 295 816 | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` | `5b4871ce9d78edeafc96f143d7d6697d943ad804` |

The distribution DSO differs from the measurement-only DSO because it is linked
with the Phase-2 shell object and the tracked version script. The **distribution
DSO is the one benchmarked**; the measurement DSO digest is carried for identity
comparison only.

The pre-existing `artifacts/phase2/install/lib/libcrypto.so.3`
(`fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9`, build-id
`592a81d4ae5e7e02bfc635ff8bcd4fbdde37de70`) and the pre-existing
`target/release/libopenssl_rs.a`
(`083b4539e86e58791771db857108a65cdc1b8c855260f251cf8f80e690a8269d`) were **not**
used: both predate the frozen archive. The campaign rebuilt from the frozen tree
into `court/tmp/pfp0-build`, so neither stale artefact contributes a number.

The DH fixtures were derived from the tracked arrays in `src/bn/dh_data.rs`
(source SHA-256 `1887a18b15c7eda2caee4956905fc0d3a8d37d7b2d4c26e6995a14f904a22505`)
by `courts/performance-frontier/baseline/extract_dh_fixtures.py`, which checks
`p == 2*q + 1`, `p mod 8 == 7` and the declared array lengths before writing
`ffdhe2048.hex`, `ffdhe3072.hex` and `modp2048.hex`. The manifest is
`fixtures/dh-fixtures.json`.

---

## 3. Loaded-artefact verification

Every process printed the mapped DSO's realpath, device, inode and size from
`/proc/self/maps`, and the runner compared those fields with `stat(2)` on the
expected on-disk file. A mismatch was a refusal.

- checks performed: **58** (15 repetitions × 2 subjects, plus warm-up, allocation
  and cross-verification processes);
- checks failed: **0**;
- every candidate process mapped inode `1627750`, device `57`, size `17 005 192`,
  the distribution DSO;
- every authority process mapped inode `325854`, device `57`, size `7 295 816`,
  the pinned `611e511d` DSO;
- every process had at least one `/proc/self/maps` entry for the resolved path.

Evidence: `raw/identity-check.tsv`; summary in
`results.json.identity.loaded_verification`.

---

## 4. The nine methodological defects

| # | before | after | demonstration |
|---|---|---|---|
| 1 | candidate then authority, every run | balanced pseudo-random order within each repetition, 8 candidate-first / 7 authority-first, fixed before execution | `cat raw/run-order.tsv`; order reproduced in `results.json.ordering` |
| 2 | five batch medians presented as a result | 15 process-level repetitions fixed before execution; paired ratios, bootstrap 95% interval, family-wise interval, relative MAD | `results.json.protocol`, `results.json.timing.*.n_pairs = 15` |
| 3 | allocation probe applied to the candidate only | the same probe and workload list applied to candidate and authority; unified `allocs_per_op` and legacy `malloc_class_per_op` reported for both | `grep '^ALLOC' raw/alloc-candidate.out raw/alloc-authority.out` |
| 4 | no verification of the loaded DSO | per-process `LOADED` realpath/device/inode/size and `MAPS` entry count, compared with `stat(2)`; 58/58 passed | `raw/identity-check.tsv`; `results.json.identity.loaded_verification` |
| 5 | result-line count equality | exact workload identifier set from `forensics/performance/WORKLOADS.json`, once each; missing, duplicate or extra ids make the campaign BLOCKED | `results.json.population`; `raw/population-*.diff` are empty |
| 6 | synthetic odd-composite DH only | real RFC 7919 FFDHE-2048/3072 and RFC 3526 MODP-2048 rows added from tracked bytes; the synthetic rows remain, labelled synthetic | `fixtures/dh-fixtures.json`; ids `dh-synth*` and `dh-ffdhe*`/`dh-modp2048` in `results.json.timing` |
| 7 | one initial ECDSA self-check | 12 cross-library exchanges at repetitions 00, 03, 06, 09, 12, 14: candidate→authority and authority→candidate, all `ok=1`, all public keys identical | `cat cross-verification.tsv` |
| 8 | benchmark DSO possibly not the distribution artefact | the distribution-shaped DSO (shell object + version script) is benchmarked; the measurement DSO digest is carried separately | `build-identity.json` artefact table |
| 9 | stale archive reuse possible | fresh `CARGO_TARGET_DIR` and `cargo build --release --lib --offline` from the frozen tree; archive digest recorded; the tracked implemented surface was recomputed and its symbol sets compared | `build-identity.json`; `shell_generation.tracked_surface_matches_fresh = true` |

### Demonstration commands

```sh
# 1. realised balanced order
awk -F '\t' '{print $2}' evidence/performance-frontier/campaigns/PFP-0/raw/run-order.tsv | sort | uniq -c

# 2. preregistered repetitions and paired ratios
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/preregistration.json
python3 -c 'import json; d=json.load(open("evidence/performance-frontier/campaigns/PFP-0/results.json")); print({k: v["n_pairs"] for k, v in d["timing"].items()})'

# 3. the same allocation instrument on both subjects
grep '^ALLOC' evidence/performance-frontier/campaigns/PFP-0/raw/alloc-candidate.out
grep '^ALLOC' evidence/performance-frontier/campaigns/PFP-0/raw/alloc-authority.out

# 4. loaded-artefact verification
awk -F '\t' 'NR > 1 {print $2, $11}' evidence/performance-frontier/campaigns/PFP-0/raw/identity-check.tsv | sort | uniq -c

# 5. exact population identifiers (all diffs are empty)
for f in evidence/performance-frontier/campaigns/PFP-0/raw/population-*.diff; do test ! -s "$f" || echo "NONEMPTY $f"; done

# 6. real group fixtures derived from tracked bytes
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/fixtures/dh-fixtures.json

# 7. both cross-verification directions
cat evidence/performance-frontier/campaigns/PFP-0/cross-verification.tsv

# 8. distribution DSO versus measurement DSO
python3 -c 'import json; d=json.load(open("evidence/performance-frontier/campaigns/PFP-0/build-identity.json")); print(d["artefacts"]["distribution_dso"]); print(d["artefacts"]["measurement_dso"])'

# 9. fresh archive and fresh-surface shell
python3 -c 'import json; d=json.load(open("evidence/performance-frontier/campaigns/PFP-0/build-identity.json")); print(d["artefacts"]["crate_archive"]); print(d["shell_generation"]["shell_used"], d["shell_generation"]["tracked_surface_matches_fresh"])'
```

### Notes on defects 8 and 9

The tracked `forensics/atlas/implemented-surface.json` names an older archive
digest (`8d7543ca…`), while the frozen build produced
`f8f605857d…`. Its **implemented symbol sets still match** the fresh derivation
exactly (`libcrypto` 5 896, `libssl` 603), so the shell is not stale in the
symbols it emits. The shell was nevertheless generated from the fresh surface,
not from the tracked file, and the record says so:
`build-identity.json.shell_generation.shell_used = "fresh"`. The fresh surface's
`body_hash` differs only because it names the campaign build path rather than
`target/release`.

The older `ARCHIVE` and `REBUILD_CANDIDATE` overrides are not accepted by the
PFP-0 runner: an externally supplied archive would bypass the frozen-build rule
and could not be bound to `S`.

---

## 5. Comparator inventory

| comparator | intended identity | observed in this environment | row status |
|---|---|---|---|
| OpenSSL 3.6.4 production | admitted production build, `linux-x86_64`, shared, `enable-legacy`, assembly default | present at the pinned prefix; DSO `611e511d…` | `MEASURED` |
| AWS-LC | a pinned `aws/aws-lc` commit (not pinned here) | no source, library, header or offline crate | `UNAVAILABLE` |
| BoringSSL | a pinned `chromium/boringssl` commit (not pinned here) | no source or library | `UNAVAILABLE` |
| rustls + named provider | a pinned rustls/provider pair (not pinned here) | no source in the offline registry; no OpenSSL C ABI | `NOT_APPLICABLE_FOR_C_API_HARNESS` |
| wolfSSL | a pinned release built with `--enable-opensslextra` | no source, library or header | `UNAVAILABLE` |
| research-frontier kernel | a specific pinned kernel plus a driver (not selected here) | no source; not a complete libcrypto | `NOT_APPLICABLE_FOR_C_API_HARNESS` |
| distribution OpenSSL 3.0.22 | not an admitted comparator | present at `/lib/x86_64-linux-gnu/libcrypto.so.3` (`aa01e614…`) | observed, not measured |

No comparator row contains a placeholder number. The absence of a comparator is
recorded as absence, not as a win. Full acquisition paths and build-profile
requirements are in `forensics/performance/AUTHORITIES.json`.

---

## 6. Measured table

Subject halves are the median of five timed batch means per process; the campaign
statistic is the median of the 15 paired per-repetition ratios. Intervals are
percentile bootstrap (20 000 resamples, seed `0x50465030`). `n = 15` pairs for
every row. The ratio column is the **paired** statistic, not the ratio of the two
displayed medians; the two differ slightly and the paired value is the
preregistered one.

| workload | candidate µs | authority µs | ratio | 95% CI | family-wise CI | rel. MAD c/a | allocations c/a |
|---|---:|---:|---:|---|---|---:|---:|
| `modexp2048` | 5 599.835 | 1 198.999 | 4.668 | [4.632, 4.691] | [4.627, 4.691] | 0.00347 / 0.00298 | 18 / 5 |
| `modexp8192` | 370 314.851 | 73 831.170 | 5.016 | [5.012, 5.020] | [5.011, 5.021] | 0.00041 / 0.00054 | 18 / 5 |
| `dh-synth2048` | 5 590.839 | 1 192.535 | 4.679 | [4.670, 4.706] | [4.664, 4.712] | 0.00316 / 0.00092 | 27 / 8 |
| `dh-synth3072` | 18 484.075 | 3 957.249 | 4.673 | [4.666, 4.682] | [4.652, 4.684] | 0.00070 / 0.00120 | 27 / 8 |
| `dh-ffdhe2048` | 5 587.435 | 1 191.383 | 4.686 | [4.685, 4.699] | [4.671, 4.699] | 0.00206 / 0.00039 | 27 / 8 |
| `dh-ffdhe3072` | 18 478.981 | 3 962.123 | 4.663 | [4.646, 4.674] | [4.633, 4.676] | 0.00040 / 0.00248 | 27 / 8 |
| `dh-modp2048` | 5 591.337 | 1 191.748 | 4.687 | [4.672, 4.706] | [4.668, 4.708] | 0.00292 / 0.00054 | 27 / 8 |
| `rsa2048` | 1 921.160 | 352.318 | 5.458 | [5.422, 5.469] | [5.404, 5.475] | 0.00132 / 0.00393 | 173 / 19 |
| `ecdsa256` | 441.007 | 12.733 | 34.651 | [34.563, 34.716] | [34.521, 34.810] | 0.00115 / 0.00173 | 277 / 29 |

Allocation counts are `malloc_class_per_op` (the legacy
`malloc`/`calloc`/`realloc` definition). The unified
`allocs_per_op` count is identical for every row and subject, because this probe
observed no `aligned_alloc`, `posix_memalign` or `memalign` calls in these
operations. The per-operation allocation ratios are 3.60 (`modexp*`), 3.38
(`dh*`), 9.11 (`rsa2048`) and 9.55 (`ecdsa256`).

Holm-Bonferroni over the nine two-sided sign tests gives an adjusted p of
`5.49e-4` for every row (the unadjusted sign-test p is `6.10e-5`, the smallest
value attainable with 15 same-direction pairs). This establishes only that the
measured ratios are consistently on one side of one in this sample; it does not
promote any row to `AHEAD`, and no row is a frontier result.

The allocation counts cover libc allocation entry points visible to the probe.
They do not count `mmap` mappings or allocator-internal activity, and they do
not classify which bytes are secret.

---

## 7. Discrepancies against previously reported numbers

The current programme table is `docs/PERFORMANCE-FRONTIER.md` §1. The historical
T21 table is `court/tmp/t21/NOTES.md` at source `3ea7a3c77`; it measured a
different source and a measurement-only DSO. Both are published below. A row is
not adjusted to match an older value.

| workload | source | previous ratio | measured ratio | delta | previous inside 95% CI | direction |
|---|---|---:|---:|---:|---|---|
| `modexp2048` | PERFORMANCE-FRONTIER §1 | 4.63 | 4.668 | +0.82% | no (lower bound 4.632) | candidate worse |
| `modexp2048` | T21 NOTES | 4.59 | 4.668 | +1.70% | no | candidate worse |
| `modexp8192` | PERFORMANCE-FRONTIER §1 | 4.90 | 5.016 | +2.36% | no | candidate worse |
| `modexp8192` | T21 NOTES | 5.00 | 5.016 | +0.32% | no | candidate worse |
| `dh-synth2048` | PERFORMANCE-FRONTIER §1 (`dh2048`) | 4.64 | 4.679 | +0.83% | no | candidate worse |
| `dh-synth2048` | T21 NOTES (`dh2048`) | 4.64 | 4.679 | +0.83% | no | candidate worse |
| `dh-synth3072` | PERFORMANCE-FRONTIER §1 (`dh3072`) | 4.77 | 4.673 | −2.03% | no | candidate better |
| `dh-synth3072` | T21 NOTES (`dh3072`) | 4.71 | 4.673 | −0.78% | no | candidate better |
| `dh-ffdhe2048` | none | — | 4.686 | — | — | new row |
| `dh-ffdhe3072` | none | — | 4.663 | — | — | new row |
| `dh-modp2048` | none | — | 4.687 | — | — | new row |
| `rsa2048` | PERFORMANCE-FRONTIER §1 | 5.43 | 5.458 | +0.51% | yes | candidate worse |
| `rsa2048` | T21 NOTES | 5.38 | 5.458 | +1.45% | no | candidate worse |
| `ecdsa256` | PERFORMANCE-FRONTIER §1 | 34.71 | 34.651 | −0.17% | yes | candidate better |
| `ecdsa256` | ETP-TODO T29 (DSO `700135fa`) | 34.70 | 34.651 | −0.14% | yes | candidate better |
| `ecdsa256` | T21 NOTES (source `3ea7a3c77`) | 82.76 | 34.651 | −58.13% | no | candidate better |

For `modexp2048`, the previous 4.63 lies outside the unadjusted 95% interval
[4.632, 4.691] but inside the family-wise interval [4.627, 4.691]; both intervals
are reported rather than choosing the more favourable one. The other “no” rows
lie outside both intervals unless stated otherwise.

Allocation discrepancies:

| workload | previous candidate / authority | measured candidate / authority | note |
|---|---|---|---|
| `modexp2048` | 18 / 5 | 18 / 5 | matches both references |
| `modexp8192` | 18 / 5 | 18 / 5 | matches both references |
| `dh-synth2048` | 27 / 8 (programme); 32 / 8 (T21) | 27 / 8 | matches the programme table; T21 measured a different source |
| `dh-synth3072` | 27 / 8 (programme); 32 / 8 (T21) | 27 / 8 | matches the programme table; T21 measured a different source |
| `dh-ffdhe2048` | — | 27 / 8 | new row |
| `dh-ffdhe3072` | — | 27 / 8 | new row |
| `dh-modp2048` | — | 27 / 8 | new row |
| `rsa2048` | 173 / 19 (programme); 238.2 / 19 (T21) | 173 / 19 | matches the programme table; T21 measured a different source |
| `ecdsa256` | 276 / 29 (programme, T29); 75 344.2 / 29 (T21) | 277 / 29 | 1 allocation above the programme figure; the T21 figure predates the fixed-scratch workspace |

### Additional out-of-band observation

An uncommitted `court/tmp/t21` run on 2026-11-22 00:35, using a measurement-only
DSO at `78dec1c2…`, reported `ecdsa256` at 51.5× and 278.2 candidate allocations.
The frozen PFP-0 distribution DSO reports 34.65× and 277 allocations, which is
consistent with the committed T29 note and the programme table. The 51.5×
scratch result is not reproducible under the frozen source/harness and is not
treated as a previously reported number; it is recorded here rather than
silently discarded.

---

## 8. Venue and PMU

- court image: `openssl-rs-court-tools:1`, container hostname `c61c1a25df26`;
- host kernel `7.3.5-2-cachyos`, `x86_64`;
- CPU: 13th Gen Intel Core i9-13900K;
- cgroup memory limit `6 442 450 944` bytes (6 GiB), CPU quota `800000 100000`
  (8 CPUs), one core pinned with `taskset -c 1`;
- `nproc` reports 30; the process is constrained by the cgroup and the pin.

PMU answer: **no usable hardware PMU is exposed**.

- `/sys/bus/event_source/devices` has no `cpu` source; it lists only
  `breakpoint`, `kprobe`, `msr`, `power`, `software`, `tracepoint`, `uprobe`;
- `cpuid.0A.version = 0`, `num_general_counters = 0`;
- `cpuid.1 hypervisor_present = 1`;
- `cpuid.80000001 PerfCtrExtCore_edx_bit22 = 0`;
- `perf stat -e cycles true` reports `<not supported>`;
- `perf stat -e task-clock true` works, but it is a software event, not a PMU
  counter.

Because the venue has no exposed PMU, no frequency/turbo/SMT control, and no core
isolation beyond the pin, every row is `SCOPED_OBSERVATION`. The ratios are
useful for direction and relative size on this venue; they are not a frontier
claim.

---

## 9. Files written

| path | purpose |
|---|---|
| `forensics/performance/WORKLOADS.json` | frozen workload population, provenance, expected line counts and security contracts |
| `forensics/performance/AUTHORITIES.json` | comparator inventory, availability, build profiles and acquisition paths |
| `docs/PERFORMANCE-METHODOLOGY.md` | preregistered protocol |
| `evidence/performance-frontier/campaigns/PFP-0/preregistration.json` | realised protocol parameters, generated before measurement |
| `evidence/performance-frontier/campaigns/PFP-0/build-identity.json` | source/artefact identity for the frozen campaign |
| `evidence/performance-frontier/campaigns/PFP-0/venue.txt` | venue and cgroup record |
| `evidence/performance-frontier/campaigns/PFP-0/fixtures/` | DH group fixtures and their manifest |
| `evidence/performance-frontier/campaigns/PFP-0/raw/` | every raw process output, run order, identity checks, PMU probes, build log |
| `evidence/performance-frontier/campaigns/PFP-0/cross-verification.tsv` | ECDSA cross-library exchanges |
| `evidence/performance-frontier/campaigns/PFP-0/results.json` | analysed result |
| `courts/phase18/timing/bench_api.c` | real-group DH rows, loaded-artefact reporting, cross-sign/cross-verify, unified allocation line |
| `courts/phase18/timing/alloc_probe.c` | unified allocation-entry counting while preserving the legacy malloc-class count |
| `courts/phase18/timing/run_bench_api.sh` | PFP-0 campaign runner |
| `courts/phase18/timing/README.md` | updated description of the instrument |
| `courts/performance-frontier/baseline/extract_dh_fixtures.py` | tracked-byte DH fixture derivation |
| `courts/performance-frontier/baseline/build_identity.py` | artefact and source identity recorder |
| `courts/performance-frontier/baseline/emit_shell.py` | fresh-surface shell generation with tracked/fresh comparison |
| `courts/performance-frontier/baseline/analyse_bench_api.py` | preregistered statistics and results writer |

No file under `src/`, `docker/`, or another item's receipt was modified.

### Development attempts before the measured campaign

Three harness-development attempts preceded the measured campaign:

1. the first failed before measurement because `implemented_surface.py` requires
   the crate archive to be inside the repository; the build directory was moved
   from `/court/pfp0-build` to `court/tmp/pfp0-build`;
2. the second failed before measurement on a shell `local` self-reference
   (`rep: unbound variable`) in `compare_checks`; the declaration was split;
3. the third completed and is the campaign recorded here.

Attempts 1 and 2 produced no `RESULT` or `ALLOC` lines and are not measurement
evidence. The deterministic order was regenerated identically for the successful
run; `PFP0_FORCE=1` was used only to clear the pre-measurement artefacts of the
failed attempts. No `BLOCKED` marker is present in the campaign directory.

---

## 10. JSON validation

All of the following returned success:

```sh
python3 -m json.tool forensics/performance/WORKLOADS.json >/dev/null
python3 -m json.tool forensics/performance/AUTHORITIES.json >/dev/null
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/results.json >/dev/null
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/build-identity.json >/dev/null
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/preregistration.json >/dev/null
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/fixtures/dh-fixtures.json >/dev/null
```

---

## 11. Evidence digests

The population, protocol and analysed result are bound by these SHA-256 values:

| file | SHA-256 |
|---|---|
| `forensics/performance/WORKLOADS.json` | `1d33143a7ee97208c25da95dadd0c7eafcce300794f71a78e6f6b3da60d7fa88` |
| `forensics/performance/AUTHORITIES.json` | `04171d2b56b385f53992b6b167e6e262905f81eece498d0472f9dc982d4cd31b` |
| `docs/PERFORMANCE-METHODOLOGY.md` | `7a7e33ae3f42d73331b022954b0ca9d0f078c3de85cbd326cbd5d6d1663b3993` |
| `evidence/performance-frontier/campaigns/PFP-0/preregistration.json` | `19a97cb76640bc77ca6547a5ad7b7555128860e890ffdf695a0c65f2cc7eb93a` |
| `evidence/performance-frontier/campaigns/PFP-0/build-identity.json` | `e8f614debfc88095c2e30b7a7ff5cc2c76376676b5b33b018669b0342a3e96f4` |
| `evidence/performance-frontier/campaigns/PFP-0/results.json` | `0fc0114746bb6c8d3e456d9ea69d335a849e6a107d3252a7c74264b669eccf56` |
| `evidence/performance-frontier/campaigns/PFP-0/fixtures/dh-fixtures.json` | `ad58f88d53ab76b608a6db95e938a6065af4b2f1c2ee287006fdd30a5abed2b2` |

---

## 12. What this campaign does not establish

- It does not establish a frontier result, a hardware-counter result, or a
  statistically supported lead over any comparator that was not executed.
- It does not establish constant-time behaviour; it measures wall time on one
  virtualised venue.
- It does not measure throughput, tail latency, parallel scaling, peak RSS,
  startup, energy, cache or branch behaviour.
- It does not compare against AWS-LC, BoringSSL, rustls, wolfSSL or a research
  kernel; those comparators are unavailable here.
- It does not establish that the synthetic DH modulus is a group, nor that the
  named-group rows perform peer validation or key generation.
- It does not establish L4 or L5 behaviour; the rows are L3 API operations.
- It does not inherit safety or compatibility graduation from a timing result.
