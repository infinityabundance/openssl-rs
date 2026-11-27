# PFP-3 — timing at `04611380…`

**Identity guard satisfied.** The candidate is the clean committed tree
`289f111877ce7aa9a9a76d25bf76357f57ed6582` (tree `11a5d18f…`), built by
`build_pfp3.sh`; the run does not rebuild. `build-identity.json` records
`build_relevant_clean: true` and
`current_head_src_matches_recorded: true`. Candidate
`04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`, archive
`6c2133c0…`, authority `611e511d…`.

The instrument is the preregistered one, unchanged: `bench_api.c`, the
analyser, **15 repetitions**, balanced pseudo-random order, `taskset -c 1`,
median of paired ratios, 20,000-resample percentile bootstrap, seed
`0x50465030`, warm-up excluded, `fmt`/identity checks per process.

## `ecdsa256`

| subject | µs/op | ratio | 95% CI | allocations |
|---|---:|---:|---|---:|
| candidate | 135.695 | **10.64** | **[10.61, 10.67]** | 76.00 |
| authority | 12.730 | | | 29.00 |

The prior figures (`ecdsa256` 18.83× at `e93776b4`, 19.22× at `553e1b8c`) are at
**different digests**. No trend across digests is claimed.

## `ecdh`

The WORKLOADS campaign has no `ecdh` row, so this uses the PFP-29 per-path
instrument (`pfp29_paths.c`) under the same conventions — 15 repetitions,
`taskset -c 1`, paired candidate/authority ratios, 20,000-resample bootstrap CI,
seed `0x50465030`. One timing-only change is recorded (`raw/ecdh-harness.diff`):
the candidate-layout taint is disabled when `--iters > 0`, because it is invalid
on the authority DSO and irrelevant to wall time.

| subject | µs/op (median) | ratio | 95% CI |
|---|---:|---:|---|
| candidate | 222.658 | **6.79** | **[4.69, 6.90]** |
| authority | 32.805 | | |

The prior 226 µs is at a **different digest** (PFP-29, `5e75b694`), not a trend.
The candidate value here (222.7 µs) is in the same range but is a separate
measurement; the wide CI is reported as measured.

## Full workload set at this digest

| workload | candidate µs | authority µs | ratio | 95% CI |
|---|---:|---:|---:|---|
| `dh-ffdhe2048` | 5,019.731 | 1,191.717 | 4.21 | [4.21, 4.22] |
| `dh-ffdhe3072` | 17,539.087 | 3,967.648 | 4.41 | [4.41, 4.43] |
| `dh-modp2048` | 5,019.821 | 1,191.646 | 4.21 | [4.21, 4.22] |
| `dh-synth2048` | 5,019.172 | 1,193.894 | 4.20 | [4.20, 4.21] |
| `dh-synth3072` | 17,545.359 | 3,973.556 | 4.42 | [4.41, 4.43] |
| `ecdsa256` | 135.695 | 12.730 | 10.64 | [10.61, 10.67] |
| `modexp2048` | 5,123.883 | 1,208.830 | 4.24 | [4.20, 4.27] |
| `modexp8192` | 355,239.903 | 73,759.077 | 4.82 | [4.81, 4.82] |
| `rsa2048` | 1,641.712 | 351.710 | 4.66 | [4.63, 4.68] |

Records: `results.json`, `build-identity.json`, `venue.txt`, `preregistration.json`,
`raw/ecdh-timing.json`. The runner retains the parent copy's final echo string
("PFP-2 timing completed"); the campaign field of the preregistration is
`PFP-3`. That label is cosmetic and does not affect the measurement; it is
recorded here rather than silently edited after execution.

No claim is made that any of these ratios is a constant-time property; the audit
result is separate and is a STOP (`../audit/AUDIT.md`).
