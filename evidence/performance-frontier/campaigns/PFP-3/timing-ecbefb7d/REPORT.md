# PFP-3 — timing after the branch-free admission (`ecbefb7d`)

**Same instrument, same protocol, new digest.** The candidate is the post-fix
distribution DSO `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053`
built by `build_pfp3.sh` from `staging` `f8d5c4b33…` with the uncommitted
`src/ec/p256/fixed_base.rs` branch-free admission; two fresh-target builds
reproduce the digest and archive `14f76179…`.

The instrument is unchanged: `bench_api.c`, the analyser, 15 repetitions,
balanced pseudo-random order, `taskset -c 1`, median of paired ratios,
20,000-resample percentile bootstrap, seed `0x50465030`, warm-up excluded,
`fmt`/identity checks per process. `ecdh` uses the PFP-29 per-path instrument
under the same conventions, with the same timing-only taint change recorded in
`../timing-04611380/raw/ecdh-harness.diff`.

## `ecdsa256`

| subject | µs/op | ratio | 95% CI | allocations |
|---|---:|---:|---|---:|
| candidate | 134.485 | **10.58** | **[10.55, 10.62]** | 76.00 |
| authority | 12.721 | | | 29.00 |

## `ecdh`

| subject | µs/op (median) | ratio | 95% CI |
|---|---:|---:|---|
| candidate | 224.290 | **6.72** | **[6.67, 6.83]** |
| authority | 33.165 | | |

## Cost of the change against `04611380`

Same instrument, two digests (`04611380` pre-fix, `ecbefb7d` post-fix):

| workload | pre-fix | post-fix | difference |
|---|---:|---:|---:|
| `ecdsa256` | 10.64× [10.61, 10.67] | **10.58× [10.55, 10.62]** | −0.6 % |
| `ecdh` | 6.79× [4.69, 6.90] | **6.72× [6.67, 6.83]** | −1.0 % |

The branch-free admission costs **no measurable amount**: the fixed-base
multiply now performs four extra 64-bit subtracts and a four-limb masked select,
which is inside run-to-run noise. The eight unaffected rows moved by a similar
±1–2 % between the two runs, so the two-digit changes are **not** claimed as a
trend; they establish only that the removal of the branch did not add cost at
this instrument.

## Full workload set at `ecbefb7d`

| workload | candidate µs | authority µs | ratio | 95% CI |
|---|---:|---:|---:|---|
| `dh-ffdhe2048` | 4,920.519 | 1,191.713 | 4.13 | [4.13, 4.13] |
| `dh-ffdhe3072` | 17,111.157 | 3,964.493 | 4.32 | [4.31, 4.33] |
| `dh-modp2048` | 4,918.672 | 1,191.883 | 4.13 | [4.12, 4.13] |
| `dh-synth2048` | 4,917.195 | 1,192.683 | 4.12 | [4.12, 4.13] |
| `dh-synth3072` | 17,108.648 | 3,962.162 | 4.32 | [4.31, 4.33] |
| `ecdsa256` | 134.485 | 12.721 | 10.58 | [10.55, 10.62] |
| `modexp2048` | 5,031.286 | 1,198.742 | 4.20 | [4.16, 4.22] |
| `modexp8192` | 359,998.824 | 73,912.842 | 4.87 | [4.86, 4.88] |
| `rsa2048` | 1,604.534 | 351.290 | 4.57 | [4.55, 4.58] |

## Identity caveat

The campaign does not commit, so `build-identity.json` records
`build_relevant_clean: false` and the exact dirty path
(`M src/ec/p256/fixed_base.rs`) rather than refusing. The artefact identity is
still pinned: the DSO/archive digests are `--expect` values in the runner, two
fresh-target builds reproduce them, and the source tree fingerprint is
`52219f14f2402ffcb2b1ce5abcc843c168b79fb4798b9db66e50b5683c3b0aee`. This is the
same working-tree convention the campaign used at `b0ada60` (see
`../DERIVATION.md`); no clean-commit claim is made.

No latency figure is a constant-time claim. Records: `results.json`,
`build-identity.json`, `preregistration.json`, `venue.txt`,
`raw/ecdh-timing.json`.
