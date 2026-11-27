# PFP-3 — artefact-level mutation control

**Result: PASS (the comb is load-bearing).** Two DSOs that both reproduce the
authority's 4,096 `mul-g` points, differing only in the admission switch,
execute materially different amounts of work: the candidate (comb) uses
**2.05×** fewer instructions and **1.96×** less wall time than the fallback
(ladder). A silent ladder fallback in the candidate would have measured like the
fallback DSO.

## Artefacts

| | digest | bytes | build-id |
|---|---|---:|---|
| A — candidate, comb admitted | `04611380…ffb15d4` | 17,128,536 | `5a70df9f…` |
| B — same source, `admits` returns `false` | `e4b2cb6e…cb3ac73` | 17,082,568 | `d162c620…` |

B is built from a **copy** of the crate (`court/tmp/pfp3-mut/srcroot`); the
repository's `src/` is not modified. The one change is the final `true` → `false`
of `admits` in `src/ec/p256/fixed_base.rs` (diff:
`raw/admission-switch.diff`). Repository `src` fingerprint before and after:
`ca5cc146…` both times. Archive `60220c33…`. Build: release,
`x86_64-unknown-linux-gnu`, rustc 1.98.1.

## Correctness: both are right, so the difference is a path difference

The differential harness (`pfp2_dso_differential.c`, `--mode mul-g`, seed
`0x5046503250485032`, 4,096 scalars) run against the authority
`611e511d…`:

* A: **0 mismatches** (and this is the recorded PFP-3 differential);
* B: **0 mismatches**.

B is therefore a correct fallback, not a different computation.

## Measurement (same harness: `pfp3_dso_ct --mode mul-g-fixed`)

Callgrind, one warm-up + 64 timed operations, per-op instruction count
computed as `(IR(64) − IR(0)) / 64`:

| subject | IR/op | relative |
|---|---:|---:|
| A (comb) | 2,389,818 | 1.00 |
| B (ladder fallback) | 4,898,523 | **2.05** |

Wall time, 9 repetitions × 200 operations, median:

| subject | ns/op | relative |
|---|---:|---:|
| A (comb) | 119,355.6 | 1.00 |
| B (ladder fallback) | 233,870.9 | **1.96** |

Raw: `raw/mutation-record.json`, `raw/callgrind.tsv`, `raw/wall.tsv`,
`raw/diff-*.out`, `raw/dso-digests.txt`.

This is the PFP-21/PFP-27 style: a separate fallback artefact, the same
instrument, a material measurement difference, and no correctness difference.
It does not upgrade the constant-time conclusion: the audit still records the
secret-derived admission branch (`../audit/AUDIT.md`).
