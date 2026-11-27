# PFP-3 — timing at `04611380…`

**Run and identity-bound.** The preregistered campaign now runs: the source is
the clean committed tree `289f111877ce7aa9a9a76d25bf76357f57ed6582` (tree
`11a5d18f…`), the identity guard reports `build_relevant_clean: true` and
`current_head_src_matches_recorded: true`, and the subject is the distribution
DSO `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`.

Protocol (unchanged): 15 repetitions, balanced pseudo-random order,
`taskset -c 1`, median of paired candidate/authority ratios, 20,000-resample
percentile bootstrap, seed `0x50465030`, warm-up excluded.

| workload | candidate | authority | ratio | 95% CI |
|---|---:|---:|---:|---|
| `ecdsa256` | 135.695 µs | 12.730 µs | **10.64×** | **[10.61, 10.67]** |
| `ecdh` | 222.658 µs | 32.805 µs | **6.79×** | **[4.69, 6.90]** |

`ecdh` is not a WORKLOADS row; it uses the PFP-29 per-path instrument under the
same conventions, with a recorded timing-only change (taint disabled for timed
runs; it reads the candidate's `BIGNUM` layout and is invalid on the authority).
The full workload table is in `timing-04611380/REPORT.md`.

The previously reported `ecdsa256` 18.83× and `ecdh` 226 µs are at **different
digests** (`e93776b4`/`5e75b694`), not a trend; no cross-digest speedup is
claimed. No latency figure is a constant-time claim; the audit is a separate
STOP (`TAINT-AUDIT.md`).
