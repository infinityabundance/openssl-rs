# PFP-8 — paired timing

**Candidate:** DSO `88c0c7e0…` (`b2cca665…`, clean `src`).
**Previous build:** DSO `6d002db2…` (the PFP-6 admitted artefact; same source
lineage without M-A1).
**Authority:** DSO `611e511d…` (OpenSSL 3.6.4 production).
**Method:** `bench_pfp8.c`, one process per arm per workload per repetition,
arm order alternated, `taskset -c 1`, 15 repetitions, 10 calls per process;
median of paired per-repetition ratios with a 95 % percentile bootstrap
(20,000 resamples, seed `0x50465038`). Raw: `timing/raw/`, `timing/results.json`.

| workload | candidate µs | previous µs | authority µs | cand/auth | prev/auth | cand/prev |
|---|---:|---:|---:|---:|---:|---:|
| key generation (`ffdhe2048`, named) | 2,628.7 | 2,661.0 | 177.7 | **14.8226× [14.4048, 14.9716]** | 14.9992× [14.5886, 15.1924] | 0.9811 [0.9757, 0.9937] |
| shared secret, 2048-bit exponent | 2,443.0 | 2,504.0 | 1,225.2 | **1.9876× [1.9514, 2.0940]** | 2.0407× [2.0199, 2.1440] | 0.9833 [0.9715, 0.9880] |
| shared secret, 225-bit exponent | 2,450.9 | 2,549.9 | 176.3 | **14.0395× [13.7525, 14.4492]** | 14.4367× [14.1022, 14.5275] | 0.9787 [0.9680, 0.9906] |

## Against the recorded 2.02×

The stated 2.02× shared-secret ratio is **inside** the 95 % interval
[1.9514, 2.0940]; the point estimate at this digest is 1.9876×. It is a
same-instrument comparison at a different digest, not a trend. No prepared-group
change was made, so the row is expected to be unchanged, and it is.

## The 14× rows

Both real-key-length rows are ~14× because the crate runs the full modulus width
(2,048 ladder bits) for a 225-bit exponent, while the authority runs the
exponent's limb width (4 limbs = 256 bits, `bn_exp.c:637`). The candidate/previous
ratios (0.981 / 0.983 / 0.979) show the M-A1 fixed-width kernel is ~2 % faster
and that this batch changed nothing. The width policy is recorded as
`PFP8-WIDTH-POLICY`, not repaired here.

## Bound comparison

| quantity | bound | measured |
|---|---:|---:|
| table-build share of the exponentiation | 1.19 % | 1.19 % (30/2,491 calls; 635,580/53,334,930 Ir) |
| best prepared-window improvement | 2.21 % (`w = 6`) | not implemented (refusal) |
| shared-secret improvement from a generator table | 0 % | 0 % (no source change; 1.9876× unchanged) |

The refused optimisation could not move the measured workload. The shared-secret
bound was 0 %, so the 2.02× target was not met — by construction, not by a
shortfall in the kernel.
