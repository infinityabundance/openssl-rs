# PFP-10 — measured crossover (Fermat / binary GCD / divstep)

All three candidates are timed **in one binary**, interleaved, 15 balanced
repetitions per domain and size. The statistic is the median of the
per-repetition batch means, with a 95 % percentile bootstrap interval (20,000
resamples, paired for ratios). Pinned with `taskset -c 1` inside the court
container.

* subject: `target/debug/deps/openssl_rs-e1a9da8d91fb8797`, profile
  `test` with `opt-level=3`, `debug=0`, `debug-assertions=false`
  (release-like except for `overflow-checks`, which the crate sets on in
  `[profile.release]` as well), SHA-256
  `473a058df52aa58b8328f590dd417082ccee890c9b84108e815a349b28e0dbed`;
* source fingerprint `9e764fe9133f15c5b1b21c79b96ec84d2275048bdbe385ea6921e35c8b89f48b`
  (889 `src/**/*.rs` files), `staging` `b2dbcd14`;
* raw samples: [`raw-samples.tsv`](raw-samples.tsv) (225 rows);
  analysis: [`analyse_pfp10.py`](analyse_pfp10.py) → [`results.json`](results.json).

The P-256 domains use the deployed forms: Fermat = `P256Scalar::invert` (order)
and `fixed_base::invert` (field), including the Montgomery conversion that the
deployed call performs; GCD and divstep run on the ordinary residue, which is
how they would be called. The 1024/2048/521 sizes use the generic const-time
Fermat ladder (`bn::arith::mod_exp_core_consttime`) and ordinary residues for the
other two. Each candidate's own per-call scratch allocation is inside the timed
region; process startup, test-harness allocation and I/O are outside it.

## 1. Absolute medians (ns per inverse)

| domain | bits | Fermat | binary GCD | divstep |
|---|---:|---:|---:|---:|
| p256-field | 256 | 11,046 [11,029, 11,091] | 49,349 [49,135, 49,598] | 22,575 [22,558, 22,688] |
| p256-order | 256 | 11,560 [11,527, 11,659] | 48,832 [48,604, 49,287] | 22,620 [22,575, 22,647] |
| m521 (2^521−1) | 521 | 62,636 [62,306, 63,084] | 194,654 [193,922, 194,955] | 79,181 [78,940, 79,318] |
| modp-1024 | 1024 | 276,002 [275,588, 277,025] | 526,611 [523,959, 531,297] | 224,718 [224,466, 225,262] |
| modp-2048 | 2048 | 2,549,022 [2,548,686, 2,552,943] | 1,977,697 [1,971,635, 1,981,217] | 892,536 [892,108, 893,904] |

## 2. Paired ratios

| domain | bits | divstep / Fermat | GCD / Fermat | divstep / GCD |
|---|---:|---:|---:|---:|
| p256-field | 256 | **2.044 [2.033, 2.050]** | 4.457 [4.443, 4.497] | 0.458 [0.455, 0.461] |
| p256-order | 256 | **1.957 [1.942, 1.958]** | 4.230 [4.210, 4.280] | 0.463 [0.460, 0.464] |
| m521 | 521 | **1.267 [1.262, 1.273]** | 3.112 [3.089, 3.128] | 0.406 [0.405, 0.409] |
| modp-1024 | 1024 | **0.814 [0.810, 0.817]** | 1.913 [1.898, 1.919] | 0.426 [0.423, 0.432] |
| modp-2048 | 2048 | **0.350 [0.350, 0.350]** | 0.775 [0.769, 0.777] | 0.452 [0.450, 0.454] |

Ratio < 1 means the named candidate is faster than the denominator.

## 3. Crossover table

| domain | size | winner | interval |
|---|---|---:|---|
| p256-field | 256 | **Fermat** | divstep is 2.044× slower; the whole interval is above 2 |
| p256-order | 256 | **Fermat** | divstep is 1.957× slower; the whole interval is above 1.94 |
| generic odd modulus | 521 | **Fermat** | divstep is 1.267× slower [1.262, 1.273] |
| generic odd modulus | 1024 | **divstep** | divstep is 0.814× Fermat [0.810, 0.817] |
| generic odd modulus | 2048 | **divstep** | divstep is 0.350× Fermat [0.350, 0.350] |
| all sizes | all | **divstep beats the binary GCD** | 0.406–0.463 of its time at every size |

## 4. Shape of the curve

The divstep/Fermat ratio falls monotonically with size: 2.04 (256, field),
1.96 (256, order), 1.27 (521), 0.81 (1024), 0.35 (2048). The binary GCD/Fermat
ratio also falls (4.46 → 0.78) but the binary GCD is overtaken by the divstep
before it ever overtakes Fermat at these sizes. A log-log interpolation between
the 521 and 1024 points puts the **Fermat/divstep crossing near 750 bits**;
the simple cubic/quadratic model (`BOUNDS.md` §4) predicts ~500–600, so the
constant factors delay the realised crossing.

There **is** a crossover in the tested range: Fermat wins below it, the divstep
above it. The binary GCD never wins against the divstep at any measured size,
and against Fermat it wins only at 2048 (0.775×) — where it is still 2.2×
slower than the divstep.

## 5. Integration decision — nothing integrated

The measurement says "divstep above ~750 bits", but there is no admissible
locus in the crate where that regime can be adopted:

1. **P-256 field and order** are the only paths with an already branch-free
   reduced operand (`P256Scalar::from_canonical_reduced`). They are 256-bit
   domain points, where the Fermat wins by 1.96–2.04×. They keep the Fermat.
2. **The generic constant-time inverse** (`BN_mod_inverse_consttime` →
   `mod_inverse_impl` → `limbs::mod_inverse_consttime`) is the only ≥ 1024-bit
   constant-time locus. It accepts `a` **not reduced modulo `m`** (the binary GCD
   handles a wider operand by construction). The divstep requires
   `0 <= a < m`; the crate has no constant-time general modular reduction, and
   the variable-time `rem` would trade a constant-time property for speed, which
   §5 of the standard forbids. The published iteration bound is also stated for
   `0 <= g <= f <= M`, a premise an unreduced operand does not meet. Extending
   the count to unreduced operands is empirically supported but not proven, and
   is not promoted here.
3. **The prototype is not constant-time at release-like codegen.** ctgrind with
   the operand tainted reports exactly one secret-dependent conditional transfer
   per divstep (590 error instances at 591 steps, 1 context; 2359 at 2360
   steps, 1 context; the standalone canary reports 4 contexts), despite the
   crate's value barriers. A secret-derived transfer is a STOP.

So the recorded conclusion is a **measured crossover with no integration**: the
divstep is a real performance winner for large odd moduli and a real winner over
the binary GCD at every size, but it cannot be admitted without first providing
a proven constant-time reduction (or a proven bound for unreduced operands) and
without eliminating the per-step conditional transfer. Neither is done by this
batch. Per the W3 rule, no path is changed for a number it cannot move: no
measured consumer in the frontier table inverts at ≥ 1024 bits on the
constant-time path.

`ARMS.json` is **not** updated: no integrated arm exists, so there is no
complete same-digest arm set to record.
