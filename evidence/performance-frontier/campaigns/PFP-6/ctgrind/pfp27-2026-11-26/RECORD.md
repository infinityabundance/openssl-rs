# PFP-27 ctgrind record — 2026-11-26

Artefact-level ctgrind on the DSO pair that differs only in the compile-time
`MontSchedule` default. Full analysis and interpretation: `../../ARTEFACT-AUDIT.md`.

| item | value |
|---|---|
| A (SOS default) | `5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae` |
| B (CIOS default) | `12023efec3e40444f579c9e88a78653c891448b2ffd2abf9c9c0ee89e0b9f9e8` |
| engine sensitivity control | `83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f` (pre-PFP-20) |
| harness | `…/PFP-2/ctgrind/pfp21-2026-11-26/pfp21_dso_ct.c`, **unmodified**, sha256 `ef1374120b29649ea8537ffcf58d9b01acd05b3bc9dcaeb0184a60c7977d3c51` |
| harness binary | sha256 `3a385537cc286cb7c19e0bbbb468c4033ffabb8edc74ac69df29237fc3d2aea1` |
| valgrind | 3.19.0, memcheck, `--num-callers=24` |
| modes / reps | `control mul-g mul-p mul-g-bytes sign sign-ex sign-ex-k`; 3 reps (1 for `control`) |
| run | `run_ctgrind.sh` in this directory; raw logs in `raw/`, attribution in `attrib/` |

## Result

* `control` — 0 errors, both artefacts (negative control).
* Engine sensitivity control — `engine_on_path = 4` on all three `mul-g`
  repetitions, reproducing PFP-21.
* `sign` — 735 contexts (A) / 753 (B) over three repetitions; **no context has
  `run_mont_ladder` in its stack**, so the admitted population never routes a
  tainted value into the ladder.
* Kernel-origin contexts from this harness: **0**, by construction, not by
  kernel silence. The kernel-taint population is supplied by
  `../../artefact-audit/run_probe.sh`, which taints the base of
  `BN_mod_exp_mont_consttime` and reports 0 contexts in the SOS and CIOS
  carriers, while the canary `97e960f3…` yields 2 contexts inside
  `mont_mul_ladder_into`.

## Reachability of the CIOS path

Callgrind (`raw/callgrind.tsv`), 64 iterations:

| mode | A Ir | B Ir | difference |
|---|---|---|---|
| `sign` | 372,813,421 | 368,399,897 | 4,413,524 |
| `mul-g` | 341,684,888 | 341,683,153 | 1,735 |
| `sign-ex-k` | 34,482,562 | 34,479,107 | 3,455 |

`sign` is the only mode whose executed instructions change with the schedule
(16,448 kernel calls per 64 operations), so the CIOS branch was taken. `sign-ex-k`'s
flat count confirms its `BN_mod_inverse` is the variable-time EEA, not the ladder.
