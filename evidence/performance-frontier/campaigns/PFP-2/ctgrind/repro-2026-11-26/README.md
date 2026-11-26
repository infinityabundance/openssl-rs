# PFP-2 ctgrind re-measurement — 2026-11-26

Companion to `../STOP-2026-11-26.md`. This directory is history, not a gate
result: it records the reproduction, the attribution, the controls and the
release-profile measurement that produced the STOP.

## Files

- `dso-identity.txt` — DSO and test-binary digests, and the pre-engine control
  source identity.
- `commands.txt` — exact recorded, reproduction and minimal-population commands.
- `variance.txt` — every run's summary and the per-class error table.
- `disassembly-mont_reduce_into.txt` — the two reported PCs mapped to the
  release instructions and to `src/ec/p256.rs:683-701`.
- `minimal_mul.c` — the minimal population (one `EC_POINT_mul` with a secret
  scalar; `sign-taint`/`sign-defined` modes for the signing path). The BigNum
  limb pointer is validated against the defined scalar before any taint, so a
  layout drift aborts (exit 13) instead of tainting the wrong bytes.
- `attribute.py` — the exhaustive classifier used to produce `attrib/`.
- `attrib/*.tsv` — one row per printed context: kind, class, origin
  `file:line`, engine-on-path, nearest crate frame, normalised stack.
- `attrib/*.summary.json` — counts per class and top origin sites.
- `*.out` — raw valgrind text logs.
- `dbgrel-min.out` — the minimal population against a line-tables-only release
  rebuild from HEAD `d2d93c7d1`; it pins the site to `src/ec/p256.rs:690`.
- `xml/*.xml` — `--xml=yes` diagnostics. These also contain leak records,
  which the uninitialised-error counts below exclude.

## Classes used in `attrib/`

- `A` test harness (`::tests::`, libtest)
- `B` new engine (`::ec::p256::`, `p256_ladder_run`)
- `C` generic bignum (`::bn::`)
- `D` pre-existing generic EC/ECDSA driver and field code (`ec::mult`,
  `ec::ecdsa_ossl`, `ec::smpl`, `ec::field`, `ec::curve`, `ec::lib`)
- `E` allocator / core / std / valgrind / libc

`engine_on_path` means a `p256` frame occurs anywhere in the stack, even if the
origin is in generic code.

## Reproduction summary

- Recorded command, unchanged: repeat 2 = `3023 errors from 123 contexts`
  (exact); observed band `3013–3047 / 121–136`; `CTGRIND_CONTROL=1` = 130
  contexts.
- Recorded population: 0 engine origins, 0 test-harness origins.
- Minimal MONT release: `12371 / 203`, 58 engine origins.
- Minimal generic release: `794 / 29`, 0 engine origins.
- Sign release: MONT `12494 / 250`, generic `847 / 82`.
- Defined controls: `0 / 0` everywhere.

The recorded binary is a debug lib test binary; the finding is about the
release DSO. Both identities are in `dso-identity.txt`.
