# PFP-8 — profile method and raw attribution

**Digest:** DSO `88c0c7e0…`; source `b2cca665…`, `src` tree `05a4a56b…`.
**Instrument:** valgrind 3.19.0 callgrind, one process per workload, `ffdhe2048`
(NID 1126), candidate DSO `/work/court/tmp/ma1/cand/distribution/libcrypto.so.3`.

## Commands

```
cc -O2 -g -I forensics/authorities/prefix/openssl-3.6.4-production/include \
   courts/performance-frontier/pfp8/bench_pfp8.c -ldl -o court/tmp/pfp8/bench_pfp8
valgrind --tool=callgrind --callgrind-out-file=.../keygen-named.out \
   .../bench_pfp8 --lib .../libcrypto.so.3 --op keygen --nid 1126 --iters 1 --runs 1
valgrind --tool=callgrind --callgrind-out-file=.../compute-named.out \
   .../bench_pfp8 --lib .../libcrypto.so.3 --op compute --nid 1126 \
   --priv "$PRIV2048" --peer "$PEER2048" --iters 1 --runs 1
```

The driver runs one untimed `CHECK` operation and one timed operation, so each
process performs **two** operations. `callgrind_annotate` files are in
`profile/`; the inclusive tree is `profile/keygen-incl.annotate`.

## Per-operation counts

| quantity | keygen | agreement |
|---|---:|---:|
| process total (2 ops) | 125,262,230 | 112,240,121 |
| `mont_mul_ladder_into` (2 ops) | 105,548,652 | 105,548,652 |
| calls to the kernel (2 ops) | 4,982 | 4,982 |
| **kernel cost per call** | **21,186 Ir** | **21,186 Ir** |
| `pow2_mod_consttime` (one MontCtx per fresh object) | 2,818,502/op | 2,819,086 once, then 0 |
| `ossl_ffc_generate_private_key` | 5,153,631/op | — |
| `name_find` (named-group lookup, one-time group table) | 2,095,420 first op | — |
| `run_mont_ladder` exclusive (scan + loop) | 415,270/op | 415,270/op |
| `mont_mul_fallible` (base conversion, SOS) | 32,158/op | 32,158/op |

Kernel call count per exponentiation: table build `2^5 − 2 = 30`, squarings
`410 · 5 = 2,050`, main-loop multiplications `410`, final conversion `1` = 2,491.

## Warm-operation totals

Agreement on a warm object excludes the one-time `BN_MONT_CTX_set`:
`(112,240,121 − 2,819,086) / 2 = 54,710,517 Ir` (≈2,583 kernel-call
equivalents). Key generation creates a fresh object per call, so it pays the
MontCtx setup and the named-group lookup every time; its timed cost is 2,628.7 µs
versus 2,443.0 µs for the warm agreement. The difference is the object/RNG work
in §1.2 of `BOUND.md`, not a different ladder.
