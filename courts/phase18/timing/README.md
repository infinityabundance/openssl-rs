# Phase-18 timing courts — the instruments behind the BN findings

These are the harnesses that produced `evidence/timing-bn-findings.json` and the
re-measurement in `evidence/timing-bn-repair.json`. They live here, tracked, so a
clean checkout can reproduce the findings without access to a previous session's
scratch space.

The single source of truth for every number remains the two receipts; this
directory is the apparatus, not the conclusion.

## What each file is

| file | role |
|---|---|
| `ct_bn.c` | ctgrind harness. Marks a secret buffer with `VALGRIND_MAKE_MEM_UNDEFINED`, calls the BN primitive, and lets stock Valgrind memcheck report secret-dependent branches and address uses. Also contains the negative control (`CRYPTO_memcmp`, expected clean) and the positive control (a deliberately leaky comparator, expected to fire). |
| `dudect_bn.c` | dudect-style statistical harness: two contrasting secret classes, warmup, batched measurement, Welch t-test. Carries the same two controls. |
| `reach.py`, `reach2.py` | static reachability walks over `libcrypto.so.3`, from the ssh/sshd imported-symbol roots to the BN symbols, distinguishing direct/GOT edges from may-bound provider-dispatch routes. |
| `frontier.py`, `slots.py`, `tables.py` | helpers used to enumerate indirect slots and method tables during the reachability work. |
| `classify_ct.py`, `summarize_ct.py` | turn raw memcheck output into the branch/address classification quoted in the receipts. |

## Build and run

Everything runs inside the court. The instruments are not in the default image;
they are in the derived tools image (`docker/openssl-rs-court-tools.Dockerfile`),
which is selected with the existing override:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
  bash docker/openssl-rs-court.sh exec sh -c '...'
```

The tools image is **not** an admitted venue for the Phase-24/25 guards, whose
manifests name `openssl-rs-court:1`. Timing work may use it; closure evidence
must not.

ctgrind (stock Valgrind plus client requests — the legacy patched fork is not
used):

```sh
cc -O1 -g -I<valgrind includes> courts/phase18/timing/ct_bn.c \
   -L artifacts/phase2/install/lib -lcrypto -Wl,-rpath,artifacts/phase2/install/lib -o /tmp/ct_bn
valgrind --tool=memcheck --error-exitcode=99 /tmp/ct_bn
```

dudect geometry as recorded: 40 000 measurements per run (~20 000 per class),
3 batches, pinned to one core with `taskset -c 1`, repeated four times.
Thresholds 10/500 as in the upstream methodology.

## Interpreting the results

`LEAKAGE_DETECTED` from a high t-statistic or from a memcheck branch report is
evidence that a specific mechanism exists. It is not a proof of exploitability.

`NO_LEAKAGE_DETECTED_AT_STATED_SENSITIVITY` is bounded evidence at a stated
geometry. It is **not** a constant-time proof, and it does not cover
microarchitectural effects that neither instrument models.

An instrument that reports nothing on the positive control has failed. Both
harnesses carry the positive control for exactly this reason; a run without it
is not evidence.
