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
| `ct_bn.c` | ctgrind harness. Marks a secret buffer with `VALGRIND_MAKE_MEM_UNDEFINED`, calls the BN primitive, and lets stock Valgrind memcheck report secret-dependent branches and address uses. Also contains the negative control (`CRYPTO_memcmp`, expected clean) and the positive control (a deliberately leaky comparator, expected to fire). Mode `modexp_len` additionally taints the exponent's normalised length (the limb-count field at `+0x10` in this build, verified from `BN_num_bits`), because the contents-only `modexp` mode cannot see a length-dependent path. |
| `dudect_bn.c` | dudect-style statistical harness: two contrasting secret classes, warmup, batched measurement, Welch t-test. Carries the same two controls. It prints the executed measurement count (`dudect.executed ... total_measurements=N`) so the receipt quotes the instrument's own figure. |
| `bench_bn.c` | Wall-clock cost of `BN_mod_exp_mont_consttime` at 2048/3072/8192 bits and the RSA-2048 CRT shape, plus the allocation-failure behaviour when paired with `alloc_probe.so`. |
| `bench_api.c` | Cross-library workload harness. Opens exactly one `libcrypto.so.3` per process with `dlopen`, runs deterministic `BN_mod_exp_mont_consttime`, `DH_compute_key` on synthetic and real FFDHE/MODP groups, `RSA_private_encrypt` (CRT, `RSA_NO_PADDING`) and `ECDSA_do_sign` (P-256) through the common C API. Prints result digests for cross-library comparison, median/min/max over batches, allocation counts when preloaded with `alloc_probe.so`, the mapped file's realpath/device/inode from `/proc/self/maps`, and `--cross-sign`/`--cross-verify` exchanges. |
| `run_bench_api.sh` | PFP-0 campaign runner: builds the crate from the frozen tree into a fresh target directory, links the distribution-shaped DSO and a measurement-only DSO, verifies the loaded artefact per process, matches the exact workload population, runs 15 paired repetitions in a preregistered balanced random order, applies the allocation probe to both subjects, runs ECDSA cross-verification in both directions, and analyses the raw samples into `results.json`. |
| `alloc_probe.c` | `LD_PRELOAD` probe that counts `malloc`/`calloc`/`realloc`/`aligned_alloc`/`posix_memalign`/`memalign` and `free`, and can force a chosen allocation to fail. `allocprobe_alloc_calls()` is the PFP-0 unified count; `allocprobe_mallocs()` keeps the legacy malloc/calloc/realloc meaning. |
| `reach.py`, `reach2.py` | static reachability walks over `libcrypto.so.3`, from the ssh/sshd imported-symbol roots to the BN symbols, distinguishing direct/GOT edges from may-bound provider-dispatch routes. |
| `frontier.py`, `slots.py`, `tables.py` | helpers used to enumerate indirect slots and method tables during the reachability work. |
| `classify_ct.py`, `summarize_ct.py` | turn raw memcheck output into the branch/address classification quoted in the receipts. |
| `binary_branch_audit.py` | T14 optimised-code review aid: extracts a named function's compiler-emitted range from the built `libcrypto.so.3` (symbol table, not a hand-picked window), then tabulates conditional jumps by condition provenance and guarded action, plus `div`/`idiv`, `cmov`/`setcc`, `jo`/`jno`, calls and `cpuid`. It does **not** establish secret-dependence; that needs binary-level taint analysis (T16). An inventory target may additionally declare `resolves_to`/`inlining` (an inlined one-line wrapper), `llvm_suffix` (a re-derived witness for the only out-of-line body of an LLVM-suffixed local copy: exact v0 structural name, unique start, producer string, direct call site) and `comparison_contract` (a within-function may-taint check that no conditional transfer depends on an XOR/OR comparison accumulator). Every clause is re-established from the artefact, and a contract violation fails the run. |
| `pmu_probe.c` | T17 CPUID probe: prints CPUID.0AH (architectural PMU version/counters), CPUID.1.ECX[31] (hypervisor present), and AMD `PerfCtrExtCore`. Used to explain why no `cpu` event source exists, rather than assuming capability. |
| `tsc_clock.c` | T17 serialised RDTSC harness: calibrates the TSC against `CLOCK_MONOTONIC`, measures the empty read-pair resolution, a deterministic xorshift workload, and the crate's 2048-bit modexp and RSA-2048 CRT. RDTSC is a reference-clock substitute, **not** a PMU counter. |
| `run_pmu_substitutes.sh` | T17 runner: discovers event sources and `perf_event_paranoid`, runs the CPUID probe, shows `perf stat -e cycles` failing, runs `perf stat -e task-clock,context-switches,page-faults,minor-faults` on `bench_bn`, then runs `tsc_clock`. Writes under `court/tmp/t1718/t17/` by default. |
| `run_timecop_supercop.sh` | T18 runner: verifies SUPERCOP 20190816 and the upstream TIMECOP patch by sha256, applies the patch to a pristine tree, installs the Valgrind/`poison.h` headers, adds a test-only leaky control, runs `do-part init` and `do-part crypto_verify 16`, and prints the deduplicated `valgrind_pass`/`valgrind_fail` verdicts. |
| `fixtures/timecop/` | T18 inputs: verbatim public-domain `poison.h` (the TIMECOP page embeds it; there is no separate URL) and `zz-leaky-control/`, a test-only early-exit comparator that TIMECOP must flag. |

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
cc -D_GNU_SOURCE -O1 -g -I<valgrind includes> -Iartifacts/phase2/install/include \
   courts/phase18/timing/ct_bn.c \
   -L artifacts/phase2/install/lib -lcrypto \
   -Wl,-rpath,$PWD/artifacts/phase2/install/lib -o /tmp/ct_bn
LD_LIBRARY_PATH=$PWD/artifacts/phase2/install/lib \
  valgrind --tool=memcheck --error-exitcode=99 /tmp/ct_bn modexp
LD_LIBRARY_PATH=$PWD/artifacts/phase2/install/lib \
  valgrind --tool=memcheck --error-exitcode=99 /tmp/ct_bn modexp_len
```

`modexp` (contents tainted, length defined) is the measurement that the ladder
has no secret-contents branch. `modexp_len` taints the length as well and is
**expected to fire**: the exponent's length is read once, to copy its value into
the fixed-width view, so it cannot be a zero-error run. Its value is to show that
the instrument *can* report a length-dependent path, and to check that any report
sits at that copy rather than inside the ladder loop. Neither mode covers
microarchitectural effects, and no memcheck run proves constant time.

dudect geometry as executed: `config.number_measurements = 20000` per batch,
3 batches, so **60 000 measurements per run** (~30 000 per class). The harness
prints `dudect.executed ... total_measurements=60000`; that line, not the former
40 000 figure, is the count the receipt quotes. Pinned to one core with
`taskset -c 1`, repeated three times. Thresholds 10/500 as in the upstream
methodology.

Cost and allocation measurement:

```sh
cc -O2 -g -Iartifacts/phase2/install/include courts/phase18/timing/bench_bn.c \
   -L artifacts/phase2/install/lib -lcrypto -lm \
   -Wl,-rpath,$PWD/artifacts/phase2/install/lib -o /tmp/bench_bn
cc -O2 -fPIC -shared courts/phase18/timing/alloc_probe.c -ldl -o /tmp/alloc_probe.so
LD_LIBRARY_PATH=$PWD/artifacts/phase2/install/lib /tmp/bench_bn
LD_PRELOAD=/tmp/alloc_probe.so LD_LIBRARY_PATH=$PWD/artifacts/phase2/install/lib /tmp/bench_bn
LD_PRELOAD=/tmp/alloc_probe.so LD_LIBRARY_PATH=$PWD/artifacts/phase2/install/lib /tmp/bench_bn fail
```

`bench_bn fail [N]` forces the Nth allocation (default 64) to fail and prints the
return value. That separates an infallible `vec!` (the process aborts) from the
ladder's `try_reserve_exact` scratch (the call returns 0), instead of assuming
which one the ordinal hit.

## Cross-library workloads (PFP-0)

`bench_api.c` and `run_bench_api.sh` implement the PFP-0 baseline. The harness is
**not** linked against libcrypto: each process `dlopen`s the one library named by
`--lib`, so two libcrypto mappings never coexist. Inputs are deterministic (no
`BN_rand`), and every `CHECK` line is compared between the two processes.

The population is frozen in `forensics/performance/WORKLOADS.json` and matched by
exact identifier, not by line count: `modexp2048`, `modexp8192`,
`dh-synth2048`, `dh-synth3072`, `dh-ffdhe2048`, `dh-ffdhe3072`, `dh-modp2048`,
`rsa2048`, `ecdsa256`. The `dh-synth*` rows keep the synthetic odd composite
modulus and are labelled synthetic. The `dh-ffdhe*` and `dh-modp2048` rows load
tracked group parameters extracted from `src/bn/dh_data.rs`; the extractor checks
`p == 2*q + 1` and `p mod 8 == 7` before writing the fixture.

Each repetition is one process per subject, and the candidate/authority order is
a balanced pseudo-random sequence fixed before execution. Every process prints
the realpath, device and inode of the mapped DSO from `/proc/self/maps`; the
runner compares them with `stat(2)` on the expected on-disk file and refuses a
mismatch. The distribution-shaped DSO is the benchmarked candidate. The same
allocation probe is preloaded for both subjects. At six repetitions an ECDSA
signature is produced by one subject and verified by the other in both
directions.

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec \
    env CARGO_BUILD_JOBS=4 PFP0_COURT_IMAGE=openssl-rs-court-tools:1 \
    bash courts/phase18/timing/run_bench_api.sh
```

Outputs go to `evidence/performance-frontier/campaigns/PFP-0/`: raw process
outputs, the realised order, build identity, venue and PMU probes, and
`results.json`. The protocol is preregistered in
`docs/PERFORMANCE-METHODOLOGY.md`.

The PFP-0 runner always builds the crate from the frozen tree into a fresh
`CARGO_TARGET_DIR`. The older `ARCHIVE` and `REBUILD_CANDIDATE` overrides are no
longer inputs: an externally supplied archive would bypass the frozen-build rule
and cannot be bound to the source identity this campaign requires.

These are wall-clock ratios on one virtualised host/container/CPU with no exposed
PMU. They are `SCOPED_OBSERVATION`, not constant-time or security evidence, and
not a frontier result. The synthetic DH rows measure exponentiation only; the
named-group rows measure exponentiation with real parameters but not peer
validation or key generation. The RSA row is a raw `RSA_NO_PADDING` private
operation with blinding on; the ECDSA row includes nonce generation and
inversion.

## PMU substitutes (T17)

There is no hardware PMU at this guest's interface: `hypervisor` is present,
CPUID.0AH returns version 0 with 0 counters, `/sys/bus/event_source/devices`
has no `cpu`, and `perf stat -e cycles` prints `<not supported>`. The two
substitutes that do work must be named as such, never presented as PMU
counters:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
  bash docker/openssl-rs-court.sh exec \
  bash courts/phase18/timing/run_pmu_substitutes.sh
```

`perf stat -e task-clock,context-switches,page-faults,minor-faults` is a kernel
software-event path. `tsc_clock` reports reference-clock ticks: it cannot
count instructions, branches or cache events, it cannot attribute kernel vs
user, and the guest does not advertise `constant_tsc`/`nonstop_tsc`. The
resolution is the serialised empty read pair (median 34 ticks ≈ 11.4 ns), not
the ~0.334 ns tick. Numbers and limits: `court/tmp/t1718/NOTES.md`.

## TIMECOP SUPERCOP harness (T18)

This is the real TIMECOP patch to SUPERCOP (not the distro `timecop-bin`
desktop application). Upstream supports SUPERCOP 20181113, 20190110 and
20190816; the runner uses 20190816 and verifies both the tarball and the patch
by sha256 before applying them.

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
  bash docker/openssl-rs-court.sh exec \
  bash courts/phase18/timing/run_timecop_supercop.sh
```

The run measured here applied 22 files / 45 hunks with 0 rejects; `crypto_verify/16/ref`
was `valgrind_pass` in 121/121 compiler configurations, and the test-only
early-exit control was `valgrind_fail` in 121/121, reporting a conditional
jump rooted in `timecop_doit`'s client request. A run where the control does
not fire is not evidence. `do-part` exits non-zero after the analysis because
it unconditionally `cat`s a missing `work/errors`; judge by the verdict table,
not that exit code.

## Interpreting the results

`LEAKAGE_DETECTED` from a high t-statistic or from a memcheck branch report is
evidence that a specific mechanism exists. It is not a proof of exploitability.

`NO_LEAKAGE_DETECTED_AT_STATED_SENSITIVITY` is bounded evidence at a stated
geometry. It is **not** a constant-time proof, and it does not cover
microarchitectural effects that neither instrument models.

An instrument that reports nothing on the positive control has failed. Both
harnesses carry the positive control for exactly this reason; a run without it
is not evidence.

## Binary branch audit (T14)

Runs on the DSO produced by `forensics/tools/build_phase2.sh`; no Rust build is
needed. It prints the DSO's SHA-256 so the measurement is bound to one artefact.

```sh
python3 courts/phase18/timing/binary_branch_audit.py \
    artifacts/phase2/install/lib/libcrypto.so.3 > court/tmp/t14/branch-audit.md
```

The output is a review aid, not a proof: it lists the branches the compiler
emitted in the named ranges and their condition provenance, but it cannot say
which conditions depend on secret data. BINSEC `-checkct` (T16) is unvalidated,
and `cmov` presence is not a constant-time result.
