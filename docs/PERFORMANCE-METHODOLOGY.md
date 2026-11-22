# Performance measurement methodology — PFP-0

**Status:** preregistered before the PFP-0 campaign was executed. The campaign
must not deviate from this document without a recorded amendment (§16).
**Campaign:** `PFP-0`.
**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-0.
**Governing standard:** `docs/PERFORMANCE-FRONTIER.md` §0, §9 and §10.
**Evidence:** `evidence/performance-frontier/campaigns/PFP-0/`.

The purpose is to make every later performance number comparable, repeatable and
bound to an artefact. A number produced by a different population, ordering,
statistic or artefact is not comparable and is not merged with these rows.

---

## 1. Claim class and scope

Every result in this campaign is a **`SCOPED_OBSERVATION`** on the named venue.
No row is `COMPETITIVE`, `PARITY_ESTABLISHED`, `AHEAD` or
`FRONTIER_LEADING`, and no row is a frontier result. The virtualised court has no
exposed PMU and no frequency/turbo/SMT control, so the evidence supports ratios,
correctness and allocation counts, not a frontier claim.

The campaign measures:

- single-operation latency, as a batch mean per call;
- allocation entry points per operation, through one instrument applied to both
  subjects;
- cross-library ECDSA correctness in both directions.

It does not measure throughput, tail latency, parallel scaling, peak RSS,
retired instructions, cycles, cache or branch behaviour, energy, startup, or any
L4/L5 integrated workload.

---

## 2. Subjects and identities

Two subjects are executed:

| role | subject | identity |
|---|---|---|
| candidate | the distribution-shaped `libcrypto.so.3` built from the frozen source tree | `forensics/performance` build-identity record: source commit, archive digest, DSO digest and build-id |
| compatibility authority | OpenSSL 3.6.4 production, `611e511d` | DSO path, size, SHA-256 and build-id in `forensics/performance/AUTHORITIES.json` |

The benchmarked candidate is the **distribution-shaped** DSO, linked with the
Phase-2 shell object and the tracked version script. A plain whole-archive
measurement DSO is also linked and its digest is carried in the identity record;
it is not benchmarked. If the two differ, the distribution DSO is the one in
every measurement row.

The authority is the admitted production build, not the distribution OpenSSL
that happens to be installed in the container. The distribution library is
recorded as observed-but-not-admitted and is never substituted.

---

## 3. Workload population

The population is frozen in `forensics/performance/WORKLOADS.json`. Each workload
has one stable identifier, declared sizes, operand provenance, an expected
result-line count and a security contract. The identifiers are:

```
modexp2048
modexp8192
dh-synth2048
dh-synth3072
dh-ffdhe2048
dh-ffdhe3072
dh-modp2048
rsa2048
ecdsa256
```

The two `dh-synth*` rows retain the synthetic odd composite modulus and are
labelled synthetic. The `dh-ffdhe*` and `dh-modp2048` rows use real named-group
parameters extracted from the tracked `src/bn/dh_data.rs` arrays. The fixture
generator checks the declared array length, the bit length, `p == 2*q + 1` and
`p mod 8 == 7`; the parameters are loaded explicitly into both subjects, so the
bytes are identical on both sides and are not read from either library's
built-in table.

A process is complete only when the exact identifier set is present once each
in its output. Equal result-line counts are not a completeness test. A missing
identifier, a duplicate identifier or an undeclared identifier makes the
campaign `BLOCKED`.

---

## 4. Independent replication and ordering

The unit of replication is **one process per subject per repetition**. Operations
inside one timed batch are not independent replications.

The campaign executes **15 repetitions**, fixed before execution. The count was
chosen from the historical run-to-run spread recorded in `court/tmp/t21/NOTES.md`
(three runs within approximately 3% for the tight rows, with RSA approximately
6%), with the expectation that the bootstrap interval for the median paired ratio
is narrow enough to distinguish the reported gaps. The count is not changed after
seeing the data.

Within every repetition, both subjects run in a balanced pseudo-random order
generated before execution from the fixed seed `0x50465030`; exactly eight
repetitions start with the candidate and seven with the authority. The realised
order is written to `raw/run-order.tsv` and reproduced in `results.json`.

Each measured process is pinned to one core with `taskset -c 1`.

---

## 5. Warm-up and stopping rule

One unrecorded warm-up pair (candidate and authority) precedes repetition 00.
The warm-up pair is excluded from every statistic. The harness itself also runs
`iters/4` warm-up calls of each workload inside each process.

The stopping rule is fixed: 15 measured repetitions. There is no early stop, no
optional continuation, no replacement of a slow repetition and no removal of an
outlier. A process that fails, is resource-exhausted or cannot establish its
artefact identity makes the campaign `BLOCKED`; it is never reported as a pass.

---

## 6. Statistic and uncertainty

For workload `w` and repetition `r`, the harness reports the median of five
timed batch means in microseconds per call. The primary statistic is

```
ratio_w = median_r ( candidate_us(w, r) / authority_us(w, r) )
```

The per-repetition ratios are paired by repetition, so slow periods shared by
both subjects cancel in the ratio. The campaign reports:

- the paired-ratio median and all 15 paired ratios;
- the ratio of the two medians, for continuity with earlier reports;
- a percentile bootstrap interval for the paired-ratio median (20 000
  resamples, seed `0x50465030`);
- the candidate and authority median and interquartile range;
- the relative median absolute deviation of each subject.

The bootstrap is a resampling description, not a proof of a population model.
The interval is reported whether it is narrow or wide.

---

## 7. Multiple comparisons

The declared family is the nine workload identifiers in §3. Two procedures are
reported, both fixed before execution:

1. **Holm-Bonferroni** over the two-sided exact sign-test p-values for
   `ratio_w = 1`, with family-wise alpha 0.05. The sign test uses only the
   direction of each paired ratio and makes no normality assumption.
2. A **Bonferroni family-wise interval** for each ratio at
   `1 - 0.05/9 = 0.99444`, alongside the unadjusted 95% interval.

A small p-value establishes only that the measured ratio is consistently on one
side of one in this sample. It does not establish a practical margin, and no row
is promoted to `AHEAD` by this campaign.

---

## 8. Exclusions and discrepancies

No observation is excluded after execution. No outlier trimming, winsorising,
normalisation or population change is permitted.

Every row is published, including a row where the candidate is worse than a
previously reported number. Where a previously reported number does not
reproduce, `results.json` records the previous value, the new value, the
difference and whether the previous value lies inside the new interval. The new
number is not adjusted to match the old one.

Synthetic and real-group DH rows are separate identifiers. Their results are
never merged, averaged or substituted for one another.

---

## 9. Identity and loaded-artefact verification

Before any timing, the campaign records:

- the source commit and the dirty state of every build-relevant path;
- the crate archive path, size and SHA-256;
- the distribution DSO path, size, SHA-256 and build-id;
- the measurement DSO path, size, SHA-256 and build-id;
- the authority DSO path, size, SHA-256 and build-id;
- the DH fixture manifest and the harness source digests;
- whether the tracked implemented-surface manifest matched the freshly derived
  one.

The candidate is built from the frozen, clean source tree into a fresh
`CARGO_TARGET_DIR`; a stale archive is not reused. The build-relevant paths are
`src/`, `Cargo.toml`, `Cargo.lock`, `build.rs` and `rust-toolchain.toml`. A dirty
build-relevant path refuses the campaign.

Every process proves which file it mapped. `bench_api.c` resolves
`dladdr(BN_new)`, reads the mapping's realpath, device and inode from
`/proc/self/maps`, and prints them; the runner compares them with `stat(2)` on the
on-disk DSO. A path mismatch, device mismatch, inode mismatch, size mismatch or
missing maps entry is a refusal, not a warning. The same check applies to the
allocation and cross-verification processes.

---

## 10. Allocation instrument

The same `LD_PRELOAD` probe is applied to both subjects, over the same workload
list, with the same process discipline and the same accounting. The probe counts
`malloc`, `calloc`, `realloc`, `aligned_alloc`, `posix_memalign`, `memalign` and
`free`.

Two counts are reported per workload:

- `allocs_per_op`: every allocation entry point the probe observes;
- `malloc_class_per_op`: the older `malloc`/`calloc`/`realloc` count, retained so
  the new measurement can be compared with earlier candidate-only rows without
  pretending the two instruments are identical.

If the probe cannot observe the authority's allocation pattern, the difference is
recorded rather than comparing unlike numbers.

---

## 11. Correctness and cross-verification

For every repetition, every `CHECK` line from the candidate is compared with the
authority, byte for byte:

- `modexp*` and `dh*` are deterministic and must be identical;
- `rsa2048` must recover its input through `RSA_public_decrypt` in-process and
  match the authority's result;
- `ecdsa256` must verify its own signature and print the same compressed public
  key on both subjects.

At repetitions `00, 03, 06, 09, 12, 14`, a DER signature is produced by one
subject and verified by the other, in both directions: candidate signs and the
authority verifies, then the authority signs and the candidate verifies. Each
verification must return `ok=1`, and the compressed public key derived by the
signer and the verifier must match. A rejection makes the campaign `BLOCKED`.

The cross check is a correctness exchange, not a signature-equality test: the
signature nonce is generated by the library and is expected to differ.

---

## 12. Venue and PMU

The campaign records the court image, container hostname, kernel, machine, CPU
model, CPU flags, cgroup memory and CPU limits, the pinned core and available
memory. It probes the CPU-side PMU through CPUID and the kernel-side interface
through `/sys/bus/event_source/devices` and `perf stat`.

The current venue has no `cpu` event source and reports a hypervisor; `perf stat
-e cycles` does not provide a usable hardware counter. The PMU answer is recorded
in `results.json` and the raw probe outputs are retained. The absence of a PMU is
the reason the results are `SCOPED_OBSERVATION`, not a reason to substitute
another counter silently.

---

## 13. Exhaustion policy

A run that exhausts memory, disk, file descriptors or time is **`BLOCKED`**. It is
not `PASS`, not `PARTIAL` and not a row to be retried at the same size. The
campaign writes a `BLOCKED` marker and stops; a later attempt is a new campaign
with its own identity and its own record.

---

## 14. Exact commands

Run inside the court, from the repository root:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec \
    env CARGO_BUILD_JOBS=4 PFP0_COURT_IMAGE=openssl-rs-court-tools:1 \
    bash courts/phase18/timing/run_bench_api.sh
```

The runner:

1. derives the DH fixtures from `src/bn/dh_data.rs`;
2. writes the preregistration and the realised order before measurement;
3. builds the crate into a fresh target directory and links both candidate DSOs;
4. runs the unrecorded warm-up pair;
5. runs the 15 measured repetitions in the recorded order;
6. runs the allocation probe for both subjects;
7. runs the cross-verification exchanges;
8. writes `results.json` through
   `courts/performance-frontier/baseline/analyse_bench_api.py`.

A JSON validation step is part of the receipt:

```sh
python3 -m json.tool forensics/performance/WORKLOADS.json >/dev/null
python3 -m json.tool forensics/performance/AUTHORITIES.json >/dev/null
python3 -m json.tool evidence/performance-frontier/campaigns/PFP-0/results.json >/dev/null
```

---

## 15. What the campaign does not establish

- It does not establish a frontier result or a hardware-counter result.
- It does not establish constant-time behaviour; it measures time on one
  virtualised venue.
- It does not measure throughput, tail latency, parallel scaling or memory.
- It does not compare against AWS-LC, BoringSSL, rustls, wolfSSL or a research
  kernel, because none is available in this environment; those rows are
  `UNAVAILABLE` or `NOT_APPLICABLE`, not losses.
- It does not establish that the synthetic DH modulus is a group, or that any
  named-group row performs peer validation.
- It does not establish L4 or L5 behaviour; the rows are L3 API operations.
- It does not inherit safety or compatibility graduation from a timing result.

---

## 16. Amendments

The protocol is committed with the campaign. A deviation requires a recorded
amendment naming the reason, the affected rows and the identity of the campaign
before and after the change. A deviation that changes the population, the
repetition count, the statistic or the exclusion rules after seeing data
invalidates the affected rows and requires a new campaign; it is not an
amendment.
