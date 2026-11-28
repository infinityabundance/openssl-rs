# PFP-66 receipt — machine-readable workload identity

**Decision: the identity is data, and a trend comparison between rows whose
timed operation sets differ is refused with `BENCH_TREND_IDENTITY_MISMATCH`.**
The motivating case — PFP-11's P-256 sign+verify row against M-A1's sign-only
row, both labelled `ecdsa256` — is the negative control and is refused.

## 1. Schema / registry extended (no parallel registry)

`forensics/performance/WORKLOADS.json` (`openssl-rs/performance/workloads/v1`)
is the existing population registry. It gained:

* `timed_operations: [ … ]` on every workload (the operations whose calls are
  inside the timed region);
* a top-level `workload_identity_schema` rule: two rows are comparable only when
  both `workload_id` **and** `timed_operations` are identical; the id is a label,
  never the identity.

`courts/performance-frontier/baseline/analyse_bench_api.py` now emits a
`workload_identity` on every timing row of `results/v1`.

Campaign rows that time a different operation set carry their own block:

| record | row | `workload_identity` |
|---|---|---|
| `campaigns/M-A1/timing/raw/timing-summary.json` | `/workloads/ecdsa256` | `{ecdsa256, [ECDSA_do_sign]}` |
| `campaigns/PFP-11/raw/phase2-three-arm.json` | `/p256/ecdsa256` | `{ecdsa256, [ECDSA_do_sign, ECDSA_do_verify]}` |
| same | `/p521/ecdsa-sign-p521` | `{ecdsa-sign-p521, [ECDSA_do_sign]}` |
| same | `/p521/ecdsa-verify-p521` | `{ecdsa-verify-p521, [ECDSA_do_verify]}` |

The two JSON records were rewritten with sorted keys by
`campaigns/PFP-66/stamp_workload_identities.py`; every numeric value is
unchanged (the diff is key ordering plus the new `workload_identity` blocks).

## 2. Comparison tooling and refusal code

`forensics/tools/benchmark_trend.py` resolves two rows (JSON pointers), validates
their `workload_identity`, and:

* emits a comparable record when both id and operations are equal;
* otherwise exits **1** with
  `BENCH_TREND_REFUSED code=BENCH_TREND_IDENTITY_MISMATCH` (specific code);
* also refuses `BENCH_TREND_IDENTITY_ABSENT`, `BENCH_TREND_IDENTITY_MALFORMED`
  and `BENCH_TREND_ROW_ABSENT`.

The negative control in `forensics/tools/tests/test_benchmark_trend.py` runs the
exact comparison:

```
first = /workloads/ecdsa256  (M-A1,  sign only)
second= /p256/ecdsa256       (PFP-11, sign + verify)
→ BENCH_TREND_REFUSED code=BENCH_TREND_IDENTITY_MISMATCH
```

Observed CLI result: `BENCH_TREND_REFUSED code=BENCH_TREND_IDENTITY_MISMATCH
detail=… first={id='ecdsa256', timed_operations=['ECDSA_do_sign']}
second={id='ecdsa256', timed_operations=['ECDSA_do_sign', 'ECDSA_do_verify']}`,
exit 1. The two rows share the label, so the refusal comes from the data, not
from a naming convention. 10 unit tests, 0 failures.

## 3. Supersede of the PFP-11 P-256 row

`campaigns/PFP-11/RECEIPT.md` §15: the row labelled `P-256 ECDSA sign` is renamed
**`P-256 ECDSA sign + verify`** by an in-place supersede; the numbers are
unchanged and the old label remains visible in the supersede text. The
"one canonical row, two instruments" paragraph gained the matching note. The
queue's `PFP-11` row carries a `PFP-66 note` recording the identity.

## 4. Gate

* `cargo fmt --all -- --check`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo test --lib -- --test-threads=4`: **2564 passed, 0 failed, 56 ignored**.
* `python3 -m unittest forensics.tools.tests.test_benchmark_trend`: **10 passed**.

## 5. Memory (court `openssl-rs-court`, `memory.max=4294967296`)

`available` 21 GiB, `Swap free` 8 GiB, cap `min(4, available − 8) = 4 GiB`
(floor 2). `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`, one heavy command
at a time. The Python tool/tests were run on the host (no compilation).

## 6. Files

`forensics/performance/WORKLOADS.json`,
`courts/performance-frontier/baseline/analyse_bench_api.py`,
`forensics/tools/benchmark_trend.py`,
`forensics/tools/tests/test_benchmark_trend.py`,
`evidence/performance-frontier/campaigns/M-A1/timing/raw/timing-summary.json`,
`evidence/performance-frontier/campaigns/PFP-11/raw/phase2-three-arm.json`,
`evidence/performance-frontier/campaigns/PFP-11/RECEIPT.md`,
`docs/PERFORMANCE-FRONTIER-TODO.md`.
