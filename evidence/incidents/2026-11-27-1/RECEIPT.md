# Memory incident 2026-11-27-1 — `rustc-LLVM out of memory` in the PFP-10 builds

Two `rustc` processes aborted with `rustc-LLVM ERROR: out of memory / Allocation
failed` inside the running `openssl-rs-court` cgroup. No kernel OOM line and no
`memory.events` `oom`/`oom_kill` increment was observed
(`low 0 / high 0 / max 18438 / oom 0 / oom_kill 0`); the allocator failure is
inside LLVM. Both are treated as §24.1 incidents because a compile was killed by
memory exhaustion.

## Measurements before the failed commands

| item | value |
|---|---|
| host `available` | 28–31 GiB |
| host `Swap free` | 21–25 GiB |
| court cgroup | `memory.max` 8 589 934 592 (8 GiB), `memory.swap.max` 8 GiB |
| court `memory.current` at the time | ≈ 0.43 GiB (page cache) |

The host was not under pressure; the binding limit was the container's 8 GiB cap,
which the running container was created with by the earlier session. The
operator's guard (`available >= 16`, `Swap free >= 16`) was met for every
command.

## Incident 1 — release-like test harness at four parallel jobs

```
OPENSSL_RS_COURT_MEM=… docker/openssl-rs-court.sh exec env \
  CARGO_BUILD_JOBS=4 CARGO_PROFILE_TEST_OPT_LEVEL=3 \
  CARGO_PROFILE_TEST_DEBUG=0 cargo test --lib --no-run
→ rustc-LLVM ERROR: out of memory
```

**Lost:** the measurement binary for that attempt. Nothing else.

**Reduced unit that succeeded:**

```
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_OPT_LEVEL=3 \
CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=false \
  cargo test --lib --no-run        (1 m 20 s, success)
```

## Incident 2 — dev test harness with debuginfo at four parallel jobs

```
CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 cargo test --lib -- --test-threads=4
→ rustc-LLVM ERROR: out of memory
```

**Lost:** the first attempt at the full library gate. Nothing else.

**Reduced unit that succeeded:**

```
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --lib -- --test-threads=4
→ 2 507 passed; 0 failed; 56 ignored; 123.17 s
```

## Discipline applied afterwards

* every subsequent build used `CARGO_INCREMENTAL=0` (avoids the 577 MiB
  incremental cache and its write churn, and the arena growth it implies);
* the release-like test profile is built one job at a time;
* no command was retried at its original size; each was re-run only after the
  unit was reduced;
* the ignored measurement/differential tests are executed directly from the
  already-built binary, so no rebuild is needed per case.

## What was **not** lost

Correctness and ctgrind evidence were produced from the reduced-unit builds and
are reported in `evidence/performance-frontier/campaigns/PFP-10/RECEIPT.md`. No
test result obtained during an aborted build is reported as a pass.
