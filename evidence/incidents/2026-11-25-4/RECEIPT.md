# Incident 2026-11-25-4 — the release *test* build aborted on LLVM allocation

AGENTS.md §24. A single `rustc` process compiling the release `--test` target of
the crate exceeded the court's per-process `RLIMIT_DATA` (4 GiB) and aborted with
`rustc-LLVM ERROR: out of memory`. The cgroup did **not** OOM-kill and the host
did not run out; the per-process data cap is what fired. This receipt records the
command, the measurements, the abort, what was lost, and the reduced unit that
replaced it. It is written by the batch that saw the incident.

## 1. The command and the venue

| field | value |
|---|---|
| command | `cargo test --release --lib -- ec::p256::tests::pfp2_kernel_measurement --no-run` (then the same binary per repetition) |
| purpose | re-run the PFP-2 kernel mutation control in the release profile, to compare with the recorded release ratios (`mul` 4.01×, `ladder` 2.40×) |
| venue | the pre-existing `openssl-rs-court` container, image `openssl-rs-court-tools:1`, cgroup `Memory=8589934592` (8 GiB), `MemorySwap=8589934592`, `OPENSSL_RS_COURT_DATA=4194304` KiB |
| concurrent heavy commands | one: nothing else was running |

## 2. Measurements

| field | value |
|---|---|
| host `free -g` immediately before | `Mem: 45 16 27 0 2 29` — available **29 GiB** |
| cap | container 8 GiB; §24.4 `min(4g, 29 − 8) = 4g` is met |
| per-process `RLIMIT_DATA` | `ulimit -d` = `4194304` KiB (4 GiB), the court default |
| cgroup `memory.current` at inspection | 829,132,800 bytes |
| cgroup `memory.events` | `oom=0 oom_kill=0` |
| `docker inspect .State.OOMKilled` | `false` |
| exit | `signal: 6 (SIGABRT)`, `rustc-LLVM ERROR: out of memory`, `Allocation failed` |

## 3. OOM evidence

```
Compiling openssl-rs v0.0.49 (/work)
rustc-LLVM ERROR: out of memory
Allocation failed
error: could not compile `openssl-rs` (lib test)
...
(process didn't exit successfully: ... rustc ... --test ...) (signal: 6, SIGABRT)
```

`cgroup memory.events` stayed `oom=0 oom_kill=0`; the abort is an in-process
`malloc` failure against `RLIMIT_DATA`, not a cgroup kill. The 8 GiB cgroup had
headroom; the 4 GiB per-process data cap did not.

## 4. What was lost

The release-profile mutation-control re-run. The recorded release ratios
(`mul` 4.01×, `ladder` 2.40×) therefore remain **history**, not re-measured by
this batch.

## 5. The reduced unit that replaced it

The same mutation control was measured in the **debug** profile, where the test
binary was already built and does not need the whole-crate release `--test`
codegen: three rotated repetitions of `pfp2_kernel_measurement` with
`PFP2_MEASURE=1`. Debug ratios are profile-dependent and are reported as a
load-bearing check only, not as a replacement for the recorded release figures.

§24.5 units subsequently run in this batch: `cargo test --lib -- p256` (debug),
`cargo clippy --all-targets -- -D warnings` (debug), the debug
`pfp2_kernel_measurement` repetitions, and the valgrind/ctgrind and branch-audit
runs. The release **library** build (no `--test`) does fit and was used for the
distribution DSO.
