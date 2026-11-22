# Instrument qualification (ETP-3)

**Status:** normative register for the assurance instruments named below, at
`staging` = `342934733` (ETP-3 hardening 2, 2026-11-22). The machine-readable
form is `evidence/etp3/instruments.json`; the executable check is
`forensics/tools/instrument_qualify.py`. This document states what each
instrument may be cited for and what it may not. It does not restate the
code-generation binding rules in `docs/CODE-GENERATION-ASSURANCE.md` or the
measurement protocol in `docs/PERFORMANCE-METHODOLOGY.md`; it extends them with
qualification of the instruments those documents rely on.

## 0. Qualification is not a security result

An instrument is qualified when its intended use is stated, its failure modes
and soundness limits are named, its version is identified, its sensitivity
controls fire, and it refuses to emit a verdict from an incomplete population.
A `PASS` in this register means exactly that the instrument's own controls
fired in the session that ran them.

It does **not** mean:

- that a measurement is correct, representative or reproducible elsewhere;
- that absence of a report establishes absence of the property (no memcheck
  result is a constant-time proof; no dudect `state 1` is constant time; no
  BINSEC `secure` is a timing result);
- that a defect class an instrument's controls do not exercise has been
  detected;
- that any claim in `evidence/etp/` is true. The claim algebra checks typing
  and law, never truth.

`AGENTS.md` §8 governs: compatible, safe and cryptographic evidence are
separate axes, and one axis's instrument never stands in for another.

## 1. How the register is checked

```
python3 forensics/tools/instrument_qualify.py validate   # register, paths, versions, bindings
python3 forensics/tools/instrument_qualify.py controls   # refusal and sensitivity controls
python3 forensics/tools/instrument_qualify.py check      # both, plus the recorded case table
python3 forensics/tools/tests/test_instrument_qualify.py # negative controls for the checker
```

The checker refuses, with a named code on stderr, when:

| code | condition |
|---|---|
| `IQ_VERSION_MISMATCH` | the recorded version string is no longer produced by the tool |
| `IQ_VERSION_NONZERO` | a version command printed the recorded string but exited nonzero, and the instrument did not declare the allowance |
| `IQ_VERSION_JUSTIFICATION` | an instrument declared `accept_nonzero_exit` without a non-empty justification |
| `IQ_PATH_MISSING` | a named instrument path does not exist |
| `IQ_CONTROL_UNKNOWN` | a control id has no implementation |
| `IQ_CONTROL_PREREQUISITE` | a declared prerequisite is absent or its digest changed |
| `IQ_RECORD_STALE` | a recorded control's bound evidence, or an asserted string in it, changed |
| `IQ_CONTROL_STATUS` | a status claims more than its evidence (for example a recorded control marked `PASS`) |
| `IQ_CONTROL_FAILED` | a live control case exited other than expected, or a control that must fire did not |
| `IQ_DISCLAIMER` / `IQ_VENUE` | the register lost the "not a security result" statement or misdescribes the venue |
| `IQ_JSON_DUPLICATE_KEY` / `IQ_JSON_NON_FINITE` | the register has no single meaning |

`check` also compares the live `(case, exit)` table to the table recorded in the
register. A control whose behaviour changed cannot leave the register silently
green: the run is refused as `CONTROL_STALE` until the entry is re-qualified.

A nonzero version probe is **not** the default contract. An instrument that
legitimately prints its version and then exits nonzero must declare
`version_validation.accept_nonzero_exit: true` **and** a non-empty
`version_validation.nonzero_exit_justification`; any other nonzero probe is
refused as `IQ_VERSION_NONZERO`, even when the expected string is present.
No instrument in the current register declares the allowance; the two checker
controls (an undeclared nonzero probe must fail, and a declared justified probe
must pass) are in `forensics/tools/tests/test_instrument_qualify.py`.

Two statuses are distinct and are never conflated:

- **`PASS`** — the control executed in the checking session and every case
  matched.
- **`RECORDED`** — the control was executed for a bound, tracked evidence
  artefact whose digest still matches, and was not re-executed here. The
  register never reports a recorded control as `PASS`.

## 2. Venue

| property | value |
|---|---|
| court image | `openssl-rs-court-tools:1` |
| kernel / CPU | `7.3.5-2-cachyos` / 13th Gen Intel Core i9-13900K |
| hardware PMU | **absent**: `cpuid.0A.version=0`, `num_general_counters=0`, `cpuid.1 hypervisor_present=1`, no `cpu` event source, `perf stat -e cycles` prints `<not supported>` |
| network | **present** (corrected at ETP-4): `getent hosts crates.io` resolves; `curl -sSI https://static.crates.io/` returns HTTP/2 404 (host reachable), GitHub and `static.rust-lang.org` return 200, `apt-get update` exits 0. The earlier entry recorded "absent", which ETP-4's tool-availability probe falsified |
| pinned prerequisites | `dudect.h` is vendored at `courts/phase18/timing/third_party/dudect/dudect.h` (digest-checked). The pinned solver is Z3 4.13.0 at `/opt/z3-solver/z3-4.13.0-x64-glibc-2.35/bin/z3`, installed by `forensics/tools/install_z3_pinned.sh` with archive and binary digests. The image's `/usr/bin/z3` is 4.8.12 and is *not* the pinned solver. No second instruction decoder is present |

The missing PMU is a **venue limitation, not an instrument property**. It is
the reason performance rows are `SCOPED_OBSERVATION`; it is not a defect of
`perf`, of `tsc_clock`, or of the crate, and it does not license the
substitution of a software event for a hardware counter.

`perf stat -e cycles true` exits **0** while printing `<not supported>`. The
exit status alone is therefore never the signal for an unavailable event; the
probe checks the text. This is recorded in the register's `failure_modes` for
`perf-pmu`.

## 3. Register summary

| id | instrument | intended use | version identified |
|---|---|---|---|
| `valgrind-ctgrind` | Valgrind memcheck + client requests | secret-dependent branch/address use on an executed path | `valgrind-3.19.0` |
| `dudect` | dudect-style t-test harness | timing difference between two input classes at a stated geometry | pinned commit + vendored `dudect.h` digest |
| `binsec-checkct` | BINSEC `-checkct` + SSE script | control-flow/memory dependence on a declared secret split | `Binsec version 0.11.3`, pinned Z3 4.13.0 |
| `timecop-supercop` | TIMECOP patch on SUPERCOP | method-level secret-dependent-flow detection on SUPERCOP trees | tarball digest `e4fe70eb…` |
| `perf-pmu` | perf + CPUID probe | whether this venue exposes architectural counters | `perf version 6.1.192` |
| `tsc-smi-fallbacks` | kernel `msr` PMU + serialised RDTSC | reference-clock/SMI measurement when no PMU exists | `cc` 12.2.0, source-bound |
| `binary-branch-audit` | `binary_branch_audit.py` | emitted instruction shape in a named function of one DSO | objdump 2.40, Python 3.11.2 |
| `differential-bench-court` | `bench_api` + runner + analyser | paired candidate/authority ratio and correctness exchange | Python 3.11.2, DSO digests |
| `alloc-probe` | `alloc_probe.c` | allocation entry points and forced failure | `cc` 12.2.0 |
| `build-reproducibility` | `build_reproducibility.sh` | byte equality of two independent builds | `ar` 2.40, rustc 1.98.1 |
| `etp-claims` | `etp_claims.py` | claim typing, laws and digest re-derivation | Python 3.11.2 |

Each entry in `evidence/etp3/instruments.json` carries the full record: the
one question it may answer, what it must never be cited for, its version
command and how it identifies the binary it actually ran, its seven failure
modes, its soundness limits, its scope, its paired sensitivity control with the
observed output, and its exit-status contract.

## 4. Timing scope: debug versus release

This distinction is normative and was previously implicit.

- The crate's **ctgrind cases run a debug-profile test binary** (`cargo test`).
  They establish *source-level dynamic observation*: that memcheck, on the
  executed path, observed a secret-dependent branch or address use. They do
  **not** establish the timing behaviour of the release DSO, and they must not
  be cited as release-binary timing assurance.
- The **dudect harness is compiled `-O2` and loads the release Phase-2 DSO**,
  but the venue has no PMU and no frequency/SMT control, so its result is a
  statistical observation at a stated sample size, not a constant-time result.
- The **binary branch audit reads the release DSO** and is the instrument that
  speaks about emitted machine code. It reports instruction shape only.

A constant-time claim therefore needs all three, and still does not follow from
any of them: source-level taint observation (ctgrind, debug), statistical
timing on this venue (dudect, release DSO), and instruction shape at the
shipping profile (branch audit, release DSO). `AGENTS.md` §5.2 and
`docs/CODE-GENERATION-ASSURANCE.md` govern the code-generation half.

## 5. The two fail-open defects and their closure

Both are now **release gates**: the exit status is authoritative and every
refusal names the specific target and reason on stderr. The human-readable
report is preserved.

### 5.1 `courts/phase18/timing/binsec_checkct.sh`

The committed script treated `insecure` as a verdict and returned the
underlying process status, which is zero when BINSEC reports an insecure
program. A wrapper that reports `insecure` and exits 0 can be read as a pass by
any caller that checks only the status.

```
# before (committed script), stand-in tool reporting insecure and exiting 0
$ EQ_MODE=insecure_zero bash binsec_checkct.sh fake.cfg tiny-elf
T16 verdict: insecure
$ echo $?
0

# after
$ EQ_MODE=insecure_zero bash courts/phase18/timing/binsec_checkct.sh fake.cfg tiny-elf
T16 verdict: insecure
$ echo $?
1

$ bash courts/phase18/timing/binsec_checkct.sh --require-secure fake.cfg tiny-elf
binsec_checkct: REFUSED target='…/tiny-elf' reason=required-secure but verdict=insecure
$ echo $?
8
```

New contract: `0` secure, `1` insecure, `2` invocation/venue refusal, `3` no
verdict line, `4` unknown, `5` candidate identity mismatch, `6` tool or
wall-clock failure, `8` `--require-secure` not satisfied. `unknown`, silence and
a truncated result line were already refused (4 and 3) and remain refused. The
wrapper now also refuses a non-ELF input before the tool runs, bounds the whole
run with a wall-clock timeout, and can bind the run to
`BINSEC_EXPECT_SHA256`.

**Interpretation change.** The T16 row previously said the script "exits 0 only
for secure/insecure". That is no longer true: exit 0 now means *secure*. No
tracked JSON receipt cites this exit status; the T16 row is updated. A
historical run that returned `insecure` with status 0 must be re-read as a
refusal, not a verdict of either kind.

#### 5.1.1 Complete verdict population (hardening 2)

The first repair still tested for the secure line **before** the insecure line,
so a transcript containing both was accepted as secure when the tool exited
zero. The wrapper now classifies the complete status population before deciding:

- the canonical line is `[checkct:result] Program status is : <verdict>`, with an
  optional ` (<seconds>)` field that is BINSEC's own elapsed time;
- the grammar is anchored to the whole line, so a verdict followed by any other
  text is refused as `verdict-trailing-text` (exit 3);
- zero well-formed verdicts is `no-verdict-line` (exit 3);
- two or more is refused: `mixed-verdicts` when secure and insecure coexist,
  `duplicate-secure` when secure is repeated, and `multiple-verdicts` otherwise
  (all exit 6);
- exactly one verdict is then dispatched under the existing `0/1/4/8` contract.

Controls: a secure verdict carrying BINSEC's timing suffix is accepted; a mixed
transcript, a duplicated secure transcript, a multiple transcript and a verdict
line with additional text are refused. The stand-in-tool control does not
exercise the solver; the live solver rows are in §7.

### 5.2 `courts/phase18/timing/binary_branch_audit.py`

At `72aee5630` the missing/ambiguous-target exits were already nonzero (commit
`285257520`); the description "a missing target prints missing but the script
can exit 0" **did not reproduce**. The residual fail-opens were:

| input | before (`HEAD` script) | after |
|---|---|---|
| zero-size symbol (no declared extent) | invented a 16-byte window and exited **0** | refused `reason=zero-size`, exit **1** |
| symbol whose final identifier has a malformed length prefix | accepted as the target and exited **0** | refused `reason=missing`, exit **1** |
| truncated disassembly of the recorded candidate | 7/7 "resolved", exit **0** | refused `reason=disassembly-truncated`, exit **1** |
| hole in the decoded stream | not detected | refused `reason=disassembly-hole`, exit **1** |
| a one-byte instruction omitted, every remaining address step ≤ 15 bytes | accepted, exit **0** | refused `reason=disassembly-hole`, exit **1** |
| overlapping decoded instruction | not detected | refused `reason=disassembly-overlap`, exit **1** |
| disassembly ending past the symbol boundary | not detected | refused `reason=disassembly-overrun`, exit **1** |
| hung `objdump` | unbounded wait | bounded refusal, exit **1** |
| wrong candidate | digest printed only | `--expect-sha256` mismatch, exit **3** |
| missing target | exit 1, generic stderr | exit 1, one `REFUSED target=… reason=…` line per target |

Symbol resolution is now exact by construction: the digits immediately before
the final identifier must parse to exactly its length, so a symbol that merely
*ends* with `<len><name>` is not a match. Ambiguity is refused. The coverage
invariant is **byte coverage**, not an address-gap bound: every instruction's
decoded length is taken from its raw byte field, each instruction must start
where the previous one ended, the first must start at the symbol address, and
the last must end exactly at the declared extent. A gap, overlap, truncation,
overrun or decoded-byte-count mismatch is a refusal. An address step of at most
15 bytes is not evidence that the intervening bytes were decoded; the
address-gap test of the first repair accepted a transcript that omitted a
one-byte instruction. The omission control now exits 1 with
`disassembly-hole:gap=+0x1@+0xe` where the pre-repair script exits 0 with
1/1 "resolved".

```
$ python3 courts/phase18/timing/binary_branch_audit.py \
    --expect-sha256 ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9 \
    court/tmp/p4/libcrypto.so.3
binary_branch_audit: 7 expected targets resolved uniquely with complete disassembly; candidate sha256=ee7fa27c…
$ echo $?
0

# earlier ETP-3 run on the stale tracked DSO; not re-run in hardening 2
$ python3 courts/phase18/timing/binary_branch_audit.py \
    artifacts/phase2/install/lib/libcrypto.so.3
REFUSED target="Montgomery multiply (core)" symbol="mont_mul_into" reason=missing
… (four targets)
binary_branch_audit: FAIL-CLOSED: 4 of 7 expected targets were refused; this report is not a gate result.
$ echo $?
1
```

**Interpretation change.** `courts/phase18/timing/RECEIPT-timing-unified.json`
records `branch_audit.exit = 0` with 7/7 resolved on
`ee7fa27c…`. The byte-coverage script re-run on that same digest still exits 0
with 7/7 and the same per-function figures, so that receipt's interpretation is
unchanged and the stricter invariant found **no coverage defect** in the
recorded run. A run whose exit status was 0 with a truncated, holed, overlapping
or overrunning population would now be a refusal; no such run is recorded.

**Single-decoder limit.** The tools image has no second instruction decoder
(`llvm-objdump`, `ndisasm`, `gdb` and Python `capstone` are absent). Byte
coverage is therefore established with GNU objdump alone. A decoder defect that
omitted an instruction while preserving contiguity would not be cross-checked;
this is recorded as an open limit, not as a passed check.

## 6. Adversarial controls

Every **refusal** control asserts a nonzero exit and a named refusal; the
positive controls assert the exit-0 path. Commands run in the court;
`python3 forensics/tools/instrument_qualify.py controls` executes all of them.

| control | input | refusal observed | exit |
|---|---|---|---|
| branch audit, missing | inventory names an absent symbol | `reason=missing` | 1 |
| branch audit, ambiguous | two symbols with the same final identifier | `reason=ambiguous` + candidates | 1 |
| branch audit, zero-size | function symbol with no `.size` | `reason=zero-size` | 1 |
| branch audit, truncated | objdump shim printing the first four instructions | `reason=disassembly-truncated` | 1 |
| branch audit, empty | objdump shim printing no instruction lines | `reason=empty-disassembly` | 1 |
| branch audit, hole | shim printing first and last instructions only | `reason=disassembly-hole` | 1 |
| branch audit, omitted short instruction | shim removing a one-byte `nop`, all address steps ≤ 15 bytes | `reason=disassembly-hole` (`gap=+0x1`) | 1 |
| branch audit, overlap | shim printing one instruction line twice | `reason=disassembly-overlap` | 1 |
| branch audit, overrun | shim appending an instruction at the stop address | `reason=disassembly-overrun` | 1 |
| branch audit, timeout | shim that sleeps, `--timeout 1` | `reason=timeout` | 1 |
| branch audit, unsupported format | a text file | `unsupported format … not an ELF file` | 2 |
| branch audit, wrong candidate | `--expect-sha256` of a different DSO | `candidate-identity-mismatch` | 3 |
| BINSEC, insecure | tool prints `insecure`, exits 0 | `T16 verdict: insecure` | 1 |
| BINSEC, timed secure | tool prints `secure (0.030)`, exits 0 | `T16 verdict: secure` | 0 |
| BINSEC, mixed | tool prints `secure` then `insecure`, exits 0 | `reason=mixed-verdicts` | 6 |
| BINSEC, duplicated secure | tool prints `secure` twice, exits 0 | `reason=duplicate-secure` | 6 |
| BINSEC, multiple | tool prints `insecure` twice, exits 0 | `reason=multiple-verdicts` | 6 |
| BINSEC, trailing text | `secure (0.030) but the exploration was incomplete` | `reason=verdict-trailing-text` | 3 |
| BINSEC, unknown | tool prints `unknown` | `unknown (incomplete; NOT a pass)` | 4 |
| BINSEC, `--require-secure` | insecure or unknown | `reason=required-secure but verdict=…` | 8 |
| BINSEC, silence | tool exits 0 with no output | `reason=no-output` | 3 |
| BINSEC, truncated verdict | `Program status is : sec` | `reason=no-verdict-line` | 3 |
| BINSEC, crash | tool exits 2 with no verdict | `reason=no-verdict-line` | 3 |
| BINSEC, inconsistent | secure verdict with nonzero tool status | `reason=secure-verdict-with-tool-status-…` | 6 |
| BINSEC, timeout | sleeping tool, `BINSEC_WALL_TIMEOUT=1` | `reason=timeout` | 6 |
| BINSEC, wrong candidate | `BINSEC_EXPECT_SHA256` mismatch | `reason=candidate-identity-mismatch` | 5 |
| BINSEC, unsupported format | non-ELF input | `reason=unsupported-format` | 2 |
| BINSEC, missing script | absent `.cfg` | `reason=cannot-read-script` | 2 |

The BINSEC control uses stand-in `binsec` and `z3` executables. It qualifies the
wrapper's exit-status contract; it does **not** exercise the solver's verdicts.
That separation is deliberate: a wrapper control cannot stand in for a solver
result. The solver's live verdicts are recorded separately in the register's
`live_solver` list and in §7.

## 7. Sensitivity controls and `UNKNOWN` entries

| instrument | positive control | negative control | observed in this session |
|---|---|---|---|
| ctgrind | `cmpnaive` reports errors | `cmpcmp` is clean | 99 / 0 |
| dudect | `cmpnaive` state 0 | `cmpcmp` state 1 | 0 / 1 (exit 0 / 1; 40000 / 60000 measurements) |
| branch audit | fixtures resolve, exit 0 | every malformed inventory refused | 13 cases |
| BINSEC wrapper | secure exits 0; timed secure exits 0 | insecure, unknown, mixed, duplicate, multiple, trailing text and silence refused | 19 cases |
| differential analyser | well-formed campaign accepted | malformed populations refused | 34 tests |
| alloc probe | two mallocs counted | forced failure hits the second | 2 cases |
| build reproducibility | identical archives equal | a different object detected | self-test |
| claim algebra | committed document validates | 59 adversarial cases refused | 59 tests |
| PMU venue | CPUID version 0 | software events work, cycles unsupported | 3 cases |

Not established in this session, recorded as `UNKNOWN` with its settling
method rather than as a pass:

- **BINSEC live verdicts (now reachable).** The pinned Z3 4.13.0 is installed by
  `forensics/tools/install_z3_pinned.sh` (archive `884e3a41…`, binary
  `0be0492e…`, both verified) and the wrapper was run with `BINSEC_Z3` pointing
  at it. The targets produced:

  | target | SSE script | verdict | wrapper exit |
  |---|---|---|---:|
  | `court/tmp/t16/ka_ct` | `ka.cfg` | `secure` | 0 |
  | `court/tmp/t16/ka_leaky` | `ka.cfg` | `insecure` | 1 |
  | `court/tmp/t16/memcmp_probe` | `memcmp.cfg` | `secure` | 0 |
  | `court/tmp/t16/real_rs` | `real_rs.cfg` | `unknown` | 4 |
  | `court/tmp/t16/inv_rs` | `inv.cfg` | `unknown` | 4 |

  The two `unknown` rows are real results at the 240 s exploration bound, not a
  failure of the repair: the standard library's allocator dispatch and
  `rust_oom` remain unresolved indirects in a statically linked binary. `unknown`
  is not a pass. The `secure` rows are model-relative to their declared
  secret/public splits and do not establish constant time.
- **TIMECOP/SUPERCOP (`RECORDED`).** The SUPERCOP 20190816 tarball is
  not present, which is why the control was not re-executed at ETP-3. The
  network entry above is corrected: reachability was established at ETP-4, so
  absence of the tarball is a missing artefact, not a missing route. The
  register binds the control to
  the tracked runner's digest and asserts the `valgrind_pass` /
  `valgrind_fail` strings and the `zz-leaky-control` fixture. Re-execution is
  the settling method.
- **TSC/SMI fallbacks (`RECORDED`).** The recorded numbers
  (7 931 483 421 ticks, 0 SMI) came from a root-capable host outside the court.
  Re-execution where `/dev/cpu/0/msr` is readable is the settling method.
- **Single-decoder instruction boundary.** No second decoder is available in the
  tools image, so the branch audit's byte coverage is not cross-checked. A
  decoder defect that preserved contiguity would be invisible. This is an open
  limit of the venue, not a passing check.
- **The live two-library differential.** PFP-0's measured campaign is bound to
  its own candidate and is not re-run here; the executable control qualifies
  the analyser's refusals, not a new measurement.

**Closed at hardening 2.** The dudect header is now vendored at
`courts/phase18/timing/third_party/dudect/dudect.h` with the pinned digest, so a
clean checkout re-qualifies the control; the z3 entry is no longer `UNKNOWN`
because the pinned solver is installed by a tracked, digest-verified script.
Changing the vendored dudect digest is a register refusal until the control is
re-qualified; the z3 archive and binary digests are checked by the installer on
every install and fail closed on a mismatch.

## 8. What this register does not establish

- It does not establish that any instrument is complete for its defect class.
  A control demonstrates that the instrument *can* detect the class it is
  pointed at; it does not bound what the instrument misses.
- It does not establish that the branch audit's single decoder is correct. A
  second decoder is not available in the venue, so a contiguity-preserving
  decoder error would not be detected.
- It does not establish constant-time behaviour, memory safety, compatibility
  or correctness for any artefact.
- It does not make a recorded control current. `RECORDED` is not `PASS`, and an
  `UNKNOWN` entry blocks any citation that needs it.
- It does not authenticate the reviewer of a sensitivity control, and it does
  not replace the independent adjudication in `AGENTS.md` §15 and §22.
- It does not promote any claim in `evidence/etp/`; the claim algebra's
  `verified: false` TCB entries for instrument qualification change only when
  an obligation is independently checked against these controls.

## 9. Invalidation

The register is stale, and the checker refuses, when:

- an instrument's recorded version string is no longer produced;
- an instrument path disappears;
- a control's live `(case, exit)` table differs from the recorded table;
- a recorded control's bound file digest, or an asserted string in it, changes;
- a declared prerequisite (the vendored dudect header, or the pinned z3 binary)
  is absent or changed;
- the venue's PMU answer changes. A venue with a usable PMU requires a new
  register entry and new sensitivity controls, not an edited `pmu_present`.

Every change to a control's expectations is a change to the instrument's
qualification and requires re-running `check` and the checker's own negative
controls.
