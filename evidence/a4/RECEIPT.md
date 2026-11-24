# A4 receipt — truthful locations for Rust, FFI and binary findings

## 1. Identity of this batch

| field | value |
|---|---|
| item | A4 (location fidelity: macro expansion, monomorphisation, the C ABI, indirect dispatch, optimised code, symbol-only occurrences) |
| branch | `staging` |
| HEAD at the start | `5f868b04f8e3c9c966a3f7cce72a71cc9b00f542` (`wip(etp-a4): observation control finds a transcribed symbol extent`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | total 45, used 45, free 0, available **0** GiB; swap total 45, used 33, free 12 |
| `/proc/meminfo` MemAvailable at measurement | 723 376 kB (inside the court, which reads the host figure) |
| derived court cap | `min(8g, 0 − 16)` is negative, below the 2 GiB floor, so **no cap was established and no new court was started** |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no build; no `src/`, `docker/` or other item's evidence modified |

The cap rule could not be met from live availability: `available` was 0 GiB, so a
new court would have been started below the 2 GiB floor. The running court was
reused instead, and that reuse is recorded here rather than presented as a
derived cap. No build was required for this item; the gates are Python only.

## 2. What was delivered

| path | role |
|---|---|
| `docs/LOCATION-FIDELITY.md` | normative document: purpose and scope, the eight classes with subjects, truthful form, unavailable fields, never-emitted forms, reachable precision, real instance and consequence; the real-instance versus synthetic-control distinction; the projection and check algorithm; all twenty refusal codes; controls and measured figures; non-claims; `NOT_RUN` |
| `forensics/tools/tests/test_location_fidelity.py` | 58 controls: registry, round trip, the five required refusal controls, one control per remaining refusal code, precision non-fabrication, provenance and integrity, the A1 scan, determinism, the command line, and document synchronisation |
| `evidence/a4/RECEIPT.md` | this receipt |

No implementation or evidence record was changed. `forensics/tools/location_fidelity.py`,
`evidence/a4/build_instances.py`, `evidence/a4/CLASSES.json` and
`evidence/a4/INSTANCES.json` are unchanged from `5f868b04f`; regeneration on the
spot reproduces both generated files byte-for-byte (SHA-256
`0a7639a30f0d3684e9bcdcfb2f741088a2716230d5027d8b9e49bb8a00913334` for
`CLASSES.json` and `4887d605e822d67be878dc967d455958c5ab42625ad2ec26e9c52355219f584f`
for `INSTANCES.json`).

## 3. The rule

An emitted location is a claim. A3 owns *identity*; A4 owns *the location of one
finding*. The rule is:

> No line, column, extent, address, symbol, call site or expansion origin is
> emitted unless the native record carries it.

`project(record)` builds the most precise truthful location the record supports
and refuses an internally inconsistent record. `check(record, emission)`
re-derives that projection and accepts only a canonically equal emission
(`json.dumps(value, sort_keys=True, separators=(",", ":"))`). A coarser truthful
location is emitted when a field is absent; the absence is recorded in
`limitations` rather than filled from the compiler, the source text or a
neighbouring symbol.

## 4. The eight classes

| class id | real instance | truthful binary or source form |
|---|---|---|
| `inline-macro-expansion` | `L1-cmp-ctx-cb-to-ptr` | invocation line 759 for a token written at the invocation; definition line 738 only for a body token; recorded origin as metadata |
| `macro-rules-derive-output` | `L2-define-new-free` | one lexical row at `string.rs:562` for every generated `*_free`; no per-instantiation line |
| `monomorphised-generic` | `L3-md32-update` | generic body `md32.rs:118` as background; binary location is the mangled instance symbol and its recorded extent |
| `dynamic-dispatch` | `L4-bsearch-dyn-call` | containing function plus call site `0x3f551c`, `call *%r13` for the `&mut dyn FnMut` call at `bsearch.rs:85` |
| `no-mangle-export` | `L5-cmp-ctx-export` | declaration `cmp_ctx.rs:748` for source; `libcrypto+0x27abd0`, size `0x77` for the machine code |
| `indirect-function-pointer-call` | `L6-store-loader-closefn` | function `0x36eee0`, call site `0x36f8d3`, `call *%rax`, provenance `OsslStoreLoader.closefn` (closure row 109) |
| `inlined-optimised-code` | `L7-store-close-it`, `L7-compress-staged` | the enclosing out-of-line symbol only; no symbol and no call site for the inlined body |
| `binary-symbol-only` | `L8-bn-mod-inverse` | dynsym name, offset `0x3cf4a0`, size 1137, GOT slot; symbol presence establishes no reachability |

The precision vocabulary is closed: `none`, `symbol-only`, `line`,
`definition-site`, `generic-definition-body`, `byte-offset-in-artifact`,
`function-offset-and-extent`, `call-site-offset-in-artifact`,
`record-condition`.

## 5. Controls and measured figures

| quantity | measured |
|---|---|
| real instances | 9 over 8 classes (`inlined-optimised-code` has 2) |
| tracked provenance entries | 20 |
| synthetic mutation controls | 34 |
| symbol and instruction observations | 13 |
| A1 emission results scanned | 4 245 in 6 runs |
| A1 scan violations | 0 |

**Real instances are not synthetic controls.** A real instance is a tracked
native record with a provenance witness: a record digest, a native row or JSON
pointer, and the fields that pointer must carry. A synthetic control is a
test-only mutation of an emission in memory with an expected refusal code. A
control that fires proves the instrument detects the substitution; it is not a
source change, not an edit to an instance record, and not a defect report.

`verify_instances` re-reads all 20 provenance entries against the tracked bytes
and applies all 34 mutations, refusing an instance whose mutation fires the wrong
code or is accepted. With `--observe
artifacts/phase2/install/lib`, all 13 observations are re-read against the DSO at
its recorded digest:
`fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9`.

The A1 emission precision population is 4 011 `line`, 200
`byte-offset-in-artifact`, 2 `function-offset-and-extent`, and 32
record-condition results with no precision property and no locations. The scan
returns zero violations. That result is a compatibility statement about this
population; it is not a safety or cryptographic result.

**Two projections are byte-identical**, and `check(record, project(record))`
accepts for every recorded instance.

## 6. A defect found in this item's own records

The symbol observation control compares a recorded observation with the candidate
DSO at its recorded digest. It found a transcription defect in `L3-md32-update`.

| field | value |
|---|---|
| old recorded value | `byteLength: 0xA5` (165) in the native record, and observation `size: 0xA5` |
| new recorded value | `byteLength: 0x165` (357), observation `size: 0x165`, one-byte-past control `0x166` (358) |
| cause | the `nm --format=posix` size field `165` read as decimal instead of hexadecimal |
| corroboration 1 | `readelf -sW` reports `357` for `_RINvNtNtCsfBoMNNx3tZr_10openssl_rs6digest4md326updateNtNtB4_3md46Md4CtxEB6_` at `0x1b4d20` |
| corroboration 2 | the next `update` instantiation begins at `0x1b4e90`; `0x1b4d20` plus 357 ends at `0x1b4e7d` (11 bytes of alignment padding), while 165 would end at `0x1b4dc5` and leave a 203-byte gap |
| preservation | the old value, the new value and the reason are recorded here; the repair commit is `5f868b04f`, which changed only `evidence/a4/{build_instances.py,CLASSES.json,INSTANCES.json}` |
| effect | with the correction, 13 of 13 observations are re-read, 0 not run |

The repair corrected the record; it did not relax the check. The observation
control would still refuse the old value against this DSO.

**A second defect, in this batch's own `docs/ETP-TODO.md` row, found by a gate and
repaired.** The first version of the A4 row named two internal identifiers
(`Md4Ctx` and `OsslStoreLoader`). `spec_guard` records `docs/ETP-TODO.md` as a
known nonconformance with an exact internal-identifier token set, so the row
produced `SP_KNOWN_FAILURE_DRIFT: docs/ETP-TODO.md: tokens added ['Md4Ctx',
'OsslStoreLoader'], removed []`. The row was reworded to name the Md4 `update`
extent and the store-loader close-function provenance; the recorded token set and
the guard were not edited, and the gate then returned `spec-guard: 10 registered
specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified,
0 unjustified exemptions` (exit 0). Both the drift and its repair are preserved
here rather than the row being silently rewritten.

## 7. Gates actually run

All commands ran inside the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| new controls | `python3 -m unittest discover -s forensics/tools/tests -p "test_location_fidelity.py"` | 58 tests, 0 failures, 0 errors |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | **701 tests, 0 failures, 0 errors** (643 before this item; no test removed, none ignored) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 |
| class record well-formedness | `python3 -m json.tool evidence/a4/CLASSES.json` | PASS |
| instance record well-formedness | `python3 -m json.tool evidence/a4/INSTANCES.json` | PASS |
| producer | `python3 evidence/a4/build_instances.py` | 9 instances, 20 provenance, 34 mutations; both generated files reproduce byte-for-byte |
| instances | `python3 forensics/tools/location_fidelity.py verify-instances evidence/a4/INSTANCES.json --repo-root .` | 9 / 20 / 34, `observations: "NOT_RUN: no --observe artefact root"` |
| instances with observations | the same command with `--observe artifacts/phase2/install/lib` | 9 / 20 / 34, `"observations": {"checked": 13, "not_run": 0}` |
| A1 scan | `python3 forensics/tools/location_fidelity.py scan-sarif evidence/a1/SARIF.json` | `{"violations": []}` over 4 245 results in 6 runs |

**An intermittent pre-existing failure, reported rather than repaired.** The
whole-suite gate failed once before this item's files existed (643 tests,
`failures=1`) and once after (701 tests, `failures=1`); six consecutive full runs
then passed. The differing text in both failures was verify.py's
`MemAvailable N GiB is below the 24 GiB floor AGENTS.md section 6.1 ...`, where
the rounded figure alternated between 10 and 11 GiB. The mechanism is that
`verify.prerequisites` stores that rounded live reading in each step record and
`test_verify.EndToEndControls.test_json_is_byte_identical_across_two_runs`
compares two `all --json` runs; this is an inference from the failing text, not
a captured failure header (the header was not captured in either failing run,
and `test_verify.py` alone passed 12 of 12 repetitions). It is unrelated to A4,
pre-dates the item, and was not modified: `forensics/tools/verify.py` and its
control are outside this item's write scope.

## 8. Obligations retained

* The `macro-rules-derive-output` derive half has **no instance**: no
  derive-generated finding occurs in the tracked tree. The rule is stated;
  the absence is recorded and not filled.
* Instruction observations are a string match against `objdump` text at a
  computed address range. That is not a decoder-level proof of instruction
  boundary validity, and it is not an aliasing or ownership result.
* Observations are `NOT_RUN` when the recorded artefact is absent. Deferred is
  not pass.
* Movement is bound to the exact DSO digest
  `fd25cc9e…d88a9`; a different build invalidates the observation evidence and
  requires a new candidate.
* The 34 synthetic mutation controls do not establish that the substituted forms
  occur in the tree. They establish that the refusal fires.

## 9. `NOT_RUN`

* **BOUNDARY.** No independent caller or dependency-closure audit, no Miri or
  sanitizer run, and no negative-control canary outside the tool's own refusal
  controls.
* **SEAL.** No full forensic regeneration, no broad compatibility or
  cryptographic assurance against this candidate, and no held-out verification.
* **Independent review.** The author of the document and the controls is not an
  independent reviewer, and no third party has reviewed the class-to-refusal
  mapping.
* **Other artefacts and profiles.** Only
  `artifacts/phase2/install/lib/libcrypto.so.3` was re-read for observations, and
  only `evidence/a1/SARIF.json` was scanned.
* **The Rust suite.** `src/` was not modified, so no Rust build or `cargo test`
  was run. The Python gates are this item's evidence.

## 10. Non-claims

A truthful location is not a claim that the finding is true, reachable, severe or
current; identity is not state, and location is not state either. A clean scan of
4 245 results is not a safety result. No profile rule is relaxed:
`a1PolicyChange` is `none`, and `docs/SARIF-PROFILE.md` §7 is unchanged. No
source, allocator, ABI or cryptographic behaviour is claimed here.
