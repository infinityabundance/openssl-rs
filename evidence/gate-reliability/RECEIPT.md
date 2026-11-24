# Gate-reliability receipt — the tools-suite determinism control

## 1. Identity of this batch

| field | value |
|---|---|
| defect | `python3 -m unittest discover -s forensics/tools/tests` was intermittently red, with the failure inside `test_json_is_byte_identical_across_two_runs` |
| base HEAD | `b272db16c` (`a6: a suppressed finding is a disposition, not an absence`), branch `staging` |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| repair scope | `forensics/tools/verify.py`, `forensics/tools/tests/test_verify.py`, this directory. No `src/`, no `docker/`, no `AGENTS.md`, no other item's evidence |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | total 45, used 14, free 26, buff/cache 5, available **31** GiB; swap total 45, used 14, free 31 |
| derived court cap | `min(8g, 31 − 16) = 8g`, above the 2 GiB floor, so the §6.1 floor was met and commands were permitted |
| court | the already-running `openssl-rs-court` container (up 26 h): image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2, `/.dockerenv` present. It was **reused, not restarted**: recreating it would not lower the 6 GiB cap, would contend with the other session, and would not change any reading this repair depends on. The recorded derived cap (8 GiB) is therefore above the running container's 6 GiB, and the receipt says so rather than implying they agree |
| heavy commands | one at a time; no Rust build was required; every gate is Python only |

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/verify.py` | 1629 | the environment block, the decision-only memory prerequisite text, the substituted `{tmp}` token, the normalised memory echo, `deterministic_projection`, `deterministic_bytes`, `environment_declaration_problem`, `_paths_that_differ`, `compare_deterministic` |
| `forensics/tools/tests/test_verify.py` | 528 | 18 new controls: the floor decision and cap, the reading-free prerequisite text, the substituted temp token, the redacted echo, and the determinism control's own refusals |
| `evidence/gate-reliability/RECEIPT.md` | this file | the three observed failures, the mechanism, the gates and the non-claims |

`git --no-pager diff --stat`: `verify.py` +247/−17 lines of file, `test_verify.py`
+224/−2, 454 insertions and 17 deletions across two files.

## 3. The three observed failures, preserved

These are the observations the repair exists for. They are recorded as they were
seen; nothing below was rewritten after the mechanism was identified.

| # | item | date | suite size at the time | observed text |
|---|---|---|---:|---|
| 1 | A4, **before** the item's files existed | 2026-11-24 | 643 tests | `failures=1`; the differing text was `MemAvailable 10 GiB` against `MemAvailable 11 GiB` |
| 2 | A4, **after** the item's files existed | 2026-11-24 | 701 tests | `failures=1`; the differing text was again `MemAvailable 10 GiB` against `MemAvailable 11 GiB` |
| 3 | A6 | 2026-11-24 | 841 tests | captured header: `FAIL: test_json_is_byte_identical_across_two_runs (test_verify.EndToEndControls)` |

**Attribution, stated honestly.** Observation 1 and 2 were **failures without a
captured test header**: only `failures=1` and the differing `MemAvailable` text
were seen, and the attribution to the byte-identity control was an **inference**
from that text. It was not evidence about which test failed. Only observation 3
captured the failing test by name, and that header is what turned the inference
into an identification. The earlier inference happened to be right; the receipt
does not pretend it was established at the time.

The dates are the commit dates of the items whose gate runs failed
(`d7fb15776`, 2026-11-24 for A4; `b272db16c`, 2026-11-24 for A6). The failing
runs themselves were not timestamped in the captured output, so no finer time is
claimed.

## 4. The mechanism, before and after

### Before

`verify.prerequisites` called `check_need("memory:24")`, which read
`/proc/meminfo` on **every step, every run** and returned

```
MemAvailable {observed / 1024 ** 3:.0f} GiB
```

`run_step` stored that string in **two** compared fields:

* `steps[i].prerequisites[j].detail` — the prerequisite record;
* `steps[i].reason` — `prerequisites`' refusal text is copied into the step's
  reason when the floor is not met.

`all` selects `rebuild` and `differential`, both of which declare
`needs=(…, "memory:24")`. The end-to-end control then compared two `all --json`
documents **byte for byte**. A rounded live reading changes between runs, so the
control failed for a reason that had nothing to do with the tool's determinism.
The A4 runs observed `10 GiB` and `11 GiB` from the same host minutes apart.

Two further live or self-induced inputs reach the same record, found while
enumerating every such read, and fixed in the same repair:

| # | field | mechanism |
|---|---|---|
| 2 | `steps[i].checks[j].summary`, `steps[i].reason` | `build_reproducibility.sh` prints `MemAvailable: N kB` before it builds; on a failing `rebuild` that line reached the record unnormalised. Reproduced during reconnaissance: `reason` was `build_reproducibility.sh exited 101: MemAvailable: 32527932 kB` |
| 3 | `candidate.untracked_changes` | `_materialise` replaced only an argument exactly equal to `{tmp}`, but every declaration writes `--out {tmp}/repro`, so the **literal** `{tmp}/repro` was passed to the delegate. Run 1 created an untracked `{tmp}/` directory in the checkout root; run 2 then read a different untracked count. The run was changing its own input. The reconnaissance run that proved this left an 86 MB `{tmp}/` tree in the checkout root; it was removed, and the tree is clean apart from the two changed files |

### After

* `environment_report()` samples the environment **once per run**, into
  `Context.environment`, and `run()` emits it as `environment`, declared
  `"declared": "environment-input"`. It records the availability in bytes and
  GiB, the AGENTS.md §6.1 floor, the floor decision, the derived cap and its
  derivation, the court's identity and presence, and any declared
  `OPENSSL_RS_COURT_MEM`/`OPENSSL_RS_COURT_MEMSWAP`.
* `check_need("memory:24")` reads **that recorded decision**, not a fresh
  sample, and returns text that depends on the decision only; the reading is
  pointed at, not copied. The two fields above therefore carry no live value.
* `normalise` redacts an echoed `MemAvailable: N kB` / `MemAvailable N GiB` to
  `MemAvailable <observed>`; the environment block is the declared place for the
  reading.
* `_materialise` substitutes `{tmp}` **wherever it appears** in an argument, and
  the displayed `argv` is normalised, so the record keeps the command's shape
  rather than a per-run temp path.
* `compare_deterministic(first, second)` is the control. It
  - parses each run's document and refuses a run that emitted none;
  - requires each run to declare and populate its `environment` block
    (`environment_declaration_problem`), including that a `floor_met: true`
    decision rests on an actual reading;
  - compares `deterministic_bytes` of `deterministic_projection` — every
    top-level field **except** `environment` — using the emitter's own
    canonical settings (`indent=2, sort_keys=True`);
  - on a difference, refuses with `E_VERIFY_DETERMINISTIC` and **names the exact
    paths** at which the records differ.

`test_json_is_byte_identical_across_two_runs` now runs `compare_deterministic`
over the two runs and separately asserts that the environment block is declared
and carries an integer `mem_available_bytes` and a `court`.

## 5. Gates

All commands ran inside the running court (`bash docker/openssl-rs-court.sh exec`,
from `/work`). One heavy command at a time. Every output quoted below was produced
from the working tree of §2 (two modified files plus this directory), which is
uncommitted here; the orchestrator's commit of these files is the source identity
the outputs bind to.

### 5.1 Focused suite

```
$ python3 -m unittest forensics/tools/tests/test_verify.py
Ran 37 tests in 8.113s
OK
```

### 5.2 Tools suite

```
$ python3 -m unittest discover -s forensics/tools/tests
Ran 859 tests in 163.830s
OK
```

859 = the 841 reported at HEAD **plus the 18 controls this repair adds**
(37 − 19 in the focused file). No test was removed, renamed away or newly
ignored; no existing assertion was weakened.

### 5.3 Repeated two-run control, eight times in a row

`python3 -m unittest …EndToEndControls.test_json_is_byte_identical_across_two_runs`,
each invocation running two live `all --json` invocations. No retry exists
inside the control; eight separate invocations:

```
Ran 1 test in 0.471s  OK
Ran 1 test in 0.453s  OK
Ran 1 test in 0.456s  OK
Ran 1 test in 0.482s  OK
Ran 1 test in 0.489s  OK
Ran 1 test in 0.445s  OK
Ran 1 test in 0.461s  OK
Ran 1 test in 0.454s  OK
```

**8 of 8 passed.**

### 5.4 The A4/A6 condition, reproduced eight times

The failing condition was a *different* reading between two runs. Forcing
10 GiB and 11 GiB into two in-process runs of the full selection, eight times:

```
repetition 1 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 2 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 3 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 4 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 5 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 6 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 7 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
repetition 8 raw-bytes-equal: False control: True | environment 10.0 vs 11.0
```

**8 of 8 passed.** The full documents differ — as they must, the environment
differed — and the whole difference is confined to the declared block:

```
full-record differences: ['environment.mem_available_bytes', 'environment.mem_available_gib']
```

That is the claim stated exactly: the environment is different, is recorded, and
is not what the determinism claim is about.

### 5.5 The control still fires (negative controls)

Injected in memory into the deterministic projection, against the real first run:

```
injected live reading: E_VERIFY_DETERMINISTIC: the deterministic record differs at steps[0].prerequisites[len 2 != 3]
changed status      : E_VERIFY_DETERMINISTIC: the deterministic record differs at steps[0].status
changed digest      : E_VERIFY_DETERMINISTIC: the deterministic record differs at steps[0].tool_digest[0].sha256
changed ordering    : E_VERIFY_DETERMINISTIC: the deterministic record differs at invocation.steps[0], invocation.steps[1], invocation.steps[2], invocation.steps[3], invocation.steps[4], invocation.steps[5] (+12 more)
dropped member      : E_VERIFY_DETERMINISTIC: the deterministic record differs at steps[len 19 != 18]
undeclared env      : E_VERIFY_DETERMINISTIC: the second run declares no 'environment' block
```

Each is also a permanent test in `DeterminismControls` or
`MemoryFloorControls`; two more tests cover a floor decision with no reading and
a run that emits no document.

### 5.6 Document consistency

```
$ python3 forensics/tools/docs_consistency.py
[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired
```

Exit 0. The one documented claim this repair affects is **not** machine-checked
and is **not** repaired here — see §7.

### 5.7 Worktree

```
$ git --no-pager status --porcelain
 M forensics/tools/tests/test_verify.py
 M forensics/tools/verify.py
```

Plus the untracked `evidence/gate-reliability/` directory this file is in.

## 6. What the control still catches, and why this is not a weakened claim

The control still fails on a changed **digest** (`tool_digest`, `evidence_identity`),
a changed **ordering** (`steps`, `invocation.steps`), a changed **member set**
(a step added or dropped), a changed **step outcome** (`status`, `reason`,
`prerequisites`), a changed candidate identity, and a document that does not
declare its environment input. All of those remain in the compared projection.

It no longer compares `environment` — the live readings. That is not a weakened
claim, because:

1. The claim was always about **deterministic inputs**. `MemAvailable` is an
   input; asking a determinism control to reproduce it asked the wrong question
   and produced the observed false failures.
2. The excluded set is **exactly one declared key**, named in the code
   (`ENVIRONMENT_KEY`), in the module contract, and in the emitted block itself
   (`"declared": "environment-input"`). The exclusion is not inferred by pattern
   or by "volatile-looking" name; nothing else is dropped.
3. The block's **presence and contents are themselves required**. A run that
   omits it, or that claims a met floor with no reading, is refused.
4. Nothing is hidden: the reading is recorded at byte precision, with the
   derived cap and its derivation, the floor decision and the court identity, so
   a reader can still say which environment produced a verdict — and the tests
   assert the block is populated.
5. The two other live reads found in the same enumeration were **removed from
   the deterministic part**, not excluded by projection: the prerequisite text
   now states the decision, and a delegate's echoed reading is normalised.

The control runs every time. It does not skip, is not `@unittest.skip`ped, does
not catch a broad exception (only a non-JSON document is refused, by name),
and never retries.

## 7. What this receipt does not establish

* **`docs/PUBLIC-VERIFICATION.md` still carries the older wording.** Lines 52–58
  say "Two runs over the same checkout are byte-identical." With a recorded
  environment block that sentence is now imprecise: the *deterministic record* is
  byte-identical, the environment block is not compared. The document is outside
  this repair's write scope, so it was **not** edited. It needs one sentence —
  for example, after the `prerequisites` clause: "The document also carries an
  `environment` block with the live readings the run observed (`MemAvailable`,
  the derived court cap, the court); it is an input, recorded and not compared,
  and the byte-identity claim is about the rest of the record." §4's row for the
  24 GiB prerequisite likewise says "`NOT_RUN` with the observed value", which is
  now true of `environment.mem_available_bytes` rather than of the step's own
  text. Until that edit lands, the document and the tool disagree in wording, and
  `docs_consistency.py` does not check this sentence, so it will not report the
  disagreement.
* **The real `all` was not run end to end.** It invokes
  `build_reproducibility.sh`, two full release builds; that script also exits
  101 in this 6 GiB court. Determinism was established over the stub-delegate
  fixture (the control's own subject) and over in-process document construction
  with forced readings — not over a completed real `all`.
* **`verify manifest` reports `FAIL` in this checkout** (91 hard refusals against
  `evidence/etp6/MANIFEST.json`). The two files this repair changes are
  uncommitted, so they are not in HEAD's tree, and 91 is not attributable to
  them; it is recorded as observed and not adjudicated here.
* **The `{tmp}` substitution fix changes what the delegate receives** (a real
  temporary directory instead of a literal `{tmp}`). It was not re-exercised
  against a completed build; the fixture's stub accepts any argument.
* No Miri, sanitizer or timing instrument applies: the change is Python
  standard-library code, and the claim under test is serialisation determinism,
  not memory safety or constant time.
* The eight repetitions show that *these* sixteen runs agreed; they do not prove
  the tool is deterministic for all inputs. They do show the observed failure
  mode — a live reading changing between runs — no longer fails the control, and
  that the control still fires on every injected non-deterministic field.
