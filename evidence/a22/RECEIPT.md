# A22 receipt — eight experiments, and the instruments that could not fail

## 1. Identity of this batch

| field | value |
|---|---|
| item | A22 (adversarial qualification: eight experiments on the instruments the campaign relies on; an instrument that cannot fail is not a measurement) |
| branch | `staging` |
| HEAD at the start | `6e64e644ced49bf5d969e0eb56ab51f8f4f2c4fc` (`a21: a summary never replaces the evidence it condenses`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 30 9 0 6 15` (total 45, used 30, free 9, available **15** GiB); `Swap: 45 37 8` |
| `free -g` before the suite | `Mem: 45 32 7 0 6 13` (available **13** GiB); `Swap: 45 37 8` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), repository at `/work`, Python 3.11.2; reused, not restarted |
| heavy commands | one at a time; no Rust build |

The host had 15 GiB available before the work and 13 GiB before the suite,
below the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was
needed — every gate is Python plus small `cc` fixtures — and the derived cap
would have been `min(8, 15 − 16)` and `min(8, 13 − 16)`, both below the 2 GiB
floor, so **no new court was started**; the already-running court with its hard
6 GiB cap was reused, as A7–A21 did. Every command that reads, compiles or runs
the tree ran inside it. No test was edited, skipped, ignored or removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/adversarial_qualification.py` | 2,481 lines | the experiment registry and runner, the eight harnesses, the canary, the 8 refusal codes, 10 controls and the CLI |
| `forensics/tools/tests/test_adversarial_qualification.py` | 490 lines | 46 controls: one per refusal code, the canary per experiment, `NOT_RUN` never qualified, instability, determinism, CLI exit codes, document synchronisation |
| `docs/ADVERSARIAL-QUALIFICATION.md` | 490 lines | the normative document: the problem, the experiment contract, the canary rule, the eight experiments and their results, the defects with owners, the refusal table, what qualification does and does not establish, `NOT_RUN`, the enforcement map |
| `evidence/a22/build_evidence.py` | 134 lines | deterministic producer of the three records; verifies the controls, the canaries and the design/observation equality before writing |
| `evidence/a22/EXPERIMENTS.json` | record | the eight designs, the instrument digests, the refusal table, the canary rule |
| `evidence/a22/RESULTS.json` | record | per experiment: verdict, every witness with its input digest, command, exit, output and output digest, the canary probes and the reported facts |
| `evidence/a22/CONTROLS.json` | record | 10 `control-only` fixtures over the 8 refusal codes, the per-experiment canary record, `coversEveryCode` |
| `docs/ETP-TODO.md` | 1 row | the A22 row replaced from `TODO` to `DONE`; no other row touched |
| `evidence/a22/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `adversarial_qualification.py` | `d23d20abc8c8d14ca140cc0ee3287522c7aa8a9ce52ed36765d110167e6dbb13` |
| `test_adversarial_qualification.py` | `7c54eb043dff535a124489e40be2173699d8b95f194c34b052ebfbe19130ee6d` |
| `ADVERSARIAL-QUALIFICATION.md` | `d247573ce90df6b48adfb0159221f164ad08e23007ac3d5109a667eb4b505733` |
| `build_evidence.py` | `c4b5487c5f2bd3b3f13dbe903d34d4c805f828cefe03704cb923b90254dd6dc3` |
| `EXPERIMENTS.json` | `ce7f6677ea7c29d4b96690e5c9d5763f7688257ab2e9473026d765ecf3e33a18` |
| `RESULTS.json` | `45098707995813c060aa802e585e5e7e0cbba66b82980408f3dbd16ca68c5dbe` |
| `CONTROLS.json` | `8494d1f857a49d6b7bfd95d46eeb25a7c43cd8a45997adec402c1b588705c683` |

## 3. The rule

> An instrument that cannot fail is not a measurement. Each experiment
> constructs an input on which a named instrument **should** refuse or report a
> failure, observes what it actually does, and records the observation with the
> exact input, command and exit status. A green result means the instrument
> refused the bad input; the canary proves the harness can tell a refusal from
> an acceptance.

An experiment carries three kinds of witness: `rejected` (the instrument must
refuse, with a named exit and a named code), `accepted` (the instrument must not
refuse; this is the canary input) and `detection` (a refused input used only as
the canary's reference). Verdicts are per experiment — `QUALIFIED`, `DEFECT`,
`PARTIAL`, `NOT_RUN` — and are never merged upward. `notRun=0` in this run; had
one appeared, `assert_all_qualified` would refuse it as a qualification.

The canary is the item's own negative control. The accepted input is
role-flipped into a witness that should have been refused: the strict detector
must report `DEFECT`, a deliberately weak detector (`accept_any`) must report
`QUALIFIED` on the same bytes, and a declared detection reference must be seen
as refused. All eight canaries were detected.

## 4. The eight experiments

| id | instrument | verdict | refused | canary | finding |
|---|---|---|---|---|---|
| E1 | `binsec_checkct.sh` | `QUALIFIED` | 3/3 | detected | — |
| E2 | `binsec_checkct.sh` | `QUALIFIED` | 3/3 | detected | — |
| E3 | `binary_branch_audit.py` | `QUALIFIED` | 5/5 | detected | — |
| E4 | `preregistration_check.py` | `QUALIFIED` | 3/3 | detected | — |
| E5 | `summarize_ct.py`, `side_channel_erasure.py` | **`DEFECT`** | 0/3 | detected | empty/unrelated log accepted; identity not matched |
| E6 | `sarif_adapter.py` | **`PARTIAL`** | 1/2 | detected | emission result count not checked |
| E7 | `instrument_qualify.py`, `policy_engine.py` | `QUALIFIED` | 6/6 | detected | two permissive consumers named |
| E8 | `policy_engine.py`, `omission.py` | `QUALIFIED` | 4/4 | detected | — |

**Six qualified, one defect, one partial. This is not a clean qualification.**

### E1 — BINSEC conflicting verdicts (`QUALIFIED`, 3/3)

The mixed transcript printed both status lines, exited **6**, and printed no
verdict. Recorded in full in `RESULTS.json` (case `conflicting-verdicts`):

```text
# binsec: <tool-version>
# z3:     <tool-version>
# script: <tmp>/aq.cfg
# binary: <tmp>/aq-tiny (70b316cb…)
# wall:   20s
[checkct:result] Program status is : secure
[checkct:result] Program status is : insecure
binsec_checkct: REFUSED target='<tmp>/aq-tiny' reason=mixed-verdicts: secure=1 insecure=1
```

`T16 verdict:` was **not** printed, so there is no verdict for a caller to read.
`secure` with tool status 1 → exit 6,
`secure-verdict-with-tool-status-1: inconsistent output`. `secure (0.030) but
the exploration was incomplete` → exit 3, `verdict-trailing-text`. `stderr` is
merged into `stdout` at the file-descriptor level so this order is the order the
wrapper wrote.

### E2 — BINSEC missing or duplicated verdict (`QUALIFIED`, 3/3)

Silence → exit 3 `no-output`. `secure` plus `secure (0.030)` → exit 6
`duplicate-secure`. A verdict line with trailing whitespace → exit 3
`verdict-trailing-text`.

### E3 — Branch audit: zero-size and malformed symbols (`QUALIFIED`, 5/5)

| input | observed |
|---|---|
| zero-size `.text` symbol | exit 1 `reason=zero-size` |
| malformed v0 length prefix (`99audit_symbol`) | exit 1 `reason=missing` |
| symbol-table entry with a non-hex size | exit 1 `reason=missing` |
| target absent from the table | exit 1 `reason=missing` |
| 3 instructions decoded for a 20-byte symbol | exit 1 `disassembly-truncated:13-bytes-undecoded` |

**Coverage is decoded instruction byte lengths** (`len(raw)` at
`binary_branch_audit.py:236`), not an address gap and not a maximum instruction
length; `MAX_INSN_BYTES = 15` (`:114`) is only a sanity bound on one decoded
length. Diagnosis limit: a malformed table entry is refused as `missing`, with
no dedicated `malformed` code.

### E4 — Timing under-sampled or failed (`QUALIFIED`, 3/3)

One batch with state 1 → `PR_EARLY_STOP_WITHOUT_LEAK`; a 5,000 total against a
10,000 batch → `PR_TOTAL_NOT_MULTIPLE`; the positive control leaving its
registered direction → `PR_POSITIVE_CONTROL_DID_NOT_FIRE`; all exit 1.
Reported from the pinned header and the recorded receipt:
`t_threshold_moderate = 10`, `t_threshold_bananas = 500`,
`DUDECT_ENOUGH_MEASUREMENTS = 10000`, geometry `10000 × 3 × 1`, and **30,000
measurements per mode actually used** (`cmpcmp` max |t| 0.98, state 1;
`cmpnaive` max |t| 208.01, state 0).

### E5 — ctgrind with no errors because nothing ran (`DEFECT`, 0/3)

| input | expected | observed |
|---|---|---|
| empty log | a named refusal | exit **0**, `total contexts: 0` |
| unrelated memcheck lines only | a named refusal | exit **0**, `total contexts: 0` |
| a ctgrind claim naming another `binary_identity` | a named refusal | **accepted** |

`summarize_ct.py` prints counts and exits 0; it has no exit-status contract, so
an empty log is indistinguishable from a clean run. `side_channel_erasure.py`
rule 2 checks that `binary_identity` is *present*, not that it matches. The
canary is detected: the same adjudicator refuses a claim where the field is
absent (`CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT`).

### E6 — SARIF population (`PARTIAL`, 1/2)

A native record whose declared counts exceed its entries (52 vs 51) → exit 1
`SARIF_REFUSED_POPULATION_MISMATCH`. An emission with one result removed and
`projection.projectedTotal` left at 17 → exit **0**, accepted.

### E7 — Strict parser versus a permissive consumer (`QUALIFIED`, 6/6)

Both strict readers refuse the A11 duplicate-key pair `{"a":1,"a":2}`
(`IQ_JSON_DUPLICATE_KEY`; `PE_JSON_REFUSED`), a BOM (`IQ_REGISTRY_UNREADABLE`;
`PE_JSON_REFUSED`) and trailing data (both refused), and accept `{"a":1}`.
Two tracked consumers still read the instrument register with plain
`json.loads`: `forensics/tools/etp_t1_seed.py` (ETP-T1) and
`forensics/tools/freshness.py` (A7).

### E8 — Policy and omission (`QUALIFIED`, 4/4)

`default: allow` → `PE_REFUSED_DEFAULT_ALLOW`; `scores: true` →
`PE_REFUSED_SCORE`; a PASS summary over a missing member →
`OM_REFUSED_PASS_WITH_MISSING`; signed bytes mutated after signing →
`OM_REFUSED_RECONCILIATION_MUTATED`; all exit 1. The live policy evaluates to
`DENY` with **no** refusal code, and a denial is not a refusal code.

## 5. The controls

Ten `control-only` fixtures, each recorded with the code it observed and
whether it was established; `coversEveryCode: true`. One code
(`AQ_REFUSED_EXPERIMENT_ABSENT`) has two controls because two different wrong
inputs reach it (a registry missing an experiment; an experiment naming an
absent file). The positive control reaches `QUALIFIED` with no refusal code.

| control | code observed | established |
|---|---|---|
| `experiment-absent`, `experiment-instrument-absent` | `AQ_REFUSED_EXPERIMENT_ABSENT` | yes |
| `no-canary` | `AQ_REFUSED_NO_CANARY` | yes |
| `not-run-as-qualified` | `AQ_REFUSED_NOT_RUN_AS_QUALIFIED` | yes |
| `expected-absent` | `AQ_REFUSED_EXPECTED_ABSENT` | yes |
| `witness-absent` | `AQ_REFUSED_WITNESS_ABSENT` | yes |
| `unstable` | `AQ_REFUSED_UNSTABLE` | yes |
| `canary-not-detected` | `AQ_REFUSED_CANARY_NOT_DETECTED` | yes |
| `defect-found` | `AQ_DEFECT_FOUND` | yes |
| `positive-qualified` | none (`QUALIFIED`) | yes |

Canary record: 8/8 detected, each with its three probes
(`strict-detector-on-the-accepted-input` → `DEFECT`,
`weak-detector-on-the-same-input` → `QUALIFIED`,
`strict-detector-on-the-detection-reference` → refused).

## 6. Defects found

Two instrument defects and one consumer finding. **None was repaired**: other
items own those instruments (`AGENTS.md` §15).

**E5 — `DEFECT`, owner ETP-T7 (and the phase-18 timing court).** Old behaviour,
observed on `6e64e644c`: `summarize_ct.py` prints `total contexts: 0` and exits
0 for an empty or unrelated log, and `side_channel_erasure.py` admits a ctgrind
claim whose `binary_identity` differs from the recorded candidate. New
behaviour: unchanged — this item did not touch either file. Queued obligation:
*a ctgrind result carries the identity of the binary that produced it, and zero
memcheck output is distinguishable from a clean run.*

**E6 — `PARTIAL`, owner A1.** Old behaviour: `validate_emission` accepts an
emission whose `run.results` count (16) disagrees with
`projection.projectedTotal` (17) and with the record's population. New
behaviour: unchanged. Queued obligation: *the emission is refused when its
result count, its stated total and the record population disagree.*

**E7 — finding, owners ETP-T1 and A7.** Old behaviour: two consumers parse the
instrument register with plain `json.loads`, so `{"a":1,"a":2}` is read as
`{"a":2}` while the strict reader refuses it. New behaviour: unchanged.

**No defect in an existing record was rejected by a gate.** No check was
relaxed and no expected value was changed.

Development corrections inside A22, before any record was produced:

* **The first record lost the write order.** `run()` concatenated `stdout` then
  `stderr`, so the BINSEC transcript preceded the wrapper's header. Old: the
  mixed case did not read as it ran. New: `stderr` merged into `stdout` at the
  file-descriptor level.
* **The first canary was weaker than it read.** It only required that the strict
  detector not report a refusal on the accepted input, which a harness that
  reports a refusal on everything also satisfies. Old: one probe. New: the
  accepted input is role-flipped and the weak detector must disagree with the
  strict one on identical bytes.
* **The first E8 run was `AQ_REFUSED_UNSTABLE`.** The A20 pin digest embeds the
  run's temporary policy path. Old: two runs differed. New: the engine's `pin=`
  digest is recorded as `<pin-digest>` and the pin bytes are digested in
  normalised form; the policy digest is left exactly as printed.
* **The first `defect-found` control observed two codes.** Its stub had no
  detection reference, so the canary also failed. Old: `AQ_DEFECT_FOUND` plus
  `AQ_REFUSED_CANARY_NOT_DETECTED`. New: the stub carries a refused detection
  witness and only `AQ_DEFECT_FOUND` is observed, so the control establishes
  one thing.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 30 9 0 6 15` (available 15 GiB); `Swap: 45 37 8` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1652 tests in 249.916s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,606 pre-existing tests are present (1,606 + 46), none removed, none ignored |
| focused A22 controls | `python3 -m unittest forensics.tools.tests.test_adversarial_qualification` | `Ran 46 tests in 9.988s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on the three records | `json.tool ok evidence/a22/EXPERIMENTS.json`, `RESULTS.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a22/build_evidence.py` and `--out /tmp/a22b` | `a22: base=6e64e644c experiments=8 qualified=6 defect=1 partial=1 notRun=0 allQualified=false codes=AQ_DEFECT_FOUND controls=10 codesCovered=8/8 canariesDetected=8/8` twice, both **exit 1** (the qualification is not clean, by design) |
| producer byte-identity | `cmp` of each name, run1 vs run2 vs committed | `identical EXPERIMENTS.json`, `identical RESULTS.json`, `identical CONTROLS.json` |
| tool, run | `python3 forensics/tools/adversarial_qualification.py run` | eight `aq:` verdict lines, `aq: experiments=8 qualified=6 defect=1 partial=1 notRun=0 allQualified=false codes=AQ_DEFECT_FOUND`; exit 1 |
| tool, canary | `python3 forensics/tools/adversarial_qualification.py canary` | eight `aq: canary EN detected …` lines, `aq: canary experiments=8 detected=8`; exit 0 |
| worktree | `git --no-pager status --porcelain` | see §10 |

## 8. Obligations retained

* **The instruments were not repaired.** E5 (ETP-T7, timing court), E6 (A1) and
  the E7 consumers (ETP-T1, A7) still behave as recorded. Their queued
  obligations are in §6 and in `docs/ADVERSARIAL-QUALIFICATION.md` §5.
* **Fixture substitution is bounded.** E1/E2 use stand-in BINSEC and Z3 (no
  solver verdict); E3 uses the real `objdump` except for one table entry and one
  disassembly shim; E4 uses the real validator but the dudect harness and the
  candidate DSO did not run (no timing measurement); E5 uses the real summariser
  and adjudicator over constructed valgrind logs (no memcheck run); E8 uses the
  real engine and tool over a synthetic population. None of this qualifies the
  real tool beyond the contract it exercised.
* **A refusal is not soundness.** Passing one malformed input says nothing about
  the next. Qualification is per input, per candidate, per configuration.
* **The author is the adjudicator.** The agent that wrote the experiments also
  scored them; no independent reviewer exists for this batch (`AGENTS.md` §15).
* **Evidence identity.** Every record names base `6e64e644c`, the tool digest and
  each instrument's digest. An edit to any instrument invalidates that
  experiment's result until the producer is re-run.

## 9. `NOT_RUN`

* The real BINSEC solver, Z3, the dudect harness and candidate DSO,
  valgrind/ctgrind, and any SARIF consumer outside this tree.
* Repairs of E5, E6, and the E7 consumer migration.
* The A22 row's earlier failure classes whose instruments lie outside this item:
  self-signed independence (A10/A12/A14), one-person-two-credentials
  (A12/A14), withdrawn claim (A19), reproducible-but-defective binary
  (A5/ETP-2), complete-and-independent evidence (A12/A17). None is claimed here.
* A BOUNDARY audit, a SEAL, an independent reviewer.
* The Rust suite: no Rust source was modified, so no rebuild and no
  `cargo test` is claimed.

## 10. Forward-freeze member and worktree

`evidence/a17/FREEZE-forward.json` declares **one** A22 member:

* **satisfied:** `a22-receipt` — `evidence/a22/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

Still open under the same freeze (**15** members, not this item's work):
`a23-receipt` … `a27-receipt` (5 remaining, A23–A27), `b0-registry`,
`b0-service-configuration`, and `b1-receipt` … `b8-receipt` (8). The
`a18-receipt` … `a22-receipt` members are produced. The freeze remains
`state: OPEN`; it was not amended and not closed, and this receipt does not
claim any of those members.

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
?? docs/ADVERSARIAL-QUALIFICATION.md
?? evidence/a22/
?? forensics/tools/adversarial_qualification.py
?? forensics/tools/tests/test_adversarial_qualification.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row
(A22); `git diff --stat` reports one insertion and one deletion for that file.

---

## 11. Correction: refresh after the E5/E6/E7 repairs (2026-11-24)

This section is appended. Sections 1–10 are the record as produced at
`6e64e644c` and are **not** edited: the old verdicts, the old findings and the
old digests stay readable.

### 11.1 Why the record was refreshed

Commit `e4029e0d5` repaired the three defects A22 found (record:
`evidence/defects/e5-e6/RECEIPT.md`): the ctgrind summariser gained an outcome
contract, `side_channel_erasure` compares a supplied expected binary identity,
the SARIF adapter refuses a count-mismatched emission, and both register
consumers use the strict loader.

That repair invalidated A22's **E7 witness**, not its instruments. E7 asserted
that two source lines existed:

* `instruments = json.loads((REPO / "evidence/etp3/instruments.json").read_text())`
  in `forensics/tools/etp_t1_seed.py`;
* `text = repo.text(commit, "evidence/etp3/instruments.json")` and
  `document = json.loads(text)` in `forensics/tools/freshness.py`.

The repair replaced those lines with `harden.loads`, so the producer refused
`AQ_REFUSED_WITNESS_ABSENT` and wrote nothing. The whole tools discovery then
reported **0 failures and 1 error**, `setUpModule (test_adversarial_qualification)`
→ `FileNotFoundError: EXPERIMENTS.json`. Binding a witness to source text that a
legitimate repair changes makes the record non-reproducible; that is a defect in
A22's witness design, not in the repaired tools.

### 11.2 What changed in the refresh

* Every witness is now an **observed outcome** (exit status, named code, printed
  verdict), never the presence of a source line.
* E7 runs `etp_t1_seed.py --instruments <duplicate-key> --output <tmp>` and
  `freshness._instrument_entries` over the same bytes. Both are required to exit
  1 with `PH_REFUSED_DUPLICATE_KEY`; the experiment reports a finding only if a
  consumer still accepts the document. The old finding is now historical.
* E5 supplies a fixture expected identity (`sha256:aa…`) to the claim driver, so
  the mismatch is witnessed (`CTGRIND_BINARY_IDENTITY_MISMATCH`). The residual
  is recorded: with no supplied identity, rule 2 is still presence-only, and no
  candidate binary was built.
* E5/E6 expectations name the exact codes rather than ``any-refusal``.
* The records were re-measured at `e4029e0d5`; `BASE_COMMIT` now names that
  candidate.

### 11.3 Old and new verdicts

| id | old (`6e64e644c`) | after repair (`e4029e0d5`) | refused |
|---|---|---|---|
| E1 | `QUALIFIED` | `QUALIFIED` | 3/3 |
| E2 | `QUALIFIED` | `QUALIFIED` | 3/3 |
| E3 | `QUALIFIED` | `QUALIFIED` | 5/5 |
| E4 | `QUALIFIED` | `QUALIFIED` | 3/3 |
| E5 | `DEFECT` 0/3 | `QUALIFIED` | 3/3 |
| E6 | `PARTIAL` 1/2 | `QUALIFIED` | 2/2 |
| E7 | `QUALIFIED` 6/6 | `QUALIFIED` | 8/8 |
| E8 | `QUALIFIED` | `QUALIFIED` | 4/4 |

* Old summary: 8 experiments, **6 qualified / 1 defect / 1 partial**, 0
  not-run, `allQualified=false`, `codes=AQ_DEFECT_FOUND`; producer exit **1**.
* New summary: 8 experiments, **8 qualified / 0 defect / 0 partial / 0 not-run**,
  `allQualified=true`, `codes=NONE`; producer exit **0**.

The new summary is recomputed from the eight verdicts; it is not asserted
independently of them. `test_every_experiment_reports_its_observed_verdict`
asserts each verdict, so a future `QUALIFIED` → `DEFECT` regression fails the
suite even if a summary were forced clean.

### 11.4 What was preserved

* The old verdicts, the old finding table and the old `E5 0/3`, `E6 1/2`, `E7
  6/6` counts remain in `docs/ADVERSARIAL-QUALIFICATION.md` and in this receipt.
* The document's §4 table now has a before column and a dated **after repair
  (`e4029e0d5`)** column; the before column is unchanged.
* The refusal codes, the canary rule (8/8 detected) and the 10 controls are
  unchanged; no test was removed, skipped, ignored or weakened.
* `evidence/a22/build_evidence.py` is unchanged (`c4b5487c…`).

### 11.5 Old and new digests (SHA-256, full)

| file | old (`6e64e644c`) | new (`e4029e0d5`) |
|---|---|---|
| `forensics/tools/adversarial_qualification.py` | `d23d20abc8c8d14ca140cc0ee3287522c7aa8a9ce52ed36765d110167e6dbb13` | `35eff911c472d380d4cb36666cc99903e2c9fcf806e054c51e50fd51175ac52d` |
| `forensics/tools/tests/test_adversarial_qualification.py` | `7c54eb043dff535a124489e40be2173699d8b95f194c34b052ebfbe19130ee6d` | `270310fb0ce45872ef8629777764c5a4203dab54ff77939f5274ed660d5218c6` |
| `docs/ADVERSARIAL-QUALIFICATION.md` | `d247573ce90df6b48adfb0159221f164ad08e23007ac3d5109a667eb4b505733` | `8879b54e9b14028eb61aaadb38e554330c39ed9f12e5c79180f327ea04a962db` |
| `evidence/a22/build_evidence.py` | `c4b5487c5f2bd3b3f13dbe903d34d4c805f828cefe03704cb923b90254dd6dc3` | unchanged |
| `evidence/a22/EXPERIMENTS.json` | `ce7f6677ea7c29d4b96690e5c9d5763f7688257ab2e9473026d765ecf3e33a18` | `253ffce418f6fe675cc2d89a2cce9b1b617711294fbc88de8105943a15d5bafe` |
| `evidence/a22/RESULTS.json` | `45098707995813c060aa802e585e5e7e0cbba66b82980408f3dbd16ca68c5dbe` | `976ecee77d13e5ab11ae78426c0cff3835a5de4bc25d2dcbbc2a035ca768ddde` |
| `evidence/a22/CONTROLS.json` | `8494d1f857a49d6b7bfd95d46eeb25a7c43cd8a45997adec402c1b588705c683` | `8c9009cc09e56eb1cba1f8f7894ad955c5886091af33b29422ee2767e3f7cb2a` |

The three new records are byte-identical across two producer runs
(`evidence/a22` vs `--out /tmp/a22-twice`).

### 11.6 Gates at the refresh

All commands ran in the reused `openssl-rs-court` container
(`openssl-rs-court-tools:1`, `HostConfig.Memory` and `MemorySwap` both
`6442450944`, running), one at a time; no Rust build.

| gate | observed |
|---|---|
| `free -g` | `Mem: 45 31 10 0 5 14` (available **14** GiB); `Swap: 45 38 6`; below the 24 GiB build floor, so no build and no new court |
| focused A22 | `Ran 46 tests in 13.515s`; `OK` |
| whole discovery | `Ran 1680 tests in 257.796s`; `OK`; 0 failures, 0 errors. The parent reported 1,634 with 1 error; before the error 1,652. `e4029e0d5` adds 28 focused tests (1,652 + 28 = 1,680); A22 remains 46, none removed or newly ignored |
| producer, twice | exit **0** both times; `qualified=8 defect=0 partial=0 notRun=0 allQualified=true codes=NONE controls=10 codesCovered=8/8 canariesDetected=8/8` |
| record byte-identity | `identical EXPERIMENTS.json`, `identical RESULTS.json`, `identical CONTROLS.json` |
| `adversarial_qualification.py run` | exit **0**; eight `QUALIFIED refused=…/… canary=detected codes=NONE` lines; `allQualified=true` |
| `adversarial_qualification.py canary` | exit **0**; `aq: canary experiments=8 detected=8` |
| `docs_consistency.py` | exit **0**; `ok: 20 hand-written claim(s) … the earned-trust constitution is wired` |
| `spec_guard.py check` | exit **0**; `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions` |

### 11.7 Residual limitations

* **E5's identity witness supplies an expected identity that A22 made up**
  (`sha256:aa…`). It proves the adjudicator compares a supplied expectation; it
  does not prove a production caller supplies one, and no candidate binary was
  built. Without one, rule 2 remains presence-only.
* **The E7 finding is historical, not erased.** Both consumers now refuse the
  duplicate-key document, but the old permissive text and its owners (ETP-T1,
  A7) remain in the document and in this receipt.
* **The fixture substitutions are unchanged.** E1/E2 still use stand-in BINSEC
  and Z3; E3 still uses two `objdump` shims; E4 still has no dudect run; E5
  still has no memcheck run; no SARIF consumer outside the tree ran.
* **The author is still the adjudicator.** No independent reviewer ran this
  refresh (`AGENTS.md` §15).
* **The refresh is uncommitted here.** This subagent did not commit or push; the
  orchestrator commits and verifies it.

---

## 12. Correction: refresh for the A20 candidate re-bind (2026-11-25)

This section is appended. Sections 1–11 are the record as produced at
`6e64e644c` and refreshed at `e4029e0d5`; they are **not** edited.

### 12.1 Why the record was refreshed

A20 re-bound its policy candidate from
`58aeb2ee01000638cc545e4cad7c9ec3b5ff9672` to
`f34e429f13aa3cc1566e1ecebc185a466765f321`
(`evidence/a20/RECEIPT.md`, the `candidate.commit` correction;
`evidence/a20/POLICY-PIN.json` `candidate.commit`). A22's E8 harness reads that
field:

```python
candidate = pin["candidate"]["commit"]
```

so the E8 policy-engine commands and the digest of the E8 input (which includes
the normalised pin bytes) embedded the superseded candidate. The record was
stale on that identity, not on any verdict.

The producer does not read the working-tree `HEAD` and has no candidate flag:
the A22 measurement candidate is the `BASE_COMMIT` constant, and E8's
`--candidate` is the A20 pin's `candidate.commit`. Neither is derived from the
live checkout.

### 12.2 Venue

E1/E2 compile fixtures with `cc`; E3 compiles three shared objects with `cc`;
their `input.sha256` (and E3's `outputSha256`) therefore depend on the compiler
and `objdump`. The producer was re-run in the declared venue,
`openssl-rs-court-tools:1` (`openssl-rs-court`, `HostConfig.Memory` and
`MemorySwap` both `4294967296`, running), so the recorded compiler/toolchain is
the court's. The committed E1/E2/E3 bytes were already that venue's output and
are unchanged; a host `cc` (GCC 16.2.1 here, against the court's Debian GCC
12.2.0) produces different fixture bytes, so the byte-reproducibility control is
meaningful only in the declared venue.

### 12.3 What moved (old → new)

| field | old | new |
|---|---|---|
| `baseCommit` / `baseCommitLong` | `e4029e0d5` / `e4029e0d5c4300bb097e1241c0bab34b069c9da6` | `11f6a06f8` / `11f6a06f831451c6a9103296d263d755985e67bd` |
| E8 embedded candidate (3 commands; 6 `input.sha256`) | `58aeb2ee01000638cc545e4cad7c9ec3b5ff9672` | `f34e429f13aa3cc1566e1ecebc185a466765f321` |
| `adversarial_qualification.py` `tool.sha256` | `35eff911c472d380d4cb36666cc99903e2c9fcf806e054c51e50fd51175ac52d` | `dc04389491075be18f846936f88cf6cce50678958ab2d65f5fea44c6b307294f` |

Record digests (SHA-256, full):

| file | old (`e4029e0d5`) | new (`11f6a06f8`) |
|---|---|---|
| `EXPERIMENTS.json` | `253ffce418f6fe675cc2d89a2cce9b1b617711294fbc88de8105943a15d5bafe` | `df72d2e090e76766f6aacc4c2ce0dd9b233305d2929d547b1893e04c4c863ce6` |
| `RESULTS.json` | `976ecee77d13e5ab11ae78426c0cff3835a5de4bc25d2dcbbc2a035ca768ddde` | `db49003319376aa633aea9898fb9599097ae6f496ec5f6ff661cb547dfba7a1c` |
| `CONTROLS.json` | `8c9009cc09e56eb1cba1f8f7894ad955c5886091af33b29422ee2767e3f7cb2a` | `40e0df959e2a08909bcfc5c3411629b6f5c494d507884ab88b957a9b155dbbf2` |

### 12.4 Outcome is unchanged

E1–E8 remain `QUALIFIED`: summary **8 qualified / 0 defect / 0 partial /
0 not-run**, `allQualified=true`, producer exit **0**. No verdict, exit status,
or `outputSha256` changed; the only observation changes are the E8 input digest
and its three command strings. `EXPERIMENTS.json` and `CONTROLS.json` moved only
in `baseCommit`, `baseCommitLong` and `tool.sha256`.

### 12.5 What was preserved

* Sections 1–11 (the `6e64e644c` record and the `e4029e0d5` refresh) are
  unchanged.
* The old record digests, the old `baseCommit`, and the old embedded candidate
  are recorded above, not erased.
* No control was removed, no deliberately broken arm was repaired, no experiment
  was dropped, and no verdict was promoted.

### 12.6 Gates

All commands ran one at a time. The Rust suite was not run (no Rust source
changed). The venue is named for each row.

| gate | venue | observed |
|---|---|---|
| focused A22 | court | `Ran 46 tests in 14.600s`; `OK` |
| focused A22 | host | `Ran 46 tests in 15.688s`; `FAILED (failures=1)` at `Determinism.test_the_committed_records_are_the_live_records (document='RESULTS.json')`, drifting only E1/E2/E3 `input.sha256`/`outputSha256` (host `cc` vs court `cc`), not E8 |
| `test_policy_engine` | court | `Ran 40 tests`; `OK` |
| `test_continuous_enforcement` | court | `Ran 43 tests`; `OK` |
| `test_baseline` | court | `Ran 57 tests`; `OK` |
| `test_sigstore_bundle` (bounded) | court | `Ran 30 tests`; `FAILED (failures=1)`; `PH_REFUSED_POPULATION_DRIFT` on `evidence/a22/CONTROLS.json`. The full module was OOM-killed at the 4 GiB cap (`evidence/incidents/2026-11-25-3`) |
| `test_harden` | court | `Ran 69 tests`; `FAILED (failures=2, errors=1)`; all three name `evidence/a22/CONTROLS.json` |
| `spec_guard.py check` | court | `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions` |
| `docs_consistency.py` | court | `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired` |

The `test_sigstore_bundle` and `test_harden` reds are the expected A16/A11
cascade: their frozen populations still bind the previous A22 bytes
(`evidence/a22/{CONTROLS,EXPERIMENTS,RESULTS}.json`). They are not re-frozen in
this batch.

---

## 13. Correction: refresh for the C24 re-measurement (2026-11-25)

This section is appended. Sections 1–12 are the record as produced at
`6e64e644c`, refreshed at `e4029e0d5`, and re-bound at `11f6a06f8`; they are
**not** edited.

### 13.1 Why the record was refreshed

A20's pinned candidate moved again, from
`f34e429f13aa3cc1566e1ecebc185a466765f321` to
`a1c3fa61b4c225ea002e321e0ab50937253101e0`, after the C19/C20 regeneration
(`evidence/a20/POLICY-PIN.json` `candidate.commit`). A22's E8 harness reads that
field directly:

```python
candidate = pin["candidate"]["commit"]
```

so the three E8 policy-engine commands and the digest of the E8 input (which
includes the normalised pin bytes) embedded the superseded candidate. The record
was stale on that identity, not on any verdict. The producer was re-measured at
the current source candidate, `97bde6560af86248114a116c8a355609e69f30b3` (C24),
and `BASE_COMMIT`/`BASE_COMMIT_LONG` now name it.

The producer still does not read the working-tree `HEAD`: the A22 measurement
candidate is the `BASE_COMMIT` constant, `tool.sha256` is the producer file's
own digest, and E8's `--candidate` is the A20 pin's `candidate.commit`. None is
derived from the live checkout.

### 13.2 Venue

E1/E2 compile fixtures with `cc`; E3 compiles three shared objects with `cc`;
their `input.sha256` (and E3's `outputSha256`) therefore depend on the compiler
and `objdump`. The producer was re-run in the declared venue,
`openssl-rs-court-tools:1` (`openssl-rs-court`, `Config.Image` =
`openssl-rs-court-tools:1`, `HostConfig.Memory` and `MemorySwap` both
`4294967296`, running). Host `available` was **30** GiB before the court run; the
operative cap under §24.4 is `min(4g, available - 8g)` = **4 GiB**, floor
`2g`, so the command ran. The committed E1/E2/E3 bytes were already that
venue's output and are **unchanged**: E1/E2 `input.sha256`
`83b394928d4a590dc81d2fbd9ba0c4dedb6d70612c1f7f5ace62b84bc4c55bf9` and E3
`ecc81a9f679000ddca1f8e9dc64c4395848db574ec68b7235310e1b303a71553` did not
move. A host `cc` (GCC 16.2.1 against the court's Debian GCC 12.2.0) produces
different fixture bytes, so the byte-reproducibility control is meaningful only
in the declared venue.

### 13.3 What moved (old → new)

| field | old (`11f6a06f8`) | new (`97bde6560`) |
|---|---|---|
| `baseCommit` / `baseCommitLong` | `11f6a06f8` / `11f6a06f831451c6a9103296d263d755985e67bd` | `97bde6560` / `97bde6560af86248114a116c8a355609e69f30b3` |
| E8 embedded candidate (3 commands) | `f34e429f13aa3cc1566e1ecebc185a466765f321` | `a1c3fa61b4c225ea002e321e0ab50937253101e0` |
| E8 `input.sha256` (6 observations) | `ffbbc5522cd309ce5643877b937559c444b7d83220c33fa2dd66982b418f3706` | `2f046532dffdccb433557af355f281ef1eec6ab12496535cbfa4df72a7bbac3b` |
| `adversarial_qualification.py` `tool.sha256` | `dc04389491075be18f846936f88cf6cce50678958ab2d65f5fea44c6b307294f` | `ef5d6c7916fe59bf3824b1bf2aab89b13739c11f91b39dce14ae03bbe5f44d34` |

Record digests (SHA-256, full):

| file | old (`11f6a06f8`) | new (`97bde6560`) |
|---|---|---|
| `EXPERIMENTS.json` | `df72d2e090e76766f6aacc4c2ce0dd9b233305d2929d547b1893e04c4c863ce6` | `b8a31717f7da05c9c8cd5bfeaca4c3736d312bfe3693dfe29a23ddbea4c0bb9e` |
| `RESULTS.json` | `db49003319376aa633aea9898fb9599097ae6f496ec5f6ff661cb547dfba7a1c` | `07d5fecd617fd88bb4a60c785a9f33432beed34a1cb899ade89ac9b224a5e46e` |
| `CONTROLS.json` | `40e0df959e2a08909bcfc5c3411629b6f5c494d507884ab88b957a9b155dbbf2` | `a8aa6ff6c53c61dd678f09ea205af7327ef4569fa249346a7064564d1b367e97` |

### 13.4 Outcome is unchanged

E1–E8 remain `QUALIFIED`: summary **8 qualified / 0 defect / 0 partial /
0 not-run**, `allQualified=true`, producer exit **0**. No verdict, exit status,
or `outputSha256` changed. E1–E3 digests did not move. The only observation
changes are E8's three `--candidate` command strings and its six `input.sha256`
values; E8 exits remain `[1,1,1,1,0,1]`. `EXPERIMENTS.json` and `CONTROLS.json`
moved only in `baseCommit`, `baseCommitLong` and `tool.sha256`.

### 13.5 What was preserved

* Sections 1–12 (the `6e64e644c` record, the `e4029e0d5` repair refresh and the
  `11f6a06f8` A20 re-bind) are unchanged.
* The old record digests, the old `baseCommit` and the old embedded candidate
  are recorded above, not erased.
* No control was removed, no deliberately broken arm was repaired, no experiment
  was dropped, and no verdict was promoted.

### 13.6 Gates

All commands ran one at a time. The focused A22 suite ran in the court; the
remaining Python suites ran on the host, as directed, because the full
`test_sigstore_bundle` module has OOM-killed at the court's 4 GiB cap. Host
`available` was **29** GiB before the host suites. The Rust suite was not run (no
Rust source changed).

| gate | venue | observed |
|---|---|---|
| focused A22 | court | `Ran 46 tests in 14.600s`; `OK` |
| `test_policy_engine` | host | `Ran 40 tests`; `OK` |
| `test_campaign` | host | `Ran 79 tests`; `FAILED (failures=2)`; b3 moved — `evidence/b3/CAMPAIGNS.json` still binds the old A22 `RESULTS.json` digest `db490033…` while a fresh run emits `07d5fecd…` (`b3: stale record(s): CAMPAIGNS.json`) |
| `test_corrections` | host | `Ran 51 tests`; `OK` |
| `test_verification_summary` | host | `Ran 42 tests`; `OK` |
| `test_vertical_slice` | host | `Ran 51 tests`; `OK` |
| `test_archival` | host | `Ran 59 tests`; `OK` |
| `test_harden` | host | `Ran 69 tests`; `FAILED (failures=2, errors=1)`; `PH_REFUSED_POPULATION_DRIFT` names `evidence/a16/CONTROLS.json` (first changed member) against `evidence/a11/SCAN.json`; the full frozen-population drift is 25 files (a16×3, a19×4, a20×2, a21×3, a22×3, a27×3, b6×7) — the reverted A11 freeze, not an A22-only change |
| `test_sigstore_bundle` | host | `Ran 58 tests`; `FAILED (failures=3, errors=1)`; `PH_REFUSED_POPULATION_DRIFT` names `evidence/a22/CONTROLS.json` (first changed member) against `evidence/a16/INVENTORY.json` (frozen at `2dc0b37da`); the full declared-population drift is exactly the three A22 records |
| `spec_guard.py check` | host | `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions` |
| `docs_consistency.py` | host | `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired` |

### 13.7 Residual

E8 embeds A20's pinned candidate commit, so any further A20 candidate
generation invalidates this record again. Recording the stable A20 *policy*
digest instead would avoid that churn, but it would not bind the `--candidate`
argument the E8 commands actually pass, so it is **not** adopted here: the
record continues to name what was executed.
