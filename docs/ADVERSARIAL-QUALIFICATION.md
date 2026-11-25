# Adversarial qualification (A22)

> **An instrument that cannot fail is not a measurement.**

This document is normative. It states the problem A22 addresses, the contract an
experiment must satisfy, the canary rule that makes a green result mean
something, the eight mandatory experiments and what they actually observed, the
defects the experiments found with their owning items, the refusal table, and
what a qualification does and does not establish.

Implementation: `forensics/tools/adversarial_qualification.py`.
Records: `evidence/a22/{EXPERIMENTS,RESULTS,CONTROLS}.json`, produced
deterministically by `evidence/a22/build_evidence.py`.
Controls: `forensics/tools/tests/test_adversarial_qualification.py`.

The standing rule this item implements is the queue rule in
`docs/ETP-TODO.md` ("an instrument must demonstrate sensitivity to the defect it
claims to detect"), restated from `AGENTS.md` §7 and §16.

---

## 1. The problem

The assurance campaign rests on instruments: a BINSEC wrapper, a binary branch
audit, a timing receipt checker, ctgrind log summarisers, a SARIF projection, a
strict JSON reader, a policy engine and an omission reconciliation. Each has
been given an input it should refuse, and each was previously qualified by
showing that it *reports* something.

Reporting is not refusing. An instrument that prints a number for every input
prints one for the input it could not measure, and the number reads the same.
The campaign has already found two instruments that returned success for a
verdict they should have refused (`docs/INSTRUMENT-QUALIFICATION.md` §5). Those
were found by hand, one at a time, after the fact. The failure mode is
structural, and it is the same everywhere:

> a tool whose success path and failure path are indistinguishable produces
> evidence that is indistinguishable from no evidence.

A22 is the systematic version: eight experiments, each constructing an input on
which the named instrument **should refuse or report a failure**, observing what
it actually does, and recording the observation. The worth of the experiment is
in the case where the answer is "it returned success": that is a defect, and it
is recorded with its owning item rather than repaired here.

### What this item does not do

It does not repair another item's instrument. A22's write scope is this
document, its tool, its tests and `evidence/a22/`; a defect found in
`courts/phase18/timing/` or `forensics/tools/sarif_adapter.py` is recorded with
old and new behaviour, its owning item, and a queued obligation (§5).

---

## 2. The experiment contract

An experiment is a declaration plus a run. It is not a test of the instrument's
correctness; it is a measurement of whether the instrument can be made to fail.

```text
experiment :=
  id            E1 … E8, one per required experiment
  instruments   the tree paths the experiment exercises (digest-bound)
  hypothesis    the claim the experiment tries to falsify
  expected      the refusal the instrument should produce
  witnesses     constructed inputs, each either
                  rejected  -- the instrument must refuse, with a named exit
                               status and a named code (or the explicit
                               "some nonzero exit carrying some named refusal")
                  accepted  -- the instrument must NOT refuse (the canary input)
                  detection -- a refused input used only as the canary's
                               detection reference; it does not enter the verdict
  canary        the accepted case and the detection reference (§3)
```

Every witness records, in `RESULTS.json`:

* the exact constructed input, or its SHA-256 and the constant in the tool that
  generates it (`input.sha256`, `input.parts`, `input.producedBy`);
* the exact command, with the run's temporary directory replaced by `<tmp>` and
  the repository root by `<repo>`;
* the process exit status;
* the observed output (capped at 4 000 characters, with `outputSha256` over the
  full normalised text and an `outputTruncated` flag);
* the expectation it was measured against.

`stderr` is merged into `stdout` at the file-descriptor level, so the recorded
order is the order the instrument wrote. This matters: the BINSEC wrapper writes
its header to `stderr` and the solver transcript to `stdout`, and a record that
put `stdout` first would not show the transcript in place.

### Verdicts

| verdict | meaning |
|---|---|
| `QUALIFIED` | every rejected witness produced its named refusal |
| `DEFECT` | no rejected witness produced a refusal: the instrument returned success when it should not have |
| `PARTIAL` | some witnesses refused and some did not |
| `NOT_RUN` | a prerequisite is unavailable, with the reason |

A verdict is per experiment and is never merged upward. A run of six
qualified and two not is not "mostly qualified"; `allQualified` is true only
when all eight are `QUALIFIED` (`test_the_recorded_summary_counts`).

### Stability

Each experiment runs twice over identical inputs. Two runs that disagree are
`AQ_REFUSED_UNSTABLE`, not a result (`test_unstable_harness_is_refused`). The
fixtures are byte-deterministic: the same assembly source compiles to the same
shared object, and the tool normalises only the temporary directory, the
repository root, the interpreter path, the tool's version lines and the A20 pin
digest (which embeds a run-local path).

---

## 3. The canary rule

Every experiment carries a canary, because "the instrument refused the bad
input" and "no test was written" look identical from a green tick.

For each experiment, the **same recorded observation** is scored three ways:

1. **strict detector on the accepted input, role-flipped.** The input the
   instrument accepted is presented to the harness as one that should have been
   refused. The harness must report `DEFECT`.
2. **deliberately weak detector (`accept_any`) on that same input.** A detector
   that treats any observation as a refusal must report `QUALIFIED`. It reports
   the opposite of the strict detector on identical bytes, which is what proves
   the *detector* produces the verdict and not the harness's plumbing.
3. **strict detector on the detection reference.** An input the instrument does
   refuse must be seen as refused. This proves the harness is not simply hard-
   wired to `DEFECT`.

If any probe fails the experiment is not counted: the canary is recorded as not
detected and `AQ_REFUSED_CANARY_NOT_DETECTED` fires
(`test_canary_not_detected_is_refused`). All eight canaries are detected in the
recorded run (`CONTROLS.json` → `allCanariesDetected: true`).

A canary is a control, not evidence about an instrument. It shows that a green
result required the instrument to refuse; it does not show the refusal is
correct, complete, or produced by a sound implementation.

---

## 4. The eight experiments and their results

| id | instrument | verdict (`6e64e644c`) | verdict after repair (`e4029e0d5`) | canary |
|---|---|---|---|---|
| `E1` | `courts/phase18/timing/binsec_checkct.sh` | `QUALIFIED` | `QUALIFIED` | detected |
| `E2` | `courts/phase18/timing/binsec_checkct.sh` | `QUALIFIED` | `QUALIFIED` | detected |
| `E3` | `courts/phase18/timing/binary_branch_audit.py` | `QUALIFIED` | `QUALIFIED` | detected |
| `E4` | `forensics/tools/preregistration_check.py` | `QUALIFIED` | `QUALIFIED` | detected |
| `E5` | `courts/phase18/timing/summarize_ct.py`, `forensics/tools/side_channel_erasure.py` | `DEFECT` | `QUALIFIED` | detected |
| `E6` | `forensics/tools/sarif_adapter.py` | `PARTIAL` | `QUALIFIED` | detected |
| `E7` | `forensics/tools/instrument_qualify.py`, `forensics/tools/policy_engine.py` | `QUALIFIED` | `QUALIFIED` | detected |
| `E8` | `forensics/tools/policy_engine.py`, `forensics/tools/omission.py` | `QUALIFIED` | `QUALIFIED` | detected |

**Before repair (`6e64e644c`):** six qualified, one defect, one partial.
**This is not a clean qualification** and the original record did not present it
as one. **After repair (`e4029e0d5`):** eight qualified, the summary is
recomputed from the eight verdicts, and **This is a clean qualification after repair**.
The before column is kept; the after column is what the refreshed
record measures. The residual limitations are named in §5.1 and §7.

### E1 — BINSEC conflicting verdicts (`QUALIFIED`, 3/3)

Hypothesis: a transcript carrying both a secure and an insecure verdict cannot
be resolved by the order of its lines, and a secure verdict with any text after
it is ambiguous.

Observed, in full, for the mixed transcript (exit **6**):

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

Both BINSEC status lines are printed, the wrapper refuses by name, and **no**
`T16 verdict:` line is printed: there is no verdict for a caller to read. The
other two witnesses: a secure verdict with a nonzero tool status → exit 6,
`secure-verdict-with-tool-status-1: inconsistent output`; a secure verdict
followed by "but the exploration was incomplete" → exit 3,
`verdict-trailing-text`. The accepted input (`secure`) exits 0 with
`T16 verdict: secure`.

The prior fail-open this closes — `grep -Fq secure` accepting a mixed transcript
when the tool exited zero — is recorded in `docs/INSTRUMENT-QUALIFICATION.md`
§5.1.1. The record here states the observation, not the history.

*Substitution:* the BINSEC and Z3 executables are stand-ins. This qualifies the
wrapper's exit-status and verdict-population contract. **The real solver did not
run and no solver verdict exists.**

### E2 — BINSEC missing or duplicated verdict (`QUALIFIED`, 3/3)

Zero verdict lines (silent tool, exit 0 on both streams) → exit 3, `no-output`.
Two secure lines, the second `secure (0.030)` for which `secure` is a prefix →
exit 6, `duplicate-secure`. A verdict line with trailing whitespace → exit 3,
`verdict-trailing-text`. The anchored grammar counts the complete population;
answering "was there a secure line" is not answering "what did the tool say".

### E3 — Binary branch audit: zero-size and malformed symbols (`QUALIFIED`, 5/5)

| input | observed |
|---|---|
| a `.text` symbol with no `.size` (extent 0) | exit 1, `reason=zero-size` |
| a symbol whose v0 length prefix is wrong (`99audit_symbol`) | exit 1, `reason=missing` |
| a symbol-table entry whose size field is not hex | exit 1, `reason=missing` |
| a target absent from the symbol table | exit 1, `reason=missing` |
| a disassembly three instructions long for a 20-byte symbol | exit 1, `disassembly-truncated:13-bytes-undecoded` |

**Coverage is inferred from decoded instruction byte lengths, not from a maximum
instruction length.** The audit takes each instruction's length from its raw
byte field (`len(raw)`,
`courts/phase18/timing/binary_branch_audit.py:236`) and requires each
instruction to start where the previous one ended. `MAX_INSN_BYTES = 15`
(`:114`) is a sanity bound on one decoded length, not the coverage test.

*Diagnosis limit, stated rather than hidden:* a malformed entry is refused as
`reason=missing`, not as a dedicated `malformed` code. The audit refuses, which
is what the experiment requires, but a reader cannot tell "the table is
malformed" from "the symbol is not there".

### E4 — Timing instrument under-sampled or failed (`QUALIFIED`, 3/3)

The instrument is the receipt validator (`forensics/tools/preregistration_check.py`)
over `evidence/etp-t7/DUDECT-ETP-T7.json` and `evidence/etp-t7/PREREGISTRATION.json`.

| mutated receipt | observed |
|---|---|
| both modes stopped at 1 batch (10 000 measurements) with state 1 | exit 1, `PR_EARLY_STOP_WITHOUT_LEAK` |
| a mode's total is 5 000, not a multiple of the 10 000 batch | exit 1, `PR_TOTAL_NOT_MULTIPLE` |
| the positive control's t-test left its registered direction (state 1) | exit 1, `PR_POSITIVE_CONTROL_DID_NOT_FIRE` |

Reported from the pinned header and the recorded receipt, not typed into the
tool:

* threshold `t_threshold_moderate = 10`, `t_threshold_bananas = 500`;
* `DUDECT_ENOUGH_MEASUREMENTS = 10000` — dudect draws no conclusion below it;
* declared geometry `per_batch = 10000`, `max_batches = 3`, `runs = 1`;
* sample count actually used: **30 000 measurements per mode** (3 batches), with
  `max|t| = 0.98` for `cmpcmp` (state 1) and `208.01` for `cmpnaive` (state 0).

An under-sampled run cannot read as a pass: the validator refuses it, and the
dudect harness itself returns `DUDECT_NO_LEAKAGE_EVIDENCE_YET` with "not enough
measurements" rather than a clean verdict. A low `t` is not a constant-time
result at any sample size (`AGENTS.md` §5, §11).

*Substitution:* the dudect harness and the candidate DSO did not run. The
validator was qualified on the recorded receipt and on three mutations of it.

### E5 — ctgrind with no errors because nothing ran (`DEFECT`, 0/3)

This is the experiment the item exists to be able to fail, and it failed.

| input | expected | observed |
|---|---|---|
| an empty log (exit 0) | a named refusal | exit **0**, `total contexts: 0` |
| a log containing only unrelated memcheck lines (exit 0) | a named refusal | exit **0**, `total contexts: 0` |
| a ctgrind claim whose `binary_identity` differs from the recorded candidate | a named refusal | **no refusal** (accepted) |

`courts/phase18/timing/summarize_ct.py` prints counts and exits 0; it has no
exit-status contract. An empty log and a clean run produce the **same** output:
`total contexts: 0`. The recorded clean results in
`evidence/etp-t7/SECRETS.json` (for example "0 errors over 0 contexts" for the
Montgomery ladder) are therefore not distinguishable, by this instrument, from a
run that produced nothing. `forensics/tools/side_channel_erasure.py` rule 2
(`CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT`) checks that a `binary_identity`
**field is present**; it does not compare it with the recorded candidate, so a
claim naming some other binary is admitted. No other tool in the tree binds a
ctgrind log or claim to the binary it was recorded from.

The canary is detected: the same adjudicator refuses the claim in which the
field is **absent** (`CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT`, exit 1). So the
finding is precise: presence is checked, identity is not; an empty run is
accepted.

**Owning item: ETP-T7** (side-channel and erasure evidence) for the claim
adjudication, and the phase-18 timing court for the summariser. **Not repaired
here** (`AGENTS.md` §15: the item that owns the instrument repairs it).
Queued obligation: *a ctgrind result must carry the identity of the binary that
produced it, and a log with zero memcheck output must be distinguishable from a
log of a clean run — either the summariser refuses an empty log, or the evidence
record states that zero contexts is not a clean result and requires the
executed-case identity.*

**After repair (`e4029e0d5`) — `QUALIFIED` 3/3.** The summariser now has an
outcome contract: the empty log exits **3** with `CT_SUMMARY_EMPTY_LOG`, the
log with only unrelated memcheck lines exits **4** with
`CT_SUMMARY_UNRELATED_LOG`, and neither prints counts. Rule 2 compares a
`binary_identity` with an expected identity when the caller supplies one and
refuses a mismatch with `CTGRIND_BINARY_IDENTITY_MISMATCH`; A22 supplies the
fixture `sha256:aa…` against a claim recording `sha256:de…`, so the mismatch
exits **1**. The canary still detects the absent-field claim
(`CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT`). **Residual:** the witness supplies
an expected identity, but no production caller was shown to supply one and no
candidate binary was built. Without one, rule 2 remains presence-only; that
limitation is recorded, not counted as a pass.

### E6 — SARIF population mismatch (`PARTIAL`, 1/2)

| input | expected | observed |
|---|---|---|
| a native record whose declared `counts` exceed its entries (52 vs 51) | `SARIF_REFUSED_POPULATION_MISMATCH` | exit 1, `SARIF_REFUSED_POPULATION_MISMATCH: counts sum 52 != 51 entries` |
| an emission with one result removed but `projection.projectedTotal` left at 17 | a named refusal | exit **0**, accepted |

The projection half works: `_project_secrets` refuses a record whose declared
population disagrees with its own entries, and refuses a class count that
disagrees with the entries' classes. The emission half does not:
`validate_emission` checks that `projection` exists and that each result's
fields are well formed, but it never compares `run.results` with the record's
population or with `projection.projectedTotal`. A dropped result leaves a
self-consistent-looking document whose stated total is 17 and whose results are
16, and it is accepted.

**Owning item: A1** (the SARIF projection and `docs/SARIF-PROFILE.md`). **Not
repaired here.** Queued obligation: *`validate_emission` must refuse an emission
whose result count, `projection.projectedTotal` and summed
`projection.projected` disagree with each other and with the record's declared
finding population, with a population-mismatch code.*

**After repair (`e4029e0d5`) — `QUALIFIED` 2/2.** `validate_emission` refuses a
result count that disagrees with `projection.projectedTotal`, with the per-rule
tallies, with the level counts, or with the native population, using
`SARIF_REFUSED_POPULATION_MISMATCH`. The one-result-short emission (17 declared,
16 present) now exits **1**. The live native record (51 findings) and the live
emission still validate; the A22 fixture emission is 17 results in one run,
while the real A1 emission is 4,245 results in 6 runs.

### E7 — Strict parser versus a permissive consumer (`QUALIFIED`, 6/6)

The A11 duplicate-key pair `{"a":1,"a":2}`, a UTF-8 BOM and trailing data were
fed to both strict readers in the tree:

| input | `instrument_qualify.load_json_strict` | `policy_engine.parse_json` |
|---|---|---|
| `{"a":1,"a":2}` | `IQ_JSON_DUPLICATE_KEY` | `PE_JSON_REFUSED` (duplicate object key) |
| BOM + `{"a":1}` | `IQ_REGISTRY_UNREADABLE` (BOM) | `PE_JSON_REFUSED` (BOM) |
| `{"a":1}` + trailing line | `IQ_REGISTRY_UNREADABLE` (extra data) | `PE_JSON_REFUSED` (extra data) |
| `{"a":1}` | accepted | accepted |

**Two tracked consumers still read the instrument register with plain
`json.loads`**, so the same register has two readings:

| consumer | item | loader | witness |
|---|---|---|---|
| `forensics/tools/etp_t1_seed.py` | ETP-T1 | `permissive` | `instruments = json.loads((REPO / "evidence/etp3/instruments.json").read_text())` |
| `forensics/tools/freshness.py` | A7 | `permissive` | `text = repo.text(commit, "evidence/etp3/instruments.json")` … `document = json.loads(text)` |
| `forensics/tools/instrument_qualify.py` | ETP-3 | `strict` | `load_json_strict` |
| `forensics/tools/etp6_verify.py` | ETP-6 | `strict` | `instrument_qualify.load_registry` |
| `forensics/tools/release_gate.py` | release gate item 4 | `strict` | `instrument_qualify.py check --registry` |
| `forensics/tools/intoto.py` | A9 | `byte-identity` | binds the register as a subject digest; does not parse |
| `forensics/tools/verify.py` | ETP-0 | `byte-identity` | binds the register by digest |

The consumer list is checked at run time: a classified consumer file that is
absent, or a file that mentions the register and is not classified, is
`AQ_REFUSED_WITNESS_ABSENT` (`test_every_named_instrument_exists` covers the
instrument paths; the consumer-list check is in `harness_strict_reader`). The
finding is recorded, not repaired: the owning items are **ETP-T1** and **A7**.

That table is the classification at `6e64e644c`. **After repair
(`e4029e0d5`)** the two permissive consumers are strict, and the witness is the
observed refusal rather than the presence of a source line:

| consumer | item | loader after repair | behavioural witness |
|---|---|---|---|
| `forensics/tools/etp_t1_seed.py` | ETP-T1 | `strict` (`load_instruments` → `harden.loads`) | `--instruments <duplicate>` exits 1 with `PH_REFUSED_DUPLICATE_KEY` |
| `forensics/tools/freshness.py` | A7 | `strict` (`_instrument_entries` → `harden.loads`) | the duplicate-key document raises `JsonError` carrying `PH_REFUSED_DUPLICATE_KEY`, exit 1 |

Both probes are recorded as rejected witnesses in `RESULTS.json`
(`duplicate-key-etp-t1-seed`, `duplicate-key-freshness`), so E7 is `QUALIFIED`
8/8 on the refreshed candidate. The earlier finding is historical: a legitimate
repair changed the old `json.loads` lines, and a witness bound to source text
would have made the record non-reproducible.

### E8 — Policy and omission (`QUALIFIED`, 4/4)

| input | observed |
|---|---|
| the live A20 policy with `default: "allow"` and its digest re-bound | exit 1, `PE_REFUSED_DEFAULT_ALLOW` |
| the live policy with `scores: true` | exit 1, `PE_REFUSED_SCORE` |
| a signed reconciliation whose `summary.pass` is true while a required member is `MISSING` | exit 1, `OM_REFUSED_PASS_WITH_MISSING` |
| a reconciliation mutated after signing, verified against the old envelope | exit 1, `OM_REFUSED_RECONCILIATION_MUTATED` |

The accepted witnesses: the live policy evaluates to `DENY` with **no refusal
code** (a denial is not a refusal code, and the record states that), and the
clean signed reconciliation verifies with `OM_VERIFIED`.

---

## 5. What the experiments found

Two instruments did not refuse, and one experiment produced a finding that is
not a defect of the strict reader but of its consumers. None was repaired here.

| finding | experiment | owning item | queued obligation |
|---|---|---|---|
| `summarize_ct.py` prints `total contexts: 0` and exits 0 for an empty or unrelated log; `side_channel_erasure` checks that a ctgrind claim's `binary_identity` is present but not that it matches | E5 `DEFECT` | ETP-T7 (and the phase-18 timing court) | a ctgrind result carries the identity of the binary that produced it, and zero memcheck output is distinguishable from a clean run |
| `validate_emission` accepts an emission whose result count disagrees with the record and with `projection.projectedTotal` | E6 `PARTIAL` | A1 | the emission is refused when its result count, its stated total and the record population disagree |
| two consumers read the instrument register with plain `json.loads` | E7 finding (experiment `QUALIFIED`) | ETP-T1, A7 | the consumers use the strict reader, or record why a duplicate-key register is acceptable to them |

**Old and new behaviour, preserved.** No instrument was edited by A22 when this
record was first produced, so there is no old/new pair to record for them: the
"old" behaviour is the behaviour described above, observed on candidate
`6e64e644c`. Development corrections inside A22 itself, before any record was
produced:

* **The first record lost the write order.** `run()` concatenated `stdout` then
  `stderr`, so the BINSEC transcript appeared before the wrapper's header and
  the mixed case did not read as it ran. Old: `stdout + stderr`. New: `stderr`
  merged into `stdout` at the file-descriptor level, so the record holds the
  order the instrument wrote (`test_the_binsec_mixed_transcript_is_recorded_in_full`).
* **The first canary was weaker than it read.** It asked only that the strict
  detector not report a refusal on the accepted input, which a harness that
  reports a refusal on *everything* also satisfies. Old: one probe. New: the
  accepted input is role-flipped and the weak detector must disagree with the
  strict one on identical bytes, so a hard-wired harness is refused
  (`test_canary_not_detected_is_refused`).
* **The first E8 run was unstable.** The pin digest embeds the run's temporary
  policy path, so two runs differed. Old: `AQ_REFUSED_UNSTABLE` on E8. New: the
  engine's `pin=` digest is recorded as `<pin-digest>` and the pin bytes are
  digested in normalised form; the policy digest, which is what the refusal is
  about, is left exactly as printed.

### 5.1 After repair (`e4029e0d5`)

The three events in the table were repaired at `e4029e0d5` (record:
`evidence/defects/e5-e6/RECEIPT.md`): the ctgrind summariser has an outcome
contract, rule 2 compares a supplied expected identity, the SARIF adapter
refuses a count-mismatched emission, and both register consumers use the strict
loader. Re-measured at that candidate, the eight verdicts are `QUALIFIED`:
E5 3/3, E6 2/2, E7 8/8, and the summary is **8 qualified / 0 defect / 0 partial
/ 0 not-run**. The old verdicts (`E5 DEFECT 0/3`, `E6 PARTIAL 1/2`, summary
6 qualified / 1 defect / 1 partial) and the findings above are kept as the
historical record; they are not erased. The old and new record digests are in
`evidence/a22/RECEIPT.md` §11. The records were later re-measured at
`11f6a06f8` when A20 re-bound its pinned candidate; the verdicts did not change
(`evidence/a22/RECEIPT.md` §12).

---

## 6. The refusal table

Each code is stable and names the wrong conclusion it prevents. Every code has
at least one `control-only` fixture in `CONTROLS.json`; one code has two,
because it is reachable by two different wrong inputs
(`test_every_code_has_a_control`).

| code | fires when | control | test |
|---|---|---|---|
| `AQ_REFUSED_EXPERIMENT_ABSENT` | a required experiment id is absent from the registry, or an experiment names an instrument file the tree does not hold | `experiment-absent`, `experiment-instrument-absent` | `test_experiment_absent_is_refused`, `test_absent_instrument_is_refused` |
| `AQ_REFUSED_NO_CANARY` | an experiment declares no accepted witness, or its canary names no detection reference | `no-canary` | `test_no_canary_is_refused` |
| `AQ_REFUSED_NOT_RUN_AS_QUALIFIED` | `assert_all_qualified` is given a `NOT_RUN` result | `not-run-as-qualified` | `test_not_run_is_refused_by_assert_all_qualified` |
| `AQ_REFUSED_EXPECTED_ABSENT` | a rejected witness declares no expected exit status or code | `expected-absent` | `test_expected_absent_is_refused` |
| `AQ_REFUSED_WITNESS_ABSENT` | a declared witness produced no observation, or a classified register consumer file is absent | `witness-absent` | `test_witness_absent_is_refused` |
| `AQ_REFUSED_UNSTABLE` | two runs of one experiment over identical inputs disagree | `unstable` | `test_unstable_harness_is_refused` |
| `AQ_REFUSED_CANARY_NOT_DETECTED` | the strict detector did not report `DEFECT` on the role-flipped accepted input, the weak detector did not report `QUALIFIED`, or the strict detector missed the detection reference | `canary-not-detected` | `test_canary_not_detected_is_refused` |
| `AQ_DEFECT_FOUND` | an experiment's verdict is `DEFECT` or `PARTIAL` | `defect-found` | `test_defect_found_is_named` |

`AQ_DEFECT_FOUND` is not an error in this item's own machinery; it is the code
that says an instrument returned success when it should have refused. It fires
on E5 and E6 in the recorded run.

---

## 7. What qualification does and does not establish

**It establishes** that, on candidate `6e64e644c`, these eight instruments
refused these inputs (six of them) or did not (E5, E6), that the harness can
tell a refusal from an acceptance (the canary), and that the records are
byte-reproducible.

**It does not establish:**

* that any instrument is **sound, complete or correct** on any other input. A
  refusal for one malformed transcript says nothing about the next one;
* that the real tool behind every fixture behaved as the fixture did. The
  substitutions are exact, not general: `E1` and `E2` run the **real** wrapper
  against stand-in BINSEC and Z3 executables, so **no solver verdict** was
  produced; `E3` runs the **real** audit and the **real** `objdump` for every
  symbol-table read and for the accepted disassembly, with `objdump` shims for
  exactly one table entry and one truncated disassembly; `E4` runs the **real**
  receipt validator with
  the **real** dudect header and receipt, but the dudect harness and the
  candidate DSO did not run, so **no timing measurement** was made; `E5` runs the
  **real** summariser and the **real** claim adjudicator over **constructed**
  valgrind logs, so **no memcheck run** happened; `E6`, `E7` and `E8` run the
  real adapter, readers, policy engine and omission tool over real records and
  real mutations. No SARIF consumer outside this tree ran;
* that a `QUALIFIED` instrument is safe to rely on in a different configuration,
  on a different candidate, or under a different compiler;
* that a `DEFECT` found here is the only defect in that instrument, or that the
  symptom recorded is the whole of its consequence;
* that the recorded observation is independent of the author. The agent that
  wrote the experiments also scored them; §15 of `AGENTS.md` requires an
  independent adjudicator, and none has reviewed this batch.

The matching positive statements are the ones made: E5 and E6 returned success
on the inputs the item names. That is a defect in those instruments, held open
in §5, not repaired here.

**After repair (`e4029e0d5`), refreshed at `11f6a06f8`.** On the refreshed
candidate the eight experiments all refused their inputs, and the records name
`11f6a06f8`. What the
qualification establishes is restated for that candidate: the eight instruments
refused these inputs, the harness can tell a refusal from an acceptance, and the
records are byte-reproducible. It still does not establish soundness, a real
solver verdict, a real timing measurement, a real memcheck run, or independence
of the author. The E5 identity witness uses a fixture expected identity; no
production caller was shown to supply one, and no candidate binary was built.

---

## 8. `NOT_RUN`

Nothing in the eight experiments is `NOT_RUN` on this candidate: `cc`, `objdump`,
`bash`, `python3`, the tool binaries behind `E1`–`E8` and the candidate DSO were
all available in the court, and the recorded summary is
`notRun=0` (`test_the_recorded_summary_is_recomputed_from_the_verdicts`).

The following are **not** run and are not claimed:

* the real BINSEC solver, Z3, the dudect harness, valgrind/ctgrind and a SARIF
  consumer outside this tree (§7);
* *(before repair)* a repair of the `E5` and `E6` defects, and the consumer
  migration named by `E7` — those are now repaired at `e4029e0d5`, but no
  production caller of the E5 expected identity and no real ctgrind/memcheck
  run is claimed;
* a BOUNDARY audit (independent caller/dependency-closure review of another
  item's instrument) and a SEAL;
* the Rust suite: no Rust source was modified, so no build and no `cargo test`
  is claimed;
* an independent reviewer or adjudicator;
* evidence about any candidate other than `11f6a06f8`; the earlier records at
  `e4029e0d5` and `6e64e644c` are preserved by their verdicts and digests in
  `evidence/a22/RECEIPT.md` §§11–12, not by the refreshed records.

---

## 9. Enforcement map

| claim | enforced by |
|---|---|
| the eight experiments are present and named | `AQ_REFUSED_EXPERIMENT_ABSENT`; `test_the_eight_required_experiments_are_present` |
| each experiment states what a failure looks like | `AQ_REFUSED_EXPECTED_ABSENT`; `test_expected_absent_is_refused` |
| each experiment carries a canary that discriminates | `AQ_REFUSED_CANARY_NOT_DETECTED`; `test_every_experiment_canary_is_detected` |
| a `NOT_RUN` is never a qualification | `AQ_REFUSED_NOT_RUN_AS_QUALIFIED`; `test_not_run_is_refused_by_assert_all_qualified` |
| two runs must agree | `AQ_REFUSED_UNSTABLE`; `test_unstable_harness_is_refused` |
| a defect is named, not averaged | `AQ_DEFECT_FOUND`; `test_every_experiment_reports_its_observed_verdict` |
| the ctgrind cases refuse | `test_the_ctgrind_experiment_refuses_all_three_cases` |
| the SARIF population halves both refuse | `test_the_sarif_native_and_emission_halves_both_refuse` |
| both repaired consumers refuse the duplicate key | `test_both_register_consumers_refuse_the_duplicate_key` |
| every refusal code has a control | `test_every_code_has_a_control`; `CONTROLS.json` → `coversEveryCode` |
| the records are the measured bytes | `test_the_committed_records_are_the_live_records` |
| the design equals the measurement | `test_the_design_witnesses_equal_the_observed_witnesses` |
| every code and verdict in this document is real | `test_every_refusal_code_is_named_in_the_document`, `test_the_document_names_no_unregistered_code`, `test_the_document_states_the_eight_verdicts` |
| every code names a test that exists | `test_every_code_names_a_test_that_exists` |
