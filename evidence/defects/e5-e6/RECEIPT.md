# Defect receipt — E5a, E5b, E6 and E7 (repairs of findings recorded by A22)

**Base HEAD:** `d3050312fd10e5b45053c6c3d8e9f501a3c6356b` (`a22: eight
instruments asked to fail, and two did`), clean `staging` at the start.

**Venue:** `free -g` reported `available 13`; the derived cap
`min(8g, 13 − 16)` is below the 2 GiB floor, so no new court was started. The
already-running `openssl-rs-court` (6 GiB memory, 6 GiB memory-swap, up 35
hours) was reused for every command. One heavy command at a time.

**Scope.** The four corrections below repair the three defect classes A22
recorded (E5, split into the summariser and identity halves, plus E6 and E7) in
`evidence/a22/RESULTS.json` and `docs/ADVERSARIAL-QUALIFICATION.md`. A22's
records were read, not edited. `src/`, `docker/`, `AGENTS.md`,
`evidence/a19/EVENTS.json` and the A1/ETP-T7 records are unchanged.

| defect | A22 witness | instrument |
|---|---|---|
| E5a | `RESULTS.json` `/experiments/4` (E5) observation `empty-log` and `unrelated-log-only` | `courts/phase18/timing/summarize_ct.py` |
| E5b | `RESULTS.json` `/experiments/4` (E5) observation `candidate-identity-mismatch` | `forensics/tools/side_channel_erasure.py` |
| E6 | `RESULTS.json` `/experiments/5` (E6) observation `emission-result-count-mismatch` | `forensics/tools/sarif_adapter.py` |
| E7 | `RESULTS.json` `/experiments/6` (E7) `reported.consumers` rows for ETP-T1 and A7 | `forensics/tools/etp_t1_seed.py`, `forensics/tools/freshness.py` |

---

## 1. E5a — the ctgrind summary had no outcome contract

**Old behaviour.** `summarize_ct.py BASE LOG` scanned the log, printed
`total contexts: N` and the stacks, and exited 0 unconditionally. An empty log,
a log with no memcheck context and a malformed/truncated report all printed
`total contexts: 0` and exited 0, so "nothing ran" was indistinguishable from a
clean run.

**New behaviour.** The script has an explicit outcome contract, documented in
its module docstring. Exit 0 is printed only for a parsed, non-empty,
well-formed report: at least one uninitialised-value context was found and every
recognised block carries at least one `at`/`by` frame. On a refusal nothing is
printed on stdout and the stable code with its reason goes to stderr. The counts
and the successful output shape are unchanged.

| condition | stable code | exit |
|---|---|---|
| empty (zero non-whitespace bytes) | `CT_SUMMARY_EMPTY_LOG` | 3 |
| non-empty but no recognised context (includes a zero-context "clean" run) | `CT_SUMMARY_UNRELATED_LOG` | 4 |
| recognised context block with no frame | `CT_SUMMARY_MALFORMED_LOG` | 5 |
| log cannot be read | `CT_SUMMARY_UNREADABLE_LOG` | 6 |
| unusable argument vector or address base | `CT_SUMMARY_USAGE` | 2 |

A missing `addr2line` now degrades the annotation to the recorded symbol and
leaves the context count unchanged; it no longer aborts the script.

**Files.** `courts/phase18/timing/summarize_ct.py` (+164/−51);
`forensics/tools/tests/test_summarize_ct.py` (new, 11 tests).

**Witness re-run (court):**

```
empty-log: exit=3 code=yes
    CT_SUMMARY_EMPTY_LOG: .../empty.log has no content: an empty log is not a clean run
unrelated-log: exit=4 code=yes
    CT_SUMMARY_UNRELATED_LOG: .../unrelated.log contains no memcheck uninitialised-value context; ...
log-with-a-finding: exit=0 counts=True
```

---

## 2. E5b — rule 2 checked presence, not identity

**Old behaviour.** `check_claim` refused a ctgrind claim only when `harness`,
`binary_identity` or `tainted_inputs` was absent. Any present
`binary_identity` value was admitted; nothing compared it with the artefact the
log came from.

**New behaviour.** `check_claim` and `check_claims` accept a keyword-only
`expected_binary_identity`, and the CLI supplies it with
`--binary-identity VALUE` or `--artefact FILE` (the latter derives
`sha256:<hex>` from the file). A ctgrind claim whose recorded identity differs
is refused with the stable code **`CTGRIND_BINARY_IDENTITY_MISMATCH`**; the
detail carries both the recorded and the expected value. `--self-test` gains
`NC-2B` (mismatch refused) and an identity positive control against `PC-2`.

*Retained limitation, stated rather than hidden:* the function cannot invent the
identity of the binary a log came from, so a caller that supplies no expected
identity still gets the presence-only check. That is why A22's recorded
`candidate-identity-mismatch` driver (which calls `check_claim` with three
positional arguments) still observes an acceptance; the repaired path is the
caller-supplied identity, demonstrated through the CLI below. The presence rule
itself is unchanged.

**Files.** `forensics/tools/side_channel_erasure.py` (+95/−3);
`forensics/tools/tests/test_side_channel_erasure.py` (+104);
`docs/SIDE-CHANNEL-AND-ERASURE.md` (+6/−1).

**Document correction.** `docs/SIDE-CHANNEL-AND-ERASURE.md` §7 stated that rule 2
refuses only a *missing* harness, identity or tainted inputs. The paragraph now
states that a supplied artefact identity is compared, and the refusal table has
a `CTGRIND_BINARY_IDENTITY_MISMATCH` row with its control. This is the only
sentence in `docs/INSTRUMENT-QUALIFICATION.md` or the side-channel document that
described the old behaviour; `docs/INSTRUMENT-QUALIFICATION.md` states no such
old behaviour and was not changed.

**Witness re-run (court):**

```
candidate-identity-mismatch: exit=1 code=yes
    CTGRIND_BINARY_IDENTITY_MISMATCH: REPLAY-CT-1: recorded binary_identity 'sha256:dede…' does not match the artefact under test 'sha256:abab…'
```

---

## 3. E6 — the SARIF emission count could disagree with its projection

**Old behaviour.** `validate_emission` checked each result's structure but never
compared the number of results with `properties.a1.projection.projectedTotal`,
with the per-rule `projection.projected` tallies, with `levelCounts`, or with
the native record's own population. Removing one result from a live emission
therefore produced a document that was accepted while its own projection still
declared the original total.

**New behaviour.** `validate_emission(document, native_populations=None)` refuses
with the existing stable code **`SARIF_REFUSED_POPULATION_MISMATCH`** when any of
the following disagrees with `run.results`:

* `projection.projectedTotal` (integer, equal to the result count);
* `projection.projected` (per-rule tallies, and their sum);
* `properties.a1.levelCounts` (per-level tallies, when present);
* the native population, when the caller supplies
  `native_populations: {record path: projected native findings}`.

`build_document` now supplies that mapping from each source's own projection, so
the emitted document is checked against the records it projects. No rule or
shape check was relaxed.

**Files.** `forensics/tools/sarif_adapter.py` (+100/−3);
`forensics/tools/tests/test_sarif_adapter.py` (+78).

**Witness re-run (court):**

```
emission-result-count-mismatch: exit=1 code=yes
    SARIF_REFUSED_POPULATION_MISMATCH: runs[0]: projection.projectedTotal is 17 but run.results has 16
live-emission-accepted: exit=0
evidence/a1/SARIF.json: accepted, 4245 results in 6 runs
```

The committed A1 emission still validates unchanged: 4,245 results in 6 runs,
with every run's `projectedTotal`, per-rule tally and `levelCounts` equal to its
results. No record was edited.

---

## 4. E7 — two consumers used the permissive reader

**Old behaviour.** `etp_t1_seed.py` read the instrument register with
`json.loads`, and `freshness._instrument_entries` read it with `json.loads` and
swallowed `JSONDecodeError` into `{}`. A duplicate key was last-wins, a BOM and
trailing data were accepted, and `NaN`/`Infinity` parsed as floats.

**New behaviour.** Both consumers read the register with
`harden.loads(bytes)`. A duplicate key, a byte-order mark, trailing data and a
non-finite number are refused with harden's own stable codes
**`PH_REFUSED_DUPLICATE_KEY`**, **`PH_REFUSED_BOM`**,
**`PH_REFUSED_TRAILING_DATA`** and **`PH_REFUSED_NONFINITE`**. The seeder prints
the code and exits 1 without writing a graph; freshness raises its `JsonError`
carrying harden's code, so the existing CLI refusal paths report it rather than
deriving from an empty or last-wins register. The seeder gained an
`--instruments PATH` input (default: the tracked register) so the consumer's
real read path is reachable in a control.

**Files.** `forensics/tools/etp_t1_seed.py` (+25/−4);
`forensics/tools/freshness.py` (+15/−4);
`forensics/tools/tests/test_freshness.py` (+55);
`forensics/tools/tests/test_traceability.py` (+44).

**Witness re-run (court), duplicate-key register through both consumers:**

```
etp_t1_seed duplicate-key: exit=1 code=yes
    PH_REFUSED_DUPLICATE_KEY: the object repeats the key 'instruments'; …
freshness duplicate-key: exit=1 code=yes
    evidence/etp3/instruments.json at f7e9e74e1ae4: PH_REFUSED_DUPLICATE_KEY: …
```

The tracked register itself still parses: `harden.loads` admits it (11
instruments), `freshness._instrument_entries` derives 11 entries at `HEAD`, and
`etp_t1_seed.py --output <tmp>` reproduces the committed
`evidence/etp-t1/TRACEABILITY.json` byte-for-byte.

---

## 5. Findings caused by the repairs (records left alone)

**5.1 A22's committed measurement is invalidated and was not rewritten.**
A22's `harness_strict_reader` records the permissive source lines of the two
consumers and refuses with `AQ_REFUSED_WITNESS_ABSENT` when a line has gone —
that is A22 working as designed ("a consumer list that has drifted is not the
list that was measured"). The required migration removes exactly those lines:

* old witness (ETP-T1):
  `instruments = json.loads((REPO / "evidence/etp3/instruments.json").read_text())`
* new read path: `instruments = load_instruments(INSTRUMENTS)`, whose loader is
  `harden.loads`.
* old witness (A7): `document = json.loads(text)`; new:
  `document = harden.loads(text.encode("utf-8"))`.

Consequently `evidence/a22/build_evidence.py` now exits before writing
(`AQ_REFUSED_WITNESS_ABSENT`), and `test_adversarial_qualification.py`'s
`setUpModule` errors because no fresh record was produced. A22's committed
`RESULTS.json` and document still describe candidate `6e64e644c` and were not
edited.

The old and new committed values, stated rather than adjusted:

| recorded value | at A22's candidate | with the repaired tools |
|---|---|---|
| E5 verdict | `DEFECT`, `0/3` refused | `PARTIAL`, `2/3` refused (the summariser half now refuses; A22's driver does not supply an identity, so its `candidate-identity-mismatch` case is unchanged) |
| E6 verdict | `PARTIAL`, `1/2` refused | `QUALIFIED`, `2/2` refused |
| E7 consumer table | `2` permissive consumers | the table is hardcoded and still says `2`; a re-derived record would be false until A22 updates it |
| summary | `6 qualified / 1 defect / 1 partial` | `7 qualified / 0 defect / 1 partial` |
| producer exit | `1` | `1` (the partial E5 keeps it nonzero) |

These are the values a re-derived record would carry once A22's source-witness
table is refreshed; today the producer aborts at E7 before writing, so no fresh
record exists at all.

If A22's E5 driver were also updated to pass the expected binary identity, E5
would become `QUALIFIED` (`3/3`) and the producer would exit 0 with 8 qualified.
That is A22's decision at its next touch; no A22 expectation was changed here.
E7's `reported` block also states the two consumers' loaders statically, so its
fresh record would still name them `permissive` after the migration until A22
updates that table.

**5.2 No committed record required a value change.** `evidence/a1/SARIF.json`,
`evidence/etp-t7/*`, `evidence/etp3/instruments.json`,
`evidence/etp-t1/TRACEABILITY.json` and `evidence/a22/*` are unmodified
(`git diff -- evidence/a22 evidence/a1 evidence/etp-t7 evidence/a19` is empty).

**5.3 A19 events are prose-only.** `evidence/a19/EVENTS.json` is owned by A19 and
was not edited. Three events should be registered there at the next A19 touch:
E5 (the ctgrind summariser and identity rule), E6 (the SARIF emission
population), and E7 (the two register consumers). Until then this receipt is the
only record of them.

---

## 6. Gates

| gate | result |
|---|---|
| `free -g` / court | `available 13`; derived cap below the 2 GiB floor; reused the running 6 GiB `openssl-rs-court` (up 35 h). |
| focused tests | `test_summarize_ct` 11 OK; `test_side_channel_erasure` 28 OK; `test_sarif_adapter` 34 OK; `test_freshness` 54 OK; `test_traceability` 31 OK. 28 new tests; none removed or newly ignored. |
| whole suite | `Ran 1634 tests in 247.447s` / `FAILED (errors=1)` — **0 failures** and **1 error**, `setUpModule (test_adversarial_qualification)` (§5.1), whose cause line is `FileNotFoundError: … 'EXPERIMENTS.json'` after `adversarial_qualification.Refusal: AQ_REFUSED_WITNESS_ABSENT`. At the base HEAD the same command ran 1652 tests `OK`; A22's 46 tests no longer run because their producer refuses, and 28 focused tests were added (1652 − 46 + 28 = 1634). The gate is **not green**; see §5.1. |
| witnesses re-run | `evidence/defects/e5-e6/replay.py` → `REPLAY PASS failures=0`; every refusal code and exit status is quoted in §§1–4. |
| real records | A1 `SARIF.json` accepted, 4,245 results / 6 runs; ETP-T7 `validate` exit 0 and `--self-test` `SELF-TEST PASS`; register parses through both consumers and the seeder reproduces the committed graph. |
| `docs_consistency.py` | `ok: 20 hand-written claim(s) agree … the earned-trust constitution is wired` |
| `spec_guard.py check` | `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions` |

**Gate 4, exact re-run** (`python3 evidence/defects/e5-e6/replay.py`, court):

```
empty-log: exit=3 code=yes
unrelated-log: exit=4 code=yes
log-with-a-finding: exit=0 counts=True
candidate-identity-mismatch: exit=1 code=yes
emission-result-count-mismatch: exit=1 code=yes
live-emission-accepted: exit=0
evidence/a1/SARIF.json: accepted, 4245 results in 6 runs
etp_t1_seed duplicate-key: exit=1 code=yes
freshness duplicate-key: exit=1 code=yes
REPLAY PASS failures=0
```

**ETP-T7 self-test, exact lines:**

```
CONTROL R2 identity positive (recorded identity equals the artefact): PASS (accepted)
CONTROL R2 negative (ctgrind without tainted inputs): PASS (refused ['CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT'])
CONTROL R2 identity negative (recorded identity differs from the artefact): PASS (refused ['CTGRIND_BINARY_IDENTITY_MISMATCH'])
SELF-TEST PASS failures=0
```

`git --no-pager status --porcelain` reports the ten modified files, the new
`forensics/tools/tests/test_summarize_ct.py`, and the new
`evidence/defects/e5-e6/` directory. Nothing was committed or pushed.

---

## 7. What is not established

* The repaired summariser has not been run on a live valgrind ctgrind capture;
  its controls use constructed logs. No memcheck measurement is claimed.
* `CTGRIND_BINARY_IDENTITY_MISMATCH` is exercised against a constructed claim
  and a derived file digest, not against a recorded candidate DSO for the
  ETP-T7 evidence; the committed ETP-T7 documents contain no ctgrind claim.
* A22's record is not reproducible at this candidate. It is invalidated, not
  repaired, and its re-derivation is A22's decision.
* No BOUNDARY or SEAL evidence was produced; no instrument was promoted to
  `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`, and no cryptography or timing claim
  is made.
