# PFP-18 receipt — performance classification binding

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-18.
**Programme:** `docs/PERFORMANCE-FRONTIER.md` §0, §9.5, §10 and §15.
**Tool:** `forensics/tools/performance_classification.py`.
**Records:** `evidence/performance-frontier/claims/`.
**Claim class:** none of these records is a frontier result. Both campaign
records are `SCOPED_OBSERVATION` on the virtualised court, and the records say so
in their own obligations.

---

## 1. Source identity

| item | value |
|---|---|
| branch | `staging` |
| source code changed | none: no file under `src/`, `Cargo.toml`, `Cargo.lock` or `build.rs` |
| build | none; no `cargo build`, no benchmark, no court run |
| tool | `forensics/tools/performance_classification.py`, SHA-256 `9ad9b402103c6d1eb6580d458dd4144cc26f9346d6d23936c92c1576dd7d2605` |
| tests | `forensics/tools/tests/test_performance_classification.py`, SHA-256 `91fe0e9b4542694b5a0700c7aff44197515984c7bf17b267c7ab883130cfbfd9` |
| PFP-0 record | `evidence/performance-frontier/claims/PFP-0.claim.json`, SHA-256 `cf368d78da1a3965fce32e64a110c6964f1368ba6ead24d59eed92ab144ffc86` |
| PFP-1 record | `evidence/performance-frontier/claims/PFP-1.claim.json`, SHA-256 `a1ec33a5bf97badf71a2019f73c7fc33a8fbd15d30569827b458b71895310357` |
| PFP-1 raw manifest | `evidence/performance-frontier/claims/PFP-1.raw-manifest.json`, SHA-256 `12229dee8ff447adc3e2de404ef4ea8b260f9136a948696a4ae21ac501e3258e` |

## 2. What the producer does

The tool reads a claim record of type `openssl-rs/performance/claim-record/v1`
and refuses an unbounded classification. It does not execute a benchmark and does
not decide whether a cited experiment occurred; the record's `producer.limits`
and `obligations.open` state that.

Each record binds:

- **candidate** — source commit, artefact label and full SHA-256, build profile
  and target; the artefact bytes are declared absent with an obligation because
  both candidates were built in the campaign workspace;
- **instrument** — harness, allocation probe, runner and analyser digests; the
  measures, unit, procedure, repetition count, unit of replication and statistic;
- **population** — the frozen nine-workload identifier set, the realised set and
  the derived missing, duplicate and undeclared lists (all empty);
- **scope** — L3, the nine workloads, the security profile and explicit
  exclusions;
- **threat model** — secret classes, tags, a statement and the observation model;
- **venue** — `VIRTUALISED_COURT`, `pmu_exposed: false`, all four bare-metal
  controls false;
- **comparators** — the measured OpenSSL 3.6.4 authority, and AWS-LC, BoringSSL,
  rustls, wolfSSL and the research-frontier kernel as `UNAVAILABLE` or
  `NOT_APPLICABLE` with reasons; none is a loss and none is a comparison row;
- **obligations** — T23, T24, T29 and the item-specific residuals, each
  `discharged: false`, with `attempted_discharge: []`.

The PFP-1 record binds a 118-file raw-sample manifest
(`PFP-1.raw-manifest.json`) whose entries are re-derived from the campaign
directory by the test module. The PFP-0 record instead records that its raw
samples were retained only in the campaign workspace and carries the obligation
`PFP0-RAW-SAMPLES`.

## 3. The refusal set

37 refusal codes. `python3 forensics/tools/performance_classification.py rules`
prints the table. The principal families:

- identity: `PF_CANDIDATE_IDENTITY_ABSENT`, `PF_CANDIDATE_IDENTITY_MULTIPLE`,
  `PF_INSTRUMENT_IDENTITY_ABSENT`, `PF_INSTRUMENT_SAMPLES_ABSENT`,
  `PF_POPULATION_ABSENT`, `PF_POPULATION_INCOMPLETE`,
  `PF_POPULATION_DECLARATION_MISMATCH`, `PF_SCOPE_ABSENT`,
  `PF_THREAT_MODEL_ABSENT`, `PF_OBLIGATIONS_ABSENT`, `PF_AUTHORITY_ABSENT`;
- venue: `PF_VENUE_ABSENT`, `PF_VENUE_CLASS_INSUFFICIENT`,
  `PF_VENUE_EVIDENCE_CONTRADICTS`, `PF_BARE_METAL_CONTROLS_ABSENT`;
- classification support: `PF_PREREGISTRATION_ABSENT`,
  `PF_STATISTICAL_SUPPORT_ABSENT`, `PF_COMPARATOR_POPULATION_ABSENT`,
  `PF_COMPARATOR_IDENTITY_ABSENT`, `PF_COMPARATOR_NOT_QUALIFIED`,
  `PF_INDEPENDENT_RECEIPT_ABSENT`, `PF_INDEPENDENCE_SELF_ASSERTED`;
- obligations and assurance: `PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE`,
  `PF_CLASSIFICATION_CONFLATES_ASSURANCE`;
- binding: `PF_REFERENCE_ABSENT`, `PF_REFERENCE_DIGEST_MISMATCH`,
  `PF_REFERENCE_UNRESOLVED`, `PF_ABSENCE_UNRECORDED`,
  `PF_PRODUCER_ABSENT`, `PF_PRODUCER_LIMITS_ABSENT`, `PF_PRODUCER_UNBOUND`;
- form: `PF_SCHEMA`, `PF_CLASSIFICATION_UNKNOWN`, `PF_JSON_MALFORMED`,
  `PF_JSON_DUPLICATE_KEY`, `PF_JSON_NON_FINITE`, `PF_DUPLICATE_RECORD_ID`.

Each code has one negative control. The self-test also carries three positive
controls, so the rule set is not vacuous:

- a frontier-leading fixture with bare-metal controls on the main venue and on a
  second platform, all comparators measured, a frozen qualified population, a
  preregistered margin and a margin-excluding interval;
- a scoped-observation fixture;
- an independently reproduced fixture with an external receipt from a party
  other than the author.

## 4. The critical control

A record is refused when it claims a frontier class while its instrument identity,
population, candidate identity, threat model or obligations is absent. The test
module exercises each of the five separately (`FrontierBindingRefusals`), and
also refuses a virtualised-venue frontier claim, a frontier claim with an
unmeasured comparator, and a record that carries `safe_compatible: true` or uses
performance evidence to discharge T23.

## 5. What this receipt does not establish

- It does not establish a frontier result, a hardware-counter result or a
  statistically supported lead. Both records are `SCOPED_OBSERVATION`.
- It does not establish that the measurements occurred as the campaign receipts
  describe. It binds their declared identity; the campaign receipts are the
  record of execution.
- It does not establish constant-time behaviour or discharge T23, T24, T29 or
  any other timing obligation.
- It does not turn a performance classification into `SAFE_COMPATIBLE` or into
  semantic assurance; the validator refuses a record that carries either.
- It does not compare against AWS-LC, BoringSSL, rustls or wolfSSL; those rows
  are `UNAVAILABLE` or `NOT_APPLICABLE`.

## 6. Verification

Run from the repository root:

```
python3 forensics/tools/performance_classification.py check
python3 forensics/tools/performance_classification.py self-test
python3 forensics/tools/tests/test_performance_classification.py
```

Observed:

```
OK evidence/performance-frontier/claims/PFP-0.claim.json
OK evidence/performance-frontier/claims/PFP-1.claim.json
performance-classification: 2 record(s) accepted, 0 refused

performance-classification: 41 controls, 0 failure(s)

Ran 23 tests in 0.225s
OK
```

No build, benchmark or court was run. `available` was 30 GiB immediately before
the Python runs; the operative cap was not used because nothing compiled.

## 7. Files written

| path | purpose |
|---|---|
| `docs/PERFORMANCE-FRONTIER.md` §15 | normative classification-binding section |
| `docs/PERFORMANCE-FRONTIER-TODO.md` PFP-18 | queue row at its honest state |
| `forensics/tools/performance_classification.py` | validator, rules and self-test |
| `forensics/tools/tests/test_performance_classification.py` | refusal, binding, coverage and determinism controls |
| `evidence/performance-frontier/claims/PFP-0.claim.json` | bound PFP-0 classification |
| `evidence/performance-frontier/claims/PFP-1.claim.json` | bound PFP-1 classification |
| `evidence/performance-frontier/claims/PFP-1.raw-manifest.json` | 118 raw-sample identities |
| `evidence/performance-frontier/claims/RECEIPT.md` | this receipt |

No `AGENTS.md`, no `docker/` file and no other item's evidence was modified.

## 8. Known consequence for the ETP-6 package

The tools named above are new files under `forensics/tools`, which the ETP-6
package declares as an input tree. `evidence/etp6/MANIFEST.json` is frozen and
does not yet contain them, so `etp6_package.py verify` will report them as
"input is present but absent from the frozen manifest" until a `--refreeze` and
the clean-room replay are performed. That replay compiles the crate, so it is
**deferred** under the no-build rule in force today rather than silently
refrozen. This is a manifest-drift consequence, not a defect in the validator,
and it is recorded here so a later session does not mistake the refusal for a
new failure.
