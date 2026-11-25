# PFP-19 receipt — arm admission and evidence reuse

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, PFP-19.
**Programme:** `docs/PERFORMANCE-FRONTIER.md` §0 (the candidate rule), §11 (the
admission conjunction and the refused shortcuts) and §16.
**Tool:** `forensics/tools/performance_admission.py`.
**Register:** `evidence/performance-frontier/admission/ARMS.json`.

---

## 1. Source identity

| item | value |
|---|---|
| branch | `staging` |
| source code changed | none |
| build | none; no `cargo build`, no benchmark, no court run |
| tool | `forensics/tools/performance_admission.py`, SHA-256 `19c0f9d768f17deaf98ccb06dee8008e8729640329fb37db4fdb5f7c161695d0` |
| tests | `forensics/tools/tests/test_performance_admission.py`, SHA-256 `0b54d189bcad4fa610e7488553916c9be9219528beb7604cde95fad453e4249a` |
| register | `evidence/performance-frontier/admission/ARMS.json`, SHA-256 `18d29f8ebaaaa5db76372e79f4103c506abaa8d814184404e2c1989f9c5f3c92` |

## 2. The rule the tool executes

An arm is a `CANDIDATE` only as the conjunction, at one candidate digest, of:

1. a measurement bound to that digest, carrying a §10 classification and a
   population frozen before execution;
2. a passing differential court at that digest;
3. a binary constant-time audit at that digest — a taint run recorded as
   `CTGRIND` is not the binary branch audit;
4. an empty timing-discharge set;
5. `safe_compatible` and `semantic_assurance` declared false;
6. no entry from the §11 refused-shortcut table.

Any arm that fails one conjunct is an `EXPERIMENT`. Reuse is admitted only at the
full five-part identity (source, tool, instrument, target, population), and a
changed population is refused rather than absorbed.

27 refusal codes, including `PA_UNMEASURED_ARM_CALLED_CANDIDATE`,
`PA_CANDIDATE_WITHOUT_COURTS`,
`PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT`,
`PA_EVIDENCE_NOT_AT_SAME_DIGEST`, `PA_STALE_BINARY`,
`PA_POPULATION_CHANGED_AFTER_EXECUTION`,
`PA_REUSE_IDENTITY_INCOMPLETE`, `PA_REUSE_IDENTITY_MISMATCH`,
`PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE` and `PA_SHORTCUT_TAKEN`.
`python3 forensics/tools/performance_admission.py rules` prints the table and the
shortcut vocabulary.

## 3. The repository's measured arm

The register contains one arm, `PFP-1`:

| field | value |
|---|---|
| status | `EXPERIMENT` |
| candidate digest | `596f4833e35932da7efff936185dee17dcb56f3b6363f4682300afb741d3c5b9` |
| source | `91ac573c0a8e1bc11371718e5f2a6022c55c9535` with patch `ddd4e0e0…` |
| measurement | `evidence/performance-frontier/claims/PFP-1.claim.json`, classification `SCOPED_OBSERVATION` |
| population | nine frozen workload identifiers, digest `40d1537b…`, frozen at source `c9a0fdd5` |
| differential courts | `null` — not recorded at this digest |
| constant-time audit | ctgrind at this digest, kind `CTGRIND`; the binary branch audit is not recorded |
| timing obligations | T23, T24, T29, `PFP1-DIFFERENTIAL-COURTS`, `PFP1-BINARY-BRANCH-AUDIT`, `PFP1-DIRTY-CANDIDATE`, `PFP1-WITHIN-CANDIDATE`, `PFP1-NO-PMU`, all `discharged: false` |
| assurance | `safe_compatible: false`, `semantic_assurance: false` |
| shortcuts | none |

The status is not a judgement on the PFP-1 change. Its code is merged, its
in-crate differential tests and ctgrind results are recorded in its own receipt,
and its queue item is `DONE`. What the register refuses to claim is that the arm
satisfies this programme's **candidate** predicate: the differential courts and
the binary branch audit at digest `596f4833` are not recorded, so the arm is an
experiment. The control in the test module promotes it to `CANDIDATE` and watches
`PA_CANDIDATE_WITHOUT_COURTS` and `PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT`
fire.

## 4. Non-vacuity

`performance_admission.py self-test` carries a complete synthetic candidate and
an incomplete measured experiment as positive controls, and one negative control
per refusal code. The complete candidate is accepted; so is the experiment.

## 5. What this receipt does not establish

- It does not establish that the PFP-1 differential tests or ctgrind run occurred
  as described; it binds the summaries they produced.
- It does not establish that ctgrind or any branch audit is sensitive to every
  secret-dependent defect class. A taint count is bounded evidence, not a proof.
- It does not establish that any arm is or is not a performance candidate at a
  digest where the relevant evidence has not been recorded.
- It does not discharge T23, T24, T29 or any timing obligation.
- It does not promote an `EXPERIMENT` to `CANDIDATE`; only evidence bound at the
  same digest can do that.

## 6. Verification

```
python3 forensics/tools/performance_admission.py check
python3 forensics/tools/performance_admission.py self-test
python3 forensics/tools/tests/test_performance_admission.py
```

Observed:

```
OK evidence/performance-frontier/admission/ARMS.json
performance-admission: 1 register(s) accepted, 0 refused

performance-admission: 32 controls, 0 failure(s)

Ran 16 tests in 0.192s
OK
```

No build, benchmark or court was run. `available` was 30 GiB immediately before
the Python runs.

## 7. Files written

| path | purpose |
|---|---|
| `docs/PERFORMANCE-FRONTIER.md` §16 | normative admission, reuse and non-substitution section |
| `docs/PERFORMANCE-FRONTIER-TODO.md` PFP-19 | queue row at its honest state |
| `forensics/tools/performance_admission.py` | validator, rules and self-test |
| `forensics/tools/tests/test_performance_admission.py` | refusal, binding, coverage and determinism controls |
| `evidence/performance-frontier/admission/ARMS.json` | the arm register |
| `evidence/performance-frontier/admission/RECEIPT.md` | this receipt |

No `AGENTS.md`, no `docker/` file and no other item's evidence was modified.

## 8. Known consequence for the ETP-6 package

The tool named above is a new file under `forensics/tools`, which the ETP-6
package declares as an input tree. `evidence/etp6/MANIFEST.json` is frozen and
does not yet contain it, so `etp6_package.py verify` will report it as "input is
present but absent from the frozen manifest" until a `--refreeze` and the
clean-room replay are performed. That replay compiles the crate, so it is
**deferred** under the no-build rule in force today rather than silently
refrozen. This is manifest drift, not a defect in the validator.
