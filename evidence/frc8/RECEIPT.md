# FRC-8 receipt — the DO-178C objective matrix for a declared non-airborne context

## 1. Identity and venue

| field | value |
|---|---|
| item | FRC-8 of `docs/FRC-TODO.md` |
| programme | `docs/FORMAL-REFINEMENT-CERTIFICATION.md` (section 6) |
| branch | `staging` |
| HEAD at production (base commit) | `7bcf7befa249b32f85e10d09b7795f7a891617fa` |
| orchestrator | commits and pushes; this agent did not |
| venue | the development host, Python 3 only; **no build, no court, no Rust, no measurement** |
| `free -g` before the work | `Mem: 45 13 29 0 3 32` (available **32 GiB**); `Swap: 45 22 23` |
| heavy commands | none. Every command was a Python validator, producer or test module; nothing compiled, linked or measured. |

The item is a records-and-documentation task. Its executable part is the Python
validator, its tests and the deterministic producer.

## 2. What was delivered

| path | role |
|---|---|
| `docs/DO178C-CONFORMANCE.md` | the normative document: declared context, 14-objective matrix, 12 missing items, independence comparison, non-claim, refusal table, `NOT_RUN` |
| `evidence/frc8/DO178C-MATRIX.json` | the machine record: context, objectives, statuses, evidence, independence, missing items, non-claim |
| `evidence/frc8/build_evidence.py` | the deterministic producer of the matrix |
| `forensics/tools/do178c_matrix.py` | the validator: 13 stable refusal codes, strict JSON, record-anchored independence, document synchronisation |
| `forensics/tools/tests/test_do178c_matrix.py` | 36 controls: one firing control per refusal code, three non-vacuity controls, producer determinism, document sync, CLI exit codes |
| `docs/FRC-TODO.md` | the FRC-8 row changed from `TODO` to `PARTIAL`, with the reason |
| `docs/ETP-TODO.md` | section K gains an FRC-8 status paragraph stating that no ETP verdict is upgraded |
| `evidence/frc8/RECEIPT.md` | this file |

Record digests (SHA-256, full, after the final edits above):

| file | sha256 |
|---|---|
| `docs/DO178C-CONFORMANCE.md` | `698e013129a8932dad5eba71b4a502c4aa262565306f3b1faa1be654acd9d178` |
| `evidence/frc8/DO178C-MATRIX.json` | `fa20aaa146a38a34a633140414e6a767bd35df95d5c71f18b040c4b9f4b59309` |
| `evidence/frc8/build_evidence.py` | `789c331dda44630080d17eb3b8d28b59fb04bedaf51b4edf79d1dd0302dfb4fb` |
| `forensics/tools/do178c_matrix.py` | `6dbaee4d2e383286bfe5ed9a2b12f69086c3a2d94a8b8c28b9b8e1747a27ebe5` |
| `forensics/tools/tests/test_do178c_matrix.py` | `1d2f32fa84227261625a489c575ddff83831a776b8ac9d1660c0d14fb3161e21` |

## 3. The declared system context, verbatim

The declaration is a scope choice, not a compliance claim.

> The software item is the libcrypto-compatible shared library built from this
> repository for the x86_64-unknown-linux-gnu target in the release profile,
> considered as a standalone library under its declared C ABI on the development
> host and in the court container. The context assigns no aircraft, engine or
> spacecraft function, no system safety assessment, no development assurance
> level and no target hardware.

The narrowest context the existing evidence supports is one host, one target
triple, one profile and one ABI. It excludes:

| exclusion id | category | excluded |
|---|---|---|
| `XCE-TARGET-HARDWARE` | target hardware | airborne, embedded and production target hardware; every cited record is from the development host or the court container |
| `XCE-AIRBORNE` | airborne/spacecraft applicability | every aircraft, engine and spacecraft installation, environment and lifecycle; DO-178C is a checklist, not an invoked certification basis |
| `XCE-DAL` | DAL | every development assurance level, including DAL A, B, C, D and E |
| `XCE-CERTIFICATION` | certification consequence | every airworthiness finding, approval, compliance statement and system-level safety result |
| `XCE-WCET` | worst-case execution | bounded execution, deadline analysis and worst-case execution time, which constant time does not establish |
| `XCE-ENVIRONMENT` | environmental qualification | temperature, vibration, radiation and electromagnetic effects |

The context is declared in `CTX-FRC8-NONAIRBORNE-LIBRARY` and the validator
refuses a declaration that omits or re-categories any exclusion. **This is a
scope choice, not a compliance claim.**

## 4. The matrix result

`evidence/frc8/DO178C-MATRIX.json` records **14 objectives** from the
programme's section 6:

| status | count | objectives |
|---|---|---|
| `SATISFIED_WITH_EVIDENCE` | **0** | — |
| `PARTIAL` | 5 | `DO8-HLR`, `DO8-ARCH`, `DO8-ROBUST`, `DO8-CM`, `DO8-CHANGE` |
| `NOT_SATISFIED` | 7 | `DO8-PLANNING`, `DO8-LLR`, `DO8-REQVER`, `DO8-COVERAGE`, `DO8-QA`, `DO8-TOOL`, `DO8-FORMAL` |
| `UNVERIFIED` | 2 | `DO8-TARGET-VALIDATION`, `DO8-BOUNDED-EXECUTION` |

**No objective is `SATISFIED_WITH_EVIDENCE`.** The two `UNVERIFIED` rows are not
recorded as unmet because even their applicability and normative wording were not
read: the programme names target-hardware validation and bounded execution after
its assurance table, and this session did not establish which objective they
instantiate. Recording them as `NOT_SATISFIED` would have claimed more than the
reading supports.

**Every one of the 14 rows records `normative_objective_ids: UNVERIFIED`.** The
exact DO-178C objective identifiers and wording were not read, so no status here
is a statement about a specific DO-178C objective; each status is a statement
about the substance as the programme's section 6 summarises it, with the reading
that would settle the exact text named per row.

Why two objectives are `PARTIAL` rather than unmet: `DO8-HLR` has 21 requirement
and 7 hazard nodes but 0 specification nodes; `DO8-ARCH` has six refinement
levels and five edges with 0 discharged and 51,703 boundary-unconfined unsafe
sites; `DO8-ROBUST` has documents and a 7-finding erasure audit with 0 repairs
and 1 HIGH; `DO8-CM` has `ALL_IDENTICAL` builds at one host and 118 of 231
uncertifiable evidence items; `DO8-CHANGE` has 6 change sets with machine-readable
impact analysis but 0 satisfied requirements and a `REFUSED` tier report. Each is
genuinely partial, not a promotion.

### 4.1 The missing items

Twelve items are registered, each with a reason and a settling method, and each
is a named blocker on at least one objective:

`MI-PLANNING`, `MI-REQUIREMENT-BASELINE`, `MI-REQUIREMENTS-BASED-TESTS`,
`MI-STRUCTURAL-COVERAGE`, `MI-SYSTEM-SAFETY-ASSESSMENT`, `MI-TOOL-QUALIFICATION`,
`MI-TARGET-EXECUTION`, `MI-CONFIGURATION-INDEX`, `MI-INDEPENDENT-REVIEW`,
`MI-FORMAL-METHODS-JUSTIFICATION`, `MI-TARGET-TIMING`, `MI-PROBLEM-REPORTING`.

The four the brief names explicitly are all present: tool qualification
(`MI-TOOL-QUALIFICATION`), target execution (`MI-TARGET-EXECUTION`),
independence of review (`MI-INDEPENDENT-REVIEW`) and configuration-index
completeness (`MI-CONFIGURATION-INDEX`). The others are what the matrix shows
absent: a plan, a requirement baseline, requirement-derived verification,
structural coverage, a safety assessment, a formal-methods justification, a
timing bound and a problem-report process.

### 4.2 Independence required versus held

`evidence/etp-t15/INDEPENDENCE.json` records **50 assignments, all 50 adjudicated
by the author's party, 0 declared parties, 0 external parties, 1 asserted
independence (refused) and 1 retained dissent**. Every objective row therefore
records `SAME_PARTY_ONLY`. `DO8-QA` requires independent checks under the
programme's section 6, so it is `NOT_SATISFIED`; the validator refuses a
`SATISFIED_WITH_EVIDENCE` row whose required independence is `UNVERIFIED` or is
held as same-party, and refuses an `INDEPENDENT` claim without a distinct trust
domain and an external party. The matrix's independence counts are compared with
the independence record, so a party count cannot be invented.

## 5. Refusal codes and the control that fires each

`forensics/tools/do178c_matrix.py` implements 13 stable refusal codes. Each has a
negative control in `forensics/tools/tests/test_do178c_matrix.py` that corrupts
one field of the committed record and observes that exact code:

| code | control corruption | test |
|---|---|---|
| `DO_REFUSED_SCHEMA` | the matrix schema is replaced | `test_schema` |
| `DO_REFUSED_DUPLICATE_KEY` | a JSON object repeats a key | `test_duplicate_key` |
| `DO_REFUSED_CONTEXT_ABSENT` | every context exclusion is removed | `test_context_absent` |
| `DO_REFUSED_STATUS_WITHOUT_EVIDENCE` | a `NOT_SATISFIED` row loses its evidence | `test_status_without_evidence` |
| `DO_REFUSED_EVIDENCE_ABSENT` | a cited path is replaced with an absent one | `test_evidence_absent` |
| `DO_REFUSED_UNVERIFIED_WITHOUT_METHOD` | an `UNVERIFIED` row loses its settling method | `test_unverified_without_method` |
| `DO_REFUSED_INDEPENDENCE_UNSUPPORTED` | a row claims `INDEPENDENT` with no trust domain | `test_independence_unsupported` |
| `DO_REFUSED_CERTIFICATION_CLAIM` | the matrix claims certification | `test_certification_claim` |
| `DO_REFUSED_MISSING_ITEM_OMITTED` | `MI-TARGET-TIMING` is removed | `test_missing_item_omitted` |
| `DO_REFUSED_MISSING_ITEM_WITHOUT_METHOD` | a missing item loses its reason | `test_missing_item_without_method` |
| `DO_REFUSED_NON_CLAIM_ABSENT` | the non-claim statement is replaced | `test_non_claim_absent` |
| `DO_REFUSED_DOCUMENT_DRIFT` | `DO8-ARCH` is renamed in the document | `test_document_drift` |
| `DO_REFUSED_USAGE` | no subcommand is given | `test_usage` |

The coverage test `test_every_declared_code_has_a_firing_control` asserts that the
control set equals `REFUSALS` and that every control fires. A separate control
`test_party_counts_cannot_outrun_the_record` changes the matrix's external-party
count to 1 while the independence record holds 0, and observes
`DO_REFUSED_INDEPENDENCE_UNSUPPORTED`.

Three **non-vacuity** controls show that the rules can accept:

* a `SATISFIED_WITH_EVIDENCE` objective whose independence requirement is
  `NONE_REQUIRED` and whose evidence exists is accepted;
* an `INDEPENDENT` review with a declared distinct trust domain, an external
  party and a matching synthetic independence summary is accepted;
* an `UNVERIFIED` objective with a settling method and no evidence is accepted.

**None of the three describes this project's state.** They establish that the
decision procedures are not refusal-only.

## 6. The non-claim, verbatim

> **Objective satisfaction is not certification.** This matrix establishes only
> which of the programme's section 6 objectives are unmet, partly met or
> unverified in the declared context. It records no certification, no DO-178C
> level and no development assurance level, and no row may be cited as a
> certification result.

The matrix does not establish certification, an airworthiness finding, an
approval, a DO-178C level, a DAL, the sufficiency of any cited evidence, the
correctness of any objective identifier, or the sufficiency of the declared
context for any certification basis. A matrix with unmet objectives establishes
only which objectives are unmet.

## 7. Gates actually run

| gate | command | result |
|---|---|---|
| memory | `free -g` before each command | first reading `Mem: 45 13 29 0 3 32` (available 32 GiB); subsequent readings 31 GiB; `Swap: 45 22 23` |
| focused controls | `python3 -m unittest forensics.tools.tests.test_do178c_matrix` | `Ran 36 tests in 0.287s`; `OK` |
| validator | `python3 forensics/tools/do178c_matrix.py check` | `do178c: objectives=14 satisfied=0 partial=5 not_satisfied=7 unverified=2 missing_items=12 normative_unverified=14 codes=DO_OK`; exit 0 |
| producer self-check | `python3 evidence/frc8/build_evidence.py --check` | `frc-8: external_parties=0 independence_assignments=50 missing_items=12 normative_ids_unverified=14 not_satisfied=7 objectives=14 partial=5 refusal_codes=13 same_party_adjudicator=50 satisfied=0 unverified=2`; exit 0 |
| producer determinism | two `--out` runs and the committed bytes | one record, byte-identical across runs and to the committed bytes (asserted by `test_producer_is_byte_identical_across_two_runs`) |
| JSON well-formedness | `python3 -m json.tool evidence/frc8/DO178C-MATRIX.json` | exit 0, well-formed |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; exit 0 |
| documentation consistency | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; exit 0 (the named Phase-7 exemption printed) |
| earned-trust constitution | `python3 forensics/tools/earned_trust.py check` | `earned-trust: ok: every article is enforced or declares none, every citation resolves, and the release mapping is complete`; exit 0 |
| population-sensitive neighbour | `python3 -m unittest forensics.tools.tests.test_harden` | `Ran 69 tests in 12.155s`; `OK` |
| population-sensitive neighbour | `python3 -m unittest forensics.tools.tests.test_sigstore_bundle` | `Ran 58 tests in 24.180s`; `OK` |

The last two were run because the new matrix is JSON under `evidence/`, which is
growth in the A11 and A16 frozen populations. Both pass, so no frozen-population
drift was introduced. The whole `forensics/tools` discovery was **not** run: the
brief forbids `unittest discover`, and only the affected named modules were
executed. That is a bounded result, not a claim that the whole suite passes.

## 8. What is not established

* **No certification, no level and no DAL.** The matrix records objective
  satisfaction only, and no row is satisfied.
* **No standard was read.** DO-178C, AC 20-115D, DO-330 and DO-333 were not
  opened; every exact objective identifier and wording is `UNVERIFIED`.
* **No tool qualification.** The instrument register is not a DO-330
  qualification, and FRC-0 admits 0 of 15 candidate provers.
* **No target execution.** Every cited record is `x86_64-unknown-linux-gnu` on
  the development host or in the court container.
* **No independent review.** The matrix, validator, producer and tests share an
  author; the independence record holds 0 external parties.
* **No re-execution.** Every cited gate and record is read as a tracked record;
  this item did not rebuild, re-run a court or re-measure anything.
* **No structural coverage.** MC/DC and object-code coverage are not measured.
* **No system safety assessment.** None exists and no DAL is assigned.
* **No ETP verdict is upgraded.** The matrix cites ETP-T1, ETP-T3, ETP-T4,
  ETP-T5, ETP-T6, ETP-T7, ETP-T9, ETP-T11 and ETP-T15 evidence and changes no
  claim, unsafe site, hazard barrier, consumer family or refinement edge. It
  supplies evidence a verdict may cite; it does not supply a verdict.

## 9. Why the queue row is `PARTIAL`, not `DONE`

The acceptance criterion is the matrix and the explicit statement that objective
satisfaction is not certification. Both exist. The matrix is honest to the point
of recording **zero satisfied objectives** and **12 absent items**, and the
document and machine record agree.

It is not `DONE` because the matrix itself does not support anything: no objective
is satisfied, every exact objective identifier is `UNVERIFIED`, no tool is
qualified, no target was executed, no independent review exists and no
configuration index is complete. The item's own acceptance asks for "the matrix,
and the explicit statement"; it does not ask for the missing items to be supplied.
But a row that reads `DONE` would be read as a completed conformance exercise,
which this is not. `PARTIAL` is the honest state: the matrix exists, the context
is declared, the gaps are named, and the conformance question remains open.

## 10. `NOT_RUN`

* Every reading of DO-178C, AC 20-115D, DO-330 and DO-333.
* Every DO-330 tool qualification.
* Every target-hardware and cross-target execution.
* Every re-execution of a cited record, test, court, build or measurement.
* Every MC/DC and object-code coverage measurement.
* Every system safety assessment and DAL assignment.
* Independent review, `BOUNDARY` and `SEAL`.
* The whole `forensics/tools` discovery.

## 11. Worktree

Added: `docs/DO178C-CONFORMANCE.md`, `evidence/frc8/DO178C-MATRIX.json`,
`evidence/frc8/build_evidence.py`, `evidence/frc8/RECEIPT.md`,
`forensics/tools/do178c_matrix.py`,
`forensics/tools/tests/test_do178c_matrix.py`. Modified: `docs/FRC-TODO.md`
(one row) and `docs/ETP-TODO.md` (one appended paragraph). `AGENTS.md` was not
opened, modified, staged, committed or pushed.
