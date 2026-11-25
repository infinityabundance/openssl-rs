# DO-178C objective conformance (FRC-8) — a matrix, not a certificate

**FRC-8 · what the programme's section 6 objectives can and cannot show for one
declared system context.**

Queue: `docs/FRC-TODO.md`, item `FRC-8`.
Programme: `docs/FORMAL-REFINEMENT-CERTIFICATION.md` (section 6).
Machine record: `evidence/frc8/DO178C-MATRIX.json`.
Validator: `forensics/tools/do178c_matrix.py`.
Receipt: `evidence/frc8/RECEIPT.md`.

This document is the normative description of the FRC-8 matrix. It declares the
system context, states each objective's substance, records the evidence that
exists today, compares the independence the objective requires with the
independence actually held, names every missing item, and states plainly what the
matrix does not establish. It is not a certification statement and it assigns no
level.

The machine record is the claim. This document must name every objective,
context, exclusion, missing item and refusal code the record contains, or the
validator refuses the drift.

---

## 0. What this item is, and what it is not

FRC-8 produces an objective-by-objective matrix. Nothing more. In the declared
context it records:

- **14 objectives** from the programme's section 6: **0** `SATISFIED_WITH_EVIDENCE`,
  **5** `PARTIAL`, **7** `NOT_SATISFIED` and **2** `UNVERIFIED`;
- **12 missing items** that must exist before the matrix could support anything;
- **every exact DO-178C objective identifier and wording marked `UNVERIFIED`**,
  because DO-178C, AC 20-115D, DO-330 and DO-333 were not read in the producing
  session;
- **no certification, no DO-178C level and no development assurance level**.

A row marked `PARTIAL` says only that some of the objective's substance has
supporting evidence in this repository. A row marked `NOT_SATISFIED` says that
the substance is not met today. A row marked `UNVERIFIED` says that even the
applicability or wording was not read. None of the four statuses is a
certification result.

---

## 1. The declared system context

The declaration is a scope choice, not a compliance claim. It narrows the matrix
to the only context the existing evidence can describe. It does not assert that
this context is sufficient for any certification basis.

**`CTX-FRC8-NONAIRBORNE-LIBRARY`**, verbatim from the machine record:

> The software item is the libcrypto-compatible shared library built from this
> repository for the x86_64-unknown-linux-gnu target in the release profile,
> considered as a standalone library under its declared C ABI on the development
> host and in the court container. The context assigns no aircraft, engine or
> spacecraft function, no system safety assessment, no development assurance
> level and no target hardware.

**This declaration is a scope choice, not a compliance claim.** Every record the
matrix cites was produced on the development host or in the court container for
`x86_64-unknown-linux-gnu`; nothing in this repository is bound to an airborne
target, an airborne environment or a development assurance level.

The context excludes each of the following, and the validator refuses a
declaration that omits or re-categories one:

| exclusion id | category | what is excluded |
|---|---|---|
| `XCE-TARGET-HARDWARE` | target hardware | no airborne, embedded or production target hardware; every cited record is from the development host or the court container |
| `XCE-AIRBORNE` | airborne/spacecraft applicability | no aircraft, engine or spacecraft installation, environment or lifecycle; DO-178C is a checklist here, not an invoked certification basis |
| `XCE-DAL` | DAL | no development assurance level is assigned, proposed or claimed, including DAL A, B, C, D and E |
| `XCE-CERTIFICATION` | certification consequence | no airworthiness finding, approval, compliance statement or system-level safety result follows, and none is claimed |
| `XCE-WCET` | worst-case execution | bounded execution, deadline analysis and worst-case execution time are excluded; constant time is not WCET |
| `XCE-ENVIRONMENT` | environmental qualification | temperature, vibration, radiation and electromagnetic effects are excluded |

A context that excluded less would claim evidence this repository does not hold.
The narrow context is the honest one, and it is why the matrix can describe the
present state without implying an airborne role that no record supports.

---

## 2. The objective matrix

Statuses apply to **the substance as the programme's section 6 states it**, not
to an unread normative wording. The exact DO-178C objective identifiers and
wording are recorded separately per row as `UNVERIFIED`, with the method that
would settle them: read the objective tables at the published revision, record
the objective identifiers, exact wording and independence attributes, and update
the row with the reading and its date.

Every row's held independence is `SAME_PARTY_ONLY`. The independence record
cited by every row is `evidence/etp-t15/INDEPENDENCE.json`: 50 recorded
assignments, all 50 adjudicated by the author's party, 0 declared parties and 0
external parties. The one asserted independence was refused. The validator
compares each row's independence numbers with that record and refuses a number
that disagrees.

| id | area | status | evidence today | required independence | held independence | blocked by |
|---|---|---|---|---|---|---|
| `DO8-PLANNING` | planning | `NOT_SATISFIED` | programme section 6; FRC queue | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-PLANNING`, `MI-SYSTEM-SAFETY-ASSESSMENT` |
| `DO8-HLR` | high-level requirements | `PARTIAL` | ETP-T1 graph: 21 requirement nodes, 0 specification nodes; traceability doc | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-REQUIREMENT-BASELINE`, `MI-SYSTEM-SAFETY-ASSESSMENT` |
| `DO8-LLR` | low-level requirements | `NOT_SATISFIED` | ETP-T1: 78 obligation nodes; ETP-T11: 0/78 satisfied | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-REQUIREMENT-BASELINE` |
| `DO8-ARCH` | architecture | `PARTIAL` | ETP-T3: 0 discharged edges; ETP-T4: 51,703 boundary-unconfined sites | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-FORMAL-METHODS-JUSTIFICATION`, `MI-INDEPENDENT-REVIEW` |
| `DO8-REQVER` | requirements-based verification | `NOT_SATISFIED` | ETP-T11: 0 satisfied, 59 not run, 19 refused; ETP-T5 differential `AGREEMENT` | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-REQUIREMENTS-BASED-TESTS`, `MI-REQUIREMENT-BASELINE` |
| `DO8-COVERAGE` | structural coverage | `NOT_SATISFIED` | traceability doc: MC/DC not measured and not claimed | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-STRUCTURAL-COVERAGE` |
| `DO8-ROBUST` | robustness | `PARTIAL` | ETP-T7: 7 findings, 0 repaired, 1 HIGH; failure-atomicity and parser docs | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-SYSTEM-SAFETY-ASSESSMENT`, `MI-TARGET-EXECUTION` |
| `DO8-CM` | configuration management | `PARTIAL` | ETP-2: `ALL_IDENTICAL` at one host/target; ETP-T6 toolchain digests; ETP-T9: 118/231 uncertifiable | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-CONFIGURATION-INDEX`, `MI-TARGET-EXECUTION` |
| `DO8-QA` | quality assurance | `NOT_SATISFIED` | independence record 50/50 same-party, 0 external; release-gate refusals | `INDEPENDENT_REQUIRED` | `SAME_PARTY_ONLY` | `MI-INDEPENDENT-REVIEW` |
| `DO8-TOOL` | tool qualification | `NOT_SATISFIED` | instrument register (not DO-330); FRC-0: 0 of 15 tools admitted | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-TOOL-QUALIFICATION` |
| `DO8-FORMAL` | formal methods | `NOT_SATISFIED` | ETP-4: no prover proof; ETP-T3: no discharged edge; FRC-0: 0 admitted | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-FORMAL-METHODS-JUSTIFICATION`, `MI-TOOL-QUALIFICATION` |
| `DO8-CHANGE` | change control | `PARTIAL` | ETP-T11: 6 change sets, status `REFUSED`; ETP-T9: 118/231 uncertifiable | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-CONFIGURATION-INDEX`, `MI-PROBLEM-REPORTING` |
| `DO8-TARGET-VALIDATION` | target-hardware validation | `UNVERIFIED` | one target, `x86_64-unknown-linux-gnu`; no cross-target claim | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-TARGET-EXECUTION`, `MI-TARGET-TIMING` |
| `DO8-BOUNDED-EXECUTION` | bounded execution and WCET | `UNVERIFIED` | venue has no PMU; timing rows are `SCOPED_OBSERVATION` | `UNVERIFIED` | `SAME_PARTY_ONLY` | `MI-TARGET-TIMING` |

The two `UNVERIFIED` rows are `DO8-TARGET-VALIDATION` and
`DO8-BOUNDED-EXECUTION`. They are not `NOT_SATISFIED` because their
applicability and normative wording were not read: the programme names
target-hardware validation and bounded execution after its assurance table, but
this session did not establish which objective they instantiate. Recording them
as unmet would have been a stronger claim than the reading supports.

### 2.1 What each status means here

| status | meaning in this matrix |
|---|---|
| `SATISFIED_WITH_EVIDENCE` | the objective's substance is met in the declared context and a real record or test is cited; **no row has this status** |
| `PARTIAL` | some of the substance has supporting evidence and named obligations remain |
| `NOT_SATISFIED` | the substance is not met today, and the record cited shows why |
| `UNVERIFIED` | the objective's applicability or wording was not read, and the settling method is named |

`PARTIAL` is not a fraction and is not averaged with anything. It is a verdict
with named open items, in the same sense as `docs/ETP-CLAIM-ALGEBRA.md` section
2.2.

---

## 3. The missing items

Twelve items must exist before the matrix could support anything. Each is
registered in the machine record with its reason and its settling method, and
each is named as a blocker by at least one objective.

| id | item | why it is required | what would settle it |
|---|---|---|---|
| `MI-PLANNING` | assurance, development and verification plans | the programme states a queue and gates, not a plan for a configuration | write and review a plan for the declared context, bound to a date and reviewer |
| `MI-REQUIREMENT-BASELINE` | HLR and LLR with acceptance criteria | ETP-T1 records 21 requirement nodes and 0 specification nodes | establish and register a negotiated baseline from normative sources |
| `MI-REQUIREMENTS-BASED-TESTS` | verification cases derived from requirements | ETP-T11: 0 satisfied, 59 not run, 19 refused of 78 | derive a case per requirement and record the trace to its result |
| `MI-STRUCTURAL-COVERAGE` | MC/DC and object-code coverage | no coverage record exists; MC/DC is not measured and not claimed | name the instrument, decision population and measured result at the artefact |
| `MI-SYSTEM-SAFETY-ASSESSMENT` | system safety assessment and the DAL it assigns | no assessment exists and no DAL is assigned | declare an airborne context, assess it and record the level; this matrix does not |
| `MI-TOOL-QUALIFICATION` | DO-330 assessment for depended-on tools | the instrument register is not a DO-330 qualification; FRC-0 admits 0 tools | record intended use, qualification basis, controls and a DO-330 assessment |
| `MI-TARGET-EXECUTION` | verification on the declared target hardware | every cited record is `x86_64-unknown-linux-gnu` on the host or court | declare the target, execute there and bind results to the target digest |
| `MI-CONFIGURATION-INDEX` | complete configuration index | ETP-2 covers one host/target; ETP-T9 marks 118 of 231 items uncertifiable | index every input and artefact with a digest, recording gaps as gaps |
| `MI-INDEPENDENT-REVIEW` | independent review in a distinct trust domain | 50 of 50 assignments are same-party; 0 external parties | name an external party with its own infrastructure and record the review |
| `MI-FORMAL-METHODS-JUSTIFICATION` | DO-333 justification and proof artefacts | no proof artefact exists; 0 refinement edges discharged | write the justification, state assumptions and TCB, bind proofs to identities |
| `MI-TARGET-TIMING` | bounded execution, deadline analysis, WCET | no execution-time bound exists; constant time is not WCET | declare the budget, measure on the target and record uncovered paths |
| `MI-PROBLEM-REPORTING` | problem reporting under a governing plan | ETP-T11 change control is `REFUSED`; no DO-178C problem-report process exists | establish the process and bind each change to its impact analysis |

Missing items are not softened into "future work". They are requirements of the
matrix, and their absence is the matrix's principal result.

---

## 4. Independence: required versus held

The independence record `evidence/etp-t15/INDEPENDENCE.json` is the authority
for what this project actually holds:

- **50** recorded assignments;
- **50** with an adjudicator from the author's party;
- **0** declared parties;
- **0** external parties;
- **1** asserted independence, which was refused;
- **1** retained dissent, preserved unchanged.

Every objective row therefore records `SAME_PARTY_ONLY`. For the thirteen rows
whose required independence is `UNVERIFIED`, the matrix does not claim that the
requirement is met or unmet: it records that the requirement was not read. For
`DO8-QA`, the programme's own section 6 names independent checks, so the required
independence is `INDEPENDENT_REQUIRED`; the held independence is same-party, and
the row is `NOT_SATISFIED`.

The validator refuses a row that claims `INDEPENDENT` without a declared distinct
trust domain, an external party and a declaration that it is distinct from the
author. It also refuses a `SATISFIED_WITH_EVIDENCE` row whose required
independence is `UNVERIFIED` or is held as `SAME_PARTY_ONLY`. This is why no row
can be satisfied by an unread requirement or by the author checking the author.

---

## 5. The non-claim

**Objective satisfaction is not certification.** This matrix establishes only
which of the programme's section 6 objectives are unmet, partly met or
unverified in the declared context. It records no certification, no DO-178C
level and no development assurance level, and no row may be cited as a
certification result.

In particular the matrix does **not** establish:

- certification, an airworthiness finding or an approval of any kind;
- a DO-178C level or a development assurance level (DAL);
- that the cited evidence is sufficient for the objective it is attached to;
- that any objective identifier or wording matches DO-178C: every exact
  identifier is `UNVERIFIED` because the standard was not read;
- that the declared context is sufficient for any certification basis.

A matrix with unmet objectives establishes only which objectives are unmet. It is
not a partial certificate, a provisional approval or a compliance finding.

---

## 6. What the matrix refuses

`forensics/tools/do178c_matrix.py` implements the following stable refusal codes.
Each has a negative control that fires it, and the test module refuses a code
that appears in one and not the other.

| code | refused when |
|---|---|
| `DO_REFUSED_SCHEMA` | the schema, a field, an identifier or a status is invalid |
| `DO_REFUSED_DUPLICATE_KEY` | a JSON object repeats a key at any depth |
| `DO_REFUSED_CONTEXT_ABSENT` | the system context is missing, empty, omits a required exclusion, or does not say it is a scope choice and not a compliance claim |
| `DO_REFUSED_STATUS_WITHOUT_EVIDENCE` | a non-`UNVERIFIED` row cites no evidence, or a `SATISFIED_WITH_EVIDENCE` row cites no record or test naming its check |
| `DO_REFUSED_EVIDENCE_ABSENT` | an evidence item names a path that is not a file |
| `DO_REFUSED_UNVERIFIED_WITHOUT_METHOD` | an `UNVERIFIED` status, required-independence field or identifier field names no settling method |
| `DO_REFUSED_INDEPENDENCE_UNSUPPORTED` | independent review is claimed without a distinct trust domain or external party; a satisfied row's required independence is unread or same-party; or the party counts disagree with the independence record |
| `DO_REFUSED_CERTIFICATION_CLAIM` | the matrix, a row or this document claims certification, a DAL or an assurance level |
| `DO_REFUSED_MISSING_ITEM_OMITTED` | a required missing item is absent; an unmet objective names no missing item; or a named item is unregistered or referenced by no objective |
| `DO_REFUSED_MISSING_ITEM_WITHOUT_METHOD` | a missing item states no reason or no settling method |
| `DO_REFUSED_NON_CLAIM_ABSENT` | the matrix or this document omits that objective satisfaction is not certification |
| `DO_REFUSED_DOCUMENT_DRIFT` | this document does not name an objective, context, exclusion, missing item or code the record contains |
| `DO_REFUSED_USAGE` | the command line is malformed |

`DO_OK` is the success code. `DO_REFUSED_USAGE` is a command-line code, not a
claim code; it exists so that a refusal is not read as a pass through an
exit-status confusion.

---

## 7. Non-claims

- No objective is `SATISFIED_WITH_EVIDENCE`. The matrix records that fact rather
  than promoting a `PARTIAL` row to make the table look stronger.
- Every exact DO-178C objective identifier and wording is `UNVERIFIED`. The
  statuses describe the programme's section 6 substance, not the unread standard.
- A `PARTIAL` row is not a fraction of satisfaction and is not averaged with
  another row. No combination of rows produces a level.
- The system context is a scope choice. It does not establish that a narrower
  context is acceptable for any certification basis, and it does not borrow
  authority from a wider one.
- A printed record is not an executed test. The matrix cites what the repository
  holds; it did not re-run any record, build, court or measurement.
- The validator checks that the matrix does not exceed its own evidence. It
  cannot decide whether a cited record supports its row, whether an objective
  identifier is correct, or whether a gap could be closed.
- Satisfying DO-178C objectives is not certification. This matrix does not even
  satisfy them: 7 are `NOT_SATISFIED` and 2 are `UNVERIFIED`.

---

## 8. `NOT_RUN`

- Any reading of DO-178C, AC 20-115D, DO-330 or DO-333. Every exact objective
  identifier is `UNVERIFIED` with its settling method.
- Any re-execution of a cited record, test, differential court, timing run or
  build. The matrix reads tracked records; it does not produce new ones.
- Any target-hardware execution, cross-target execution or environmental test.
- Any DO-330 tool qualification.
- Any independent review. The matrix, validator, producer and tests share an
  author, and the independence record holds 0 external parties.
- Any system safety assessment or DAL assignment.
- Any MC/DC or object-code coverage measurement.
- Any certification activity.

---

## 9. Reproducing the check

```sh
python3 forensics/tools/do178c_matrix.py check
python3 forensics/tools/do178c_matrix.py inventory
python3 evidence/frc8/build_evidence.py --check
python3 -m unittest forensics.tools.tests.test_do178c_matrix
```

The validator reads `evidence/frc8/DO178C-MATRIX.json`,
`docs/DO178C-CONFORMANCE.md` and `evidence/etp-t15/INDEPENDENCE.json`, and no
other input. It writes no timestamp. The producer writes the matrix with sorted
keys and a trailing newline, so two runs over the same tree reproduce the same
bytes.
