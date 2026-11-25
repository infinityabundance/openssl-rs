# FRC-0 receipt — the frontier-gap register, the P-256 hierarchy, and tool admission

## 1. Identity and venue

| field | value |
|---|---|
| item | FRC-0 of `docs/FRC-TODO.md` |
| programme | `docs/FORMAL-REFINEMENT-CERTIFICATION.md` |
| branch | `staging` |
| base commit (working-tree head at production) | `829483c8121381e0a035f6d0cd08613b2755f7f8` |
| orchestrator | commits and pushes; this agent did not |
| venue | the development host, Python 3 only; **no build, no court, no Rust, no measurement** |
| `free -g` before the work | `Mem: 45 11 2 0 31 33` (available **33 GiB**); `Swap: 45 23 22` |
| heavy commands | none. The item's own brief forbids a court run and a build, and no command compiled anything. |

The item is a documentation-and-records task. The only executable work is the
Python validator, its tests, and the deterministic producer.

## 2. What was delivered

| path | role |
|---|---|
| `docs/SPECIFICATION-HIERARCHY.md` | the normative document: the P-256 hierarchy, the frontier-gap table, the admission table, the refusal table, non-claims, `NOT_RUN` |
| `evidence/frc/FRONTIER-GAPS.json` | 15 classified frontier entries with `this_project` state and a settling method for every `UNVERIFIED` item |
| `evidence/frc/SPECIFICATION-HIERARCHY.json` | the machine projection of the normative document: six levels, five edges, normative anchors |
| `forensics/frc/TOOLS.json` | 15 candidate tools, each with an admission decision and the fields that decision may rest on |
| `forensics/tools/frc_registers.py` | the validator: 17 stable refusal codes, strict JSON, document synchronisation, ETP-T3 drift check |
| `forensics/tools/tests/test_frc_registers.py` | 37 controls: one firing control per refusal code, three non-vacuity controls, producer determinism, document sync, CLI exit codes |
| `evidence/frc/build_evidence.py` | the deterministic producer of the three records |
| `docs/FRC-TODO.md` | the FRC-0 row changed from `TODO` to `PARTIAL`, with the reason |
| `docs/ETP-TODO.md` | section K gains an FRC-0 status paragraph naming the ETP evidence the registers cite and stating that no ETP verdict is upgraded |
| `evidence/frc/RECEIPT.md` | this file |

The `SPECIFICATION-HIERARCHY.json` record is **not an additional claim**. It is
the machine form of the normative document, and it exists so that the document
can be checked: the validator refuses a level, edge, entry, tool or refusal code
that appears in one and not the other. The document remains the normative
artefact the acceptance names.

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `docs/SPECIFICATION-HIERARCHY.md` | `87bfdd0e14acd6dbee927cf046dfdb808e9ea1b797ea506d80c9d66f50bbe6ba` |
| `evidence/frc/FRONTIER-GAPS.json` | `09504b236d02c83f7f37df968ab07d892bfeeecc95fe216f2b1b4d96c78ca737` |
| `evidence/frc/SPECIFICATION-HIERARCHY.json` | `d081562de0d8596ef6cc8e08f846b13f9b70148d03c2be78b6bcf4b1cd0ae437` |
| `forensics/frc/TOOLS.json` | `d83879db28ce168d00a141d83f3cf82d427bb58f5e560c675876805ba0520f3b` |
| `forensics/tools/frc_registers.py` | `456dbba0ba882959c10669d0ef351be71467339471461d2bb3928da7755467d6` |
| `forensics/tools/tests/test_frc_registers.py` | `0c10e7786c6c55149423f5146e7778ed6fef94dfc7d6d795554c32f1a5d97a99` |
| `evidence/frc/build_evidence.py` | `56f39187b3a95f1fe6b52314b2973c8fc4588cb59095336a9fe72bb0b7f320a3` |

## 3. The register's actual result

**No prover is admitted. No refinement edge is discharged. Fourteen of fifteen
frontier dimensions record `this_project.state = NONE`.** That is the result,
and the validator reproduces it: `frontier_entries=15 frontier_classified=15
frontier_project_none=14 levels=6 edges=5 edges_discharged=0 edges_none=3
edges_partial=2 tools=15 tools_admitted=0 tools_refused=15 tools_unverified=13
refusal_codes=17`.

### 3.1 Frontier gaps

Every entry records what the reference proves, what it assumes, what this
project proves, and the additional theorem that would be a genuine improvement.
The one non-`NONE` entry is `FG-S2N-A3` at `BOUNDED_EVIDENCE`: instrument
results exist at named DSOs and each states that it is not a physical guarantee
and not a proof about the binary. `BOUNDED_EVIDENCE` is not `ESTABLISHED`.

`FG-S2N-D3` is recorded as a `PROJECT_GAP` and is also this project's own gap:
ETP-T3 records no discharged edge and ETP-T6 records no source-to-binary
correspondence. The `FG-DO178C-OBJECTIVES` entry records
`certification_claimed: false` and `objective_satisfaction_only: true`; the
validator refuses an entry that claims certification.

### 3.2 Specification hierarchy

The six levels are the ETP-T3 levels, instantiated for P-256 field and scalar
arithmetic, not a second taxonomy. The five edges are `RFE-1` … `RFE-5` and
carry exactly the statuses in `evidence/etp-t3/REFINEMENT.json`:
`RFE-1 NONE`, `RFE-2 NONE`, `RFE-3 PARTIAL`, `RFE-4 NONE`, `RFE-5 PARTIAL`.
The validator reads that record and refuses any disagreement in identity,
direction or status (`FR_REFUSED_HIERARCHY_DRIFT`), so this item cannot claim a
refinement the project does not record.

Every normative anchor is `UNVERIFIED`. The anchors are FIPS 186-4 Appendix
D.1.2.3 and section 6.4, NIST SP 800-186, SEC 1 version 2.0 sections 2.4 and
4.1, RFC 6979 section 3.2, RFC 5480, the System V AMD64 ABI supplement,
`rust-toolchain.toml`, RFC 4253, RFC 5656 and the project's declared contract
documents. **None was read in the producing session.** A locator is stated so
the reading is checkable; the settling method is "read the named clause of the
named edition, record its exact text, edition and digest, and the date it was
read."

### 3.3 Tool admission

Fifteen tools or mechanisms are recorded. **None is admitted.**

| tool | admission | reason class |
|---|---|---|
| `Kani` | `REFUSED` | does not support the pinned rustc `1.98.1`; runs its bundled `nightly-2026-08-21` (`rustc 1.100.0-nightly`) |
| `z3` | `REFUSED` | no Rust front-end and no verified encoding; admitted for nothing |
| `SAW` | `REFUSED` | the reported 1.5 Rust-MIR support and its rustc range were not read; no admission test run |
| `Verus`, `Creusot`, `Aeneas`, `Charon`, `Lean`, `Rocq (Coq)`, `Cryptol`, `HOL Light`, `Isabelle/HOL`, `Translation validation`, `Candle`, `Proof-trace checkers` | `REFUSED` | not installed, not tested; denial by default |

Two refusals rest on a recorded observation, not on absence: Kani's positive and
negative controls fired and its driver digests are in
`evidence/etp4/VERIFICATION-RECEIPT.md`; z3's version and digest are in the same
record. The validator requires each recorded digest to occur literally in the
record cited for it (`FR_REFUSED_DIGEST_UNSOURCED`), which is why thirteen rows
carry no digest at all.

**The SAW 1.5 / rustc 1.98.1 question is recorded, not resolved.** The release
notes were not read and no admission test was run, so the reported support is
`UNVERIFIED`. SAW is refused. Changing the pinned compiler to suit a tool is a
separate decision and was not taken.

## 4. What the validator checks, and the control that proves each check fires

`forensics/tools/frc_registers.py` implements 17 stable refusal codes. Each has
a negative control in `forensics/tools/tests/test_frc_registers.py` that
corrupts one field of the committed record and observes that exact code:

| code | control corruption | test |
|---|---|---|
| `FR_REFUSED_SCHEMA` | the frontier schema is replaced | `test_schema` |
| `FR_REFUSED_DUPLICATE_KEY` | a JSON object repeats a key | `test_duplicate_key` |
| `FR_REFUSED_UNCLASSIFIED_CLAIM` | an entry's classification is replaced | `test_unclassified_claim` |
| `FR_REFUSED_UNVERIFIED_WITHOUT_METHOD` | an `UNVERIFIED` block loses its settling method | `test_unverified_without_method` |
| `FR_REFUSED_VERIFICATION_WITHOUT_SOURCE` | a recorded block cites an absent witness | `test_verification_without_source` |
| `FR_REFUSED_PROVEN_WITHOUT_EVIDENCE` | `BOUNDED_EVIDENCE` cites an absent path | `test_proven_without_evidence` |
| `FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES` | a beyond-frontier claim omits the added property | `test_frontier_without_both_properties` |
| `FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN` | a claim's matched entry is `NONE` | `test_exceeds_frontier_unproven` |
| `FR_REFUSED_TOOL_ADMITTED_INCOMPLETE` | Kani is marked `ADMITTED` | `test_tool_admitted_incomplete` |
| `FR_REFUSED_TOOL_REFUSAL_WITHOUT_REASON` | a refusal loses its reason | `test_tool_refusal_without_reason` |
| `FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION` | a level is marked implementation-derived | `test_specification_restates_implementation` |
| `FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF` | an edge is `DISCHARGED` with no proof | `test_refinement_discharged_without_proof` |
| `FR_REFUSED_HIERARCHY_DRIFT` | an edge status is changed against ETP-T3 | `test_hierarchy_drift` |
| `FR_REFUSED_DIGEST_UNSOURCED` | a digest is replaced with zeros | `test_digest_unsourced` |
| `FR_REFUSED_DO178_CERTIFICATION` | a DO-178C entry claims certification | `test_do178_certification` |
| `FR_REFUSED_DOCUMENT_DRIFT` | `RFE-3` is removed from the document | `test_document_drift` |
| `FR_REFUSED_USAGE` | no subcommand is given | `test_usage` |

The coverage test `test_every_declared_code_has_a_firing_control` asserts that
the control set equals `REFUSALS` and that every control fires. Three
**non-vacuity** controls show that the rules can accept: a complete admitted
tool is accepted, a discharged edge with a machine-checked proof artefact is
accepted, and a beyond-frontier claim whose matched entry is `ESTABLISHED` is
accepted. **None of the three describes this project's state**; they establish
that the decision procedures are not refusal-only.

## 5. Gates actually run

| gate | command | result |
|---|---|---|
| memory | `free -g` | `Mem: 45 11 2 0 31 33` (available 33 GiB); `Swap: 45 23 22` |
| focused controls | `python3 -m unittest forensics.tools.tests.test_frc_registers` | `Ran 37 tests in 0.269s`; `OK` |
| validator | `python3 forensics/tools/frc_registers.py check` | `frc: frontier=15 levels=6 edges=5 tools=15 admitted=0 refused=15 unverified=13 codes=FR_OK`; exit 0 |
| producer, two runs and the committed bytes | `python3 evidence/frc/build_evidence.py --out <tmp1>` and `--out <tmp2>`, then byte comparison | three records identical to each other and to the committed bytes |
| producer self-check | `python3 evidence/frc/build_evidence.py --check` | exit 0 |
| JSON well-formedness | `python3 -m json.tool` on all three records | `json.tool ok` |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; exit 0 |
| documentation consistency | `python3 forensics/tools/docs_consistency.py` | `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; exit 0 (the named Phase-7 exemption printed) |
| earned-trust constitution | `python3 forensics/tools/earned_trust.py check` | `ok: every article is enforced or declares none, every citation resolves, and the release mapping is complete`; exit 0 |
| population-sensitive neighbours | `python3 -m unittest forensics.tools.tests.test_harden` | `Ran 69 tests`; `OK` |
| population-sensitive neighbours | `python3 -m unittest forensics.tools.tests.test_sigstore_bundle` | `Ran 58 tests`; `OK` |

The last two were run because this item adds JSON records under `evidence/`,
which are members of the A11 and A16 frozen populations. Both pass, so no
frozen-population drift was introduced. The whole `forensics/tools` discovery
was **not** run: the brief forbids `unittest discover`, and only the affected
named modules were executed. That is a bounded result, not a claim that the
whole suite passes.

## 6. What is not established

* **No proof.** There is no theorem, no machine-checked obligation and no
  refinement discharge. A model proof would not be a proof about the binary
  anyway; this item has neither.
* **No admission test.** Kani and z3 were not re-run, and the thirteen other
  tools were not installed. Their refusals are merit-based for Kani and z3, and
  denial-by-default for the rest. A tool not tested is not admitted.
* **No primary standard was read.** Every external anchor is `UNVERIFIED` with
  a settling method. A locator is not evidence.
* **The SAW question is open.** The reported SAW 1.5 Rust-MIR support and its
  supported rustc range remain `UNVERIFIED`.
* **No binary and no court.** Nothing here is bound to a compiled artefact, and
  no timing or memory result is claimed.
* **No independent review** (Earned Trust Article 5). The registers, validator
  and tests share an author.
* **No ETP verdict is upgraded.** The registers cite ETP-T3, ETP-T4, ETP-T5,
  ETP-T6 and ETP-T7 evidence and change no verdict; the refinement edges remain
  the three `NONE` and two `PARTIAL` that ETP-T3 records.
* **The document is not in the ETP-T3 specification population.** Registering it
  would change that population's measured size, and that is an ETP-T3 record
  change outside this item's write scope. The FRC validator enforces the
  Article 6 rule for it directly; the document names no implementation source
  path.

## 7. Why the queue row is `PARTIAL`, not `DONE`

The three acceptance artefacts exist, every claim is classified, and every
unverified item is marked `UNVERIFIED` with a settling method. What the item
also asks for, and this session did not do, is **reading the release notes and
running an admission test** to resolve the SAW 1.5 / rustc 1.98.1 question.
That requires installing and executing a tool against the pinned compiler,
which the brief excludes ("no court run, no build"). The honest state is
`PARTIAL`: the register is complete, the empirical admission is not.

## 8. `NOT_RUN`

* Every admission test and every tool execution.
* Every reading of a primary standard.
* Any machine-checked theorem, translation validation, source-to-binary
  correspondence or refinement discharge.
* Any court, build, Rust test, sanitizer, timing measurement or binary timing
  result.
* Independent review, `BOUNDARY` and `SEAL`.
* The whole `forensics/tools` discovery.

## 9. Worktree

Added: `docs/SPECIFICATION-HIERARCHY.md`, `evidence/frc/` (producer, two
records, this receipt), `forensics/frc/TOOLS.json`,
`forensics/tools/frc_registers.py`,
`forensics/tools/tests/test_frc_registers.py`. Modified: `docs/FRC-TODO.md`
(one row) and `docs/ETP-TODO.md` (one appended paragraph). `AGENTS.md` was not
opened, modified, staged, committed or pushed.
