# The P-256 specification hierarchy and the FRC-0 registers

**FRC-0 · what the reference results prove, what this project proves, and which
prover is admitted.**

Queue: `docs/FRC-TODO.md`, item `FRC-0`.
Programme: `docs/FORMAL-REFINEMENT-CERTIFICATION.md`.
Machine records: `evidence/frc/FRONTIER-GAPS.json`,
`evidence/frc/SPECIFICATION-HIERARCHY.json`, `forensics/frc/TOOLS.json`.
Validator: `forensics/tools/frc_registers.py`.

This document is the normative description of the three FRC-0 registers. It
states what they contain, what each entry means, and what none of them
establishes. It is not a frontier-gap claim of its own: the machine records are
the claims, and this document must name every level, edge, frontier entry, tool
and refusal code they contain, or the validator refuses the drift.

---

## 0. What this item is, and what it is not

FRC-0 does three things, and this is the whole of its result:

1. It records, for each reference result in the programme's section 1, **what
   that result proves, what it assumes, what this project currently proves, and
   the additional theorem that would be a genuine improvement**.
2. It states the **specification hierarchy for the first target**, P-256 field
   and scalar arithmetic, entirely from normative sources, and it records the
   status of every refinement edge.
3. It records an **admission decision for every candidate prover**, with the
   fields that decision is allowed to rest on, and refuses every tool for which
   those fields are absent.

It does **not** prove anything. There is no theorem in this item, no prover run,
no binary, no measurement, and no court. Every external source is marked
`UNVERIFIED` with the method that would settle it, because none was read in the
producing session. Every tool is `REFUSED`, because no admission test was run in
the producing session and two of the tools that were tested earlier fail a
declared requirement. **Zero tools are admitted and zero refinement edges are
discharged.** Those are results, not omissions.

The correct reading of `this_project.state = NONE` is: *this project proves
nothing for this dimension*. The correct reading of `UNVERIFIED` is: *the item
was not checked, and here is how to check it*. Neither reading is a defect in
the product; both are defects in a claim that suppressed them.

---

## 1. The frontier-gap register

`evidence/frc/FRONTIER-GAPS.json` is bound to `base_commit`
`829483c8121381e0a035f6d0cd08613b2755f7f8` (the working-tree head at
production) and declares 15 entries. Every entry has a closed-set
`classification`, non-empty `proves`, `assumes` and `additional_theorem`
fields, a `this_project` block and a `verification` block.

The classifications are:

| classification | meaning |
|---|---|
| `REFERENCE_PROOF` | what the reference's own theorem establishes |
| `REFERENCE_RESIDUAL_RISK` | a gap the reference itself documents |
| `REFERENCE_ENVIRONMENT_ASSUMPTION` | a modelling or platform assumption the reference relies on |
| `PROJECT_GAP` | a gap this project shares with, or inherits from, the reference |
| `DO_178C_OBJECTIVE` | an objective-based assurance item, never a certificate |
| `FRONTIER_DIMENSION` | an axis on which the programme states what exceeding would require |

| id | classification | this project's state |
|---|---|---|
| `FG-S2N-A1` | `REFERENCE_PROOF` | `NONE` |
| `FG-S2N-A2` | `REFERENCE_RESIDUAL_RISK` | `NONE` |
| `FG-S2N-A3` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `BOUNDED_EVIDENCE` |
| `FG-S2N-A4` | `REFERENCE_RESIDUAL_RISK` | `NONE` |
| `FG-S2N-B1` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `NONE` |
| `FG-S2N-B2` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `NONE` |
| `FG-S2N-B3` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `NONE` |
| `FG-S2N-C1` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `NONE` |
| `FG-S2N-D1` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `NONE` |
| `FG-S2N-D2` | `REFERENCE_RESIDUAL_RISK` | `NONE` |
| `FG-S2N-D3` | `PROJECT_GAP` | `NONE` |
| `FG-S2N-REASSEMBLY` | `REFERENCE_ENVIRONMENT_ASSUMPTION` | `NONE` |
| `FG-AWSLC-END-TO-END` | `FRONTIER_DIMENSION` | `NONE` |
| `FG-SEL4-REFINEMENT` | `FRONTIER_DIMENSION` | `NONE` |
| `FG-DO178C-OBJECTIVES` | `DO_178C_OBJECTIVE` | `NONE` |

Fourteen entries record `NONE`: no machine-checked theorem, no
source-to-binary correspondence, no end-to-end chain. One entry,
`FG-S2N-A3`, records `BOUNDED_EVIDENCE`: instrument results exist at named
DSOs, and every one of them says that it is not a physical guarantee and not a
proof about the binary. `BOUNDED_EVIDENCE` is deliberately not called
`ESTABLISHED`, and the validator treats it as proof-bearing only for the
purpose of requiring a readable evidence path.

The s2n-bignum entries are transcribed from the programme's section 1.1, which
records that it read `SOUNDNESS.md` on 2026-11-22. **This item did not re-read
the primary source**, so every such entry is `UNVERIFIED` with the settling
method: re-read `SOUNDNESS.md` at a pinned commit, record the exact clause and
its digest, and record the date. The same rule applies to the AWS-LC, seL4 and
DO-178C entries.

### 1.1 The frontier cannot be exceeded by declaration

`FRC-0` records `beyond_frontier_claims: 0` and gives every entry an explicit
`beyond_frontier: {"claim": false, ...}` block. A future claim to exceed a
reference must set `claim: true`, name **both** the matched property and the
added property, and name a `matched_entry` whose project state is `ESTABLISHED`.
The validator refuses a claim that names only one property
(`FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES`) and refuses a claim whose
matched entry is unresolved or not established
(`FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN`). Matching the frontier is the
precondition for exceeding it; this register does not claim to have matched it.

### 1.2 DO-178C is recorded as objectives, never certification

`FG-DO178C-OBJECTIVES` is the only `DO_178C_OBJECTIVE` entry. It records
`certification_claimed: false` and `objective_satisfaction_only: true`. The
validator refuses an entry that claims certification
(`FR_REFUSED_DO178_CERTIFICATION`), and it refuses this document if it omits the
sentence that objective satisfaction is not certification. Certifying an
airborne system is a separate act with a system safety assessment; satisfying
an objective is not that act.

---

## 2. The specification hierarchy

`evidence/frc/SPECIFICATION-HIERARCHY.json` targets **P-256 field and scalar
arithmetic**: the prime field of the base point, the scalar field modulo the
group order, point arithmetic, scalar multiplication, and ECDSA signing with a
deterministic nonce. Key generation, verification-only paths, other curves, TLS
record protection and every non-arithmetic concern are declared out of scope.

The level identifiers are the **ETP-T3 refinement levels**. FRC-0 instantiates
them for P-256 rather than inventing a second taxonomy. The six levels are:

| id | name | what it constrains |
|---|---|---|
| `LVL-L1` | abstract specification | the functional statement a kernel must satisfy, with no representation |
| `LVL-L2` | executable reference | an implementation readable without the crate |
| `LVL-L3` | Rust implementation | must refine `LVL-L2`, including every unsafe contract on the path |
| `LVL-L4` | ABI contract | the observable behaviour a C caller may rely on |
| `LVL-L5` | machine code | must preserve the `LVL-L4` properties, including any claimed timing discipline |
| `LVL-L6` | consumer composition | the real caller must respect every precondition and boundary |

Each level has `implementation_derived: false` and a non-empty
`normative_sources` list. The sources are named by document, clause and edition;
each carries its own `UNVERIFIED` state and settling method. **No level is
sourced from the implementation**, and the validator refuses a level that is
marked implementation-derived or whose source names an internal source path
(`FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION`). A specification that
restates the implementation inherits the defect it is meant to find.

The anchors are:

| level | normative anchors |
|---|---|
| `LVL-L1` | FIPS 186-4 Appendix D.1.2.3 (Curve P-256) and section 6.4 (ECDSA); NIST SP 800-186; SEC 1 version 2.0 sections 2.4 and 4.1; RFC 6979 section 3.2 |
| `LVL-L2` | FIPS 186-4 section 6.4; RFC 6979 section 3.2; the realisation is the independent reference under `forensics/etp5_crypto/` |
| `LVL-L3` | FIPS 186-4 section 6.4; NIST SP 800-186; the implementation's identifiers are deliberately not named here |
| `LVL-L4` | RFC 5480; the project's declared ABI contract in `docs/ABI_POLICY.md` |
| `LVL-L5` | the System V AMD64 ABI supplement; the pinned compiler channel in `rust-toolchain.toml` |
| `LVL-L6` | RFC 4253; RFC 5656; the declared consumer cohort in `docs/OPENSSH-COHORT.md` |

**Every external anchor is `UNVERIFIED`.** The clause locator is stated from the
programme's transcription or from general knowledge of the standard, and the
settling method names the exact reading that would confirm it: read the named
clause of the named edition, record its exact text, edition and digest, and the
date it was read. A locator that was not read is not evidence; it is a question
with an address.

### 2.1 The edges and their recorded status

The five edges are the ETP-T3 edges, with the same identifiers and the same
statuses. `evidence/etp-t3/REFINEMENT.json` is the authoritative record, and the
validator refuses any disagreement in identity, direction or status
(`FR_REFUSED_HIERARCHY_DRIFT`). This means FRC-0 cannot quietly claim a
refinement the project does not record.

| edge | from → to | status | why |
|---|---|---|---|
| `RFE-1` | `LVL-L1` → `LVL-L2` | `NONE` | the executable reference exists, but no separate abstract-specification artefact does; a differential is not a refinement proof |
| `RFE-2` | `LVL-L2` → `LVL-L3` | `NONE` | 4,326 sampled differential cases are bounded evidence, not a refinement proof |
| `RFE-3` | `LVL-L3` → `LVL-L4` | `PARTIAL` | symbols, versions and layouts are checked; ownership, error-queue ordering and callbacks are not established |
| `RFE-4` | `LVL-L4` → `LVL-L5` | `NONE` | byte-identical builds are a build-identity result, not source-to-binary correspondence |
| `RFE-5` | `LVL-L5` → `LVL-L6` | `PARTIAL` | bounded consumer closures exist; none establishes `Pre(c) ⇒ P`, and both report `safe_compatible` false |

`discharged_edges: 0`. A `DISCHARGED` edge requires a proof object whose kind
is a machine-checked theorem or translation validation and whose artefact is a
file that exists; anything else is refused
(`FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF`). A build identity, a
passing differential court and a reachability closure are all refused as
discharge evidence, because none of them is one.

The hierarchy is not a second taxonomy: the programme's section 5.1 states that
the three proof categories are the section 3 chain, and FRC-0 records a result
against the link it actually discharges. No result moves across a link without
the refinement argument that link requires.

---

## 3. Tool admission

`forensics/frc/TOOLS.json` declares the pinned toolchain (`1.98.1`, from
`rust-toolchain.toml`) and **15 candidate tools or mechanisms**. Admission
requires a pinned version and digest, the theorem class the tool is entitled to
establish, its TCB, a positive control, a negative control, and the rustc range
it actually supports. A tool that cannot process the pinned compiler is not
admitted.

| tool | purpose | admission | reason |
|---|---|---|---|
| `Kani` | Rust source verification | `REFUSED` | runs on bundled nightly-2026-08-21 (rustc 1.100.0-nightly), not the pinned 1.98.1; a result describes a different compilation unit |
| `z3` | SMT backend | `REFUSED` | no Rust front-end and no verified encoding; admitted for nothing |
| `SAW` | specification and symbolic equivalence | `REFUSED` | the reported SAW 1.5 Rust-MIR support and its rustc range were not read, and no admission test was run |
| `Verus` | Rust source verification | `REFUSED` | not installed, not tested |
| `Creusot` | Rust source verification | `REFUSED` | not installed, not tested |
| `Aeneas` | Rust source verification | `REFUSED` | not installed, not tested |
| `Charon` | Rust source verification frontend | `REFUSED` | not installed, not tested |
| `Lean` | source verification and formalisation | `REFUSED` | not installed, not tested |
| `Rocq (Coq)` | source verification and formalisation | `REFUSED` | not installed, not tested |
| `Cryptol` | specification and symbolic equivalence | `REFUSED` | not installed, not tested |
| `HOL Light` | machine-code proof | `REFUSED` | not installed, not tested |
| `Isabelle/HOL` | machine-code proof | `REFUSED` | not installed, not tested |
| `Translation validation` | machine-code proof | `REFUSED` | no implementation selected; not tested |
| `Candle` | independent kernel checking | `REFUSED` | not installed, not tested |
| `Proof-trace checkers` | independent kernel checking | `REFUSED` | not installed, not tested |

**0 admitted, 15 refused.** Two refusals rest on a recorded observation and are
marked `RECORDED_BY_THIS_PROJECT`:

* `Kani` 0.68.0 with CBMC 6.11.0 was installed and its positive and negative
  controls fired (exit 0 with `SUCCESSFUL`; exit 1 with `FAILED` and a
  counterexample). The driver digests are copied from
  `evidence/etp4/VERIFICATION-RECEIPT.md`, and the validator checks that each
  digest occurs in that file (`FR_REFUSED_DIGEST_UNSOURCED`). The refusal is on
  merit: the bundled compiler is not the pinned one.
* `z3` 4.8.12 was installed, its digest is recorded in the same receipt, and it
  was admitted for nothing because it has no Rust front-end.

The other thirteen refusals are **denial by default**: the tool was not
installed and no admission test was run, so nothing about it was measured. A
tool that was not tested is not admitted. Its row records the theorem class it
would be entitled to establish, the reason it is refused, and the settling
method that would change the decision.

### 3.1 The SAW 1.5 / rustc 1.98.1 question

The programme records one unverified claim to settle at FRC-0: SAW 1.5 is
reported to support Rust MIR verification beyond experimental status, with a
supported rustc range that may not include the pinned 1.98.1. **This item did
not settle it.** The release notes were not read and no admission test was run,
so the claim remains `UNVERIFIED`. SAW is therefore `REFUSED`, and a tool that
cannot process the pinned compiler is not admitted. The settling method is:
read the SAW 1.5 release notes at a pinned version, record the supported rustc
range and the tool digest, and run a positive and a negative admission control
against rustc 1.98.1 in the court. Changing the pinned compiler to suit a tool
is a separate decision and is not taken here.

### 3.2 Digests are copied, never invented

A row may carry a digest only with a `recorded_in` path, and the validator
requires the 64-hex digest to occur literally in that record. A malformed
digest, a missing record, or a digest that does not occur in its cited record is
refused (`FR_REFUSED_DIGEST_UNSOURCED`). This is why thirteen rows carry no
digest at all: there is no record to copy one from, and an invented digest would
be worse than an absent one.

---

## 4. What the registers refuse

The validator `forensics/tools/frc_registers.py` implements the following
stable refusal codes. Each has a negative control that fires it, and the test
module refuses a code that appears in one and not the other.

| code | refused when |
|---|---|
| `FR_REFUSED_SCHEMA` | the schema, a field, an identifier or an enum value is invalid |
| `FR_REFUSED_DUPLICATE_KEY` | a JSON object repeats a key at any depth |
| `FR_REFUSED_UNCLASSIFIED_CLAIM` | a frontier entry has no classification, or an edge has no status |
| `FR_REFUSED_UNVERIFIED_WITHOUT_METHOD` | an `UNVERIFIED` block names no settling method |
| `FR_REFUSED_VERIFICATION_WITHOUT_SOURCE` | a non-`UNVERIFIED` block cites no readable witness |
| `FR_REFUSED_PROVEN_WITHOUT_EVIDENCE` | a project state other than `NONE` has no evidence, a cited path is missing, or `ESTABLISHED` has no proof artefact |
| `FR_REFUSED_FRONTIER_WITHOUT_BOTH_PROPERTIES` | a beyond-frontier claim omits the matched or the added property |
| `FR_REFUSED_EXCEEDS_FRONTIER_UNPROVEN` | a beyond-frontier claim's matched entry is unresolved or not `ESTABLISHED` |
| `FR_REFUSED_TOOL_ADMITTED_INCOMPLETE` | an admitted tool lacks a pinned version, digest, theorem class, TCB, control, supported range or support for the pinned compiler |
| `FR_REFUSED_TOOL_REFUSAL_WITHOUT_REASON` | a refused tool states no reason |
| `FR_REFUSED_SPECIFICATION_RESTATES_IMPLEMENTATION` | a level is implementation-derived, or a source or this document names an internal source path |
| `FR_REFUSED_REFINEMENT_DISCHARGED_WITHOUT_PROOF` | a `DISCHARGED` edge has no machine-checked or translation-validation proof artefact |
| `FR_REFUSED_HIERARCHY_DRIFT` | a level or edge disagrees with the ETP-T3 refinement record |
| `FR_REFUSED_DIGEST_UNSOURCED` | a digest is malformed or does not occur in its cited record |
| `FR_REFUSED_DO178_CERTIFICATION` | a DO-178C entry claims certification, or this document omits the distinction |
| `FR_REFUSED_DOCUMENT_DRIFT` | this document does not name a level, edge, entry, tool or code the records contain |
| `FR_REFUSED_USAGE` | the command line is malformed |

`FR_OK` is the success code. `FR_REFUSED_USAGE` is a command-line code, not a
claim code; it exists so that a refusal is never read as a pass through an
exit-status confusion.

---

## 5. Non-claims

* No theorem is proved, no prover is run, no binary is built and no measurement
  is taken by this item.
* A frontier gap that a reference publishes is not a defect in that reference.
  It is a statement of scope, and it is recorded here as one.
* A recorded digest is an identity, not an admission. Two tool digests copied
  from a receipt do not make either tool admitted.
* `BOUNDED_EVIDENCE` is not `ESTABLISHED`. Instrument evidence at a named DSO is
  not a proof about the binary and is not a physical side-channel guarantee.
* `NONE` is not a verdict on the product. It is the state of this project's
  evidence for one dimension, and it is the honest state today.
* No entry claims to match or exceed a frontier. `beyond_frontier_claims` is
  zero, and the validator refuses a claim that names only one property.
* Satisfying DO-178C objectives is not certification, and a matrix is not a
  system safety assessment.
* The validator checks that the registers do not exceed their own evidence. It
  cannot decide whether a clause locator is correct, whether a control is
  sufficient, or whether a tool is genuinely independent.

---

## 6. `NOT_RUN`

* Any admission test: no prover was installed or executed in this session, and
  the two tools with recorded controls were not re-run.
* Any reading of a primary standard. Every external anchor is `UNVERIFIED` with
  its settling method.
* Any machine-checked theorem, any source-to-binary correspondence and any
  refinement discharge.
* Any court, any build, any Rust test and any measurement.
* An independent reviewer (Earned Trust Article 5). The registers, the validator
  and the tests share an author.
* Registration of this document in the ETP-T3 specification population. It is
  written to be independent of the implementation, but registering it would
  change that population's measured size, and that is an ETP-T3 record change
  outside this item's write scope. The FRC validator enforces the Article 6 rule
  for this document directly.
