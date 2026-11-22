# Refinement architecture (ETP-T3)

Status: **normative for the refinement chain**. This document states the six
levels, the five edges between them, the obligation each edge carries, who
discharges it, the artefact that records the discharge, the invalidation rule,
what the edge does **not** establish, and the current status of each edge. It
also states the mechanical rule against implementation-shaped specifications and
binds every level and edge into the ETP-T1 graph.

The normative statement of the underlying chain is
`docs/FORMAL-REFINEMENT-CERTIFICATION.md` §3. This document does not replace it:
it makes the chain a typed graph with a discharge status per edge.

---

## 1. The levels

| id | rank | level | what it is | artefact population |
|---|---:|---|---|---|
| `LVL-L1` | 1 | abstract specification | the normative statement of an operation and its properties, independent of any implementation | the RFC, FIPS publication or project constitution quoted by a requirement |
| `LVL-L2` | 2 | executable reference | an independently written executable implementation of the abstract specification | a reference program and its conformance run |
| `LVL-L3` | 3 | Rust implementation | the crate under `src/` | the tracked `src/` tree at the candidate |
| `LVL-L4` | 4 | ABI contract | the observable C surface: symbols and versions, `repr(C)` layouts, ownership, error queue, callback semantics | `docs/ABI_POLICY.md`, `docs/OWNERSHIP_MODEL.md`, `docs/PARITY_MODEL.md`, `artifacts/phase2/libcrypto.ld` |
| `LVL-L5` | 5 | machine code | the exact compiled artefact deployed to a consumer | the DSO digests recorded by `evidence/etp2/reproducibility.json` |
| `LVL-L6` | 6 | consumer composition | the loaded DSO in a real consumer, with every reachable call site's precondition | `evidence/closure-curl-049.json`, `evidence/closure-ssh-b85c.json`, `evidence/etp5/REFUSALS.json` |

Two levels are **populated** (`L1`, `L3`), one is **identity-only** (`L5`: the
artefact digest is recorded, but no correspondence to the source is argued), and
three are **partial or absent** (`L2` absent, `L4` partial, `L6` partial).

---

## 2. The edges

Each edge is a separate claim with its own evidence, trust base and invalidation
rule. No later edge inherits an earlier edge's result.

| edge | from → to | obligation | discharged by | discharge artefact | current status |
|---|---|---|---|---|---|
| `RFE-1` | L1 → L2 | the reference implements every normative statement of the abstract specification, for the declared input population, and is independent of the Rust implementation | ETP-T5 / FRC-1 | none | **NONE** |
| `RFE-2` | L2 → L3 | the Rust implementation agrees with the reference at the declared interface, including failure behaviour, over a frozen population | ETP-T5 differential | none | **NONE** |
| `RFE-3` | L3 → L4 | the observable C surface matches the contract: symbols and versions, layouts, ownership, error queue, callbacks | ABI symbol, layout and version-script checks | `ART-FILE-ABI-LAYOUT` (`artifacts/phase2/libcrypto.ld`) | **PARTIAL** |
| `RFE-4` | L4 → L5 | the exact compiled artefact implements the contract and preserves the verified source properties, including the reassembly question | ETP-T6 / FRC-4 | none | **NONE** |
| `RFE-5` | L5 → L6 | ∀ call site `c` reachable in the loaded DSO: `Pre(c) ⇒ P`, and `Q` satisfies the next consumer | consumer reachability closure | `ART-CURL-DSO-FD25` (the curl closure's admitted DSO) | **PARTIAL** |

### 2.1 `RFE-1`: abstract specification → executable reference

- **Obligation.** The reference implements the abstract specification's
  normative statements for the declared input population, and is independent of
  the Rust implementation.
- **Who discharges it.** ETP-T5 (*Cryptographic correctness independent of
  OpenSSL*) and FRC-1.
- **Artefact.** A reference program and its conformance run at a named candidate.
- **Invalidation.** A change to the abstract specification, the reference, or the
  conformance tool.
- **What it does not establish.** A proof about the abstract specification says
  nothing about whether the reference implements it. A reference can be wrong in
  the same way as any implementation, and a reference written by the same party
  can share the implementation's misconception.
- **Status.** `NONE`. ETP-T5 is `TODO`; FRC-1 is open. There is no independent
  executable reference in the tree. The OpenSSL authority is an executable
  implementation, but it is not a reference derived from the abstract
  specification and it is not independent of the compatibility target.

### 2.2 `RFE-2`: executable reference → Rust implementation

- **Obligation.** The Rust implementation agrees with the reference at the
  declared interface, including failure behaviour, over a frozen input
  population.
- **Who discharges it.** ETP-T5's differential run.
- **Artefact.** A frozen input population, a differential harness and a run at
  the candidate identity.
- **Invalidation.** A change to the reference, the Rust implementation, or the
  harness; the population is bound to the candidate.
- **What it does not establish.** Agreement on a finite population is not a
  refinement proof. A passing differential court says nothing about inputs
  outside the population or about failure behaviour it did not exercise. **A
  passing differential court is not a refinement proof.**
- **Status.** `NONE`. There is no level-2 reference to compare against. The
  ETP-4 REDC congruence check compares two computations inside the same crate
  (`out*R == input (mod m)` against `limbs::{mul, rem}`); it is a bounded internal
  cross-check, not an independent reference. The differential courts compare the
  candidate against the OpenSSL authority; that is compatibility evidence, not a
  reference-to-implementation refinement.

### 2.3 `RFE-3`: Rust implementation → ABI contract

- **Obligation.** The observable C surface matches the contract: exported symbols
  and their versions, `repr(C)` layouts, ownership transfer and refcount
  conventions, error-queue classification and ordering, and callback semantics.
- **Who discharges it.** ABI symbol, layout and version-script checks at the
  candidate, with the mechanism obligations discharged.
- **Artefact.** `ART-FILE-ABI-LAYOUT` (`artifacts/phase2/libcrypto.ld`) and the
  ABI/symbol/layout courts.
- **Invalidation.** A change to any exported symbol, `repr(C)` layout, error path
  or callback signature; the contract is re-measured at the new candidate.
- **What it does not establish.** An exported-symbol match and a layout probe are
  an ABI result, not a semantic or memory-safety result. Ownership,
  error-queue ordering and callback semantics are separate planes
  (`docs/PARITY_MODEL.md` §3) and an ABI match does not imply them.
- **Status.** `PARTIAL`. The exported symbol set and the public layouts are
  checked at the candidate, and `libcrypto.ld` agrees with the built DSO's
  exports. Ownership, error-queue ordering and callback semantics are not
  established: `OBL-MECH-C-ABI-CONTRACT` is `NOT_ESTABLISHED` (5 obligations),
  `OBL-XCUT-CALLBACKS` is open, and the parity model's `OWNERSHIP_PASS`,
  `ERROR_PASS` and `STATE_PASS` columns are not proved for the candidate.

### 2.4 `RFE-4`: ABI contract → machine code

- **Obligation.** The exact compiled artefact implements the ABI contract and
  preserves the verified source properties, including the reassembly question.
- **Who discharges it.** ETP-T6 (*Binary-level assurance*) and FRC-4.
- **Artefact.** Object-code correspondence for the exact artefact.
- **Invalidation.** A change to the compiler, linker, assembler, target, profile
  or any build input; no result carries across targets.
- **What it does not establish.** A proof about the source is not a proof about
  the binary. Build reproducibility shows that two builds produce the same bytes;
  it does not show that the bytes refine the source. Source-level constant-time
  intent is not a binary timing result. **A proof in a model is not a proof about
  the binary.**
- **Status.** `NONE`. ETP-2 records that two independently initialised clean
  builds are byte-identical (archive `641471443209`, measurement DSO
  `85395dcf7b76`, distribution DSO `139966033ac9`); that is a build-identity
  result and a precondition, not a correspondence argument. The branch audit is a
  review aid. ETP-T6 and FRC-4 are open.

### 2.5 `RFE-5`: machine code → consumer composition

- **Obligation.** For every reachable call site `c` in the loaded DSO,
  `Pre(c) ⇒ P`, and `Q` satisfies the precondition of the next consumer. This is
  the compositional obligation of `docs/FORMAL-REFINEMENT-CERTIFICATION.md` §2.
- **Who discharges it.** The consumer closure at the loaded DSO identity.
- **Artefact.** `ART-CURL-DSO-FD25`: the curl closure at the admitted install,
  with the ssh closure at b85c as the second population.
- **Invalidation.** A change to the DSO, the loader resolution or the consumer
  binary; the closure is re-run at the new identities.
- **What it does not establish.** A reachability classification is not a
  memory-safety proof and not a `SAFE_COMPATIBLE` promotion. The closure's own
  non-claims state that a discharged obligation means an existing receipt covers
  a site, not that the site's precondition is established. A binary timing
  result is not a physical side-channel guarantee.
- **Status.** `PARTIAL`. The bounded populations are named: the curl closure
  reaches 644 files and discharges 7/7 reachable production obligations; the ssh
  closure reaches 625 files and discharges 290/290. Neither closure establishes
  `Pre(c) ⇒ P`: both report `safe_compatible: false`, the independent b85c
  adjudication is `NOT_ESTABLISHED`, and the curl element-7 refusal population
  remains open (`ETP-5` R5). The closure is a reachability measurement, not a
  refinement proof.

### 2.6 Status discipline

- A `BOUNDED` status is permitted only when a finite population is named and the
  artefact that checked it is named.
- A `PARTIAL` status names what is missing.
- Any other state is `NONE`. The differential courts are bounded evidence,
  ctgrind is detection at a harness, and neither is a refinement proof. No edge
  is `DISCHARGED`.

---

## 3. The anti-implementation-shaped rule

A specification that restates the implementation proves nothing. The rule is:

> A specification artefact declares its refinement level and must not reference
> an internal identifier of the implementation level it refines: no internal
> function name, type name, field name or `src/`/`crate::`/`super::`/`self::`
> path.

The rule is enforced by `forensics/tools/spec_guard.py` against the register
`evidence/etp-t3/SPECIFICATIONS.json`.

### 3.1 The population is derived, not hand-listed

The population is the union of:

1. the distinct source documents of the `requirement` nodes in
   `evidence/etp-t1/TRACEABILITY.json`; and
2. the contract documents named in the register.

A new requirement source enters the population automatically. A population
member that is neither a registered specification, a recorded known
nonconformance, nor an explicit exclusion is refused.

### 3.2 What the check detects

The guard builds a lexicon of implementation-internal identifiers from tracked
`src/**/*.rs`: Rust `struct`/`enum`/`trait`/`type` names and distinctive
snake_case `fn` names, minus every exported symbol recorded in
`artifacts/*.ld`, `#[no_mangle]`, `#[export_name]` and `extern "C"` declarations.
It examines code spans and explicit `src/...`, `crate::`, `super::` and `self::`
paths, and names the offending token and line.

An ABI observable is not an internal identifier and needs no exemption.

### 3.3 Exemptions

A genuinely needed internal identifier may be named only through an exemption
that records a `token`, a `justification`, a `reviewer` and a `reviewed`
identity. An exemption missing any of these is refused as unjustified. An
exemption whose token no longer appears in the text is refused as stale, so
exemptions cannot accumulate silently.

### 3.4 Result at this identity

At `794a7c549`, the population is 15 documents: 10 are registered
specifications and pass, and 5 are recorded known nonconformances:

| document | declared level | internal tokens | representative tokens |
|---|---|---:|---|
| `docs/ETP-TODO.md` | L1 | 87 | `SecretBuf`, `SecretRef`, `ScalarLadderWorkspace`, `NameDb`, `normalise_consttime` |
| `AGENTS.md` | L1 | 17 | `OwnedBlock`, `OwnedBuf`, `OwnedCtx`, `OwnedNode`, `OwnedRaw`, `OwnedStr`, `OwnedTree`, `CtxDestroy`, `guard_ffi` |
| `docs/HAZARD-REGISTER.md` | L1 | 14 | `SecretBuf`, `OwnedBuf`, `OwnedTree`, `ChainSnapshot`, `ecdsa_sign_setup`, `rsa_get_blinding` |
| `docs/OWNERSHIP_MODEL.md` | L4 | 1 | `up_ref` |
| `docs/PARITY_MODEL.md` | L4 | 1 | `up_ref` |

**Five of fifteen specification-bearing documents would fail the rule today.**
The finding is recorded, not repaired: the documents are not rewritten, and each
known nonconformance carries a `would_close` statement. A change to one of these
documents that adds or removes an internal token is refused as drift; a repair
that removes every token is refused as a stale known failure until the register
is updated.

The top offenders are the documents that state the safety contract in the
vocabulary of the types that implement it: the standing standard names the owner
types and constructors, and the hazard register names the mechanisms that guard
each hazard. That is exactly the implementation-shaped pattern the rule exists to
make visible.

### 3.5 Limits

- Detection covers code spans and explicit source or Rust paths. An internal
  concept restated in prose without naming it is not detected. The rule checks
  **naming**, not semantic independence: a paraphrase in different words passes.
- The lexicon is a static scan. A name that is both an authority observable and
  a Rust shim (`OPENSSL_clear_free` is one) is flagged by name and needs a
  reviewed exemption.
- A known nonconformance is not an exemption and is not a licence to add another.

---

## 4. Binding to the ETP-T1 graph

Every level and edge is a node or an edge in
`evidence/etp-t1/TRACEABILITY.json`, so the orphan machinery covers the chain.
The model is extended, not forked.

| addition | kind | count |
|---|---|---:|
| `refinement_level` | node type | 6 |
| `refinement_edge` | node type | 5 |
| `refines_to` | edge type (`level → edge`) | 5 |
| `discharges` | edge type (`edge → level`) | 5 |
| `obligates` | edge type (`edge → obligation`) | 5 |

Each edge also raises one obligation node (`OBL-RFE-1` … `OBL-RFE-5`), all
`OPEN`. The seed is `forensics/tools/etp_t1_seed.py`; the validator is
`forensics/tools/traceability.py`.

### 4.1 New orphan classes

| class | identifier | detection | what closes it |
|---|---|---|---|
| 9 | `ORPHAN-9:<level>` | a non-source level has no incoming `discharges`, or a non-terminal level has no outgoing `refines_to` | the connecting edge exists |
| 10 | `ORPHAN-10:<edge>` | the edge's `obligation` does not resolve to an obligation node, or `obligation_artefact` does not resolve to an artefact | the obligation and its artefact exist |
| 11 | `ORPHAN-11:<edge>` | the edge is `NONE`; or it claims `BOUNDED`/`PARTIAL` with no discharger or no resolvable discharge artefact; or it claims `BOUNDED` with no named population | the discharge exists, is named, and is recorded |

Structural refusals added with the edge classes: `TG_REFINEMENT_LEVEL`,
`TG_REFINEMENT_EDGE`, `TG_REFINEMENT_OBLIGATION`, `TG_REFINEMENT_SHAPE`.

### 4.2 Counts

| dimension | before ETP-T3 | after ETP-T3 |
|---|---:|---:|
| nodes | 325 | 342 |
| edges | 403 | 423 |
| declared orphans | 21 | 24 |
| orphan classes present | 1, 3, 6, 8 | 1, 3, 6, 8, 11 |

The three new orphans are `ORPHAN-11:RFE-1`, `ORPHAN-11:RFE-2` and
`ORPHAN-11:RFE-4`: the three edges honestly recorded as `NONE`. Classes 9 and 10
have zero instances in this seed and are exercised by controls, in the same way
as classes 2, 4, 5 and 7.

The existing controls still pass: `forensics/tools/tests/test_traceability.py`
is 24/24, and the seed reproduces the committed graph byte for byte.

---

## 5. What a proof on one side does not establish on the other

| edge | a result on the left does not establish | a result on the right does not establish |
|---|---|---|
| L1 → L2 | a proof about the specification says nothing about the reference's fidelity | the reference's success says nothing about the specification's completeness |
| L2 → L3 | a passing differential court over a finite population is not a refinement proof | agreement inside the crate is not agreement with an independent reference |
| L3 → L4 | a safe interior does not establish the observable ownership or error contract | an ABI match does not establish memory safety or semantics |
| L4 → L5 | build reproducibility is not source-to-binary refinement | a binary that matches the ABI is not thereby a refinement of the source |
| L5 → L6 | a reachability classification is not a precondition proof | a consumer that runs is not a consumer whose preconditions hold |

These separations are structural: the status of each edge is a separate field,
and no edge inherits a neighbouring edge's result.

---

## 6. Non-claims

- This architecture does **not** establish any refinement relation. Four of five
  edges are `NONE` or `PARTIAL`, and no edge is `DISCHARGED`.
- **No object-code result exists.** A proof in a model is not a proof about the
  binary; the only level-5 result is a build-identity digest.
- **A passing differential court is not a refinement proof.** It is bounded to
  its population and its harness.
- **Reproducibility is not correctness.** Byte-identical builds are a
  precondition, not a source-to-binary argument.
- **A consumer closure is not a `SAFE_COMPATIBLE` promotion.** Both closures
  report `safe_compatible: false`, and the b85c graduation is `NOT_ESTABLISHED`.
- **The anti-implementation-shaped guard checks naming, not truth.** A
  specification that rephrases the implementation in different words passes, and
  an internal concept named only in prose is not detected.
- **The known-nonconformance population is a finding, not a licence.** The five
  documents are recorded and not repaired; each carries what would close it.
- **Population completeness is `UNKNOWN`.** There is no frozen expected manifest
  of levels, edges or specification documents, so this architecture cannot prove
  that it lists every level or every specification-bearing document.

---

## 7. Operating instructions

```
python3 forensics/tools/spec_guard.py check
python3 forensics/tools/spec_guard.py inventory
python3 forensics/tools/spec_guard.py self-test
python3 forensics/tools/etp_t1_seed.py
python3 forensics/tools/traceability.py validate
python3 forensics/tools/tests/test_spec_guard.py
python3 forensics/tools/tests/test_traceability.py
```

`check` exits 0 only when the registered specifications pass, every exemption is
justified and current, every known nonconformance reproduces its recorded token
set, and every population member is classified. `inventory` reports the measured
population and exits 1 while a known nonconformance remains; that exit is the
recorded finding, not a gate failure of the registered specifications.
