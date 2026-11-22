# Requirements traceability (ETP-T1)

**Status:** normative for ETP-T1 of `docs/ETP-TODO.md`.
**Candidate:** `staging` at `21bea3188` (source identity `S`).
**Graph:** `evidence/etp-t1/TRACEABILITY.json` (`openssl-rs/etp/traceability/1`).
**Seeder:** `forensics/tools/etp_t1_seed.py` (reproduces the committed graph byte for byte).
**Checker:** `forensics/tools/traceability.py`.
**Tests:** `forensics/tools/tests/test_traceability.py`.
**Receipt:** `evidence/etp-t1/RECEIPT.md`.

This document defines the traceability model, the eleven orphan classes, and
what the graph deliberately does not decide. It is not a hazard analysis
(ETP-T2), a reconciliation of the OpenSSH adjudication (ETP-T15), or an
independent specification hierarchy (FRC-0).

The graph is a directed typed graph. Every node and every edge cites a tracked
file, a span within it, and the SHA-256 of the Git blob at the node's
`bound_commit`. Digests are read from the named commit, not from the working
tree, so a later documentation commit cannot silently rebind evidence.

## 1. The trace direction and the support direction

The spine is:

```
threat | hazard -> requirement -> specification -> implementation
    -> artefact -> obligation -> evidence -> adjudication -> release_claim
```

Every legal edge points forward along this spine. The direction is called the
**support direction**: an edge from `A` to `B` means the record states that `A`
is the provider and `B` is the candidate that consumes `A`'s support, constraint
or trace. A path that returns to its origin is therefore a circular support
claim, and is orphan class 7.

The edge vocabulary is fixed. An edge of an unknown type, or between type pairs
outside the table below, is refused as `TG_ILLEGAL_EDGE` before orphan
detection runs.

## 2. Node types

| type | what the node records | minimum outgoing | minimum incoming |
|---|---|---|---|
| `threat` | an adversarial class the architecture must resist | many `motivates` | none |
| `hazard` | a technical state that can cause harm, scoped by API family and input class (ETP-T2) | at least one `motivates` (structural) | none |
| `requirement` | an externally observable functional or safety requirement, quoted from a tracked normative document | at least one `satisfied_by` (class 1) | at least one `motivates` |
| `specification` | an independent specification refined from a requirement | at least one reachable implementation (class 6) | at least one `refines` |
| `implementation` | a source location or mechanism | at least one `realised_by` (class 2) | at least one `satisfied_by` |
| `artefact` | a tracked file digest, DSO digest, commit or consumer binary | none | at least one `realised_by` |
| `obligation` | an open item that blocks a verdict, a requirement or a release claim | none | at least one `raises` or a claim record |
| `evidence` | a receipt, record, court run, instrument result or status prose | none | at least one `evidenced_by` |
| `adjudication` | a verdict with its authority and independence status, including a typed ETP claim's recorded verdict | none | at least one `assessed_by` |
| `release_claim` | a consumer graduation, compatibility claim or performance classification | none | at least one `releases` and every declared `constrains` (classes 3, 5) |
| `refinement_level` | one of the six adjacent levels of the ETP-T3 refinement architecture, with a unique rank | one outgoing `refines_to` unless it is the terminal level (class 9) | one incoming `discharges` unless it is the source level (class 9) |
| `refinement_edge` | the obligation that connects two adjacent levels, its discharger, its artefact, its invalidation rule and its status (`NONE`, `BOUNDED`, `PARTIAL`) | one `obligates` and one `discharges` | one `refines_to` |

A `requirement` declares `specification_required`. When it is `true`, the model
states that an independent specification must refine it; the absence of that
refinement is orphan class 6, not a reason to omit the requirement.

A `release_claim` declares `claimed_verdict`, `requires_independent_adjudication`
and `scope_requirements`. Every scope requirement must exist and be a
`requirement`; an absent or wrong-typed reference is `TG_RELEASE_SCOPE_UNKNOWN`.

An `obligation` declares `blocks_release_claims`. Every named claim must be a
`release_claim`, and every such declaration must have a corresponding
`constrains` edge (class 5). A `constrains` edge without the declaration is
refused as `TG_UNJUSTIFIED_BLOCK_EDGE`: an edge may not be manufactured to make
the graph look connected.

A `hazard` is the ETP-T2 projection. It declares `scope` (one `api_family` and
one primary `input_class`), `trigger_classes`, `memory_safe_claim`, an optional
`class3_disposition`, `barrier` (state, control, evidence, `would_close`) and
`affected_release_claims`. A hazard that is reachable from `contract_violation`
may not claim memory safety; a barrier recorded as `CLAIMED_NO_EVIDENCE` or
`BARRIER_ABSENT` may not cite evidence; and `affected_release_claims` must equal
the claims reached by the hazard's motivated requirements and raised
obligations. The register (`evidence/etp-t2/HAZARDS.json`) is the source of
these fields, and the graph records its digest.

## 3. Edge types

| edge | from -> to | meaning | cardinality | an edge is invalid when |
|---|---|---|---|---|
| `motivates` | hazard \| threat -> requirement | the hazard or threat is the stated reason for the requirement | many-to-many; each requirement needs at least one | the cited source does not state that reason |
| `refines` | requirement -> specification | an independent specification refines the requirement | many-to-many; mandatory where `specification_required` | the "specification" restates the implementation (not mechanically detectable; a provenance failure, not an orphan) |
| `satisfied_by` | requirement \| specification -> implementation | the implementation is offered as satisfying the requirement or specification | many-to-many; each requirement needs at least one (class 1) | the implementation does not address the requirement's stated scope |
| `realised_by` | implementation -> artefact | the implementation is realised by a tracked file or shipped artefact | many-to-many; each implementation needs at least one (class 2) | the artefact digest belongs to a different implementation or candidate |
| `raises` | hazard \| implementation \| artefact -> obligation | the hazard, implementation or artefact carries the obligation | many-to-many | no tracked record states the obligation |
| `evidenced_by` | hazard \| requirement \| implementation \| artefact \| obligation \| adjudication -> evidence | the record is cited as evidence for the source | many-to-many | the evidence is bound to a different identity than the implementation it supports (class 4) |
| `assessed_by` | evidence \| requirement -> adjudication | the evidence or requirement is assessed by the adjudication | many-to-many | the adjudicator is the same party that produced the evidence, where independence is required (class 3) |
| `releases` | adjudication -> release_claim | the adjudication is the recorded verdict for the claim | at least one per claim (class 3) | the verdict does not support the claimed verdict, or the adjudicator is not independent where required |
| `constrains` | obligation -> release_claim | the open obligation blocks the release claim | at least one per declared blocking relation (class 5) | the obligation does not declare that it blocks the claim |
| `refines_to` | refinement_level -> refinement_edge | the level is refined through this edge | exactly one per non-terminal level | the edge's `from_level` is a different level |
| `discharges` | refinement_edge -> refinement_level | the edge produces this level | exactly one per non-source level | the edge's `to_level` is a different level |
| `obligates` | refinement_edge -> obligation | the edge carries the named refinement obligation | exactly one per edge | the target disagrees with the edge's `obligation` field |

A `refinement_edge` declares `from_level`, `to_level`, `status`, `discharged_by`,
`obligation`, `obligation_artefact`, `discharge_artefact` (or `null`),
`bounded_population`, `invalidation_rule` and `does_not_establish`. Its
`from_level` and `to_level` must be adjacent ranks. A `NONE` edge is an honest
"no discharge"; a `BOUNDED` edge names a finite population and the artefact that
checked it; a `PARTIAL` edge names what is missing. No edge inherits a
neighbouring edge's result.

`assessed_by` from a `requirement` to an `adjudication` records a typed claim
that asserts a property of that requirement. The ETP-1 claim inventory is typed
as `adjudication` nodes with `record_kind: typed_claim` and `independence:
NOT_CLAIMED`: a typed claim is a verdict record produced by the same campaign
that produced its evidence, not an independent adjudication. A release claim
that needs independence cannot be supported by a typed claim alone.

## 4. Orphan taxonomy

An orphan is a node, or a node pair, that the model says must be connected and
is not. Orphans are **not** omitted and they are **not** repaired by adding an
edge the records do not state. They are named in the graph's `orphans` register
with a `would_close` statement, and the checker reconciles the register against
what it discovers.

| class | identifier | detection rule | what makes a declaration invalid |
|---|---|---|---|
| 1 | `ORPHAN-1:<requirement>` | a `requirement` has no `satisfied_by` edge | the identifier names a node that is not a requirement, or an implementation edge exists |
| 2 | `ORPHAN-2:<implementation>` | an `implementation` has no `realised_by` edge | the node is not an implementation, or an artefact edge exists |
| 3 | `ORPHAN-3:<release_claim>` | no `releases` adjudication; or none independent where the claim requires it; or no adjudication verdict is in the set allowed for the claimed verdict (`adjudication_refuses`, `not_independent`, `no_adjudication`) | a supporting independent adjudication exists, or the claim's `claimed_verdict` is not the one the verdict supports |
| 4 | `ORPHAN-4:<node>` | a node's recorded digest disagrees with the blob at its `bound_commit`; a named `bound_artefact` disagrees with the node digest; or evidence cited by an implementation is bound to a different commit than that implementation (`digest_mismatch`, `bound_artefact_mismatch`, `support_identity_mismatch`) | the digests agree at the stated identity |
| 5 | `ORPHAN-5:<obligation>:<release_claim>` | an obligation declares that it blocks a claim and no `constrains` edge reaches it (the omission case) | the edge exists, or the obligation does not declare the block |
| 6 | `ORPHAN-6:REQ:<requirement>` and `ORPHAN-6:SPEC:<specification>` | a requirement with `specification_required: true` has no refining specification; or a specification reaches no implementation | a refining specification exists, or the requirement does not require one; or the specification reaches an implementation |
| 7 | `ORPHAN-7:<sorted members>` | a strongly connected component of size greater than one, or a self-loop, in the support direction | the cycle no longer exists |
| 8 | `ORPHAN-8:<node>:<path>` | a node's source path does not exist at its `bound_commit` | the path exists at the named commit |
| 9 | `ORPHAN-9:<level>` | a non-source `refinement_level` has no incoming `discharges`, or a non-terminal level has no outgoing `refines_to` | the level is connected to its edge |
| 10 | `ORPHAN-10:<edge>` | a `refinement_edge`'s `obligation` does not resolve to an obligation node, or `obligation_artefact` does not resolve to an artefact | the obligation and the artefact that records it exist |
| 11 | `ORPHAN-11:<edge>` | a `refinement_edge` is `NONE`; or claims `BOUNDED`/`PARTIAL` with no discharger or no resolvable discharge artefact; or claims `BOUNDED` with no named population | the discharge exists, is named and is recorded |

Class 3's allowed verdict set depends on the claim. A positive claim
(`SAFE_COMPATIBLE`, `ESTABLISHED`, `PASS`, `ACCEPTED`) is supported only by a
positive adjudication. A negative claim (`NOT_ESTABLISHED`, `NOT_GRADUATED`,
`REFUSED`, `CONTRADICTED`, `WITHDRAWN`, `SUPERSEDED`, `PARTIAL`) may be
supported by a refusal. A claim that is honestly recorded as refused is
therefore not an orphan merely because its adjudication refuses it.

Class 4 has three branches because "a different artefact identity" has three
mechanical forms: the bytes changed under a recorded digest, the evidence names
an artefact whose digest is different, and the evidence is bound to a different
candidate than the implementation it is offered for. The third is not visible
from either node alone; it is a property of the edge.

## 5. Failing closed

The checker validates the graph and then reconciles the discovered orphan set
with the declared register. It exits non-zero when:

| code | condition |
|---|---|
| `TG_GRAPH_UNREADABLE` / `TG_GRAPH_MALFORMED` | the graph cannot be read or parsed |
| `TG_SCHEMA` | a required field is absent or has the wrong type |
| `TG_JSON_DUPLICATE_KEY` / `TG_JSON_NON_FINITE` | the document has no single meaning |
| `TG_COMMIT_UNRESOLVED` | `identity.commit` or a node's `bound_commit` does not resolve |
| `TG_DUPLICATE_ID` / `TG_DUPLICATE_EDGE` / `TG_DUPLICATE_ORPHAN` | an identifier is reused |
| `TG_UNKNOWN_NODE_TYPE` / `TG_UNKNOWN_EDGE_TYPE` | a type outside the closed vocabulary |
| `TG_DANGLING_EDGE` | an edge endpoint does not exist |
| `TG_ILLEGAL_EDGE` | the source/target type pair is not legal |
| `TG_UNJUSTIFIED_BLOCK_EDGE` | a `constrains` edge the obligation does not declare |
| `TG_UNKNOWN_BLOCK_TARGET` / `TG_RELEASE_SCOPE_UNKNOWN` | a block or scope reference names an absent or wrong-typed node |
| `TG_UNSETTLED_FIELD` | a digest is `UNKNOWN` without a settling method |
| `TG_UNKNOWN_ARTEFACT` | an evidence node names an absent artefact |
| `TG_UNDECLARED_ORPHAN` | a discovered orphan is absent from the register |
| `TG_STALE_ORPHAN` | a declared orphan no longer reproduces |
| `TG_ORPHAN_REASON` | a declaration's reason disagrees with the discovered reason |
| `TG_ORPHAN_UNSETTLED` | a declaration does not state what would close it |
| `TG_HAZARD_UNSCOPED` | a hazard has no API-family scope, no primary input class, or no entry point |
| `TG_HAZARD_NO_INPUT_CLASS` | a hazard's trigger set is empty, duplicated or names an unknown class |
| `TG_HAZARD_CLASS3_DISPOSITION` | a class-3-reachable hazard states no valid disposition |
| `TG_HAZARD_CLASS3_SAFE_CLAIM` | a class-3-reachable hazard claims memory safety |
| `TG_HAZARD_BARRIER` | a hazard barrier state, control or `would_close` is missing |
| `TG_HAZARD_BARRIER_UNEVIDENCED` | `EVIDENCED` has no evidence id, or a claimed/absent barrier cites one |
| `TG_HAZARD_UNMOTIVATED` | a hazard has no `motivates` edge |
| `TG_HAZARD_CLAIM_UNRELATED` | a hazard names a release claim its requirements and obligations do not reach |
| `TG_REFINEMENT_LEVEL` | a refinement level has no positive integer rank, a duplicate rank, or a rank set that is not consecutive |
| `TG_REFINEMENT_EDGE` | a refinement edge has an unknown status, no `discharged_by`, or no `invalidation_rule`/`does_not_establish` |
| `TG_REFINEMENT_OBLIGATION` | a refinement obligation field is the wrong type, or an `obligates` edge disagrees with it |
| `TG_REFINEMENT_SHAPE` | a refinement edge joins non-adjacent ranks, a level has two outgoing/incoming edges, or an edge/level endpoint disagrees |

`TG_UNDECLARED_ORPHAN` is the omission case: a new gap cannot enter the graph
without being named. `TG_STALE_ORPHAN` is its converse: a gap cannot remain
declared after it is closed, because a register that drifts away from the graph
stops being evidence. Each refusal names the node, the edge rule or class, and
the artefact or path. Output is sorted and serialised deterministically.

`report` prints the same counts and orphans without the reconciliation verdict.
It is a view, not an acceptance: only `validate` exits 0.

## 6. The seeded graph

At `S = 21bea3188`, after the ETP-T2 hazard projection, and after the ETP-T3
refinement projection:

| type | count |
|---|---|
| threat | 8 |
| hazard | 20 |
| requirement | 22 |
| specification | 0 |
| implementation | 20 |
| artefact | 26 |
| obligation | 86 |
| evidence | 101 |
| adjudication | 41 |
| release_claim | 6 |
| refinement_level | 6 |
| refinement_edge | 5 |
| **total** | **342** |

| edge | count |
|---|---|
| `motivates` | 45 |
| `refines` | 0 |
| `satisfied_by` | 46 |
| `realised_by` | 29 |
| `raises` | 51 |
| `evidenced_by` | 61 |
| `assessed_by` | 130 |
| `releases` | 8 |
| `constrains` | 33 |
| `refines_to` | 5 |
| `discharges` | 5 |
| `obligates` | 5 |
| **total** | **423** |

Provenance of the seed:

- **Threats** are the eight adversary classes in `evidence/etp0/RECEIPT.md`,
  with the mechanism each does and does not cover.
- **Hazards** are the ETP-T2 register's 20 hazards, projected from
  `evidence/etp-t2/HAZARDS.json`. Sections 1-5 and 21 of `AGENTS.md` and queue
  rows T1 and T9 named the original seven characterisations; ETP-T2 quantifies
  them and adds 13 mechanism hazards, each with a scope, an input
  classification, a barrier state and declared T1 edges.
- **Requirements** quote a tracked normative document: `AGENTS.md`,
  `docs/ETP-TODO.md`, `docs/ETP-CLAIM-ALGEBRA.md`, `docs/OPENSSH-COHORT.md`,
  `docs/PERFORMANCE-FRONTIER.md` and
  `docs/FORMAL-REFINEMENT-CERTIFICATION.md`. ETP-T2 adds `REQ-CORR-01` because
  the original population had no requirement for cryptographic correctness.
  The population is a deliberate seed, not a complete extraction of every
  normative sentence in the corpus; section 8 records that gap.
- **Specifications**: zero. No independent specification hierarchy exists at
  `S`; FRC-0 is the item that establishes it. Every safety requirement that
  declares `specification_required: true` therefore carries a class-6 orphan.
- **Implementations** are source paths and mechanisms, each with a tracked file
  digest and, where a candidate is recorded, a DSO or consumer-binary artefact.
- **Artefacts** are file digests at `S`, one commit, and six recorded candidate
  artefacts (two DSOs, two OpenSSH binaries, one curl DSO, one PFP-1 DSO). Their
  digests are copied from the record that states them; the record itself is the
  node's source.
- **Obligations** are the 42 distinct obligations in the typed claim inventory,
  16 named T-row residues (including `OBL-BN-ALLOCATOR`), 8 open queue items,
  13 obligations from the independent b85c adjudication (five mechanisms, two
  scoped discharges, four cross-cutting premises, and B54-F1/B55-F1), and three
  obligations ETP-T2 raises (`OBL-RSA-EXTKEY-ORACLE`, `OBL-PANIC-ATOMICITY`,
  `OBL-VERIFY-RETURN-POLARITY`). All 81 are `OPEN`.
- **Evidence** is 66 records cited by the typed claims, 7 queue-status prose
  records bound to `S`, 11 instrument results from the ETP-3 register with
  their qualification status (`PASS` or `RECORDED`), and 17 consumer,
  performance, reproducibility and governance records.
- **Adjudications** are the 35 typed claims (17 `ESTABLISHED`, 13 `PARTIAL`,
  4 `CONTRADICTED`, 1 `SUPERSEDED`), the independent b85c adjudication
  (`NOT_ESTABLISHED`, `INDEPENDENT`), and the five ETP-5 refusals
  (`REFUSED`, `SAME_PARTY`).
- **Release claims** are the OpenSSH b85c graduation, the 1/33 cohort counter,
  the 33/33 L7 atlas statement, the curl non-graduation, and the two
  `SCOPED_OBSERVATION` performance classifications.

Identity binding is explicit, because the records are not all bound to `S`:

| bound commit | nodes | what it is |
|---|---|---|
| `21bea3188` | 258 | implementations, artefacts, hazards and records at this candidate |
| `9372bb28b` | 66 | the evidence records cited by the ETP-1 typed claims, bound to the ETP-0 source identity |
| `cc2e5fa32` | 1 | the withdrawn O7 revision, read at the commit the claim names |
| `794a7c549` | 17 | the ETP-T3 refinement chain: six levels, five edges, five obligations and the refinement record artefact |

The two populations are not silently merged. The claim tier is evidence about
`9372bb28b`; the implementation tier is `21bea3188`. No
implementation→evidence edge is drawn across that boundary, because doing so
would assert support the records do not establish, and the checker would then
correctly refuse it as class 4. The consequence is stated in section 7.

## 7. What the graph shows that was not visible before

1. **No specification exists.** Twelve safety and functional requirements
   declare that an independent specification is required, and none has one.
   The graph makes the absence a node-level fact (`ORPHAN-6:REQ:*`) rather than
   a sentence in a queue.
2. **The OpenSSH graduation is refused by two independent records.** The
   release claim `REL-OPENSSH-B85C` has three adjudications: the independent
   `NOT_ESTABLISHED` verdict, ETP-5 refusal R1, and `ETP0-CLM-030`
   (`CONTRADICTED`). The claim is `ORPHAN-3` with `adjudication_refuses`.
3. **The cohort counter is internally contradictory.** The claim
   `REL-COHORT-COUNTER-1-33` is adjudicated only by same-party records
   (`ETP0-CLM-032` contradictory, R2 refused), so it is both
   `adjudication_refuses` and `not_independent`.
4. **33/33 L7 is an atlas fact, not a current measurement.** Its sole
   adjudication is `PARTIAL` (`ETP0-CLM-028`), and the graph records the claim
   as refused rather than treating the number as established.
5. **Performance classifications have no adjudication at all.** PFP-0 and PFP-1
   are `SCOPED_OBSERVATION` with evidence and a venue limitation, but no record
   adjudicates the classification. The omission is a named gap, not a silent
   pass.
6. **The graduation is blocked by 13 obligations that the closure's 290/290
   count does not show.** Five mechanisms, two scoped caller preconditions,
   four cross-cutting premises and two reopened rows (B54-F1, B55-F1) reach the
   release claim through explicit `constrains` edges. The omission case is now
   visible from the claim.
7. **One requirement has no implementation.** `REQ-SPEC-01` is the
   independent-specification requirement itself; its implementation is FRC-0,
   which is open.
8. **Three evidence paths do not exist at the commit that cites them.**
   `court/tmp/t20/NOTES.md`, `court/tmp/t21/libcrypto.so.3` and
   `forensics/phase7_courts.py` are class-8 orphans; the typed claims already
   record their absence, and the graph now makes it an executable fact.
9. **The implementation tier has no fresh receipt evidence.** The records cited
   by the typed claims are bound to `9372bb28b`, and the implementation is at
   `21bea3188`. The graph draws no support edge across that boundary. This is
   not one of the eleven orphan classes; it is the freshness problem ETP-T9
   owns, and it is visible in the bound-commit table rather than hidden.
10. **The ETP-T2 hazards are nodes, not prose.** Twenty hazards carry a scope, a
   trigger classification and a barrier state. Four have no barrier at all
   (`HAZ-15`, `HAZ-16`, `HAZ-18`, `HAZ-20`) and 16 are `CLAIMED_NO_EVIDENCE`;
   none is `EVIDENCED`. Three hazards (`HAZ-05`, `HAZ-12`, `HAZ-17`) reach no
   release claim because no claim declares a memory requirement in scope. The
   projection is checked against the register's digest and fields, so a hazard
   cannot be softened in one artefact and left unchanged in the other.
11. **The refinement chain is missing three of five discharges.** The six levels
   and five edges are nodes and edges, so the chain cannot be described in prose
   while an edge is absent from the graph. Three edges are `NONE` (class 11):
   there is no independent executable reference (`RFE-1`), no reference-to-Rust
   differential (`RFE-2`), and no source-to-binary correspondence (`RFE-4`). The
   other two are `PARTIAL`: the ABI contract is not established for ownership,
   error queue and callbacks (`RFE-3`), and the consumer closures do not establish
   the `Pre(c) ⇒ P` obligation (`RFE-5`).

## 8. Coverage, stated honestly

**MC/DC is not measured anywhere in this item, and it is not claimed.**

- The traceability graph is a documentary structure. Its completeness is a
  *population* question: does the graph contain every requirement, obligation,
  evidence record and release claim that the tracked queues name? That question
  is **not measured**. There is no frozen expected-node manifest, so the graph
  can show what it seeded and cannot prove that it seeded everything. The
  requirement that would make the answer measurable is the A17 pre-registered
  evidence manifest (`OBL-A17-RESIDUAL`), reconciled after execution. Until
  that exists, population coverage is `UNKNOWN`.
- MC/DC applies to executable decision logic, not to a graph. No MC/DC result is
  claimed for `forensics/tools/traceability.py`, for the crate, or for any
  court. The 24 checks in `test_traceability.py` are behavioural controls: four
  positive, determinism, seed-reproduction and report controls; fourteen controls
  covering the eleven orphan classes (class 4, class 6 and class 11 have two
  branches each); and six structural and register controls. They demonstrate
  that the named refusal fires on a mutation; they are not a control-flow
  coverage measurement.
- If a release claim ever cites MC/DC or structural coverage, it must name the
  instrument, the decision population, the condition/decision table and the
  measured result under `REQ-EVID-02`. No such record exists, so no claim may
  cite it.

This is a gap, not a pass: the graph machinery is demonstrated on the eight
defect classes it names, and nothing is claimed about decision coverage.

## 9. Non-claims

- The graph records what the tracked records state. An edge is not proof that
  the relation is true; it is proof that a tracked document asserts it.
- A node with `evidence` does not establish that the requirement is met.
  Evidence support is one axis (AGENTS.md §8) and does not imply safety,
  compatibility or cryptographic correctness.
- A specification node's independence is a claim about provenance, not about
  correctness, and there are no specification nodes at this candidate.
- The checker detects the eleven named omissions. It does not detect stale
  evidence, an incorrect measurement, a false claim that cites a real record, a
  requirement that was never written down, or an implementation-derived
  specification whose provenance is concealed.
- Classes 9-11 check the refinement chain's connectivity, obligation artefact and
  discharge status. They do not establish that a discharge is correct, that a
  `BOUNDED` population is representative, or that a `PARTIAL` statement names
  every missing piece. A `NONE` edge is the honest default and is never
  upgraded by this model.
- Class 6 can only flag the requirement-side and specification-side absence of a
  specification. It cannot decide whether a specification that exists is
  independent; that is a reviewer judgment under FRC-0.
- Class 3 checks independence only where the claim declares that it requires an
  independent adjudication. A claim that under-declares the requirement is not
  detected.
- The graph records the ETP-T2 hazard projection and refuses a hazard without a
  scope, without an input class, with a class-3-only trigger claimed memory-safe,
  or with a barrier state that its evidence does not support. It does not show
  that a barrier works; `docs/HAZARD-REGISTER.md` records what each barrier's
  evidence does and does not establish.
- The graph does not reconcile the OpenSSH records (ETP-T15) and does not decide
  whether the b85c graduation is a principal risk acceptance or an
  evidence-derived verdict.

## 10. Operating instructions

```
python3 forensics/tools/traceability.py validate
python3 forensics/tools/traceability.py report
python3 forensics/tools/traceability.py report --json
python3 forensics/tools/etp_t1_seed.py            # regenerate the committed graph
python3 forensics/tools/spec_guard.py check
python3 forensics/tools/spec_guard.py inventory
python3 forensics/tools/spec_guard.py self-test
python3 forensics/tools/hazard_register.py validate
python3 forensics/tools/hazard_register.py report
python3 forensics/tools/tests/test_traceability.py
python3 forensics/tools/tests/test_spec_guard.py
python3 forensics/tools/tests/test_hazard_register.py
```

`validate` exits 0 only when the graph is structurally valid, every discovered
orphan is declared with its reason, and every declaration still reproduces.
Exit 1 is a refusal; exit 2 is a usage error. The graph is bound to
`identity.commit`; to rebind it, a new graph is generated and a new identity is
recorded. Editing a source file does not change the graph's verdicts, because
the digests are read at the recorded commit.

The graph is seeded from tracked records only. A new node or edge requires a
tracked source and a digest; a new gap requires an orphan declaration and a
statement of what would close it.
