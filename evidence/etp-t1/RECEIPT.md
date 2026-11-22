# ETP-T1 receipt — requirements traceability graph and orphan detection

**Item:** ETP-T1 of `docs/ETP-TODO.md`.
**Candidate:** `staging` at `21bea318819a56f641b3aa2f25027216b97a1c4d` (`S`); the
worktree was clean at the start of the item.
**Evidence commit:** the commit that adds this directory and the ETP-T1 row
(`UNKNOWN` at generation time; settled by
`git log -1 --format=%H -- evidence/etp-t1/TRACEABILITY.json`).
**Environment:** `openssl-rs-court-tools:1`, Python 3.11.2, git 2.39.5.
`free -g` reported 27 GiB available; the computed cap was
`min(8g, 27-16) = 8g`, and the run used the more conservative 6g/6g. No Rust
build was run; no compiler was invoked.

## 1. Deliverables

| artefact | role |
|---|---|
| `docs/REQUIREMENTS-TRACEABILITY.md` | normative model, edge rules, orphan taxonomy, non-claims, coverage statement |
| `evidence/etp-t1/TRACEABILITY.json` | the seeded graph, validated with `python3 -m json.tool` |
| `forensics/tools/traceability.py` | validation, orphan detection, `report` mode |
| `forensics/tools/etp_t1_seed.py` | reproducible seeder; reproduces the committed graph byte for byte |
| `forensics/tools/tests/test_traceability.py` | 17 controls, including the eight orphan classes |
| `evidence/etp-t1/RECEIPT.md` | this receipt |
| `docs/ETP-TODO.md` | the ETP-T1 row |

## 2. Graph counts at `S`

| node type | count | | edge type | count |
|---|---:|---|---|---:|
| threat | 8 | | `motivates` | 28 |
| hazard | 7 | | `refines` | 0 |
| requirement | 21 | | `satisfied_by` | 43 |
| specification | 0 | | `realised_by` | 28 |
| implementation | 19 | | `raises` | 27 |
| artefact | 25 | | `evidenced_by` | 50 |
| obligation | 78 | | `assessed_by` | 130 |
| evidence | 101 | | `releases` | 8 |
| adjudication | 41 | | `constrains` | 31 |
| release_claim | 6 | | **total** | **345** |
| **total** | **306** | | | |

Identity binding, because the records are not all from one commit:

| bound commit | nodes | meaning |
|---|---:|---|
| `21bea3188` | 239 | implementations, artefacts and records at this candidate |
| `9372bb28b` | 66 | evidence cited by the ETP-1 typed claims, bound to the ETP-0 source identity |
| `cc2e5fa32` | 1 | the withdrawn O7 revision, at the commit the claim names |

Three evidence nodes carry `sha256: UNKNOWN` with a settling method; they are the
three paths that do not exist at the commit that cites them, and they are
class-8 orphans.

The seeder is tracked, so the graph is reconstructable: `python3
forensics/tools/etp_t1_seed.py` writes the committed bytes. The control
`test_seed_reproduces_the_committed_graph` asserts this.

## 3. Orphans by class

| class | count | identifiers |
|---|---:|---|
| 1 requirement without implementation | 1 | `ORPHAN-1:REQ-SPEC-01` |
| 2 implementation without artefact | 0 | — |
| 3 release claim without supporting independent adjudication | 5 | `ORPHAN-3:REL-OPENSSH-B85C`, `ORPHAN-3:REL-COHORT-COUNTER-1-33`, `ORPHAN-3:REL-L7-ATLAS-33-33`, `ORPHAN-3:REL-PERF-PFP0`, `ORPHAN-3:REL-PERF-PFP1` |
| 4 evidence bound to a different artefact identity | 0 | — |
| 5 obligation unreachable from its release claim | 0 | — |
| 6 specification coverage gap | 11 | `ORPHAN-6:REQ:` for REQ-ABI-01, REQ-MEM-01, REQ-MEM-02, REQ-MEM-03, REQ-PANIC-01, REQ-SEC-01, REQ-SEC-02, REQ-TIM-01, REQ-TIM-02, REQ-COMPAT-01, REQ-COMPAT-02 |
| 7 cycle in the support direction | 0 | — |
| 8 dangling artefact or evidence path | 3 | `ORPHAN-8:EVD-C006:forensics/phase7_courts.py`, `ORPHAN-8:EVD-C019:court/tmp/t20/NOTES.md`, `ORPHAN-8:EVD-C022:court/tmp/t21/libcrypto.so.3` |
| **total** | **20** | |

The most consequential:

1. **`ORPHAN-3:REL-OPENSSH-B85C`** — the `SAFE_COMPATIBLE` graduation is
   adjudicated by the independent b85c adjudication as `NOT ESTABLISHED`, by
   ETP-5 R1 as `REFUSED`, and by `ETP0-CLM-030` as `CONTRADICTED`. No
   adjudication supports the claimed verdict.
2. **`ORPHAN-6:REQ:*` (11)** — no independent specification exists for any
   safety or functional requirement. This is a single systemic gap (FRC-0,
   `OBL-FRC-0`), not eleven independent omissions; the graph records it per
   requirement because the requirement declares that a specification is
   required.
3. **`ORPHAN-3:REL-COHORT-COUNTER-1-33`** — the counter is adjudicated only by
   same-party records, and one of them contradicts it; the claim is both
   `adjudication_refuses` and `not_independent`.
4. **`ORPHAN-3:REL-L7-ATLAS-33-33`** — the only adjudication is `PARTIAL`
   (`ETP0-CLM-028`), so 33/33 is recorded as refused rather than established.
5. **`ORPHAN-3:REL-PERF-PFP0` / `REL-PERF-PFP1`** — the two performance
   classifications have evidence and a venue limitation but no adjudication.
6. **`ORPHAN-8:*` (3)** — the ETP-1 claims already record these absences; the
   graph makes them executable.

Classes 2, 4, 5 and 7 have zero instances in this seed. Their machinery is
demonstrated by the controls below, not by a fabricated seed instance.

## 4. Controls and observed refusals

Every control writes a mutated copy of the graph and runs the validator against
the repository. The refusal identifier is asserted exactly.

| control | mutation | observed refusal |
|---|---|---|
| class 1 | remove every `satisfied_by` edge of `REQ-MEM-01` | `ORPHAN-1:REQ-MEM-01` |
| class 2 | remove every `realised_by` edge of `IMP-RSA` | `ORPHAN-2:IMP-RSA` |
| class 3 | remove every `releases` edge into `REL-CURL-049` | `ORPHAN-3:REL-CURL-049` (`no_adjudication`) |
| class 4a | change `EVD-ETP0-RECEIPT`'s recorded digest | `ORPHAN-4:EVD-ETP0-RECEIPT` (`digest_mismatch`) |
| class 4b | cite an evidence node bound to `9372bb28b` from an implementation bound to `21bea3188` | `ORPHAN-4:EVD-C001` (`support_identity_mismatch`) |
| class 5 | remove `OBL-C1 -> REL-CURL-049` | `ORPHAN-5:OBL-C1:REL-CURL-049` |
| class 6a | add a specification with no implementation | `ORPHAN-6:SPEC:SPEC-TEST` |
| class 6b | remove the declaration for a real requirement-side gap | `ORPHAN-6:REQ:REQ-SEC-02` |
| class 7 | add `ADJ-ETP5-R1 -> EVD-ETP5-REFUSALS`, closing a support cycle | `ORPHAN-7:ADJ-ETP5-R1+EVD-ETP5-REFUSALS` |
| class 8 | point a node at a nonexistent path | `ORPHAN-8:EVD-ETP0-RECEIPT:evidence/etp0/RECEIPT-absent.md` |

Additional controls:

| control | mutation | observed refusal |
|---|---|---|
| positive | the committed graph | exit 0, 20 declared and reproduced, 0 undeclared, 0 stale |
| dangling edge | edge to an absent node | `TG_DANGLING_EDGE` |
| stale declaration | declare an orphan that does not reproduce | `TG_STALE_ORPHAN` |
| undeclared omission | add a positive release claim with only a same-party refusal | `ORPHAN-3:REL-TEST` (`not_independent`) |
| determinism | run `validate` twice | byte-identical stdout and stderr |
| report counts | `report --json` | totals equal the graph's own node, edge and orphan counts |
| seed reproduction | run the tracked seeder | output byte-identical to the committed graph |

Observed gate output:

```
traceability graph at 21bea318819a56f641b3aa2f25027216b97a1c4d: 306 nodes ...;
345 edges (...)
orphans: 20 declared and reproduced (20 ids), 0 undeclared, 0 stale
Ran 17 tests in 9.294s
OK
```

## 5. Determinism

- Every node's source digest and every evidence digest is read from the node's
  `bound_commit`, never from the working tree.
- Nodes are sorted by id; edges by `(from, type, to)`; orphans by `(class, id)`.
- `validate` and `report` serialise sorted output with fixed separators.
- The two-run byte comparison is a test.
- The seeder's output is compared byte for byte by a test.

The graph is a static artefact. A later documentation commit changes neither
the graph nor any verdict, because the digests are bound to the named commits.

## 6. What the graph makes visible, and what it cannot show

Visible now:

- the four broken release claims and the absence of any specification;
- the 13 b85c adjudication obligations that block the graduation while the
  closure reports 290/290 discharged;
- the five mechanisms, two scoped caller preconditions, four cross-cutting
  premises and two reopened rows (B54-F1, B55-F1) as nodes, not prose;
- the evidence bound to `9372bb28b` separated from implementations at
  `21bea3188`;
- three cited evidence paths that do not exist at the commit that cites them.

Not shown, and not claimed:

- **Population completeness.** No frozen expected-node manifest exists, so the
  graph cannot prove it contains every requirement or obligation in the corpus.
  This is `UNKNOWN`; A17 (`OBL-A17-RESIDUAL`) is the mechanism that would
  measure it.
- **Evidence freshness.** The implementation tier carries no fresh receipt
  evidence; the typed-claim evidence is bound to `9372bb28b`. No edge is drawn
  across that boundary, and no orphan class represents the staleness. ETP-T9
  owns the freshness model.
- **Truth of the records.** The graph checks citation, binding and typed
  relations. It does not check that a measurement is correct, that an
  independence claim is true, or that a specification is genuinely independent.
- **MC/DC or structural coverage.** Not measured and not claimed. The 17
  controls are behavioural; they are not a decision-coverage measurement.

## 7. Obligation and compatibility accounting

- **Unsafe operations:** none added, removed or relocated; `src/`, `docker/`
  and the crate build are untouched.
- **Obligations:** 78 obligation nodes are recorded, all `OPEN`. This item
  discharges none of them; it makes them traceable. `OBL-BN-ALLOCATOR` and the
  16 T-row residues are nodes with explicit implementation edges.
- **New obligations introduced by this item:** none as a node. The item
  introduces 20 **orphans**, each with a `would_close` statement; an orphan is a
  traceability gap, not a safety obligation.
- **Compatibility:** not affected; no code or library artefact changed.
- **Hidden assumptions:** the model cannot mechanically detect a specification
  that restates the implementation, a requirement that was never written down,
  or a claim that under-declares its independence requirement. These are stated
  in `docs/REQUIREMENTS-TRACEABILITY.md` §9 rather than reported as zero.
- **STOP conditions:** none triggered. No corroborated defect, ABI regression,
  weakened detector or newly unsafe safe-API was found. The item found no
  counterexample to a safety claim; it found four unsupported release claims,
  which is the expected outcome of applying the model.

## 8. Commands

All Python ran in the court:

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 OPENSSL_RS_COURT_MEM=6g \
OPENSSL_RS_COURT_MEMSWAP=6g bash docker/openssl-rs-court.sh exec sh -c '
  cd /work &&
  python3 forensics/tools/etp_t1_seed.py &&
  python3 -m json.tool evidence/etp-t1/TRACEABILITY.json >/dev/null &&
  python3 forensics/tools/traceability.py validate &&
  python3 forensics/tools/traceability.py report &&
  python3 forensics/tools/tests/test_traceability.py'
```
