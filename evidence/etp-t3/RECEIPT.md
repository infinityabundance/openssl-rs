# ETP-T3 receipt — refinement architecture and the anti-implementation-shaped guard

**Item:** ETP-T3 of `docs/ETP-TODO.md`.
**Analysis candidate:** `staging` at
`794a7c5491e6095992744f1ab624f5183ca3457d`; the worktree was clean at the start.
**Graph commit:** `21bea318819a56f641b3aa2f25027216b97a1c4d` (the ETP-T1 seed);
the 17 ETP-T3 nodes are bound to `794a7c549`.
**Evidence commit:** `UNKNOWN` at generation time; settled by
`git log -1 --format=%H -- evidence/etp-t3/REFINEMENT.json`.
**Environment:** `openssl-rs-court-tools:1`, Python 3.11.2, git 2.39.5.
`free -g` reported 25 GiB available; the computed cap was
`min(8g, 25-16) = 8g`, and the run used the more conservative 6g/6g. No Rust
build, compiler, test or benchmark was run; `src/`, `docker/` and every build
input are untouched.

## 1. Deliverables

| artefact | role |
|---|---|
| `docs/REFINEMENT-ARCHITECTURE.md` | the six levels, five edges, their obligations, dischargers, artefacts, invalidation rules, non-establishments, current statuses and non-claims |
| `evidence/etp-t3/REFINEMENT.json` | machine-readable levels, edges, obligations and statuses (schema `openssl-rs/etp/refinement/1`), validated with `python3 -m json.tool` |
| `evidence/etp-t3/SPECIFICATIONS.json` | the specification register: 10 registered specifications, 5 recorded known nonconformances, 6 controls (schema `openssl-rs/etp/spec-guard/1`) |
| `forensics/tools/spec_guard.py` | the fail-closed implementation-shaped specification guard |
| `forensics/tools/tests/test_spec_guard.py` | 17 controls for the guard |
| `forensics/tools/traceability.py` | extended with two node types, three edge types, three orphan classes and four structural refusals |
| `forensics/tools/etp_t1_seed.py` | projects the refinement chain into the T1 graph |
| `evidence/etp-t1/TRACEABILITY.json` | regenerated: 342 nodes, 423 edges, 24 declared orphans |
| `forensics/tools/tests/test_traceability.py` | 24 controls; the refinement classes and structural refusals are new |
| `docs/REQUIREMENTS-TRACEABILITY.md` | model, edge rules, orphan taxonomy, counts and refusal codes updated |
| `docs/ETP-TODO.md` | the ETP-T3 row |
| `evidence/etp-t3/RECEIPT.md` | this receipt |

## 2. Levels and edges

| level | rank | status of the level's artefact population |
|---|---:|---|
| `LVL-L1` abstract specification | 1 | populated: the normative sources quoted by requirements |
| `LVL-L2` executable reference | 2 | **absent** |
| `LVL-L3` Rust implementation | 3 | populated: the tracked `src/` tree |
| `LVL-L4` ABI contract | 4 | **partial**: symbols and layouts, not ownership/error/callbacks |
| `LVL-L5` machine code | 5 | **identity only**: the ETP-2 DSO digests, no correspondence argument |
| `LVL-L6` consumer composition | 6 | **partial**: reachability closures, not `Pre(c) ⇒ P` |

| edge | obligation | discharger | artefact | status |
|---|---|---|---|---|
| `RFE-1` L1 → L2 | the reference implements the specification and is independent of the Rust crate | ETP-T5 / FRC-1 | none | **NONE** |
| `RFE-2` L2 → L3 | the Rust implementation agrees with the reference, including failure behaviour, over a frozen population | ETP-T5 differential | none | **NONE** |
| `RFE-3` L3 → L4 | symbols, versions, layouts, ownership, error queue and callbacks match the contract | ABI symbol/layout/version checks | `ART-FILE-ABI-LAYOUT` | **PARTIAL** |
| `RFE-4` L4 → L5 | the exact artefact implements the contract and preserves the verified source properties | ETP-T6 / FRC-4 | none | **NONE** |
| `RFE-5` L5 → L6 | `∀` reachable `c`: `Pre(c) ⇒ P`, and `Q` satisfies the next consumer | consumer closure | `ART-CURL-DSO-FD25` | **PARTIAL** |

No edge is `DISCHARGED`. `RFE-1`, `RFE-2` and `RFE-4` are `NONE`; `RFE-3` and
`RFE-5` are `PARTIAL`. The bounded populations for `RFE-5` are named: the curl
closure reaches 644 files and discharges 7/7 reachable production obligations;
the ssh closure reaches 625 files and discharges 290/290. Both closures report
`safe_compatible: false`, the independent b85c adjudication is `NOT_ESTABLISHED`,
and the curl element-7 refusal population remains open.

The statuses are not upgraded:

- The differential courts are bounded evidence; a passing differential court is
  not a refinement proof.
- ctgrind is detection at a harness; it is not a refinement proof.
- ETP-2's byte-identical builds (archive `641471443209`, measurement DSO
  `85395dcf7b76`, distribution DSO `139966033ac9`) are a build-identity result,
  not source-to-binary correspondence.
- The ETP-4 REDC congruence check is an internal cross-check inside one crate,
  not an independent executable reference.

## 3. The anti-implementation-shaped rule

`forensics/tools/spec_guard.py` enforces:

> A specification artefact declares its refinement level and must not reference
> an internal identifier of the implementation level it refines: no internal
> function name, type name, field name or source/Rust module path.

The population is derived, not hand-listed: the distinct source documents of the
T1 `requirement` nodes, union the nine contract documents named in the register.
A population member that is neither a registered specification, a recorded known
nonconformance, nor an explicit exclusion is refused.

The check fails closed on: an unclassified population member; a missing or
unknown level; an internal identifier inside a code span or an explicit source
path; an incomplete or stale exemption; a known nonconformance whose token set
drifts or no longer reproduces; an unreadable register or graph; and a duplicate
JSON key. Every refusal names the token and the line.

### 3.1 Finding at this identity

The population is 15 documents: 10 registered specifications pass, and 5 are
recorded known nonconformances. **Five of fifteen specification-bearing documents
would fail the rule today:**

| document | level | internal tokens | representative tokens |
|---|---|---:|---|
| `docs/ETP-TODO.md` | L1 | 87 | `SecretBuf`, `SecretRef`, `ScalarLadderWorkspace`, `NameDb`, `normalise_consttime` |
| `AGENTS.md` | L1 | 17 | `OwnedBlock`, `OwnedBuf`, `OwnedCtx`, `OwnedNode`, `OwnedRaw`, `OwnedStr`, `OwnedTree`, `CtxDestroy`, `guard_ffi` |
| `docs/HAZARD-REGISTER.md` | L1 | 14 | `SecretBuf`, `OwnedBuf`, `OwnedTree`, `ChainSnapshot`, `ecdsa_sign_setup`, `rsa_get_blinding` |
| `docs/OWNERSHIP_MODEL.md` | L4 | 1 | `up_ref` |
| `docs/PARITY_MODEL.md` | L4 | 1 | `up_ref` |

No document was rewritten. Each known nonconformance carries a `would_close`
statement in the register. A change that adds or removes an internal token is
refused as drift; a repair that removes every token is refused as a stale known
failure until the register is updated.

The pattern is what the rule exists to expose: the documents that state the
safety contract in the vocabulary of the types and functions that implement it.
The standing standard names the owner types and constructors; the hazard
register names the mechanism behind each barrier.

### 3.2 Limits

- Detection covers code spans and explicit source or Rust module paths. An
  internal concept restated in prose without naming it is not detected.
- The rule checks naming, not semantic independence: a paraphrase in different
  words passes.
- The lexicon is a static scan of tracked `src/**/*.rs` and the exported-symbol
  records. A name that is both an authority observable and a Rust shim
  (`OPENSSL_clear_free`) is flagged by name and needs a reviewed exemption.
- A known nonconformance is not an exemption and is not a licence to add another.

## 4. The T1 projection

The model is extended, not forked. `traceability.py` gains two node types
(`refinement_level`, `refinement_edge`), three edge types (`refines_to`,
`discharges`, `obligates`), three orphan classes and four structural refusals.

| dimension | before ETP-T3 | after ETP-T3 |
|---|---:|---:|
| nodes | 325 | 342 |
| edges | 403 | 423 |
| declared orphans | 21 | 24 |
| orphan classes present | 1, 3, 6, 8 | 1, 3, 6, 8, 11 |

New orphan classes:

| class | identifier | detection | control |
|---|---|---|---|
| 9 | `ORPHAN-9:<level>` | a non-source level has no incoming `discharges`, or a non-terminal level has no outgoing `refines_to` | remove `LVL-L3 -> RFE-3` |
| 10 | `ORPHAN-10:<edge>` | the edge's `obligation` or `obligation_artefact` does not resolve | point `RFE-1.obligation_artefact` at an absent artefact |
| 11 | `ORPHAN-11:<edge>` | the edge is `NONE`, or claims a status with no discharger/artefact/population | remove the `RFE-1` declaration; null `RFE-3.discharge_artefact` |

The three new orphans are `ORPHAN-11:RFE-1`, `ORPHAN-11:RFE-2` and
`ORPHAN-11:RFE-4`: the three edges honestly recorded as `NONE`. Classes 9 and 10
have zero instances in this seed and are exercised by controls, in the same way
as classes 2, 4, 5 and 7.

Existing controls still pass: `test_traceability.py` is 24/24, the committed
graph validates with 0 undeclared and 0 stale orphans, and the seed reproduces
the committed graph byte for byte.

Observed gate output:

```
traceability graph at 21bea318819a56f641b3aa2f25027216b97a1c4d: 342 nodes
(adjudication=41, artefact=27, evidence=101, hazard=20, implementation=20,
obligation=86, refinement_edge=5, refinement_level=6, release_claim=6,
requirement=22, threat=8); 423 edges (assessed_by=130, constrains=33,
discharges=5, evidenced_by=61, motivates=45, obligates=5, raises=56,
realised_by=29, refines_to=5, releases=8, satisfied_by=46)
orphans: 24 declared and reproduced (24 ids), 0 undeclared, 0 stale
spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s),
6 level(s); 0 unclassified, 0 unjustified exemptions
5/15 specification-bearing documents name an internal identifier
spec-guard self-test: 6 controls behaved as recorded
Ran 17 tests in 8.731s
OK
Ran 24 tests in 12.147s
OK
```

## 5. The guard's controls

| control | expectation | observed |
|---|---|---|
| a specification naming an internal identifier | refused | `SP_INTERNAL_IDENTIFIER` (token and line named) |
| a justified exemption | accepted | exit 0 |
| an unjustified exemption | refused | `SP_EXEMPTION_UNJUSTIFIED` and `SP_INTERNAL_IDENTIFIER` |
| a specification with no declared level | refused | `SP_NO_LEVEL` |
| an unknown level | refused | `SP_UNKNOWN_LEVEL` |
| a stale exemption | refused | `SP_STALE_EXEMPTION` |
| an unclassified population member | refused | `SP_UNCLASSIFIED` |
| a known nonconformance whose token set changes | refused | `SP_KNOWN_FAILURE_DRIFT` |
| a known nonconformance that no longer reproduces | refused | `SP_STALE_KNOWN_FAILURE` |
| a known nonconformance with no level | refused | `SP_NO_LEVEL` |
| an unknown classification | refused | `SP_UNKNOWN_CLASSIFICATION` |
| an exclusion with no reason | refused | `SP_EXCLUSION_UNJUSTIFIED` |
| a duplicate JSON key | refused | `SP_JSON_DUPLICATE_KEY` |
| the committed register | accepted | exit 0 |

## 6. Obligation and compatibility accounting

- **Unsafe operations:** none added, removed or relocated. `src/`, `docker/`,
  `Cargo.toml`, `Cargo.lock` and the build scripts are untouched.
- **Obligations created:** `OBL-RFE-1` … `OBL-RFE-5`, all `OPEN`. They record the
  five refinement obligations; none blocks a release claim directly, because an
  undischarged refinement edge is already visible as a class-11 orphan.
- **Obligations discharged:** none. The architecture makes the refinement gaps
  traceable; it does not close them.
- **New orphans:** three class-11 declarations (`ORPHAN-11:RFE-1`, `-RFE-2`,
  `-RFE-4`). An orphan is a traceability gap, not a safety obligation.
- **Compatibility:** not affected; no library artefact changed. The consumer
  statements are read from the existing closures and are not re-measured.
- **Hidden assumptions:** the guard detects naming, not semantic independence;
  the statuses are statements about the tracked evidence, not new measurements;
  population completeness is `UNKNOWN` because no frozen expected manifest
  exists. These are stated in `docs/REFINEMENT-ARCHITECTURE.md` §6 rather than
  reported as zero.
- **STOP conditions:** none triggered. No corroborated memory-safety defect,
  ABI regression, weakened detector or newly unsafe safe-API was found.

## 7. What this does not establish

- **No refinement relation is established.** Four of five edges are `NONE` or
  `PARTIAL`, and no edge is `DISCHARGED`.
- **A proof in a model is not a proof about the binary.** The only level-5
  result is a build-identity digest; no object-code correspondence exists.
- **A passing differential court is not a refinement proof.** It is bounded to
  its population and its harness.
- **A reachability closure is not a `SAFE_COMPATIBLE` promotion.** Both closures
  report `safe_compatible: false`, and the b85c graduation is `NOT_ESTABLISHED`.
- **The anti-implementation-shaped guard checks naming, not truth.** A
  specification that rephrases the implementation in different words passes.
- **The finding is not a repair.** The five nonconforming documents are recorded
  and left unchanged, each with what would close it.
- **Population completeness is `UNKNOWN`.** There is no frozen expected manifest
  of levels, edges or specification documents.

## 8. Commands

All Python ran in the court:

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 OPENSSL_RS_COURT_MEM=6g \
OPENSSL_RS_COURT_MEMSWAP=6g bash docker/openssl-rs-court.sh exec sh -c '
  cd /work &&
  python3 -m json.tool evidence/etp-t3/REFINEMENT.json >/dev/null &&
  python3 -m json.tool evidence/etp-t3/SPECIFICATIONS.json >/dev/null &&
  python3 forensics/tools/etp_t1_seed.py &&
  python3 -m json.tool evidence/etp-t1/TRACEABILITY.json >/dev/null &&
  python3 forensics/tools/traceability.py validate &&
  python3 forensics/tools/spec_guard.py check &&
  python3 forensics/tools/spec_guard.py self-test &&
  python3 forensics/tools/tests/test_spec_guard.py &&
  python3 forensics/tools/tests/test_traceability.py'
```
