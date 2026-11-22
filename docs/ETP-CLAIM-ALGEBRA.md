# ETP claim algebra — typed claims as a conjunction of obligations

Status: normative for ETP-1 of `docs/ETP-TODO.md`.
Type: `openssl-rs/etp/claims/v1` (`evidence/etp/claim.schema.json`).
Implementation: `forensics/tools/etp_claims.py`.
Typed inventory: `evidence/etp/claims.json`.
Tests: `forensics/tools/tests/test_etp_claims.py`.

This document defines the claim type, the operations the assurance programme
uses, and the refusals the validator must make. It is the normative reference
for every later ETP item that writes, reads, combines, invalidates or
adjudicates a claim.

The governing rule is denial by default: **a claim that the schema cannot
express is not a claim.** A verifier that cannot evaluate a claim must refuse;
it may not pass it, and no authority may promote a refused claim by
declaration.

---

## 1. The rule that no axis implies another

A claim is a record of distinct, orthogonal axes. The type deliberately has no
derived field, no weighting, no ranking, no confidence value and no score. The
following statements are therefore true by construction:

- a `property` does not imply a `modality`;
- a `modality` does not imply a `verdict`;
- a `verdict` does not imply a different `modality`, a `reproduction` status,
  or a §7 graduation state;
- `BINARY_REFINEMENT_VERIFIED` does not imply `SAFE_COMPATIBLE`;
- an exact `identity` binding does not imply that the bound bytes were executed;
- a present `evidence` file does not imply that its content supports the
  `interpretation`;
- `TESTED` with an open obligation does not carry a graduated verdict;
- a stronger member of a cohort cannot hide a weaker or blocked member.

The type enforces this mechanically: the schema is closed
(`additionalProperties: false` on every object), so an extra field that could
be read as a combined strength is a schema violation; the pre-scan refuses the
known score and ranking key names outright; and no operation in this document
consumes `measure` as a number.

## 2. The axes

Every claim carries all of the following. Each axis is required and each has a
distinct role.

| axis | field | meaning | what it cannot do |
|---|---|---|---|
| property | `property` | what is asserted: identity, provenance, compatibility, memory-safety, timing, cryptographic-assurance, reproducibility, consumer-graduation, claim-governance | it selects the threat-model requirement; it never strengthens evidence |
| interpretation | `interpretation` | the operational meaning of the assertion in this scope | prose is never evidence |
| quantification | `quantification` | universal / existential / statistical / enumerated, the population, and an opaque `measure` | a measure is not a score and is never combined |
| scope | `scope` | the exact code, artefact, ABI surface or consumer family, with explicit exclusions | a location list does not establish coverage completeness |
| threat / leakage model | `threat_model` | the adversary and observation model under which the claim is asserted | required for security-relevant properties; never establishes adequacy |
| source identity | `identity.source` | candidate, commit, binding state and tree digest | an exact binding does not prove execution |
| build identity | `identity.build` | toolchain, profile, target | a null build identity is an unstated premise, not a default |
| artefact digests | `identity.artefacts` | labelled digests, with a path where one exists | a label and a digest do not identify the producing toolchain |
| authority | `authority` | the OpenSSL authority version or other normative source | a normative source is not measured evidence |
| target | `target` | the object the claim is about | the target is not the scope |
| assumptions | `assumptions` | named premises, each with an independently checkable procedure | an assumption is never discharged by the claim that uses it |
| evidence | `evidence` | artefacts with type, path, digest class, presence and reconstructability | presence is not support |
| TCB | `tcb` | compiler, linker, loader, instruments, unverified dependencies | `verified: false` is honest; qualification is ETP-3's job |
| obligations | `obligations` | open items that block a verdict or a graduation until settled | an open item never silently lowers a verdict, and is never hidden |
| invalidation dependencies | `invalidation` | the exact identities whose change invalidates the claim | a dependency does not assert equivalence |
| modality | `modality` | `DOCUMENTED`, `IMPLEMENTED`, `TESTED`, `INSTRUMENTED`, `PROOF_OBLIGATIONS_DISCHARGED`, `BINARY_REFINEMENT_VERIFIED` | modalities are not ranked and imply no verdict |
| reproduction | `reproduction` | `NOT_ATTEMPTED`, `ATTEMPTED`, `REPRODUCED`, `FAILED`, `UNKNOWN`, `NOT_APPLICABLE`, with procedure and identity | reproduction is not correctness |
| verdict | `verdict` | `UNKNOWN`, `REFUTED`, `CONTRADICTED`, `NOT_ESTABLISHED`, `ESTABLISHED`, `SAFE_COMPATIBLE`, `PARTIAL`, `SUPERSEDED`, `WITHDRAWN` | no verdict implies any other axis's strength |

`contradiction` is present exactly when the verdict is `CONTRADICTED`, and
`closure` exactly when the verdict is `SAFE_COMPATIBLE`. Both conditions are
encoded in the schema.

### 2.1 `measure` is an observation, not a score

`measure` carries `form` (`count`, `ratio`, `set`, `boolean`, `digest-list`), a
string `value`, and the constant `"aggregation": "forbidden"`. The string form
is deliberate: no tool can average two axes by accident. The validator refuses
a measure whose aggregation is not forbidden, and the pre-scan refuses
`score`, `weight`, `confidence`, `modality_rank`, `modality_order`, `ranking`,
`aggregate`, `composite`, `grade` and `level_score` anywhere in a claim
document.

### 2.2 `PARTIAL` is a verdict, not a level

`PARTIAL` records that the cited population is partly established and that
named obligations remain. It is not a numeric level and is not averaged with
anything. The conjunction operation uses a fixed meet over the verdicts; no
operation produces a new value between two verdicts.

## 3. The algebra

### 3.1 Conjunction without aggregation

A cohort's verdict is the **meet** of its members' verdicts and the **union**
of their open obligations. The meet is fixed as follows:

1. If any member is `CONTRADICTED`, `REFUTED`, `WITHDRAWN` or `SUPERSEDED`,
   the cohort takes the first of those four in that order. These verdicts are
   absorbing: a stronger neighbour cannot hide them.
2. Otherwise the cohort takes the weakest member under the order
   `UNKNOWN < NOT_ESTABLISHED < PARTIAL < ESTABLISHED < SAFE_COMPATIBLE`.
   `UNKNOWN` is weakest because an unevaluable member is a refusal, and a
   refusal may not be combined into a stronger result.

The result also returns `members` (every member's own verdict and modality),
`blocked_by` (every member with an open obligation or a verdict below
`ESTABLISHED`), `weakest` (the members at the meet) and the obligations by
name. There is no summarised strength, no percentage and no count of "passing"
members that could stand in for the decision.

### 3.2 Invalidation

A claim names its invalidation inputs in `invalidation.depends_on`. The
operation is conservative:

- a changed identity invalidates a claim when it matches a named dependency,
  a cited evidence path, an evidence digest, the source commit or candidate,
  a tree digest, an artefact label or digest, the authority path, or the
  target path;
- invalidation then propagates transitively over claim-to-claim
  `depends_on` edges;
- no non-impact is inferred. Only a change confined to a path proven not to be
  an input preserves the claim, and the algebra does not attempt that proof:
  an unprovable non-impact invalidates.

The output separates direct from transitive invalidation, so a dependent can
be inspected rather than assumed.

### 3.3 Obligation propagation

An open obligation on a dependency propagates to every dependent, and then to
that dependent's dependents, until the graph is exhausted. Propagation stops
on an edge only when the obligation carries an exclusion that names the
dependent, states an argument, and names an independently checkable
procedure. An empty argument or an uncheckable procedure does not stop
propagation and is itself a refusal (`EG_EXCLUSION_UNCHECKABLE`).

### 3.4 Contradiction

Two claims with the same `property`, the same `scope.subject` and the same
source candidate and commit, but different verdicts, are a hard error. No
preference, ordering or later timestamp resolves them. A single claim whose
verdict is `CONTRADICTED` must instead name at least two distinct sources in
`contradiction.parties`; both sides are preserved in the record.

### 3.5 Denial by default

An input that fails the schema is refused; it is not partially interpreted. An
unknown property, an unknown verdict, a missing required axis and an
unsupported value all refuse. A document that declares its own acceptance
policy is refused before schema evaluation, with the specific rule
`EG_SELF_DECLARED_POLICY`.

## 4. The validator and its refusals

`forensics/tools/etp_claims.py` validates a document against the closed type
and the cross-field laws. The court image does not contain `jsonschema`, so
the tool implements a self-contained JSON Schema 2020-12 subset (`$ref` to
local `$defs`, `type`, `enum`, `const`, `required`, `properties`,
`additionalProperties`, `items`, `minItems`, `maxItems`, `uniqueItems`,
`pattern`, `minLength`, `maxLength`, `minimum`, `allOf`, `anyOf`, `oneOf`,
`not`, `if`/`then`/`else`, `dependentRequired`). `format` is not interpreted;
the schema does not use it.

Each refusal names the offending JSON pointer, the field and the rule. Output
is sorted by `(path, rule, detail)` and serialised with sorted keys and fixed
separators, so the same input produces byte-identical output.

### 4.1 Required refusals

| # | refusal | rule |
|---|---|---|
| 1 | a verdict outruns its modality (`DOCUMENTED` + `ESTABLISHED` with no evidence) | `EG_VERDICT_MODALITY` |
| 2 | a graduated verdict with an unresolved obligation | `EG_GRADUATED_WITH_OPEN_OBLIGATION`, `EG_GRADUATED_WITHOUT_CLOSURE` |
| 3 | evidence with neither a path nor a digest, so it cannot be reconstructed | `EG_EVIDENCE_UNRECONSTRUCTABLE` |
| 4 | a security-relevant property with no stated threat model | `EG_THREAT_MODEL_MISSING` |
| 5 | a self-declared permissive acceptance policy | `EG_SELF_DECLARED_POLICY` |
| 6 | an alias or duplicate key presented as two independent pieces of evidence | `EG_EVIDENCE_ALIAS` |
| 7 | a dependency cycle in invalidation | `EG_INVALIDATION_CYCLE` |
| 8 | a modality ranking that would silently promote a claim | `EG_MODALITY_RANKING` |
| 9 | a claim that names two different candidate identities | `EG_MULTIPLE_CANDIDATES` |
| 10 | a cohort whose member list does not cover its population | `EG_QUANTIFICATION_COVERAGE` |

An evidence entry whose `kind` is `commit` and whose `note` names the commit
is a historical revision of a path, not a second independent source; the alias
rule does not merge it with the working-tree entry of the same path. Every
other duplicate path, duplicate id or duplicate digest inside one claim is an
alias.

### 4.2 Additional refusals

| rule | condition |
|---|---|
| `EG_SCHEMA_VIOLATION` | the closed type is not satisfied |
| `EG_EVIDENCE_ABSENT_NO_OBLIGATION` | evidence is absent or not reconstructable and no obligation names it |
| `EG_EVIDENCE_DIGEST_MISMATCH` | a cited digest cannot be re-derived at the stated identity |
| `EG_EVIDENCE_CHECK_UNAVAILABLE` | a cited digest cannot be checked and the document claims one |
| `EG_INVALIDATION_CYCLE` | the claim-level invalidation graph contains a cycle |
| `EG_UNKNOWN_CLAIM_DEPENDENCY` | a claim depends on a claim id that is absent |
| `EG_PARTIAL_NO_OBLIGATION` | `PARTIAL` with no recorded obligation |
| `EG_VERDICT_MISSING_SETTLING_OBLIGATION` | `UNKNOWN` or `NOT_ESTABLISHED` with no open obligation naming what would settle it |
| `EG_CONTRADICTION_PARTIES` | `CONTRADICTED` with fewer than two distinct sources |
| `EG_CONTRADICTION_UNRESOLVED` | two claims share property, scope and identity but disagree |
| `EG_DERIVED_VERDICT_MISMATCH` | conversion changed the recorded ETP-0 verdict |
| `EG_DERIVED_PROPERTY_MISMATCH` | conversion changed the recorded ETP-0 property |
| `EG_ASSUMPTION_UNCHECKABLE` | an assumption has no independently checkable procedure |
| `EG_EXCLUSION_UNCHECKABLE` | an exclusion argument or procedure is absent or vacuous |
| `EG_EXCLUSION_WITNESS_MISSING` | an exclusion has no witness record |
| `EG_EXCLUSION_WITNESS_UNBOUND` | a witness does not name its obligation, candidate or procedure |
| `EG_EXCLUSION_WITNESS_CANDIDATE` | a witness is bound to a candidate the claim does not name |
| `EG_EXCLUSION_WITNESS_SELF_AUTHORED` | a witness reviewer is the claim author, or the claim names no author |
| `EG_EXCLUSION_WITNESS_RESULT_ABSENT` | a witness result is not present, has no digest, or cannot be re-derived |
| `EG_EXCLUSION_WITNESS_DIGEST` | a witness result's bytes do not match its recorded digest |
| `EG_JSON_DUPLICATE_KEY` | a claim document repeats an object key |
| `EG_JSON_NON_FINITE` | a claim document carries `NaN` or `Infinity` |
| `EG_JSON_MALFORMED` | a claim document is not parseable JSON |
| `EG_MEASURE_AGGREGATION` | a measure does not declare aggregation forbidden |
| `EG_DUPLICATE_CLAIM_ID` | two claims share an id |
| `EG_AUTHORITY_MISSING_VERSION` | an OpenSSL authority claim names no version |

### 4.2.1 Admitted exclusion witnesses

An exclusion argument and a non-placeholder `checkable_by` establish only that an
explanation was written. The exclusion is admitted only when it carries a
`witness` record that binds:

1. the **obligation identifier** the exclusion is about;
2. the **candidate identity**, which must be one of the claim's declared source
   identities;
3. the **verification procedure**;
4. an independently produced **result** with its own path, SHA-256 digest and
   `S`/`E` digest identity, marked present; the tree check re-derives the digest;
5. a **reviewer** whose declared role and identity differ from the claim
   author's. A claim that uses an exclusion must declare an `author`, because
   reviewer independence cannot otherwise be established.

`propagate` applies the same structural admission: an unadmitted exclusion does not
stop an obligation. The CLI validates the document — including re-deriving each
witness result digest — before invoking propagation. The witness proves that a
digest-bound result exists and that the declared reviewer is distinct; it does
not prove organisational independence or that the procedure ran as named.

All operations (`conjoin`, `invalidate`, `propagate`, `contradictions`) validate
the whole document with the schema, laws and Git-bound digest check before
answering. An invalid document is refused with the same rule identifiers as
`validate`; no operation payload is produced from it.

### 4.3 Tree check

With `--check` (the default when no `--no-tree-check` is given), every cited
digest is re-derived: an `S` digest from the Git object at
`source_identity.commit`, an `E` digest from the working tree. A missing or
mismatching derivation is a refusal, not a warning. This is what prevents a
typed claim from citing bytes that the stated identity does not contain.

## 5. Typing the ETP-0 inventory

`evidence/etp/claims.json` types all 35 claims of
`evidence/etp0/CLAIMS.json`. The conversion is recorded per claim in
`derived_from`, including the original id, property and verdict, and the
validator enforces the fixed mapping:

| ETP-0 verdict | typed verdict |
|---|---|
| `SUPPORTED` | `ESTABLISHED` |
| `PARTIAL` | `PARTIAL` |
| `CONTRADICTED` | `CONTRADICTED` |
| `SUPERSEDED` | `SUPERSEDED` |
| `WITHDRAWN` | `WITHDRAWN` |
| `UNKNOWN` | `UNKNOWN` |

No verdict changed. The resulting counts are 17 `ESTABLISHED`, 13 `PARTIAL`,
4 `CONTRADICTED` and 1 `SUPERSEDED`. The four contradictions are preserved
with both sides identified:

| claim | sides | resolution owner |
|---|---|---|
| `ETP0-CLM-004` | seal prose vs the tracked Phase-18 registry | `ETP-T15` |
| `ETP0-CLM-005` | seal prose vs probe source and machine threshold | `ETP-T15` |
| `ETP0-CLM-030` | graduation record vs closure receipts and independent adjudication | `ETP-T15` |
| `ETP0-CLM-032` | campaign counter vs its own non-claim and `PROGRESS.md` | `ETP-T15` |

Claims whose evidence was incomplete gained obligations instead of being
silently downgraded: 33 of 35 claims carry at least one open obligation (90 in
total), including every `PARTIAL` claim and every `ESTABLISHED` claim whose
cited evidence is only partly reconstructable. The five
`assumption_not_stated` gaps became seven named assumptions with checkable
procedures. The 81 cited evidence entries carry 78 digests (77 re-derived from `S`, one from the historical commit read through `git show`);
three cited paths are absent at `S` (`court/tmp/t20/NOTES.md`,
`court/tmp/t21/libcrypto.so.3`, `forensics/phase7_courts.py`) and are recorded
as absent with an obligation each, and one entry is a historical revision whose digest is taken from the
historical Git object it names.

Two representation corrections were required:

- `ETP0-CLM-004` cites `forensics/phase7_courts.py`, but the tracked file is
  `forensics/tools/phase7_courts.py`. The typed claim keeps the cited path and
  marks it absent; the path is not silently rewritten.
- `ETP0-CLM-011` records the commit field as prose (`36fae14be (first), later
  candidates unnamed in the row`). The typed claim records `36fae14be` in
  `identity.source.commit`, keeps the three candidate DSO labels in
  `identity.source.candidate`, and preserves `binding: "multiple"`. The
  prose is not lost: the original ETP-0 record remains the input document, and
  the three-candidate multiplicity is the claim's quantified population.

No claim required a schema change to be represented faithfully. The schema
does not represent a scalar strength, a ranking or a self-declared policy, and
that omission is intentional.

## 6. Identity and evidence freeze

The typed claims are evidence about the ETP-0 candidate
`S = 9372bb28b2fbe2f71cf2aa2ab501414d45e87d42`. `source_identity` is copied
from the ETP-0 freeze; `derived_from` records the digest of the input claim
inventory and trust-gap register and the evidence commit that introduced them.
Adding this document and the typed claims changes only evidence: it does not
move `S`, and every `S` digest is re-derived from the Git object at `S`, so a
later working-tree edit cannot masquerade as the cited bytes. If ETP-2
re-measures at a later candidate, that claim must name the later candidate and
the earlier claim remains a historical record with its own identity.

## 7. What the algebra deliberately does not decide

- whether a cited experiment occurred as described;
- whether an instrument is sensitive to the defect it claims to detect
  (ETP-3);
- whether two different identities are the same source or the same binary;
- whether an authority disagreement is resolved by preference (it is not);
- whether a proof is valid (ETP-T4) or a binary refines its source
  (ETP-T6);
- whether a consumer family graduates under §7 (the closure rule is checked
  for a `SAFE_COMPATIBLE` verdict, but the underlying mechanism discharges are
  ETP-5's and ETP-T15's);
- whether a claim's population is complete beyond a declared enumerated member
  list;
- freshness beyond the named invalidation inputs;
- authorial intent, external review or organisational independence.

These are separate evidence axes. A green validator run is a statement about
the claim's form and its internal laws, not about the truth of its content.

## 8. Running the checker

```
python3 forensics/tools/etp_claims.py validate
python3 forensics/tools/tests/test_etp_claims.py
```

The first command validates `evidence/etp/claims.json` against the schema, the
cross-field laws and the Git-bound digests. The second runs the positive and
negative controls, the determinism checks and the algebra tests.
