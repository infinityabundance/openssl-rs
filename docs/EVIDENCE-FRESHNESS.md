# Evidence freshness — dependency model, invalidation and carry-forward

*ETP-T9. Normative description of `forensics/tools/freshness.py`,
`evidence/etp-t9/DEPENDENCIES.json` and `evidence/etp-t9/HISTORY-RUNS.json`.*

An evidence artefact is a statement about an identity: these bytes, this source
commit, this tool version, this instrument configuration, these upstream
records. It remains true only while those inputs stay still. This repository has
historically carried artefacts forward by convention, and the ETP-0 inventory
found where that failed: eight `evidence_not_reconstructable` gaps, where the
cited inputs exist only in an untracked working tree, and eight
`identity_mismatch` gaps, where a record names a candidate other than the one it
is read as describing. Freshness is computed here from a recorded dependency
model and refused when it cannot be computed. It is never asserted in prose.

The engine decides three separate things, and the separation is the point:

| mode | question | answer |
|---|---|---|
| `record` | what does each artefact depend on? | a registry derived from the tree |
| `check --base A --head B` | what does *this* change set invalidate? | per-artefact verdicts, per-claim refusals |
| `check` (no range, the tree sweep) | is each artefact still true of the tree it names? | fresh / stale / history / unresolved |

`diff --base A --head B` classifies a change set on its own; `diff --runs F`
re-derives a committed multi-range history record.

---

## 1. The dependency model

### 1.1 Dependency kinds

A dependency names *why* a change matters. The set is closed; an unknown kind is
a refusal (`FR_UNKNOWN_DEPENDENCY_KIND`).

| kind | what it is | how a change matches it |
|---|---|---|
| `source_tree` | a crate source path or build input (`src`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml`, `libcrypto.ld`) | the changed path is the entry or lies beneath it |
| `verification_tool` | the tool that produced or checks the artefact, plus the tool's test file as its control | the changed path is the tool or one of its controls; a tool recorded without a usable digest makes the artefact *unresolved* |
| `instrument` | an instrument register entry (`evidence/etp3/instruments.json`) and the harness paths it names | a harness path changed, or the register changed and that entry's canonical bytes differ |
| `path` | a named document, log or data file the artefact reads | the changed path is the entry or lies beneath it |
| `upstream_evidence` | another evidence artefact this one states it re-uses | the upstream artefact is invalidated, unresolved or absent |
| `venue` | the court image, launcher and entrypoint that supplied the environment | any of those paths changed |

`path` matching is by equality or directory containment in either direction. A
rename is treated as a delete plus an add, because the same path at both ends is
the only shape from which non-impact can be concluded mechanically.

### 1.2 `upstream_evidence` is narrower than "mentions another file"

An upstream edge is created only when a field states that evidence is re-used:
`inventory_path`, `receipt_path`, `ledger_record`, `artifact_rel`, `freeze`,
`digests_source`, `previous_record`, `document`, `recipe`, or a traceability
node's `source.path`. A bare cross-reference between two records is a `path`
dependency: it invalidates on change, but it does not create transitivity.
Without that distinction two mutually-referencing records — a freeze that names
a campaign status, and a status that names the freeze — form a dependency cycle
that means nothing about evidence derivation. Cycles are still refused
(`FR_DEPENDENCY_CYCLE`) when one exists; the narrower rule is what keeps the
graph a derivation graph.

### 1.3 The population

The population is derived, not listed. An artefact is in scope when it is a
tracked file under `evidence/`, `courts/` or `artifacts/` with a `.json`, `.md`
or `.txt` suffix, plus every path a typed claim or a traceability evidence node
cites, subject to:

| exclusion | reason recorded in the registry |
|---|---|
| `evidence/etp-t9/**` | this item's own registry and receipt; a dependency model cannot contain itself |
| `evidence/etp5/probes/**` | generated probe sources, rebuilt by `run_probes.py` |
| path contains `/raw/` or `/fixtures/` | raw campaign payloads and fixtures |
| file larger than 512 KiB | artefact size bound |
| `docs/**` cited by a claim | a normative document is a claim dependency, not an evidence artefact; `docs_consistency.py` owns its internal consistency |

Every exclusion is written into the registry with its reason, so the omitted
population is visible rather than implied.

At `26c127262` the population is **331 artefacts** carrying **5,183 dependency
edges** — 3,880 `path`, 570 `source_tree`, 570 `venue`, 103 `upstream_evidence`,
48 `verification_tool`, 12 `instrument` — and 387 advisory citations. 228 paths
are excluded: 189 for the size bound, 25 raw campaign payloads, fixtures or
generated probe sources, 12 normative documents cited as claim or traceability
inputs, and 2 files of this item's own registry. The registry names the commit it
was derived at, so a reader can re-derive it.

### 1.4 Identity

An artefact's identity is the tree it was taken at. It is read from the
artefact's own structured fields in a fixed precedence order
(`source_identity.repository_head`, `source_identity.commit`, `identity.commit`,
`source_head`, `repository_head`, `head_at_start`, `head_at_adjudication`,
`evidence_source_head`, `source_commit`, `recorded_at_commit`, `commit`,
`bound_commit`), at any depth up to three.

- **Several identities at equal precedence** are recorded as an array and marked
  ambiguous. The engine evaluates all of them; it does not pick the convenient
  one.
- **A prose receipt** with no structured identity falls back to a recorded
  heuristic: an explicit `commit`, `head`, `bound to`, `at S` or `S =` mention in
  the first eighty lines. The result is labelled `heuristic-prose` and is
  advisory, not authoritative.
- **An artefact with no identity** is not given one. Its last-modifying commit is
  recorded as `provenance` with the rule stated: a provenance commit is an upper
  bound on when a file was written, never the tree it was measured on.

At `26c127262`: 77 artefacts carry a structured identity, 23 a prose identity,
and **231 name no identity at all**. That last figure is the ETP-0 finding stated
as a number: most of the tree's evidence does not say what it is evidence about.
Those 231 are triaged once into `DERIVED`, `DECLARED`, `HISTORICAL` or
`UNCERTIFIABLE` (§7); the registry itself is not rewritten.

### 1.5 Derived and declared

| part | status |
|---|---|
| population, subject to the recorded exclusions | derived from the tree and from the claim and traceability documents |
| identity, ambiguity, provenance | derived from the artefact's own fields and from Git |
| dependencies | derived from structured path/tool/instrument fields, the citing claims' `scope.locations` and `invalidation.depends_on`, traceability evidence nodes, and the instrument register |
| build-input and venue closures | derived from the artefact's declared identity: an artefact that names a tree depends on the whole crate input closure |
| absent citations | derived: every structured path the tree does not contain is recorded with `present: false` and exposed as `absent_dependencies` in the tree sweep |
| advisory citations | derived from prose backticks; recorded, never an authority |
| the history record's registry binding | derived: the registry path is repo-relative and its SHA-256 is recorded |
| population exclusions | declared, one reason each |
| carry-forward declarations (`HISTORY`, `PRESERVATION`) | declared, validated, and refused when malformed |
| the preservation procedures | declared in this document and implemented in the tool |

### 1.6 What is deliberately not a dependency

A path named only in running text is a **citation**, not a dependency. It is
recorded with a `present` flag so a reader can see whether the prose points at a
tracked file, but it never invalidates anything. Reading prose for dependencies
would make the model unverifiable, and an unverifiable model is worse than an
incomplete one: it would look complete.

---

## 2. Invalidation

### 2.1 Matching

A change set is a list of `(status, path)` rows from `git diff --name-status`
between two commits, or a caller-supplied path list. Each artefact dependency is
matched against it by kind, as in the table above. A match is a **direct**
invalidation.

### 2.2 Causality: evidence taken after the change is not invalidated

A change invalidates evidence only if the evidence predates it. If the
artefact's identity commit is the change's head or a descendant of it, the change
is already part of what the artefact measured, and the artefact is reported
`UNAFFECTED` with that argument. An unresolvable or unrelated identity is *not*
treated as incorporating the change: it falls through to the conservative path.
The same rule is applied to claims through their `identity.source.commit`.

This matters: without it a mid-history commit appears to invalidate every later
receipt, which is noise that hides the real finding. The tree sweep applies one
change set per artefact, from that artefact's own identity to the scanned head.
Because it evaluates the whole registry over that range, an upstream artefact
whose own identity is later than the dependent's is assessed over the dependent's
wider range; that can over-invalidate, never under-invalidate, and an
over-invalidated artefact is reported stale rather than certified.

### 2.3 Transitivity

Two propagation paths, kept distinct in the output:

- **evidence**: an artefact whose `upstream_evidence` is invalidated, unresolved,
  absent, unmodelled or declared explicit history is invalidated or unresolved,
  and the relation is transitive. A dependent that re-uses an artefact the model
  cannot evaluate, or one excluded as history, is never reported `UNAFFECTED`:
  nothing about it was shown to be current.
- **claims**: the claim algebra's own invalidation edges
  (`forensics/tools/etp_claims.py`, imported by path — never reimplemented). The
  changed paths, their ancestor directories and the invalidated artefact paths
  are passed as tokens; a claim is invalidated when a token matches a dependency
  it names, and invalidation then propagates over claim-to-claim `depends_on`
  edges. Direct and transitive-only invalidation are reported separately.

### 2.4 Unresolved is not unaffected

A dependency is **unresolved** when it cannot be evaluated:

- a tool recorded without a usable digest (`UNKNOWN` or absent);
- a cited path that is not tracked in this tree (`present: false`) — the ETP-0
  `evidence_not_reconstructable` class;
- an instrument with no recorded register-entry digest;
- an artefact with neither a declared identity nor a modelled dependency.

An unresolved artefact is never reported as unaffected. In change-set mode it is
counted and listed but does not gate, because it is a pre-existing property of
the artefact; in the tree sweep it is refused (`FR_IDENTITY_UNKNOWN` or
`FR_DEPENDENCY_UNRESOLVED`). The engine does not infer that a dependency it cannot
see is unchanged.

The tree-sweep record also names the absent citations directly:
`absent_dependencies` lists every structured path with `present: false`, and
`modelled_dependencies` gives the size of the edge set. That field is what makes
the ETP-0 `evidence_not_reconstructable` class visible for an artefact that names
no identity, where the verdict alone would be only `FR_IDENTITY_UNKNOWN`. At
`26c127262` **55 artefacts** carry **341 absent-citation edges** over **298
distinct paths**; 124 of those paths are under `court/tmp/`.

### 2.5 Two scopes, kept apart

Change-set mode answers only what *this* change set caused.

A **change-caused** reason gates a current claim:

- a dependency of the evidence moved in the change set;
- the claim algebra invalidates the claim from the change set;
- the change set modifies or removes a path the claim cites as evidence;
- a dependency claim is invalidated and propagates over the claim edges.

A **pre-existing** condition is reported in `claims.preexisting` and does not
gate a change set: an artefact that never named an identity, a dependency that
was already unresolved, a file that was already absent, or an artefact with no
modelled dependency. A history declaration that a current claim still cites is
reported in `claims.history_cited_as_current`. The tree sweep is where those
gate, because they are properties of the tree rather than of the change. Without
this split an unrelated commit would be blamed for every existing gap.

The separation is explicit in the output. `verified_current` names only current
claims with neither a change-caused finding nor a pre-existing reason;
`not_verified_current` names every current-claim candidate that has one of
either. A pre-existing failure is therefore not silently counted as current, and
a modified evidence file is a change-caused reason even when the artefact also
has a pre-existing gap.

### 2.6 Refusing a claim presented as current

A claim whose verdict is not `WITHDRAWN`, `SUPERSEDED`, `REFUTED` or
`CONTRADICTED` is presented as current. In change-set mode such a claim is
refused (`FR_CLAIM_EVIDENCE_STALE`) when:

- the claim algebra invalidates it from the change set;
- evidence it cites is invalidated by this change set;
- this change set modifies or removes evidence it cites. A modified file is a
  change-caused reason, not a pre-existing one: its bytes at the head are not the
  bytes the claim cited.

`PARTIAL` claims are included: a partial verdict is still a current assertion.
Claims already withdrawn, superseded, refuted or contradicted are reported as
findings and do not gate, because invalidating them changes nothing.

---

## 3. Carry-forward

A stale artefact may remain in the tree in exactly two ways. Anything else is
refused (`FR_CARRY_FORWARD_UNDECLARED` in the tree sweep).

### 3.1 Explicit history

```json
{"artefact": "PATH", "kind": "HISTORY",
 "identity": {"commit": "..."}, "basis": "..."}
```

The commit named must resolve. The artefact is excluded from current claims, and
a current claim that cites it as evidence is refused
(`FR_HISTORY_CITED_AS_CURRENT`). A withdrawn or superseded claim that cites it is
not refused.

### 3.2 Verified preservation argument

```json
{"artefact": "PATH", "kind": "PRESERVATION", "argument": "...",
 "procedure": "comment_only",
 "concerned_paths": ["..."], "assumes_unchanged": ["..."],
 "evidence": [{"path": "...", "sha256": "..."}]}
```

Every field is required. `concerned_paths` and `assumes_unchanged` must name
dependencies of the artefact, so an argument about some other file is refused
(`FR_PRESERVATION_INCOMPLETE`). `assumes_unchanged` and `concerned_paths` are
both checked against the change set: an argument that assumes away a touched
file is refused (`FR_PRESERVATION_TOUCHED`). The argument's own evidence must be
tracked at the head and match its recorded digest
(`FR_PRESERVATION_UNEVIDENCED`).

A touched dependency the argument does not mention is unaccounted for and is
refused (`FR_PRESERVATION_INCOMPLETE`). For `comment_only` every touched
dependency must be named in `concerned_paths`, and every touched concern must be
a language in the admitted line-comment set; for
`instrument_register_unchanged` no touched dependency may lie outside the
instrument register. `narrowed_scope_untouched` and `blob_identical` carry a
wider declared premise — the concern is asserted to be the complete set — and are
not given that coverage guard; their limits are stated in the table.

The procedure is a member of a closed set and is **executed**, not read:

| procedure | what it proves | what it does not prove |
|---|---|---|
| `comment_only` | every added and removed line in each concerned file is empty or a line comment for a language that has line comments (`.rs`, `.c`, `.h`), and the file contains no block comment and no raw-string opener at either identity | that comments are semantically inert for macro expansion, or anything about a language outside the admitted set |
| `narrowed_scope_untouched` | a coarse dependency is wider than the concern the artefact actually analysed, and no concerned path was touched | that the declared concern is the *complete* set of files the property depends on |
| `instrument_register_unchanged` | the instrument register's bytes are identical at both identities | that an instrument is qualified for a use (ETP-3) |
| `blob_identical` | every assumed path has identical bytes at both identities | anything about a path whose bytes differ |

A procedure name outside the set — including any free-text explanation, and
including "no test covers this" — is refused
(`FR_PRESERVATION_UNDECIDABLE`). Non-impact is a proof obligation; it is not a
sentence. A bare path list (`check --paths`) has no base identity, so no
procedure can be executed against it and preservation is refused there.

---

## 4. Refusal rules

| rule | meaning |
|---|---|
| `FR_SCHEMA` | the registry or an artefact record is malformed |
| `FR_DUPLICATE_ARTEFACT` | two records claim the same path |
| `FR_UNKNOWN_DEPENDENCY_KIND` | a dependency kind outside the closed set |
| `FR_DEPENDENCY_CYCLE` | a cycle over `upstream_evidence` edges |
| `FR_DECLARATION_INVALID`, `FR_DECLARATION_UNKNOWN_TARGET` | a carry-forward declaration that is malformed or names no artefact |
| `FR_ENGINE_SELF_DECLARED_POLICY` | the registry declares its own acceptance policy |
| `FR_EVIDENCE_INVALIDATED` | a dependency matches the change set |
| `FR_EVIDENCE_TRANSITIVE` | an upstream artefact is not current |
| `FR_DEPENDENCY_UNRESOLVED` | a dependency cannot be evaluated |
| `FR_EVIDENCE_ABSENT` | a recorded artefact is absent at the head |
| `FR_EVIDENCE_SUPERSEDED` | the artefact's bytes differ from the recorded digest |
| `FR_CARRY_FORWARD_UNDECLARED` | a stale artefact with neither explicit history nor a verified preservation argument |
| `FR_NO_MODELLED_DEPENDENCY` | no dependency is modelled and no identity is declared, so non-impact cannot be established |
| `FR_PRESERVATION_INCOMPLETE`, `FR_PRESERVATION_UNEVIDENCED`, `FR_PRESERVATION_TOUCHED`, `FR_PRESERVATION_FAILED`, `FR_PRESERVATION_UNDECIDABLE` | the preservation argument is malformed, unevidenced, contradicts the change set, fails its own procedure, or is not a procedure |
| `FR_IDENTITY_UNKNOWN` | the artefact names no usable identity, so freshness cannot be established |
| `FR_HISTORY_CITED_AS_CURRENT` | an explicit-history artefact is cited as current evidence |
| `FR_CLAIM_EVIDENCE_STALE` | a claim presented as current rests on evidence this change invalidated or removed |

The engine fails closed: `check` exits non-zero when any refusal is present, and
`diff --runs` exits non-zero when a committed history record is not reproducible
from the current registry.

---

## 5. What the engine reports at `26c127262`

Not a summary of anything; each figure is a list in the output that can be read.

| | |
|---|---|
| tree sweep | 331 artefacts: **90 stale**, 2 explicit history, 10 unaffected, **229 unresolved** |
| tree sweep refusals | 340: 90 `FR_CARRY_FORWARD_UNDECLARED`, 229 `FR_IDENTITY_UNKNOWN`, 17 `FR_CLAIM_EVIDENCE_STALE`, 4 `FR_HISTORY_CITED_AS_CURRENT` |
| stale and cited by a claim | 50 artefacts |
| claim findings | 12 claims, of which the current-verdict subset is refused; `not_verified_current` names 15 current-claim candidates |
| stale receipts | 7 `RECEIPT` artefacts, each by a `source_tree` edge (`src` or `Cargo.lock`) |
| source change (`0eddfe839`) | 97 artefacts invalidated, 8 claim findings of which 5 are current and refused, 102 refusals |
| tool change (`3951f0f5e`) | 15 artefacts invalidated, 3 claim findings all current and refused, 18 refusals |
| evidence-only change (`8a697aa7e`) | nothing invalidated, no refusal |
| tool-control change (`3ddab71a8`) | 2 artefacts invalidated, 0 claim findings, 2 refusals |

The engine does **not** reproduce all eight `evidence_not_reconstructable` gaps as
their own conditions, and it does not decide the `identity_mismatch` class.
Six of the eight have a mechanical witness in the registry: `009`, `010` and
`037` through an absent structured citation of `court/tmp/t20/NOTES.md`,
`artifacts/phase2/libcrypto.so.3` and `artifacts/phase2/shell/libcrypto.shell.rs`;
`011` through O9's absent `/tmp/o9-*.log`; `012` through the absent
`court/freeze-b85*` generators; and `008` in aggregate through 124 absent
`court/tmp/` paths (its three named artefacts are outside the population). `013`
and `014` are not reproduced: their inputs are named only in prose, so the engine
reports `FR_IDENTITY_UNKNOWN` rather than the gap's condition. For the eight
`identity_mismatch` gaps, `018`, `020`, `023` and `025` are surfaced as
`UNRESOLVED` — the precondition of a mismatch, not the mismatch itself; `019` and
`024` are represented only by declared `HISTORY` records derived from the gaps;
`021` is outside the population; and `022` is a field-value defect, not a
freshness question. `evidence/etp-t9/RECEIPT.md` carries the per-gap mapping.

---

## 6. Non-claims

The engine does **not** establish:

- that a cited experiment occurred, or occurred as described;
- that a claim is true. A green `check` over a change set says the change set did
  not invalidate anything the model records; it does not say the evidence is
  correct;
- that the dependency model is complete. A missing dependency makes the engine
  under-invalidate, and the model is a reviewable declaration for exactly that
  reason. The measured shape of that incompleteness is in the counts: 231
  artefacts name no identity, 112 have no modelled dependency, and 55 carry 341
  absent-citation edges;
- that the tree sweep is free of false stales. It evaluates one change set per
  artefact from that artefact's identity to the scanned head, and evaluates the
  whole registry over that range, so an upstream whose identity is later than the
  dependent's is assessed over the dependent's wider range. That can
  over-invalidate, never under-invalidate; an over-invalidated artefact is
  reported stale rather than certified;
- that an instrument is sensitive to the defect it claims to detect (ETP-3), or
  that a tool version is qualified for a use;
- that two different identities are the same source or the same binary. The
  engine reports an unresolved identity; it never equates two identities;
- that a preservation argument is sound beyond its stated procedure. The
  `comment_only` procedure does not model macro expansion, and no procedure in
  the set reasons about semantics;
- that a claim's population is complete, or that an artefact not in the
  population is irrelevant;
- freshness for an artefact that remains `UNCERTIFIABLE` after identity triage
  (§7). That is reported as unresolved, which is a refusal to certify, not a
  pass; a `DECLARED` or `DERIVED` identity is the artefact's own statement and
  is checked only for resolvability, not for truth.

A path named in prose is not a dependency, a source-level argument is not a
proof, and an absent test is not evidence of non-impact.

---

## 7. Identity triage (follow-up, 2026-11-23)

`freshness.py triage` derives a class for every artefact the registry leaves
unbound and writes `evidence/etp-t9/IDENTITY-TRIAGE.json`, bound to the
registry's `recorded_at_commit`. The classes are closed:

| class | meaning | identity |
|---|---|---|
| `DECLARED` | the artefact names the tree it was taken at in a named field | that commit, if it resolves |
| `DERIVED` | a recorded derivation rule establishes the tree | a digest-bound freeze record, or the registry's tree for a tracked harness input |
| `HISTORICAL` | a record of one moment | the commit it was introduced at, or the frozen commit it declares |
| `UNCERTIFIABLE` | no identity can be established or honestly declared | none; the record carries a cause and what would make it certifiable |

`check` loads the document as an overlay (`triaged_registry`), never mutating
the committed registry:

- a `DECLARED` or `DERIVED` identity is used in place of the missing one;
- a `HISTORICAL` artefact is `HISTORY`, is excluded from current claims, and a
  current claim citing it is refused (`FR_HISTORY_CITED_AS_CURRENT`);
- an `UNCERTIFIABLE` artefact is `UNRESOLVED` with `FR_IDENTITY_UNCERTIFIABLE`
  in both change-set and tree mode, and inherits no identity from an upstream
  artefact. In change-set mode this is a pre-existing condition (§2.5): it does
  not gate the change set, but the artefact is not `UNAFFECTED` and a claim
  citing it is not `verified_current`.

The triage is a required item: an absent document is `FR_TRIAGE_MISSING`; one
bound to another registry, missing a required record, carrying a class outside
the set, or reporting counts that disagree with its records is `FR_TRIAGE_STALE`
or `FR_TRIAGE_SCHEMA`. `release_gate.py` consumes the same document and refuses
a current claim whose required evidence is `UNCERTIFIABLE`
(`RG_CLAIM_UNCERTIFIABLE_EVIDENCE`) or `HISTORICAL`
(`RG_CLAIM_HISTORICAL_EVIDENCE`), naming the artefact.

The triage does not establish that a declared identity was the tree a
measurement used, that a derived freeze record was honest, or that a
`UNCERTIFIABLE` artefact is irrelevant. It establishes only which artefacts can
be certified current at all, and refuses the rest by name. The measured
population at `26c127262` is in `evidence/etp-t9/IDENTITY-TRIAGE.md`.
