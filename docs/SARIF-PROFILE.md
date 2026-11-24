# SARIF 2.1.0 interoperability profile (A1)

Status: **normative for every SARIF artefact this project emits**. Delivered by
item **A1** of `docs/ETP-TODO.md` §E. Producer:
`forensics/tools/sarif_adapter.py`. Controls:
`forensics/tools/tests/test_sarif_adapter.py`. Emission:
`evidence/a1/SARIF.json`, receipt `evidence/a1/RECEIPT.md`.

A profile is a constraint on an emission, not evidence about the code analysed.
Nothing here is a memory-safety, cryptographic or compatibility claim; those are
governed by §§8–20 of `AGENTS.md` and by `docs/EARNED-TRUST.md`.

## 1. Specification and version

| item | value |
|---|---|
| format | SARIF **2.1.0 plus Errata 01** |
| `sarifLog.version` | `"2.1.0"` (the only value the 2.1.0 schema accepts) |
| `sarifLog.$schema` | `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json` |
| citation | `[SARIF-v2.1.0-Errata01]`, OASIS Standard incorporating Approved Errata, 28 August 2023 |

Consulted at the point of use on 2026-11-23, at
`https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html`:
§3.4 (`artifactLocation`), §3.10 (URIs), §3.13 (`sarifLog`), §3.14 (`run`),
§3.19 (`toolComponent`), §3.20 (`invocation`), §3.24 (`artifact`), §3.27
(`result`), §3.28–§3.33 (`location`, `physicalLocation`, `region`, `address`,
`logicalLocation`), §3.49–§3.50 (`reportingDescriptor`,
`reportingConfiguration`), §5 (conformance), Appendix B (normative,
fingerprints), Appendix F (deterministic output), Appendix I (incomplete result
sets).

Errata 01 is applied where it changes what a conforming log may contain; the
document is cited as a whole because the profile does not re-derive the errata
list.

**Two conventions are deliberately not followed to the letter**, and the reason
is Article 1 rather than convenience:

- `region.endLine`/`region.endColumn` are never emitted. Their schema defaults
  would assert an extent the native record does not record. A line-only region is
  `{"startLine": L}`; the profile marks it with
  `properties.a1.locationPrecision = "line"`, and §8.4 states that the default
  column extent is **not** a recorded claim.
- `run.columnKind` is emitted (required by §3.14.27 when text artifacts are
  processed and results are non-empty) as `"unicodeCodePoints"`, but **no column
  value is emitted anywhere**. The declared unit therefore has no effect on any
  emitted number; recorded column numbers are preserved verbatim under
  `properties.a1.native.fields.column` with
  `properties.a1.native.fields.columnUnit = "not-recorded"`.

## 2. What the profile covers, and what it does not

Covered: the shape of an emitted log, the three identities and their
fingerprints, the location rules per finding class, the mechanical assignment of
`ruleId`/`kind`/`level`, the refusal conditions, determinism, and what a consumer
may and may not infer.

Not covered — these belong to other queue items and are named here so that a
reader does not mistake this profile for them:

| concern | owner | how it attaches to A1 |
|---|---|---|
| lossless preservation of original output, arguments, timeouts, unsupported operations, native populations | **A2** | A1 records the native record path, its SHA-256, the JSON locator and the projected/not-projected population. A2 owns the raw bytes and the reconciliation of the native and exported populations. |
| rule / logical / exact identity as a project-wide model | **A3** | A1 defines the scheme the profile emits; A3 owns the cross-artefact model and its joins. |
| Rust/FFI/binary location fidelity across macro expansion, monomorphisation, indirect dispatch and optimised code | **A4** | A1 states per-class rules for the classes it emits (§7); no macro-expanded or monomorphised finding occurs in the A1 emission, and the class rule is stated without an instance. |
| expected-versus-examined population, skips, truncation admission | **A5** | A1 emits every truncation the native record records, with its bound and its omitted count. A1 never states that a population is complete. |
| suppression governance | **A6** | A1 never suppresses and never emits `result.suppressions`. A native aggregate that records suppressions without member rows is emitted as a finding whose limitation is that no member location exists (§7.11). |
| baselines and regression tracking | **A7** | A1 emits no `baselineState` and no `run.baselineGuid`; no comparison was performed. |
| GitHub code-scanning export and shard manifests | **A8** | Not emitted; nothing in the A1 profile depends on a hosted consumer. |
| attestation, signing, transparency | **A9–A21** | Out of scope; the SARIF file is not signed and its provenance is the Git object containing it. |

## 3. Emission model: one run per native record

A SARIF `run` is "an invocation of a specified analysis tool on a specified
version of a specified set of analysis targets" (§3.14). The A1 emission therefore
contains **one run per native record**, never one run over several records:

| run id (record path) | native record | candidate identity source |
|---|---|---|
| `evidence/etp-t7/SECRETS.json` | secret classification register | `candidate.commit`, `candidate.branch` |
| `evidence/timing-bn-findings.json` | BN timing/leakage findings | `candidate.source_head`, `candidate.libcrypto.sha256` |
| `evidence/etp-t4/SAFETY-SITES.json` | unsafe-site obligation inventory | `identity.commit`, `identity.source_tree_sha256` |
| `evidence/closure-curl-049.json` | curl closure receipt | `source_identity.repository_head`, `candidate_identity.*_sha256` |
| `evidence/b85c-adjudication.json` | OpenSSH b85c adjudication | `evidence_source_head`, `src_content_sha256` |
| `evidence/b85c-row-reconciliation.json` | b85c reviewer row reconciliation | `source_candidate` |

This is a deliberate correction of a defect class recorded at A0 (`A0-F15`,
`A0-F16`): a file that aggregates records at different source identities into one
attributable object invites the reader to apply one candidate's identity to
another's findings. Runs are ordered by record path; the order is part of the
deterministic emission.

Each run is **refused** rather than emitted when its candidate identity is absent
(§11). A refusal refuses the whole file: emitting the other runs would silently
omit the refused population.

`run.tool.driver` describes the adapter, not an upstream analysis tool: the rule
being evaluated is the projection rule (§4). The native producer, where the record
names one, is carried verbatim at `properties.a1.native.producer`. The adapter
therefore **does not emit `run.conversion`**: the converter object would have to
name a single analysis tool, and five records in this emission name five different
producers or none.

## 4. Mandatory and forbidden fields

### 4.1 Mandatory on `sarifLog` and `run`

| object | field | value / rule |
|---|---|---|
| `sarifLog` | `version` | `"2.1.0"` |
| `sarifLog` | `$schema` | the Errata 01 schema URI in §1 |
| `sarifLog` | `runs` | one run per native record, ordered by record path |
| `run` | `tool.driver.name` | `openssl-rs-sarif-adapter` |
| `run` | `tool.driver.semanticVersion`, `.version` | `1.0.0` |
| `run` | `tool.driver.fullDescription.text` | one sentence naming the native record projected |
| `run` | `tool.driver.rules` | the subset of the closed rule registry (§5) used by this run, sorted by `id`; each entry carries `shortDescription`, `fullDescription`, `defaultConfiguration.level` |
| `run` | `invocations[0].executionSuccessful` | `true` (§3.20.14 requires the field) |
| `run` | `invocations[0].exitCode` | `0` |
| `run` | `columnKind` | `"unicodeCodePoints"` (§1) |
| `run` | `artifacts` | every artifact referenced by a result of this run, sorted by `uri`, each with `location.uri` and, where a digest is recorded, `hashes["sha-256"]` |
| `run` | `results` | present (possibly empty), ordered by the key in §12 |
| `run` | `properties.a1` | `record`, `candidate`, `projection`, `consumerRules`, `fingerprintCollisions` (§4.3) |

### 4.2 Mandatory on every `result`

| field | rule |
|---|---|
| `ruleId` | a member of the closed registry (§5) |
| `ruleIndex` | index of that rule in this run's `tool.driver.rules` |
| `kind` | `"fail"` or `"informational"`, mechanically assigned (§8.2) |
| `level` | `"error"`, `"warning"`, `"note"` or `"none"`, mechanically assigned (§8.1) |
| `message.text` | plain text built from native fields; no claim the record does not contain |
| `partialFingerprints` | `a1Rule/v1`, `a1Logical/v1`, `a1Exact/v1` (§6) |
| `properties.a1.candidate` | the native candidate identity, verbatim |
| `properties.a1.artifact` | `{uri, digestScope, algorithm, digest}` — the artefact the native finding was bound to (§6.3) |
| `properties.a1.native` | `{record, recordSha256, locator, fields}` — `locator` is a JSON pointer into the native record; `fields` holds the native values used, verbatim |
| `properties.a1.levelBasis` | the name of the mapping row that assigned `level` (§8) |

A result may have no `locations`. It must not have an invented one.

### 4.3 Mandatory on `run.properties.a1`

| field | content |
|---|---|
| `record` | native record path and SHA-256 as emitted |
| `candidate` | the candidate block of §3, verbatim from the record |
| `projection` | `nativePopulation` (the totals the record itself declares), `projected` (count per `ruleId`), `notProjected` (`[{block, count, reason}]`), and `sumMatchesPopulation` where the record's own totals permit the check |
| `consumerRules` | the prohibitions of §10, machine-readable |
| `fingerprintCollisions` | number of `a1Exact/v1` values shared by more than one result in this run, plus the full list of collisions when non-zero. Never truncated, never merged. |
| `adapter` | path and SHA-256 of `forensics/tools/sarif_adapter.py` as emitted |

### 4.4 Forbidden fields

These are forbidden in every emission of this profile, and the adapter never
writes them:

| field | reason |
|---|---|
| `run.conversion` | would name one analysis tool as the source of findings from several records; see §3 |
| `invocation.startTimeUtc`, `endTimeUtc`, `machine`, `account`, `processId`, `workingDirectory`, `environmentVariables`, `stdin`, `stdout`, `stderr`, `stdoutStderr` | Appendix F non-determinism; none is needed to interpret a finding |
| absolute file URIs, installation prefixes, host paths | Appendix F §F.4; URIs are relative references with `uriBaseId = "SRCROOT"` |
| `result.suppressions` | suppression governance is A6. An absent `suppressions` means "not available", an empty array means "available and nothing suppressed"; A1 can assert neither. |
| `result.baselineState`, `run.baselineGuid` | A7 owns regression tracking; no baseline comparison was performed |
| `result.rank` | a priority score would be a new fact and is read as a probability (Article 9) |
| `result.fixes` | A1 proposes no repair |
| `result.guid`, `result.correlationGuid`, `run.automationDetails.guid`, `tool.driver.guid` | a GUID not derived from a recorded identity would be invented stability |
| `result.provenance.*TimeUtc`, `result.occurrenceCount` | not recorded, and time-valued |
| `result.taxa` / `run.taxonomies` | no taxonomy is assigned by this profile; categories would be interpretation |
| `region.endLine`, `region.endColumn`, `region.charOffset`, `region.charLength`, `region.snippet` | extent, offsets and content are not recorded verbatim by the native records used here (§1) |
| `logicalLocations` for a construct the record does not name | §7 |

## 5. Rule identity (identity 1)

A rule is a **class of finding**, stable across occurrences and across runs. The
registry is closed and lives in the adapter as `RULES`; a result whose rule is not
in it is a producer defect, not an extension point.

| `ruleId` | class |
|---|---|
| `A1-SECRET-LEAKAGE-REPORTED` | a secret register entry whose recorded instrument result is a leak |
| `A1-SECRET-CLEANSING-UNMET` | a secret-bearing entry whose cleansing obligation is required and not met |
| `A1-SECRET-CONTROL-NO-EVIDENCE` | a secret-dependent control with no recorded evidence |
| `A1-SECRET-CLASSIFICATION-RECORDED` | a public-data or declassification-boundary entry recorded as such |
| `A1-SECRET-EVIDENCE-CONTRACT-ONLY` | a secret-bearing entry whose only evidence is a source contract |
| `A1-TIMING-LEAKAGE-DETECTED` | a BN primitive with a recorded timing/taint leak verdict |
| `A1-TIMING-NOT-RUN` | an analysis the timing record names as not run |
| `A1-UNSAFE-OBLIGATION-UNESTABLISHED` | a caller obligation the inventory records as unestablished |
| `A1-UNSAFE-OBLIGATION-VACUOUS` | a vacuous precondition or an unmet implementer obligation |
| `A1-UNSAFE-OBLIGATION-DELEGATED` | an obligation delegated to a caller or to the documented C ABI |
| `A1-UNSAFE-CONTRACT-ABSENT` | an unsafe site with no contract text |
| `A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT` | an aggregate suppression count with no member rows |
| `A1-ISA-BINARY-UNRESOLVED` | an unresolved indirect transfer in a built artefact |
| `A1-ISA-POPULATION-TRUNCATED` | a bounded/truncated record population |
| `A1-ELEMENT7-PREDICATE` | the curl element-7 blocking predicate |
| `A1-OBLIGATION-DISCHARGED` | a closure obligation the record marks DISCHARGED |
| `A1-OBLIGATION-DISPOSITION-SUPERSEDED` | a superseded conflicting disposition |
| `A1-CLOSURE-VERDICT` | the closure receipt's own verdict block |
| `A1-ADJUDICATION-VERDICT` | an adjudication verdict |
| `A1-ADJUDICATION-REFUTATION` | one ordered refutation ground |
| `A1-ADJUDICATION-MECHANISM` | one mechanism state |
| `A1-ADJUDICATION-CROSS-CUTTING` | the cross-cutting obligation block |
| `A1-RECONCILIATION-ROW` | one reviewer reconciliation row |

Assignment rules:

1. `ruleId` is **opaque and independent of the occurrence**: it never contains a
   path, line, address, candidate or count.
2. `ruleId` never changes when a finding moves, is re-catalogued under a new
   native coordinate, or is re-emitted at a new candidate. A change to a
   `ruleId`'s meaning is a new rule with a new id and a `deprecatedIds` entry for
   the old one; no such change has occurred.
3. `ruleIndex` is per-run and is never used across runs.
4. `rules` is sorted by `id`, so `ruleIndex` is deterministic.
5. A rule's `defaultConfiguration.level` is the level most occurrences of that
   rule take. **Consumers must read `result.level`;** every result sets it
   explicitly, and the default is never a substitute for it.

## 6. Logical and exact identities

Three identities are kept distinct. Conflating them is the failure mode this
section exists to prevent.

### 6.1 Identity 1 — rule

Rule identity is the `ruleId` of §5. Its fingerprint is
`a1Rule/v1 = SHA-256("a1-rule/v1" NUL ruleId)`. Two occurrences of the same rule
in different artefacts share identity 1 and **nothing else**.

### 6.2 Identity 2 — logical finding

The same underlying finding across runs, candidates and code motion. It is a hash
over the rule and a **logical key built only from native fields that do not
depend on location**:

```
a1Logical/v1 = SHA-256("a1-logical/v1" NUL ruleId NUL logicalKey)
```

| class | logical key (native fields) | excluded on purpose |
|---|---|---|
| secret register entry | `id` | path, line |
| BN primitive | primitive name (`BN_mod_exp_mont_consttime`, `BN_mod_inverse`) | DSO offset, size |
| BN analysis not run | the not-run item text, whitespace-normalised | ordinal |
| unsafe obligation (vacuity) | `path`, `symbol`, `status` | line, column |
| unsafe contract-absent site | `path`, `symbol`, `class` | line, column |
| suppression aggregate | the literal `suppressions` | lint names (counts only) |
| curl closure obligation | the record's `stable_id` | recorded `line` |
| curl superseded disposition | obligation id, `boundary`, `receipt` | nothing |
| curl unresolved indirect site | `dso`, `class`, `reason` | function and call-site addresses |
| curl truncation bound | the native field path `precision.residual_sites` | sample size |
| curl element-7 predicate | the native field path `precision.predicate_element_7` | counters |
| closure verdict | the native field path `verdict` | nothing |
| adjudication verdict | the literal `verdict` (one verdict per record) | candidate head |
| adjudication refutation | SHA-256 of the whitespace-normalised refutation text | ordinal |
| adjudication mechanism | mechanism name | obligation counts |
| adjudication cross-cutting block | the native field path `item4_mechanisms.cross_cutting` | nothing |
| reconciliation row | `obligation`, `decision` | `ledger_pointer` (positional) |

Prose-keyed identities hash the record's own text. They are stable while the text
is stable and are **not** a claim that two differently worded refusals are the
same. A reworded refutation is a different logical finding, and the profile says
so rather than normalising meaning away.

### 6.3 Identity 3 — exact occurrence

This location in this artefact at this digest:

```
a1Exact/v1 = SHA-256("a1-exact/v1" NUL ruleId NUL logicalKey NUL
                     subjectUri NUL digestScope ":" digest NUL regionKey)
```

`regionKey` is `line=<L>` for a source region, `byteOffset=<O>;address=<A>` for a
binary region, and `locator=<JSON pointer>` for a record-level finding.

`subjectUri` is the artefact the finding is **about**: the source path, the DSO
name, or the native record path for a record-level condition. `digest` is the
strongest identity the native record binds that artefact to, and `digestScope`
says which:

| `digestScope` | `algorithm` | meaning | used when |
|---|---|---|---|
| `artifact` | `sha-256` | the digest is of the artefact's bytes | DSO findings; the record records the DSO SHA-256 |
| `source-tree` | `sha-256` | the digest is of the whole source tree the finding was scanned from | unsafe-site obligations; a per-file digest is not recorded |
| `candidate-commit` | `sha1-git-object` | a Git object identifier: SHA-1 over the object header and bytes | secret register, closure obligations |
| `record` | `sha-256` | the digest is the native record's own bytes | record-level conditions |

**The algorithm is named, not assumed.** `sha1-git-object` is deliberately not
called `sha-1` so that a 40-hex commit id is not mistaken for a content digest of
a file. A consumer that requires file bytes must not accept either
`source-tree`, `candidate-commit` or `record` as a per-file digest.

**`digestScope` is not decoration.** A consumer that needs the bytes of
`src/x509/v3_info.rs` must not treat `source-tree` or `candidate-commit` as a
per-file digest. The profile forbids that reading; the field makes it visible.

### 6.4 What the fingerprints may not be used for

1. **Never authorise reuse across artefacts.** `a1Logical/v1` may match while
   `a1Exact/v1` differs; the pair is then two occurrences of one logical finding,
   not one occurrence twice. A suppression, discharge, receipt or cache entry
   established for one exact identity never transfers to another.
2. **Never authorise reuse across candidates.** Two runs at different candidate
   identities are different evidence. `properties.a1.candidate` is mandatory on
   every result precisely so that this comparison can be made.
3. **Be conservative on collisions.** When two results in one run share
   `a1Exact/v1`, the adapter emits both and counts the collision at
   `run.properties.a1.fingerprintCollisions`. It never merges, deduplicates or
   drops. A consumer receiving a collision must treat the colliding results as a
   set and require a second discriminator (native locator, message) before
   identifying them.
4. **Never treat a fingerprint as a verdict.** Equal fingerprints do not establish
   that a finding is still true, still reachable, or still open. They establish
   identity, not state.
5. **Never compute a fingerprint over a line number or an absolute address**, in
   either the logical or the rule fingerprint. Appendix B states the reason; this
   profile makes the exact identity (which does contain a location) the only one
   that moves with location.

## 7. Location fidelity per finding class

The rule is: **emit the most precise location the native record actually
records, and name the limitation where it is less than a source line.** No
finding in this emission is assigned a line number that the native record does not
contain.

### 7.1 Source finding with a recorded line

`physicalLocation.artifactLocation` = `{uri: <record path>, uriBaseId: "SRCROOT",
index: <run.artifacts index>}`; `region = {"startLine": L}`.
`properties.a1.locationPrecision = "line"`. Class member: secret register entries,
unsafe obligation rows, contract-absent rows, curl closure obligations.

### 7.2 Source finding with a recorded column

The column is **not** emitted as a SARIF column (§1, §8.4). It is preserved
verbatim at `properties.a1.native.fields.column` with
`columnUnit = "not-recorded"`. Emitting it as `startColumn` would assert a
measurement unit the native record does not state. Class member:
`A1-UNSAFE-CONTRACT-ABSENT`.

### 7.3 Binary finding: function extent recorded

`physicalLocation.artifactLocation` = the DSO; `address = {absoluteAddress: <function
offset>, kind: "function", length: <recorded size>}`; `region = {byteOffset:
<function offset>, byteLength: <recorded size>}`. The two lengths are equal, as
§3.29.2 requires. `properties.a1.locationPrecision = "function-offset-and-extent"`.
Class member: `A1-TIMING-LEAKAGE-DETECTED`.

### 7.4 Binary finding: address only, no line, no extent

`physicalLocation.artifactLocation` = the DSO; `address = {absoluteAddress: <offset>,
kind: "instruction"}`; `region = {byteOffset: <offset>}` — **no `startLine`, no
`byteLength`**. `properties.a1.locationPrecision = "byte-offset-in-artifact"`,
`properties.a1.lineInfoAvailable = false`, `properties.a1.extentRecorded = false`.
The message and the limitation property state that the native record records no
source line and no extent for the site. Class members:
`A1-ISA-BINARY-UNRESOLVED`, and the BN branch sites carried as `relatedLocations`.

A machine-code finding is **never** given a line number, a column or a file path,
including when a symbol name exists; the symbol is emitted as the address's
`name` only when the record names one. In this emission the curl residual rows
carry offsets only, so no symbol name is emitted.

### 7.5 Macro-expanded finding

Class rule, no instance in the A1 emission: the location is the expansion site the
native record records, with expansion metadata only if the record supplies it
(`properties.a1.expansion = {kind, origin}`). The definition site is never
substituted for the expansion site, and a derived line is never invented. A record
that gives only a macro name and no expansion site is emitted as
`properties.a1.locationPrecision = "symbol-only"` with `logicalLocations` naming the
symbol and a limitation saying no expansion site was recorded.

### 7.6 Monomorphised binary finding

Class rule, no instance in the A1 emission: the location is the mangled or
demangled symbol and the offset the record records, with
`logicalLocations` (`kind: "function"`, `decoratedName` where recorded) and a
binary region as in §7.4. The generic source definition is **not** presented as the
location of the monomorphised instance.

### 7.7 Finding whose location is a record-level condition

Some native findings are conditions of a **record**, not of a code location: a
predicate failure over a DSO set, a truncated population, a closure verdict, a
suppression aggregate with no member rows, an adjudication of a consumer family,
a reconciliation row. These are emitted with **no `locations`** and

```
properties.a1.locationKind = "record-condition"
properties.a1.native.locator = "<JSON pointer into the native record>"
```

with `properties.a1.artifact` = the record itself (`digestScope = "record"`). The
profile does not attach them to a source file, a DSO or a symbol, because the
native record does not. Class members: `A1-ISA-POPULATION-TRUNCATED`,
`A1-ELEMENT7-PREDICATE`, `A1-CLOSURE-VERDICT`, `A1-UNSAFE-SUPPRESSION-MEMBERS-ABSENT`,
`A1-ADJUDICATION-*`, `A1-RECONCILIATION-ROW`, `A1-RECONCILIATION-LIMIT`.

### 7.8 Where precision is unavailable

| finding class | unavailable | emitted instead |
|---|---|---|
| curl unresolved indirect site | source line, symbol name, instruction extent | DSO URI, function offset as `address`, call-site offset as `region.byteOffset` |
| BN ctgrind branch site | source line (`file_line: NOT AVAILABLE` in the record), instruction extent | DSO URI, offset, `relatedLocations` entry with the recorded instruction mnemonic in `properties.a1.native.fields.instr` |
| suppression aggregate | any member location | record-level result with `membersRecorded: false` and the recorded total |
| adjudication, reconciliation, verdict, predicate, truncation | any code location | record-level result bound to candidate and record digest |
| source finding with no recorded column | column unit | line-only region; column preserved in properties where present |

## 8. `level` and `kind`

### 8.1 Level is a disposition class, not a severity estimate

`level` answers "what does the native record do with this finding?" It is never a
probability, a risk score or a prediction (Article 9). The mapping is mechanical
and is recorded per result at `properties.a1.levelBasis`:

| level | assigned when the native record |
|---|---|
| `error` | refuses the claim the finding supports: records leak verdicts, unmet required cleansing, an unestablished caller obligation, a predicate `FAIL`, a `NOT_ESTABLISHED` verdict / refutation / mechanism / cross-cutting block |
| `warning` | records an unresolved gap or limitation it does not resolve: no evidence for a secret-dependent control, a not-run analysis, a vacuous precondition, an unmet implementer obligation, a site with no contract, an aggregate with no members, an unresolved indirect site, a truncated population |
| `note` | records a delegated or historical state: an obligation delegated to a caller or a C ABI, a public-data/declassification classification, contract-only evidence, a superseded disposition, a scoped `SAFETY_DISCHARGED (scoped)` mechanism, a reconciliation row |
| `none` | records a covered obligation or a verdict block with no live gap: a `DISCHARGED` closure obligation, the closure verdict |

### 8.2 `kind` follows SARIF's constraint

§3.27.9 requires `kind = "fail"` whenever `level != "none"`. Therefore:
`kind = "fail"` for `error`, `warning` and `note`; `kind = "informational"` for
`none`. The adapter's structural validator refuses any other pairing.

`kind = "pass"` is never emitted. A `DISCHARGED` obligation means an existing
committed receipt covers the exact site; the closure record states that the tool
did not re-audit, re-run or independently review it. Calling that a pass would be a
claim beyond the evidence (Article 1).

### 8.3 Unresolved, blocked, not-run and superseded findings

They are emitted. None is dropped, merged, suppressed or re-levelled without a
property that says so:

| native state | emitted as |
|---|---|
| unresolved / blocked / `NOT_ESTABLISHED` | a result at `level = error`, with the native state verbatim in `properties.a1.native.fields` |
| not run | a result of `A1-TIMING-NOT-RUN` (a named analysis the timing record lists as not run) or `A1-RECONCILIATION-LIMIT` (an evidence level whose gates the reconciliation record declares `NOT_RUN`), at `level = warning` |
| superseded | a result of `A1-OBLIGATION-DISPOSITION-SUPERSEDED` at `level = note`, with `superseded: true`, the superseded disposition and the receipt that superseded it, all verbatim |
| bounded / truncated | the sample is emitted, and a separate `A1-ISA-POPULATION-TRUNCATED` result carries sample, population and omitted counts; `omitted_members_recorded: false` is copied verbatim |
| correction / reclassification | a `A1-RECONCILIATION-ROW` result carrying `old_state` and `new_state`; the earlier state is preserved, never overwritten (Article 10) |

### 8.4 Column extent is not a claim

No result emits `endColumn`, `endLine`, `charOffset` or `charLength`. §3.30.8
defaults `endColumn` to one past the last character of the line; that default is a
rendering convenience and **not** a recorded extent. A consumer that highlights a
line-only region must not report the highlighted extent as the finding's extent.

## 9. Message content

`message.text` is built from native fields only: the native status or verdict, the
native symbol/path/address, and, where the record supplies one, the native
`detail`, `reason`, `note`, `basis`, `consistency` or refutation text, verbatim.
The adapter adds no diagnosis, no severity adjective, no remedy and no count that
the native record does not contain. Where the adapter adds a sentence, it
describes the **representation** (e.g. "no source line is recorded for this
site"), not the code.

## 10. What a consumer may and may not infer

### 10.1 May infer

- A result exists in the named native record at the named JSON locator, and the
  fields under `properties.a1.native.fields` are that record's values, verbatim.
- The finding is bound to the candidate identity and artefact digest under
  `properties.a1.candidate` and `properties.a1.artifact`, subject to
  `digestScope`.
- The set of results in a run is exactly the projection of the declared
  population at `run.properties.a1.projection`, with the declared `notProjected`
  blocks named and counted.
- `level` states the native disposition class of §8.1.
- Two results with equal `a1Exact/v1` in the same run are the same occurrence,
  subject to the collision rule of §6.4.
- The file is byte-identical for identical inputs (§12).

### 10.2 May not infer

- **That absence of a result is absence of a defect.** A1 projects declared
  populations; it never states a population is complete. Completeness admission is
  A5, and an absent population is not an empty population.
- **That a rule was evaluated over the whole code base.** The tool is a projector;
  the population is the native record's.
- **That `level` is a severity, a probability, an exploitability or a priority.**
  Article 9.
- **That `kind = "informational"` or `level = "none"` means safe, fixed or
  discharged.** A covered receipt is receipt coverage; a classification is a
  classification.
- **That a fingerprint authorises reuse** across artefacts, candidates or runs
  (§6.4).
- **That two results with the same `ruleId` are the same defect**, or that results
  with different `ruleId` are different defects.
- **That a record-level verdict describes the whole record's contents.** The curl
  closure's `verdict.state` and `precision.predicate_element_7.status` are emitted
  as separate results precisely because they disagree; neither summarises the
  other.
- **That the SARIF file is the evidence.** It is an index into native records. A2
  owns the raw bytes; a consumer claiming a finding must read the native record at
  the locator and re-derive its digest.
- **That SARIF conformance is evidence of memory safety, cryptographic correctness
  or compatibility.** `docs/ETP-TODO.md` §I and `docs/NON_CLAIMS.md` bind this.
- **That the emission is attributable to one candidate.** Each run has one
  candidate; a file with several runs has several (§3).
- **That a location is more precise than `properties.a1.locationPrecision`
  states**, including the default column extent of a line-only region (§8.4).

## 11. Refusal conditions

The adapter exits `2` and writes **no output file** when any of the following
holds. A partial emission is never written; the temporary file is discarded.

| code | condition |
|---|---|
| `SARIF_REFUSED_SOURCE_UNREADABLE` | a native record is absent, unreadable, not JSON, or lacks a required top-level block |
| `SARIF_REFUSED_MISSING_CANDIDATE_IDENTITY` | the record's candidate identity field is absent, empty or null. The run is refused rather than emitting unattributed results. |
| `SARIF_REFUSED_MISSING_ARTIFACT_DIGEST` | a binary finding names an artefact for which the record records no digest |
| `SARIF_REFUSED_POPULATION_MISMATCH` | the record's own declared total disagrees with the rows it contains (e.g. `summary.contract_absent` versus decoded rows, or `residual_sites_bound.sample_size` versus the list length) |
| `SARIF_REFUSED_UNSUPPORTED_NATIVE_SHAPE` | a row lacks a field the projection needs, or a native vocabulary value is unknown to the adapter |
| `SARIF_REFUSED_EMISSION_INVALID` | the structural validator of §13 rejects the assembled document |

Exit `0` means the file was written and validated. Exit `1` is an internal error
and is not a refusal. The refusal code and the record and locator are printed to
stderr on one line per refusal; refusals are sorted and de-duplicated, so the same
input produces byte-identical stderr.

## 12. Determinism

Two runs over identical inputs produce byte-identical output:

- no timestamp, machine, account, process id, working directory, environment or
  absolute path is emitted (§4.4);
- `json.dumps(..., sort_keys=True, indent=2, ensure_ascii=True)` plus a trailing
  newline; object key order is therefore canonical;
- `runs` is ordered by native record path; `results` by
  `(ruleId, a1Exact/v1, a1Logical/v1, native.record, native.locator, message)`;
  `tool.driver.rules` by `id`; `artifacts` by `uri`; `notProjected` by block name;
  collision entries by fingerprint;
- all sets and dictionaries derived from records are emitted from sorted
  sequences, never from iteration order;
- the adapter's own SHA-256 and every native record's SHA-256 are computed from the
  bytes read, so a change in an input changes the output — that is identity
  binding, not nondeterminism.

Appendix F's warning about baselines does not apply: A1 emits no `baselineState`
and no `baselineGuid`.

## 13. Structural validation and conformance

The adapter validates its own emission before writing (`validate_emission`) and
refuses with `SARIF_REFUSED_EMISSION_INVALID` when any of the following fails:

1. `version == "2.1.0"`; `$schema` is the Errata 01 URI; `runs` is a non-empty
   array; runs are in record-path order.
2. Every run has `tool.driver.name`, `invocations[0].executionSuccessful`,
   `columnKind`, `results`, and a `properties.a1` block with the fields of §4.3.
3. Every result has the mandatory fields of §4.2; `ruleId` is in the registry and
   matches `tool.driver.rules[ruleIndex].id`.
4. `level`/`kind` obey §8.2.
5. `partialFingerprints` contains exactly the three versioned keys, each 64
   lowercase hex characters.
6. Every artifact index is in range and every `artifactLocation.uri` is a relative
   reference (no leading `/`, no scheme, no `..` segment).
7. Every binary region has `byteOffset` and no text property; every source region
   has `startLine` and no `endLine`/`endColumn`/`charOffset`.
8. Every result of a run names an artefact that appears in `run.artifacts`; each
   digest matches the algebra named in `properties.a1.artifact.algorithm`
   (`sha-256` → 64 hex, `sha1-git-object` → 40 hex) and no other algorithm is
   admitted.
9. No forbidden field of §4.4 is present anywhere in the document.

**Conformance claim.** The emission satisfies SARIF Conformance Clause 1 (SARIF log
file, §5.2) and is produced by a SARIF producer (§5.3). Clause 4 (Converter) and
Clause 3 (Direct producer) are **not** claimed: the adapter neither analyses the
code itself nor performs a faithful field-for-field conversion of one analysis
tool's output, and it emits no converter-only object.

**What validation does not establish.** `validate_emission` is a structural check
written by the same author as the adapter; it is not the OASIS JSON Schema, and no
JSON-Schema validator is available in the Python standard library. Schema
validation against the published Errata 01 schema is `NOT_RUN`; the receipt records
that. Structural conformance is not a claim that any finding is true.

## 14. Non-claims

- A SARIF result is not a vulnerability, a memory-safety finding, a timing result
  or a compatibility result. It is a projection of a native record's own fields.
- No finding's truth, reachability, exploitability or severity is established by
  its presence, its `level`, its rule or its fingerprint.
- The emission is not complete for any source, any subsystem or the project.
- The emission is not signed, not attested, not timestamped and not in a
  transparency log.
- The three identities are identities of **records**, not of defects: two records
  that describe the same defect under different logical keys are not merged by this
  profile, and merging them would require evidence this profile does not have.
- `properties.a1.projection` states what was projected; it is not a
  completeness statement, and A5 owns the expected-versus-examined admission.
