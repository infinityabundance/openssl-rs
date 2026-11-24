# Code-scanning export: a local shard export with no GitHub dependency (A8)

## 1. The problem

A code-scanning upload is a **lossy, third-party step**. The service decides what
it keeps; it may cap a file at 5,000 results, it may reject a file for a size or
schema reason it reports elsewhere, it may collapse results that share a
fingerprint, and it may re-index a location. None of that is observable from
this repository, and none of it is this project's evidence. If the project's
statement of what it found depended on an upload succeeding, then a rejected or
truncated upload would silently become "nothing was found".

The project must therefore be able to perform the whole transformation locally:
read the A1 emission, partition it, emit self-contained SARIF shards, and state
the whole population in an object it controls. A service may then ingest the
result, but ingestion is neither required for the export to exist nor evidence
that the export is complete.

This document is the normative description of that export. The implementation is
`forensics/tools/code_scanning_export.py`; the controls are
`forensics/tools/tests/test_code_scanning_export.py`; the records are
`evidence/a8/{PLAN,MANIFEST,CONTROLS}.json` and `evidence/a8/SHARD-000.sarif`,
produced deterministically by `evidence/a8/build_evidence.py`.

## 2. The no-dependency rule

The export module contains **no API client, no network call, no credential read
and no upload**. It imports only `argparse`, `ast`, `copy`, `hashlib`, `json`,
`re`, `sys`, `tempfile`, `collections`, `pathlib` and `typing` — the Python
standard library, none of it a network client. `network_dependency_findings`
parses a module source and returns a refusal for an import of `urllib`, `http`,
`requests`, `socket`, `ssl`, `subprocess` and their listed relatives, and for any
read of `os.environ` / `os.getenv`. The detector is conservative: it treats any
environment read as a credential read, because the module needs neither.

This is checked structurally, not asserted in prose. Enforced by
`test_the_module_imports_no_network_client`, `test_the_module_reads_no_credential`
and `test_a_network_import_is_refused_structurally`, and recorded as the
`network-or-credential` control. A finding is
`EX_REFUSED_NETWORK_OR_CREDENTIAL`.

The limit is stated: a call assembled from strings at run time is outside a
source inspector's claim; the module has no such call, and the test inspects the
imports and environment reads it can see.

## 3. The sharding rule, and why 5,000

A shard holds **at most 5,000 results**, the reported per-file result limit of
GitHub code-scanning ingestion. That is the only ingestion limit modelled here.

`plan(document, max_results=5000)` returns a deterministic partition of the
**input order**: results are flattened run by run, result by result, and cut at
fixed boundaries. A shard is `{index, total, results, runIndices}` where
`results` is a list of global result indices and `runIndices` is the distinct set
of runs that contribute. Boundaries are by input order, never hash order, so
re-running the plan reproduces it, and a reader can check a shard's position in
the parent without recomputing an identity.

Why input order and not a content-ordered partition: a content order makes the
plan depend on every result's bytes, so one changed result can move an unrelated
result across a boundary and a shard digest cannot be attributed to a stable
position. Input order makes the plan a function of counts alone, and the parent
order is already the A1 emission's recorded order (`docs/SARIF-PROFILE.md` §12).

The tracked population is **4,245 results**, so the real export has **one**
shard. The 5,000 boundary is proven by a synthetic 12,001-result population:
three shards at indices `0–4999`, `5000–9999`, `10000–12000`, holding 5,000,
5,000 and 2,001 results. That population is a boundary control, labelled
synthetic, and is never an evidence population. A second **real** shard cannot be
produced from the tracked parent without inventing results, and
`build_evidence.py` does not invent one.

Enforced by `test_boundaries_follow_input_order`,
`test_exactly_five_thousand_results_are_accepted` and
`test_five_thousand_and_one_results_are_refused`; an over-limit shard is
`EX_REFUSED_OVERSIZE_SHARD`.

## 4. The shard contract

`emit(document, shard, manifest)` returns one SARIF 2.1.0 log. It is
**self-contained** and a **subset**:

1. It holds a copy of every run that contributes a result, in parent run order.
2. `tool` is complete except `tool.driver.rules`, which is restricted to the
   `ruleId`s the shard's results use, sorted by id, and every `ruleIndex` is
   relabelled against the restricted table.
3. `artifacts` is restricted to the URIs the shard's results reference — through
   `locations`, `relatedLocations`, or `properties.a1.artifact.uri` — and every
   `artifactLocation.index` is relabelled against the restricted table.
4. `results` is the subset, in parent order.
5. Everything else in the run (invocations, `columnKind`, `properties.a1`) is
   copied verbatim. The copied `run.properties.a1.projection` describes the
   **parent run's** projection, not the shard's result list; a consumer reads
   `properties.shard.resultCount` for the shard and the manifest's `union` block
   for the population.
6. `properties.shard` is exactly `{index, total, parentDigest,
   parentResultCount, resultCount, candidate}`.
7. It carries **no completeness or census property**. `_census_properties`
   refuses a shard whose properties claim to be the whole population; an omitted
   key is never read as a completeness claim, and `parentResultCount` beside
   `resultCount` states the subset relation rather than hiding it.

The shard is **not** a census. It does not say its results are the population,
it does not say the parent's rules were evaluated over the code base, and it
does not say a finding is true. A shard is a genuine SARIF log and can be
uploaded, but "upload-ready" here means only "structurally self-contained and
within the modelled result limit". No service's acceptance is claimed.

Enforced by `test_the_shard_is_self_contained_and_well_formed`,
`test_the_shard_keeps_the_tool_rules_and_artifacts`,
`test_no_shard_carries_a_census_property`; a shard that claims to be the census
is `EX_REFUSED_SHARD_AS_CENSUS`.

## 5. The manifest contract

The manifest is the **only object that states the export's whole population**. It
records:

| field | content |
|---|---|
| `parent` | the relative path, the SHA-256 and byte length of the exact input bytes on disk, the result and run counts, the per-run result counts, an identity digest over the whole population, and the producer identity of the runs |
| `candidate` | the per-run candidate blocks read from the document, their count, whether they are mixed, and one token over them. A candidate is **refused if absent** (`EX_REFUSED_CANDIDATE_UNRECORDED`); the A1 parent holds six per-run candidates and is recorded as mixed, never relabelled as one |
| `limit` | the result limit the export was planned at (5,000) |
| `shards` | per shard: index, file name, byte length, SHA-256, result count, contributing run indices, and first/last parent result index |
| `union` | parent count, shard count, distinct identities, missing, extra, duplicate, the equality verdict, and the union identity digest |
| `tool` | the exporter's name, version, path and SHA-256, and the statement that the dependency is none |
| `nonClaims` | the subset, upload and projection limits, machine-readable |

The manifest binds the **parent bytes**, so a changed parent invalidates it; the
**shard bytes**, so a changed shard is not the analysed shard; and the
**candidate**, so results cannot be reused at another candidate. The parent
digest is computed from the bytes on disk, not from a re-serialisation.

The manifest is produced from the shard contents it describes. It records the
observed union verdict rather than asserting one, and `verify` is what refuses a
manifest whose union check reads false. There is no partial write: shards and
the manifest are built in memory, verified, and only then written.

Enforced by `test_the_union_is_the_parent_once_each`,
`test_the_committed_shard_and_manifest_match_a_fresh_build` and
`test_the_document_matches_the_manifest`.

## 6. Verification conditions

`verify(manifest, shards, parent)` refuses unless all of the following hold. Each
condition names its code; a failure is one code and stops the verification.

1. A manifest is present and its schema is the supported one —
   `EX_REFUSED_MANIFEST_ABSENT`, `EX_REFUSED_UNSUPPORTED_VERSION`.
2. The manifest's parent digest is the parent bytes; the manifest's parent path
   is relative — `EX_REFUSED_DIGEST_MISMATCH`, `EX_REFUSED_ABSOLUTE_PATH`.
3. The parent is SARIF 2.1.0, every result's `ruleId` is in its run's table at
   its `ruleIndex`, every artifact index resolves to the URI it claims, every
   referenced URI is listed, and no URI is absolute —
   `EX_REFUSED_UNSUPPORTED_VERSION`, `EX_REFUSED_RULE_DROPPED`,
   `EX_REFUSED_ARTIFACT_DROPPED`, `EX_REFUSED_ABSOLUTE_PATH`,
   `EX_REFUSED_PARENT_SHAPE`.
4. The manifest's candidate is the parent's candidate identity, and every shard's
   candidate is the same — `EX_REFUSED_CANDIDATE_UNRECORDED`.
5. The manifest and the supplied shard set name the same shards, every shard for
   exactly one index, and every manifest file name is a bare relative name —
   `EX_REFUSED_MANIFEST_SHARD_MISSING`, `EX_REFUSED_ABSOLUTE_PATH`.
6. Each shard is SARIF 2.1.0; its `properties.shard` index and total agree with
   the manifest; its parent digest is the manifest's; its bytes hash to the
   manifest's shard digest —
   `EX_REFUSED_UNSUPPORTED_VERSION`, `EX_REFUSED_MANIFEST_SHARD_MISSING`,
   `EX_REFUSED_DIGEST_MISMATCH`.
7. Each shard carries no census property — `EX_REFUSED_SHARD_AS_CENSUS`.
8. Each shard holds at most the limit (and never more than 5,000), and its actual
   result count is the count it and the manifest state —
   `EX_REFUSED_OVERSIZE_SHARD`, `EX_REFUSED_UNION_INCOMPLETE`.
9. Each shard run's `tool` projection (everything except the restricted `rules`)
   equals the parent run's — `EX_REFUSED_TOOL_DROPPED`.
10. Every result's `ruleId` is in the shard's restricted table, every rule entry
    equals the parent's entry, and every `ruleIndex` resolves to that rule —
    `EX_REFUSED_RULE_DROPPED`.
11. Every referenced URI is in the shard's restricted artifact table, every
    artifact entry equals the parent's, and every `artifactLocation.index`
    resolves to the URI it claims — `EX_REFUSED_ARTIFACT_DROPPED`.
12. The union of shard exact identities equals the parent population exactly once
    each, and the manifest's own union block states that union —
    `EX_REFUSED_UNION_DUPLICATE`, `EX_REFUSED_UNION_INCOMPLETE`.
13. Each shard's identity sequence is the parent order restricted to it —
    `EX_REFUSED_ORDER_CHANGED`.

The exact identity is `a1Exact/v1`, the A1 emission's identity 3
(`docs/SARIF-PROFILE.md` §6.3). Where that value collides in one document, the
export refines it with the native record, locator and message — the second
discriminator A1 §6.4(3) requires — and never drops or merges a colliding
result. A repeated refined identity is a refusal, not a deduplication.

## 7. The refusal table

Every code is stable and is cited verbatim by the tool, the tests, the document
and `CONTROLS.json`. The third column is the wrong conclusion the code prevents.

| code | condition | prevents |
|---|---|---|
| `EX_REFUSED_OVERSIZE_SHARD` | a shard holds more results than the 5,000 limit | that a file the service would truncate is a complete shard, so an ingestion-side cut is read as a shard that held nothing more |
| `EX_REFUSED_SHARD_AS_CENSUS` | a shard carries a completeness or census property | that one shard is the population, which would make every other shard and the manifest look like duplicates or noise |
| `EX_REFUSED_MANIFEST_ABSENT` | no manifest was supplied or it cannot be read | that a set of shard files is an export: without the manifest there is no statement of the population and no union check |
| `EX_REFUSED_MANIFEST_SHARD_MISSING` | the manifest and the shard set disagree about which shards exist | that the files on disk and the results the manifest accounts for are the same set |
| `EX_REFUSED_UNION_INCOMPLETE` | a parent result identity is missing from the union of the shards | that the shards together hold the parent population when a result was dropped or never emitted |
| `EX_REFUSED_UNION_DUPLICATE` | the union holds an exact identity more than once | that a repeated result is two results, which would inflate the population and hide a missing one |
| `EX_REFUSED_ORDER_CHANGED` | a shard's result order is not the parent order restricted to it | that a reordered shard is a faithful subset; order is the only positional check against the parent's emission order |
| `EX_REFUSED_DIGEST_MISMATCH` | a shard's bytes do not hash to the digest the manifest records | that the analysed shard is the emitted shard, so evidence from one file is not reused for another |
| `EX_REFUSED_TOOL_DROPPED` | a shard run's tool identity is not the parent run's | that a result produced by a different producer is evidence from this parent |
| `EX_REFUSED_RULE_DROPPED` | a result names a rule the shard's `rules` table omits or changed | that a self-contained log exists when its rule descriptions are absent, which leaves `ruleId` readable but its meaning unstated |
| `EX_REFUSED_ARTIFACT_DROPPED` | a result names an artifact URI the shard's `artifacts` table omits or changed | that a location is resolvable when its artifact entry is absent, and that an index still points at the artifact it claims |
| `EX_REFUSED_CANDIDATE_UNRECORDED` | the parent, a shard or the manifest records no candidate, or a different one | that a result is bound to the candidate it was emitted at when the identity is absent or has moved |
| `EX_REFUSED_ABSOLUTE_PATH` | a parent URI, a shard URI, a shard file name or a manifest parent path is absolute | that a host path is read as a portable artefact reference, and that a shard file is taken from outside the export directory |
| `EX_REFUSED_UNSUPPORTED_VERSION` | the parent, a shard or the manifest is not the supported version | that a different format is read with this export's rules; a 2.2 or a later manifest is not this manifest |
| `EX_REFUSED_NETWORK_OR_CREDENTIAL` | the export module imports a network client, reads a credential, or uploads | that the export depends on a service, a token or a network call; the export is a local transformation and must remain one |
| `EX_REFUSED_PARENT_SHAPE` | the parent is unreadable, malformed, or internally inconsistent | that a shape this tool does not understand is exported as if it were the A1 profile |
| `EX_REFUSED_OUTPUT_NOT_EMPTY` | the output directory is not empty and `--force` was not given | that an unrelated directory is overwritten in the belief that it is this export's output |

## 8. The real export and its figures

The parent is `evidence/a1/SARIF.json`: **13,651,450 bytes**, SHA-256
`5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852`,
**6 runs**, **4,245 results** (17, 4, 211, 3,953, 51 and 9 per run). It holds
**six per-run candidate identities** — the export records the set as mixed and
does not pick one — with candidate token
`dea0f4228962fc342930e0a45dc50d3b12a9962cef0c4510bc47be89db7a5b92`. All six
runs name `openssl-rs-sarif-adapter` 1.0.0, and every result carries
`a1Exact/v1`; the parent has **4,245 distinct exact identities**.

The real export is **one shard**, because 4,245 is below 5,000:

| shard | results | bytes | sha256 | parent indices |
|---|---:|---:|---|---|
| `SHARD-000.sarif` | 4,245 | 8,699,144 | `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed` | 0–4244 |

The shard copies all six runs. Restricting the tables leaves
**rules per run 4, 2, 6, 5, 5, 2** and **artifacts per run 1, 1, 9, 616, 31, 2**:
run 4 lists 32 artifacts in the parent and its shard holds 31, because one
parent artifact is referenced by no result of that run. All other parent
artifacts are referenced. Every `ruleIndex` and artifact index was relabelled
against the restricted tables, and `verify` checked each one.

The union is **complete**: parent 4,245, shard results 4,245, distinct 4,245,
missing 0, extra 0, duplicates 0, `equalsParent: true`, union identity digest
`1c3b64ca5e1f694f1950f199281d7e61b95e3258128985c470c54f5e21ad5777` — the same
digest as the parent population.

The shard is a **single real shard**. The task's second-real-shard case is not
available from the tracked population; the 5,000 boundary is instead proven by
the synthetic 12,001-result plan in `PLAN.json`, clearly labelled.

## 9. Controls

`evidence/a8/CONTROLS.json` records 17 controls over the 17 codes, one per code.
Each mutates a copy in memory or a temporary directory and asserts the named
code fires. They are controls, not findings: a control that fires proves the
refusal works, not that the substituted form occurs in the tree.

| control | code |
|---|---|
| `oversize-shard` | `EX_REFUSED_OVERSIZE_SHARD` |
| `shard-as-census` | `EX_REFUSED_SHARD_AS_CENSUS` |
| `manifest-absent` | `EX_REFUSED_MANIFEST_ABSENT` |
| `manifest-shard-missing` | `EX_REFUSED_MANIFEST_SHARD_MISSING` |
| `union-incomplete` | `EX_REFUSED_UNION_INCOMPLETE` |
| `union-duplicate` | `EX_REFUSED_UNION_DUPLICATE` |
| `order-changed` | `EX_REFUSED_ORDER_CHANGED` |
| `digest-mismatch` | `EX_REFUSED_DIGEST_MISMATCH` |
| `tool-dropped` | `EX_REFUSED_TOOL_DROPPED` |
| `rule-dropped` | `EX_REFUSED_RULE_DROPPED` |
| `artifact-dropped` | `EX_REFUSED_ARTIFACT_DROPPED` |
| `candidate-unrecorded` | `EX_REFUSED_CANDIDATE_UNRECORDED` |
| `absolute-path` | `EX_REFUSED_ABSOLUTE_PATH` |
| `unsupported-version` | `EX_REFUSED_UNSUPPORTED_VERSION` |
| `parent-shape` | `EX_REFUSED_PARENT_SHAPE` |
| `network-or-credential` | `EX_REFUSED_NETWORK_OR_CREDENTIAL` |
| `output-not-empty` | `EX_REFUSED_OUTPUT_NOT_EMPTY` |

The `network-or-credential` control has two halves: a source that imports
`urllib.request` and reads `GITHUB_TOKEN` produces the code, and the real module
produces no finding (`realModule: "clean"`). Enforced by
`test_every_control_fires_its_named_code`, `test_the_recorded_controls_are_current`
and `test_the_module_imports_no_network_client`.

The boundary is controlled in both directions: exactly 5,000 results are
accepted as one shard and 5,001 are refused, by
`test_exactly_five_thousand_results_are_accepted` and
`test_five_thousand_and_one_results_are_refused`.

## 10. Non-claims

- **A shard is not a census.** It is a subset. Only `MANIFEST.json` states the
  export's population, and even that is the A1 population, not the code base.
- **An upload is not an admission.** Nothing here uploads. If a service later
  ingests a shard, its ingestion is not evidence that the shard's results are
  true, complete or current; A5 owns completeness and A7 owns regression state.
- **GitHub's ingestion is not evidence this project controls.** The export models
  the reported 5,000-result limit. It does not model the service's size ceiling,
  schema validator, deduplication, permissions, retention or indexing. A
  rejection there says nothing about this export's correctness.
- **`EMITTED` is not `UPLOADED`.** `SHARD-000.sarif` being "upload-ready" means
  self-contained and within the modelled limit. It has not been uploaded and no
  service has accepted it.
- **An exact identity is an identity of a record, not of a defect.** The
  collision refinement follows A1 §6.4; two records that describe one defect
  under different keys are not merged.
- **No severity, exploitability, priority or truth is implied** by presence,
  `level`, `ruleId` or fingerprint (`docs/SARIF-PROFILE.md` §10.2).
- **The copied `run.properties.a1.projection` is the parent run's**, not the
  shard's; it is not a completeness statement (A1 §10.2), and the shard states
  its own count against the parent count beside it.
- **The plan is not a claim about what a service will keep.** It is a local
  partition of the input order.
- **There is one real shard.** Nothing here estimates what a second real shard
  would contain.

## 11. `NOT_RUN`

- **Upload to GitHub, or to any service.** No API client, no token, no network
  call and no upload exist in the tool by construction; the structural test is
  the enforcement, and an actual upload is `NOT_RUN` by design, not blocked.
- **GitHub's file-size ceiling.** The shard is 8,699,144 bytes, below the
  commonly reported 10 MiB `NOT_RUN` observation, but no size check is
  implemented and no service was asked. Only the 5,000-result limit is a check.
- **JSON-Schema validation of the shard against the OASIS SARIF schema.** The
  same limit as A1 §13: no JSON-Schema validator is in the Python standard
  library. The shard is checked structurally, not against the published schema.
- **An independent consumer replay of the shard.** No external code-scanning
  client or reader was run against `SHARD-000.sarif`.
- **A second real shard.** The tracked population is 4,245 results; the
  5,000-boundary evidence is the labelled synthetic plan.
- **Independent review of this export.** A8 is a tool and its controls; its
  author is not an independent adjudicator, and no claim of safety or
  correctness inherits from it.
- **Observability of any service's truncation behaviour.** The reason the shard
  limit exists cannot be tested from here; the export refuses an over-limit
  shard instead of learning what a service would do with one.
