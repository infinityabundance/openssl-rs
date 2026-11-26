# Continuous enforcement of the transparency policy

Status: **normative** (B8). This document defines the enforcement, its refusal
vocabulary and the two applications that remain pending. It is not a claim that
transparency was achieved; it is the rule that a transparent *claim* cannot
silently outrun its evidence.

## 1. The problem

A policy enforced only by convention regresses silently. The transparency work
of B0–B7 is recorded in `evidence/b0` … `evidence/b7`, but a record does not
check itself. The failure this item prevents has a concrete shape:

1. a later commit removes the non-claims document, or a gate item, or a refusal
   code, and every remaining test still passes because nothing asserted the
   removed thing was required;
2. a claim is edited to say a statement was published, or a log admitted it,
   while `evidence/b4/PUBLICATION.json` still records `published: 0` and
   `admittedService: false`;
3. a claim grows a new field named `transparencyState`, which the schema does
   not define and no reader interprets;
4. a release gate loses item 10 in a refactor and the release still passes
   because the remaining items are green.

Each is a silent regression: the document or the reviewer believed something
that the tree no longer enforces. B8's evidence is therefore **a gate item that
refuses**, not a document that says it would.

## 2. The gate item

`forensics/tools/release_gate.py` item **10**, `check_transparency`, runs
`forensics/tools/continuous_enforcement.py check --json` and maps each refusal to
one gate row. It is wired in `evaluate()` after item 9 and is required: an
absent tool is `RG_TRANSPARENCY_TOOL_MISSING` and an unparseable result is
`RG_TRANSPARENCY_ERROR`; neither is a skip.

The tool reads:

| input | what it establishes |
|---|---|
| `evidence/b0/REGISTRY.json` | the pinned profile versions and the presence facts |
| `docs/ETP-ADDENDUM-B.md` | the clause each declared version must appear in |
| `evidence/b4/PUBLICATION.json` | `published` and `admittedService`, the facts a claim may not exceed |
| `evidence/etp/claims.json` | every claim's optional `transparency` field |
| `evidence/etp/claim.schema.json` | the field's definition, its closed enum and when it is required |
| `docs/TRANSPARENCY-NON-CLAIMS.md` | the public statement of what is not established |
| `forensics/tools/release_gate.py` | that items 1–11 exist and items 10 and 11 are called |
| `evidence/b8/ENFORCEMENT.json` | the baseline of checked codes and the before/after counts |
| `docs/CONTINUOUS-ENFORCEMENT.md` | this document, which must still name every code |

Before B8 the gate produced **35** refusals at base `69cccd242`; the task that
commissioned this item expected 34, and the difference is one environmental
`RG_INSTRUMENT` refusal (`valgrind-ctgrind`, `rc=127`, binary absent). With item
10 present and the records below in place the gate still produces **35**: item
10 passes and adds **0** refusals. That is the honest result, and
`evidence/b8/ENFORCEMENT.json` records both counts with their provenance. A
control shows that removing the non-claims document makes item 10 the 36th
refusal.

## 3. The refusal codes

Every code is stable, is printed on one line, and has a control in
`evidence/b8/CONTROLS.json` and a test in
`forensics/tools/tests/test_continuous_enforcement.py`.

| code | it refuses | enforced by |
|---|---|---|
| `CE_REFUSED_PROFILE_ABSENT` | the B0 registry or the B4 publication record is absent or unreadable | `test_profile_absent_refused` |
| `CE_REFUSED_REGISTRY_STALE` | the registry contradicts itself, or a declared version is not in the addendum clause it cites | `test_registry_stale_refused` |
| `CE_REFUSED_PUBLICATION_CLAIM` | a claim asserts `PUBLISHED` while B4 records `published: 0` | `test_publication_claim_refused` |
| `CE_REFUSED_PROFILE_NOT_ADMITTED` | a claim asserts `ADMITTED` while B4 records `admittedService: false` | `test_profile_not_admitted_refused` |
| `CE_REFUSED_SCHEMA_FIELD_ABSENT` | a claim carries a transparency field the schema does not define, a value outside the closed enum, or omits the field where the schema requires it | `test_schema_field_absent_refused`, `test_missing_field_where_required_refused` |
| `CE_REFUSED_UNBOUND_CLAIM` | an `ADMITTED` or `PUBLISHED` claim names no statement and bundle digest bound by SHA-256 | `test_unbound_claim_refused` |
| `CE_REFUSED_NONCLAIMS_ABSENT` | the public non-claims document is absent or no longer names an unestablished property | `test_nonclaims_absent_refused` |
| `CE_REFUSED_ENFORCEMENT_REGRESSION` | a gate item has disappeared, item 10 is no longer wired, the enforcement record or this document is absent, or a previously checked code is no longer named | `test_enforcement_regression_refused` |
| `CE_OK` | the positive code: nothing was refused | `test_honest_not_admitted_accepted` |
| `CE_REFUSED_USAGE` | the command line was used incorrectly (exit 2) | `test_cli_exit_codes` |

## 4. The schema field and its closed enum

`evidence/etp/claim.schema.json` adds one optional claim property,
`transparency`, defined in `$defs/transparency`:

```json
{
  "state": "NOT_ADMITTED" | "ADMITTED" | "PUBLISHED",
  "profile": "public-good-rekor-v2",
  "statementDigest": "<sha256>",
  "bundleDigest": "<sha256>",
  "publishedAt": "<RFC 3339 UTC instant>"
}
```

* `additionalProperties: false`; there is **no free-text field**, so a claim
  cannot narrate a publication it has not bound.
* `state` is a closed enum; `profile` is a closed enum; the two digests use the
  schema's existing `sha256` definition; `publishedAt` is a timestamp pattern.
* `ADMITTED` requires `profile`, `statementDigest` and `bundleDigest`;
  `PUBLISHED` additionally requires `publishedAt`. `NOT_ADMITTED` requires only
  `state`, because it asserts that nothing is bound.
* `authority.kind` gains the value `public-transparency-log`; a claim carrying
  that authority **must** carry `transparency`. No claim did before B8, so the
  absence check is **vacuous today**: the 35 existing claims carry the field
  **0** times and none was rewritten. `evidence/b8/SCHEMA.json` records the
  population as 0 and says the check is vacuous, not that it passed.

The tool reads the enum and the requirement from the schema, so a schema edit
that closed the enum differently is the input to the check rather than a second
copy of it. `test_schema_enum_is_closed` and
`test_schema_requires_field_for_transparency_authority` pin both.

## 5. The public non-claims

`docs/TRANSPARENCY-NON-CLAIMS.md` states, with the record that shows each, that
this repository claims **no admitted Rekor service**, **no witness**, **no
trusted timestamp**, **no publication** and **no independent reproduction**. The
requirement is §B.29's SEAL row ("complete required external publication,
trusted timestamping, inclusion and consistency verification, witness-policy
evaluation, archival, release reconciliation") and EXTERNAL row ("independent
parties publish their own authenticated review and reproduction results"): the
list is exactly the part of those rows this venue does not satisfy.

The document is an input to item 10, not a comment on it. Deleting a row is
`CE_REFUSED_NONCLAIMS_ABSENT` (`test_nonclaims_absent_refused`).

## 6. The enforcement-regression rule

`check_enforcement` treats the enforcement itself as data:

1. every gate item 1–11 must still have its function, and every function must
   still be called from `evaluate()`;
2. the release gate must still name `continuous_enforcement` and item
   "10. transparency";
3. the B8 enforcement record must still exist and must still list every refusal
   code the tool emits;
4. this document must still exist and must still name every refusal code.

Item 10 is B8's own item; item 11 (PFP-34's branch audit) was added to the gate
after B8 and is now part of the same baseline, so removing it is also refused.
The enumeration tracks the gate as it grows rather than freezing at ten items.

Any of those failing is `CE_REFUSED_ENFORCEMENT_REGRESSION`. The control renames
`def check_transparency(` in a copy of the gate and observes the refusal; a
second direction removes a code from the record. The rule is a tripwire, not
tamper-proofing: a commit that removes a check *and* the record *and* this
document *and* the non-claims can still pass, and no purely local checker can
prevent that. What the rule guarantees is that the ordinary **single-edit
regression** — one edit dropping one thing — is refused.

## 7. The two pending applications

Two integrations cannot be completed by this batch. They are tracked as patches
and marked pending; they are **not** claimed as applied.

| application | patch | state | why |
|---|---|---|---|
| `AGENTS.md` section on continuous enforcement | `forensics/etp8/agents-patch.diff` | `PENDING_MAINTAINER_APPLICATION` | `AGENTS.md` is the user's standing document; a conversion batch does not edit it. The patch is additive and is recorded with its digest in `evidence/b8/PENDING.json`. |
| CI job running item 10 | `forensics/etp8/ci-transparency-job.patch` | `PENDING_CREDENTIAL` | the credential that pushes this branch is an OAuth app without the `workflow` scope, and GitHub refuses a workflow update from such a token — the same limitation recorded for `forensics/etp7/ci-assurance-job.patch`. |

Neither pending application is `PASS`. Until they are applied, enforcement runs
in the release gate and in the tools suite, not on every push.

## 8. Non-claims

* A passing item 10 does **not** establish that anything was published, admitted,
  witnessed, timestamped, archived or independently reproduced. It establishes
  that no claim says otherwise and that the machinery that would refuse one is
  still wired.
* The schema field is **unpopulated** by the 35 claims; the absence check is
  vacuous, and this document says so rather than reporting it as coverage.
* The enforcement-regression rule detects single edits, not a coordinated
  removal of the gate, the record, this document and the non-claims.
* The gate item was exercised by controls, not by a real adversarial service.
* `AGENTS.md` and the CI workflow do not contain the new integration yet.

## 9. `NOT_RUN`

* An admitted public transparency log, its key, client and inclusion proofs.
* A witness cosignature from an independent operator.
* A trusted RFC 3161 timestamp.
* A published release and a durable archival record.
* An independent party's reproduction or authenticated review.
* A citation of item 10 from an applied `AGENTS.md` section or CI job.
* The IETF/transparency-community conformance of the profile.
* `BOUNDARY`, `SEAL` and the Rust suite: no Rust source was modified.

These are `NOT_RUN`, not `PASS`.
