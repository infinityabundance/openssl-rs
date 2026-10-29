# Edge provenance record schema (v1.4)

`forensics/tools/consumer_closure.py` emits one record per indirect site it
classifies. The record is the tool's account of **what it proved** versus
**what it approximated**, and every ledger in it is checked against the others
rather than trusted. The ledgers are **mutually redundant within the record**,
and are **cross-checked against the graph-derived oracle**; they are not
independent derivations of the same fact.

Schema: `openssl-rs/campaign/safe-c33/edge-record/v1.4`

Change history:

- `v1` — first per-site records.
- `v1.1` — derivation obligation, per-reason evidence, the reachability oracle.
- `v1.2` — subject-scoped claims, module binding, a recomputable
  `candidate_source`, the full alias set at reachable addresses, fail-closed
  unknown modules, honest dispositions (no vacuous proofs), role-bearing unique
  identities, and a streaming/sample receipt contract.
- `v1.3` — **row kinds**: a closed target-drop vocabulary and a closed subject
  vocabulary, so a caller/writer-scoped label can no longer hide a target drop;
  every target drop is bound to a structured subject→target mapping
  (`candidate_source` callers, `evidence.targets`, `would_store_targets`);
  `target_reachability` is derived from the disposition; the sidecar defaults
  into the gitignored workdir; and the receipt binds the validator identity and
  the sidecar digest.
- `v1.4` — **complete caller attribution**: every caller row, reachable or
  excluded, carries the per-call-site witness and the argument-summary
  attribution that produced its contribution (`REACHABLE_CALLER_SCHEMA` v2);
  `candidate_source` for `argument-targets` embeds those witnesses and the
  `unattributed_targets` set; a candidate that no caller row attributes is
  **admitted** (never dropped) and recorded in `unattributed_admissions`; a
  site whose whole candidate set is unattributable is `UNRESOLVED` with the
  named missing property instead of emitting a bounded set.

v1.3 exists because v1.2 accepted three residual unsound claims and two
evidence/operations defects:

1. `caller-not-in-reachable-set` and `writer-not-in-reachable-set` were legal in
   `exclusions[]`, where they drop a target. Validation checked only that the
   *subject* was absent and that a self-described `target_reachability` said
   `not-claimed`, so a record could drop a reachable target and attach an
   unrelated absent caller/writer.
2. `declared-name-absent` accepted a free-text `target_derivation`, so an
   unrelated reachable target could be mapped to an absent name.
3. `not-contributed-by-reachable-callers` read the claim's self-asserted
   `contributed_targets`; forging that list (omitting the contributing reachable
   caller) validated.
4. With `--output` inside the repository the 1.3 GB sidecar landed beside the
   receipt and was not gitignored.
5. The receipt recorded only `{path, version}` for the tool; the validator
   digest and the sidecar digest were not bound into the evidence identity.

v1.4 exists because a real libcrypto record exposed a **derivation gap**, not a
validator weakness: `site["arg_targets"]` is a flat union over all callers, but
per-caller attribution was computed only for *reachable* callers. The excluded
caller `OSSL_PROVIDER_do_all` forwards its own parameter, so its recorded
argument was the symbolic value `("arg", 1)`; the old attribution recorded no
target for it and the record dropped 178 targets it could not recompute. The
v1.3 validator correctly refused all 178. The repair is in the derivation:

1. every caller row (reachable and excluded) is attributed with the same
   argument-summary interpreter that produced the site's flat target set, and
   carries the per-call-site witness for its contribution;
2. a candidate target that no caller row attributes is admitted conservatively
   and listed in `unattributed_admissions`; it is never dropped;
3. a bounding that cannot attribute any candidate is not emitted as a bounded
   set at all: the record is `UNRESOLVED` with
   `caller attribution incomplete: <n> candidate target(s) have no attributable
   caller`.

**Soundness direction.** Admitting a target is always safe for the upper bound.
Excluding one requires (i) the caller/writer is absent from the
final-upper-bound oracle and (ii) the target is demonstrably produced by that
subject. Per-caller attribution is **analyzer-produced**; record-level
validation checks the record against itself and the oracle, **not** against a
re-derivation of the image. The call-site witness makes the contribution
recomputable from the record, and a contribution that its own witness does not
show is refused.

## Row kinds (v1.3)

Every exclusion row and every auxiliary claim row carries
`"row_kind": "target-drop" | "subject"`. There are two closed vocabularies:

```
TARGET_DROP_REASONS = {
  "target-not-in-reachable-set",            # subject = the dropped target; oracle: absent
  "not-contributed-by-reachable-callers",   # bound per caller in candidate_source
  "declared-name-absent",                   # bound by evidence.targets
  "no-reachable-writer",                    # bound to the writer subject rows
  "provenance-unbounded", "non-image-value",
}
SUBJECT_ROW_REASONS = {
  "caller-not-in-reachable-set", "writer-not-in-reachable-set",
  "provenance-unbounded",
}
```

- A row in `exclusions[]` must have `row_kind: "target-drop"` **and** a reason
  from `TARGET_DROP_REASONS`. A caller/writer-scoped reason there is refused:
  *a target drop cannot be justified by a caller/writer claim*. This makes the
  v1.2 hole inexpressible rather than adding a check to it.
- A row in `excluded_callers[]`, `excluded_writers[]` or
  `unbounded_call_sites[]` must have `row_kind: "subject"` and a reason from
  `SUBJECT_ROW_REASONS`. A target-drop reason there is refused.
- `target-not-in-reachable-set` requires `claim.subjects == [target]` and
  `evidence.symbol == target` (carried from v1.2).

## Fields

| field | meaning |
|---|---|
| `edge_id` | `module::defining_function::operation_kind::call_site_role::ordinal`, optionally `::<content-hash>` when two sites still collide |
| `semantic_identity.source_operation` | the indirect instruction text |
| `semantic_identity.operation_kind` | `call` / `jmp` |
| `semantic_identity.defining_function` | the containing function (`?` is never proved or contract-bounded) |
| `semantic_identity.call_site_role` | `method-store-slot`, `in-image-data-slot`, `argument-callback`, `abi-contract-dispatch`, `unresolved-dispatch`, `value-flow` |
| `semantic_identity.provenance_chain` | per target: the derivation steps that reach it |
| `semantic_identity.artifact_local_witness` | module, function/site address, and a note that the address is **not** the identity |
| `disposition` | `PROVED_TARGET_SET`, `CONTRACT_BOUNDED`, `UNRESOLVED` |
| `disposition_demotion` | `empty-target-set`, `no-defining-symbol`, or null |
| `target_set` | admitted targets when `PROVED_TARGET_SET`; empty otherwise |
| `target_set_claim` | true only when the record claims a proved target set |
| `target_reachability` | **derived**: `claimed` iff `disposition == PROVED_TARGET_SET`, else `not-claimed`. It is not self-described. |
| `witness_id` | required when `CONTRACT_BOUNDED` |
| `missing_property` | required when `UNRESOLVED` |
| `exclusions[]` | target-drop rows only: `{target, reason, row_kind, claim, evidence}` |
| `excluded_callers[]`, `excluded_writers[]`, `unbounded_call_sites[]` | subject rows only: the same row shape and the same validator, different list kind |
| `candidate_source` | a recomputable enumeration of how candidates were derived |
| `unattributed_admissions[]` | round 4: `{dso, site, function, target, reason}` for every candidate admitted because no caller row attributes it |
| `exclusion_accounting` | candidate / admitted / excluded / unaccounted target sets |

## The claim model

Every row names its kind, the record module and its subjects:

```json
{"target": "...", "reason": "not-contributed-by-reachable-callers",
 "row_kind": "target-drop",
 "claim": {"kind": "not-contributed-by-reachable-callers",
           "module": "<the record's module>",
           "subjects": [],
           "reachable_callers": [{"symbol": "...", "contributed_targets": ["..."]}],
           "excluded_callers": ["..."]},
 "evidence": {"reachable_basis": "final-upper-bound"}}
```

`claim.reachable_callers` is the minimal projection of `candidate_source.callers`
(symbol, address, contributed targets); the full per-call-site witness lives in
`candidate_source`. The two mappings must be equal for the same symbols.

`claim.kind` is fixed by the reason and **`claim.module` must equal
`semantic_identity.artifact_local_witness.module`**. The oracle lookup uses that
module, never free text in `evidence`.

| reason | row kind | binding rule |
|---|---|---|
| `target-not-in-reachable-set` | target-drop | `subjects == [target]`; `evidence.symbol == target`; the oracle must not reach the target |
| `not-contributed-by-reachable-callers` | target-drop | `candidate_source` is `{kind: "argument-targets", callers: [{symbol, reachable, reason, call_sites: [{call_site, arguments: [{argument_index, targets, witness_instruction}]}], contributed_targets}], excluded_callers: [<same shape>], targets: [...], unattributed_targets: [...]}`. On each row, `contributed_targets` must equal the union of its per-call-site `targets` (an empty call-site list contributes nothing). The claim's per-caller mapping must equal the source's for the same symbols. The target must be in the excluded contribution union, not in the recomputed reachable union, and not in `unattributed_targets`; `admitted_targets` must equal `((⋃ reachable contributions) ∩ image symbols) ∪ unattributed_targets`; and `candidates == admitted ∪ excluded ∪ unattributed`. Every excluded caller must be absent from the bound; every reachable caller must be present |
| `declared-name-absent` | target-drop | `evidence.declared_name`, `evidence.present is False`, and **`evidence.targets`** (a non-empty structured list). `target ∈ evidence.targets`; every listed target must be a candidate; `claim.subjects == [declared_name]`; the name must be absent from the oracle's defined symbol set; and the dropped target must be absent from the final upper bound. A free-text `target_derivation` is not evidence and is not in the schema |
| `no-reachable-writer` | target-drop | `target ∉ evidence.derived_targets`; `evidence.reachable_writers == []`; every `writer-not-in-reachable-set` subject row must carry `would_store_targets`, each entry a candidate |
| `caller-not-in-reachable-set` | subject | non-empty caller symbols; the oracle checks **the callers, never the target** |
| `writer-not-in-reachable-set` | subject | exactly `[writer_symbol]`; `evidence.would_store_targets` (a list) and each entry must be a candidate; the oracle checks the writer |
| `provenance-unbounded` | either | non-empty `failure` |
| `non-image-value` | target-drop | `in_image is False`; with an oracle, a symbol-shaped value is absent from the module's defined symbols |

Booleans are compared with `is`. A subject that is not a symbol-shaped name must
carry an artifact-local address in `subject_addresses`, and the oracle then
checks the address node as well as the name.

## Candidate source and accounting

The validator derives these ledgers from the record:

- `claimed` = `set(target_set)`;
- `acct_admitted` = `set(exclusion_accounting.admitted_targets)`;
- `derived` = targets with a valid derivation;
- `excluded` = targets named by `exclusions[]`;
- `candidates` = recomputed from `candidate_source`.

`candidate_source` is one of:

- `{"kind": "store-writer-call-sites", "resolved": bool, "rows": [{caller,
  call_site, included, reason, targets}], "writers": [...], "collapsed": [...],
  "declared": [...]}` — the candidates are the targets of included rows, the
  excluded writers' would-store values, thunk-collapsed names and declared
  targets;
- `{"kind": "argument-targets", "callers": [{symbol, address, reachable,
  reason, call_sites, contributed_targets}], "excluded_callers": [<same
  shape>], "argued_by": [...], "targets": [...], "unattributed_targets":
  [...]}` — every caller row, reachable or excluded, carries the
  per-call-site witness from the argument-summary interpreter (v1.4; the
  derived `REACHABLE_CALLER_SCHEMA` is v2). The caller-bound drop is
  recomputable from this mapping, not from the claim; `candidate_enumeration`
  is `complete`. A target in `unattributed_targets` is a candidate that no row
  attributes: it is admitted and listed in `unattributed_admissions`.
- `{"kind": "resolver-admitted-set", "class": ..., "reason": ...}` — the
  candidates are exactly the admitted set; an exclusion cannot hide here.

Round-4 checks on `argument-targets`:

- `contributed_targets` equals the union of the row's own call-site
  `targets`; a drop resting on a contribution its witness does not show is
  refused;
- `unattributed_admissions` is exactly `candidate_source.unattributed_targets`;
  every entry is a candidate, is attributed to no caller row, is not excluded,
  and (when the disposition is not `UNRESOLVED`) is admitted;
- a caller-bound record with **no** attributable candidate may not claim
  `PROVED_TARGET_SET`; it must be `UNRESOLVED`, admit nothing, and carry
  `missing_property` beginning `caller attribution incomplete:`;
- `candidates == admitted ∪ excluded ∪ unattributed`; and the complete
  enumeration's unaccounted set excludes `unattributed_targets`.

A `CONTRACT_BOUNDED` or `PROVED_TARGET_SET` record's admitted set is the
reachable contribution union **plus** the unattributed admissions. Admitting is
the conservative direction: it can only widen the upper bound. Excluding still
requires an excluded subject that demonstrably produces the target and is
absent from the final-upper-bound oracle.

The following are defects:

- `set(candidate_targets) != candidates`;
- `acct_admitted ⊄ candidates`;
- an exclusion target that is not a candidate;
- a `declared-name-absent` `evidence.targets` entry that is not a candidate;
- a `writer-not-in-reachable-set` `would_store_targets` entry that is not a
  candidate;
- an `argument-targets` attribution to a target outside `targets`;
- a `contributed_targets` list that is not the union of the row's call-site
  `targets`, or a contribution with no call-site witness;
- an `unattributed_admissions` entry naming a non-candidate, an attributed
  target, an excluded target, or a target its own accounting does not admit;
- an `unattributed_admissions` list that differs from
  `candidate_source.unattributed_targets`;
- a zero-attribution record claiming a bounded set;
- any exclusion under `resolver-admitted-set` (it has no recomputable source).

For `argument-targets`, `candidates` must equal exactly `admitted ∪ excluded`;
a candidate that is neither admitted nor excluded is a defect even when the
record sets `candidate_enumeration: not-applicable`.

| disposition | rule |
|---|---|
| `PROVED_TARGET_SET` | non-empty `target_set`; `claimed == acct_admitted`; `claimed ∩ excluded = ∅`; `claimed ⊆ derived`; no claimed target uses an unproved step |
| `CONTRACT_BOUNDED` | `claimed = ∅`; `acct_admitted ⊆ derived`; `acct_admitted ∩ excluded = ∅`; no admitted target uses an unproved step |
| `UNRESOLVED` | `claimed = ∅` and `target_set_claim` is false |

For every disposition, `set(accounting.excluded_targets)` must equal `excluded`.
Names are compared as **sets of symbol names**, never by list length:
identical-code folding gives several names to one address.

## Disposition honesty (no vacuous proofs)

v1.1 emitted 584 `PROVED_TARGET_SET` records with an empty target set, and one
record whose defining function was `?`. v1.2 demotes them, and v1.3 retains the
rule:

- a site with no admitted target and no ABI contract is `UNRESOLVED`, with
  `missing_property` equal to the site's reason or
  `"empty target set: the resolver admitted no target and enumerated no
  candidates"`;
- a site whose containing function has no symbol is `UNRESOLVED` with
  `missing_property` naming that fact, and can never be `PROVED_TARGET_SET` or
  `CONTRACT_BOUNDED`.

Each demotion is counted in the receipt
(`edge_provenance.demotions.vacuous_target_sets_demoted`,
`no_symbol_function_demoted`) and the first 40 site identities are listed, so
the resolver gap stays visible instead of being counted as a proof.

## The reachability oracle (authoritative)

`REACHABILITY_ORACLE_SCHEMA = openssl-rs/campaign/safe-c33/reachability-oracle/v1`.

`ReachabilityOracle(graphs, upper_reach)` holds, per module, the final
upper-bound nodes and the union of **every name the image records for every
reached address** (`funcs`, `all_syms` and `names_at`, normalised as
`_edge_symbol`).

A negative reachability claim needs a sound over-approximation. The
derivation-time set is the pre-closure direct set, an under-approximation, so:

- records built with an oracle record the **observed** membership in the final
  upper bound and `reachable_basis = final-upper-bound`;
- records built without an oracle keep `reachable_basis = pre-closure-direct` and
  still state the observed membership and the covered symbols;
- with an oracle, the validator requires `final-upper-bound`, requires the
  oracle to cover the record's module, and refuses any claimed observation that
  differs from the oracle;
- an **unknown module fails closed**: it is a defect in the record validator and
  a violation in the audit, never "unavailable is fine".

`reachability_exclusion_audit(graphs, oracle, records=None)` walks the
**records**, not site metadata: every subject row, every target drop, every
semantic call-site row with `included: false`, and every caller-bound dropped
target. A subject that the bound reaches is a violation; a row that cannot be
checked is also a violation. The audit is mutually redundant with the record
validator (same record, same oracle) and runs in the same streaming pass.

## Sidecar and receipt identity

`build_edge_records(graphs, oracle=None, sink=None)` yields records one at a
time. `build_receipt` supplies an `EdgeRecordStream` that:

- writes one JSON object per line to
  `<workdir>/edge-records.<artifact_sha[:16]>.jsonl`. **This is always the
  default**, whatever `--output` is; `--edge-records PATH` is the only override.
  A multi-hundred-MB sidecar is never written beside `--output` by default: the
  default sidecar lives under the gitignored `court/` workdir, and the explicit
  `--edge-records` escape hatch is additionally covered by the
  `*.edge-records.jsonl` and `edge-records.*.jsonl` patterns;
- validates and audits each record in the same pass, accumulating the **full**
  defect count (only the number rendered into the refusal `detail` is capped);
- records `records_path` (repo-relative when inside the repository, else
  absolute), `records_sha256`, `records_bytes` and `sidecar_lines` in the
  receipt.

The receipt's `tool` block is `{path, version, sha256, schema}` where `sha256`
is the digest of `consumer_closure.py` at run time and `schema` is
`EDGE_RECORD_SCHEMA`. `edge_provenance.admissibility` binds
`{validator_sha256, record_schema, artifact_sha256, records_sha256,
sidecar_lines}`: admissibility of a record set requires re-running the pinned
validator over the pinned sidecar for the pinned artefact.

The receipt's `records_sample` is a bounded selection, not the population.
Exclusion-bearing records and reachable residual sites are admitted first, then
non-PROVED records fill the remaining slots, up to `--max-record-sample`
(default 500). Long per-record lists are truncated to 32 entries with a count.
The complete population is the sidecar.

## Refusal rules

`validate_edge_records(records, oracle=None)` reports a defect for any violation
above, including a duplicate `edge_id`. `build_receipt` turns defects into a
refusal and appends:

- `EDGE_RECORD_EXCLUSION_UNSOUND` — the record set is not checkable or its
  ledgers disagree; and
- `REACHABILITY_EXCLUSION_UNSOUND` — a reachability-based claim contradicts the
  final upper bound, or names a module the oracle does not cover.

## What validation proves and what it does not

**It proves:**

- internal consistency of the record: its disposition, target set, accounting,
  derivations, row kinds, structured mappings, per-call-site attribution
  witnesses and `candidate_source` agree (a contribution that its own witness
  does not show is refused);
- that every negative reachability claim in the record agrees with the
  final-upper-bound oracle for the record's module.

**It does not prove:**

- **that the record was produced by the analyzer rather than forged.** A forged
  record that is internally consistent and agrees with the bound is outside the
  power of record-level validation. Admissibility of a record set requires the
  identity chain in `edge_provenance.admissibility` (validator sha256, record
  schema, artefact sha256, sidecar digest and line count) — that is, re-running
  the pinned validator over the pinned sidecar — or an equivalent externally
  witnessed production record. Do not claim more anywhere.
- **No re-derivation to a fixpoint.** The validator does not re-run the
  precision resolver, so an internally consistent record that agrees with the
  bound is not thereby proved complete. In particular, the per-caller
  attribution is **analyzer-produced**: the validator checks that
  `contributed_targets` equals the union of the row's own call-site `targets`
  and that a drop is attributable to an excluded caller, but it does not
  re-execute the argument-summary interpreter over the image. Re-derivation is
  the pinned tool's job; record-level validation checks the record against
  itself and the oracle.
- **No real-ELF link-level coverage in the corpus.** The metamorphic corpus and
  self-test use synthetic graphs; the real run exercises the linked candidate
  DSOs of the v1p measurement (`ad5913099`, `libcrypto.so.3` `c335ac3c…`,
  rebuilt at 0.0.43 as `dadb0263…`; `atlas-refresh/build-0.0.43.json`), but no
  second derivation of the same slot is performed. Read this as the current
  candidate identity, not the v1m DSOs an earlier revision of this file named.
- **No cross-revision identity.** The oracle is per-candidate. A record is not
  checked against a second revision.
- **No cryptographic or timing claim.** This schema is about the reachability
  evidence a record carries, not about the safety of the target it names.
- **The sample is not the population.** The sidecar is the population; the
  receipt sample is a bounded, prioritised selection.
