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

Additive fields under `v1.4` (no schema-id change): **admission by refutation**.
An exclusion derived against the pre-closure direct set is false when the sound
upper bound reaches its subject. The site then carries
`refutation_admissions` (the admitted subject, role, address and admitted
targets) and `refuted_exclusions` (the role and subject of each refuted
claim), and the admitted targets carry a `refutation-admission` derivation step
in `provenance_chain`. A refuted caller becomes an ordinary reachable caller row
(`admitted_by_refutation: true`) and may be named in
`candidate_source.refutation_admitted_callers`; a re-derived stored-value site
names retained targets in `candidate_source.refutation_targets`. A subject with
no finite recorded contribution makes the site `UNRESOLVED` with a
`refutation-unbounded` missing property rather than keeping an unsound finite
claim. Exclusions the bound does not reach survive unchanged and are validated
as before.

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

## The closure operator (v1.5): monotone bound and least fixed point

`build_graph` is the definition of the reachable set the oracle then judges. Two
soundness defects were fixed in `forensics/tools/consumer_closure.py`
(`closure-fixpoint-repair.json` records the measurements):

1. **Non-monotone residual admission.** For a *classified* unresolved site the
   v1.4 bound was the class-specific set (`taken_code` ∪ field-store values ∪
   unknown-call-argument targets). That set is not a superset of what the same
   site admitted when it was `PROVED_TARGET_SET`, so losing precision narrowed
   the reachable set. Across v1n→v1p, 59 sites went `PROVED→UNRESOLVED`, dropped
   whole evaluated unions, and `CRYPTO_cbc128_encrypt` left the bound although
   the consumer `.text` was byte-identical.
2. **One-pass closure.** Residual admission was applied once, to the direct
   reachable set only, so a function reached *through* residual admission was
   never scanned for its own unresolved sites:
   `root → dispatch A → B → dispatch B → C` omitted `C`.

### The bound (`unresolved_site_bound`)

Every residual site is bounded by the union of **all** materialised-address
evidence for its module, independent of its class:

- `address_taken_union` (code/data materialisations, relocated function slots,
  and in-image dynamic-relocation targets);
- `taken_code` (named explicitly so the record shows the source);
- every integer stored into a field by reachable code (`field_stores`);
- every value passed at an unresolved call site
  (`unknown_call_arg_targets`);
- the site's own resolver `targets` and `arg_targets`.

A class-specific set remains in the receipt as **precision reporting** (the
per-site class and `precision.unresolved_by_class`), never as the sole bound.
The rule is one-directional: **a bound may be widened for soundness, never
narrowed by classification.**

Address to node mapping is also widening-only. A value that is a defined
function start is its own node; an integer inside `.text`/`.plt`/`.plt.got` is
mapped to its enclosing function start; a non-executable integer cannot be a
function entry and is counted (`bound_evidence_sources.*.non_code_values`), not
silently used; a symbolic target resolves through the export index and an
unresolved one is counted. No start-set filter is applied to the evidence
union, so no function-start target can be dropped by the bound.

**Dynamic-relocation widening.** `taken_code`, `taken_data` and `slot_funcs`
were built only from in-image code materialisations and `R_X86_64_RELATIVE`
slots. A `R_X86_64_GLOB_DAT`/`JUMP_SLOT` slot whose symbol is defined in the
same image fixes a function address exactly as a RELATIVE slot does, and was
missing. `publish()` now adds those targets (`dynamic_reloc_targets`) to
`address_taken_union`. On the three measured libcrypto builds the widening adds
1,346–1,349 functions, including `CRYPTO_cbc128_encrypt` (referenced by a
`GLOB_DAT` slot and by call/jump slots — the earlier finding recorded 25 from
21 callers), which is absent from the pre-widening union in every build:

| libcrypto | pre-widening union | + dynamic relocs | `address_taken_union` | CBC member |
|---|---|---|---|---|
| v1p `dadb0263…` | 5,238 | 1,349 | 6,587 | yes |
| v1p neutral `c335ac3c…` | 5,244 | 1,346 | 6,590 | yes |
| v1n `3901731a…` | 5,248 | 1,347 | 6,595 | yes |

### The iteration (least fixed point)

```
reach = walk(roots)                       # direct edges, resolved site edges, export aliases
for round in 1..max_rounds:
    bound = ⋃ unresolved_site_bound(g, s)
              over every unresolved site whose containing function is in reach
    nxt   = walk(reach ∪ bound ∪ imports)
    if nxt == reach: converged at round; break
    reach = nxt
```

This is chaotic/worklist iteration over a finite lattice: the node set is the
finite set of function addresses in the linked DSOs, `walk` is a monotone graph
closure, and the transfer function only unions evidence, so `reach` is
increasing. It therefore terminates in at most `|V|` non-final rounds; the cap
is `4 × total_functions + 8` (65,424–65,552 in the measured runs) and a run
that hits the cap returns `converged = false` and appends the refusal
`CLOSURE_NONCONVERGENT` naming the cap, the last growth and the reachable size.
A partial bound is never accepted. The standard concepts are Kildall 1973 (a
unifying lattice-theoretic data-flow framework) and Cousot & Cousot 1977
(abstract interpretation); no quotation is implied.

The return value keeps `direct_reachable` and `upper_reachable` (the fixpoint)
and adds `closure_rounds`, `round_sizes`, `sites_scanned_per_round`,
`converged`, `nonconvergent_detail`, `residual_bound_nodes` and
`bound_evidence_sources`.

### Analysis identity and retention

`analysis_identity(graphs)` is the canonical identity of the **analysis input**
(domain `openssl-rs/campaign/safe-c33/analysis-identity/v2`). Per module it binds:

- every allocated (SHF_ALLOC) section's name, ELF type, virtual address, size
  and byte digest. The selection is "allocated minus metadata", not a
  hand-maintained allowlist: `section_of` is unconstrained in `cstring_at` and
  `switch_targets`, so a new allocated section is bound automatically. The
  required minimum is `.text`, `.plt`, `.plt.got`, `.init`, `.fini`, `.rodata`,
  `.data`, `.data.rel.ro`, `.data.rel.ro.local`, `.got`, `.got.plt`,
  `.init_array`, `.fini_array`; `.bss` and other SHT_NOBITS sections contribute
  their address and size only;
- the sorted relocation table `(section, section-relative offset, type,
  canonical symbol, addend)` read by `_build_slots` for
  `R_X86_64_RELATIVE`, `GLOB_DAT`, `JUMP_SLOT` and `R_X86_64_64`;
- the sorted `[name, addr, size, kind]` defined-symbol rows (the v1 input);
- the sorted dynamic-symbol rows (the export set used by `export_index`, the
  resolver and the dynamic-reloc widening);
- the loader entries (SONAME/NEEDED/RUNPATH/RPATH) that select the modules.

The symbol names are canonicalised for the compiler-generated `.llvm.<hash>`
suffix and the `@@VERSION` suffix (both name no distinct analysis subject; the
address, size and kind keep distinct symbols distinct). Analysis-irrelevant
metadata is excluded and named in the basis: `.debug_*`, `.comment`, `.note*`,
`.gnu_debuglink`, the build-id note, `.gnu.build.attributes`, and every
non-allocated section (for example `.symtab`, `.strtab`, `.shstrtab`). The DSO
file digest is recorded as a **non-identity**: a comment-only edit changes it
while the analysis sections and symbol addresses are unchanged.

This closes the v1 limitation that two candidates with different data but
identical `.text` and symbols shared an identity. It is **not** a proof of input
completeness: it binds the enumerated inputs of this derivation, and a new read
of another section requires extending the enumeration. The negative control
(`court/closure/negative-control-result.json`) patches one `.data.rel.ro`
dispatch-slot relocation addend with `.text` and the symbol table byte-identical:
the identity changes and the targeted build_graph upper bound gains the patched
function. The positive control (`court/neutral/a` vs `b`) keeps the identity
equal across a comment-only rebuild.

### Symbolic-target dispositions (P0-B)

A symbolic value in the module residual bound or in a site's own bound is never
counted and discarded. It is resolved through this fixed order and recorded in
`graph.closure.symbol_dispositions`:

1. `exact-export` (the name as written in `export_index`);
2. `version-stripped-export` (`name.split('@')[0]`);
3. `names-at` (every defined-symbol-table alias address for the base name);
4. `dynamic-symbol-table` (the module's `.dynsym` definition);
5. `soname-qualified-import` (`libcrypto.so.3:NAME` whose target module
   matches);
6. `plt-stub` (a `.plt`/`.plt.got` stub jumping through the symbol's GOT slot).

Every row carries `symbol`, `module`, `slot_offsets`, `sites`, `disposition`,
`path` and either `targets`, an `external_interface` with its justification, or a
`reason`. `external-contract` is available only for an exact name in the cited
`EXTERNAL_SYMBOL_CONTRACTS` table; it is not a wildcard and not a way to clear a
refusal. Any remaining `blocking` row produces the refusal
`CLOSURE_UNRESOLVED_SYMBOL`, which names **every** blocking symbol, module, slot
and site. The summary counts (`resolved` / `external-contract` / `blocking`) are
descriptive; the rows are the evidence.

On the v1p candidate the five values the v1 receipt counted as unresolved
(`CRYPTO_128_unwrap`, `CRYPTO_128_unwrap_pad`, `CRYPTO_128_wrap`,
`CRYPTO_128_wrap_pad`, `PEM_def_callback`, each carrying
`@@OPENSSL_3.0.0`) resolve by `version-stripped-export`: the bound value carries
the version suffix from `readelf -rW`, while `export_index` is keyed by the
version-stripped name. No symbol is marked external and no blocking symbol
remains.

The receipt persists `graph.closure.reachable_functions` (sorted
`module:hex:name`), `reachable_functions_sha256` (sha256 over the
newline-terminated entries), `reachable_functions_per_module` and the identity
block, so a movement between candidates can be adjudicated from the receipt
rather than the ~1.3 GB record sidecar.

### Source-root hash rules

The build record hashes the pristine tree with
`sha256('openssl-rs/source-tree/v1\0' + path\0bytes\0)`; the build/link atlas
emits `sha256(canonical_json(sorted [[relpath, size, sha256]]))` under the same
field name. The v1.4 check compared them directly, so it always failed when
provenance was supplied. `source_root_hash_checks` now classifies both rules and
compares like with like: equal rules compare `source_root_hash` (`STALE_HASH` on
difference), different rules emit `HASH_RULE_MISMATCH` naming both, and
`source_tree_domain_hash` is compared when both sides provide it.

### Non-claims

- The bound is a may-bound, not a completeness proof: a function that no
  materialised-address source names is not admitted.
- Monotonicity is a property of the transfer function, not of any particular
  pair of builds. The measured v1p-install vs neutral-build pair is **not** a
  neutral control: their `.text` differs (4,962,638 vs 4,950,510 bytes) because
  `Cargo.toml` moved 0.0.42 → 0.0.43, a build-relevant input. Cross-build
  stability of the fixpoint is therefore not established by that pair.
- The extended analysis identity binds the enumerated inputs (sections,
  relocations, defined and dynamic symbol tables, loader entries); it is not a
  proof that no other input exists, and it is not a cross-toolchain
  byte-reproducibility claim.
- A symbol disposition is a record of a resolution path, not a proof that the
  resolved target is the only target the site can select.

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
