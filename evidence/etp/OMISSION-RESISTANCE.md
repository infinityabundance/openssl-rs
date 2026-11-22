# Omission resistance for the ETP claim algebra

This receipt records a **hardening of the typed-claim validator**, not a change
to any measurement. Before the change, four machinery gaps recorded in
`evidence/etp5/REFUSALS.json` let a claim validate even when its own evidence or
a second claim contradicted it. The four gaps now have rules with exact refusal
identifiers, a control for each rule, and a re-validation of the committed
evidence. No claim is promoted, no consumer family graduates and no recorded
verdict changes.

## Source identity

| field | value |
|---|---|
| repository | `openssl-rs` |
| branch | `staging` |
| HEAD at start | `8af8870f14a0fefc76f6a353d2eb26d562e928f4` (`8af8870f1`) |
| worktree at start | clean (`git status --porcelain` empty) |
| claim source identity `S` | `9372bb28b2fbe2f71cf2aa2ab501414d45e87d42` (from `evidence/etp/claims.json`) |
| court image | `openssl-rs-court-tools:1` |
| court Python | 3.11.2 (standard library only) |
| host `available` before the runs | 26 GiB (guard threshold 24 GiB) |
| court memory cap | command environment `OPENSSL_RS_COURT_MEM=6g`, `OPENSSL_RS_COURT_MEMSWAP=6g` |
| evidence commit | the commit that introduces this file; resolve with `git log -1 --format=%H -- evidence/etp/OMISSION-RESISTANCE.md` |

Sums of the files this receipt describes (sha256, full 64 hex digits):

| file | sha256 |
|---|---|
| `forensics/tools/etp_claims.py` | `fde564ada4eb7ccbc2dc0f3a869c2520f6bec0ca164c8daf9810091ede810c2d` |
| `evidence/etp/claim.schema.json` | `f7bfba7f3f74db43d7c92fb333f055fc3aaa8e2634d6585ec3b40c6b1d72146a` |
| `forensics/tools/tests/test_etp_claims.py` | `9195f0db981db0186c4d69a664703beca7f82f48bc99bccd70a5b643c2536d6a` |
| `evidence/etp/omission/revalidate.py` | `82c5d739a9b6b630e9f9dbff58851c9ca6beab7d6d81ea1bfc7ac0d2058fd16a` |
| `evidence/etp/omission/REVALIDATION.json` | `5d9be1fae14957a5ebf980bd374402657c5c4a5451e5fc29ae110d451f2e4cff` |

## F1 — evidence state is bound to the verdict

**Gap.** An evidence record could not declare its own machine-readable state, so
nothing connected that state to the claim's verdict. An `ESTABLISHED` claim over
the withdrawn O7 bytes (probe `p4a`) and one over the element-7 record whose own
predicate says `established: false` (probe `p6`) both validated with zero
refusals.

**Rule.** An evidence record may carry `state`: a closed object with `value`
(`WITHDRAWN`, `ESTABLISHED`, `NOT_ESTABLISHED`, `SUPERSEDED`, `REFUTED`,
`PARTIAL`), the `artefact` it is about, and the `revision` it applies to. The
state is copied from the tracked artefact and is never inferred. A positive
verdict (`ESTABLISHED`, `SAFE_COMPATIBLE`) or a graduation modality
(`PROOF_OBLIGATIONS_DISCHARGED`, `BINARY_REFINEMENT_VERIFIED`) over a present
entry whose declared state is `WITHDRAWN`, `REFUTED` or `NOT_ESTABLISHED` is
refused; a positive verdict with no present entry that is not withdrawn,
refuted, not established or superseded is refused by the same rule.

**Refusal.** `EG_EVIDENCE_CONTRADICTS_VERDICT`, naming the evidence entry and
its state.

**Controls** (`forensics/tools/tests/test_etp_claims.py`):

| control | malformed input | asserted identifier |
|---|---|---|
| `test_withdrawn_evidence_over_established_is_refused` | present evidence declares `WITHDRAWN` | `EG_EVIDENCE_CONTRADICTS_VERDICT` at `evidence/0/state` |
| `test_refuted_evidence_over_established_is_refused` | present evidence declares `REFUTED` | `EG_EVIDENCE_CONTRADICTS_VERDICT` at `evidence/0/state` |
| `test_not_established_evidence_over_established_is_refused` | present evidence declares `NOT_ESTABLISHED` | `EG_EVIDENCE_CONTRADICTS_VERDICT` at `evidence/0/state` |
| `test_graduation_modality_over_withdrawn_evidence_is_refused` | `BINARY_REFINEMENT_VERIFIED` over `WITHDRAWN` evidence | `EG_EVIDENCE_CONTRADICTS_VERDICT` |
| `test_no_non_current_evidence_over_positive_verdict_is_refused` | the only present evidence declares `SUPERSEDED` | `EG_EVIDENCE_CONTRADICTS_VERDICT` at `evidence` |
| `test_positive_evidence_state_is_accepted` | evidence declares `ESTABLISHED` | no refusal |
| `test_state_requires_the_artefact_and_revision` | `state` without `revision` | `EG_SCHEMA_VIOLATION` |

A record whose state is unknown carries an obligation; the validator does not
infer a state from the verdict, the path or a note.

## F2 — `EG_MULTIPLE_CANDIDATES` is reachable on a schema-valid document

**Gap.** The pre-scan read `identity.source.candidates`, which the closed schema
forbade, so the rule could fire only together with `EG_SCHEMA_VIOLATION`.

**Rule.** `identity.source.candidates` is a permitted array of at least two
distinct identities, permitted only with `candidate_relationship`, which states
how the candidates relate. More than one candidate without that relationship is
refused, and the candidate/commit mismatch check is gated by the same condition,
because a stated relationship may legitimately bind a candidate token and a
commit that differ.

**Refusal.** `EG_MULTIPLE_CANDIDATES`.

**Controls:**

| control | input | asserted identifier |
|---|---|---|
| `test_two_candidates_without_a_relationship_is_refused` | two candidates, no `candidate_relationship` | the refusal set is exactly `{EG_MULTIPLE_CANDIDATES}` |
| `test_two_candidates_with_a_stated_relationship_are_accepted` | two candidates plus a relationship | no refusal |

The first control asserts that the document is otherwise schema-valid: the only
refusal is the candidate rule itself.

## F3 — an aggregate must be bound to the cells it summarises

**Gap.** The O7 aggregate receipt carries no per-cell receipt binding and its BB
log digest differs from the tracked per-cell BB receipt. Both files are tracked,
and the existing receipt checker passes them because each digest matches its own
bytes.

**Rule.** A claim that claims to summarise cells carries `aggregate_cells` with
`summarises_cells: true` and a `cells` list. Each cell names its `id`, the
`receipt_path` of the per-cell receipt, and that receipt's `receipt_sha256`. An
aggregate that names no cell is refused; a named digest that disagrees with the
tracked receipt is refused. The rule binds the aggregate to the cells' receipt
digests; it deliberately does not compare log contents.

**Refusals.** `EG_AGGREGATE_UNBOUND`, `EG_AGGREGATE_DIGEST_MISMATCH`.

**Controls:**

| control | input | asserted identifier |
|---|---|---|
| `test_unbound_aggregate_without_cells_is_refused` | `summarises_cells: true`, no `cells` | `EG_AGGREGATE_UNBOUND` at `aggregate_cells/cells` |
| `test_unbound_aggregate_with_an_empty_cell_list_is_refused` | `cells: []` | `EG_AGGREGATE_UNBOUND` at `aggregate_cells/cells` |
| `test_cell_digest_that_disagrees_with_the_tracked_receipt_is_refused` | cell digest `0…0` for a present receipt | `EG_AGGREGATE_DIGEST_MISMATCH` |
| `test_cell_digest_that_matches_the_tracked_receipt_is_accepted` | cell digest re-derived from the receipt | no refusal |

## F4 — a comparative measure is typed and single-valued

**Gap.** Two `ESTABLISHED` claims carrying 1/33 and 0/33 both validated and
conjoined to `ESTABLISHED`, because the counter was an opaque string.

**Rule.** A measure may be opaque (string `value`) or typed: a named `counter`
with integer `numerator` and `denominator`, or a named numeric `value` with a
`unit`. Two claims with the same property, scope, identity and measure name are
compared. Identical typed values are one observation repeated; different typed
values are refused; a named free-text measure that is compared is refused as
untyped. `conjoin` returns `CONTRADICTED` for conflicting typed counters, so a
positive meet cannot absorb the conflict.

**Refusals.** `EG_CONTRADICTION_UNRESOLVED`, `EG_MEASURE_UNTYPED`.

**Controls:**

| control | input | asserted identifier |
|---|---|---|
| `test_equal_typed_counters_are_accepted` | two claims, both `1/33` | no refusal |
| `test_different_typed_counters_are_refused` | `1/33` and `0/33` | `EG_CONTRADICTION_UNRESOLVED` at `quantification/measure` |
| `test_free_text_compared_measure_is_refused` | same name, string values `1/33` and `0/33` | `EG_MEASURE_UNTYPED` at `quantification/measure` |
| `test_numeric_measures_with_different_values_are_refused` | named numeric `1` and `0` families | `EG_CONTRADICTION_UNRESOLVED` |
| `test_conjoin_blocks_conflicting_counters` | direct `conjoin` of the two typed claims | verdict `CONTRADICTED`, `measure_conflicts` present |
| `test_contradictions_operation_reports_conflicting_counters` | `contradictions` over the two typed claims | a `value` conflict named `safe_compatible_counter` |

## Re-validation against committed evidence

The stricter validator was run over the committed evidence and over every
tracked ETP-5 probe. The probe inputs were read, not rewritten.

### `evidence/etp/claims.json`

* 35 claims, **0 refusals** under the schema, the cross-field laws and the
  Git-bound digest re-derivation.
* **No committed claim loses acceptance.** The committed evidence declares no
  `state`, no `candidates`, no `aggregate_cells` and no named measure, so none of
  the new rules fires. The distinction to state plainly: **the rules were too
  weak before; the evidence was not wrong.**
* No committed evidence was repaired by rewriting. The re-validation additions
  are new files under `evidence/etp/omission/`.

### Tracked probes (read-only)

| probe | before | after the change |
|---|---|---|
| `p1-openssh-graduation-promotion` | refused | refused (`EG_GRADUATED_WITH_OPEN_OBLIGATION`, `EG_GRADUATED_WITHOUT_CLOSURE`) |
| `p2-openssh-two-records` | refused | refused (`EG_CONTRADICTION_UNRESOLVED`) |
| `p3-counter-single-source` | refused | refused (`EG_CONTRADICTION_PARTIES`) |
| `p3b-counter-promotion` | refused | refused (`EG_GRADUATED_WITHOUT_CLOSURE`, `EG_GRADUATED_WITH_OPEN_OBLIGATION`) |
| `p3c-counter-two-established` | **accepted** | **accepted** — the measure has no `name`, so no comparison is possible |
| `p4a-withdrawn-o7-historical-accepted` | **accepted** | **accepted** — the record declares no `state` |
| `p4b-withdrawn-o7-current-identity` | refused | refused (`EG_EVIDENCE_DIGEST_MISMATCH`) |
| `p4c-withdrawn-o7-nonpromotion` | accepted (non-promotion) | accepted (`WITHDRAWN` verdict) |
| `p5-build-b-identity-split` | refused | refused (`EG_MULTIPLE_CANDIDATES`) |
| `p6-curl-element7-closed` | **accepted** | **accepted** — the record declares no `state` |
| `p6b-curl-graduation-promotion` | refused | refused (`EG_GRADUATED_WITHOUT_CLOSURE`, `EG_GRADUATED_WITH_OPEN_OBLIGATION`) |
| `p6c-curl-element7-typed` | accepted (`NOT_ESTABLISHED`) | accepted (`NOT_ESTABLISHED`) |

`p4a`, `p6` and `p3c` remain accepted because the typed probe documents do not
declare the state or the measure name that would make the new rules applicable.
That is the A17 omission, not a validator pass: a producer that omits the state
or the comparison key is outside what a claim-inspecting validator can detect.
No probe was edited to make its gap disappear.

### Derived demonstrations against the same tracked artefacts

`evidence/etp/omission/revalidate.py` reads the tracked probes and artefacts and
derives typed documents in memory; `evidence/etp/omission/REVALIDATION.json`
records the result. Each derived document adds only the typed field the rule
requires: the state the tracked artefact states, the aggregate binding the
aggregate omits, or the typed counter both ledger readings state. No tracked
probe or receipt is edited.

| demonstration | source | observed |
|---|---|---|
| F1 withdrawn O7 | `p4a` plus the revision's `WITHDRAWN` state | `EG_EVIDENCE_CONTRADICTS_VERDICT` at `$.claims/0/evidence/0/state` |
| F1 element 7 | `p6` plus the triage's `NOT_ESTABLISHED` state | `EG_EVIDENCE_CONTRADICTS_VERDICT` at `$.claims/0/evidence/1/state` |
| F3 unbound aggregate | O7 aggregate with no cell digests | `EG_AGGREGATE_UNBOUND` at `$.claims/0/aggregate_cells/cells` |
| F3 digest mismatch | O7 aggregate log digest used as the BB cell receipt digest | `EG_AGGREGATE_DIGEST_MISMATCH` at `$.claims/0/aggregate_cells/cells/0` |
| F3 bound aggregate | the four tracked per-cell receipt digests (`AA 053037d3…`, `AB 02df1f09…`, `BA 82191db9…`, `BB 341f836a…`) | accepted |
| F4 typed counter | `p3c` with `1/33` and `0/33` read from `consumers.safe_compatible` and `consumers.note` | `EG_CONTRADICTION_UNRESOLVED` at both `quantification/measure` paths; `conjoin` verdict `CONTRADICTED` |
| F4 untyped counter | the same probe with a measure name and free-text value | `EG_MEASURE_UNTYPED` at both `quantification/measure` paths |

## Determinism

All output is sorted and carries no timestamp.

```
python3 forensics/tools/tests/test_etp_claims.py   -> Ran 78 tests ... OK
python3 forensics/tools/etp_claims.py validate     -> valid true, 35 claims, 0 refusals
validate run twice, cmp                            -> VALIDATE_DETERMINISTIC
revalidate.py twice, cmp                           -> DETERMINISTIC_SAME
revalidate.py, cmp against committed REVALIDATION  -> REVALIDATION_STABLE
```

The suite grew from 59 tests to 78: 19 new controls, each asserting an exact
rule identifier. The committed `claims.json` still validates 35/35 with 0
refusals, and the re-validation document is byte-identical across runs.

## What the machinery still cannot establish

* **Omission by a producer that publishes nothing.** A validator can only
  inspect a claim that exists. A producer that never publishes the aggregate,
  never publishes a cell receipt, or never declares a state is not detected.
  The remaining A17 mechanism is a **pre-execution expected-evidence manifest**
  closed by a signed reconciliation manifest, so an absent item is a
  reconciliation failure rather than an absent rule trigger. That mechanism is
  not implemented here.
* **Aggregate completeness.** The rule checks every cell the aggregate names, but
  it cannot know how many cells the aggregate should name. A producer that names
  a strict subset of the cells, or a different population, is bound only for the
  cells it did name; completeness again needs the expected manifest above.
* **The artefact's own state is copied, not parsed.** The validator cannot read
  an arbitrary record's schema to discover whether it says `WITHDRAWN`. A
  producer that omits `state` leaves an obligation; the algebra does not infer
  one. `revalidate.py` demonstrates the rule only by copying a state the tracked
  record already states.
* **An aggregate is bound by receipt digests, not by log content.** A bound
  aggregate may still record a log digest that differs from a cell's log. The
  rule closes the unbound aggregate; resolving the log difference is a matter
  for the interop receipt's own checker.
* **No independent review, signing or witness.** A declared reviewer or signer
  is a declared field. Distinctness is enforced; organisational independence,
  signature verification and transparency-log inclusion are outside this change.
* **`--no-tree-check` remains an explicit escape.** With it, aggregate and
  evidence digests are not re-derived. It is opt-in; the default re-derives them.
* No Rust build, sanitizer, Miri, cryptographic vector or timing instrument was
  run: the change is Python validator machinery and its evidence is the controls
  and re-validation above.

## Files changed

| file | change |
|---|---|
| `evidence/etp/claim.schema.json` | optional evidence `state`; schema-permitted `candidates` and `candidate_relationship`; typed `measure` alternatives; `aggregate_cells` binding with `cells` |
| `forensics/tools/etp_claims.py` | F1 evidence-state rule; reachable F2 rule; F3 aggregate binding and digest re-derivation; F4 typed-measure comparison; `conjoin` returns `CONTRADICTED` on conflicting counters |
| `forensics/tools/tests/test_etp_claims.py` | 19 controls for F1–F4, each asserting the exact identifier |
| `evidence/etp/omission/revalidate.py` | deterministic, read-only re-validation of committed evidence and probes |
| `evidence/etp/omission/REVALIDATION.json` | generated re-validation record |
| `evidence/etp/OMISSION-RESISTANCE.md` | this receipt |
| `docs/ETP-CLAIM-ALGEBRA.md` | normative description of the four rules and their refusals |
| `docs/ETP-TODO.md` | ETP-1, ETP-5 and A17 rows updated |
