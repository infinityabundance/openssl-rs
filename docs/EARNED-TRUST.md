# Earned trust — the claim constitution

Status: normative. Delivered by ETP-T14 of `docs/ETP-TODO.md` at candidate
`1e068243d2ec045852bddd3e64c4d6233829eb1d` (`staging`).
Machine record: `evidence/etp-t14/ARTICLES.json` (schema
`openssl-rs/etp-t14/articles/1`).
Consistency checker: `forensics/tools/earned_trust.py`, invoked from
`forensics/tools/docs_consistency.py`, which is release-gate item 6.
Release mapping: `docs/RELEASE_GATES.md` §10.

## 1. What this document is

This is the constitution of the project's standing commitments about claims. It
is **normative and cumulative** with `AGENTS.md` and with the documents that
standard cites: it adds no permission and withdraws none, and where an article
and a clause describe the same commitment, the stricter reading governs. A
session re-reads it at the point of use, exactly as it already re-reads
`AGENTS.md`.

An article is a rule about **what may be claimed**, not a description of the
code. Each article has four fields, and all four are part of the article:

- `Why` names the failure mode the article prevents, with an observed instance
  where one exists.
- `Enforced by` names the tool and rule identifier that refuses a violation, or
  a structural property of a type that makes the violation inexpressible.
  Everything named here exists and runs at the candidate above.
- `Refused when` is the observable condition: the input a reader can construct
  and watch the check reject.
- `Not established` is what the article does not promise. It is not a
  disclaimer appended to the article; it bounds it.

**An article with no enforcement says so in `Enforced by`, and that sentence is
an open item rather than a claim.** No article may claim an enforcement that does
not exist, and no rule identifier may be cited that the credited tool does not
emit.

The mapping is machine-checked by `forensics/tools/earned_trust.py`, which fails
closed. It refuses an `Article N` citation in `AGENTS.md` or
`docs/RELEASE_GATES.md` that names no article (`ET_CITATION_UNKNOWN`), an article
that names no enforcement and does not declare that none exists
(`ET_ENFORCEMENT_ABSENT`), a cited rule identifier absent from the tool it
credits (`ET_ENFORCEMENT_UNKNOWN`), a gate section that does not name every
article no gate item covers (`ET_GATE_LIST_MISMATCH`), and a release-gate mention
of an article that no gate item covers (`ET_GATE_UNCOVERED`). An unparseable
input is a refusal, never a pass.

---

### Article 1. A claim may never exceed its evidence

- **Why.** A sentence acquires the status of a result because a document was
  written. The observed form at ETP-0 is four `CONTRADICTED` claims: a seal prose
  claim against the tracked registry (`ETP0-CLM-004`), a probe claim against the
  probe source and machine threshold (`-005`), a graduation record against its
  adjudication and closure receipts (`-030`), and a campaign counter against its
  own non-claim (`-032`).
- **Enforced by.** `forensics/tools/etp_claims.py` — `EG_VERDICT_MODALITY` (a
  verdict that outruns its modality), `EG_EVIDENCE_CONTRADICTS_VERDICT` (a
  positive verdict over `WITHDRAWN`, `REFUTED` or `NOT_ESTABLISHED` evidence, or
  over no present current evidence), `EG_GRADUATED_WITH_OPEN_OBLIGATION`, and the
  closed claim type (`EG_SCHEMA_VIOLATION`), which has no field for a combined
  strength; `forensics/tools/release_gate.py` — `RG_CLAIM_CONTRADICTED`,
  `RG_CLAIM_REFUTED`, `RG_CLAIM_WITHDRAWN`;
  `forensics/tools/continuous_enforcement.py` — `CE_REFUSED_PUBLICATION_CLAIM` (a
  claim asserts publication the B4 record does not support) and
  `CE_REFUSED_PROFILE_NOT_ADMITTED` (a claim asserts admission the B4 record does
  not support).
- **Refused when.** A claim whose verdict is `ESTABLISHED` or `SAFE_COMPATIBLE`
  rests on an evidence entry whose declared state is `WITHDRAWN`, `REFUTED` or
  `NOT_ESTABLISHED`, or on no present current evidence; a `DOCUMENTED` modality
  carries an `ESTABLISHED` verdict; a graduation carries an open obligation; a
  release candidate's claim set contains a contradicted, refuted or withdrawn
  claim.
- **Not established.** The validator checks the claim's form and its internal
  laws, not whether the cited experiment occurred, whether the evidence is true,
  or whether the population is adequate. A green `validate` is a statement about
  claim form, never about the truth of the content.

### Article 2. Evidence is bound to an exact identity

- **Why.** Five consecutive `SAFE_COMPATIBLE` adjudications were rejected for
  identity drift rather than analysis: the analysed DSO was not the rebuilt one
  and the executed consumer was not the analysed one (`AGENTS.md` §22). ETP-T11
  then found 0 of 78 requirements bindable to an identity, and ETP-0 recorded
  eight `identity_mismatch` gaps.
- **Enforced by.** `forensics/tools/etp_claims.py` — the tree check re-derives
  every cited digest from the Git object at `identity.source.commit`
  (`EG_EVIDENCE_DIGEST_MISMATCH`) and refuses several candidates without a stated
  relationship (`EG_MULTIPLE_CANDIDATES`); `forensics/tools/freshness.py` —
  `FR_EVIDENCE_SUPERSEDED`, `FR_IDENTITY_UNKNOWN`; `forensics/tools/scheduling.py`
  — the applicability identity of source, tool, instrument, target and
  population, with `SC_IDENTITY_UNKNOWN_FIELD` and `SC_IDENTITY_MISSING_FIELD`
  refusing an incomplete identity before any cache lookup;
  `forensics/tools/release_gate.py` — `RG_TRIAGE_STALE`,
  `RG_CLAIM_HISTORICAL_EVIDENCE`.
- **Refused when.** A cited digest cannot be re-derived at the stated commit; two
  candidate identities are named without a stated relationship; an evidence
  artefact's bytes differ from its recorded digest; artefact identity cannot be
  established; the identity triage is bound to a different dependency registry; a
  historical record is cited as current evidence.
- **Not established.** An exact binding does not prove that the bound bytes were
  executed, and does not establish that two identities are the same source or the
  same binary. A label and a digest do not identify the producing toolchain, and
  the checker holds no model of which differences between two identities are
  immaterial.

### Article 3. Deferred is never pass

- **Why.** A check that was not run becomes context rather than a gap: a prose
  receipt quotes a full-suite count, a green exit code stands in for the result,
  and "will be run" is read as run. ETP-T11 found 78 requirements with 0
  `SATISFIED`, 59 `NOT_RUN` and 19 `REFUSED`, every recorded claim prose.
- **Enforced by.** `forensics/tools/scheduling.py` — the five-state vocabulary
  `SATISFIED`/`NOT_RUN`/`FAILED`/`REFUSED`/`BLOCKED`, worst-of aggregation in
  which `BLOCKED` outranks every other state, exit codes in which only `0` is
  satisfied, and `SC_BLOCKED_WITHOUT_BOUND`/`SC_RESULT_EXCEEDS_BOUND`;
  `forensics/tools/etp_claims.py` — `EG_VERDICT_MISSING_SETTLING_OBLIGATION` (an
  `UNKNOWN` or `NOT_ESTABLISHED` verdict must name what would settle it),
  `EG_GRADUATED_WITH_OPEN_OBLIGATION`; `forensics/tools/instrument_qualify.py` —
  `IQ_CONTROL_STATUS` (a `RECORDED` instrument control is not a `PASS`);
  `forensics/tools/release_gate.py` — `RG_CLAIM_NOT_ESTABLISHED`.
- **Refused when.** A declaration has an incomplete identity (resolved to
  `REFUSED`, never to `SATISFIED`); a `PASS` or `FAILED` record has no complete
  resource observation or exceeds a bound; a `BLOCKED` claim carries no bound and
  observed value; an `UNKNOWN` verdict carries no settling obligation; a
  graduation rests on an open obligation; a `RECORDED` control is presented as a
  pass.
- **Not established.** The scheduling tool does not run the checks it names: a
  `SATISFIED` aggregate says a `PASS` is bound to the exact identity claimed, not
  that the result is correct or the population adequate. The release gate holds
  only the claim-level and instrument-level deferral refusals; the scheduling tier
  vocabulary is not a release-gate item.

### Article 4. An omission is not a pass

- **Why.** A closure that does not see a call is treated as if the call did not
  exist, and a summary is read as stronger than its worst member. At
  `7e70b667f` the closure audit recorded 1 121 omissions, 744 failing, 695 of
  them structurally complete but uncheckable at the recorded identity; a
  `SAFE_COMPATIBLE` record carrying a `NOT_ESTABLISHED` dissent was audited as a
  pass, and a campaign counter reported 1/33 with three blocked adjudications.
- **Enforced by.** `forensics/tools/closure_discipline.py` — the five-requirement
  exclusion bar and `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`;
  `forensics/tools/etp_claims.py` — `EG_AGGREGATE_PASS_HIDES_BLOCKED_CELL`,
  `EG_AGGREGATE_CELL_STATE_UNDECLARED`, `EG_SAFE_COMPATIBLE_CLOSURE_UNBOUND`,
  `EG_SAFE_COMPATIBLE_EXCLUSION_FAILS_BAR`; `forensics/tools/traceability.py` —
  `TG_UNDECLARED_ORPHAN` (class-13 projection of a failing exclusion);
  `courts/phase18/interop/check_receipts.py` — `R2` (a withdrawal that names no
  successor), `R5` (a manifest that claims a count it did not derive), and the
  parse, live-receipt and log-digest rules beside them.
- **Refused when.** A positive aggregate contains a cell whose declared state is
  blocked, or omits the state of a cell; a `SAFE_COMPATIBLE` verdict names no
  closure receipt, or a receipt with a failing exclusion; a target-drop or
  residual sample is shorter than the total the receipt declares, so the
  unrecorded remainder is counted as failing; a limitation has no edge, reason or
  procedure; a live receipt carries a zero-exit claim it did not derive.
- **Not established.** A passing row establishes that the procedure *can be run*
  against the recorded identity, not that it was re-run, that its result is
  correct, or that the external implementation is safe. The audit reads the
  populations the receipts record and cannot enumerate an operation a receipt never
  records; CPU intrinsics, inline assembly and libc syscall wrappers are not
  separately enumerated.

### Article 5. Independence is never asserted without a distinct trust domain

- **Why.** A role label is read as a party. All 50 recorded assignments have an
  adjudicator from the author's own party, 0 parties are declared and 0 external
  trust domains exist; the b85c adjudication asserted independence and is refused
  on four grounds, and "an independent agent is not an independent organisation"
  is a standing rule of `docs/ETP-TODO.md`.
- **Enforced by.** `forensics/tools/independence.py` — `IND_REVIEW_UNSUPPORTED`
  (independence asserted with no reviewer identity, role or artefact),
  `IND_ADJUDICATOR_IS_AUTHOR`, `IND_REVIEWERS_ALIASED`, `IND_THRESHOLD_ALIASED` (a
  distinct-party threshold met by aliases of one party),
  `IND_REPRODUCER_CONTAMINATED` (an "independent" reproduction that used this
  repository's environment or a project-produced artefact), plus structural
  refusals for an unknown role or class, an aliased party, an unfilled required
  role and a recorded sameness that disagrees with the computed sameness;
  `forensics/tools/release_gate.py` — `RG_AUTHORISATION_REFUSED` (a release
  action refused, not run, or signed by too few distinct signers) and
  `RG_THRESHOLD_UNMET` (the release threshold unmet or unreachable over distinct
  established trust domains).
- **Refused when.** A review asserts independence without a reviewer identity; the
  adjudicator is the author's party where the class requires separation; a
  threshold is met by two aliases of one party; a reproduction used this
  repository's environment or a project artefact; a recorded aggregate is better
  than the computed conservative meet.
- **Not established.** No external independence exists today: no party outside the
  project is named in any tracked artefact, no artefact is signed, and
  `SAFE_COMPATIBLE` and `SAFETY_DISCHARGED` remain unreachable for a family whose
  adjudicator is the author. The checker does not verify that a named reviewer
  acted or that a declared organisation exists. **No release-gate item runs
  `independence.py check`**; `gate-7` and `gate-8` run `authorisation.py` and
  `thresholds.py` and refuse a release whose role separation or distinct-domain
  threshold fails, which is the part of this article a release artefact can
  evidence, while the independence check itself remains outside the gate.

### Article 6. A specification is never a restatement of the implementation

- **Why.** A specification written by reading the code cannot find a code defect,
  and a requirement document that names the implementation's internals restates
  the artefact it is supposed to constrain. `RFE-1` and `RFE-2` are undischarged
  (`NONE`): no separate abstract specification artefact exists for the executable
  reference to refine.
- **Enforced by.** `forensics/tools/spec_guard.py` — `SP_INTERNAL_IDENTIFIER` (a
  tracked specification may not name an internal Rust function, type or module, or
  a `src/...`/`crate::` path, without an exemption), `SP_EXEMPTION_UNJUSTIFIED`
  (an exemption needs a justification, a reviewer and a review date),
  `SP_STALE_EXEMPTION` (an exemption the text no longer needs is refused),
  `SP_NO_LEVEL` (every specification declares a refinement level), and
  `SP_GRAPH_EMPTY`; the population is derived from the T1 requirement sources and
  the contract documents, so a member cannot be hand-omitted.
- **Refused when.** A specification names an internal implementation identifier
  without a justified, reviewed, still-matching exemption; a specification
  declares no refinement level; the requirement graph records no source for the
  population.
- **Not established.** The guard is a static identifier scan. It does not detect an
  internal concept restated in prose without naming it, and it cannot decide
  semantic independence; those remain review obligations. No refinement edge is
  discharged, so the article constrains specification text, not a refinement
  claim. **No release-gate item runs `spec_guard.py`**, so Article 6 is not
  covered by the release gate.

### Article 7. A proof in a model is not a proof about the binary

- **Why.** A result over a model, a source-level analysis or a proof assistant is
  read as a statement about the compiled artefact, and then inherited across
  targets and profiles. Kani ran on `nightly-2026-08-21` rather than the pinned
  `1.98.1`, so no Kani result is claimed; BINSEC returns `unknown` on the ladder
  and the inversion; `RFE-4` (ABI contract → machine code) remains `NONE`.
- **Enforced by.** `forensics/tools/binary_assurance.py` —
  `BA_CROSS_TARGET_INHERITANCE` and `BA_CROSS_PROFILE_INHERITANCE` (a claim whose
  evidence is bound to another target or build profile), `BA_FORBIDDEN_CLAIM` (a
  status or modality text asserting a source-to-binary correspondence is refused
  because no artefact bears it), `BA_UNBOUND_ASSERTED` (an unasserted claim must
  be recorded as a gap, with status `NONE`/`UNBINDABLE`, instrument `NONE` and no
  artefact binding), `BA_TCB_MISMATCH` and `BA_EVIDENCE_DIGEST_MISMATCH`.
- **Refused when.** A claim's evidence is bound to a different target triple or
  build profile; a claim asserts a source-to-binary correspondence with no
  artefact; an unasserted claim carries a status, instrument or artefact binding;
  a build's TCB digest differs from the claim's; a claimed artefact digest differs
  from the recorded build's.
- **Not established.** The checker does not verify that an instrument measured what
  it names, and no source-to-binary correspondence is established. Byte-identical
  builds are a build-identity result, not a refinement result. **No release-gate
  item runs `binary_assurance.py`**, so Article 7 is not covered by the release
  gate.

### Article 8. A constant-time result is not a proof of constant time

- **Why.** A low dudect `|t|` is read as proof, an assembled absence of conditional
  branches is read as secret independence, and a ctgrind count is quoted without
  the harness and taint identity that produced it. `docs/NON_CLAIMS.md` §3 already
  limits the wording to "no statistically detectable timing class was observed
  under the specified test conditions".
- **Enforced by.** `forensics/tools/side_channel_erasure.py` —
  `CT_T_WITHOUT_PREREGISTERED_GEOMETRY` (a `t` statistic with no pre-registered
  geometry, controls and stopping conditions is refused),
  `DUDECT_STATE_1_TREATED_AS_PROOF`, `CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT`,
  `SECRET_DEPENDENT_CONTROL_WITHOUT_EVIDENCE`; `forensics/tools/instrument_qualify.py`
  — `IQ_DISCLAIMER`, `IQ_SCOPE` and `IQ_FAILURE_MODES`, which require every
  registered timing instrument to state what it does not establish, the profile it
  applies to, and its failure modes.
- **Refused when.** A timing claim quotes a `t` statistic without the
  pre-registered geometry; a dudect state-1 result is recorded as a proof; a
  ctgrind count is recorded without the harness and taint identity; a
  secret-dependent control site carries no evidence; a timing instrument's
  register entry states no soundness limits, scope or disclaimer.
- **Not established.** No constant-time property is proved for any algorithm. A
  clean ctgrind, dudect or BINSEC result is the absence of a detected class under
  one geometry, on one target, compiler and profile. The branch audit is a review
  aid, not a secret-dependence result. The release gate holds only the instrument
  register item (`gate-4`); a claim's *wording* reading a timing result as proof is
  refused by `side_channel_erasure.py`, which no release-gate item runs.

### Article 9. Severity is not a probability

- **Why.** A severity multiplied by a guessed likelihood becomes a number a reader
  treats as an expected loss. The hazard register's `severity` is the local
  severity *before* the barrier (`docs/HAZARD-REGISTER.md` §5), and the
  memory-safety exposure precedence and its `S0`…`S4` tiers are a review ordering
  whose own non-claim states that a class is not a likelihood and a tier is not a
  probability or a vulnerability count.
- **Enforced by.** `forensics/tools/hazard_register.py` — `HR_FMEA_SEVERITY`
  requires a severity from the closed vocabulary `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`,
  and the register records no likelihood, frequency, probability or risk-score
  field for a severity to be combined with; `forensics/tools/side_channel_erasure.py`
  — `ER_BAD_SEVERITY` applies the same closed vocabulary to erasure findings;
  `forensics/tools/ms_exposure.py` derives the exposure classes and tiers with the
  recorded non-claim that the precedence is a review ordering, not a probability.
  **No tool refuses a reader who treats a severity as a probability**; that half of
  the article has no mechanical enforcement and is a review obligation.
- **Refused when.** An FMEA row names no severity or a severity outside the closed
  set; an erasure finding does the same.
- **Not established.** No tool establishes that a severity is comparable across
  components, that one hazard is more likely than another, or that any hazard's
  likelihood has been estimated. A prose document may still multiply a severity by
  a guessed probability without a refusal. **No release-gate item runs
  `hazard_register.py` or `side_channel_erasure.py`**, so Article 9 is not covered
  by the release gate.

### Article 10. A correction preserves what was believed

- **Why.** Deleting the record that was wrong makes the history unfalsifiable and
  hides that the correction happened. An O7 matrix result was withdrawn in a
  machine-readable record before correction; the ETP-0 → ETP-1 conversion retained
  every identity and verdict; the b85c dissent must survive the graduation record
  that it dissents from.
- **Enforced by.** `forensics/tools/etp_claims.py` — `EG_DERIVED_VERDICT_MISMATCH`
  and `EG_DERIVED_PROPERTY_MISMATCH` (a conversion may not change the recorded
  verdict or property), and the closed verdict set with `SUPERSEDED` and
  `WITHDRAWN` as recorded outcomes; `forensics/tools/preservation.py` —
  `PM_MIGRATION_IDENTITY_LOST`, `PM_MIGRATION_HISTORY_REWRITTEN`,
  `PM_RENEWAL_BYTES_CHANGED`; `forensics/tools/independence.py` —
  `IND_DISSENT_DROPPED`, `IND_DISSENT_REMOVED_BY_TARGET`,
  `IND_DISSENT_OVERRIDDEN`; `forensics/tools/freshness.py` —
  `FR_HISTORY_CITED_AS_CURRENT` (a historical record is retained, and cannot be
  cited as current).
- **Refused when.** A migration drops a claim identity or rewrites its verdict or
  property; a renewal record's bytes differ from the retained binding; a retained
  dissent is absent from the aggregate, removed by the party it dissents from, or
  overridden by a better aggregate; a history artefact is cited as current
  evidence.
- **Not established.** Retention is not correctness: a retained wrong belief is
  still wrong. The tools do not compare the content of two revisions to show which
  part changed. `docs/DECISIONS.md` is append-only by convention, and no tool
  enforces that convention.

### Article 11. No authority may promote a contradicted claim by declaration

- **Why.** Rank, intent or a stated risk acceptance stands in for evidence. A
  graduation record reported `SAFE_COMPATIBLE` beside a `NOT ESTABLISHED`
  adjudication; a campaign status reported 1/33 while three adjudications were
  `NOT ESTABLISHED` and both gates were blocked; the graduation described itself as
  a principal-decided risk acceptance.
- **Enforced by.** `forensics/tools/etp_claims.py` — `EG_SELF_DECLARED_POLICY` (a
  document that declares its own acceptance policy is refused before schema
  evaluation), `EG_CONTRADICTION_UNRESOLVED` (two claims at one property, scope and
  identity with different verdicts are a hard error, with no preference resolved by
  timestamp or rank), `EG_VERDICT_MODALITY`; `forensics/tools/release_gate.py` —
  `RG_CLAIM_CONTRADICTED`, `RG_CLAIM_REFUTED`, `RG_CLAIM_WITHDRAWN`,
  `RG_POLICY_DENIED`;
  `forensics/tools/closure_discipline.py` —
  `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`; `forensics/tools/independence.py` —
  `IND_DISSENT_OVERRIDDEN` and `IND_AGGREGATE_MISMATCH` (the aggregate is
  recomputed, not trusted).
- **Refused when.** A release candidate's claim set contains a contradicted claim;
  two claims share property, scope and identity but disagree, or share a measure
  name with different typed values; a positive aggregate contains a blocked row; a
  recorded aggregate is better than the computed conservative meet; a record
  declares its own acceptance rule.
- **Not established.** The machinery cannot detect a claim that was never written
  down, or a release performed without the gate: there is no release script and no
  tag-triggered publish path, so the gate is a mandatory manual step
  (`docs/RELEASE_GATES.md`, "Known gap"). An exclusion or a risk acceptance remains
  a decision recorded by a party, and the article refuses a promotion, not the
  recording of a dissent.

---

## 2. What the constitution does not establish

- It does not establish that any claim is true, or that any consumer is safe,
  compatible or graduated. It states what may be claimed and what refuses a
  violation of that statement.
- It does not establish that the named enforcement is the only, the strongest or
  the best enforcement of an article. The checker verifies that a named tool exists
  and emits the named identifier; it cannot show that the identifier is reachable
  from the release artefacts or that it covers every form of the violation.
- It does not make a prose document obey an article. A document that is not parsed
  by a checker can restate the risk the article refuses; the articles bound what
  the checked artefacts may assert.
- It does not give every article a release-gate item. `docs/RELEASE_GATES.md` §10
  names the four articles no gate item covers (Articles 5, 6, 7 and 9); the tools
  named in those articles are the enforcement, and they are not release-gate items
  today.
- It is not a specification of the implementation, and it does not discharge an
  obligation recorded in `AGENTS.md` §7 or in the ETP queue.

## 3. Reproducing the check

Inside the court, Python 3.11 standard library only:

```
python3 forensics/tools/earned_trust.py check
python3 forensics/tools/earned_trust.py --json
python3 forensics/tools/tests/test_earned_trust.py
python3 forensics/tools/docs_consistency.py
```

The first command exits `0` only when every article is present, every article
names an enforcement or declares none, every named rule exists in the credited
tool, every citation resolves, and every uncovered article is named. A refusal
prints the rule on one line and exits `1`.
