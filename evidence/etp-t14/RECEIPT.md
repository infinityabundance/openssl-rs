# ETP-T14 — earned-trust constitution: receipt

**Item:** ETP-T14, `EARNED-TRUST.md` constitution plus integration into
`AGENTS.md` and the release policy.
**Verdict:** `DONE` for the constitution, the machine record, the additive
`AGENTS.md` section, the release mapping and the consistency checker with its
controls. The constitution names four articles no release-gate item covers, and
that gap is recorded rather than closed.
**Date:** 2026-11-23.

---

## 1. Source identity and environment

| field | value |
|---|---|
| branch | `staging` |
| HEAD at start | `1e068243d2ec045852bddd3e64c4d6233829eb1d` |
| worktree at start | clean (`git status --porcelain` empty) |
| `free -g`, available | 19 GiB |
| derived cap | `min(8, 19 − 16)` = **3g** (2g floor met) |
| court | `openssl-rs-court-tools:1`, `OPENSSL_RS_COURT_MEM=3g`, `OPENSSL_RS_COURT_MEMSWAP=3g` |
| Rust build | not run: `available` (19 GiB) is below the 24 GiB build threshold, and this item changes no Rust source |
| Python | court Python 3.11, standard library only |

Every command below ran inside the court at that cap, one at a time, after
`free -g` was read. No `src/` or `docker/` file was touched.

---

## 2. Deliverables

| path | content | SHA-256 of the working-tree bytes |
|---|---|---|
| `docs/EARNED-TRUST.md` | 11 articles, each with the four required fields, plus the non-claims | `ae5f1519…62f3bca` |
| `AGENTS.md` | one appended section, §23 | additive-only (31 insertions, 0 deletions) |
| `docs/RELEASE_GATES.md` | §10, the constitution gate and its uncovered-article list | additive-only |
| `evidence/etp-t14/ARTICLES.json` | machine record, schema `openssl-rs/etp-t14/articles/1` | `2b89f1b1…9eeb2c2` |
| `forensics/tools/earned_trust.py` | the consistency checker | `2ab93600…e32634e` |
| `forensics/tools/tests/test_earned_trust.py` | 28 `unittest` controls | `662fb21f…1257af6` |
| `evidence/etp-t14/RECEIPT.md` | this receipt | — |

`evidence/etp-t14/ARTICLES.json` is accepted by `python3 -m json.tool`.

---

## 3. The articles

Eleven articles, in the order `AGENTS.md` §23 lists them. Every enforcement
entry below names a tool that exists at this candidate and a rule identifier the
tool's own bytes contain; the checker re-derives both facts on every run.

| # | commitment | enforcement (tool → rule) | gate item |
|---|---|---|---|
| 1 | a claim may never exceed its evidence | `etp_claims.py` → `EG_VERDICT_MODALITY`, `EG_EVIDENCE_CONTRADICTS_VERDICT`, `EG_GRADUATED_WITH_OPEN_OBLIGATION`, `EG_SCHEMA_VIOLATION`; `release_gate.py` → `RG_CLAIM_CONTRADICTED`, `RG_CLAIM_REFUTED`, `RG_CLAIM_WITHDRAWN` | `gate-2` |
| 2 | evidence is bound to an exact identity | `etp_claims.py` → `EG_EVIDENCE_DIGEST_MISMATCH`, `EG_MULTIPLE_CANDIDATES`; `freshness.py` → `FR_EVIDENCE_SUPERSEDED`, `FR_IDENTITY_UNKNOWN`; `scheduling.py` → `SC_IDENTITY_UNKNOWN_FIELD`, `SC_IDENTITY_MISSING_FIELD`; `release_gate.py` → `RG_TRIAGE_STALE`, `RG_CLAIM_HISTORICAL_EVIDENCE` | `gate-1`, `gate-2`, `gate-2b`, `gate-5` |
| 3 | deferred is never pass | `scheduling.py` → `SC_BLOCKED_WITHOUT_BOUND`, `SC_RESULT_EXCEEDS_BOUND`; `etp_claims.py` → `EG_VERDICT_MISSING_SETTLING_OBLIGATION`, `EG_GRADUATED_WITH_OPEN_OBLIGATION`; `instrument_qualify.py` → `IQ_CONTROL_STATUS`; `release_gate.py` → `RG_CLAIM_NOT_ESTABLISHED` | `gate-2`, `gate-4` |
| 4 | an omission is not a pass | `closure_discipline.py` → `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`; `etp_claims.py` → `EG_AGGREGATE_PASS_HIDES_BLOCKED_CELL`, `EG_AGGREGATE_CELL_STATE_UNDECLARED`, `EG_SAFE_COMPATIBLE_CLOSURE_UNBOUND`, `EG_SAFE_COMPATIBLE_EXCLUSION_FAILS_BAR`; `traceability.py` → `TG_UNDECLARED_ORPHAN`; `courts/phase18/interop/check_receipts.py` → `R2`, `R5` | `gate-2`, `gate-3` |
| 5 | independence is never asserted without a distinct trust domain | `independence.py` → `IND_REVIEW_UNSUPPORTED`, `IND_ADJUDICATOR_IS_AUTHOR`, `IND_REVIEWERS_ALIASED`, `IND_THRESHOLD_ALIASED`, `IND_REPRODUCER_CONTAMINATED` | **none** |
| 6 | a specification is never a restatement of the implementation | `spec_guard.py` → `SP_INTERNAL_IDENTIFIER`, `SP_EXEMPTION_UNJUSTIFIED`, `SP_STALE_EXEMPTION`, `SP_NO_LEVEL`, `SP_GRAPH_EMPTY` | **none** |
| 7 | a proof in a model is not a proof about the binary | `binary_assurance.py` → `BA_CROSS_TARGET_INHERITANCE`, `BA_CROSS_PROFILE_INHERITANCE`, `BA_FORBIDDEN_CLAIM`, `BA_UNBOUND_ASSERTED`, `BA_TCB_MISMATCH`, `BA_EVIDENCE_DIGEST_MISMATCH` | **none** |
| 8 | a constant-time result is not a proof of constant time | `side_channel_erasure.py` → `CT_T_WITHOUT_PREREGISTERED_GEOMETRY`, `DUDECT_STATE_1_TREATED_AS_PROOF`, `CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT`, `SECRET_DEPENDENT_CONTROL_WITHOUT_EVIDENCE`; `instrument_qualify.py` → `IQ_DISCLAIMER`, `IQ_SCOPE`, `IQ_FAILURE_MODES` | `gate-4` |
| 9 | severity is not a probability | `hazard_register.py` → `HR_FMEA_SEVERITY`; `side_channel_erasure.py` → `ER_BAD_SEVERITY` | **none** |
| 10 | a correction preserves what was believed | `etp_claims.py` → `EG_DERIVED_VERDICT_MISMATCH`, `EG_DERIVED_PROPERTY_MISMATCH`; `preservation.py` → `PM_MIGRATION_IDENTITY_LOST`, `PM_MIGRATION_HISTORY_REWRITTEN`, `PM_RENEWAL_BYTES_CHANGED`; `independence.py` → `IND_DISSENT_DROPPED`, `IND_DISSENT_REMOVED_BY_TARGET`, `IND_DISSENT_OVERRIDDEN`; `freshness.py` → `FR_HISTORY_CITED_AS_CURRENT` | `gate-2`, `gate-2b` |
| 11 | no authority may promote a contradicted claim by declaration | `etp_claims.py` → `EG_SELF_DECLARED_POLICY`, `EG_CONTRADICTION_UNRESOLVED`, `EG_VERDICT_MODALITY`; `release_gate.py` → `RG_CLAIM_CONTRADICTED`, `RG_CLAIM_REFUTED`, `RG_CLAIM_WITHDRAWN`; `closure_discipline.py` → `CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW`; `independence.py` → `IND_DISSENT_OVERRIDDEN`, `IND_AGGREGATE_MISMATCH` | `gate-2` |

**No article is unenforced.** Article 9 is the one partial case and says so in
its own `Enforced by` field: the closed severity vocabulary and the absence of a
likelihood field are enforced, while the prohibition on *reading* a severity as a
probability has no mechanical enforcement and is a review obligation. The
machine record carries `declared_none: false` for every article because every
article has at least one executable refusal.

---

## 4. The `AGENTS.md` addition

One section appended at the end of the file. The diff is **31 insertions and 0
deletions** (`git diff --numstat -- AGENTS.md` → `31 0`), so no existing clause,
number, instruction or byte changed. The section is:

```
---

## 23. Earned-trust constitution (additive, 2026-11-23)

`docs/EARNED-TRUST.md` is the standing constitution of this project's
commitments about claims. It is **normative and cumulative** with this standard:
it adds no permission and withdraws none, and where an article and a clause here
describe the same commitment, the stricter reading governs. A session re-reads
the constitution at the point of use, exactly as it must re-read this file.

| article | commitment |
|---|---|
| 1 | a claim may never exceed its evidence |
| 2 | evidence is bound to an exact identity |
| 3 | deferred is never pass |
| 4 | an omission is not a pass |
| 5 | independence is never asserted without a distinct trust domain |
| 6 | a specification is never a restatement of the implementation |
| 7 | a proof in a model is not a proof about the binary |
| 8 | a constant-time result is not a proof of constant time |
| 9 | severity is not a probability |
| 10 | a correction preserves what was believed |
| 11 | no authority may promote a contradicted claim by declaration |

The machine record is `evidence/etp-t14/ARTICLES.json`. The release mapping is
`docs/RELEASE_GATES.md` §10, which names the four articles no gate item covers.
The consistency checker is `forensics/tools/earned_trust.py`, invoked from
`forensics/tools/docs_consistency.py` (release-gate item 6); it refuses an
article citation that names no article, an article with no enforcement and no
declaration of that, and a gate mention of an article no gate item covers.
```

The appended-section shape is not awkward: the file already ends with a numbered
`## 22` section, so `## 23` continues the existing structure without renumbering
or reformatting anything.

---

## 5. Release-gate mapping

`docs/RELEASE_GATES.md` §10 states the admissibility rule — a release is
admissible only when every article whose scope it enters is satisfied, evidenced
only by the gate items listed there — and maps the six required and the 2b
optional items of `release_gate.py` to the articles each one refuses:

| gate item | articles |
|---|---|
| `gate-1` candidate identity | 2 |
| `gate-2` claim set | 1, 2, 3, 4, 10, 11 |
| `gate-2b` identity triage | 2, 10 |
| `gate-3` interop receipts | 4 |
| `gate-4` instrument register | 3, 8 |
| `gate-5` external package | 2 |
| `gate-6` documentation consistency | none (meta-item: it refuses a broken mapping) |

**Articles no gate item covers: 5, 6, 7 and 9.** Their enforcing tools
(`independence.py`, `spec_guard.py`, `binary_assurance.py`,
`hazard_register.py`, `side_channel_erasure.py`) are not release-gate items, so
the section states that a release whose claim scope enters one of those articles
is not admissible on the gate's authority alone. Closing the gap means adding the
tools as gate items, not relaxing the articles; that is recorded as an open item,
not deferred silently.

The section also states the limit of each item in its own column, so an article
is not claimed to be more covered than the item's actual refusal is. For example,
`gate-4` evidences Article 8 only through the instrument register's required
soundness limits, scope and disclaimer; a claim's wording reading a timing result
as a proof is refused by `side_channel_erasure.py`, which no gate item runs.

---

## 6. The consistency checker and its controls

`forensics/tools/earned_trust.py` fails closed. It parses
`docs/EARNED-TRUST.md` (`### Article N.` headings, four labelled fields, contiguous
numbering), strictly loads `evidence/etp-t14/ARTICLES.json` (duplicate keys and
non-finite numbers refused), and then refuses:

| rule | condition |
|---|---|
| `ET_DOC_MISSING` | the constitution cannot be read |
| `ET_ARTICLE_MISSING` | the document defines no article |
| `ET_DUPLICATE_ARTICLE`, `ET_NUMBERING` | an article is defined twice, or numbering is not contiguous from 1 |
| `ET_FIELD_MISSING` | an article has an empty `Why`/`Enforced by`/`Refused when`/`Not established` |
| `ET_ENFORCEMENT_ABSENT` | an article lists no enforcement and does not declare that none exists |
| `ET_ENFORCEMENT_UNKNOWN` | a credited tool does not emit the credited rule identifier |
| `ET_ENFORCEMENT_TOOL_MISSING` | a credited tool path does not exist |
| `ET_ENFORCEMENT_DRIFT` | the document and record disagree about an article's enforcement, or an article declares none while listing one |
| `ET_RECORD_SCHEMA`, `ET_RECORD_DRIFT` | the record is malformed, or its article set/titles/`refusals` disagree with the document |
| `ET_STANDARD_SECTION_MISSING`, `ET_CITATION_UNKNOWN`, `ET_CITATION_OMITTED`, `ET_CITATION_DUPLICATE`, `ET_CITATION_EMPTY` | the `AGENTS.md` section is absent, cites an article that does not exist, omits or repeats an article, or gives a row no summary |
| `ET_GATE_SECTION_MISSING`, `ET_GATE_ITEM_DRIFT`, `ET_GATE_ITEM_UNKNOWN` | the release-gate section is absent, its item table disagrees with the record's registry, or an article names an unregistered item |
| `ET_GATE_LIST_MISSING`, `ET_GATE_LIST_MISMATCH` | the section does not name the uncovered articles, or names a set that disagrees with the table |
| `ET_GATE_UNCOVERED` | the gate section cites an article that no gate item covers |

**Observed on the committed tree:**

```
$ python3 forensics/tools/earned_trust.py check
earned-trust: ok: every article is enforced or declares none, every citation
resolves, and the release mapping is complete
exit 0

$ python3 forensics/tools/earned_trust.py check --json
{"ok": true, "problems": []}
```

**Controls: 28/28 pass** (`forensics/tools/tests/test_earned_trust.py`). The
three the item requires are present by name and are checked for presence by a
test:

| required control | mutation | observed refusal |
|---|---|---|
| `test_cited_article_that_does_not_exist` | `AGENTS.md` gains a row for Article 3 in a two-article constitution | `ET_CITATION_UNKNOWN` |
| `test_article_with_no_enforcement_and_no_declaration` | an article's `Enforced by` becomes prose and its record entry lists no enforcement, without a declaration | `ET_ENFORCEMENT_ABSENT` |
| `test_release_gate_cites_an_uncovered_article` | a three-article constitution where Article 3 is correctly named uncovered, plus a prose gate mention of Article 3 | `ET_GATE_UNCOVERED` |

The other controls cover an unknown rule identifier, a missing tool path, a
declared-none article that still lists enforcement, a missing field, a duplicate
article, a numbering gap, record title drift, a record missing an article, a
missing constitution, a missing `AGENTS.md` section, a missing gate section, an
uncovered-list mismatch, an absent uncovered sentence, a registered gate item
with no table row, recorded gate items that disagree with the table, an
unregistered gate item, a duplicate JSON key, determinism of two runs, a
nonexistent root, the committed tree passing, the `docs_consistency` integration,
and a no-first-person scan of the three tracked deliverables it can read as text.
Each mutation is built in a temporary tree, so a control cannot alter the
repository.

`forensics/tools/docs_consistency.py` imports the checker and appends its
refusals to the same failure path (`  STALE: …`), so release-gate item 6 refuses
a broken constitution without any change to `release_gate.py`. The real checker
is also the positive control in `release_gate.py --self-test`.

---

## 7. Gate output

```
$ python3 -m json.tool evidence/etp-t14/ARTICLES.json >/dev/null
JSON_OK

$ python3 forensics/tools/earned_trust.py check
earned-trust: ok: ... ; exit 0

$ python3 forensics/tools/tests/test_earned_trust.py
Ran 28 tests in 0.043s
OK

$ python3 forensics/tools/docs_consistency.py
[docs-consistency] EXEMPT: docs/PHASE-7-EVP-SEAL.md: 'phase7_claim_candidate_version' ...
[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources;
    the earned-trust constitution is wired
exit 0

$ python3 forensics/tools/docs_consistency.py --self-test
docs-consistency: self-test skipped: the ledger has an empty side
exit 0

$ python3 forensics/tools/tests/test_release_gate.py
Ran 10 tests in 0.017s
OK

$ python3 forensics/tools/release_gate.py --self-test
  ok   documentation inconsistency: expected RG_DOCS
  ok   real documentation checker (positive control): expected no refusal
release-gate self-test: ok (13 cases)
exit 0
```

`cargo fmt`/`cargo clippy`/`cargo test` were not run: no Rust changed, and
`available` was below the §6.1 build threshold. The Python checks are the
affected gate for this change set.

---

## 8. Obligations

**Discharged (with a control):** the constitution exists with 11 numbered
articles and the four required fields each; every article cites an enforcement
that exists and runs, verified mechanically against the tool's bytes; the
`AGENTS.md` integration is additive (31/0); the release mapping is complete and
names the uncovered articles; the three required consistency controls fire in a
temporary tree; `docs_consistency.py` — and therefore release-gate item 6 —
runs the checker.

**Retained (recorded, not repaired):** four articles (5, 6, 7, 9) have no
release-gate item; the tools that enforce them are not gate items, so a release
entering their scope is not admissible on the gate's authority alone. Article 9's
"not a probability" reading has no mechanical enforcement. The checker verifies
wiring, not fairness: it cannot show that a rule is the only or best enforcement,
that it is reachable from a release artefact, or that a prose document obeys an
article.

**Newly introduced:** no unsafe surface (no Rust change), but one new tracked
checker and one new normative document, both with controls. The checker is
additive to `docs_consistency.py`; it does not weaken an existing check. No
existing article, clause, rule or evidence record was reworded to fit it — the
first run found a real drift (Article 4's `Enforced by` field named `R1–R5` but
not the identifiers `R2`/`R5` the record credits) and the document was corrected,
not the checker.

---

## 9. Non-claims

- The constitution does not establish that any claim is true, or that any
  consumer is safe, compatible or graduated. It states what may be claimed and
  what refuses a violation of that statement.
- The checker does not prove that a named rule is reachable on the release path,
  that it covers every form of the violation, or that an unparsed document obeys
  the article.
- `DONE` here means the artefacts exist at the named commit and the controls
  pass. It does not mean the release gate covers every article.
- No external reviewer, organisation or signing key was involved; every control
  ran in this repository's court on the same day as the record.
- No Rust gate (fmt, clippy, the library suite) is claimed: none was run, and the
  reason is the §6.1 memory threshold, not a judgement that the checks are
  unnecessary.
