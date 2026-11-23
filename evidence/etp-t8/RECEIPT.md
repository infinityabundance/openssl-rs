# ETP-T8 — independence roles, refusal machinery and dissent

Item: ETP-T8 of `docs/ETP-TODO.md` — role separation, honest recording of the
actual state, refusal of fabricated independence, and preservation of dissent.

Candidate identity at the start of the batch:

| field | value |
|---|---|
| branch | `staging` |
| HEAD | `bf8c6437128b2d3ab0bf76d76aa5b529532de84f` |
| worktree | clean (`git status --porcelain` empty) |
| host `available` before the batch | 24 GiB |
| court | `openssl-rs-court-tools:1`, `OPENSSL_RS_COURT_MEM=6g`, `OPENSSL_RS_COURT_MEMSWAP=6g` |
| Rust build | none; Python 3.11 only |
| `src/`, `docker/`, other items' evidence | untouched |

The 24 GiB `available` reading is at the §6.1 threshold. No Rust build was
run; the batch used one Python process at a time under the 6g court cap.

## 1. Deliverables

| path | role |
|---|---|
| `docs/INDEPENDENCE.md` | the roles, distinctness matrix, four sameness levels, refusal rules, dissent policy and the statement that no external independence exists |
| `evidence/etp-t8/ROLES.json` | role definitions, claim classes, sameness levels and rules (validated with `python3 -m json.tool`) |
| `evidence/etp-t8/ASSIGNMENTS.json` | 50 assignments, parties, dissent and aggregate (validated with `python3 -m json.tool`) |
| `forensics/tools/independence.py` | `validate`, `check`, `seed`, `report`, `aggregate`; strict JSON; fails closed |
| `forensics/tools/tests/test_independence.py` | one control per refusal rule, a positive control, determinism, seed reproduction and dissent controls |
| this receipt and the ETP-T8 row | report and status |

## 2. Roles and the distinctness matrix

Nine roles are defined: author, proof producer, instrument author, evidence
producer, adjudicator, reviewer, independent reproducer, release authority and
revocation authority. Each has a stated set of assertions it may make and
artefacts it may sign.

The four-level rule is enforced mechanically:

- an adjudicator must differ from the author at `same_agent` for
  `SAFETY_DISCHARGED`, `SAFE_COMPATIBLE_RELEASE` and
  `INDEPENDENT_ADJUDICATION`;
- a reproducer must differ at `same_agent`, `same_organisation`,
  `same_infrastructure` and `same_key` (a different trust domain, not a
  different name);
- a release authority must differ from the author and the adjudicator at
  `same_agent`.

The full pair/class matrix is in `docs/INDEPENDENCE.md` §2 and
`evidence/etp-t8/ROLES.json` `claim_classes`.

## 3. Actual state

The record covers 35 typed claims, 13 receipts, the b85c adjudication and the
OpenSSH graduation.

| measure | value |
|---|---|
| assignments | 50 |
| author and adjudicator the same agent | **50 / 50** |
| adjudicator distinctness not established | 0 |
| declared parties | 0 |
| external trust domains | 0 |
| assertions of independence | 1 (`A-ADJ-B85C`) |
| assertions supported | **0** |
| retained dissents | 1 (`D-OPENSSH-B85C`) |
| `SAFE_COMPATIBLE_RELEASE` cohort | `NOT_ESTABLISHED` |
| overall cohort | `CONTRADICTED` |

Every claim and receipt is same-party. The single independence assertion (the
b85c adjudication) is refused on four independent grounds: no reviewer
identity, the adjudicator is the same undeclared party as the author, the
distinct-party threshold collapses to one party, and the reproduction used this
repository's working environment against project-produced artefacts.

The OpenSSH graduation is refused as a release: the adjudicator is the author,
the release authority declares no identity and is not established as distinct,
and no independent reproduction exists. Its retained dissent sets the release
aggregate to `NOT_ESTABLISHED`.

## 4. Refusal controls

`forensics/tools/independence.py check` on the committed record reports 13
refusals, all on the two independence-asserting assignments. The control suite
mutates a synthetic distinct-party record and requires each named refusal.

| rule | control | observed field |
|---|---|---|
| `IND_REVIEW_UNSUPPORTED` | reviewer identity removed | `reviewers[0].identity` |
| `IND_REVIEW_UNSUPPORTED` | reviewer list emptied | `reviewers` |
| `IND_ADJUDICATOR_IS_AUTHOR` | adjudicator moved to the author's party | `filled.adjudicator\|filled.author` |
| `IND_REVIEWERS_ALIASED` | two reviewers share an identity | `reviewers[0].identity\|reviewers[1].identity` |
| `IND_REVIEWERS_ALIASED` | two reviewers share a signing key | `...signing_key` |
| `IND_THRESHOLD_ALIASED` | one account under two names | `threshold.satisfied_by` |
| `IND_THRESHOLD_ALIASED` | two URLs under one operator | `threshold.satisfied_by` |
| `IND_REPRODUCER_CONTAMINATED` | project working environment | `reproduction.used_project_working_environment` |
| `IND_REPRODUCER_CONTAMINATED` | project-produced artefact | `reproduction.used_project_produced_artefact` |
| `IND_REPRODUCER_CONTAMINATED` | no rebuild from the frozen package | `reproduction.rebuilt_from_frozen_package` |
| `IND_DISSENT_DROPPED` | retained dissent omitted from the aggregate | `aggregate.included_dissents` |
| `IND_DISSENT_DROPPED` | aggregate raised above the dissent | `aggregate.per_assignment` |
| `IND_DISSENT_DROPPED` | removal accepted by the dissented-from party | `removal_requests[0]` |

The positive control is a synthetic record with three parties distinct at all
four levels; it produces zero refusals. An `ORDINARY_CLAIM` with a same-party
adjudicator is also admissible, because the class does not require separation;
the same-party fact is recorded rather than refused.

Strict-loading controls refuse a duplicate JSON key and a non-finite number.

## 5. Dissent

`D-OPENSSH-B85C` is attached to `A-REL-OPENSSH-B85C`, retained, and included in
the aggregate. The aggregate for that assignment is `NOT_ESTABLISHED`, which is
the dissent's position and worse than the asserted `SAFE_COMPATIBLE`. The
control suite demonstrates that:

- the dissent survives aggregation and lowers both the assignment and the
  release cohort to `NOT_ESTABLISHED`;
- dropping it from `included_dissents` is refused;
- raising the recorded aggregate above it is refused;
- an accepted removal requested by the dissented-from party is refused;
- a withdrawal by the dissenting party is admissible.

## 6. Gate

Commands run in the court, one at a time:

```
python3 forensics/tools/independence.py validate
python3 forensics/tools/independence.py check
python3 forensics/tools/tests/test_independence.py
python3 -m json.tool evidence/etp-t8/ROLES.json
python3 -m json.tool evidence/etp-t8/ASSIGNMENTS.json
```

Observed:

- `validate` → `PASS`, 50 assignments, 0 structural refusals;
- `check` → `REFUSED`, 13 independence refusals, 50/50 same-party adjudicators,
  0 external parties;
- `test_independence.py` → 41 tests, 0 failures;
- both JSON documents accepted by `python3 -m json.tool`.

The `check` refusal is the correct outcome. The committed record is admissible
because it states the absence of independence; the independence assertion it
contains is not accepted.

## 7. Non-claims

- This record does not create an external reviewer, organisation or key.
- It does not downgrade or upgrade any claim's truth; it records which party
  filled which role.
- It does not establish that the b85c adjudication was wrong on the evidence.
  It establishes that the adjudication's asserted independence is not supported
  by a distinct party.
- It does not make `SAFE_COMPATIBLE` or `SAFETY_DISCHARGED` reachable. Those
  states remain blocked for this cohort until an adjudicator and a reproducer in
  a different trust domain exist.
- `test_independence.py` controls the checker. A passing control is evidence
  about the checker, not about the candidate's safety.
