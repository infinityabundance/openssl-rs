# Independence: roles, distinctness and dissent (ETP-T8)

This document defines the independence roles, the claim classes that require
distinct parties, the four levels of sameness, the refusal rules and the
handling of dissent. The machine-readable companions are
`evidence/etp-t8/ROLES.json` and `evidence/etp-t8/ASSIGNMENTS.json`; the checker
is `forensics/tools/independence.py` and its controls are
`forensics/tools/tests/test_independence.py`.

The central finding is stated first and is not softened anywhere below:

> **No external independence exists today.** Every role in every existing
> claim and receipt is filled inside the project's own working environment by an
> undeclared producing party. No reviewer, organisation or signing key outside
> the project is named in any tracked artefact, and none is invented here. The
> release authority names a "decision-maker (campaign principal)" with no
> identity, organisation, infrastructure or key, so its distinctness from the
> producing party is not established. A different role label, a different file
> path or a second build in the same venue is not a different party.

The record distinguishes an **admissible record** from an **accepted
independence assertion**. An artefact may honestly say that independence is
absent; the record is then admissible and the assertion is refused. Refusal is
a verdict about the claim, not a corruption of the record.

## 1. Roles

Each role may assert only what its own evidence supports, and may sign only the
artefacts it produced. Signing is an assertion of provenance, not a transfer of
the other roles' authority.

| Role | May assert | May sign | Must be distinct from (high classes) |
|---|---|---|---|
| Author | the claim proposition, interpretation, quantification, scope, threat model and assumptions; an exclusion argument | claim document, assumption register, exclusion argument | adjudicator; independent reproducer; release authority |
| Proof producer | that a proof object establishes a stated property under stated axioms | proof artefact, axiom and admitted-result register | adjudicator |
| Instrument author | what an instrument measures and does not measure; its qualification and limits | instrument source, qualification record | adjudicator |
| Evidence producer | the measured result, its artefact identity and digest binding; the run environment | evidence artefact, run log, environment record | adjudicator; independent reproducer |
| Adjudicator | the verdict for a named claim at a named candidate identity; the obligation disposition | adjudication record, verdict row | author, proof producer, instrument author, evidence producer |
| Reviewer | that a stated procedure was applied to a stated obligation and result | review record, ETP-1 exclusion witness | author, evidence producer |
| Independent reproducer | that a rebuild from the frozen package in its own trust domain reproduced the observables | reproduction record, environment and input manifest | author, evidence producer |
| Release authority | the release or graduation decision and the risks it accepts | release record, graduation record | author, evidence producer, adjudicator |
| Revocation authority | that a claim is withdrawn, superseded or revoked, and why | revocation record | author of the revoked claim |

The rule that matters most, repeated in every applicable place:

> For a `SAFE_COMPATIBLE` graduation, a `SAFETY_DISCHARGED` verdict, or an
> independent-reproduction claim, the **adjudicator must not be the author**,
> and the **reproducer must be a different trust domain** — not merely a
> different name.

## 2. Claim classes and the distinctness matrix

`ORDINARY_CLAIM` requires no distinctness. It records the parties so that the
absence of independence is visible, but it does not refuse a claim for being
self-adjudicated. The four classes below require separation.

| Required pair | `SAFETY_DISCHARGED` | `SAFE_COMPATIBLE_RELEASE` | `INDEPENDENT_ADJUDICATION` | `RELEASE_DECISION` |
|---|---|---|---|---|
| adjudicator ≠ author | `same_agent` | `same_agent` | `same_agent` | — |
| adjudicator ≠ evidence producer | `same_agent` | `same_agent` | `same_agent` | — |
| adjudicator ≠ instrument author | `same_agent` | — | — | — |
| reproducer ≠ author | — | all four levels | all four levels | — |
| reproducer ≠ evidence producer | — | all four levels | — | — |
| release authority ≠ author | — | `same_agent` | — | `same_agent` |
| release authority ≠ adjudicator | — | `same_agent` | — | — |

`same_agent` distinctness is the minimum for an adjudicator. A trust-domain
requirement is satisfied only when **all four** sameness levels are established
as `DIFFERENT`; `UNKNOWN` is not `DIFFERENT`.

## 3. The four levels of sameness

| Level | Same means | Required by | Satisfied today |
|---|---|---|---|
| `same_agent` | one declared identity, one account, or one undeclared producing party | every separation of adjudicator from author or evidence producer; release from author and adjudicator | **yes** — one undeclared producing party fills every role |
| `same_organisation` | one organisation, or neither party declares one | trust-domain separation of the reproducer | **yes** — no organisation is declared, so distinct organisations are not established |
| `same_infrastructure` | one infrastructure operator: the working environment, the court image, or two URLs under one operator | trust-domain separation of the reproducer | **yes** — one working environment and one court image |
| `same_key` | one signing key, or neither party declares a key | trust-domain separation of the reproducer | **not established** — no signing key is declared, which is not a distinct key |

The order matters. A second account is still `same_agent` if the account
belongs to the same declared agent. A second URL is still
`same_infrastructure` if one operator runs both. A second directory in this
repository is still `same_infrastructure` and normally `same_agent`. A rebuild
that consumes an artefact this project produced is not a rebuild from the
frozen package, even if it runs in a container.

## 4. Refusal rules

`independence.py check` applies the structural rules and the six independence
rules. `independence.py validate` applies only the structural rules, so an
honest record of absent independence remains admissible.

| Rule | Refuses | Field inspected | Control |
|---|---|---|---|
| `IND_REVIEW_UNSUPPORTED` | independent review asserted with no reviewer identity, role or artefact | `claimed_independence`, `reviewers[*]` | reviewer identity removed; reviewer list emptied |
| `IND_ADJUDICATOR_IS_AUTHOR` | adjudicator not distinct from the author where the class requires it | `filled.adjudicator`, `filled.author` | adjudicator moved to the author's party |
| `IND_REVIEWERS_ALIASED` | two reviewers with one identity, account or signing key | `reviewers[*].identity`, `.account`, `.signing_key` | duplicate identity; duplicate signing key |
| `IND_THRESHOLD_ALIASED` | a distinct-party threshold met by aliases of one party | `threshold.satisfied_by` | one account under two names; two URLs under one operator |
| `IND_REPRODUCER_CONTAMINATED` | an "independent" reproduction that used this repository's environment or a project-produced artefact | `reproduction.*` | project environment; project artefact; no frozen rebuild |
| `IND_DISSENT_DROPPED` | a retained dissent absent from the aggregate, a dissent removed by the target, or an aggregate better than the dissent | `dissents[*]`, `aggregate.*` | dissent dropped; aggregate raised; removal accepted by the target |

Structural refusals include an unknown role or claim class, an unknown party,
a duplicate assignment, a recorded sameness that disagrees with the computed
sameness, an unfilled required role, a dissent unattached to an assignment, and
an aggregate that is not the computed conservative meet. Strict loading also
refuses duplicate JSON keys and non-finite numbers.

## 5. Dissent

A dissenting adjudication is a first-class record attached to the assignment it
dissents from. It carries the dissenting party, the role, the party dissented
from, the position, the artefact and a statement. It is `retained: true`.

1. **Attached.** The dissent names its assignment. An unattached dissent is
   refused.
2. **Not removable by the target.** A removal request is accepted only when the
   requesting party is the party that recorded the dissent. Acceptance by the
   dissented-from party is refused as `IND_DISSENT_REMOVED_BY_TARGET`.
3. **Not droppable from the aggregate.** Every retained dissent identifier must
   appear in `aggregate.included_dissents`; omission is
   `IND_DISSENT_DROPPED`.
4. **Conservative meet.** The aggregate for an assignment is the worse of its
   asserted verdict and every retained dissent attached to it. A recorded
   aggregate better than that meet is `IND_DISSENT_OVERRIDDEN`; any disagreement
   with the computed meet is `IND_AGGREGATE_MISMATCH`. The checker recomputes
   the meet rather than trusting the recorded value.

The real OpenSSH case exercises all four parts. `evidence/b85c-adjudication.json`
returned `NOT ESTABLISHED` against the graduation.
`evidence/SAFE-COMPATIBLE-openssh-b85c.json` records that dissent, states that
it is preserved unchanged, and states that it is not withdrawn or
reinterpreted. The aggregate for `A-REL-OPENSSH-B85C` is therefore
`NOT_ESTABLISHED`, not the `SAFE_COMPATIBLE` value the graduation asserts. The
retraction in the graduation record concerns a label, not the dissent's
position, and does not remove the dissent from the aggregate.

## 6. Actual state

`evidence/etp-t8/ASSIGNMENTS.json` records 50 assignments: 35 typed claims from
`evidence/etp/claims.json`, 13 receipts (`evidence/etp0`, `etp2`, `etp5`,
`etp6`, `etp7`, `etp-t1` through `etp-t7`, and `haz-16`), the b85c adjudication,
and the OpenSSH `SAFE_COMPATIBLE` graduation.

| Measure | Value |
|---|---|
| assignments recorded | 50 |
| assignments whose author and adjudicator are the same agent | **50 / 50** |
| assignments whose adjudicator distinctness is not established | 0 |
| declared parties (identity, organisation or key) | 0 |
| external trust domains | 0 |
| assertions of independence | 1 (`A-ADJ-B85C`) |
| assertions of independence supported | **0** |
| retained dissents | 1 (`D-OPENSSH-B85C`) |
| release-cohort aggregate | `NOT_ESTABLISHED` |
| overall aggregate | `CONTRADICTED` (the four contradicted claims) |

**ETP-T15 supersession (2026-11-23).** The table above is the ETP-T8 identity.
After the b85c graduation was reclassified `RISK_ACCEPTED`, the current
projection is `evidence/etp-t15/INDEPENDENCE.json`: it keeps all 50 assignments,
parties and the retained dissent, and changes exactly the OpenSSH release entry to
`ORDINARY_CLAIM` with `asserted_verdict: RISK_ACCEPTED`, `claimed_independence:
false` and no required distinct party. It asserts no independence, so the check
produces no finding for `A-REL-OPENSSH-B85C`; `validate` passes (50 assignments,
0 structural refusals). The adjudication's own independence assertion is not
retracted and is still refused (8 findings, all `A-ADJ-B85C`). The historical
ETP-T8 record still yields 13 findings, because it still asserts
`SAFE_COMPATIBLE_RELEASE` for the same entry. No party, reviewer, organisation or
key was created.

The b85c adjudication asserts independence and is refused on four grounds: no
reviewer identity, the same party as the author it judges, a distinct-party
threshold that collapses to one party, and a reproduction that ran in this
repository's working environment against stored project artefacts. The OpenSSH
graduation is refused as a release: the adjudicator is the author, the release
authority declares no identity and is not established as distinct, and no
independent reproduction exists.

### What independence does not exist today

- **No external reviewer.** No identity, organisation, account or key outside
  the project appears in any claim, receipt, adjudication or release record.
- **No external adjudicator.** Every verdict in the recorded population was
  issued inside the same working environment as the evidence it judges.
- **No external reproducer.** The b85c adjudication re-ran a predicate by
  importing this repository's tool and re-hashing stored artefacts; the ETP-6
  clean-room replay is described in its own receipt as self-reproduction.
- **No distinct signing key.** No artefact is signed; `same_key` is not
  established for any pair.
- **No independent acceptance of the OpenSSH graduation.** The graduation
  record itself says it is a principal-decided risk acceptance, and the
  adjudication dissents.

These are recorded as absent. The record does not create a reviewer,
organisation or key to fill them.

## 7. Non-claims

- A role label is not a party. A second name for one account is an alias.
- A second build in one environment is a second execution, not a second trust
  domain.
- An independent reference implementation written by the same party is model
  diversity, not reviewer independence.
- A clean-room replay in this repository is self-reproduction.
- This document does not establish that any claim is true, safe or compatible.
  It establishes only who filled which role and whether those parties are
  distinct.
- `SAFE_COMPATIBLE` and `SAFETY_DISCHARGED` remain unreachable for any family
  whose adjudicator is the author, regardless of how strong the underlying
  evidence is.
