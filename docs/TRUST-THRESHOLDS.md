# Trust-domain thresholds — A15

Status: normative. Delivered by item A15 of `docs/ETP-TODO.md` at candidate
`b099cd599b6728a7b7686a76b515ff0b67a7acc1` (`staging`). The implementation is
`forensics/tools/thresholds.py`; the records are `evidence/a15/DOMAINS.json`,
`evidence/a15/THRESHOLDS.json`, `evidence/a15/APPROVALS.json`,
`evidence/a15/EVALUATION.json` and `evidence/a15/CONTROLS.json`; the
deterministic producer is `evidence/a15/build_evidence.py`; the controls are
`forensics/tools/tests/test_thresholds.py`; the receipt is
`evidence/a15/RECEIPT.md`.

This document is normative for the threshold decision. It is cumulative with
`AGENTS.md`, `docs/EARNED-TRUST.md` (Articles 1, 2, 3, 4, 5 and 11),
`docs/INDEPENDENT-VERIFICATION.md` (A12) and `docs/ROLE-AUTHORISATION.md` (A14).
Where this document and another describe the same commitment, the stricter
reading governs.

## 1. The problem: a label is not a domain

A k-of-n threshold is a claim about **distinct trust domains**. It is not a
claim about distinct strings, distinct files, distinct role labels or distinct
signatures. Five substitutions turn a label into a false quorum:

1. **a self-asserted domain** — the approval's own `domainId` is the only thing
   asserting the domain;
2. **an alias** — two domain labels resolve to one underlying domain;
3. **a duplicate** — one domain approves twice and is counted twice;
4. **the candidate's own domain** — the project, the producer or a same-party
   domain approves itself;
5. **a wrong role** — a verified signature in a role the threshold does not
   require, or a role A14's records do not establish, is counted as an approval.

Two further mistakes are about the declaration rather than an approval:

6. **a lowered threshold** — a declaration made after the approvals were
   collected, or amended afterwards, is not the threshold that was met;
7. **an unreachable threshold** — a k-of-n threshold cannot be met when fewer
   than k distinct domains exist at all.

The wrong conclusion this item prevents is: *"k approvals met the threshold"*.
The count is over distinct **established** domains whose approval is verified,
role-valid, fresh for the artefact digest, and not the candidate's own domain.
The real state is **0 external trust domains**, therefore **0 thresholds can be
met**, and that result is recorded rather than worked around.

- Enforced by `TH_REFUSED_SELF_ASSERTED_DOMAIN`, `TH_REFUSED_ALIASED`,
  `TH_REFUSED_DOMAIN_DUPLICATE`, `TH_REFUSED_CANDIDATE_DOMAIN`,
  `TH_REFUSED_WRONG_ROLE`, `TH_REFUSED_THRESHOLD_LOWERED` and
  `TH_REFUSED_THRESHOLD_UNREACHABLE`.
- Enforced by `test_self_asserted_domain_is_one_approval_not_two`,
  `test_alias_is_one_domain_not_two`, `test_duplicate_domain_is_one_domain_not_two`,
  `test_candidate_domain_is_not_an_independent_approval`,
  `test_wrong_role_is_not_an_approval`, `test_threshold_lowered_declared_after_earliest_approval`
  and `test_k_larger_than_available_domains_is_unreachable`.

## 2. The domain contract

A domain record has four fields:

| field | meaning |
|---|---|
| `domainId` | the lookup key an approval uses; it is **not** authority |
| `kind` | `external`, or a candidate/same-party kind (`candidate`, `producer`, `same-party`, `project`, `self`) |
| `establishedBy` | `{path, sha256}`: the record outside the candidate that establishes the domain |
| `independentOfCandidate` | `true` only when the domain is declared independent of the candidate |

A domain is **established** when `establishedBy` names a non-empty path and a
64-character lowercase SHA-256. An absent, empty or malformed `establishedBy`
is not an establishment: the approval's field would be the only assertion, which
is `TH_REFUSED_SELF_ASSERTED_DOMAIN`.

A domain is **available** to a threshold when it is established, its kind is not
one of the candidate/same-party kinds, and `independentOfCandidate` is exactly
`true`. A missing or false declaration is refused
(`TH_REFUSED_CANDIDATE_DOMAIN`); independence cannot be acquired by omission. A
`same-party` domain may be recorded by a candidate-internal record (A12's root
inventory does exactly this) because the record establishes the domain's
*existence*, not its independence; the `independentOfCandidate: false` field is
what keeps it out of the count.

The approval's `domainId` is a **lookup key only**. The domain record decides
what the label means. Two labels whose records share one `establishedBy` are one
domain; a label with no record is not a domain.

- Enforced by `TH_REFUSED_DOMAIN_UNRECORDED`, `TH_REFUSED_SELF_ASSERTED_DOMAIN`
  and `TH_REFUSED_CANDIDATE_DOMAIN`.
- Enforced by `test_external_domains_require_an_establishment`,
  `test_same_party_and_candidate_domains_are_not_available` and
  `test_alias_is_one_domain_not_two`.

## 3. The threshold declaration and the no-lowering rule

A threshold declaration has:

```
{id, action, k, n, requiredRoles, distinctDomains: true,
 declaredAt, declaredBy, artefactDigest, asOf, scope, amendments}
```

`k` is the number of distinct domains required, `n` is the declared quorum size,
`requiredRoles` is the role set an approval may hold, `distinctDomains` must be
`true` (this is not a same-domain repetition counter), `declaredAt` and
`declaredBy` record who declared it and when, `artefactDigest` binds approvals
to the bytes they approve, and `scope` is the action scope A14's assignments
must cover. A declaration missing or malforming any required field is
`TH_REFUSED_THRESHOLD_UNRECORDED`; nothing is evaluated and `NOT_RUN` is not a
pass.

**The no-lowering rule.** The declaration must pre-exist the approvals. A
declaration whose `declaredAt` is after the earliest approval is
`TH_REFUSED_THRESHOLD_LOWERED`. An amendment whose `at` is at or after the
earliest approval is also `TH_REFUSED_THRESHOLD_LOWERED`, even when the amended
`k` is higher: a threshold changed after the approvals were collected is not the
threshold that was met. The evaluation compares the recorded declaration with
the approvals it is given; it does not trust a "current" declaration to describe
an earlier collection.

A threshold of k is **unreachable** when fewer than k distinct establishments
exist in the domain inventory at all. An alias pair is one establishment, so a
k=2 threshold over two labels sharing one establishment is unreachable, not
merely unmet.

- Enforced by `TH_REFUSED_THRESHOLD_UNRECORDED`,
  `TH_REFUSED_THRESHOLD_LOWERED` and `TH_REFUSED_THRESHOLD_UNREACHABLE`.
- Enforced by `test_threshold_unrecorded`, `test_threshold_lowered_amended_after_approvals`,
  `test_amendment_at_the_earliest_approval_is_refused` and
  `test_alias_pair_is_one_available_domain`.

## 4. The evaluation order

`evaluate(threshold, approvals, domains, role_assignments, at, artefact_digest)`
applies the following order. An earlier refusal prevents a later question from
being reached.

1. **Declaration.** The declaration must exist and be well-formed
   (`TH_REFUSED_THRESHOLD_UNRECORDED`, outcome `NOT_RUN`).
2. **No lowering.** The declaration must pre-exist the earliest approval and
   must not be amended at or after it (`TH_REFUSED_THRESHOLD_LOWERED`, outcome
   `UNMET`).
3. **Reachability.** Fewer than k distinct establishments is
   `TH_REFUSED_THRESHOLD_UNREACHABLE` (outcome `UNREACHABLE`).
4. **Per approval, in order:** the `domainId` resolves to a record
   (`TH_REFUSED_DOMAIN_UNRECORDED`); the domain is established
   (`TH_REFUSED_SELF_ASSERTED_DOMAIN`); the domain is not the candidate's or a
   same-party domain (`TH_REFUSED_CANDIDATE_DOMAIN`); the signature is verified
   (`TH_REFUSED_UNVERIFIED`); the dates are readable
   (`TH_REFUSED_STALE_APPROVAL`); the role is required and held under A14's
   assignment records (`TH_REFUSED_WRONG_ROLE`); the artefact digest matches and
   the approval has not expired (`TH_REFUSED_STALE_APPROVAL`).
5. **Identity collapse.** One identity approving under two established domains
   contributes one domain; the first approval is kept and the later one is
   `TH_REFUSED_DUPLICATE_IDENTITY`.
6. **Domain collapse.** Two labels sharing one establishment are one domain
   (`TH_REFUSED_ALIASED`); one label approving twice is one domain
   (`TH_REFUSED_DOMAIN_DUPLICATE`).
7. **Count and outcome.** The count is the number of distinct establishments
   among the qualifying approvals. `MET` when the count is at least k;
   otherwise `UNMET` with `TH_REFUSED_INSUFFICIENT_DOMAINS`.

A per-approval code records why an approval did not contribute. It does not
invalidate a threshold met by other legitimate domains: a `MET` result may carry
a refusal code for an approval that was correctly excluded, and the count must
be read together with the codes. The structural refusals (1–3) cannot coexist
with `MET`.

The role check is **delegated**: `thresholds.py` hands a single verified
signature to `authorisation.authorise` over A14's assignment records and reads
only the codes that say the identity does not hold the role for the action
(`RA_REFUSED_IDENTITY_UNRECORDED`, `RA_REFUSED_ROLE_UNKNOWN`,
`RA_REFUSED_ROLE_NOT_ASSIGNED`, `RA_REFUSED_EXPIRED`, `RA_REFUSED_REVOKED`,
`RA_REFUSED_SCOPE_EXCEEDED`, `RA_REFUSED_WRONG_ROLE`,
`RA_REFUSED_ACTION_UNKNOWN`). The action-level codes (insufficient signers,
separation, self-authorisation, duplicate signer) are A14's whole-action policy
and are not re-applied here.

- Enforced by `test_wrong_role`, `test_wrong_role_is_not_an_approval` and
  `test_stale_artefact_digest` / `test_stale_expiry`.
- Enforced by `test_duplicate_identity` and `test_distinct_domains_returns_groups_not_only_a_number`.

## 5. The alias rule and the count it yields

Two labels are an alias when their domain records share the same
`establishedBy` path **and** digest. The count is over establishments, not
labels, so:

| approvals | domain records | count | code |
|---|---|---:|---|
| `alpha`, `alpha-alias` | both share one establishment | **1** | `TH_REFUSED_ALIASED` |
| `beta`, `beta` | one record | **1** | `TH_REFUSED_DOMAIN_DUPLICATE` |
| `alpha`, `beta` with one identity | two establishments | **1** | `TH_REFUSED_DUPLICATE_IDENTITY` |
| `alpha`, `beta` with two identities | two establishments | **2** | none |

`distinct_domains(approvals, domains)` returns the count **and** the groups, the
alias groups, the duplicate labels, the duplicate identities and the unresolved
or non-independent labels. A reader can see which approvals collapsed; a bare
number would hide the substitution. The alias control in
`evidence/a15/CONTROLS.json` is exactly the first row: two labels, one
establishment, count one.

- Enforced by `TH_REFUSED_ALIASED`, `TH_REFUSED_DOMAIN_DUPLICATE` and
  `TH_REFUSED_DUPLICATE_IDENTITY`.
- Enforced by `test_distinct_domains_returns_groups_not_only_a_number`,
  `test_duplicate_labels_are_reported` and `test_duplicate_identities_are_reported`.

## 6. The refusal table

Every code is stable. The second column names the wrong conclusion it prevents.

| code | what it prevents |
|---|---|
| `TH_REFUSED_THRESHOLD_UNRECORDED` | an undeclared or malformed threshold evaluated as a recorded k-of-n claim |
| `TH_REFUSED_THRESHOLD_LOWERED` | a threshold lowered or amended after the approvals were collected being read as the threshold that was met |
| `TH_REFUSED_THRESHOLD_UNREACHABLE` | a threshold reported as merely unmet when no set of approvals could ever meet it |
| `TH_REFUSED_SELF_ASSERTED_DOMAIN` | a domain invented at the point of approval being counted as a distinct trust domain |
| `TH_REFUSED_DOMAIN_UNRECORDED` | a label with no domain record counted because it appears in an approval |
| `TH_REFUSED_CANDIDATE_DOMAIN` | the candidate or the producing party counted as an independent approval of itself |
| `TH_REFUSED_ALIASED` | one domain counted twice by spelling its label twice |
| `TH_REFUSED_DOMAIN_DUPLICATE` | a repeated approval from one domain counted as a second domain |
| `TH_REFUSED_UNVERIFIED` | an unchecked approval borrowing a domain and a role |
| `TH_REFUSED_WRONG_ROLE` | a verified approval in the wrong role, or a role A14's records do not establish, being counted |
| `TH_REFUSED_STALE_APPROVAL` | an approval for different bytes, or an expired approval, being counted |
| `TH_REFUSED_INSUFFICIENT_DOMAINS` | fewer approvals than k reported as meeting a reachable threshold |
| `TH_REFUSED_DUPLICATE_IDENTITY` | one approver counted as two domains |

One control per code is recorded in `evidence/a15/CONTROLS.json`; the test file
asserts that the control set exercises all thirteen and that every control
fires. Staleness has two controls (a changed digest and an expiry), and the
no-lowering rule has two (a late declaration and a later amendment).

- Enforced by `test_threshold_unrecorded`, `test_threshold_lowered_declared_after_earliest_approval`,
  `test_threshold_lowered_amended_after_approvals`, `test_threshold_unreachable`,
  `test_self_asserted_domain`, `test_domain_unrecorded`, `test_candidate_domain`,
  `test_aliased`, `test_domain_duplicate`, `test_unverified`, `test_wrong_role`,
  `test_stale_artefact_digest`, `test_stale_expiry`, `test_insufficient_domains`
  and `test_duplicate_identity`.

## 7. The real result: 0 domains, 0 thresholds met

`evidence/a15/DOMAINS.json` records one domain:

| domain | kind | established by | independent of candidate |
|---|---|---|---|
| `openssl-rs:same-party` | `same-party` | `evidence/a12/TRUST-ROOTS.json` (A12's single root, the A10 test-only HMAC-SHA256 key) | **false** |

`externalDomains` is `[]`. A12's inventory records one root, `symmetric: true`,
`trustDomain: "same-party"`, provenance inside the candidate. It establishes
that the domain exists; it does not establish a domain independent of the
candidate. There are **0 external trust domains**.

`evidence/a15/THRESHOLDS.json` declares four thresholds. `n` is the quorum the
policy contemplates; `domainsAvailable` is measured from the inventory and is 0.

| threshold | k | n | available domains | distinct domains | outcome | codes |
|---|---:|---:|---:|---:|---|---|
| `release` | 2 | 3 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |
| `claim-promotion` | 1 | 2 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |
| `consumer-graduation` | 2 | 3 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |
| `instrument-qualification` | 1 | 2 | 0 | 0 | `UNREACHABLE` | `TH_REFUSED_THRESHOLD_UNREACHABLE` |

`evidence/a15/APPROVALS.json` records no approval. No real signature exists
(A14 records every attempt `verified:false`; A10/A12 record only a test-only
symmetric key), and no external domain exists. The real aggregate is
**0 met, 0 unmet, 4 unreachable, 0 not run**; **0 thresholds can be met**.

This is the honest result. It is not worked around by promoting the same-party
domain to an external one, by counting a label twice, by inventing an approval,
or by lowering k until the empty approval set meets it.

- Enforced by `test_no_external_domain_is_recorded`,
  `test_zero_thresholds_are_met`, `test_every_real_threshold_is_unreachable` and
  `test_no_real_approval_is_recorded`.
- Enforced by `test_the_four_thresholds_are_declared`.

## 8. The controls and what the positive control does and does not establish

`evidence/a15/CONTROLS.json` holds fifteen refusal controls (one per code, with
a second control for each of the two staleness triggers and each of the two
no-lowering triggers) and one positive control. Every synthetic domain and
identity is labelled `control-only` and is excluded from the real aggregate.

* The **refusal controls** each assert that their named code fires. The alias
  control uses two labels sharing one establishment and asserts that the count
  stays **1**. The duplicate-identity control asserts that one identity under two
  labels counts once. The unreachable control uses zero external domains and
  k=2.
* The **positive control** (`positive-distinct-domains`) uses two distinct
  synthetic parties in two distinct synthetic external domains and reaches
  `MET` with a count of 2. It establishes that the counting procedure is not
  fail-closed by construction: when two distinct domains are present with
  verified, role-valid, fresh approvals, the procedure can count them. It is
  **control-only** and does **not** establish that any real approval exists,
  that any real domain is independent, that any real action is authorised, or
  that a release should happen. The real aggregate remains **0 met**.
* The **producer asserts** every control fires, that the positive reaches `MET`,
  and that the real aggregate is 0, so a control that stops firing fails the
  build rather than being reported as green.

- Enforced by `test_controls_exercise_every_code`, `test_positive_and_alias_controls`
  and `test_two_distinct_synthetic_domains_reach_met`.
- Enforced by `test_the_positive_control_is_not_a_real_approval`.

## 9. Release-gate integration

The release gate has a per-refusal row structure: each checker returns a
`Results(refusals, recorded)` and the gate combines rows without changing
another checker's verdict. A15 joins that seam as item 8,
`check_thresholds`, without changing items 1–7.

The gate runs `forensics/tools/thresholds.py evaluate release --json` against
`evidence/a15/THRESHOLDS.json`, `evidence/a15/APPROVALS.json`,
`evidence/a15/DOMAINS.json` and `evidence/a14/ROLES.json`. A threshold that is
not `MET` is one row:

```
REFUSED RG_THRESHOLD_UNMET a15/release: outcome=UNREACHABLE codes=TH_REFUSED_THRESHOLD_UNREACHABLE distinctDomains=0 availableDomains=0
```

An absent tool, declaration, approvals, domains or role record is
`RG_THRESHOLD_TOOL_MISSING`, `RG_THRESHOLD_MISSING` or
`RG_THRESHOLD_ROLES_MISSING`; an unparseable result is `RG_THRESHOLD_ERROR`. A
missing threshold check is a refusal, never a skip, in the same way as the
gate's other items.

**Status: integrated.** The gate's real run on this candidate refuses with the
A15 row in addition to its pre-existing refusals. The gate's real run at the base
had 32 refusal items; with the A15 row it has 33, and items 1–7 are unchanged.
The constitution mapping in `docs/RELEASE_GATES.md` §10 is **not** updated in
this item and is retained as an obligation: the table does not list the new row
and still names Articles 5, 6, 7 and 9 as uncovered.

- Enforced by `RG_THRESHOLD_UNMET` in `forensics/tools/release_gate.py` (`test_unmet_threshold_is_one_refusal_row`).
- Enforced by `test_met_threshold_is_recorded_not_refused`,
  `test_missing_threshold_record_is_refused` and
  `test_unparseable_threshold_evaluation_is_refused`, in
  `forensics/tools/tests/test_release_gate.py`.

## 10. Boundary with A12, A14, A16 and A17

* **A12 (trust roots).** A12 decides whether an envelope is independently
  verified and records the roots. A15 consumes the *domain* record and does not
  re-verify a signature: the approval's `verified` flag is supplied by the
  caller. A12's real inventory records 0 external roots; A15's domain inventory
  records 0 external domains. Neither result is borrowed to satisfy the other.
* **A14 (roles).** A14 decides whether a signature authorises an action, with
  its separations. A15 delegates the role/identity/scope check to A14's
  assignment records and does not restate the seven roles or the separation
  policy. A `MET` threshold is **not** an authorisation: the action must also be
  `AUTHORISED` by A14. A threshold can count two approvals in the same required
  role; A14's separation policy is what refuses that combination for the action.
* **A16 (Sigstore bundles).** A16 will supply certificate and transparency
  evidence for an approval. A15 records only the domain record and the
  `verified` flag; it does not read a bundle, a certificate or an inclusion
  proof.
* **A17 (transparency and omission resistance).** A17 freezes the expected
  evidence and reconciles it. A15's `CONTROLS.json` and `EVALUATION.json` are
  ordinary records; they do not claim that no approval was omitted, and a
  producer that publishes no failing evaluation is not detected by A15. That
  remains A17's reconciliation.

- Enforced by `TH_REFUSED_CANDIDATE_DOMAIN` and `TH_REFUSED_WRONG_ROLE` for the
  substitutions this item owns.
- Enforced by `test_wrong_role` (the role policy is read from A14, not restated)
  and `test_candidate_domain` (a same-party domain is not independent).

## 11. Non-claims

* **No real threshold is met.** The aggregate is 0. The positive control is
  synthetic and establishes only the counting procedure.
* **No cryptographic verification is performed here.** `verified` is supplied by
  the caller; this module does not implement a signature primitive, a key
  distribution mechanism, a trust root or a bundle.
* **No real external trust domain exists.** `DOMAINS.json` records 0 external
  domains. The same-party domain is recorded with `independentOfCandidate:
  false`; this document does not claim independence (Article 5).
* **A domain record is not an organisation.** A15 does not establish that a
  named domain is a distinct organisation, that its record is truthful, or that
  an approval was authorised by that organisation.
* **A threshold is not an authorisation and not truth.** A `MET` threshold says
  the count is satisfied; A14 decides authorisation and no signature decides
  truth.
* **The gate row is not the whole release decision.** The gate refuses on many
  other grounds; A15 adds one row and inherits none of the other items' results.

## 12. Obligations retained

* **`docs/RELEASE_GATES.md` §10 is not updated.** The gate runs
  `check_thresholds`, but the constitution's gate-item table still names
  Articles 5, 6, 7 and 9 as uncovered and does not list the new row. Deciding
  which article the threshold row evidences and updating the table is a
  separate, deliberate change.
* **No external trust domain exists.** No record establishes a domain outside
  the candidate. A12's only root is the test-only HMAC-SHA256 key; A15 records
  the same-party domain rather than inventing an external one.
* **No verified, externally domain-bound approval exists.** `APPROVALS.json` is
  empty. A production signing key, key distribution, a verification record and a
  real identity ceremony are A12/A16/A17 work.
* **The declarations are same-party.** `declaredBy` is the project's undeclared
  producer party (`P-CAMPAIGN`); A14 records `maintainer: none`, so no maintainer
  declared the thresholds. This is recorded, not remedied.
* **The positive and alias controls are not real approvals.** They are labelled
  `control-only` and are excluded from the real aggregate.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## `NOT_RUN`

* A real external trust domain, a real key ceremony and a real organisational
  identity.
* A real verified, externally domain-bound approval and a real approved action.
* A real threshold being met, a real release or claim promotion authorised by a
  threshold, and a real consumer graduation.
* A16 Sigstore bundles, A17 transparency and omission reconciliation, A18/A19
  where the queue names them.
* A BOUNDARY audit, a full Miri/ASan/TSan campaign, independent review and SEAL.
* The Rust suite: `src/` was not modified, so no rebuild and no `cargo test` is
  claimed.

## 13. Reproducing the result

Inside the court, Python 3.11 standard library only:

```
python3 evidence/a15/build_evidence.py
python3 forensics/tools/thresholds.py domains
python3 forensics/tools/thresholds.py evaluate release
python3 forensics/tools/thresholds.py evaluate claim-promotion
python3 forensics/tools/thresholds.py evaluate consumer-graduation
python3 forensics/tools/thresholds.py evaluate instrument-qualification
python3 -m unittest forensics.tools.tests.test_thresholds
python3 -m unittest discover -s forensics/tools/tests
```

`build_evidence.py` is deterministic: two runs are byte-identical, and the
committed records match a fresh run. The source identity is the candidate, the
digests of the named input records, the threshold tool and the delegated role
tool; a later edit to either tool invalidates the record.
