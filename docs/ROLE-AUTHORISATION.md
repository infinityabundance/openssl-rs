# Role-bound authorisation — A14

Status: normative. Delivered by item A14 of `docs/ETP-TODO.md` at candidate
`4e9262bf34e937439ec92bc832b5a569b27267b8` (`staging`). The implementation is
`forensics/tools/authorisation.py`; the records are `evidence/a14/ROLES.json`,
`evidence/a14/AUTHORISATION.json` and `evidence/a14/CONTROLS.json`; the
deterministic producer is `evidence/a14/build_evidence.py`; the controls are
`forensics/tools/tests/test_authorisation.py`; the receipt is
`evidence/a14/RECEIPT.md`.

This document is normative for the authorisation decision. It is cumulative with
`AGENTS.md`, `docs/EARNED-TRUST.md` (Articles 1, 2, 5, 6 and 11) and
`docs/INDEPENDENT-VERIFICATION.md`. Where this document and another describe the
same commitment, the stricter reading governs.

## 1. The problem: a signature is not a role

A signature says that a key signed bytes. It does not say that the signer holds
the role the action requires, that the role covers the action's scope, that the
role was valid when the action was taken, or that the required separation of
duties holds. Treating a valid signature as an authorisation conflates four
independent questions:

1. **authenticity** — did this key sign these bytes? (A10/A12 own this);
2. **identity** — which recorded identity does the key belong to? (A12 owns the
   root of trust);
3. **authorisation** — does that identity hold the role this action requires, at
   this scope, at this time, with the required separation? (this item);
4. **truth** — is the proposition the signature covers actually true? (no
   signature answers this).

A14 decides only question 3. A17 (transparency) and the cryptographic
verification instruments decide other questions; none of their results is
borrowed here.

The wrong conclusion this item prevents is: *"a signature by a valid key
authorises the release"*. A signature by the wrong role, at the wrong scope, at
the wrong time, or by one party occupying both sides of a separation is
insufficient. The expected real result is therefore **0 actions authorised**,
because every recorded identity is the same undeclared party and no
authorisation signature exists.

- Enforced by `RA_REFUSED_WRONG_ROLE`, `RA_REFUSED_SCOPE_EXCEEDED`,
  `RA_REFUSED_EXPIRED`, `RA_REFUSED_REVOKED`, `RA_REFUSED_SEPARATION` and
  `RA_REFUSED_SELF_AUTHORISATION`.
- Enforced by `test_signature_unverified`, `test_wrong_role` and
  `test_every_constraint_is_individually_violated`.

## 2. The seven roles

The queue names seven roles. Every role is a `role` token in a role assignment;
an identity may hold more than one, but a separation policy may still refuse one
identity filling two roles for one action.

| role | what it may authorise | real tracked record |
|---|---|---|
| `maintainer` | an evidence correction, and the care of the repository's records | **none** — no tracked record assigns a maintainer identity or party |
| `producer` | source, build, analysis or proof production; the instrument's author; the sole author of a release | `evidence/etp-t8/ASSIGNMENTS.json` summary: `author` 50/50, `evidence_producer` 50/50, `proof_producer` 15/50, `instrument_author` 15/50, all at party `P-CAMPAIGN` |
| `instrument_reviewer` | qualification or re-qualification of an instrument | **none** — T8's single `reviewer` fill is the b85c adjudication's reviewer (`RV-B85C-1`), not an instrument reviewer |
| `adjudicator` | a claim verdict and its promotion | `evidence/etp-t8/ASSIGNMENTS.json`: `adjudicator` 50/50, `same_party_adjudicator` 50, all at party `P-CAMPAIGN` |
| `external_reproducer` | a reproduction from an external trust domain | `evidence/etp-t8/ASSIGNMENTS.json#A-ADJ-B85C`: `independent_reproducer` filled at `P-CAMPAIGN` in this repository's environment; **not external**, so the real state is `none` |
| `release_authority` | a release or graduation decision | `evidence/etp-t8/ASSIGNMENTS.json#A-REL-OPENSSH-B85C`: `release_authority` filled at `P-PRINCIPAL`, whose distinctness from `P-CAMPAIGN` is not established; **no declared release authority exists**, so the real state is `none` |
| `revocation_authority` | a revocation, withdrawal or supersession | `evidence/etp-t8/ASSIGNMENTS.json#A-REL-OPENSSH-B85C`: `revocation_authority` filled at `P-CAMPAIGN` |

A role label is not a party. `P-CAMPAIGN` and `P-PRINCIPAL` are both undeclared;
T8 records that `P-PRINCIPAL`'s distinctness from `P-CAMPAIGN` is not
established. `evidence/a14/ROLES.json` therefore maps both to the conservative
party `P-PROJECT-UNDECLARED`, and distinct signers are counted by party, not by
identity token. Two aliases of one party are one signer, and a separation cannot
be met by spelling the same party twice.

- Enforced by `RA_REFUSED_ROLE_UNKNOWN` (a role outside the seven) and
  `test_alias_parties_are_one_signer`.
- Enforced by `RA_REFUSED_IDENTITY_UNRECORDED` (an identity token no tracked
  record establishes) and `test_unknown_identity_is_not_a_role_label`.

## 3. The action policy

Each action declares the roles it requires, the minimum number of distinct
signer parties, the separations it requires, and whether the producer of the
evidence may sign at all.

| action | required roles | minimum distinct signers | separation constraints |
|---|---|---:|---|
| `release` | `release_authority`, `adjudicator` | 2 | `release_authority` ≠ `producer`; `release_authority` ≠ `adjudicator` |
| `claim-promotion` | `adjudicator` | 1 | `adjudicator` ≠ `producer`; the producer may not sign |
| `consumer-graduation` | `adjudicator`, `external_reproducer` | 2 | `adjudicator` ≠ `producer`; `external_reproducer` ≠ `producer`; `adjudicator` ≠ `external_reproducer`; the producer may not sign |
| `instrument-qualification` | `instrument_reviewer` | 1 | `instrument_reviewer` ≠ `producer` (the instrument's author) |
| `evidence-correction` | `maintainer` | 1 | `maintainer` ≠ `producer`; the producer may not sign |
| `revocation` | `revocation_authority` | 1 | `revocation_authority` ≠ `producer`; the producer may not sign |

The producer of the evidence being adjudicated, the author of an instrument being
reviewed, and the sole author of a release are the `producer` identity in that
action's context. This keeps the vocabulary at the seven named roles while making
each separation constraint nameable.

The policy is data, not prose: `authorisation.ACTIONS` is the single source, and
`authorisation.explain(action)` returns it. The records embed the policy under
`AUTHORISATION.json#policy`.

- Enforced by `RA_REFUSED_ACTION_UNKNOWN` (an action with no policy) and
  `test_action_unknown`.
- Enforced by `test_every_action_is_named` (the document and the policy agree).

## 4. The authorisation algorithm, in order

`authorise(action, signatures, assignments, policy, at, context)` applies the
following order. The order is part of the result: an earlier refusal prevents a
later question from being reached.

1. **Action known.** No policy entry is `RA_REFUSED_ACTION_UNKNOWN`. A policy
   declared `NOT_RUN`, or no signature set at all, returns the `NOT_RUN`
   outcome, which is not a pass.
2. **Signature verified.** A signature whose `verified` field is not `true` is
   refused as `RA_REFUSED_SIGNATURE_UNVERIFIED` *before its role is read*. An
   unverified signature is not a signer.
3. **Identity recorded.** The signer's identity token must be established by an
   assignment that names a tracked record (`evidence`); otherwise
   `RA_REFUSED_IDENTITY_UNRECORDED`. A role label with no record is not an
   identity.
4. **Role known.** The role named at signing must be one of the seven;
   otherwise `RA_REFUSED_ROLE_UNKNOWN`.
5. **Role assigned at the time.** An assignment of that role to that identity
   must exist (`RA_REFUSED_ROLE_NOT_ASSIGNED`), must have begun by the action
   time (also `RA_REFUSED_ROLE_NOT_ASSIGNED`), must not have been revoked by
   then (`RA_REFUSED_REVOKED`), and must not have expired
   (`RA_REFUSED_EXPIRED`).
6. **Scope.** Both the signature's scope and the assignment's scope must cover
   the action's scope; otherwise `RA_REFUSED_SCOPE_EXCEEDED`. A narrow grant
   does not cover a wider action.
7. **Role required.** The role must be one the action requires; a valid
   signature in another role is `RA_REFUSED_WRONG_ROLE`.
8. **Self-authorisation.** When the policy forbids it, a valid signer whose
   party is the producer of the evidence is `RA_REFUSED_SELF_AUTHORISATION`.
9. **Separation.** If one party fills both sides of a required separation, the
   action is `RA_REFUSED_SEPARATION`. This is checked over the valid signers and
   the context's role identities.
10. **Distinct signers.** The same identity signing twice is
    `RA_REFUSED_DUPLICATE_SIGNER`; fewer distinct signer parties than the
    minimum, or a required role with no valid signer, is
    `RA_REFUSED_INSUFFICIENT_SIGNERS`.
11. **Outcome.** `AUTHORISED` only when no code fired; otherwise `REFUSED`.

`authorise` returns every code that fired, in the registry order above, with a
detail line for each. It does not stop at the first refusal across different
signatures, because a consumer needs to see every reason the set fails.

`separation_failures(action, assignments, context, at)` is a separate structural
reading of the recorded role fills. It exists because the real recorded attempt
is refused at step 2 (no authorisation signature exists), and a reader still
needs to see *which* separation the same-party records fail. It is never an
authorisation and never changes the outcome.

- Enforced by `test_signature_unverified` (step 2 before step 4) and
  `test_not_yet_granted` / `test_expired` / `test_revoked` (step 5).
- Enforced by `test_assignment_scope_narrower_than_action` (step 6) and
  `test_duplicate_signer` (step 10).

## 5. The refusal table

Every code is stable. The second column names the wrong conclusion it prevents.

| code | what it prevents |
|---|---|
| `RA_REFUSED_SIGNATURE_UNVERIFIED` | an unverified signature borrowing a role; the signature is refused before its role is considered |
| `RA_REFUSED_IDENTITY_UNRECORDED` | a name invented at the point of use; no tracked record establishes the identity |
| `RA_REFUSED_ROLE_UNKNOWN` | a made-up role label outside the seven-role vocabulary |
| `RA_REFUSED_ROLE_NOT_ASSIGNED` | a signer choosing its own role, or acting before the grant began |
| `RA_REFUSED_EXPIRED` | a stale grant outliving its validity and authorising a later action |
| `RA_REFUSED_REVOKED` | a withdrawn authority being used after its revocation |
| `RA_REFUSED_SCOPE_EXCEEDED` | a narrow grant covering a wider action |
| `RA_REFUSED_WRONG_ROLE` | the right key being treated as the right role |
| `RA_REFUSED_SELF_AUTHORISATION` | the author of the evidence accepting its own run |
| `RA_REFUSED_SEPARATION` | two signatures that are one party occupying both sides of a separation |
| `RA_REFUSED_DUPLICATE_SIGNER` | one identity signing twice and being counted as two signers |
| `RA_REFUSED_INSUFFICIENT_SIGNERS` | an under-signed action, or a required role with no valid signer |
| `RA_REFUSED_ACTION_UNKNOWN` | an unlisted action inheriting permission by default |

One control per code is recorded in `evidence/a14/CONTROLS.json`; the test file
asserts that the control set exercises all thirteen and that every control passes.

- Enforced by `test_role_unknown`, `test_role_not_assigned`, `test_wrong_role`,
  `test_self_authorisation`, `test_separation`, `test_identity_unrecorded`,
  `test_signature_unverified`, `test_scope_exceeded`,
  `test_assignment_scope_narrower_than_action`, `test_expired`, `test_revoked`,
  `test_not_yet_granted`, `test_insufficient_signers`, `test_duplicate_signer`
  and `test_action_unknown`.

## 6. The real result: 0 authorised

`evidence/a14/ROLES.json` records five real assignments from
`evidence/etp-t8/ASSIGNMENTS.json`. There are two identity tokens,
`P-CAMPAIGN` and `P-PRINCIPAL`, both undeclared and both mapped to
`P-PROJECT-UNDECLARED`. No assignment records a grantor, an account, an
organisation or a signing key. The only recorded signing root is
`test-only:hmac-sha256:8e10a5a15d233d54` (A10/A12), which is symmetric, same-party
and signs A9 statements — not role authorisations. There are 0 declared
identities and 0 external trust domains.

Each of the six actions is attempted twice in `evidence/a14/AUTHORISATION.json`:

* **recorded** — the role fills taken as signature records with `verified:false`,
  because no authorisation signature exists;
* **face-value** — the same role fills with `verified:true`, clearly labelled
  `COUNTERFACTUAL_ROLE_ASSESSMENT`. This is not a real signature; it shows what
  the role policy says even if the role fills were signed.

| action | recorded outcome and codes | face-value codes | separation that failed |
|---|---|---|---|
| `release` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SEPARATION`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `release_authority` ≠ `producer`; `release_authority` ≠ `adjudicator`, all `P-PROJECT-UNDECLARED` |
| `claim-promotion` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SELF_AUTHORISATION`, `RA_REFUSED_SEPARATION` | `adjudicator` ≠ `producer` |
| `consumer-graduation` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SELF_AUTHORISATION`, `RA_REFUSED_SEPARATION`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `adjudicator` ≠ `producer`; `external_reproducer` ≠ `producer`; `adjudicator` ≠ `external_reproducer` |
| `instrument-qualification` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_ROLE_NOT_ASSIGNED`, `RA_REFUSED_WRONG_ROLE`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | not evaluable: no `instrument_reviewer` identity is recorded |
| `evidence-correction` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_ROLE_NOT_ASSIGNED`, `RA_REFUSED_WRONG_ROLE`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | not evaluable: no `maintainer` identity is recorded |
| `revocation` | `REFUSED`: `RA_REFUSED_SIGNATURE_UNVERIFIED`, `RA_REFUSED_INSUFFICIENT_SIGNERS` | `RA_REFUSED_SELF_AUTHORISATION`, `RA_REFUSED_SEPARATION` | `revocation_authority` ≠ `producer` |

**Aggregate: 0 actions authorised, 6 refused, 0 not run.** Both the recorded and
the face-value counts are **0 authorised**. The recorded attempt is refused first
at an unverified signature; the face-value assessment is still refused because
every identity is the same undeclared party, a required role is unassigned, or
the required separation fails. The real state explicitly records
`externalReproducer: none`, `releaseAuthority: none`, `maintainer: none` and
`instrumentReviewer: none`.

This is the honest result. It is not worked around by promoting a role label to a
party, by counting `P-CAMPAIGN` and `P-PRINCIPAL` as two signers, or by treating
the A10 test-only HMAC key as an authorisation signature.

- Enforced by `test_no_real_action_is_authorised`,
  `test_real_recorded_attempts_are_unverified`,
  `test_the_absent_roles_are_recorded_as_none` and
  `test_every_identity_is_the_same_party`.
- Enforced by `test_real_separations_are_recorded`.

## 7. The controls and what the positive control does and does not establish

`evidence/a14/CONTROLS.json` holds thirteen refusal controls (one per code), one
positive control, one `NOT_RUN` control and one alias-count control. Every
synthetic identity is labelled `control-only` and is excluded from the real
aggregate.

* The **thirteen refusal controls** each assert that their named code fires. The
  separation control uses `instrument-qualification` so that
  `RA_REFUSED_SEPARATION` is the only code, and the unverified control uses an
  unknown role to prove the ordering rule: only
  `RA_REFUSED_SIGNATURE_UNVERIFIED` fires, not `RA_REFUSED_ROLE_UNKNOWN`.
* The **positive control** (`positive-distinct-roles`) uses three distinct
  synthetic parties — a release authority, an adjudicator and a producer — and
  reaches `AUTHORISED`. It establishes that the decision procedure is not
  fail-closed by construction: when the right roles and separation are present,
  the procedure can authorise. It is **control-only**, and it does not establish
  that any real action is authorised, that any real identity is distinct, or that
  a release should happen. The real aggregate remains **0 authorised**.
* The **`NOT_RUN` control** establishes that a declared-not-run policy and an
  unattempted action report `NOT_RUN`, which is not a pass.
* The **alias-count control** establishes that two identity tokens of one party
  are one signer and one side of a separation, not two.

The controls are positive and negative: a refusal control that does not fire
fails the producer and the test, and the positive control that fails to authorise
fails too.

- Enforced by `test_controls_exercise_every_code`,
  `test_positive_control_is_control_only` and
  `test_distinct_synthetic_identities_reach_authorised`.
- Enforced by `test_positive_control_cli_exits_zero`.

## 8. Release-gate integration

The release gate has a per-refusal row structure: each checker returns a
`Results(refusals, recorded)` and the gate combines the rows without altering
another checker's verdict. A14 joins that seam as item 7,
`check_authorisation`, without changing items 1–6.

The gate now runs `forensics/tools/authorisation.py authorise release --json`
against `evidence/a14/AUTHORISATION.json` and `evidence/a14/ROLES.json`. A
refused release authorisation is the row:

```
REFUSED RG_AUTHORISATION_REFUSED a14/release: outcome=REFUSED codes=...
```

An absent tool or record is `RG_AUTHORISATION_TOOL_MISSING` or
`RG_AUTHORISATION_MISSING`; an unparseable result is `RG_AUTHORISATION_ERROR`. A
missing checker is a refusal, never a skip, in the same way as the gate's other
items.

**Status: integrated.** The gate's real run on this candidate now refuses with
the A14 row in addition to its pre-existing refusals; the release gate refuses a
release whose `release` action is not authorised. The gate's item list and the
constitution mapping in `docs/RELEASE_GATES.md` §10 have **not** been updated in
this item: §10 still names Articles 5, 6, 7 and 9 as uncovered by a gate item.
Adding the new row there, and deciding which article it evidences, is a retained
obligation (see §10). The integration itself is not deferred: the gate executes
the check.

- Enforced by `RG_AUTHORISATION_REFUSED` in `forensics/tools/release_gate.py` (`test_refused_authorisation_is_one_refusal_row`).
- Enforced by `test_refused_authorisation_is_one_refusal_row`,
  `test_authorised_authorisation_is_recorded_not_refused` and
  `test_missing_authorisation_record_is_refused` in
  `forensics/tools/tests/test_release_gate.py`.

## 9. Non-claims

* **No real action is authorised.** The aggregate is 0. The positive control is
  synthetic and establishes only the decision procedure.
* **No cryptographic verification is performed here.** `verified` is supplied by
  the caller; this module does not implement a signature primitive, a key
  distribution mechanism or a trust root.
* **No real external identity or trust domain exists.** `P-CAMPAIGN` and
  `P-PRINCIPAL` are undeclared; A12 records 0 external trust domains. This
  document does not claim independence (Article 5).
* **A role assignment is not a grant ceremony.** The real records name no
  grantor, account, organisation or signing key; the assignment records that
  absence rather than inventing one.
* **Authorisation is not truth.** A correctly authorised action can still be
  wrong, and a refused action can still be true. A14 does not upgrade any claim's
  verdict.
* **The gate row is not the whole release decision.** The gate refuses on many
  other grounds; A14 adds one row and inherits none of the other items'
  results.

## 10. Obligations retained

* **`docs/RELEASE_GATES.md` §10 is not updated.** The gate now runs
  `check_authorisation`, but the constitution's gate-item table still names
  Articles 5, 6, 7 and 9 as uncovered and does not list the new row. Deciding
  whether the authorisation row evidences Article 5 or Article 11 (or neither)
  and updating the table is a separate, deliberate change.
* **No real authorisation signature exists.** Every recorded attempt is
  `verified:false`. A production signing key, key distribution and a verification
  record are A12/A16/A17 work.
* **No external role holder exists.** No maintainer, instrument reviewer,
  external reproducer or declared release authority is established by a tracked
  record. A14 records `none`; it does not create them.
* **No grantor is recorded.** The T8 assignments name no grantor identity, role,
  account, organisation or signing key. A14 records `grantedBy` as null rather
  than inventing a ceremony.
* **The positive control is not a real action.** It is labelled `control-only`
  and is excluded from the real aggregate.
* **No independent review.** The author of the tool, document, records and
  controls is not an independent adjudicator of the code-to-conclusion mapping.

## `NOT_RUN`

* A cryptographic signature verification, a production signing key, key
  distribution, revocation distribution and a real identity ceremony.
* A real maintainer, instrument reviewer, external reproducer or declared
  release authority.
* A real authorised release, claim promotion, consumer graduation, instrument
  qualification, evidence correction or revocation.
* A15 thresholds, A16 Sigstore bundles, A17 transparency, A18/A19 where the
  queue names them, and the release gate's package and documentation items.
* A BOUNDARY audit, a full Miri/ASan/TSan campaign, independent review and SEAL.
* The Rust suite: `src/` was not modified, so no rebuild and no `cargo test`
  is claimed.

## 11. Reproducing the result

Inside the court, Python 3.11 standard library only:

```
python3 evidence/a14/build_evidence.py
python3 forensics/tools/authorisation.py authorise release
python3 forensics/tools/authorisation.py authorise release --face-value
python3 forensics/tools/authorisation.py roles P-CAMPAIGN --at 2026-11-24
python3 forensics/tools/authorisation.py explain claim-promotion
python3 -m unittest forensics.tools.tests.test_authorisation
python3 -m unittest discover -s forensics/tools/tests
```

`build_evidence.py` is deterministic: two runs are byte-identical, and the
committed records match a fresh run. The source identity is the candidate and the
digests of the named input records; the tool digest is recorded so a later tool
edit invalidates the record.
