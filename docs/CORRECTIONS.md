# Authenticated corrections and retractions (A19)

This is the normative document for A19. The implementation is
`forensics/tools/corrections.py`; the controls are
`forensics/tools/tests/test_corrections.py`; the records are `evidence/a19/`,
produced deterministically by `evidence/a19/build_evidence.py`.

## 1. The problem

A correction is not an edit. A project that silently changes a recorded value
keeps the new value and loses the fact that it once believed something else. The
history becomes unfalsifiable: a reader cannot tell a value that was always right
from one that was repaired, cannot see which downstream conclusions relied on the
old value, and cannot check that the repair reached them.

The rule this item implements is:

> A correction is a new, bound event. The original is never edited. Everything
> that cited the old value is marked invalidated, and both what was believed and
> what was disproved remain readable.

## 2. The event

An event is a JSON object:

```
{eventId, kind: assert|correct|retract, subject,
 supersedes: {previousEventId, previousDigest} | null,
 reason, oldValue, newValue, recordedAt,
 recordedBy: {role, identity}, evidence, authentication, signature}
```

`assert` records what was believed: `oldValue` is `null` and `newValue` is the
asserted value. `correct` records a successor value: both are present.
`retract` records that the subject now has no accepted value: `oldValue` is
present and `newValue` is `null`.

A value is not a paraphrase. It is:

```
{value, digest, citation, record: {path, sha256, committed, commit} | null}
```

`digest` is SHA-256 over the canonical JSON of `value`. `citation` is the literal
a dependent can quote. `record` names the file that carries the value at the
stated commit; `sha256` is that file's digest when it was committed, and `null`
when the original was never committed. A correction binds **both** the value
digest and the record digest, so a dependent that quotes either is found.

**Enforced by** `CR_REFUSED_EVENT_INVALID` (`test_event_invalid`).

## 3. The append-only rule

The log is:

```
{schema, model, sourceIdentity, authentication,
 events: [event, ...], history: [{eventId, digest, subject, kind,
                                   previousEventId, previousDigest}, ...],
 logDigest, logEnvelope}
```

`history` is a witness over the events, not a second copy: each entry carries the
canonical digest of the stored event, including its signature. `logDigest` is
SHA-256 over the canonical bytes of `history`. `logEnvelope` is a DSSE envelope
over the canonical bytes of the log without `logEnvelope`.

`append(log, event)` never edits an existing event and never mutates its input.
It recomputes the whole chain first. An edited event, a deletion, a reordered
history or a `logDigest` that no longer matches is refused with
`CR_REFUSED_HISTORY_ERASED` (`test_history_erased`; the `history-erased`
control). The original `assert` is never edited: a later value is a `correct` or
a `retract` that names it.

The log envelope is a byte-integrity seal, not an external anchor. A reader who
can recompute the digest chain and re-sign with the public test-only key is not
detected; see §11.

## 4. The binding rule: id plus digest

A `correct` or `retract` must name **both** its predecessor's event id and that
predecessor's canonical digest. Naming only the id is not a binding and is
refused with `CR_REFUSED_UNBOUND_CORRECTION` (`test_unbound_correction`; the
`unbound-correction` control). A digest that is not the stored predecessor's
canonical digest is refused with `CR_REFUSED_PREDECESSOR_MISMATCH`
(`test_predecessor_mismatch`; the `predecessor-mismatch` control).

The event also binds the **exact original value**: `oldValue.digest` must equal
the predecessor's accepted `newValue.digest`, and the record digests must agree.
A correction that points at a different value is refused with
`CR_REFUSED_ORIGINAL_MISMATCH` (`test_original_mismatch`; the
`original-mismatch` control).

A correction that names a different subject is not a correction. It is a new
assertion for a new subject, and it is refused with
`CR_REFUSED_SUBJECT_CHANGED` (`test_subject_changed`; the `subject-changed`
control). A second `assert` for a subject that already has one is refused with
`CR_REFUSED_ASSERTION_EXISTS` (`test_assertion_exists`; the `assertion-exists`
control). An `eventId` that already exists is refused with
`CR_REFUSED_EVENT_ID_REUSED` (`test_event_id_reused`; the `event-id-reused`
control).

A `retract` whose subject has no prior assertion is refused with
`CR_REFUSED_RETRACTION_UNBOUND` (`test_retraction_unbound`; the
`retraction-unbound` control).

## 5. Propagation: how dependents are derived

A dependent is **any record that cites a superseded digest**. The dependency is
built from the records' own citations, never from a hand-written list:

* `derive_dependents(log, repo_root)` walks `evidence/`, `docs/`,
  `forensics/tools/` and `courts/` (`.md`, `.json`, `.py`, `.txt`, at most 2 MiB
  per file) for each superseded digest and each event's `oldValue.citation`.
* Each match records the path, line and text of the citation, and the nearest
  supersession marker (`withdrawn`, `superseded`, `invalidated`, `retracted`,
  `old recorded value`, `old value`, `old counts`, `old sha-256`, `old and new`,
  `the earlier`, `no longer`, `correction`, `corrected`, `was wrong`,
  `before_reconciliation`, `preserved`, `before and after`, `not a pass`).
* A citation with a marker is declared `INVALIDATED`; a citation without one is
  declared `VALID`.

`propagate(log, dependents)` then marks and checks:

* every dependent that cites a superseded digest must be `INVALIDATED`; a
  dependent left `VALID` is refused with
  `CR_REFUSED_INVALIDATION_NOT_PROPAGATED` (`test_invalidation_not_propagated`;
  the `invalidation-not-propagated` control, which is a retraction whose
  dependent is left valid);
* a dependent declared `INVALIDATED` while it cites no superseded digest is
  refused with `CR_REFUSED_SPURIOUS_INVALIDATION`
  (`test_spurious_invalidation`; the `spurious-invalidation` control);
* the same retraction with the dependent correctly `INVALIDATED` is accepted
  (`test_retraction_propagates`; the `retraction-propagates` positive control).

The marker classification is **reported, not proved**. A record that relies on a
value in a form the token scan does not recognise is not found; the citation and
marker are recorded so a reviewer can check every call. The limits are stated in
§12.

## 6. Fork and cycle

A predecessor may have exactly one direct successor. A second event naming the
same predecessor is a fork: two different corrections of one record, one of which
would be silently dropped. It is refused with `CR_REFUSED_FORK` (`test_fork`;
the `fork` control). A chain that follows a successor is not a fork: the second
event names the first successor, not the shared ancestor.

A predecessor chain that revisits an event is a cycle and is refused with
`CR_REFUSED_CYCLE` (`test_cycle`; the `cycle` control). Cycle is checked before
fork because a cycle necessarily makes its predecessor look forked.

## 7. What a correction is not

* **Not a new assertion.** A different value for an existing subject must name
  the predecessor; otherwise it is refused as an assertion over existing history.
* **Not a rewrite.** An edit or deletion of an event is refused by recomputing the
  digest chain. The original bytes remain.
* **Not an erasure.** `current` returns the accepted event and the full history.
  A retracted subject has no accepted value and keeps every event.
* **Not a silent subject change.** The subject must equal the predecessor's.
* **Not a claim that the old value was wrong for the right reason.** The record
  binds a successor and preserves the reasoning; it does not establish that the
  reasoning is correct. See §12.

## 8. The real log

`evidence/a19/EVENTS.json` holds **eleven subjects and twenty-two events**: an
`assert` for what was believed and a bound `correct` or `retract`. Six subjects
are `CORRECTED`, five are `RETRACTED`, none is `DISPUTED` or `UNKNOWN`.

Every event is signed with A10's test-only HMAC-SHA256 signer and labelled
`SELF_ISSUED`. **No event is authenticated.** Seven corrections are recorded in
prose only; four claim retractions are machine-readable but unsigned. In the
records those states are `prose-only` for the seven and
`machine-readable-unsigned` for the four. The original is preserved for every
subject, but for A4, gate-reliability and the 99.6 % posterior the
pre-correction record was never committed and only the correcting receipt
preserves it.

| subject | event | kind | binding (old → new) | authenticated? | recorded as | outcome |
|---|---|---|---|---|---|---|
| `A4/L3-md32-update/byteLength` | `A19-E01`,`E02` | correct | `0xA5` (165) → `0x165` (357), record `4887d605` at `5f868b04f` | no | prose-only (`evidence/a4/RECEIPT.md` §6) | `CORRECTED` |
| `gate-reliability/verify-deterministic-projection` | `A19-E03`,`E04` | correct | live `MemAvailable` in the compared record → declared `environment` block; `{tmp}` substituted wherever it appears | no | prose-only (`evidence/gate-reliability/RECEIPT.md` §3–§5) | `CORRECTED` |
| `A7/sourceIdentity` | `A19-E05`,`E06` | correct | live `HEAD` at `BASELINES.json` `f2d6e379` → explicit identity and 16 input digests at `2a5a3f86` | no | prose-only (`evidence/a7/RECEIPT.md` §11) | `CORRECTED` |
| `A11/SCAN.json/population` | `A19-E07`,`E08` | correct | live glob at `9cc6680f` → frozen 386-member list at `0307db34` | no | prose-only (`evidence/a11/RECEIPT.md` §12) | `CORRECTED` |
| `A16/INVENTORY.json/populationFiles` | `A19-E09`,`E10` | correct | live glob 407 at `b6c06350` → frozen 404-member list at `a7e20060` | no | prose-only (`evidence/a16/RECEIPT.md` §11) | `CORRECTED` |
| `HAZ-15/external-key-KDK` | `A19-E11`,`E12` | correct | `SHA-256(decrypted block)` → keyed derivation (CRT primes or `RAND_priv_bytes`) | no | prose-only (`evidence/haz-15/KDK-CORRECTION.md`; commit `c28ac7bb9`) | `CORRECTED` |
| `HAZ-15/posterior-probability-99.6` | `A19-E13`,`E14` | retract | the unconditional `99.6%` posterior → no accepted value; the conditional formula remains in §5.3 | no | prose-only (`evidence/haz-15/REENTRANCY-AND-LENGTH.md` §5.3) | `RETRACTED` |
| `ETP0-CLM-004/verdict` | `A19-E15`,`E16` | retract | `CONTRADICTED` → `SUPERSEDED` | no | machine-readable but unsigned (`evidence/etp/claims.json`; history copy) | `RETRACTED` |
| `ETP0-CLM-005/verdict` | `A19-E17`,`E18` | retract | `CONTRADICTED` → `SUPERSEDED` | no | machine-readable but unsigned | `RETRACTED` |
| `ETP0-CLM-030/verdict` | `A19-E19`,`E20` | retract | `CONTRADICTED` → `RISK_ACCEPTED`; `SAFE_COMPATIBLE` remains `NOT_ESTABLISHED` | no | machine-readable but unsigned | `RETRACTED` |
| `ETP0-CLM-032/verdict` | `A19-E21`,`E22` | retract | `CONTRADICTED` → `SUPERSEDED` | no | machine-readable but unsigned | `RETRACTED` |

The four claim retractions are bound to the **exact original claim object** in
`evidence/etp-t15/history/claims.before-reconciliation.json`, not to the digest
of the file that carries it. The file digest is shared by four claims and by every
record that cites the claims set as an input; using it would make the dependency
relation meaningless. The successor is recorded by claim identity in
`evidence/etp/claims.json` and in `docs/ADJUDICATION-RECONCILIATION.md`, so no
downstream record quotes the old object's digest. `PROPAGATION.json` records that
negative result rather than inventing a dependent.

The KDK retraction is recorded in `evidence/haz-15/KDK-CORRECTION.md` and in the
commit message `rsa: withdraw the unkeyed KDK and key the synthetic answer
properly` (`c28ac7bb9`). It is the one event whose record names a commit message
as well as a document.

## 9. The controls

`evidence/a19/CONTROLS.json` holds **sixteen** `control-only` fixtures over the
sixteen refusal codes, plus two positives. Every fixture is synthetic. A control
that fires proves the refusal works; it is not a defect report.

| control | code | what it refuses |
|---|---|---|
| `event-invalid` | `CR_REFUSED_EVENT_INVALID` | an event missing a required field |
| `unbound-correction` | `CR_REFUSED_UNBOUND_CORRECTION` | a correction naming an id but not a digest |
| `predecessor-mismatch` | `CR_REFUSED_PREDECESSOR_MISMATCH` | a `previousDigest` that is not the stored predecessor's |
| `original-mismatch` | `CR_REFUSED_ORIGINAL_MISMATCH` | an `oldValue` that is not the predecessor's accepted value |
| `history-erased` | `CR_REFUSED_HISTORY_ERASED` | an event edited after the log was chained |
| `fork` | `CR_REFUSED_FORK` | a second direct successor of one predecessor |
| `cycle` | `CR_REFUSED_CYCLE` | a predecessor chain that revisits an event |
| `subject-changed` | `CR_REFUSED_SUBJECT_CHANGED` | a correction of a different subject |
| `retraction-unbound` | `CR_REFUSED_RETRACTION_UNBOUND` | a retraction of a never-asserted subject |
| `unsigned` | `CR_REFUSED_UNSIGNED` | an event with no signature |
| `signature` | `CR_REFUSED_SIGNATURE` | a signature over different bytes |
| `role` | `CR_REFUSED_ROLE` | an identity with no A14 assignment for the role |
| `assertion-exists` | `CR_REFUSED_ASSERTION_EXISTS` | a second assert for one subject |
| `event-id-reused` | `CR_REFUSED_EVENT_ID_REUSED` | two events sharing an `eventId` |
| `invalidation-not-propagated` | `CR_REFUSED_INVALIDATION_NOT_PROPAGATED` | a retraction whose dependent is left valid |
| `spurious-invalidation` | `CR_REFUSED_SPURIOUS_INVALIDATION` | an invalidation with no superseded citation |

The two positives are `retraction-propagates` (the same retraction with the
dependent `INVALIDATED` reaches `CR_OK`) and `positive-chain` (an
`assert → correct → correct` chain verifies and its accepted event is
`CORRECTED`).

`PROPAGATION.json` records fourteen real dependents across the seven value- and
record-bound corrections (A4, gate-reliability, A7, A11, A16, KDK, 99.6 %). All
fourteen are `INVALIDATED`; there is no stale dependent and no spurious
invalidation. The dependents are the correcting receipts and the records that
quote both the old and the new value. The four claim retractions have no
digest-citing dependent, as §8 states.

## 10. Refusal table

Every code is stable. The final column names the control and the test that fire
it.

| code | wrong conclusion it prevents | enforced by |
|---|---|---|
| `CR_REFUSED_EVENT_INVALID` | a malformed event read as a checked correction | `event-invalid`; `test_event_invalid` |
| `CR_REFUSED_UNBOUND_CORRECTION` | a correction that cannot be tied to its predecessor | `unbound-correction`; `test_unbound_correction` |
| `CR_REFUSED_PREDECESSOR_MISMATCH` | a correction that points at bytes other than the predecessor's | `predecessor-mismatch`; `test_predecessor_mismatch` |
| `CR_REFUSED_ORIGINAL_MISMATCH` | a correction that silently corrects a different value | `original-mismatch`; `test_original_mismatch` |
| `CR_REFUSED_HISTORY_ERASED` | editing or deleting an event and keeping the new history | `history-erased`; `test_history_erased` |
| `CR_REFUSED_FORK` | two corrections of one record, one silently dropped | `fork`; `test_fork` |
| `CR_REFUSED_CYCLE` | a correction that is its own ancestor | `cycle`; `test_cycle` |
| `CR_REFUSED_SUBJECT_CHANGED` | re-labelling a different subject as a correction | `subject-changed`; `test_subject_changed` |
| `CR_REFUSED_RETRACTION_UNBOUND` | retracting a value the project never asserted | `retraction-unbound`; `test_retraction_unbound` |
| `CR_REFUSED_UNSIGNED` | an unsigned event read as a signed correction | `unsigned`; `test_unsigned` |
| `CR_REFUSED_SIGNATURE` | a signature over different bytes counted as this event's | `signature`; `test_signature` |
| `CR_REFUSED_ROLE` | an identity outside the correcting role recording an event | `role`; `test_role` |
| `CR_REFUSED_ASSERTION_EXISTS` | a second assertion that silently replaces the first | `assertion-exists`; `test_assertion_exists` |
| `CR_REFUSED_EVENT_ID_REUSED` | one id satisfying two events in the chain | `event-id-reused`; `test_event_id_reused` |
| `CR_REFUSED_INVALIDATION_NOT_PROPAGATED` | a correction that leaves a relying record looking current | `invalidation-not-propagated`; `test_invalidation_not_propagated` |
| `CR_REFUSED_SPURIOUS_INVALIDATION` | an invalidation with no superseded record behind it | `spurious-invalidation`; `test_spurious_invalidation` |

The role mapping is A19's: `assert` and `correct` require the `producer` role,
and `retract` requires the `revocation_authority` role. A14 has no correction
role; the mapping is stated here so it is not inferred from the implementation.
The identity must already be assigned that role in `evidence/a14/ROLES.json`; no
identity is invented. A14 records no declared identity, so the role check is a
membership check, not an authentication.

## 11. The A12 caveat on the signature

The only signing key in this tree is A10's test-only HMAC-SHA256 key, derived
from a fixed public seed and recorded at
`test-only:hmac-sha256:8e10a5a15d233d54`. A12 records it as symmetric,
same-party and `SELF_ISSUED`, with **0 external roots**.

A signature made with it proves that the event or log bytes have not changed
since signing. It does **not** prove who recorded the event, that the recorder
held the role, that an independent party reviewed the correction, or that the
original assertion was made by the party it names. The log and every event are
labelled `SELF_ISSUED`; `authentication.authenticated` is `false` throughout.
No external trust root, key ceremony, timestamp authority or transparency log is
configured.

## 12. Non-claims

* **A correction record does not establish that the corrected value was wrong for
  the right reason.** It establishes that a bound successor exists and what the
  project said about it.
* **The dependent classification is reported, not proved.** The token scan finds
  a record that quotes the old digest, value or citation. A record that relies on
  the old value in a form the scan does not recognise is not found. Every
  citation and marker is recorded so the call can be checked.
* **The log is not authenticated.** The test-only key is public and symmetric;
  the `SELF_ISSUED` label is the honest state.
* **History-erasure detection is relative to the log's own chain.** A rewriter
  who recomputes the chain and re-signs with the public test key is not detected
  by this mechanism. An external anchor is A16/B1-B5's subject, not this item's.
* **A retraction is not a finding that the original was false.** It records that
  the project no longer accepts the value; the reasoning for the retraction is in
  `reason` and `evidence`.
* **The four claim retractions have no digest-citing dependent.** Their successor
  is recorded by claim identity in `evidence/etp/claims.json` and in
  `docs/ADJUDICATION-RECONCILIATION.md`; the propagation is by identity, not by
  the old object's digest.
* **The old value was not always committed.** For A4, gate-reliability and the
  99.6 % posterior, the pre-correction record existed only in the working tree;
  the correcting receipt is the only preservation, and it is prose.
* **The roles are A19's mapping.** A14 has no correction role and declares no
  identity; the mapping does not create an authority.
* This is evidence bookkeeping, not a safety, compatibility, cryptographic or
  build result.

## `NOT_RUN`

* An authenticated correction event: none exists. A14 declares no identity, and
  the only signer is the test-only HMAC key.
* A real independent recorder, reviewer or adjudicator of a correction: none
  exists.
* A production key, a key ceremony, key distribution, or an external trust root:
  none exists.
* A wall-clock, RFC 3161 or transparency-log timestamp for the log or an event:
  none is configured.
* A repair of a stale dependent: none was found on real data. The four claim
  retractions have no digest-citing dependent, and the fourteen found dependents
  are all `INVALIDATED`; that is a negative result, not a proof that no stale
  record exists in a form the scan does not recognise.
* Independent review, a BOUNDARY audit, a SEAL, and the Rust suite: `src/` was
  not modified, so no rebuild and no `cargo test` is claimed.
