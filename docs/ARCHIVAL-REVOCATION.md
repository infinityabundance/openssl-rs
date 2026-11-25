# Archival and revocation (B6)

This is the normative document for B6 of `docs/ETP-ADDENDUM-B.md` (§B.17,
§B.19, §B.30). The implementation is `forensics/tools/archival.py`; the controls
are `forensics/tools/tests/test_archival.py`; the records are `evidence/b6/`,
produced deterministically by `evidence/b6/build_evidence.py`.

## 1. The property, and why it needs three mechanisms

> A withdrawn claim is refused by current-state policy while its original
> inclusion proof remains valid.

This is one sentence about two things that must not be confused. *Historical
inclusion* is a fact about bytes that existed and were committed to in a log; it
does not change when the project stops accepting the claim. *Current
applicability* is a decision about the present; it must change, or a withdrawal
would be ineffective. An implementation that deletes the record to withdraw the
claim satisfies the second half and destroys the first. An implementation that
verifies the inclusion proof as if it settled the present satisfies the first
half and defeats the withdrawal.

So the item has three independent mechanisms and each is demonstrated separately:

1. **the archive** reconstructs the claim's evidence from archived bytes alone;
2. **the current state** records what the project accepts now, derived from A19;
3. **the policy** refuses a present-tense use of a subject that is not ACTIVE,
   while the inclusion lookup for that same subject still succeeds.

**Withdrawal is not erasure.** The original statement, its leaf, its inclusion
proof, its checkpoint and the event that withdrew it all remain; only the
subject's *state* changes.

**Enforced by** `RV_REFUSED_WITHDRAWN_ACCEPTED` and `RV_REFUSED_INCLUSION_LOST`
(`test_the_present_tense_use_is_refused_and_names_the_event`,
`test_the_discarded_proof_loses_inclusion_not_the_withdrawal`).

## 2. The archive contract

`evidence/b6/ARCHIVE/` is a directory with a manifest at `MANIFEST.json` and the
member bytes under `members/`. The contract is:

* **Byte identity.** Every member carries `{id, path, role, bytes, sha256}`. The
  manifest carries `manifestDigest`, SHA-256 over its own canonical bytes with
  the `manifestDigest` field removed. A manifest whose digest does not cover its
  bytes is `RV_REFUSED_ARCHIVE_INVALID`.
* **Containment.** A member path is relative to the archive, contains no `..` and
  resolves inside the archive directory. A path that escapes is
  `RV_REFUSED_ARCHIVE_INVALID`, because an archive that reads outside itself is
  not a self-contained record.
* **No working tree.** Reconstruction takes the archive directory as its only
  input. It does not read `evidence/a19/`, `evidence/a9/` or any other tracked
  path: the A19 binding, the two state versions, the A9 statement and the fixture
  statement are members. The control
  `test_reconstruction_reads_only_the_archive_copy` copies the archive to a
  temporary directory, points `REPO_ROOT` at a path that does not exist and
  still reconstructs.
* **Every member re-hashed.** A member whose bytes do not hash to its recorded
  digest is `RV_REFUSED_RECONSTRUCTION_MISMATCH`; a member the manifest requires
  but the archive does not hold is `RV_REFUSED_ARCHIVE_MISSING`.
* **A reconstruction, not a copy.** After the digests, the procedure verifies, in
  this order, that (1) the archived checkpoint's signature, origin and size
  verify; (2) the archived publication record names the same leaf, size and root;
  (3) the statement hashes to the recorded leaf and leaf hash; (4) the RFC 6962
  inclusion proof verifies against the checkpoint root; (5) the archived leaf list
  recomputes that root; (6) the statement's subject digest is the archived A19
  assertion event identity and its `retractedBy` digest is the archived
  retraction identity, and the archived current state binds the withdrawal to
  that retraction; (7) both archived states validate, the current one names the
  earlier one as its previous, and the claim is `WITHDRAWN` in the current one.
  Any failure is `RV_REFUSED_RECONSTRUCTION_MISMATCH`.

The `b6-archive-1` archive has **9 members** and runs **9 checks**; `ARCHIVE.json`
records each member's digest and the reconstruction result, and
`test_the_archive_record_matches_a_fresh_reconstruction` asserts that the record
is a fresh run rather than a transcription.

The archive holds the *leaf hashes* of all five leaves but the *payloads* only of
the two statements it reconstructs. That is what an inclusion proof needs and it
is stated rather than implied: the archive does not reconstruct the synthetic
leaves' bytes.

The A19 events are archived as **event identities** (event id and canonical event
digest), not as copies of the events. A copy would duplicate the withdrawn
value's digest, which is the original record itself rather than a record citing
it; A19's own citation scan excludes `evidence/a19` for exactly that reason and
has no way to extend the exclusion to another directory. So the reconstruction
binds the statement and the state to the A19 event *digests*, and re-deriving an
event digest from its bytes remains `NOT_RUN` here: that needs
`evidence/a19/EVENTS.json`, which is the authority for the event bytes.

**Enforced by** `RV_REFUSED_ARCHIVE_INVALID`, `RV_REFUSED_ARCHIVE_MISSING`,
`RV_REFUSED_RECONSTRUCTION_MISMATCH`
(`test_a_manifest_not_covering_its_bytes_is_refused`,
`test_a_discarded_member_is_refused`, `test_one_flipped_byte_is_refused`).

## 3. The current state, and its version

`evidence/b6/CURRENT-STATE.json` is an index over A19:

```
{schema, model, identity, version, versionRule, asOf, derivedFrom,
 previous: {version, asOf, digest} | absent, subjects: [entry, ...], digest}

entry = {subject, state: ACTIVE|CORRECTED|WITHDRAWN, supersededBy,
         correctionDigest, history}
```

The index is **derived, not written**: `archival.derive_state` rebuilds the A19
prefix through `corrections.append` (which re-checks every event's signature,
role and binding), then asks `corrections.current` for each subject. The mapping
is A19's own vocabulary: `CURRENT -> ACTIVE`, `CORRECTED -> CORRECTED`,
`RETRACTED -> WITHDRAWN`; `DISPUTED` and `UNKNOWN` have no current state and are
refused rather than guessed. `test_the_committed_state_is_the_derivation`
re-derives both versions and compares them with the committed bytes.

`supersededBy` is the A19 event that superseded the assertion, and
`correctionDigest` is that event's canonical digest (`corrections.event_digest`,
which includes its signature) — the same digest form A19's `supersedes`
already uses. It is not the value digest of the correction.

**Binding.** A `CORRECTED`/`WITHDRAWN` entry must name an event that exists in
the A19 log, is about the same subject, has the matching kind (`correct` for
`CORRECTED`, `retract` for `WITHDRAWN`) and hashes to `correctionDigest`. A
withdrawal with nothing behind it is `RV_REFUSED_REVOCATION_UNBOUND`; the
control `withdrawal-unbound` removes the digest and recomputes the state digest,
so the refusal is about the binding and not about a stale hash.

**Propagation.** In the other direction, every A19 correction must be reflected.
`check_propagation` refuses a state that omits a corrected subject, records it
`ACTIVE`, or binds it to another event (`RV_REFUSED_CORRECTION_UNPROPAGATED`).
The control checks the version-21 state against the full log: A19 records
`ETP0-CLM-032/verdict` as retracted at version 22 and the older state still says
`ACTIVE`.

**The version is the number of A19 events the state covers.** A19's log is
append-only (A19's `CR_REFUSED_HISTORY_ERASED`), so a later derivation covers a
strict superset and its version is strictly greater. `asOf` is the `recordedAt`
of the last covered event. The real index has 11 subjects: **0 ACTIVE, 6
CORRECTED, 5 WITHDRAWN**.

**Enforced by** `RV_REFUSED_STATE_INVALID`, `RV_REFUSED_REVOCATION_UNBOUND`,
`RV_REFUSED_CORRECTION_UNPROPAGATED` (`test_a_hand_edited_state_is_refused`,
`test_a_withdrawal_with_no_correction_is_refused`,
`test_an_unpropagated_correction_is_refused`).

## 4. The anti-rollback rule

The version may not decrease, and an older file may not stand in for the current
one. Three distinct refusals, because they are three distinct wrong conclusions:

| rule | refusal | what it prevents |
|---|---|---|
| a newer state's version is lower than the state it follows | `RV_REFUSED_ROLLBACK_OF_STATE` | the index walked backwards and called current |
| a state with an older version is offered as the current one | `RV_REFUSED_REPLAY_AS_CURRENT` | an old index replayed to resurrect a withdrawn claim |
| two states at one version carry different digests | `RV_REFUSED_STATE_CONFLICT` | two current histories at one version, one silently preferred |

`check_monotonic(previous, next)` is the producer's rule and fires the first.
`admit(candidate, accepted)` is the verifier's rule: an older candidate fires the
second before anything else is considered, and only the exact accepted document
may be re-admitted at its own version. A *newer* candidate is admitted only when
it names the accepted state's digest as its `previous`, so a skipped version or a
broken link is `RV_REFUSED_STATE_INVALID`.

The two replay codes are not synonyms. `ROLLBACK_OF_STATE` is about a version
sequence that goes down; `REPLAY_AS_CURRENT` is about presenting an earlier
document at the point where the current state is demanded. The real demonstration
records both against the same pair (version 21 over version 22).

The `previous.digest` link is also checked during reconstruction, so an archive
holding two valid but unrelated states is refused
(`RV_REFUSED_RECONSTRUCTION_MISMATCH`).

**Enforced by** `RV_REFUSED_ROLLBACK_OF_STATE`, `RV_REFUSED_REPLAY_AS_CURRENT`,
`RV_REFUSED_STATE_CONFLICT` (`test_a_version_may_not_decrease`,
`test_a_replayed_state_is_refused`, `test_a_same_version_conflict_is_refused`).

## 5. The three-fact demonstration

`evidence/b6/FIXTURE-2.json` publishes a five-leaf RFC 6962 log. Leaf 0 is the
real frozen A9 statement `evidence/a9/STATEMENTS/a8-shard-000.json`. **Leaf 1 is
a fixture statement**: no A9 statement covers an A19 correction subject, so the
statement is built over the withdrawn record's bytes, its subject is
`a19:ETP0-CLM-032/verdict` at the canonical digest of `A19-E21`, and it is
labelled `fixture-statement` / `notAnA9Statement` with a predicate type that A9's
registry does not contain. Leaves 2–4 are synthetic test-only entries.

The log is published with leaf index **1**, a 3-element inclusion proof, and a
size-5 checkpoint (root
`4b9b97a4…4946d6`) signed by
A10's test-only HMAC-SHA256 key. `evidence/b6/ARCHIVE.json` reconstructs that
claim from archived bytes alone.

`evidence/b6/DEMONSTRATION.json` records the three facts at one state version:

| fact | record | result |
|---|---|---|
| the inclusion proof still verifies against the checkpoint | `inclusionStillValid` | `RV_OK`, leaf 1, 3 elements, size 5 |
| `current(subject)` is withdrawn | `currentIsWithdrawn` | `RV_OK`, `WITHDRAWN`, version 22, superseded by `A19-E22` |
| a present-tense use is refused | `presentTenseRefused` | `RV_REFUSED_WITHDRAWN_ACCEPTED` |

`test_the_three_facts_are_recorded_together` asserts all three from the record and
`test_inclusion_remains_valid_for_the_withdrawn_subject` re-runs the inclusion
lookup against the committed archive, so the record cannot drift from the tool.

Then the **replayed** version: the version-21 state (still `ACTIVE`) offered as
current is `RV_REFUSED_REPLAY_AS_CURRENT`, and the version sequence 22 → 21 is
`RV_REFUSED_ROLLBACK_OF_STATE`. That is the point of the whole mechanism: the
older state is not forged, it is genuine and was once correct. It is refused
because it is not current.

## 6. The controls

`evidence/b6/CONTROLS.json` holds **15 `controlOnly` rows**: one per refusal code
and one positive. Each row records the mutation, the code and message observed,
and a **restoration** replay — the unmutated input accepted by the same call, per
§B.24's mutation / refusal / restoration / positive replay. One restoration is
deliberately not an acceptance:

* `subject-not-indexed` cannot be restored by the same call, because no state
  exists for a subject that is not in the index; the row says so and records the
  control subject instead.

One restoration is an acceptance that the item must explain:

* `withdrawn-used-as-current` is accepted in the present tense at version 21. That
  is exactly the replay the anti-rollback rule refuses; the row states the scope
  rather than hiding it.

The controls are control-only and mutate temporary copies; they are not source
changes and not defect reports. A refusal that fires proves the check works, not
that a real archive is complete.

## 7. The refusal table

Every code is stable and printed. The final column names the control and the test
that fire it.

| code | the wrong conclusion it prevents | enforced by |
|---|---|---|
| `RV_OK` | — (the positive control) | `positive-control`; `test_the_positive_control_passes` |
| `RV_REFUSED_USAGE` | a mistyped request read as a check | `derivation-out-of-range`; `test_a_derivation_out_of_range_is_refused` |
| `RV_REFUSED_IO` | an unreadable record read as absent or valid | `state-unreadable`; `test_an_unreadable_state_is_an_io_refusal` |
| `RV_REFUSED_ARCHIVE_INVALID` | an archive whose own contract does not hold treated as a store of bytes | `archive-manifest-unbound`; `test_a_manifest_not_covering_its_bytes_is_refused` |
| `RV_REFUSED_ARCHIVE_MISSING` | a discarded member read as reconstructed | `archive-member-discarded`; `test_a_discarded_member_is_refused` |
| `RV_REFUSED_RECONSTRUCTION_MISMATCH` | bytes that are not the archived member accepted as that member | `reconstruction-flipped-byte`; `test_one_flipped_byte_is_refused` |
| `RV_REFUSED_STATE_INVALID` | a hand-edited or unbound index read as the derived state | `state-not-covered-by-digest`; `test_a_hand_edited_state_is_refused` |
| `RV_REFUSED_REVOCATION_UNBOUND` | a withdrawal with nothing behind it | `withdrawal-unbound`; `test_a_withdrawal_with_no_correction_is_refused` |
| `RV_REFUSED_CORRECTION_UNPROPAGATED` | a correction that leaves the claim looking current | `correction-unpropagated`; `test_an_unpropagated_correction_is_refused` |
| `RV_REFUSED_ROLLBACK_OF_STATE` | an index walked backwards and called current | `version-decreases`; `test_a_version_may_not_decrease` |
| `RV_REFUSED_REPLAY_AS_CURRENT` | an old index replayed to resurrect a withdrawn claim | `stale-state-as-current`; `test_a_replayed_state_is_refused` |
| `RV_REFUSED_STATE_CONFLICT` | two current histories at one version, one silently preferred | `same-version-conflict`; `test_a_same_version_conflict_is_refused` |
| `RV_REFUSED_WITHDRAWN_ACCEPTED` | a withdrawn claim used as if it were current | `withdrawn-used-as-current`; `test_the_present_tense_use_is_refused_and_names_the_event` |
| `RV_REFUSED_SUBJECT_UNKNOWN` | an absent state read as an accepted one | `subject-not-indexed`; `test_an_unknown_subject_is_refused` |
| `RV_REFUSED_INCLUSION_LOST` | a withdrawn claim's inclusion record discarded with the claim | `inclusion-proof-discarded`; `test_the_discarded_proof_loses_inclusion_not_the_withdrawal` |

`test_every_refusal_code_has_exactly_one_control` asserts the table, the controls
and the code registry are the same set.

## 8. Non-claims

* **An archive is not an independent copy.** `b6-archive-1` is one member set in
  one repository. Reconstruction proves that *these bytes* verify; it does not
  establish that they are the earliest, the only or an uncorrupted copy. §B.17's
  independently verifiable mirror does not exist here. A rewriter who replaces
  the archive, its manifest and both states consistently is not detected by this
  mechanism.
* **The archive is one copy and its A19 binding is by digest.** The events
  themselves live in `evidence/a19/EVENTS.json`; the archive records their
  identities. A verifier who wants the event bytes must read the log, and this
  reconstruction does not re-derive an event digest from them.
* **A fixture log is not a public log.** `FIXTURE-2` is a local RFC 6962
  construction, not `rekor-tiles`, not a Rekor entry and not an admitted service.
  It has no log key, no witness and no integrated time. Its checkpoint is signed
  with A10's fixed public test-only HMAC key, so a valid signature proves byte
  integrity under a public key, not identity.
* **The fixture statement is not an A9 attestation.** A9's registry has five
  predicate types and none covers an A19 subject; the statement is labelled and
  is not submitted to `intoto.py`.
* **A withdrawal does not make the original untrue; it makes it not current.**
  `A19-E22` records that the project no longer accepts `ETP0-CLM-032`'s
  `CONTRADICTED` verdict; it does not establish that the verdict was never
  recorded. Both remain readable, and the inclusion proof remains valid.
* **The withdrawal is not authenticated.** A19 records it as
  `machine-readable-unsigned`: the only signer is the test-only HMAC key, A14
  declares no identity, and `authentication.authenticated` is false. This item
  binds the withdrawal to an event; it does not authenticate the recorder.
* **The current state is not a TUF repository.** It has a version and an
  anti-rollback rule, but no signed metadata, no role separation and no
  timestamp authority. An adversary who can rewrite the state and keep the
  version increasing is not detected.
* **The subject set is A19's.** The index covers the 11 subjects A19 records; a
  claim A19 never logged has no current state and is
  `RV_REFUSED_SUBJECT_UNKNOWN`, not `ACTIVE`.
* **Evidence bookkeeping is not a safety, compatibility, cryptographic or build
  result.** No Rust source was modified.

## 9. `NOT_RUN`

* **A public or admitted log**: no service, client, log key or network exists;
  FIXTURE-2 is local.
* **A witness or cosignature** for the size-5 checkpoint (B5 records 0
  witnesses).
* **A trusted timestamp** for the publication, the state or the correction
  (B2 records no authority).
* **An authenticated correction or withdrawal**: A14 declares no identity and
  the only signer is the test-only HMAC key.
* **An independent archive or mirror**: one member set, one repository.
* **An independent reviewer or operator**: the producer is the validator.
* **`BOUNDARY`, `SEAL` and the Rust suite**: no Rust source changed, so no
  `cargo` command ran.
* **Closure of the A17 forward freeze**: this item satisfies its `b6-receipt`
  member only; the freeze stays `OPEN`.

## 10. The queue status

`docs/ETP-TODO.md`'s B6 row is `PARTIAL` at base `19b710192`: the archive,
current-state, policy, anti-rollback and the demonstration are implemented and
controlled; the admitted-log, authenticated-correction and independent-archive
halves do not exist in this venue.
