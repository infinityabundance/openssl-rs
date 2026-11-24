# in-toto Statement v1 attestations (A9)

A statement is the attestation envelope this project emits. Its substance is not
its shape: it is that a statement **must not assert more than the records behind
it admit**, and must not name an artefact it has not hashed. This document is
normative for `forensics/tools/intoto.py`; the controls are
`forensics/tools/tests/test_intoto.py`, the recorded statements are
`evidence/a9/STATEMENTS/`, and the index and controls are
`evidence/a9/STATEMENTS.json` and `evidence/a9/CONTROLS.json`.

A10 owns the DSSE envelope and the pre-authentication encoding (PAE). A11 owns
parser hardening, A12 independent cryptographic verification, A14 role-bound
authorisation, A15 thresholds over distinct keys, A16 the Sigstore bundle and A17
transparency and omission resistance. Nothing here signs, verifies a signature,
applies PAE or establishes a trust root.

## 1. The problem

An in-toto Statement v1 is a small JSON envelope with a large implied claim: the
subject is bound by a content digest to exact bytes, and the predicate says what
is true of them. Two failures are easy and both look authoritative:

1. **A digest that is not of the bytes.** A Git commit id, an abbreviated token,
   a digest carried over from an earlier generation or a caller-supplied value is
   placed in `subject[].digest`. The statement then names bytes it never read.
2. **A predicate stronger than its record.** A record admits `TRUNCATED_BOUNDED`
   and the statement says `COMPLETE`; a delta records zero resolutions and the
   statement says `RESOLVED`; an aggregate has no member rows and the statement
   presents a census; an instrument's control is `RECORDED` and the statement
   calls it verified. The record is honest and the envelope is not.

The fix is not a prose warning. A subject digest is always recomputed from the
bytes; a predicate is built from the record's own admitted values and is
re-checked against a fresh reading of that record at emission and at
verification. Every refusal has a stable code naming the wrong conclusion it
prevents.

## 2. The three mandatory parts

| part | rule |
|---|---|
| `_type` | exactly `https://in-toto.io/Statement/v1`. Any other value is refused. |
| `subject` | a non-empty list of `{name, digest}`. `name` is a repo-relative artefact path; `digest` is an object whose only key is `sha256` and whose value is 64 lowercase hexadecimal characters. |
| `predicateType`, `predicate` | a type registered in §4 and a predicate that carries only fields that type licenses, restating values its named record admits. |

The emitted document has exactly these four fields. A document with an extra
field, a different shape, reordered keys or added whitespace is not the canonical
form this tool writes and is refused
(`IT_REFUSED_STATEMENT_MUTATED`, enforced by
`test_one_byte_mutation_is_refused`, `test_a_non_canonical_reordering_is_refused`
and `test_the_canonical_form_is_sorted_and_compact`).

## 3. The subject rule

> A subject digest is a **content** digest of the exact bytes of the named
> artefact. It is computed by reading the bytes, never supplied by a caller, and
> it is recomputed at verification.

* `subject_for(path)` reads the file and hashes it. It has no parameter for a
  digest. A missing file is refused (`IT_REFUSED_SUBJECT_ABSENT`), never skipped
  and never hashed as empty.
* The only accepted algorithm key is `sha256`. A digest object with `sha1`, a
  40-character Git object id, a short token, uppercase hex, a non-hex string or
  the wrong length is refused (`IT_REFUSED_SUBJECT_DIGEST_FORM`).
* A caller-supplied subject whose digest disagrees with the bytes is refused
  (`IT_REFUSED_SUBJECT_DIGEST_MISMATCH`) by `verify_subject`, and every
  verification recomputes every subject (`verify_subject_files`).
* Two subjects with one name are refused (`IT_REFUSED_DUPLICATE_SUBJECT`): one
  artefact has one digest in one statement.
* The predicate's `record` block must name a subject of the statement at that
  subject's digest. A predicate that names a record the statement did not hash is
  refused (`IT_REFUSED_SUBJECT_DIGEST_MISMATCH`).

**The commit token is not a digest.** The statement's subject digest is SHA-256
over the exact bytes. `evidence/a9/STATEMENTS.json` records a `sourceIdentity`
with a commit token and an audit of the measured inputs. That token records *when
the inputs were measured*; it is never placed in a subject digest, and a Git
object id in that position is refused. This is the two-identity contract of
`evidence/a7/RECEIPT.md` §11 applied to the envelope: the digest names the bytes,
not the commit that carries them.

Enforced by `test_subject_for_reads_the_bytes`,
`test_subject_for_has_no_caller_supplied_digest`,
`test_a_caller_supplied_digest_is_refused_when_it_disagrees`,
`test_a_git_object_id_is_not_a_content_digest`, `test_a_duplicate_subject_is_refused`
and `test_the_record_must_be_a_subject`.

## 4. The predicate registry

Every predicate type is versioned and is this project's own. A SLSA predicate
type is refused rather than borrowed: no statement here is genuine SLSA
provenance, and using the SLSA type for a project claim would misrepresent it
(`IT_REFUSED_PREDICATE_TYPE`, enforced by
`test_a_slsa_predicate_type_is_refused_not_borrowed`).

| predicate type | required fields | forbidden fields | carries |
|---|---|---|---|
| `https://openssl-rs.invalid/attestation/population/v1` | `population`, `state`, `declared`, `examined`, `omitted`, `membersRecorded`, `refusal`, `record` | `verified`, `resolved`, `absent`, `complete` | the A5 admission of one declared population |
| `https://openssl-rs.invalid/attestation/baseline-delta/v1` | `delta`, `dispositions`, `records`, `resolved`, `admitted`, `codes`, `record` | `verified`, `absent`, `complete`, `census` | the A7 disposition of one delta |
| `https://openssl-rs.invalid/attestation/sarif-emission/v1` | `sarifVersion`, `schema`, `runs`, `results`, `subset`, `record` | `census`, `complete`, `suppressions`, `baselineState`, `rank`, `fixes` | the shape of one SARIF 2.1.0 log or shard |
| `https://openssl-rs.invalid/attestation/instrument-qualification/v1` | `instrument`, `status`, `mode`, `control`, `record` | `resolved`, `absent`, `complete`, `census` | one instrument's registered qualification status |
| `https://openssl-rs.invalid/attestation/suppression/v1` | `suppression`, `disposition`, `declaredDisposition`, `target`, `authorisedScope`, `justification`, `reviewer`, `reviewerRecord`, `policyBasis`, `expiry`, `record` | `resolved`, `absent`, `complete`, `census` | one A6 suppression and its disposition |

A missing required field, a malformed field or a forbidden field is refused
(`IT_REFUSED_PREDICATE_FIELD`). A missing field is never defaulted: the predicate
either states the record's value or is not emitted. The SARIF type forbids
`suppressions`, `baselineState` and `rank` because the A1 profile never emits
them; admitting them would let a statement reintroduce a suppression the profile
excluded.

Enforced by `test_every_registered_type_declares_required_and_forbidden`,
`test_a_missing_required_field_is_refused`, `test_a_forbidden_field_is_refused`
and `test_an_unknown_predicate_type_is_refused`.

## 5. The no-upgrade rule

> A predicate may restate what its record admits. It may not assert a stronger
> state, a larger count or a tighter identity than the record states.

The builder reads the record's own values; the verifier re-reads the record and
compares every carried value. Each of the following is individually refused with
`IT_REFUSED_CLAIM_UPGRADE`:

| refused upgrade | the record says | the wrong conclusion it prevents |
|---|---|---|
| `COMPLETE` over a bounded population | `TRUNCATED_BOUNDED` | that every member was examined when the remainder is counted and unexamined |
| `RESOLVED` over a delta with none | `RESOLVED` count is 0 | that an absence is a resolution |
| a member census over an aggregate | `AGGREGATE_ONLY`, `membersRecorded: false` | that a total is a set of identified members |
| a census over a record with no member identities | `membersRecorded: false` | that a count can be audited member by member |
| a verified instrument | `RECORDED` in the instrument register | that a recorded control executed and passed in this session |
| an `ACTIVE` suppression with no expiry | no expiry and no unbounded claim | that a suppression is in force without a lifecycle |
| a `RESOLVED` or `absent` flag on a suppression | a suppression is a disposition | that a suppression removes a finding from the population |
| an evidence identity with no digest | an identity is a path and a digest | that an evidence reference binds bytes it never named |
| a shard presented as the parent | `subset: true`, `parentResultCount` recorded | that one shard is the whole population |
| a member list whose length is not the examined count | the record's examined count | that identities were omitted or invented |
| an `UNKNOWN` population attested as observed | admitted at `UNKNOWN` | that an unbounded observation is a bounded one |

The population builder also refuses to emit a statement for a population
admitted at `UNKNOWN`, `AGGREGATE_ONLY`, `DEFERRED` or `ABSENT`: such a predicate
would restate only that nothing is known, and the admission record — not an
attestation envelope — is the right vehicle for that state. A record that fails
its own admission is refused (`IT_REFUSED_RECORD_INADMISSIBLE`); an absent record
is refused (`IT_REFUSED_RECORD_ABSENT`). The admission check re-derives the
declaration from `evidence/a5/POPULATIONS.json`; where that declaration is absent
the recorded admission is used as-is, which is stated here as a limitation rather
than presented as a full re-derivation. The real tree carries the declaration,
and the re-derivation matched all 16 populations.

Enforced by `test_complete_over_truncated_is_refused`,
`test_resolved_over_none_is_refused`,
`test_a_census_over_an_aggregate_is_refused`,
`test_a_verified_instrument_over_recorded_is_refused`,
`test_an_expiry_free_active_suppression_is_refused`,
`test_an_evidence_identity_without_a_digest_is_refused`,
`test_an_unknown_population_cannot_be_attested`,
`test_an_inadmissible_population_is_refused` and
`test_a_refused_delta_cannot_be_admitted`.

## 6. The refusal table

Every code is stable and is cited verbatim by the tool, the tests, this document
and the receipt. The second column is the condition; the third is the wrong
conclusion the code prevents.

| code | condition | prevents |
|---|---|---|
| `IT_REFUSED_TYPE` | `_type` is not `https://in-toto.io/Statement/v1` | that another document type (a DSSE envelope, a v0.1 statement, a bare predicate) is read as a Statement v1 |
| `IT_REFUSED_MISSING_SUBJECT` | no subject, or a subject has no name | that an attestation about nothing is read as an attestation about an artefact |
| `IT_REFUSED_SUBJECT_ABSENT` | the subject file is not present | that a missing artefact is skipped or hashed as empty |
| `IT_REFUSED_SUBJECT_DIGEST_FORM` | an algorithm other than `sha256`, or a value that is not 64 lowercase hex characters | that a Git object id, a short token or a non-hex string is read as a content digest |
| `IT_REFUSED_SUBJECT_DIGEST_MISMATCH` | a digest differs from the bytes, or the predicate names a record the statement did not hash | that a statement names an artefact it has not hashed |
| `IT_REFUSED_DUPLICATE_SUBJECT` | two subjects with one name | that two digests for one artefact are both read as its identity |
| `IT_REFUSED_PREDICATE_TYPE` | an unregistered type, or a SLSA type for a non-SLSA statement | that a borrowed or unversioned type makes a project claim look external |
| `IT_REFUSED_PREDICATE_FIELD` | a required field is missing or malformed, or a forbidden field is present | that an absent field is defaulted, or that a field smuggles a second claim |
| `IT_REFUSED_CLAIM_UPGRADE` | the predicate asserts a state, count or identity the record does not admit | that a statement upgrades its record |
| `IT_REFUSED_RECORD_ABSENT` | the record the predicate restates is not present | that a predicate is built from no source at all |
| `IT_REFUSED_RECORD_INADMISSIBLE` | the source record fails its own A5/A6/A7 admission, or disagrees with the declaration it records | that a refused declaration is laundered into an admitted one |
| `IT_REFUSED_STATEMENT_MUTATED` | re-reading the emitted bytes does not reproduce the canonical statement, or the shape is not the emitted shape | that a reordered, re-spaced or re-shaped document is verified as the emitted statement |

## 7. The real statements

`evidence/a9/build_evidence.py` reads every digest and every predicate value from
the named record; nothing below was typed into the producer. The four statements
are those the records support.

| statement | subject | subject SHA-256 | predicate type | source record | asserted = record |
|---|---|---|---|---|---|
| `STATEMENTS/a1-sarif.json` (`d53bc4eb66f71bab7227fb9e590d151287a1d64b4446f8dd84b94ca8fef26329`) | `evidence/a1/SARIF.json` | `5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852` | `.../sarif-emission/v1` | `evidence/a1/SARIF.json` | 6 runs, 4,245 results, `subset: false` |
| `STATEMENTS/a5-admission.json` (`d17bb4c990893dc61ee06687a78b6c1b9a91b772e9dbefe233d1fa8b6c21e45f`) | `evidence/a5/ADMISSION.json` | `d4871ec97ae3a27b8ec820896e292429e44b4db4d11d2671a69b9dc0230ddc0a` | `.../population/v1` | `evidence/a5/ADMISSION.json#/populations/a1-sarif-results` | `COMPLETE`, examined 4,245, omitted 0 |
| `STATEMENTS/a7-delta.json` (`d4dfa5a3b374ffc4382964dcac61e8a785cfe7f833cbe5c7731a210c0fe7fba8`) | `evidence/a7/DELTA.json` | `0444a879bf4a0ddf5c50cffba7f51a5834b0fc4a1702d5190815de1f4470c8cf` | `.../baseline-delta/v1` | `evidence/a7/DELTA.json#/deltas/a3-fingerprint-migration` | 4,245 records, 0 `RESOLVED`, admitted |
| `STATEMENTS/a8-shard-000.json` (`ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582`) | `evidence/a8/SHARD-000.sarif` | `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed` | `.../sarif-emission/v1` | `evidence/a8/SHARD-000.sarif` | 6 runs, 4,245 results, `subset: true`, parent 4,245 |

What each statement **does** assert: that the exact bytes named hash to the
digest in `subject`, and that the named record admits precisely the carried
predicate values at the time of verification.

What each statement **does not** assert:

* the A1 statement does not assert that the findings are true, current, complete
  or severe, nor that 4,245 is the whole tree. It says this SARIF log has this
  shape and these bytes.
* the A5 statement does not assert that the `a1-sarif-results` population is the
  tree; `COMPLETE` is complete over the declared population. It does not assert
  that the other fifteen populations are admitted.
* the A7 statement does not assert a fix. The delta is admitted because the tool
  changed and every exact identity was reproduced with no absence claimed; its
  `RESOLVED` count is **0**, and the statement says 0.
* the A8 statement does not assert that one shard is the export or the
  population. It says `subset: true`, records the parent population count and
  the parent digest, and claims nothing about the parent's contents.

Enforced by `test_the_four_statements_exist_and_verify`,
`test_the_index_matches_the_statement_bytes`,
`test_each_asserted_state_is_the_record_state`,
`test_the_shard_is_not_presented_as_the_parent` and
`test_the_a7_statement_names_zero_resolutions`.

## 8. What the records refuse

Seven attempts are made by the producer on the real records, and each refusal
code is read from the tool, never typed into the producer. They are recorded in
`evidence/a9/STATEMENTS.json` under `notAttested`.

| record | selection | attempted | code |
|---|---|---|---|
| `evidence/a5/ADMISSION.json` | `t4-suppressions` | a census over an aggregate whose declaration is refused | `IT_REFUSED_RECORD_INADMISSIBLE` |
| `evidence/a5/ADMISSION.json` | `t11-satisfied-runs` | a census over an aggregate whose declaration is refused | `IT_REFUSED_RECORD_INADMISSIBLE` |
| `evidence/a5/ADMISSION.json` | `o11-interop-scripts` | a completeness claim over the HAZ-15 population admitted `UNKNOWN` | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/a5/ADMISSION.json` | `curl-residual-sites` | `COMPLETE` over a `TRUNCATED_BOUNDED` population (200 examined, 249 omitted) | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/a7/DELTA.json` | `a3-fingerprint-migration` | one `RESOLVED` over a delta with zero | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/etp3/instruments.json` | `timecop-supercop` | a verified claim over a `RECORDED`-only control | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence/a6/SUPPRESSIONS.json` | `t4-suppressions` | an `ACTIVE` suppression with no expiry (the record is `NON_ACTIONABLE`) | `IT_REFUSED_CLAIM_UPGRADE` |

No statement is emitted for these. The honest outcome is that an aggregate cannot
support a member census, the HAZ-15 population is `UNKNOWN`, and a `RECORDED`
control is not a verification. The admission, delta, instrument and suppression
records remain the authoritative statements of those facts.

## 9. The controls

`evidence/a9/CONTROLS.json` records 17 controls over the 12 codes: one per code,
and one per distinct upgrade. Each control mutates a real record's values in
memory and asserts its named code fires; a control that does not fire is a
producer assertion failure, not a warning.

| control | code |
|---|---|
| `missing-subject` | `IT_REFUSED_MISSING_SUBJECT` |
| `absent-file` | `IT_REFUSED_SUBJECT_ABSENT` |
| `git-object-id` | `IT_REFUSED_SUBJECT_DIGEST_FORM` |
| `digest-mismatch` | `IT_REFUSED_SUBJECT_DIGEST_MISMATCH` |
| `duplicate-subject` | `IT_REFUSED_DUPLICATE_SUBJECT` |
| `wrong-type` | `IT_REFUSED_TYPE` |
| `unknown-predicate-type` | `IT_REFUSED_PREDICATE_TYPE` |
| `missing-predicate-field` | `IT_REFUSED_PREDICATE_FIELD` |
| `complete-over-truncated` | `IT_REFUSED_CLAIM_UPGRADE` |
| `resolved-over-none` | `IT_REFUSED_CLAIM_UPGRADE` |
| `census-over-aggregate` | `IT_REFUSED_CLAIM_UPGRADE` |
| `verified-over-recorded` | `IT_REFUSED_CLAIM_UPGRADE` |
| `expiry-free-suppression` | `IT_REFUSED_CLAIM_UPGRADE` |
| `evidence-without-digest` | `IT_REFUSED_CLAIM_UPGRADE` |
| `absent-record` | `IT_REFUSED_RECORD_ABSENT` |
| `inadmissible-record` | `IT_REFUSED_RECORD_INADMISSIBLE` |
| `mutated-statement` | `IT_REFUSED_STATEMENT_MUTATED` |

Enforced by `test_every_control_fires_its_named_code`,
`test_every_refusal_code_has_a_control`, `test_each_upgrade_has_its_own_control`
and `test_the_recorded_controls_are_current`.

## 10. The boundary with A10

A bare in-toto Statement v1 is **not a signed attestation**. This item emits the
statement and nothing above it:

* the DSSE envelope (`payloadType`, `payload`, `signatures`) is A10's;
* the exact pre-authentication encoding (PAE) over the received bytes is A10's;
* `keyid` is an unauthenticated hint and is A10/A11's subject;
* signature verification and the trust root are A12's;
* role-bound authorisation, thresholds and transparency are A14–A17's.

A statement is therefore not a signature, not a proof, not a verification and not
admission. A verifier that wants an authenticated claim must obtain a DSSE
envelope over these exact bytes and verify it under an authorised key; that work
is not done here and is not implied by the statement's existence. This item does
not pre-empt A10: it emits no envelope, no PAE and no signature, and it refuses a
document whose `_type` is a DSSE envelope or an older in-toto statement type
(`IT_REFUSED_TYPE`).

## 11. Non-claims

* A statement is not evidence that its predicate is true; it is evidence that the
  named record admits the predicate and that the bytes hash to the subject.
* A statement is not a signature, a proof, a verification or an admission.
* A statement is not current beyond the bytes it names. If the record changes,
  verification fails; the statement is not updated in place.
* `COMPLETE` in a population predicate is complete over the declared population,
  not over the tree; `subset: true` is a subset, not a census; `admitted: true`
  on a delta is not a fix and not a resolution.
* No SLSA provenance statement is emitted, and no SLSA predicate type is used.
* No statement is emitted for an aggregate, an `UNKNOWN` population or a
  `RECORDED`-only instrument.
* The `sourceIdentity.commit` in the index is an audit of when the inputs were
  measured. It is not a subject digest and is not asserted by any statement.
* No independent reviewer has adjudicated the refusal-to-code mapping.

## 12. `NOT_RUN`

* **DSSE and PAE.** A10's envelope and pre-authentication encoding. No envelope is
  built or parsed here.
* **Signatures and trust.** A12's cryptographic verification, A14's role
  authorisation, A15's thresholds, A16's Sigstore bundle and A17's transparency
  and omission resistance.
* **Parser hardening.** A11's duplicate-key, encoding, size and algorithm
  downgrade rules. `decode` uses the standard parser and refuses non-canonical
  bytes; it makes no A11 claim.
* **Schema validation.** No in-toto JSON-Schema validator is present in the
  standard library; `python3 -m json.tool`, the structural checks and
  `verify_statement` ran instead.
* **A genuine SLSA statement.** None exists in the tree, and none was fabricated.
* **Multi-subject statements.** The four real statements have one subject each.
  The tool accepts several subjects (and refuses duplicates), but no multi-subject
  statement is emitted or tested against a real record.
* **BOUNDARY.** No caller/dependency-closure audit of the module and no
  independent review of the record readers. No sanitizer or model checker is
  applicable to a Python-only item; the negative controls are the tool's own.
* **SEAL.** No full forensic regeneration, no downstream replay and no release
  candidate assurance.

## 13. Reproducing the evidence

```
python3 evidence/a9/build_evidence.py --source-commit f1c5047a5
python3 forensics/tools/intoto.py verify evidence/a9/STATEMENTS/a1-sarif.json
python3 -m unittest forensics.tools.tests.test_intoto
```

The producer's source identity is supplied, not read live: when
`--source-commit` is absent and the index exists, the recorded commit is used, so
re-running at the commit that carries the record reproduces the bytes. Every
input is audited by path and SHA-256 in `STATEMENTS.json`. Two runs are
byte-identical, and the committed files match a fresh build (enforced by
`test_the_producer_is_deterministic` and
`test_the_committed_files_match_a_fresh_build`).
