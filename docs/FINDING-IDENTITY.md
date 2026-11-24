# Finding identity: one model for rule, logical and exact identity

This document is the normative description of the project's finding-identity
model. The implementation is `forensics/tools/finding_identity.py`; the controls
are `forensics/tools/tests/test_finding_identity.py`; the evidence is
`evidence/a3/{CODE-MOTION,COLLISIONS,MIGRATION}.json`.

The model was extracted from the SARIF adapter, which was the first consumer to
need all three identities. The recorded fingerprint labels are therefore the SARIF
profile's labels, and they are the wire format of this single model rather than a
scheme private to SARIF. `docs/SARIF-PROFILE.md` §6 remains the normative document
for the emitted document; this document is normative for the identity scheme that
the profile, the claim algebra, the closure discipline and the freshness engine
all use.

## 1. The three identities

| identity | what it names | construction | occurs per |
|---|---|---|---|
| rule | the class of finding | `SHA-256("a1-rule/v1" NUL ruleId)` | many |
| logical | the same underlying finding across runs, candidates and code motion | `SHA-256("a1-logical/v1" NUL ruleId NUL logicalKey)` | one logical key per finding class |
| exact | this location, in this artefact, at this digest, for this candidate | `SHA-256("a1-exact/v1" NUL ruleId NUL logicalKey NUL subjectUri NUL digestScope ":" digest NUL regionKey)` | one per occurrence |

`MODEL_ID` is `a1/v1`. The recorded labels are `a1Rule/v1`, `a1Logical/v1` and
`a1Exact/v1`. Changing any of them invalidates every recorded fingerprint and
requires a migration; none was changed by the extraction, and §8 shows that the
recorded values are reproduced exactly.

The identities are not interchangeable. A rule match says two findings are of the
same class and nothing else. A logical match says two occurrences are the same
underlying finding. An exact match says one occurrence is the same occurrence.
None of them says that a finding is true, current, reachable or severe; identity
is not state (Article 1).

## 2. Logical keys

A logical key is built only by a registered constructor. The registry declares,
per class, the native fields the key uses, the location fields it excludes,
whether the key is location-independent, and whether it is keyed by prose.

| key class | fields | excluded | location-independent | prose-keyed |
|---|---|---|---|---|
| `register-entry` | `id` | path, line, column, byte offset, address | yes | no |
| `primitive-name` | `name` | DSO, byte offset, address, line | yes | no |
| `normalised-text` | `text` (whitespace-normalised) | ordinal | yes | yes |
| `path-symbol-status` | `path`, `symbol`, `status` | line, column, byte offset, address | no | no |
| `path-symbol-class` | `path`, `symbol`, `class` | line, column, byte offset, address | no | no |
| `literal` | `value` | count, members, line | yes | no |
| `stable-id` | `id` | line, ordinal, call site | yes | no |
| `obligation-boundary-receipt` | `obligation`, `boundary`, `receipt` | ordinal, line | yes | no |
| `dso-class-reason` | `dso`, `class`, `reason` | function, call site, byte offset, address | yes | no |
| `field-path` | `json_path` (a locator inside the native record) | count, sample, line | yes | no |
| `refutation` | `text` (whitespace-normalised), `digest_chars` | ordinal | yes | yes |
| `mechanism` | `name` | count, obligations, ordinal | yes | no |
| `obligation-decision` | `obligation`, `decision` | ledger pointer, line | yes | no |

A test asserts that no registered class uses a line, column, offset, address,
ordinal or call site as a key field, so a location can never enter a logical
identity by a later edit to a key constructor.

A prose-keyed class hashes the record's own text. Such an identity is stable
while the text is stable; it is not a claim that two differently worded refusals
are the same finding. A reworded refutation is a new logical identity, and the
model says so rather than normalising meaning away.

**Recorded weakness, preserved.** The `refutation` class takes `digest_chars` as
an explicit field because the recorded `a1/v1` scheme uses 16 hex characters (64
bits), not the full 256. That is a smaller collision domain than the other classes.
The recorded values are preserved (Article 10) and collision detection is
load-bearing for this class; a future scheme version should use the full digest,
which is a key change and therefore a migration.

## 3. Artefact bindings

The exact identity names an artefact binding: `(uri, digest, digestScope)`. The
scope fixes the algorithm, so a commit id is never read as file bytes.

| scope | required algorithm | meaning |
|---|---|---|
| `artifact` | `sha-256` | the digest is of the artefact's bytes |
| `source-tree` | `sha-256` | the digest is of the whole scanned source tree |
| `candidate-commit` | `sha1-git-object` | a Git object identifier, SHA-1 over the object header and bytes |
| `record` | `sha-256` | the digest is of the native record's own bytes |

A binding whose digest form does not match its declared scope is refused with
`FI_REFUSED_SCOPE_ALGORITHM`. The algorithm is named, not inferred from the scope
alone, so a consumer that needs per-file bytes cannot accept `source-tree`,
`candidate-commit` or `record` as one.

A region records only the most precise location the native data states: a source
line, a binary byte offset with its address, or the record's own JSON locator.
The precedence is fixed and a finding with no line is not given one. Location
semantics for macro expansion, monomorphisation, the C ABI, indirect dispatch and
optimised code belong to A4; this model does not invent a location.

## 4. Code motion

Preservation is derived by recomputing the key from recorded native fields, then
comparing the binding and the region. Nothing is assumed about the edit's intent.
When a key field changed, no equivalence between the old and new keys is recorded,
so the logical identity is new.

| case | representative class | logical identity | exact identity | relation |
|---|---|---|---|---|
| moved within a file | `register-entry` | preserved: the key is the register id | new: the region, and in a real edit the tree digest, changed | `location-moved` / `artefact-bytes-changed` |
| moved within a file | `path-symbol-status` | preserved: path, symbol and status unchanged | new | `location-moved` / `artefact-bytes-changed` |
| moved to another file | `path-symbol-status` | **new**: `path` is a key field | new | `logical-key-changed` |
| moved to another file | `register-entry` | preserved: the id did not change | new: the subject artefact changed | `subject-changed` |
| renamed | `path-symbol-status` | **new**: `symbol` is a key field | new | `logical-key-changed` |
| renamed | `register-entry` | preserved: the register id is the identity | new: the file bytes changed | `artefact-bytes-changed` |
| reformatted, no semantic change | both | preserved | new: a source-tree-scoped exact identity includes the tree digest | `artefact-bytes-changed` |
| insertion above | `path-symbol-status` | preserved: lines are not key fields | new: the region, and the tree digest in a real edit | `location-moved` / `artefact-bytes-changed` |
| deletion above | `path-symbol-status` | preserved | new | `location-moved` / `artefact-bytes-changed` |
| file split | `path-symbol-status` | **new**: `path` changed | new | `logical-key-changed` |
| file split | `register-entry` | preserved | new: the subject artefact changed | `subject-changed` |
| file merge | `path-symbol-status` | **new**: `path` changed | new | `logical-key-changed` |
| file merge | `register-entry` | preserved | new: the subject artefact changed | `subject-changed` |

`evidence/a3/CODE-MOTION.json` records all eight cases, 17 variants, each with
the before and after fingerprints, the observed relation and its declared
expectation. `classify_motion` produced every observed value.

The rule is conservative in both directions:

* **A preserved logical identity requires every key field to be unchanged.** No
  field is assumed immaterial, and no rename, split or merge is inferred to be
  the same code.
* **An exact identity is preserved only when rule, key, binding, scope, digest and
  region are all unchanged.** A reformat or an insertion above therefore changes
  the exact identity even when no line moved, because a source-tree digest
  changed.
* **An unjustified preservation is a refusal.** `require_preservation` raises
  `FI_REFUSED_UNJUSTIFIED_PRESERVATION` whenever the derived verdict says the
  logical identity changed.

The one place a rename does not change the logical identity is a
location-independent key such as a register entry id: the id is the identity, and
a function rename does not change it. That is not an assumption about the code;
it is what the recorded key says. The exact identity still changes.

## 5. Collision

Two members that share a fingerprint are a **set**. The model counts and lists
every group and every member, and no function merges, deduplicates or drops a
member.

`attribute(findings, fingerprint, kind, discriminator)` resolves a fingerprint to
exactly one member. It refuses with `FI_REFUSED_AMBIGUOUS_ATTRIBUTION` when more
than one member matches. A discriminator narrows a collision but does not by
itself make an attribution valid: after filtering, exactly one member must
remain. A filter that leaves two, or none, is refused as well.

This is the refusal condition required by A3: a claim may not be supported by a
finding that the identity does not single out. A logical collision is therefore a
refusal to attribute, never a merge.

**Observed collisions in the recorded population.** Recomputing every recorded
fingerprint over `evidence/a1/SARIF.json` (4 245 results, 6 runs) gives:

| run | results | exact collisions | logical collisions | logical members |
|---|---|---|---|---|
| `evidence/b85c-adjudication.json` | 17 | 0 | 0 | 0 |
| `evidence/b85c-row-reconciliation.json` | 4 | 0 | 0 | 0 |
| `evidence/closure-curl-049.json` | 211 | 0 | 35 | 130 |
| `evidence/etp-t4/SAFETY-SITES.json` | 3 953 | 0 | 49 | 133 |
| `evidence/etp-t7/SECRETS.json` | 51 | 0 | 0 | 0 |
| `evidence/timing-bn-findings.json` | 9 | 0 | 0 | 0 |

The 84 logical groups (263 members, all within a run; no additional group spans
runs) come from two coarseness properties of the recorded keys:

* `path-symbol-status` and `path-symbol-class` exclude the native `site`, so
  several unsafe sites in one function with the same status or class share a
  logical key.
* `dso-class-reason` excludes the function and call-site addresses, so several
  unresolved indirect transfers in one DSO with the same class and reason share a
  logical key.

The exact identities distinguish them (0 exact collisions), because the region
differs. The collisions are reported, not removed. Including the site or the
addresses in the logical key would make the identity candidate-bound and lose the
cross-build stability the key exists to provide; the model chooses stability and
treats the collision as a set. A consumer that needs a per-site conclusion uses
the exact identity or a discriminator; it may not use the logical identity alone.

A1's emission counts exact-occurrence collisions at
`runs[*].properties.a1.fingerprintCollisions`. It does not carry a logical
collision count, and A3 does not regenerate the A1 artefact to add one (§8).

## 6. Reuse prohibitions

`relate(left, right, relationship)` requires a relationship from a closed set and
returns a `Permit` that states what the relationship authorises.

| relationship | required | scope | authorises exact-scope reuse |
|---|---|---|---|
| `same-occurrence` | same rule, key, binding, digest, region and candidate | exact | yes |
| `same-logical-finding` | equal logical fingerprint | logical | no |
| `code-motion` | equal logical fingerprint, and the binding or region differs | logical | no |
| `distinct` | nothing; no relation claimed | none | no |

Refusals:

| code | condition |
|---|---|
| `FI_REFUSED_CROSS_ARTEFACT_REUSE` | an exact identity reused as the same occurrence of a different artefact binding |
| `FI_REFUSED_CROSS_CANDIDATE_REUSE` | an exact identity reused as the same occurrence at a different candidate |
| `FI_REFUSED_NOT_SAME_OCCURRENCE` | `same-occurrence` claimed for two different exact identities |
| `FI_REFUSED_NOT_SAME_LOGICAL_FINDING` | `same-logical-finding` claimed for two different logical identities |
| `FI_REFUSED_NOT_CODE_MOTION` | `code-motion` claimed without a logical match or without any movement |
| `FI_REFUSED_UNSTATED_RELATIONSHIP` | a fingerprint presented as evidence that two findings are the same, with no stated relationship |
| `FI_REFUSED_INSUFFICIENT_RELATIONSHIP` | an exact-scoped use of a permit that established only a logical relationship |

A logical match across candidates is permitted as an identity relation, and the
permit records `crossCandidate: true` and `authorisesExactReuse: false`. It is not
evidence that a finding was seen at the other candidate, and it cannot transfer a
suppression, discharge, receipt or cache entry.

A logical relationship between two artefacts does not authorise a conclusion
about either one. `authorise_about` refuses with
`FI_REFUSED_CROSS_ARTEFACT_REUSE` when a conclusion about a binding is drawn from
a finding bound elsewhere, including from a `same-logical-finding` permit. The
permit states that one logical finding appears in both artefacts; it does not
state that a conclusion about one occurrence transfers to the other, and a
conclusion about the second artefact needs that artefact's own exact identity. A
`distinct` permit authorises no conclusion at all
(`FI_REFUSED_INSUFFICIENT_RELATIONSHIP`).

## 7. Consumers

| consumer | uses the model for | cannot use it for | why |
|---|---|---|---|
| SARIF adapter (`sarif_adapter.py`) | every logical key, all three fingerprints, artefact bindings, regions, exact-collision detection, result reconstruction and verification | — | full adoption |
| claim algebra (`etp_claims.py`) | canonical JSON, and the digest-form rule that a `sha256` field must be a content digest, not a Git object id (`EG_EVIDENCE_DIGEST_FORM`) | `relate`, occurrence identities | A claim relates evidence records to a claim under a closed claim type; it does not relate finding occurrences. The claim's own `S`/`E` digest-identity axis and its `EG_MULTIPLE_CANDIDATES` rule are claim-schema concepts, not finding identities. |
| closure discipline (`closure_discipline.py`) | content digests, and the construction of row, site and target identities as *positional* identities (`portable: false`) | logical or exact finding identities for closure rows | `consumer_closure.py` records only positional data (file and line, function and call site, edge and target). Deriving a logical key from fields that were not recorded would fabricate an identity, which the model refuses to do. The fix belongs upstream in the closure engine, outside A3. |
| freshness engine (`freshness.py`) | content digests, and the token rule that distinguishes a Git object id from a content digest when an artefact's own identity is read from a structured field | occurrence identities | Freshness reasons about artefact versions over time, not about finding occurrences. Its reuse decision (`FR_HISTORY_CITED_AS_CURRENT`) is about time and artefact identity; the model supplies the identity vocabulary, not the temporal rule. Its canonical JSON deliberately keeps `ensure_ascii=False`, because its recorded registry digests depend on that encoding; the model's identity canonicaliser uses `ensure_ascii=True`. |

A consumer that needs a capability above the line it lacks must add it to the
model, not carry a private notion.

## 8. Migration of the recorded fingerprints

`evidence/a1/SARIF.json` was produced by the pre-extraction adapter (SHA-256
`35614b905d18bea2090fcac9e8c86ddee08b470fd7ad0ccbca189d4a54929d5b`) before the
identity model existed as a module.

**Outcome: reproducible, no migration required.** The adapter's private
fingerprint and region functions were replaced by the model's, the six native
records were re-projected in memory, and every result's three fingerprints were
compared with the recorded values at the same position:

| quantity | value |
|---|---|
| results compared | 4 245 |
| fingerprints compared | 12 735 |
| fingerprints reproduced | 12 735 |
| fingerprint mismatches | 0 |
| digest of the recorded fingerprint stream | equal to the recomputed stream |
| run-property differences (excluding the adapter's own digest) | none |
| result-object differences | none |

The only difference between the recorded document and a re-emission is
`runs[*].properties.a1.adapter.sha256`, which records the producer's own digest
and changed because the producer's source changed. No fingerprint is computed
over that field.

The recorded artefact was not rewritten. Its bytes remain the recorded bytes
(SHA-256 `5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852`),
and the recorded values remain the recorded values. `evidence/a3/MIGRATION.json`
binds the old adapter digest, the new module digest, the old and new fingerprint
streams, and the comparison. Had any fingerprint changed, the outcome would have
been `migrated` with the old value retained per fingerprint; the producer asserts
the reproduction rather than regenerating and declaring stability.

No key class was changed by the extraction, including the truncated refutation
key of §2.

## 9. Refusal codes

| code | condition |
|---|---|
| `FI_REFUSED_DIGEST_FORM` | a value is not a full-length sha-256 or Git object id |
| `FI_REFUSED_UNKNOWN_SCOPE` | the digest scope is not one of the four |
| `FI_REFUSED_SCOPE_ALGORITHM` | the digest form does not match the scope's algorithm |
| `FI_REFUSED_UNKNOWN_KEY_CLASS` | a logical key class is not registered |
| `FI_REFUSED_KEY_FIELD` | a required key or region field is absent, or a region kind is unknown |
| `FI_REFUSED_UNKNOWN_IDENTITY` | no member has the requested fingerprint, or a discriminator matches none |
| `FI_REFUSED_AMBIGUOUS_ATTRIBUTION` | more than one member matches the fingerprint |
| `FI_REFUSED_CROSS_ARTEFACT_REUSE` | an exact identity is reused across artefact bindings |
| `FI_REFUSED_CROSS_CANDIDATE_REUSE` | an exact identity is reused across candidates |
| `FI_REFUSED_NOT_SAME_OCCURRENCE` | `same-occurrence` claimed for different exact identities |
| `FI_REFUSED_NOT_SAME_LOGICAL_FINDING` | `same-logical-finding` claimed for different logical identities |
| `FI_REFUSED_NOT_CODE_MOTION` | `code-motion` claimed without a logical match or without movement |
| `FI_REFUSED_UNSTATED_RELATIONSHIP` | no stated relationship is given |
| `FI_REFUSED_INSUFFICIENT_RELATIONSHIP` | an exact-scoped use of a logical permit |
| `FI_REFUSED_UNJUSTIFIED_PRESERVATION` | preservation claimed where the derived verdict changed the logical identity |
| `FI_REFUSED_RECORDED_FINGERPRINT_MISMATCH` | a recorded fingerprint is not the model's recomputation from the result's own fields |

## 10. Non-claims

* A fingerprint establishes identity, not state. Equality does not establish that
  a finding is still true, still reachable or still open, and inequality does not
  establish that a defect was fixed.
* A zero collision count is a statement about one population, not about the hash
  function.
* The refutation key's 64-bit recorded domain is a weakness that is preserved and
  documented, not repaired silently.
* The model does not add location precision; A4 owns macro expansion,
  monomorphisation, the C ABI, indirect dispatch and optimised code.
* The model does not decide whether an artefact binding is the one that ran; the
  claim algebra and the freshness engine enforce identity binding for their own
  populations.
* Reproducing the recorded fingerprints does not validate the findings, the
  populations or the adjudications in the source records. It shows only that the
  identity scheme is unchanged.
* The closure discipline and the freshness engine adopt the model's identity
  vocabulary but retain their own domain rules; neither is claimed to be a full
  identity consumer.

## 11. Reproducing the evidence

```
python3 evidence/a3/build_evidence.py          # writes the three JSON records
python3 -m json.tool evidence/a3/CODE-MOTION.json
python3 -m json.tool evidence/a3/COLLISIONS.json
python3 -m json.tool evidence/a3/MIGRATION.json
python3 -m unittest discover -s forensics/tools/tests -p test_finding_identity.py
```

The builder asserts every code-motion expectation, every collision refusal and
the full fingerprint reproduction; a mismatch stops it rather than being written.
