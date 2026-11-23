# Long-term preservation — ETP-T13

**Status:** `PARTIAL`. The models, records, reader and controls exist and pass;
the acceptance criterion is met only inside this repository. Nothing is archived
outside it, no independent party has verified anything, and no signature or
timestamp exists. Those are stated as gaps, not as future promises.

**Candidate:** `S = 0eecec734` (`staging`). Every record in `evidence/etp-t13/`
is derived from that commit's blobs with `git cat-file`/`git show`, never from a
working-tree copy, so the evidence commit that adds these documents cannot
change the population it describes.

**Records:** `evidence/etp-t13/{IDENTITY-SYSTEMS,FORMATS,DIGESTS,ARCHIVAL}.json`,
all validated with `python3 -m json.tool`.

**Tool:** `forensics/tools/preservation.py` (Python 3.11, standard library only).
**Tests:** `forensics/tools/tests/test_preservation.py` (38 tests).

---

## 1. The acceptance criterion and how far it is met

> An external verifier should be able to reconstruct an old verdict using only
> archived, publicly accessible inputs, even if the original project environment
> no longer exists.

**Met inside this repository; not met as an external claim.**

What a third party can do today, from a checkout of the candidate:

| step | what it needs | recorded? |
|---|---|---|
| identify the repository-identity system | `git rev-parse --show-object-format`, or the `candidate.object_format` field | yes |
| re-derive a content digest and check it was named | the bytes and the recorded algorithm | yes, on every named record |
| read two versions of the schema family that changed | the two shapes in `read_versioned_document` | yes |
| check a digest renewal covers the same bytes | the renewal record and the archived bytes | yes, two records |
| detect archive corruption | the archive and its manifest | yes, four refusals plus two extra |
| rebuild the verifier | CPython 3.11 and the tool source | version requirement and tool digests recorded; interpreter binary not recorded |
| fetch a copy of the inputs from outside the project | an external archive | **no** |

The criterion fails as an *external* claim for three reasons, all recorded:

1. **Nothing is externally archived.** Every location in `ARCHIVAL.json` is a
   path inside this Git repository. Durability is exactly the durability of a
   copy of this repository.
2. **The ETP-6 package is a bundle, not an archive.** It is built from one
   commit, it is not tracked, it has not been deposited with an independent
   archive, and it carries no external review receipt. It also predates the
   ETP-T1…ETP-T13 records and does not contain them.
3. **The verifier's own reconstruction is incomplete.** The interpreter version
   and the tool digest are recorded; the interpreter binary digest, its libc and
   zlib identities, and a reproducible interpreter build recipe are not.

These are reported as the honest state of the item. No external review is
fabricated, and no durability is claimed.

---

## 2. Four identity systems, kept apart

The defect this item corrects is a conflation: SHA-256 was described as the
algorithm of Git object identity. It is not. Git object ids in this repository
are 40 hexadecimal characters because the configured object format is `sha1`;
SHA-256 is used for content, evidence and package digests. The four systems:

### 2.1 Repository object identity

| property | value |
|---|---|
| observed by | `git rev-parse --show-object-format` |
| format | `sha1` |
| object-id length | 40 hexadecimal characters |
| subject | a commit, tree, blob or tag inside one object database |
| computation | the object format's hash over a `"<type> <size>\0"` header plus the bytes |

The object id of a blob is therefore *not* a digest of the raw bytes. A worked
example is recorded in `IDENTITY-SYSTEMS.json`: for
`evidence/etp0/CLAIMS.json` the object id is
`971c810aa24d5aed3a9e5a213e0475267a727985` (40 hex) and the SHA-256 content
digest is a 64-hex value of the same bytes. They identify the same bytes and are
not interchangeable.

**Implication for a future format change.** A SHA-256 object format produces
64-hex object ids. The same bytes have different object ids in repositories with
different formats; a recorded 40-hex id does not name an object in a SHA-256
repository. A format change rewrites every object id, so recorded ids must be
re-derived and an old id must never be compared with a new one as if they were
one naming scheme. The format is read from the repository, never inferred from a
digest length.

### 2.2 Content digests

A digest over bytes, inside or outside the repository. Every record must name
the algorithm, in the field name (`source_sha256`) or in an adjacent
`digest_algorithm`/`hash_algorithm` field. The admitted set is listed in
`DIGESTS.json`; `sha256` is `PRIMARY`, `sha1` and `md5` are
`LEGACY_COMPATIBILITY_ONLY` and never admitted for a new commitment, and the
SHA-2/SHA-3/BLAKE2/SM3 members are `RENEWAL_CANDIDATE`.

The relationship to object identity is: none. A content digest can be computed
without Git; an object id cannot.

### 2.3 Signature and attestation algorithms

**Absent.** No DSSE envelope, Rekor entry, Sigstore bundle, OpenPGP signature or
trusted timestamp is recorded anywhere in this repository; Addendum B is a work
queue. Consequently no signature or attestation algorithm is admitted, recorded
or claimed. A record that names one while the system is absent is refused
(`PM_SIGNATURE_ALGORITHM_CLAIMED`). The absence of signatures is not evidence of
integrity, and this item does not create any.

### 2.4 Digest renewal

A new authenticated commitment over the *same archived bytes*, preserving the
old binding rather than replacing it. `DIGESTS.json` contains two renewal
records (SHA-256 → SHA-384 over `evidence/etp0/CLAIMS.json` and over
`forensics/etp6/verify.sh`), each stating the subject's object id separately
because that id is a different system.

A renewal cannot retroactively prove that an old signature was valid before a
compromise; it inherits trust in the old record's time and does not establish it;
and it cannot change a repository object id.

### 2.5 Separation rules and refusals

| rule | what it refuses |
|---|---|
| `PM_IDENTITY_OBJECT_FORMAT_MISMATCH` | a record naming an object format or object-id length the repository does not report |
| `PM_IDENTITY_OBJECT_FORMAT_UNKNOWN` | an object format this tool cannot interpret |
| `PM_IDENTITY_CONFLATION` | an object-id algorithm that is really a content-digest name, judged against the observed format |
| `PM_SIGNATURE_ALGORITHM_CLAIMED` | a signature system declared absent that nevertheless names algorithms |
| `PM_RENEWAL_BYTES_CHANGED` | a renewal whose old or new digest does not cover the archived bytes |

`validate` re-checks every record's `candidate` block against the live
repository: if the object format differs, every record is refused rather than
read as if its ids were comparable.

---

## 3. Format and schema registry

Every tracked schema is listed in `FORMATS.json` with identifier, version,
definition site, reader, attribution basis and unknown-version action.

| population | count |
|---|---|
| tracked `.json` documents | 3 123 (all parseable) |
| documents declaring a `schema` | 1 016 |
| distinct versioned schema identifiers | 524 |
| JSON Schema documents | 2 (1 versioned, 1 not) |
| code schema registries (`SCHEMAS = {…}`) | 3 (0 versioned) |
| unversioned schema definitions | 4 |
| identifiers with no definition in the tracked tree | 32 |
| schema documents with no reader | 1 |
| documents with no `schema` key | 2 107 |
| — of those, evidence records | 8 |
| identifiers using a `/part` marker | 2 |

The eight evidence documents that declare no schema, the one unversioned schema
document, the three unversioned code registries and the 32 identifiers with no
definition in the tree are **recorded as a migration population and not
edited**. No existing record was rewritten to add a version or an algorithm.

Unknown-version behaviour is stated per format and per identifier. A versioned
identifier is a different type, not a compatible extension; a reader must refuse
an unknown version rather than interpret it best-effort.

---

## 4. Migration

Two rules, both enforced with controls:

- `EXPLICIT_CONVERTER_PRESERVING_SOURCE` — a converter produces a new document
  under a new schema; the source is retained byte-for-byte and the target names
  the source digest;
- `FORWARD_ONLY_WITH_EXPLICIT_HISTORY` — every revision is retained in Git; a
  required-field addition needs either a converter with a version bump or a
  demonstration that every retained document is still accepted.

**Demonstration 1 — the claim schema's conversion.** `MIG-CLAIM-ETP0-TO-ETP1`
converts the ETP-0 inventory (`evidence/etp0/CLAIMS.json`) into the typed claim
set (`evidence/etp/claims.json`). The source is retained with one recorded
revision and its SHA-256; the target records `derived_from` with that same
digest; all 35 claim identities survive; and the verdict map
`SUPPORTED → ESTABLISHED`, `PARTIAL → PARTIAL`, `CONTRADICTED → CONTRADICTED`,
`SUPERSEDED → SUPERSEDED` is applied and checked. What is preserved is the
source bytes, the identities and the verdicts; what changes is the document
shape, which is why a converter and a new identifier exist.

**Demonstration 2 — the claim schema's own shape history.**
`MIG-CLAIM-SCHEMA-HISTORY` records each revision of
`evidence/etp/claim.schema.json`, the required-set differences between
revisions, and the acceptance of the retained claim document at each revision,
checked with the project's own `etp_claims.check_schema` rather than a weaker
second implementation. The required sets were tightened in nested definitions;
the retained document is still accepted by every later revision, so no converter
and no version bump are required — and that fact is demonstrated, not asserted.

`history_rewritten` is `false` in both records and is checked.

---

## 5. Cross-version reader

`read_versioned_document` dispatches on the exact version of a known family. The
family used to demonstrate it is
`openssl-rs/campaign/safe-c33/consumer-closure`, which has two tracked versions
with different shapes:

| version | documents | shape | reader |
|---|---|---|---|
| `v1` | 2 | flat closure record (`closure`, `compatibility`, `verdict`) | `_read_consumer_closure_v1` |
| `v2` | 210 | graph record (`graph`, `precision`, `refusals`, `mode`) | `_read_consumer_closure_v2` |

Both are read by shape-aware code and one tracked document of each is accepted
(`accepted_examples` in `FORMATS.json`). An unknown version — `v3` or `v1.5` —
is refused with `PM_SCHEMA_UNKNOWN_VERSION`, naming the versions that are
understood. It is never reinterpreted as `v1` or `v2`, and a `v2` document is not
accepted by the `v1` reader.

The demonstration establishes version-dispatch and refusal. It does not
establish that the two shapes are semantically equivalent, and it does not
migrate the two `v1` documents.

---

## 6. Digest agility

`DIGESTS.json` names the admitted set and measures the population.

| population | documents | occurrences |
|---|---|---|
| named digests | 2 405 | 345 091 |
| — SHA-256 | — | 345 039 |
| — SHA-1 (named as a content digest) | — | 52 |
| unnamed digests | 1 428 | 283 646 |
| unadmitted algorithms | 0 | 0 |
| explicit absence markers (`sha256` field holding `UNRESOLVED`…) | — | 11 278 |
| length mismatch (value cannot be the digest it names) | — | 2 |
| algorithm-named key with a non-digest value | — | 3 224 |
| **repository object ids (not digests)** | 365 | **53 088** |

The 53 088 object ids are separated by declaring key (`commit`, `head`,
`bound_commit`, `tree`, …). Length alone cannot separate them: a 64-hex value
may be a SHA-256 object id or a SHA-256 content digest, and only the key says
which. They are excluded from every digest population above.

The 1 428 documents with an unnamed digest are the migration population; they
are recorded, not edited. The most frequent unnamed keys are `span_hash`
(219 109), `span_current_hash` (47 004) and `source_root_hash` (2 113).

**Renewal record fields:** `subject`, `subject_content_sha256`,
`subject_object_id` (separate system), `old {algorithm, digest}`,
`new {algorithm, digest}`, `bytes_identical`, `renewal_reason`, `original_at`.
Both digests are recomputed over the archived bytes at build and at validate.
The control `renewal_differing_bytes_refused` appends one byte and requires
`PM_RENEWAL_BYTES_CHANGED`. The population is **not** migrated; the plan for
renewing every record is stated and `status` remains `PLAN_ONLY`.

---

## 7. Archival inventory

Per class: where it lives, whether it is inside this repository, whether it is
externally durable, and how much of it the ETP-6 bundle covers.

| class | tracked files | inside repository | externally durable | ETP-6 coverage |
|---|---|---|---|---|
| source | 898 | yes | no | partial |
| recipes | 57 | yes | no | partial |
| proofs | 40 | yes | no | partial |
| checkers | 281 | yes | no | partial |
| instrument identity | 26 | yes | no | partial |
| trust metadata | 24 | yes | no | partial |
| receipts | 40 | yes | no | partial |
| schemas | 5 | yes | no | partial |
| raw observations | 7 117 | yes | no | partial |
| external review record | 0 | — | no | none |

**Nothing is externally archived.** There are no external archives, no
persistent identifiers, and no externally durable class. The ETP-6 package is a
reproduction **bundle**: built from one commit, not tracked, not deposited, and
without an external review receipt. The `external review record` class has no
location at all, which is the one unarchived required class.

### 7.1 Archival corruption controls

`verify_archive_bytes` checks, in order: the manifest names its digest
algorithm; the archive decodes; each member is listed and matches; every listed
member is present. All controls run on a deterministic `tar.gz` fixture (sorted
members, zero mtime, uid/gid 0).

| control | corruption | refusal |
|---|---|---|
| `archive_roundtrip_accepted` | none (positive) | accepted, 3/3 members |
| `truncated_archive_refused` | archive cut in half | `PM_ARCHIVE_TRUNCATED` |
| `byte_flipped_member_refused` | one member's bytes changed | `PM_ARCHIVE_MEMBER_DIGEST` |
| `missing_member_refused` | one manifest member absent | `PM_ARCHIVE_MEMBER_MISSING` |
| `manifest_digest_disagreement_refused` | manifest digest replaced | `PM_ARCHIVE_MEMBER_DIGEST` |
| `unlisted_member_refused` | archive carries an extra member | `PM_ARCHIVE_MEMBER_UNLISTED` |

A byte-flipped member and a manifest that disagrees are the same observation
from the verifier's side: it knows only that the two disagree, not which was
altered. Both are refused; the control records which side was mutated. The
controls run against a fixture because the production ETP-6 archive is not
tracked in this repository.

---

## 8. Verifier reconstructability

| requirement | value |
|---|---|
| interpreter | CPython 3.11 (verified on CPython 3.11) |
| dependencies | standard library only: argparse, datetime, gzip, hashlib, io, json, platform, re, subprocess, sys, tarfile, tempfile, zlib, pathlib, typing |
| tool digest at candidate | recorded (`sha256_at_candidate`) |
| tool digest at the evidence commit | recorded (`sha256_of_working_tree`) |
| supporting verifier | `forensics/tools/etp6_verify.py` and `forensics/etp6/verify.sh` digests recorded |
| test suite | added by the evidence commit; not present at the candidate |

The two tool digests differ whenever the tool changes without a rebuild, and
recording both makes that visible instead of hiding it. `validate` re-derives the
record, so editing the tool without rebuilding is a drift refusal.

**Not recorded:** the interpreter binary's own digest; a reproducible interpreter
build recipe; the platform libc and zlib identities, although `gzip` and
`tarfile` delegate decompression to zlib. A byte-identical verifier executable is
therefore not guaranteed, only a verifier that runs from a standard CPython 3.11.

Reconstruction steps: install CPython 3.11; obtain
`forensics/tools/preservation.py` and compare its SHA-256 with the recorded
working-tree digest; run `--self-test`, then `validate`, against a checkout of
the candidate.

---

## 9. How to verify

```
python3 forensics/tools/preservation.py --self-test
python3 forensics/tools/preservation.py --determinism
python3 forensics/tools/preservation.py validate
python3 forensics/tools/preservation.py status raw_observations
python3 forensics/tools/preservation.py archive-check ARCHIVE MANIFEST
python3 forensics/tools/tests/test_preservation.py
```

Exit codes: `0` success and every control passed; `1` a refusal, drift or failed
control; `2` a refused invocation or missing record. `validate --strict` turns
the recorded open populations into refusals and exits 1; the open populations
include the unnamed-digest records, the documents declaring no schema, the
unversioned schema definitions, the unarchived `external review record` class
and the absent digest markers.

---

## 10. Non-claims

- No external archive, mirror or persistent identifier exists.
- No independent party has verified anything, and no external review receipt
  exists.
- The ETP-6 package is a bundle, not an archive, and does not contain the
  ETP-T1…ETP-T13 records.
- No signature, attestation, transparency-log entry or trusted timestamp exists;
  no signature algorithm is admitted.
- A digest renewal is a demonstration over two archived inputs, not a migration
  of the population.
- The cross-version reader establishes version dispatch and refusal, not
  semantic equivalence of the two shapes.
- Determining a digest algorithm from a value's length is not claimed; a 64-hex
  value is classified only by its declaring key.
- The archive corruption controls ran against a deterministic fixture, not the
  production bundle.
- The verifier's interpreter binary and its platform libraries are not recorded,
  so a byte-identical verifier executable is not established.
- This item does not make any claim about cryptographic strength, constant-time
  behaviour or the correctness of any OpenSSL behaviour.
