# ETP-T13 — long-term preservation: receipt

**Item:** ETP-T13, long-term preservation (open formats, schema migration, digest
agility, archival of source/recipes/proofs/checkers).
**Verdict:** `PARTIAL`. The models, records, reader and controls exist and pass;
the acceptance criterion is met only inside this repository.
**Date:** 2026-11-23.

---

## 1. Source identity and environment

| field | value |
|---|---|
| branch | `staging` |
| HEAD at start | `0eecec7347527dae03ff8e829709a305a44fc605` |
| worktree at start | **dirty**: `evidence/etp-t13/{FORMATS,DIGESTS,ARCHIVAL}.json` and `forensics/tools/preservation.py` modified on top of `wip(etp-t13)` `0eecec734`; treated as unverified and replaced by derived records |
| git object format | `sha1` (`git rev-parse --show-object-format`) |
| object-id length | 40 hexadecimal characters |
| `free -g`, available | 19 GiB |
| derived cap | `min(8, 19 − 16)` = **3g** (2g floor met) |
| court | existing `openssl-rs-court` container, cgroup ceiling 6 GiB set by an earlier session; `RLIMIT_DATA` enforced at **3 GiB** per process for every command here |
| Rust build | not run: `available` (19 GiB) is below the 24 GiB build threshold, and this item touches no Rust source |

Candidate for every record: `S = 0eecec734` (`staging`). Populations are read
from that commit's blobs, not from the working tree.

---

## 2. The defect corrected

The interrupted version described SHA-256 as the algorithm used for Git object
identity. Git object ids here are 40 hex characters (object format `sha1`);
SHA-256 is a content digest. The four identity systems are now separate in
`IDENTITY-SYSTEMS.json`, every record's `candidate` block names the repository
object format and length, and a record naming a different format is refused.

Worked evidence: for `evidence/etp0/CLAIMS.json` the object id is
`971c810aa24d5aed3a9e5a213e0475267a727985` (40 hex) and the SHA-256 content
digest is 64 hex of the same bytes. The object id is the `sha1` hash over
`"blob <size>\0"` plus the bytes; the content digest is SHA-256 over the raw
bytes.

---

## 3. Deliverables

| path | content |
|---|---|
| `docs/PRESERVATION.md` | four identity systems, registry, migration, agility, archival inventory, acceptance criterion and non-claims |
| `evidence/etp-t13/IDENTITY-SYSTEMS.json` | schema `openssl-rs/etp-t13/identity-systems/1` |
| `evidence/etp-t13/FORMATS.json` | schema `openssl-rs/etp-t13/formats/1` |
| `evidence/etp-t13/DIGESTS.json` | schema `openssl-rs/etp-t13/digests/1` |
| `evidence/etp-t13/ARCHIVAL.json` | schema `openssl-rs/etp-t13/archival/1` |
| `forensics/tools/preservation.py` | derivation, validation, reader, renewal and archive controls |
| `forensics/tools/tests/test_preservation.py` | 38 unittest tests |
| `evidence/etp-t13/RECEIPT.md` | this receipt |

All four JSON records pass `python3 -m json.tool`.

---

## 4. Format and schema populations

| population | count |
|---|---|
| tracked `.json` documents | 3 123, all parseable |
| documents declaring `schema` | 1 016 |
| distinct versioned identifiers | 524 |
| schema documents | 2 (1 versioned, 1 not) |
| code schema registries | 3 (0 versioned) |
| unversioned schema definitions | 4 |
| identifiers undefined in the tracked tree | 32 |
| schema documents without a reader | 1 |
| documents declaring no schema | 2 107 |
| — of those, evidence records | 8 |
| `/part` marker identifiers | 2 |

The 4 unversioned definitions and the 8 evidence documents are recorded as a
migration population; no record was edited to add a version.

---

## 5. Migration demonstration

**`MIG-CLAIM-ETP0-TO-ETP1`** (`EXPLICIT_CONVERTER_PRESERVING_SOURCE`): the ETP-0
claim inventory is retained with one recorded revision and its SHA-256; the typed
claim set records `derived_from` with that same digest; all 35 claim identities
survive (`ids_equal: true`); the verdict map `SUPPORTED→ESTABLISHED`,
`PARTIAL→PARTIAL`, `CONTRADICTED→CONTRADICTED`, `SUPERSEDED→SUPERSEDED` is applied
and checked (`mapped_verdicts_equal: true`). Preserved: source bytes, claim
identities, verdicts. Changed: document shape (hence the new identifier).

**`MIG-CLAIM-SCHEMA-HISTORY`** (`FORWARD_ONLY_WITH_EXPLICIT_HISTORY`): every
revision of `evidence/etp/claim.schema.json` is recorded with its required-set
differences, and the retained claim document is tested for acceptance at each
revision with the project's own `etp_claims.check_schema`. The retained document
is accepted by every later revision, so no converter and no version bump are
required — demonstrated, not asserted. `history_rewritten` is `false` in both.

---

## 6. Cross-version reader

`read_versioned_document` dispatches on the exact version of
`openssl-rs/campaign/safe-c33/consumer-closure`:

| version | documents | shape | accepted example |
|---|---|---|---|
| `v1` | 2 | flat closure | `forensics/memory-safety/campaign/safe-c33/atlas-refresh/consumer-closure-C2.json` |
| `v2` | 210 | graph | `court/freeze-b76/e7-b76c-after.json` |

Both are accepted by shape-aware readers. `v999` and `v1.5` are refused with
`PM_SCHEMA_UNKNOWN_VERSION`; a `v2` document is not read by the `v1` reader.

---

## 7. Digest populations

| population | documents | occurrences |
|---|---|---|
| named | 2 405 | 345 091 |
| — `sha256` | — | 345 039 |
| — `sha1` (content digest) | — | 52 |
| unnamed (migration population) | 1 428 | 283 646 |
| unadmitted | 0 | 0 |
| explicit absence markers | — | 11 278 |
| length mismatch | — | 2 |
| algorithm-named key, non-digest value | — | 3 224 |
| repository object ids (not digests) | 365 | 53 088 |

The 53 088 object ids are separated by declaring key (`commit` 39 599,
`head` 12 593, `bound_commit` 720, `tree` 45, …) and excluded from every digest
population. Length alone cannot separate a 64-hex object id from a 64-hex
content digest; only the key can.

Renewal records (2), each over identical archived bytes:
`evidence/etp0/CLAIMS.json` and `forensics/etp6/verify.sh`, SHA-256 → SHA-384.
The old binding is preserved, the object id is recorded as a separate system, and
the population is not migrated (`status: PLAN_ONLY`).

---

## 8. Archival classes

| class | tracked files | inside repository | externally durable | ETP-6 |
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

Nothing is externally archived; there are no external archives or persistent
identifiers. The ETP-6 package is a bundle (not an archive) built from one
commit, not tracked, not deposited, and without an external review receipt. The
`external review record` class has no location and is the one unarchived
required class.

---

## 9. Controls

**Self-test: 48 controls, 0 failed.** New controls here:

| control | rule observed |
|---|---|
| `object_format_match_accepted` | positive, `sha1`/40 |
| `object_format_mismatch_refused` | `PM_IDENTITY_OBJECT_FORMAT_MISMATCH` |
| `object_id_length_refused` | `PM_IDENTITY_OBJECT_FORMAT_MISMATCH` |
| `unknown_object_format_refused` | `PM_IDENTITY_OBJECT_FORMAT_UNKNOWN` |
| `conflation_refused` / `non_conflated_identity_accepted` | `PM_IDENTITY_CONFLATION` / positive |
| `absent_signature_algorithm_refused` | `PM_SIGNATURE_ALGORITHM_CLAIMED` |
| `renewal_identical_bytes_accepted` / `renewal_differing_bytes_refused` | positive / `PM_RENEWAL_BYTES_CHANGED` |
| `two_versions_accepted` / `unknown_version_refused` | positive / `PM_SCHEMA_UNKNOWN_VERSION` |
| `archive_roundtrip_accepted` | positive, 3/3 members |
| `truncated_archive_refused` | `PM_ARCHIVE_TRUNCATED` |
| `byte_flipped_member_refused` | `PM_ARCHIVE_MEMBER_DIGEST` |
| `missing_member_refused` | `PM_ARCHIVE_MEMBER_MISSING` |
| `manifest_digest_disagreement_refused` | `PM_ARCHIVE_MEMBER_DIGEST` |
| `unlisted_member_refused` | `PM_ARCHIVE_MEMBER_UNLISTED` |
| `every_admission_rule_has_a_control` | 19/19 admission rules covered |

The archive fixture is deterministic (sorted members, zero mtime, uid/gid 0), so
each corruption control changes exactly one thing. A byte-flipped member and a
manifest that disagrees are the same observation from the verifier's side; it
refuses the pair and records which side the control mutated.

**Unit tests: 38/38 pass** (`forensics/tools/tests/test_preservation.py`), using
`unittest`, including positive controls so a validator that refuses everything
cannot pass.

---

## 10. Gate output

```
$ python3 -m json.tool evidence/etp-t13/{FORMATS,DIGESTS,ARCHIVAL,IDENTITY-SYSTEMS}.json
JSON_OK  (4 files)

$ python3 forensics/tools/preservation.py --self-test
... 48 PASS ... SELFTEST=0

$ python3 forensics/tools/preservation.py --determinism
PASS determinism_formats:  ee9da7e475e58d2bdaf19f71db845b0ee0b3752883bad628eec384dc8227fc4f
PASS determinism_digests:  469d299f45fdf5115be0629d5b56b9d6b0634e3d1f6cea2be4c70a13a859fbf9
PASS determinism_archival: 9cb942af119b6204b02e431f80cdc6d7eae402c9a21748fe48aa0ba41f634df9
PASS determinism_identity: 1baf5088c1bf2aa6d320225f4c1a3dabdc094b516bc55ee5799b8f40dafc25a7
DET_EXIT=0

$ python3 forensics/tools/preservation.py validate
PASS evidence/etp-t13/FORMATS.json evidence/etp-t13/DIGESTS.json
     evidence/etp-t13/ARCHIVAL.json evidence/etp-t13/IDENTITY-SYSTEMS.json;
     48 controls passed; candidate 0eecec7347527dae03ff8e829709a305a44fc605;
     object format sha1
OPEN ... (recorded populations: 8 undeclared evidence documents, 1 unversioned
     schema document, 3 unversioned code registries, 32 undefined identifiers,
     1 428 unnamed-digest documents, 11 278 absence markers, 2 length
     mismatches, 1 unarchived class)
VALIDATE_EXIT=0

$ python3 forensics/tools/tests/test_preservation.py
Ran 38 tests ... OK
```

Tool identity: `forensics/tools/preservation.py` at the candidate is
`56785c4f…d7d69e`; the working-tree bytes that produced this evidence commit are
`d8b6f39c…a8538f`. Both are recorded, and `validate` re-derives the record, so
editing the tool without rebuilding is a drift refusal. Build cost: 61.6 s and
351 MiB peak; validation re-derives twice.

`cargo fmt`/`cargo clippy`/`cargo test` are not run: this item adds no Rust. The
Python tool is standard-library only and its suite is `unittest`.

---

## 11. Obligations

**Discharged (with a control):** object format read from the repository; records
carry and check the object format; conflation refused; absent signature system
refused if it names algorithms; renewal verified against archived bytes; unknown
schema version refused without nearest-match fallback; four archive corruption
classes refused; no external durability claimed; no existing record rewritten.

**Retained (recorded, not repaired):** 1 428 documents with unnamed digests;
11 278 absent digest markers; 8 evidence documents declaring no schema; 1
unversioned schema document; 3 unversioned code registries; 32 identifiers
undefined in the tracked tree; 1 schema document without a reader; 2 length
mismatches; 1 unarchived required class (`external review record`).

**Newly introduced:** none that is hidden. The new unsafe surface is zero (no
Rust); the new Python surface is the renewal and archive verifiers, each with
negative controls. Two limitations are stated rather than deferred silently: the
archive controls run on a fixture because the production bundle is untracked, and
the verifier's interpreter binary is not recorded.

---

## 12. Non-claims

- No external archive, mirror or persistent identifier exists; durability is the
  durability of a copy of this repository.
- No independent verification or external review receipt exists.
- The ETP-6 package is a bundle, not an archive, and predates these records.
- No signature, attestation, transparency entry or trusted timestamp exists.
- The digest renewal is a demonstration over two inputs, not a population
  migration.
- The cross-version reader establishes dispatch and refusal, not semantic
  equivalence.
- Length never determines a digest algorithm; only the declaring key separates
  an object id from a content digest.
- A byte-identical verifier executable is not established.
