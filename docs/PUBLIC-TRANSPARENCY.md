# Public transparency — B4

**Status:** the classification gate, the classifier, one publishable bundle and
an independently executable verifier exist and are controlled. **Nothing has
been published.** No admitted public endpoint exists in this venue, and no party
outside this project has run the verifier, so publication and independent
verification are `NOT_RUN` and `PENDING`.

| field | value |
|---|---|
| item | B4 (`docs/ETP-ADDENDUM-B.md` §B.15, §B.16, §B.30) |
| base | `dc5855733` (`staging`) |
| policy and counts | `evidence/b4/CLASSIFICATION.json` |
| bundle | `evidence/b4/BUNDLE/` (8 members, 4 release-critical) |
| what would be published | `evidence/b4/PUBLICATION.json` |
| in-venue run | `evidence/b4/VERIFICATION.json` |
| controls | `evidence/b4/CONTROLS.json` |
| producer | `evidence/b4/build_evidence.py` |
| classifier | `forensics/tools/publication.py` |
| tests | `forensics/tools/tests/test_publication.py` |

---

## 1. What may be published, and why the default is not to publish

§B.16 treats every transparency-log submission as potentially permanent and
public. A mistake cannot be redacted afterwards, so the gate is designed the
other way round from a content filter: **nothing is publishable until a rule
classifies it as publishable, and a rule may never promote secret-bearing
material.**

The policy in `evidence/b4/CLASSIFICATION.json` has four decisions:

1. exact rules, which promote a named artefact to a named class;
2. private patterns, which classify secret-bearing paths and **outrank** every
   other rule, including an exact promotion;
3. scope rules, which classify each tracked evidence directory as internal;
4. the default, `UNCLASSIFIED`, which is not publishable and is refused.

The order is enforced in `classify_path` and stated in §4. The consequence is
that an artefact nobody classified cannot be published by accident, and a path
that matches a private pattern cannot be published by naming it.

Enforced by `PB_REFUSED_UNCLASSIFIED`, `PB_REFUSED_PRIVATE_MATERIAL`,
`PB_REFUSED_INTERNAL_MATERIAL`, `test_the_default_is_not_to_publish` and
`test_a_private_pattern_outranks_an_exact_public_rule`.

---

## 2. The four classes

| class | meaning | publication rule |
|---|---|---|
| `PUBLIC_RELEASE_CRITICAL` | a reader needs it to check the release claim itself: the statement, the admission record, the forward commitment | published; a bundle that omits a declared member is refused |
| `PUBLIC_SUPPORTING` | it explains or authenticates release-critical material but does not carry the claim: the envelope, the bundle description, the verifier | published alongside the release-critical set |
| `INTERNAL_NOT_PUBLISHED` | a tracked record that is not a publication candidate; this is the default for an evidence record | never published; a bundle that contains it is refused rather than redacted |
| `PRIVATE_NEVER_PUBLISHED` | secret-bearing material: keys, credentials, tokens, secret diagnostics, unredacted personal information, embargoed detail | never published and never copied into a bundle |

Enforced by `PB_REFUSED_CLASSIFICATION_MISMATCH`,
`PB_REFUSED_PRIVATE_MATERIAL`, `PB_REFUSED_INTERNAL_MATERIAL`,
`test_the_policy_defines_exactly_four_classes` and
`test_the_manifest_binds_every_member`.

---

## 3. The refusal rules

`build` refuses **and writes nothing** on any refusal. It checks the whole
member set in memory, then writes to a temporary sibling and renames it into
place; a refusal before that point leaves no directory behind.

`verify` takes a bundle directory, checks the manifest body against its own
digest, checks every member against the size and digest the manifest records,
refuses a file the manifest does not declare, scans each member for a private
reference and an absolute path, and reports whether the bundle is publishable.

Enforced by `test_unclassified_member_is_refused`,
`test_private_member_is_refused`, `test_internal_member_is_refused`,
`test_private_reference_is_refused`, `test_absolute_path_is_refused`,
`test_a_file_absent_from_the_manifest_is_refused`,
`test_omitting_release_critical_material_is_refused`,
`test_a_classification_disagreement_is_refused`,
`test_a_publication_without_a_service_is_refused`,
`test_an_external_claim_that_was_not_run_is_refused`.

### 3.1 The refusal table

| code | meaning |
|---|---|
| `PB_REFUSED_UNCLASSIFIED` | an artefact no policy rule classifies; unclassified material is never published |
| `PB_REFUSED_PRIVATE_MATERIAL` | an artefact classified `PRIVATE_NEVER_PUBLISHED`; it may not enter a bundle |
| `PB_REFUSED_INTERNAL_MATERIAL` | an artefact classified `INTERNAL_NOT_PUBLISHED`; only release-critical and supporting material may enter a bundle |
| `PB_REFUSED_PRIVATE_REFERENCE` | a member references a private scratch path, a home directory, a host-only path, a token or a credential |
| `PB_REFUSED_ABSOLUTE_PATH` | a member references an absolute path |
| `PB_REFUSED_UNBOUND_MEMBER` | a member's digest is absent from the manifest, does not match it, or the member is not declared at all |
| `PB_REFUSED_RELEASE_MEMBER_MISSING` | a bundle omits a member the policy declares release-critical |
| `PB_REFUSED_CLASSIFICATION_MISMATCH` | a manifest classification disagrees with the policy for the member's source |
| `PB_REFUSED_NO_PUBLIC_SERVICE` | a publication was claimed but no admitted public endpoint exists |
| `PB_REFUSED_EXTERNAL_NOT_RUN` | independent verification was claimed but no external party ran it |
| `PB_REFUSED_MANIFEST_INVALID` | the manifest is absent, does not parse, has a foreign schema, or its body does not hash to its own digest |
| `PB_REFUSED_IO` | an input could not be read |
| `PB_REFUSED_USAGE` | the command line was used incorrectly |

Every code has one live control in `evidence/b4/CONTROLS.json`, and each control
is marked `controlOnly`. Enforced by
`test_the_control_record_covers_every_code_and_every_control_fires`.

---

## 4. Precedence and the content scans

Classification precedence, in order:

1. a private pattern (basename or path glob), which **outranks** every other rule;
2. an exact rule for the path;
3. a scope rule (`under` a directory, or the top-level `depth` rule);
4. `UNCLASSIFIED`.

The private pattern is checked first so that a secret-bearing file can never be
promoted by naming it, whether the naming is in a scope or in an exact rule. The
scan is therefore safe under either: an artefact that looks private is private
before any exact rule is consulted. This is tested rather than assumed
(`test_a_private_pattern_outranks_an_exact_public_rule`).

Two content scans run over bundle members:

* a private-reference scan for a court scratch path, a home directory, a
  root-only path, a host temporary directory, a file URL, a bearer token, an
  authorization header, an AWS access-key identifier, a PEM private-key block
  and an assigned credential;
* an absolute-path scan for a JSON string value beginning at a conventional
  filesystem root.

A URL does not match the absolute-path rule, and a JSON pointer such as
`/records` does not either. The scanner's own pattern sources are assembled from
fragments, so neither the policy record nor the bundled verifier contains the
literal path it searches for; this is why the verifier passes its own scan.

Enforced by `PB_REFUSED_PRIVATE_REFERENCE`, `PB_REFUSED_ABSOLUTE_PATH`,
`test_no_member_carries_a_private_reference` and
`test_the_bundled_verifier_is_the_generated_program`.

---

## 5. The bundle and its manifest

`evidence/b4/BUNDLE/` contains **8 members**: five source artefacts and three
generated files.

| member | class | bytes | source |
|---|---|---:|---|
| `members/a9-statement-a8-shard-000.json` | `PUBLIC_RELEASE_CRITICAL` | 714 | `evidence/a9/STATEMENTS/a8-shard-000.json` |
| `members/a10-envelope-a8-shard-000.json` | `PUBLIC_SUPPORTING` | 1 130 | `evidence/a10/ENVELOPES/a8-shard-000.json` |
| `members/b1-publication.json` | `PUBLIC_RELEASE_CRITICAL` | 3 729 | `evidence/b1/PUBLICATION.json` |
| `members/a5-admission.json` | `PUBLIC_RELEASE_CRITICAL` | 5 120 | `evidence/a5/ADMISSION.json` |
| `members/a17-freeze-forward.json` | `PUBLIC_RELEASE_CRITICAL` | 4 948 | `evidence/a17/FREEZE-forward.json` |
| `README.md` | `PUBLIC_SUPPORTING` | 2 753 | generated |
| `verify.py` | `PUBLIC_SUPPORTING` | 10 378 | generated |
| `verify.sh` | `PUBLIC_SUPPORTING` | 299 | generated |

The B1 record is the test fixture **FIXTURE-1**: a six-leaf fixture log, a
test-only HMAC-SHA256 checkpoint key, and no Rekor entry. The A10 envelope is
test-only in the same way. Both labels are declared in the manifest
(`subjectLabels`) and checked to occur in the member.

`MANIFEST.json` is the bundle's identity:

| field | meaning |
|---|---|
| `members` | every member, sorted by path, with role, source path, class, byte count and SHA-256 |
| `policy` | the classification rules an outsider needs, with a `policyDigest` over that body |
| `releaseCriticalMembers` | the members that carry `PUBLIC_RELEASE_CRITICAL` |
| `subjectLabels` | the labels a member must contain |
| `entryPoint`, `entryShell`, `minimumInterpreter` | `verify.py`, `verify.sh`, `3.8` |
| `declarations` | `network: false`, `privateState: none`, `absolutePaths: false`, `unclassifiedMembers: 0` |
| `manifestDigest` | SHA-256 over the canonical body without this field |

Bundle manifest digest `fd46c75910d0a7b03b2b459894457813b204b037ca54d7d6a7777adb501ba24a`;
embedded policy digest `c2d91666a1823fe6424600380dbefc072d5b93bdcf8c84a999200029855acebd`.

The manifest is **not self-authenticating**. A rewritten bundle can carry a
rewritten manifest with a recomputed digest. The manifest detects an accidental
or casual edit, not a deliberate forgery; a recipient must obtain the digest
through a channel it trusts. Enforced by `PB_REFUSED_MANIFEST_INVALID`,
`PB_REFUSED_UNBOUND_MEMBER`, `test_the_manifest_binds_every_member` and
`test_a_tampered_manifest_digest_is_refused`.

---

## 6. The independently executable verifier

`BUNDLE/verify.py` imports nothing from this tree. It opens only files beside
itself, and it can be run from a fresh temporary directory with a stripped
environment:

```
env -i PATH=<interpreter dir> HOME=<tmp> TMPDIR=<tmp> LANG=C LC_ALL=C \
  python3 -I -S -B verify.py
```

It prints one JSON line and exits 0 only when every check passes. `verify.sh` is
a parameter-expansion wrapper with no external command. Enforced by `test_the_bundle_verifies_in_a_stripped_environment`
and `test_the_bundled_verifier_is_the_generated_program`.

Both programs are generated by the classifier, and the committed bytes are
checked against a fresh build, so a drifted verifier is a test failure rather
than a silent difference. Enforced by `test_the_committed_bundle_is_the_build_of_the_policy`.

### 6.1 The in-venue run

`evidence/b4/VERIFICATION.json` records two runs of the bundled verifier, each in
a fresh temporary directory outside the project tree, with an environment of
exactly `PATH`, `HOME`, `TMPDIR`, `LANG` and `LC_ALL` (one `PATH` entry, no
`PYTHONPATH`), under `-I -S -B`. Both exited 0 with identical output; the audit
reported **0 reads outside the copied bundle, the temporary root, the standard
library and the interpreter directory**, and **0 socket or HTTP audit events**.
The recorded outcome is `PUBLIC_BUNDLE_VERIFIED_IN_VENUE`.

**This is not external verification.** It was run by the producing project, in
the producing venue. `venue` is `in-venue`, `external` is `NOT_RUN`, and
`externalVerification` is `PENDING`. Enforced by `test_the_venue_record_is_not_an_external_result`.

---

## 7. The real classification counts

The measurement is over a **bounded population declared in the policy**: every
file tracked under `evidence/` at the pinned base commit `dc5855733`, plus the
bundle under test. Pinning the commit is what makes the measurement
reproducible; a record committed later does not change the population this run
measured. The producer's own records are not in the base tree and are excluded
by name; they are classified `INTERNAL_NOT_PUBLISHED` and refused if offered to
a bundle.

| measure | value |
|---|---:|
| declared population (tracked at base 924, plus 9 bundle files) | **933** |
| classified | **933** |
| unclassified | **0** |
| private (`PRIVATE_NEVER_PUBLISHED`) | **0** |
| `PUBLIC_RELEASE_CRITICAL` | 8 |
| `PUBLIC_SUPPORTING` | 6 |
| `INTERNAL_NOT_PUBLISHED` | 919 |
| individually classified (explicit rule) | 14 |
| classified by scope rule | 919 |
| artefacts containing a private reference in the inspected bytes | **377** |
| artefacts containing an absolute path in the inspected bytes | **13** |

The bound: at most 1 200 files, 65 536 bytes per member, 33 554 432 bytes in
total. The run considered 933 files, scanned 933, skipped none, read 22 466 845
bytes, and **truncated 233 members** at the per-member cap. The classification
uses the path and covers the whole population; the two reference counts are
**lower bounds** over the uninspected tail of those 233 members. The bound was
reached (`reached: true`) because of the per-member cap.

Two honest readings of these numbers:

* **0 unclassified is structural, not a finding.** The policy names every
  tracked evidence directory as internal, so no tracked evidence file falls
  through to the default. Unclassified can only arise for a path outside those
  scopes, and that is exactly what the refusal controls exercise.
* **377 records name a court scratch path.** Those records cannot be published
  as they stand, not because they are secret but because they reference a
  host-only directory. This is the concrete reason the default is not to
  publish.

Enforced by `test_the_classification_counts_are_internally_consistent`,
`test_the_scan_reports_its_bound` and `test_the_document_records_the_real_counts`.

---

## 8. The real result

| claim | state |
|---|---|
| an admitted public-good Rekor v2 profile | **not admitted**: no endpoint, no log key, no client, no witness, no network; the only pinned digest is the `linux/amd64` AWS asset, not the POSIX-backend server |
| `admittedService` | `false` |
| `endpoint` | `null` |
| `published` | `0` |
| `externalVerification` | `PENDING` |

In one line: `admittedService: false`, `endpoint: null`, `published: 0`,
`externalVerification: PENDING`.

`evidence/b4/PUBLICATION.json` states what *would* be published — the eight
members above, with their digests — and to which profile. It asserts no
publication. A publication claim is refused with
`PB_REFUSED_NO_PUBLIC_SERVICE`, and an external-verification claim with
`PB_REFUSED_EXTERNAL_NOT_RUN`. Enforced by `test_the_publication_record_claims_nothing`.

---

## 9. Controls

`evidence/b4/CONTROLS.json` records **14 controls, 14 fired**, covering all 13
refusal codes (two controls reach `PB_REFUSED_UNBOUND_MEMBER` by different
routes), plus one canary: the same synthetic bundle with no mutation is accepted
(`PB_OK`). Every control is `controlOnly`. A control that fires proves the
refusal works; it is not a finding about this tree.

The controls construct: an unclassified source, a private source, an internal
source, a member carrying a court scratch path, a member carrying an absolute
path, an undeclared file, a digest that does not bind, a source set that omits
release-critical material, a manifest that downgrades release-critical material,
a publication without a service, an external claim with no external party, an
unparseable manifest, a missing bundle, and a usage error.

Enforced by `test_the_control_record_covers_every_code_and_every_control_fires`.

---

## 10. Non-claims

* **A publishable bundle is not a published one.** The bundle is internally
  consistent and classified for publication; it sits in this repository.
* **A public transparency log does not make the claim true.** An entry records
  that a claim was made. It is not evidence that the claim holds.
* A manifest digest detects an accidental edit, not a deliberate forgery.
* The fixture log `FIXTURE-1` is not a Rekor log; its key is test-only; the A10
  envelope signature is test-only.
* A classification is a publication decision, not a safety, compatibility or
  cryptographic result.
* Zero private artefacts in the population is not proof that no secret exists in
  the tree: it is a measurement over the declared set, bounded per member.
* No external party has run the verifier.

---

## `NOT_RUN`

* **Publication itself.** No admitted public endpoint, log key, client, witness,
  trusted timestamp or network exists in this venue. `published` is `0`.
* **Independent verification by an outside party.** The verifier ran in the
  producing venue only; `external` is `NOT_RUN` and `externalVerification` is
  `PENDING`.
* **An admitted public-good Rekor v2 profile.** The profile is described, not
  admitted; B0 records every service claim as unestablished.
* **Inclusion in any transparency log**, a receipt from a log operator, a
  signed checkpoint from an admitted key, and a witness cosignature: none exists.
* **A sanitisation of the 377 records that name a court scratch path** and the 13
  that name an absolute path: they are counted, not rewritten.
* **The uninspected tail of the 233 truncated members**: not scanned for private
  references, so the counts are lower bounds.
* Independent review, `BOUNDARY`, `SEAL` and the Rust suite (no Rust source was
  modified).

---

## 11. Reproducing the evidence

```
python3 evidence/b4/build_evidence.py          # writes the four records and the bundle
python3 evidence/b4/build_evidence.py --check  # recomputes and compares the bytes
python3 forensics/tools/publication.py scan
python3 forensics/tools/publication.py verify --policy evidence/b4/CLASSIFICATION.json
python3 -m unittest forensics/tools/tests/test_publication.py
```

The producer reads no clock and no environment variable, and writes no absolute
path into a record; two runs are byte-identical.
