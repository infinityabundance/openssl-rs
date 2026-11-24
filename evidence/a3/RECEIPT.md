# A3 receipt — one finding-identity model

## 1. Identity of this batch

| field | value |
|---|---|
| item | A3 (identity model: rule / logical / exact; no reuse across artefacts; conservative on collisions and code motion) |
| branch | `staging` |
| HEAD at the start | `1925780c55fcbb482197796d7f7e602bd2b09d21` (`a2: preserve what a finding came from, and reconcile the populations`) |
| worktree at the start | clean (`git status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | total 45, used 13, available **31** GiB |
| derived court cap | `min(8g, 31 − 16) = 8g`, above the 2 GiB floor |
| court | `docker/openssl-rs-court.sh` with `OPENSSL_RS_COURT_MEM=8g`, `OPENSSL_RS_COURT_MEMSWAP=8g`, image `openssl-rs-court-tools:1`, Python 3.11.2 |
| heavy commands | one at a time; no build; no `src/`, `docker/` or other item's evidence modified |

## 2. What was delivered

| path | role |
|---|---|
| `docs/FINDING-IDENTITY.md` | normative model, key-class registry, code-motion rule and table, collision rule, reuse prohibitions, consumer adoption, migration, non-claims |
| `forensics/tools/finding_identity.py` | the model: logical-key constructors, bindings, regions, three fingerprints, motion classification, collision report and attribution, reuse permits, positional identities |
| `forensics/tools/tests/test_finding_identity.py` | 47 controls (wire format, key classes, bindings, motion, collisions, reuse, positional identities, consumer adoption, hygiene) |
| `evidence/a3/build_evidence.py` | deterministic producer of the three JSON records; asserts every expectation |
| `evidence/a3/CODE-MOTION.json` | 8 cases, 17 variants, observed and expected identities |
| `evidence/a3/COLLISIONS.json` | collision fixture with refusals, and a full scan of the recorded A1 population |
| `evidence/a3/MIGRATION.json` | the reproduction of every recorded fingerprint under the generalised module |

Consumers changed to use the model:

| consumer | change |
|---|---|
| `forensics/tools/sarif_adapter.py` | every logical key is built by a registered constructor; all three fingerprints, artefact bindings, regions, exact-collision detection and result reconstruction come from the model; the private `_fingerprint`, `_region_key` and `_normalise_text` functions were removed |
| `forensics/tools/etp_claims.py` | canonical JSON is the model's; a cited `sha256` must have the model's content-digest form, refused as `EG_EVIDENCE_DIGEST_FORM` (a Git object id in a `sha256` field is a scope confusion) |
| `forensics/tools/closure_discipline.py` | content digests are the model's; row, site and target identities are built as the model's positional identities |
| `forensics/tools/freshness.py` | content digests are the model's; an artefact's own identity token is classified by the model's Git-object/content-digest rule |

`docs/ETP-CLAIM-ALGEBRA.md` gains the `EG_EVIDENCE_DIGEST_FORM` row for the new
claim-algebra refusal. The model's refusals are enumerated in
`docs/FINDING-IDENTITY.md` §9.

## 3. The model

`a1/v1`, with the recorded labels `a1Rule/v1`, `a1Logical/v1` and `a1Exact/v1` as
the wire format:

* rule: `SHA-256("a1-rule/v1" NUL ruleId)`.
* logical: `SHA-256("a1-logical/v1" NUL ruleId NUL logicalKey)`, where every key
  is built by one of 13 registered constructors. Each constructor declares the
  fields it uses and the location fields it excludes, and a test asserts that no
  registered class uses a line, column, offset, address, ordinal or call site.
* exact: `SHA-256("a1-exact/v1" NUL ruleId NUL logicalKey NUL subjectUri NUL
  digestScope ":" digest NUL regionKey)`, where the binding's scope fixes its
  algorithm (`artifact`, `source-tree` and `record` are SHA-256;
  `candidate-commit` is a Git object id) and the region is the most precise
  location the native data records.

Adoption is complete for the SARIF adapter. The other three consumers adopt the
identity vocabulary and computations that fit their domain and keep their own
domain rules; `docs/FINDING-IDENTITY.md` §7 states, per consumer, what cannot be
adopted and why. In particular:

* the claim algebra relates evidence to a claim under a closed claim type, not
  findings to one another, so it does not use `relate`;
* the closure discipline's upstream engine records only positional data, so a
  logical key cannot be derived without fabricating fields; the positional
  identities are marked `portable: false`;
* the freshness engine reasons over artefact versions in time, not finding
  occurrences, and its recorded registry digests depend on its
  `ensure_ascii=False` canonical JSON, which is left unchanged.

## 4. Code motion

The eight required cases, all produced by `classify_motion` and recorded with
fingerprints in `evidence/a3/CODE-MOTION.json`:

| case | logical | exact | why |
|---|---|---|---|
| moved within a file | preserved | new | no key field changes; the region (and, in a real edit, the tree digest) does |
| moved to another file | new for `path-symbol-*`; preserved for a location-independent key | new | `path` is a key field for the former; the subject artefact changes for both |
| renamed | new for `path-symbol-*`; preserved for a register id | new | `symbol` is a key field; a register id is the identity |
| reformatted | preserved | new | a source-tree digest is part of the exact identity |
| insertion above | preserved | new | lines are not key fields |
| deletion above | preserved | new | lines are not key fields |
| file split | new for `path-symbol-*`; preserved for a register id | new | `path` changes; the subject artefact changes |
| file merge | new for `path-symbol-*`; preserved for a register id | new | `path` changes; the subject artefact changes |

Conservatism is enforced, not documented only: preservation is recomputed from
the recorded fields, never asserted, and `require_preservation` refuses
`FI_REFUSED_UNJUSTIFIED_PRESERVATION` when the derived verdict changed the
logical identity. No rename, split or merge is inferred to be the same code.

## 5. Collision

A colliding fingerprint is a set. Every member is retained, counted and listed;
nothing is merged, deduplicated or dropped. Attribution is refused unless exactly
one member matches, including after a discriminator filters the set
(`FI_REFUSED_AMBIGUOUS_ATTRIBUTION`); a filter that leaves none is
`FI_REFUSED_UNKNOWN_IDENTITY`. This is the refusal that stops a claim resting on
the wrong finding.

Recorded population (`evidence/a1/SARIF.json`, 4 245 results, 6 runs):

| run | results | exact collisions | logical collisions | logical members |
|---|---|---|---|---|
| `evidence/b85c-adjudication.json` | 17 | 0 | 0 | 0 |
| `evidence/b85c-row-reconciliation.json` | 4 | 0 | 0 | 0 |
| `evidence/closure-curl-049.json` | 211 | 0 | 35 | 130 |
| `evidence/etp-t4/SAFETY-SITES.json` | 3 953 | 0 | 49 | 133 |
| `evidence/etp-t7/SECRETS.json` | 51 | 0 | 0 | 0 |
| `evidence/timing-bn-findings.json` | 9 | 0 | 0 | 0 |

84 logical groups, 263 members, all within a run; no additional group spans runs.
They come from two recorded coarseness properties: `path-symbol-*` excludes the
native `site`, and `dso-class-reason` excludes the function and call-site
addresses. The exact identities separate the members (0 exact collisions). The
model reports the groups and refuses sole attribution; it does not re-key them,
because adding a site or an address would make the key candidate-bound.
A1's emission counts exact collisions only and is not regenerated here.

## 6. Migration

`evidence/a1/SARIF.json` (SHA-256
`5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852`, 13 651 450
bytes) was produced by the pre-extraction adapter (SHA-256
`35614b905d18bea2090fcac9e8c86ddee08b470fd7ad0ccbca189d4a54929d5b`).

**Outcome: reproducible; no migration required.** Re-projecting the six native
records in memory under the generalised module and comparing at the same position:

| quantity | value |
|---|---|
| results compared | 4 245 |
| fingerprints compared | 12 735 |
| fingerprints reproduced | 12 735 |
| mismatches | 0 |
| recorded fingerprint-stream digest | equal to the recomputed stream digest |
| run-property differences excluding the adapter's own digest | none |
| result-object differences | none |

The only difference is `runs[*].properties.a1.adapter.sha256`, the producer's own
digest, over which no fingerprint is computed. The recorded artefact was read
only: no fingerprint was regenerated, no key class was changed (including the
64-bit recorded refutation key, documented as a preserved weakness), and the old
value is bound in `evidence/a3/MIGRATION.json`. Had any fingerprint changed, the
record's outcome would be `migrated` with the recorded and recomputed values per
mismatch.

## 7. Validation actually run

| check | command | result |
|---|---|---|
| compile | `python3 -m py_compile` on the five touched tools and the builder | OK |
| new controls | `python3 -m unittest discover -s forensics/tools/tests -p test_finding_identity.py` | **47 tests, 0 failures, 0 errors** |
| SARIF adapter controls | `… -p test_sarif_adapter.py` | 26 tests, 0 failures |
| claim-algebra controls | `… -p test_etp_claims.py` | 95 tests, 0 failures |
| closure-discipline controls | `… -p test_closure_discipline.py` | 34 tests, 0 failures; self-test 7 control groups passed |
| freshness controls | `… -p test_freshness.py` | 51 tests, 0 failures |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | **643 tests, 0 failures, 0 errors** |
| claim document | `python3 forensics/tools/etp_claims.py validate` | 35/35 claims, 0 refusals |
| documentation gate | `python3 forensics/tools/docs_consistency.py` | 20 hand-written claims agree; earned-trust constitution wired |
| SARIF emission | `python3 forensics/tools/sarif_adapter.py --out /tmp/sarif.json --print-summary` | 6 runs, 4 245 results, per-rule counts unchanged |
| evidence well-formedness | `python3 -m json.tool` on each of the three A3 records | PASS |
| determinism | the builder twice; the identity values and collision groups are order-stable | identical values |

Controls that are negative by construction: an ambiguous attribution without a
discriminator, a non-discriminating filter, a cross-artefact `same-occurrence`, a
cross-candidate `same-occurrence`, a logical permit used at exact scope, an
unstated relationship, a changed-key `code-motion`, an unjustified preservation,
a commit id recorded as a content digest, a tampered recorded fingerprint, a
`source-tree` binding with a Git object id, and a `candidate-commit` binding with a
SHA-256 digest.

## 8. Limits and obligations

* A4 owns location fidelity (macro expansion, monomorphisation, C ABI, indirect
  dispatch, optimised code). This batch does not add location precision and does
  not pre-empt A4.
* The marker `A1-ISA-BINARY-UNRESOLVED` already carries a binary region with an
  address; the model records it but makes no claim about instruction identity.
* The 84 recorded logical collisions are available for A5/A6/A7 consumers; whether
  a logical key should be narrowed for the unsafe-site and indirect-site classes is
  a key change and therefore a future migration, not a silent edit.
* The refutation key's 64-bit recorded domain is a preserved weakness; a future
  scheme version should use the full digest.
* The closure engine's upstream records are positional only; deriving a logical
  edge identity requires a change in `consumer_closure.py`, outside A3.
* BOUNDARY and SEAL evidence, independent review and any consumer-family
  graduation are `NOT_RUN`. This batch is BATCH-level evidence for the identity
  mechanism; it promotes no claim and graduates no family.
* A naive first-person scan over the new documents, module, builder and evidence
  reports no match. The only match in the batch is the literal list of forbidden
  words inside the hygiene control's regular expression; it is not first-person
  prose.

## 9. Non-claims

Identity is not state, truth, reachability or severity. A reproduced fingerprint
shows that the scheme is unchanged, not that a finding is correct. A zero
collision count describes one population. The migration check reads the A1
artefact; it does not re-audit the records it was projected from. No safety,
timing, cryptographic or compatibility result is claimed here.
