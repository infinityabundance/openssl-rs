# Identity triage — ETP-T9 follow-up

*Normative description of `forensics/tools/freshness.py triage`,
`evidence/etp-t9/IDENTITY-TRIAGE.json` and the release-gate rules that consume
them. Addendum to `evidence/etp-t9/RECEIPT.md`; the receipt itself is not
rewritten.*

An evidence artefact's freshness is decided against the tree it names. The
T9 registry (`evidence/etp-t9/DEPENDENCIES.json`, recorded at `26c127262`)
derives 331 artefacts and reads an identity for 100 of them: 77 structured, 23
prose. **231 name no identity.** T9 reported that count as a refusal
(`FR_IDENTITY_UNKNOWN`) in the tree sweep, but the refusal was not decisive: an
artefact with modelled dependencies was still reported `UNAFFECTED` in
change-set mode, and nothing stopped a claim that cited such an artefact from
passing the release gate.

This follow-up classifies every one of the 231, records the class in a derived
document, and makes the class gate both the freshness engine and the release
gate. No artefact is given an identity it does not support: the class
`UNCERTIFIABLE` is a result, not a failure to classify.

## 1. The four classes

`forensics/tools/freshness.py triage` derives the class from the artefact's own
content, its Git history, and the commit it resolves at. Rules are tried in the
order below; the first that applies wins, and the rule that fired is recorded
per artefact.

| class | rule | what is checked |
|---|---|---|
| `DECLARED` | `declared-identity-field` | One of the exact field paths in `TRIAGE_IDENTITY_FIELDS` (`head`, `identity.head`, `identity.source.head`, `source.head`, `candidate.head`, `candidate_identity.source_head`, `source_identity.head`, `source_identity.repository_head`, `source_identity.repository_head_start`, `head_at_start`, `repository_head_at_measurement`, `identity.analysis_candidate`, `analysis_candidate`, `source_candidate`) holds a hex value that resolves to a commit which is an ancestor of the derivation commit. When several distinct trees are declared, the earliest is adopted, because a wider range can only over-invalidate; every one stays visible in `identity.all`. |
| `DECLARED` (history) | `declared-prose-frozen-at` | A Markdown record in its first 80 lines says `frozen … at <commit>` and the commit resolves. The record is `HISTORICAL`, not current. |
| `DERIVED` | `digest-bound-freeze-record` | The artefact's `freeze` field names a tracked record whose blob digest equals the artefact's `freeze_sha256`, and that record declares exactly one tree. The derivation is a digest check plus a declaration, not proximity. |
| `DERIVED` | `tracked-input-at-head` | The artefact is a harness input or schema (`courts/**` or `forensics/tools/**` with `.c`, `.h`, `.sh`, `.py`, `.pem`, `.txt`, or any `*.schema.json`). Such a file is not a measurement: its truth is that these bytes are in the tree, so its identity is the tree the registry was recorded at. The rule is definitional and is marked `heuristic: true`; a later change to its bytes is `FR_EVIDENCE_SUPERSEDED`. |
| `HISTORICAL` | `introduced-at-single-commit` | The path has exactly one commit in its history, so its current bytes are exactly the bytes introduced at that commit. The commit is the identity and the artefact is a record of that moment. |
| `UNCERTIFIABLE` | one of the causes in §4 | No identity can be established or honestly declared. |

Precedence detail: a declared tree that the artefact itself qualifies (a
`worktree` field recording a dirty tree, a `build_relevant_clean: false`, or a
non-empty `build_relevant_status`) is refused as `U7` **before** it becomes a
`DECLARED` identity. `build_relevant_clean: true` is accepted as the
certification the campaign records for exactly that purpose, which is why the
PFP-0 records are `DECLARED` and the PFP-1 ctgrind record is not.

## 2. Counts

| class | count |
|---|---|
| `DECLARED` | 13 |
| `DERIVED` | 21 (19 `tracked-input-at-head`, 2 `digest-bound-freeze-record`) |
| `HISTORICAL` | 79 (78 `introduced-at-single-commit`, 1 declared prose record) |
| `UNCERTIFIABLE` | 118 |
| **total** | **231** |

`python3 forensics/tools/freshness.py triage` re-derives the document at the
registry's own commit and compares it byte-for-byte with the committed
`IDENTITY-TRIAGE.json`. The record is bound to
`registry_recorded_at_commit = 26c127262`; a triage for another registry, a
missing record, or a class outside the closed set is a refusal
(`FR_TRIAGE_STALE`, `FR_TRIAGE_MISSING`, `FR_TRIAGE_SCHEMA`).

## 3. Declared and derived identities

The 13 declared artefacts, named exactly as the field they declare:

| artefact | field | commit |
|---|---|---|
| `evidence/b78-l7-replay.json` | `repository_head_at_measurement` | `5628e8d6710e` |
| `evidence/b81-review-x509-surface.json` | `candidate.head` | `2ee194228ea2` |
| `evidence/b84-l4-binding.json` | `head` | `79a09f778c4d` |
| `evidence/b85-l4-binding.json` | `head` | `2170f55b4cec` |
| `evidence/b85c-row-reconciliation.json` | `source_candidate` | `17042ccf29bc` |
| `evidence/element7-curl-049-closedset-receipt.json` | `source_identity.repository_head_start` | `377e66a85048` |
| `evidence/element7-curl-049-rest-receipt.json` | `source_identity.repository_head_start` | `230d2a13e983` |
| `evidence/etp-t2/HAZARDS.json` | `identity.analysis_candidate` | `6da02233f941` |
| `evidence/etp-t3/REFINEMENT.json` | `source_identity.head` | `794a7c5491e6` |
| `evidence/haz-15/observables.json` | `identity.head` | `5750ac15008e` |
| `evidence/l7-replay-049.json` | `repository_head_at_measurement` | `8eaefe6268a1` |
| `evidence/performance-frontier/campaigns/PFP-0/build-identity.json` | `source.head` | `c9a0fdd58429` |
| `evidence/performance-frontier/campaigns/PFP-0/results.json` | `identity.source.head` | `c9a0fdd58429` |

The 21 derived identities are 19 harness inputs and schemas (the interop
scripts, `ct_primitives_probe.c`, the two RSA fixtures, the phase-8 expectation
files, `run_bench_api.sh`, `build_reproducibility.sh`, `claim.schema.json`, and
the downstream-result schema) plus two ledger records whose freeze record is
tracked and digest-bound:

| artefact | derivation | commit |
|---|---|---|
| `evidence/sshd-artifact-ledger.json` | `freeze: court/freeze-b73/FREEZE-b73.json` | `15bebabc90e1` |
| `evidence/sshd-artifact-ledger-b76.json` | `freeze: court/freeze-b76/FREEZE-b76.json` | `0238c6e4adbc` |

The other eighteen ssh/sshd ledger records name a freeze record that either is
not tracked (`court/` is ignored; only b73 and b76 were force-added) or no
longer matches the ledger's `freeze_sha256`. They are `UNCERTIFIABLE` (`U5`),
not derived: the recorded digest cannot be checked against the tree, and
`source_root_hash_rule` is null in every one, so the source-root digest cannot be
recomputed either.

## 4. The residual `UNCERTIFIABLE` population

118 artefacts, by cause:

| cause | count | what it is | what would make it certifiable |
|---|---|---|---|
| `U1` multi-commit-no-declaration | 87 | modified in more than one commit and names no tree: 59 under `artifacts/`, 20 under `courts/`, 6 under `evidence/`, 2 under `forensics/`. The modifying commits are provenance, not identity, and the current bytes are not the bytes at the introducing commit. | a declared identity commit in the artefact, or a single-commit history |
| `U2` candidate-name-only | 9 | the Phase-25 summary and the seven CVE replays declare `candidate_identity: "openssl-rs 0.0.27 (reconstructing openssl-3.6.4-production)"`. A version is not a tree, and tracked records bind `0.0.27` to at least two different heads (`67ae7f8e9` in `state.json`, `8751ea75f` in `atlas-refresh/candidate.json`), so the name does not determine a commit. | a commit field, or a tracked mapping from the candidate name to the tree measured |
| `U5` uncheckable-source-binding | 18 | the ssh/sshd ledger records: `source_root_hash` with a null rule, and a freeze record that is untracked (b80, b81, b82, b83, b84, b85) or digest-mismatched (b78, b79, b85c). | a non-null hash rule and a tracked, digest-matching freeze record |
| `U6` build-output-no-identity | 2 | `artifacts/phase2/install/lib/libcrypto.so.3` and `libssl.so.3`: build outputs with no build-identity record, and 492 and 136 commits of history respectively. | a build-identity record naming the source commit and the output digest |
| `U7` self-qualified-declaration | 2 | `evidence/haz-16/CLASSIFICATION.json` declares `identity.head` and says the worktree was dirty at generation; `PFP-1/ctgrind/summary.json` declares `source.head` and `source.worktree = "dirty: PFP-1 patch applied"`. Neither claims to correspond to the commit it names. | a clean-tree declaration, or the base commit plus the patch digest |

The largest single cause is `U1`. It is not a defect in the classifier: a record
that was revised across N commits has no tree that explains its current bytes,
and the last-modifying commit is exactly the provenance the T9 engine already
refuses to promote to an identity.

### Outside the 231

Three further artefacts are recorded by the registry with an identity that is
**not a commit of this repository**: `evidence/etp-t6/RECEIPT.md` (`48a229cea`,
the rustc commit), `evidence/timing-tools-inventory.json`
(`dc269651fb25`, the pinned dudect commit) and
`courts/phase17/downstream/openssh/cve-2026-123158/result.json`
(`4353fdc43ef6`, which does not resolve). The registry's extractor read a
`commit` leaf that names another repository's tree. They are outside the 231
because the registry believes they are bound, but the engine reports them
`FR_IDENTITY_UNKNOWN` in the tree sweep and none is cited by a claim. They
remain a registry-extraction defect: fixing them requires either a narrower
identity precedence or a triage scope extended to non-resolving identities.

## 5. What the engine now does

`forensics/tools/freshness.py check` loads the triage as a declared overlay
(`triaged_registry` copies the registry; the committed registry is never
mutated):

- `DECLARED` and `DERIVED` identities are used by the tree sweep's `base_for`,
  so those artefacts are evaluated from their own tree instead of
  `FR_IDENTITY_UNKNOWN`.
- `HISTORICAL` artefacts are `HISTORY` in both modes, are excluded from current
  claims, and a current claim that cites one is refused
  (`FR_HISTORY_CITED_AS_CURRENT`).
- `UNCERTIFIABLE` artefacts are `UNRESOLVED` with `FR_IDENTITY_UNCERTIFIABLE`
  in **both** modes. In change-set mode this is a pre-existing condition and does
  not gate the change set (T9 §2.5), but the artefact is no longer `UNAFFECTED`
  and its citing claims are no longer `verified_current`. Inheritance from an
  upstream artefact is also refused for an `UNCERTIFIABLE` artefact: a borrowed
  tree would certify what the triage says cannot be certified.

Observed tree sweep at `87d0868ef` with the triage:

| | before (T9) | after |
|---|---|---|
| `HISTORY` | 2 | 81 |
| `INVALIDATED` | 90 | 92 |
| `UNAFFECTED` | 10 | 31 |
| `UNRESOLVED` | 229 | 127 (118 `FR_IDENTITY_UNCERTIFIABLE`, 6 dependency-unresolved, 3 `FR_IDENTITY_UNKNOWN`) |
| refusals | 340 | 265 |
| claims `not_verified_current` | 15 | 26 |

The commitment history record (`evidence/etp-t9/HISTORY-RUNS.json`) was
regenerated with the triage applied and re-derives byte-for-byte
(`diff --runs` `PASS`); the evidence-only run still invalidates nothing and
refuses nothing.

## 6. What the release gate now refuses

`forensics/tools/release_gate.py` loads the triage as its own required item and
refuses a current claim whose required evidence is `UNCERTIFIABLE`
(`RG_CLAIM_UNCERTIFIABLE_EVIDENCE`) or `HISTORICAL`
(`RG_CLAIM_HISTORICAL_EVIDENCE`), naming the artefact. A `PARTIAL` claim is a
current assertion and is included; a claim already `WITHDRAWN`, `SUPERSEDED`,
`REFUTED` or `CONTRADICTED` is refused once, by its verdict, and a
`NOT_ESTABLISHED` claim asserts that the property is not established, so its
evidence supports no positive conclusion. A missing triage is
`RG_TRIAGE_MISSING`; a triage bound to another registry, with a class outside
the closed set, or with inconsistent counts is `RG_TRIAGE_STALE`.

On the committed claim set (35 claims), the claim item now returns 34 refusals:
4 pre-existing `RG_CLAIM_CONTRADICTED` (`ETP0-CLM-004`, `-005`, `-030`, `-032`),
19 `RG_CLAIM_UNCERTIFIABLE_EVIDENCE` and 11 `RG_CLAIM_HISTORICAL_EVIDENCE`. The
20 distinct current claims affected:

| rule | claims |
|---|---|
| `RG_CLAIM_UNCERTIFIABLE_EVIDENCE` | `ETP0-CLM-006`, `-007`, `-015`, `-017`, `-020`, `-021`, `-023`, `-025`, `-028`, `-034`, `-035` |
| `RG_CLAIM_HISTORICAL_EVIDENCE` | `ETP0-CLM-011`, `-016`, `-018`, `-019`, `-022`, `-023`, `-024`, `-026`, `-027`, `-029` |

### One claim refused

```
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-034/artifacts/phase25/summary.json:
  claim ETP0-CLM-034 (ESTABLISHED) requires artifacts/phase25/summary.json, which
  has no certifiable identity: U2 candidate-name-only -- the only declared
  identity is the candidate name 'openssl-rs 0.0.27 (reconstructing
  openssl-3.6.4-production)', and the repository binds that name to more than one
  tree, so it does not determine a commit
```

The Phase-25 seal record is the most consequential single refusal: it is
`ESTABLISHED`, and it names the candidate by version only. The same gate refuses
`ETP0-CLM-029` for a historical artefact
(`forensics/memory-safety/campaign/safe-c33/CLOSURE.md`, a frozen inventory at
`67ae7f8e9` that its own header declares superseded) under
`RG_CLAIM_HISTORICAL_EVIDENCE`.

### One claim unaffected

```
ETP0-CLM-031  ESTABLISHED  evidence: evidence/b85c-row-reconciliation.json
```

`ETP0-CLM-031` cites one artefact, and the triage classifies it `DECLARED` at
`17042ccf29bc` (field `source_candidate`). Neither new rule fires.
`ETP0-CLM-009` (`PARTIAL`, the CT primitives probe and the two RSA fixtures) and
`ETP0-CLM-012` (`PARTIAL`, `build_reproducibility.sh`) are likewise unaffected:
their triaged evidence is `DERIVED`.

## 7. What this does not close

- **118 artefacts remain `UNCERTIFIABLE`**, and 11 current claims rest on them.
  The largest group is 87 records revised across several commits; naming any of
  those revisions as "the" tree would be a fabricated identity. They become
  certifiable only if their producers record the source commit (a build-identity
  record, a `source_identity.head`, or a freeze record that stays tracked and
  digest-matched).
- **The two `.so` artefacts** cited by `ETP0-CLM-035` are build outputs with no
  build-identity record. Their source tree is not recoverable from the tree.
- **The 18 ledger records** depend on freeze records that are untracked or have
  drifted. `court/` is ignored, so a ledger can bind a working-tree file that
  does not exist in any checkout; six freeze records (b80 to b85) are untracked
  across twelve ledger artefacts, and three (b78, b79, b85c) no longer match the
  ledger's recorded digest.
- **Three registry identities are not commits of this repository** (the rustc
  commit, the dudect pinned commit, and a non-resolving value). They are
  reported as `FR_IDENTITY_UNKNOWN`, not silently accepted, but the registry's
  extractor still records them as bound.
- **This triage is a snapshot at the registry's commit.** A registry
  re-derivation at a later commit makes the triage stale and is refused
  (`FR_TRIAGE_STALE`) until it is re-derived.
- **It does not decide that a claim is true**, that a `DECLARED` identity is
  the tree the measurement actually used (only that the artefact says so and the
  commit resolves), or that a `tracked-input-at-head` artefact was used in any
  run. It decides which artefacts can be certified current at all.

## 8. Reproduction

```sh
# re-derive the triage from the registry's own commit and compare
python3 forensics/tools/freshness.py triage

# the tree sweep, with the triage as a required overlay
python3 forensics/tools/freshness.py check

# the recorded multi-range history, regenerated with the triage applied
python3 forensics/tools/freshness.py diff --runs evidence/etp-t9/HISTORY-RUNS.json

# the gate's claim item over the committed claim set
python3 -c 'import sys; sys.path.insert(0, "forensics/tools"); import release_gate as g; \
index, _ = g.load_triage(g.IDENTITY_TRIAGE, g.DEPENDENCY_REGISTRY); \
r = g.check_claims(g.ROOT, g.CLAIMS, g.CLAIM_SCHEMA, False, triage=index); \
print("\n".join(x.line() for x in r.refusals))'

# the controls
python3 -m unittest discover -s forensics/tools/tests -p 'test_freshness.py'
python3 -m unittest discover -s forensics/tools/tests -p 'test_release_gate.py'
python3 forensics/tools/release_gate.py --self-test
```

Every command except the `unittest`/gate invocations runs in the court image
(`docker/openssl-rs-court.sh exec`) under its memory cap.
