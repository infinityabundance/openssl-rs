# A0 evidence-audit repairs

Item: A0 of `docs/ETP-TODO.md` (findings only; this record holds the repairs).
Date: 2026-11-23.
Base: branch `staging`, HEAD `86a4362c70f563729dc568c6b21a427cb0810bd6`, clean
worktree at the start.
Commit identity: **`TO_BE_FILLED_BY_ORCHESTRATOR`** (this record and the source
changes are returned uncommitted; the orchestrator commits and records the hash).

**Label note.** The task brief names the second item `F10`, but both
`evidence/a0/FINDINGS.json` and `docs/EVIDENCE-AUDIT.md` number the
release-gate package defect **`A0-F16` / `F16`**. The audit's `F10` is a
different finding (`forensics/STATUS.md`, the `current` 33/33 row) and is not
repaired here. This record repairs `A0-F15` and `A0-F16`; `F10` is left open.

---

## A0-F15 — a discharged obligation whose evidence digest resolves to the earlier bytes

### Original finding (unchanged)

`ETP0-CLM-032` recorded `OBL-GAP-005` as `DISCHARGED` with `settled_by` text
asserting the live 0/33 state, while `EV-01.sha256` was
`abb8a6cb6ae4e430bbc8104683909664fad3dfa2dd5dcbc1f8aa69229d16606f` with
`digest_identity: S`. That digest is the Git blob at
`S = 9372bb28b`, and the blob records `consumers.safe_compatible: 1`. The live
file is `8affeac4d2280289cda17b1716e39bc63535cd893d71642b8cda21735e314e38`
and records `0`. Both the digest (for `S`) and the settlement (for the live
tree) were individually honest, and the record did not distinguish the two
identities.

### Citation before and after

| | before | after |
|---|---|---|
| historical record | `EV-01` = `abb8a6cb…`, `digest_identity: S`, no declared state, cited as if current | `EV-01` = `abb8a6cb…`, `digest_identity: S`, `kind: commit` (historical revision of the path), declared `state.value: SUPERSEDED`, `state.revision: 9372bb28b…`, declared `state.measure: consumers.safe_compatible = 1/33`, with a `note` naming it pre-reconciliation history |
| current record | absent from `evidence[]`; the live value appeared only in prose (`settled_by`, `verdict.basis`) | `EV-04` = `8affeac4…`, `digest_identity: E`, `kind: record`, declared `state.value: ESTABLISHED`, `state.revision: e0b727d06…`, declared `state.measure: consumers.safe_compatible = 0/33` |
| obligation evidence | `OBL-GAP-005.evidence = ["EV-01"]` | `OBL-GAP-005.evidence = ["EV-01", "EV-04"]` |
| invalidation | artefact digest `abb8a6cb…` only | both `abb8a6cb…` (S history) and `8affeac4…` (live reconciliation) |
| measure | opaque ratio string | typed counter `consumers.safe_compatible = 0/33`, so the algebra can join the assertion to the evidence record |

`EV-01` is represented as `kind: commit` because the algebra's alias rule
treats a second entry for the same path as an alias unless the historical
revision is a commit entry (`EG_EVIDENCE_ALIAS`). The `note` states that the
entry is the Git blob of the path at `S`, not a commit object; the digest is
still re-derived from `S` by `etp_claims.py`.

### Text alignment

- `interpretation` now names the `S` value (`consumers.safe_compatible = 1`),
  the contradiction inside the same record, the live value (`0`), the
  risk-accepted family (`openssh`), the preserved history fields
  (`consumers.safe_compatible_before_reconciliation`,
  `note_before_reconciliation`) and the two cited evidence ids.
- `OBL-GAP-005.statement` is prefixed with `at S=9372bb28b`, says exactly what
  the `S` bytes record, and states the live record's values and preserved
  fields.
- `OBL-GAP-005.settled_by` names both digests and revisions and says which one
  is history.
- `verdict.basis` names `EV-04` and its digest, and labels `EV-01` as history;
  it no longer asserts that the `S` prose records agree at the live tree.

### Verdict before and after

`verdict.state` was `SUPERSEDED` before and remains `SUPERSEDED`. The citation
now supports the verdict: the live ledger's own field names
(`safe_compatible_before_reconciliation`, `note_before_reconciliation`) and its
note state that the earlier 1/33 reading is superseded. No verdict was raised;
the repair is a stricter citation and text alignment, not a promotion.

### Is the contradiction class mechanically detectable?

Before this repair, no. The algebra had one related rule,
`EG_EVIDENCE_CONTRADICTS_VERDICT`, but it (a) applies only to a positive verdict
or graduation modality and (b) compares a categorical declared state
(`WITHDRAWN`/`REFUTED`/`NOT_ESTABLISHED`/`SUPERSEDED`), not the numeric value the
cited bytes record. `ETP0-CLM-032`'s verdict is non-positive, and its
contradiction was numeric, so neither the verdict nor the count was comparable.

After this repair, yes, for a record that declares the value:

- `evidence[].state.measure` is now schema-permitted and carries the typed
  measure the cited revision records. The value is copied from the artefact; it
  is never inferred from the claim.
- A new rule, **`EG_EVIDENCE_CONTRADICTS_ASSERTION`**, refuses a present,
  non-historical evidence entry whose declared measure has the same name as the
  claim's own typed `quantification.measure` and a different value.
- A non-current entry (`SUPERSEDED`, `WITHDRAWN`, `REFUTED`,
  `NOT_ESTABLISHED`) is exempt, which is what lets the repaired claim cite the
  earlier 1/33 bytes as labelled history.

Controls (`forensics/tools/tests/test_etp_claims.py`,
`EvidenceAssertionControls`):

| control | expected |
|---|---|
| current evidence declares 1/33 while the claim asserts 0/33 | `EG_EVIDENCE_CONTRADICTS_ASSERTION` at `evidence/0/state/measure` |
| current evidence declares 0/33 while the claim asserts 0/33 | accepted |
| the same 1/33 entry is labelled `SUPERSEDED` and the verdict is non-positive | accepted (history) |
| the committed `ETP0-CLM-032` cites `EV-01` (S, `SUPERSEDED`) and `EV-04` (E), and `OBL-GAP-005` cites `EV-04` | accepted and asserted |

`etp_claims.py validate` continues to accept the committed document: 35 claims,
0 refusals.

### Derived projection

`evidence/etp-t1/TRACEABILITY.json` embeds the claim's verdict basis, its
obligation statement and its evidence nodes, so the graph was regenerated with
`forensics/tools/etp_t1_seed.py` (363 nodes, 476 edges, 43 orphans, unchanged
orphan count). The seeder now binds an `E`-identity digest to the commit the
evidence record names in `state.revision`, but only after checking that the blob
at that commit hashes to the cited digest (`e0b727d06` for `EV-04`). Previously
it bound every non-historical digest to `S0`, which for an `E` digest would have
reproduced the F15 false-identity pattern in the derived graph. If the declared
revision cannot be shown to hold the digest, the node keeps the `S0` binding and
the graph's class-4 check reports the mismatch rather than claiming an identity
it cannot show.

### What remains open in F15

- The rule detects only a contradiction the producer declares. If an evidence
  entry records no `state.measure`, the algebra has nothing to join and does not
  invent one; that is the same open condition as an undeclared `state` and
  remains an obligation, not a pass.
- The rule compares exact strings for free-text measures and exact
  numerator/denominator (or value/unit) for typed measures. It does not parse
  prose.
- Other claims still share `source_identity.commit = 9372bb28b` while several
  are settled by later items. `ETP0-CLM-032` is repaired; the wider
  settlement-identity question named in the finding's consequence statement is
  not closed for the rest of the set.
- `EV-04` uses `digest_identity: E`, so its digest is the worktree bytes. The
  orchestrator's commit keeps those bytes; a future edit to
  `CAMPAIGN-STATUS.json` invalidates the claim, as intended.

---

## A0-F16 — the release gate's package item does not bind the package to the candidate

### Original finding (unchanged)

`check_package` resolved the package, ran `verify.sh` or `etp6_verify.py`, and
reported the verifier result. It never read `MANIFEST.json candidate.commit` or
`candidate.tree`, so a package built for `98c7b5d29` satisfied gate-5 for a
release at another commit.

### Repair

`check_package` now takes the resolved `candidate`, its `candidate_tree`, and an
optional `supersedes` commit, and reads the package manifest from
`MANIFEST.json` (built archive root) or `evidence/etp6/MANIFEST.json` (this
tree's layout).

| condition | result |
|---|---|
| no manifest in the package | `RG_PACKAGE_MANIFEST_ABSENT` |
| manifest does not parse, or records no `candidate.commit` | `RG_PACKAGE_MANIFEST_INVALID` |
| `candidate.commit` differs from the gate candidate and is not an explicit supersession | `RG_PACKAGE_CANDIDATE_MISMATCH`, naming both commits |
| `candidate.commit` matches but `candidate.tree` differs from the candidate's tree | `RG_PACKAGE_CANDIDATE_MISMATCH`, naming both trees |
| `--package-supersedes REF` resolves to the package's commit | accepted and recorded as an explicit supersession |
| `--package-supersedes REF` does not resolve | `RG_PACKAGE_SUPERSESSION_UNRESOLVED` |

The verifier still runs; its refusals (`RG_PACKAGE`) are reported alongside the
identity refusals, so one item can name every reason it refused. The gate is
not weakened: the only path for a differing commit is the explicit
`--package-supersedes` flag, whose resolved identity is written into the
decision's `recorded` lines, and a mismatching flag does not suppress the
refusal.

### Controls

`release_gate.py --self-test` (case count 16 before, 21 after):

| control | expected |
|---|---|
| package for another candidate | `RG_PACKAGE_CANDIDATE_MISMATCH` naming the package commit |
| package for another tree (same commit) | `RG_PACKAGE_CANDIDATE_MISMATCH` naming the package tree |
| package without a manifest | `RG_PACKAGE_MANIFEST_ABSENT` |
| package whose verifier fails (manifest matches) | `RG_PACKAGE` |
| matching package (positive control) | no refusal |
| explicit supersession (positive control) | no refusal, supersession recorded |

`forensics/tools/tests/test_release_gate.py` (`PackageCandidateControls`) adds
six unit controls over the same behaviour, including that a supersession flag
which does not match the package is still refused.

### What remains open in F16

- The gate now binds identity; it still does not decide that the package was
  produced by an independent party, that the reproduction is genuine, or that
  the package's verifier is sensitive to the defect class it claims to detect.
  Those disclaimers in the docstring stand.
- The tracked `evidence/etp6/MANIFEST.json` records
  `candidate.commit = 98c7b5d290a8e40a1bd4d979ed34599038733e4d` and
  `candidate.tree = 64f796e906bd7317b7f2fffbbea88bc171b3620b`. A real gate run
  at a different candidate must now refuse it unless the operator declares an
  explicit supersession. That is the intended behaviour, not a regression; the
  package itself is a separate ETP-6 item.
- A tree mismatch is checked only when the commit matches, because the tree of a
  different commit is expected to differ and the commit refusal already names
  the identity.

---

## Validation

Commands run inside `docker/openssl-rs-court.sh exec` from `/work`, with
`OPENSSL_RS_COURT_MEM=2g` and `OPENSSL_RS_COURT_MEMSWAP=2g`
(host `free -g` reported 18 GiB available; `min(8, 18 - 16) = 2g`, the floor).

| command | before | after |
|---|---|---|
| `python3 -m unittest discover -s forensics/tools/tests` | 525 tests, OK | 535 tests, OK |
| `python3 forensics/tools/etp_claims.py validate` | 35 claims, 0 refusals, valid | 35 claims, 0 refusals, valid |
| `python3 forensics/tools/release_gate.py --self-test` | 16 cases, ok | 21 cases, ok |
| `python3 forensics/tools/docs_consistency.py` | exit 0, 20 claims | exit 0, 20 claims |
| `python3 -m json.tool` on changed JSON | n/a | `claims.json`, `claim.schema.json` parse |

No test was removed or skipped: the ten added tests are
`EvidenceAssertionControls` (four) and `PackageCandidateControls` (six).

## Files changed

- `evidence/etp/claims.json` — `ETP0-CLM-032` citation, text, measure and
  invalidation.
- `evidence/etp/claim.schema.json` — optional `evidence[].state.measure`.
- `forensics/tools/etp_claims.py` — `_declared_evidence_measure`,
  `_claim_typed_measure`, `EG_EVIDENCE_CONTRADICTS_ASSERTION`, docstring.
- `forensics/tools/tests/test_etp_claims.py` — four controls.
- `forensics/tools/release_gate.py` — package-candidate comparison, manifest
  readers, `--package-supersedes`, six self-test controls.
- `forensics/tools/tests/test_release_gate.py` — six controls.
- `forensics/tools/etp_t1_seed.py` — bind an `E`-identity claim-evidence digest
  to its declared revision when the blob there matches, never to `S0` by
  default.
- `evidence/etp-t1/TRACEABILITY.json` — regenerated projection (derived).
- `docs/EVIDENCE-AUDIT.md` — repair status for `F15` and `F16`.
- `docs/ETP-TODO.md` — follow-ups on the ETP-1 and ETP-7 rows.
- `docs/ETP-CLAIM-ALGEBRA.md` — the new refusal in the normative rule list.
- `evidence/a0/REPAIRS.md` — this record.
