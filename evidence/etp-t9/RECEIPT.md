# ETP-T9 — evidence freshness, invalidation and carry-forward

*Receipt for the dependency model, the invalidation engine, the history runs and
the controls. Normative description: `docs/EVIDENCE-FRESHNESS.md`. Machine
records: `evidence/etp-t9/DEPENDENCIES.json` and
`evidence/etp-t9/HISTORY-RUNS.json`.*

## 1. Identity

| | |
|---|---|
| branch | `staging` |
| source candidate `S` | `26c12726283c84185540844f5e150db22038d05e` |
| worktree at the start | clean (`git status --porcelain` empty) |
| `DEPENDENCIES.json` `recorded_at_commit` | `26c12726283c84185540844f5e150db22038d05e` |
| `forensics/tools/freshness.py` | sha256 `251caa6b500aac6fb0b4ba1ed3c0bf88b898945fcf26f4da5463bd2c17a9d9b7` |
| `forensics/tools/tests/test_freshness.py` | sha256 `917586eac2bce964cbe7401b72344bfa1b9915c4d61fe63bf79b3f1b2a79afd0` |
| `evidence/etp-t9/DEPENDENCIES.json` | sha256 `f48202bfba1f78e5b248d2f8b3c104c6e720ee7104a0cc0d28213aefc7d4e2d8` |
| `evidence/etp-t9/HISTORY-RUNS.json` | sha256 `9c26b6e38c40106f800e9a78e8160f30993cca647ef25c47411f86723554e844` |

The registry names the commit it was derived at. The history record names the
registry by repo-relative path and records its SHA-256, so re-deriving it from a
different checkout location does not change it.

## 2. Environment and memory guard

Read before any command:

```
$ free -g
              total        used        free      shared  buff/cache   available
Mem:             45          21          19           0           4          24
Swap:            45          36           9
```

`available` was 24 GiB, exactly the §6.1 threshold. The cap chosen was
`min(8, 24 - 16) = 8g`, and the court was started with 6g for both memory and
memory+swap:

```
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec sh -c '<command>'
```

Every Python run used that court (`Python 3.11.2`); one heavy command ran at a
time. No `cargo` build, test or benchmark ran, and no command ran on the host.

## 3. What the partial commit got right, and what changed

The `wip(etp-t9)` commit supplied the three-mode design (`record`, `check`,
`diff`), the import of the claim algebra rather than a reimplementation, the
closed preservation-procedure set, the population exclusions, the history record
and 33 passing tests. Those remain.

The following were wrong or incomplete and were changed:

1. `Git.changed` was defined twice; the first definition was dead. Removed.
2. `HISTORY-RUNS.json` embedded the absolute registry path (`/work/...`), so the
   committed record could not be re-derived from another checkout. The path is
   now repo-relative and `registry_sha256` is recorded.
3. A cited evidence file that the change set itself modified was not a
   change-caused reason when the artefact was unmodelled; the claim could remain
   in `verified_current`. Modified evidence is now always change-caused, and
   `verified_current` excludes claims with pre-existing reasons.
4. A dependent that re-used an absent or unmodelled upstream artefact could be
   reported `UNAFFECTED`. It is now `UNRESOLVED`: an upstream the engine cannot
   evaluate is not non-impact.
5. The tree sweep evaluated one artefact at a time, so an invalidated upstream
   was not propagated to its dependents. The whole registry is now evaluated over
   each artefact's range; this found five more stale artefacts (85 → 90) and
   moved the same five out of `UNAFFECTED` (15 → 10).
6. `comment_only` did not require the argument to account for every touched
   dependency, and could ignore a touched concern outside `.rs`/`.c`/`.h`. Both
   are now refused (`FR_PRESERVATION_INCOMPLETE` / `FR_PRESERVATION_UNDECIDABLE`).
7. Tree-sweep records now expose `absent_dependencies` and
   `modelled_dependencies`, so the ETP-0 `evidence_not_reconstructable` class is
   visible even when the artefact names no identity.
8. The document's ETP-0 claim was not supportable ("every one of the eight
   evidence gaps and six of the eight identity gaps"). It is replaced by the
   mapping in §8, which states which gaps are reproduced and which are not.
9. The registry was re-recorded at `S`. The population and dependencies are
   unchanged; `excluded` rose from 226 to 228 because the two `evidence/etp-t9/`
   files now exist and are recorded as self-exclusions.
10. The test suite grew from 33 to 41 controls.

## 4. The dependency model

At `S` the registry contains **331 artefacts**, **5,183 dependency edges** and
**387 advisory citations**:

| edge kind | count |
|---|---|
| `path` | 3,880 |
| `source_tree` | 570 |
| `venue` | 570 |
| `upstream_evidence` | 103 |
| `verification_tool` | 48 |
| `instrument` | 12 |

228 paths are excluded: 189 larger than 512 KiB, 25 raw payloads/fixtures/probe
sources, 12 normative documents cited as claim or traceability inputs, and 2
files of this item itself. Every exclusion is written with its reason.

Identity: 77 artefacts carry a structured identity, 23 a prose heuristic, 231
none. 112 artefacts have neither a dependency nor an identity. 55 artefacts carry
341 absent-citation edges over 298 distinct paths; 124 of those paths are under
`court/tmp/`.

**Derived from the seed and validators.** Population (subject to the recorded
exclusions), identity and ambiguity, provenance, dependency edges, build-input
and venue closures, absent citations, the history record's registry binding, and
advisory prose citations. The claim algebra is imported from
`forensics/tools/etp_claims.py`; the traceability graph and the instrument
register are read, not restated.

**Declared by hand.** The two `HISTORY` declarations (from `ETP0-GAP-019` and
`ETP0-GAP-024`), the population exclusions and the closed preservation
procedures. There are no `PRESERVATION` declarations in the committed registry.

## 5. The invalidation engine

`check --base A --head B` and `check --paths[-file]` accept a change set and
produce, per artefact, `UNAFFECTED` (with the argument that every dependency was
evaluated and none matched), `INVALIDATED` (with the matching dependency),
`UNRESOLVED`, `UNMODELLED`, `CARRIED_FORWARD` or `HISTORY`. Claims are evaluated
through the claim algebra's own invalidation edges and transitive `depends_on`
propagation; direct and transitive-only invalidation are reported separately.

Conservative rules, each mechanically enforced:

- a changed dependency invalidates;
- an unprovable non-impact invalidates (`FR_NO_MODELLED_DEPENDENCY`,
  `FR_DEPENDENCY_UNRESOLVED`);
- an upstream artefact that is invalidated, absent or unmodelled makes its
  dependents invalidated or unresolved;
- a claim presented as current is refused when the change set invalidates or
  changes evidence it cites, or invalidates a dependency claim;
- pre-existing conditions are reported in `claims.preexisting` and do not gate a
  change set; they gate in the tree sweep.

`verified_current` contains only current-claim candidates with neither a
change-caused finding nor a pre-existing reason. `not_verified_current` names
every current candidate that has either. A pre-existing failure is therefore not
counted as current, and a modified evidence file is never reported as
pre-existing.

## 6. Carry-forward

A stale artefact remains only as:

- `HISTORY` — the named commit resolves, the artefact is excluded from current
  claims, and a current claim that cites it is refused
  (`FR_HISTORY_CITED_AS_CURRENT`); or
- `PRESERVATION` — a stated argument with its own tracked evidence and a
  procedure from the closed set, executed by the tool. A touched dependency the
  argument does not account for is refused; a touched concern outside the
  admitted languages is refused; an argument that assumes a touched file
  unchanged is refused; an unknown or free-text procedure is refused.

At `S`, both declarations are `HISTORY`; no artefact is carried by a preservation
argument. The tree sweep refuses every stale artefact with neither declaration
(`FR_CARRY_FORWARD_UNDECLARED`).

## 7. History runs

`diff --runs evidence/etp-t9/HISTORY-RUNS.json` re-derives all four runs from the
current registry and returns `PASS`. The record names the registry's relative
path and digest.

| run | base → head | changed paths | invalidated | claims | refusals |
|---|---|---|---|---|---|
| source change | `618f5e6ec` → `0eddfe839` | 8 (4 source, 3 evidence, 1 docs) | **97** (86 `source_tree`, 7 `path`, 4 `upstream_evidence`) | 8 findings, 5 current and refused | 102 |
| tool change | `8af8870f1` → `3951f0f5e` | 8 (2 tool, 4 evidence, 2 docs) | **15** (11 `path`, 4 `upstream_evidence`) | 3 findings, 3 refused | 18 |
| evidence-only change | `98c7b5d29` → `8a697aa7e` | 2 evidence | **0** | 0 | **0** |
| tool-control change | `fe852d8e5` → `3ddab71a8` | 1 tool test | **2** (1 `verification_tool`, 1 `path`) | 0 | 2 |

The source run refuses `ETP0-CLM-010`, `-011`, `-029`, `-030` and `-031`; the
tool run refuses `ETP0-CLM-011`, `-013` and `-014`. The other findings in the
source run are already `CONTRADICTED` or otherwise not current and are reported
without gating. The evidence-only run invalidates nothing and refuses nothing,
which is the required result and shows that an evidence change nothing depends on
is not turned into a false invalidation.

The `UNRESOLVED` counts in these runs (67, 100, 104 and 102 across the 331
artefacts) are pre-existing conditions; they are listed and counted, not refused
in change-set mode.

## 8. Receipts stale today, and the ETP-0 gaps

The tree sweep applies `<artefact identity>..26c127262` to each artefact. Of the
38 `RECEIPT` artefacts, **7 are stale** and **31 are uncertifiable** (no usable
identity). The 7 stale receipts, with the dependency the engine records as moved:

| receipt | moving dependency | identity commit | changed paths in range |
|---|---|---|---|
| `evidence/etp-t3/RECEIPT.md` | `source_tree` `src` | `794a7c549` | 107 |
| `evidence/etp0/RECEIPT.md` | `source_tree` `src` | `9372bb28b` | 501 |
| `evidence/etp2/RECEIPT.md` | `source_tree` `src` | `9372bb28b` | 501 |
| `evidence/etp5/RECEIPT.md` | `source_tree` `Cargo.lock` | `17042ccf2` | 855 |
| `evidence/etp6/RECEIPT.md` | `source_tree` `src` | `98c7b5d29` | 118 |
| `evidence/etp7/RECEIPT.md` | `source_tree` `src` | `8a697aa7e` | 116 |
| `evidence/performance-frontier/campaigns/PFP-0/RECEIPT.md` | `source_tree` `src` | `c9a0fdd58` | 493 |

The engine reports the first dependency that moved and the number of changed
paths in that artefact's range; it does not claim that every changed path is
relevant. The 31 uncertifiable receipts are: `courts/phase18/interop/RECEIPT-o2`,
`-o3`, `-o4`, `-o5`, `-o6`, `-o7`, `-o7-AA`, `-o7-AB`, `-o7-BA`, `-o7-BB`,
`-o8`, `-o9`, `-o10` and `-o12`, `courts/phase18/timing/RECEIPT-dudect-modes`,
`RECEIPT-timing-unified`, both `evidence/element7-curl-049-*` receipts,
`evidence/etp-t1`, `etp-t2`, `etp-t4`, `etp-t5`, `etp-t6`, `etp-t7`, `etp-t8`
receipts, `evidence/etp4/VERIFICATION-RECEIPT.md`,
`evidence/etp5/REEXECUTION-RECEIPT-o7-BA` and `-BB`, `evidence/haz-16/RECEIPT.md`,
and the two PFP-1 receipts. Three of those name absent inputs and expose them
directly: O9 (`/tmp/o9-a.log`, `/tmp/o9-b.log`) and the two re-execution receipts
(`court/tmp/o4/cell-BA.log`, `court/tmp/o4/cell-BB.log`).

### ETP-0 mapping

The engine does not reproduce all eight `evidence_not_reconstructable` gaps as
their own conditions, and it does not decide `identity_mismatch`.

| gap | class | mechanical witness at `S` | disposition |
|---|---|---|---|
| 008 | not reconstructable | 124 absent `court/tmp/` paths across 55 records; the three named artefacts are outside the population | class reproduced in aggregate; named artefacts not modelled |
| 009 | not reconstructable | `evidence/etp6/MANIFEST.json` and `evidence/etp-t1/TRACEABILITY.json` record `court/tmp/t20/NOTES.md` absent; `build_reproducibility.sh` is unresolved with no identity | reproduced by citation, not by the named tool |
| 010 | not reconstructable | `artifacts/phase7/COURTS.json` and `evidence/etp6/MANIFEST.json` record `artifacts/phase2/libcrypto.so.3` absent | reproduced |
| 011 | not reconstructable | O9 records `/tmp/o9-a.log` and `/tmp/o9-b.log` absent; O6 and O8 name no log path and are unresolved with no identity | partial: O9 reproduced; O6/O8 unresolved only |
| 012 | not reconstructable | `evidence/b85c-safety-argument.json` records four `court/freeze-b85*` generators absent; both b85c records are invalidated by other dependencies | reproduced for the sidecars |
| 013 | not reconstructable | O3 and O10 unresolved with no identity; no absent structured path | not reproduced (prose-only inputs) |
| 014 | not reconstructable | `evidence/timing-bn-repair.json` is invalidated by a timing receipt; no absent structured path | not reproduced as the stated condition |
| 018 | identity mismatch | O4, O5, `MANIFEST-o11-B` and `RECEIPT-o7-BB` unresolved with no identity | precondition surfaced; mismatch not decided |
| 019 | identity mismatch | `evidence/baseline-20261120.json` declared `HISTORY` at `0500fa9ef` | declared from the gap, not derived |
| 020 | identity mismatch | the two install DSOs unresolved with no identity | precondition surfaced; provenance mismatch not decided |
| 021 | identity mismatch | not in the population | not reproduced |
| 022 | identity mismatch | both b85c records invalidated by other dependencies | field-value defect, not a freshness question |
| 023 | identity mismatch | the atlas and `RECEIPT-o7` unresolved with no identity | precondition surfaced; candidate mismatch not decided |
| 024 | identity mismatch | `CAMPAIGN-STATUS.json` declared `HISTORY` at `afcfdc47e` | declared from the gap, not derived |
| 025 | identity mismatch | `artifacts/phase25/summary.json` unresolved with no identity | precondition surfaced; version mismatch not decided |
| 037 | not reconstructable | `evidence/etp6/MANIFEST.json` records `artifacts/phase2/shell/libcrypto.shell.rs` absent; `SHELL_MANIFEST.json` is unresolved with no identity | reproduced by citation, not by the named manifest |

## 9. Controls

`python3 forensics/tools/tests/test_freshness.py` is **41/41 OK** in the court.
Each control builds a throwaway Git repository, commits a known tree and changes
exactly one thing.

| required control | test | observed assertion |
|---|---|---|
| changed dependency invalidates | `test_changed_dependency_invalidates` | `INVALIDATED`, `FR_EVIDENCE_INVALIDATED`, status `REFUSED` |
| comment-only change to an unconcerned file does not | `test_comment_only_change_to_unconcerned_file_does_not_invalidate` | `UNAFFECTED`, no refusal |
| unprovable non-impact invalidates | `test_unprovable_preservation_is_refused`, `test_empty_argument_is_refused`, `test_preservation_without_its_own_evidence_is_refused`, `test_preservation_about_a_non_dependency_is_refused` | `FR_PRESERVATION_UNDECIDABLE` / `INCOMPLETE` / `UNEVIDENCED`, artefact `INVALIDATED` |
| unlabelled stale artefact refused | `test_stale_artefact_with_no_declaration_is_refused_in_the_tree` | `FR_CARRY_FORWARD_UNDECLARED`, status `REFUSED` |
| explicit history accepted | `test_explicit_history_is_accepted` | verdict `HISTORY`, no refusal, status `PASS` |
| history cited as current refused | `test_explicit_history_cited_as_current_is_refused` | `FR_HISTORY_CITED_AS_CURRENT` in the tree sweep |
| preservation naming a touched dependency refused | `test_preservation_assuming_a_touched_dependency_is_refused` | `FR_PRESERVATION_TOUCHED`, artefact `INVALIDATED` |
| transitive invalidation through a claim | `test_invalidation_travels_through_the_claim_edges` | C-1 direct and C-2 transitive-only, both refused |
| determinism | `test_output_is_byte_identical`, `test_record_is_byte_identical` | two runs byte-identical |
| positive control | `test_comment_only_procedure_carries_the_artefact_forward` | `CARRIED_FORWARD`, status `PASS` |

The **comment-only choice** is deliberate. The dependency model matches paths, not
diffs, so it cannot prove non-impact for a comment-only change to a file the
artefact names: that case is asserted as `INVALIDATED`
(`test_comment_only_change_to_a_concerned_file_invalidates_without_an_argument`).
A comment-only change to a file the artefact does **not** name is `UNAFFECTED`
because the file is not a dependency at all, which is the only non-impact the
model can establish without a preservation argument. The model does not claim to
distinguish comments from code.

Additional controls cover change-caused/pre-existing separation
(`test_a_change_to_unmodelled_evidence_is_change_caused`,
`test_preexisting_unresolved_evidence_is_reported_separately`,
`test_a_claim_carries_both_a_change_caused_and_a_preexisting_reason`),
upstream-unmodelled dependents
(`test_upstream_evidence_with_no_modelled_dependency_is_unresolved`),
upstream declared history (`test_upstream_declared_history_is_not_current`),
preservation coverage
(`test_comment_only_argument_must_account_for_every_touched_dependency`),
absent-citation exposure
(`test_tree_sweep_exposes_an_absent_dependency_even_without_an_identity`), and
the registry model refusals (cycle, unknown kind, duplicate artefact, unresolved
tool digest, absent dependency, missing identity, unmodelled artefact, path list).
`RegistryShape` validates the committed registry and re-derives the committed
history record.

## 10. Determinism

Two invocations of the same change-set check produced byte-identical output
(`cmp`), and two tree sweeps produced byte-identical output (`cmp`). The tree
sweep at `S` has sha256
`7e4f3f6b876df4eaed9951b68ae4fb94e80a27d7bebc099c9a70a2db210fc4ba`.
`diff --runs` returns `PASS`.

## 11. Reproduction

All commands run in the court described in §2.

```sh
# registry re-derivation at S
cp evidence/etp-t9/DEPENDENCIES.json /tmp/registry.json
python3 forensics/tools/freshness.py record --at 26c127262 --out /tmp/registry.json
cmp /tmp/registry.json evidence/etp-t9/DEPENDENCIES.json

# history record
python3 forensics/tools/freshness.py diff --runs evidence/etp-t9/HISTORY-RUNS.json

# tree sweep and the four ranges
python3 forensics/tools/freshness.py check --head 26c127262
python3 forensics/tools/freshness.py check --base 618f5e6ec --head 0eddfe839
python3 forensics/tools/freshness.py check --base 8af8870f1 --head 3951f0f5e
python3 forensics/tools/freshness.py check --base 98c7b5d29 --head 8a697aa7e
python3 forensics/tools/freshness.py check --base fe852d8e5 --head 3ddab71a8

# controls
python3 forensics/tools/tests/test_freshness.py
```

`check` exits non-zero when any refusal is present. The tree sweep and the source,
tool and control ranges therefore exit 1 by design; the evidence-only range exits
0.

Files touched: `docs/EVIDENCE-FRESHNESS.md`, `docs/ETP-TODO.md`,
`evidence/etp-t9/DEPENDENCIES.json`, `evidence/etp-t9/HISTORY-RUNS.json`,
`evidence/etp-t9/RECEIPT.md`, `forensics/tools/freshness.py`,
`forensics/tools/tests/test_freshness.py`. No `src/`, `docker/` or other item's
evidence was modified.

## 12. What this does not establish

- That a cited experiment occurred, or occurred as described.
- That a claim is true. A green change-set check says this change set did not
  invalidate anything the model records; it does not say the evidence is correct.
- That the dependency model is complete. A missing dependency under-invalidates;
  the model is a reviewable declaration for that reason. The measured shape is
  231 artefacts with no identity, 112 with no dependency and no identity, and 55
  with absent-citation edges.
- That the tree sweep has no false stales. It can over-invalidate when an upstream
  identity is later than the dependent's; it never under-invalidates, and an
  over-invalidated artefact is reported stale rather than certified.
- That two identities are the same source or the same binary. The engine reports
  an unresolved identity; it never equates two identities.
- That an instrument is sensitive to the defect it claims to detect, or that a
  tool version is qualified for a use (ETP-3).
- That a preservation argument is sound beyond its executed procedure.
  `comment_only` does not model macro expansion, and no procedure in the set
  reasons about semantics.
- That the population is complete, or that an artefact outside it is irrelevant.
- Freshness for an artefact that names no identity. That is reported as
  unresolved — a refusal to certify, not a pass.

The seven stale receipts are **not** edited. Their states are reported here; a
new record supersedes them, and rewriting the originals would destroy the
history this item exists to preserve.

---

## 13. Addendum — identity triage (2026-11-23)

This addendum is appended; sections 1-12 above are unchanged.

**The gap.** Section 1.4 of `docs/EVIDENCE-FRESHNESS.md` records 231 artefacts
with no identity, and the tree sweep refuses each with `FR_IDENTITY_UNKNOWN`.
That refusal was not decisive. In change-set mode an artefact with modelled
dependencies was still reported `UNAFFECTED`, and the release gate read only the
claim document, so a claim resting on an unbound artefact could pass. The count
was recorded; nothing depended on it.

**What was added.** `forensics/tools/freshness.py triage` derives a class for
each of the 231 and records it in `evidence/etp-t9/IDENTITY-TRIAGE.json`
(schema `openssl-rs/etp/identity-triage/1`), bound to the registry's commit
`26c127262`. The class is `DERIVED` (a recorded derivation rule), `DECLARED`
(the artefact names a resolving tree in a named field), `HISTORICAL` (a record of
one moment, not citable as current) or `UNCERTIFIABLE` (no identity can be
established or honestly declared, with a cause and what would make it
certifiable). `check` loads the triage as a declared overlay: a `DECLARED` or
`DERIVED` identity is used; a `HISTORICAL` artefact is `HISTORY` and a current
claim citing it is refused; an `UNCERTIFIABLE` artefact is `UNRESOLVED` with
`FR_IDENTITY_UNCERTIFIABLE` in both modes and does not inherit an identity from
an upstream record. `forensics/tools/release_gate.py` makes the triage a required
item and refuses a current claim whose evidence is `UNCERTIFIABLE`
(`RG_CLAIM_UNCERTIFIABLE_EVIDENCE`) or `HISTORICAL`
(`RG_CLAIM_HISTORICAL_EVIDENCE`), naming the artefact.

**Result.** 13 `DECLARED`, 21 `DERIVED`, 79 `HISTORICAL`, **118
`UNCERTIFIABLE`** (87 `U1` multi-commit, 9 `U2` candidate-name-only, 18 `U5`
uncheckable source binding, 2 `U6` build output, 2 `U7` self-qualified
declaration). Tree sweep: 81 `HISTORY`, 92 `INVALIDATED`, 31 `UNAFFECTED`, 127
`UNRESOLVED`; 265 refusals. `HISTORY-RUNS.json` was regenerated with the triage
applied and re-derives byte-for-byte; the evidence-only run still passes with no
refusal. The gate's claim item returns 34 refusals on 35 claims: 4 pre-existing
`CONTRADICTED`, 19 `RG_CLAIM_UNCERTIFIABLE_EVIDENCE` and 11
`RG_CLAIM_HISTORICAL_EVIDENCE`, affecting 20 distinct current claims. The
release gate is now **red on claims that previously passed**, and that is the
intended consequence: `ETP0-CLM-034` (the Phase-25 seal, named only by candidate
version) and `ETP0-CLM-029` (a frozen inventory its own header declares
superseded) cannot be cited as current evidence.

**Controls.** `forensics/tools/tests/test_freshness.py` gains ten controls (one
per class, determinism, four malformed/stale-triage refusals, uncertifiable not
`UNAFFECTED`, historical not citable, declared identity resolved, non-mutation).
A new `forensics/tools/tests/test_release_gate.py` has ten controls (one per
new refusal, both positive controls, missing/stale binding).
`release_gate.py --self-test` is 13/13.

**Not closed.** The 118 `UNCERTIFIABLE` artefacts remain so; the full residual,
by cause and with the claims affected, is in
`evidence/etp-t9/IDENTITY-TRIAGE.md` §4, §6 and §7. Three further registry-bound
artefacts carry an identity that is not a commit of this repository (a rustc
commit, a pinned dudect commit, and a non-resolving value); they are outside the
231 by the registry's own count and remain a registry-extraction defect. No
identity was declared that the artefact does not support: where a freeze record
was untracked or digest-mismatched, the artefact is `UNCERTIFIABLE` rather than
bound to the digest it names.

Files touched by this addendum: `docs/EVIDENCE-FRESHNESS.md`,
`docs/ETP-TODO.md`, `docs/RELEASE_GATES.md`,
`evidence/etp-t9/IDENTITY-TRIAGE.json`, `evidence/etp-t9/IDENTITY-TRIAGE.md`,
`evidence/etp-t9/HISTORY-RUNS.json`, `evidence/etp-t9/RECEIPT.md`,
`forensics/tools/freshness.py`, `forensics/tools/release_gate.py`,
`forensics/tools/tests/test_freshness.py`,
`forensics/tools/tests/test_release_gate.py`. No `src/`, `docker/` or other
item's evidence was modified.
