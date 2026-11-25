# A0 evidence-audit repairs, third batch — F06 currency and F10 current status

**Candidate:** branch `staging`, head
`f5d9515cf0d31914dff2df6784f2c911314ce7f7`, 2026-11-25. Records and
documentation only: no Rust build, no `cargo`, no court run, no benchmark.

**Venue and memory.** Host `free -g` before every command: `available` 23–24 GiB.
The operative cap is `min(4g, available − 8g)` = **4g**, above the 2 GiB floor.
Only documentation tools and `unittest` modules ran; one command at a time.

**Starting position.** `evidence/a0/FINDINGS.json` (candidate `e0b727d0`)
records A0-F06 (silent suppression) and A0-F10 (summary without
reconstruction). A second batch (commit `025e86385`) had already:
labelled the `8a697aa7e` transcript in `evidence/etp7/RECEIPT.md` §3/§5 as
history; added §9 at `2d31a23fb`; and split the `forensics/STATUS.md`
downstream row by identity. This batch checks whether those repairs still hold
at `f5d9515cf` and repairs what does not.

## 1. A0-F06 — the stale full-gate transcript

### What the artefact is and what it is bound to

- The artefact is `evidence/etp7/RECEIPT.md`. The "full gate" is the six-item
  `forensics/tools/release_gate.py` decision plus the §5 table of commands.
- §3 and §5 are the run at `8a697aa7e` (four `RG_CLAIM_CONTRADICTED`, 33
  blocked, 42 open obligations), preserved unedited.
- §9 is the run at `2d31a23fb` (`SUPERSEDED`, 33 blocked, 37 open obligations,
  31 refusals), with the claim-set digest `2968ffd…`.
- **`2d31a23fb` is on no branch and is not an ancestor of `f5d9515cf`.** The
  merge-base is `6eb619dfb`. The §9 transcript was therefore still presented as
  the current result when it was not, which is A0-F06 recurring one identity
  later.

### Can it be reproduced here?

No. The §5 gate comprises `cargo fmt --all -- --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test --lib -- --test-threads=4`, and an
ETP-6 package built by `forensics/tools/etp6_package.py` and verified by its
`verify.sh --full` (two-build reproducibility). That needs a Rust build and the
court venue. A no-package `release_gate.py` run would omit the package item and
would run on a dirty tree, so it would not be the full gate. This batch is
forbidden from both a build and a court run.

### What the record now says

- The `Record status` paragraph no longer says "a reader who needs the current
  result reads §9". A dated 2026-11-25 note says that sentence was a stale
  currency claim, names the divergence, and points to §10.
- §3's and §5's superseded notes say §9 is also history of a divergent lineage.
- §9 carries a `History (A0-F06, 2026-11-25)` note: bound to `2d31a23fb`, not a
  current result, retained unedited.
- New §10 records **`NOT_RUN` at `f5d9515cf`** with: the head, the current
  `evidence/etp/claims.json` digest `2968ffd…` (equal to §9's, so the claim set
  did not move), `validate` = 35 claims / 0 refusals, `conjoin` =
  `SUPERSEDED` / 33 blocked / 37 obligations, and the exact commands that would
  regenerate the gate.

### Disposition

**OPEN at `f5d9515cf`.** The false currency claim is removed; the full gate has
not run at this head. `docs/ETP-TODO.md` (ETP-7 row) and
`docs/RELEASE_GATES.md` carry the same dated correction.

## 2. A0-F10 — the current-status 33/33 occurrences

### Committed truth

`evidence/etp/claims.json` `ETP0-CLM-032` is `SUPERSEDED`:
`CAMPAIGN-STATUS.json` records `consumers.safe_compatible = 0`,
`consumers.risk_accepted = 1` (`openssh`), and `consumers.l7_functional = 33`.
`ETP0-CLM-028` records the `33/33` as an atlas fact at `L7-functional` with the
evidence-reuse caveat, not a fresh measurement.

### Current-status occurrences corrected

| path | before | after |
|---|---|---|
| `README.md` achievements row | `33 / 33 families at L7-functional … carried forward 27/33` | same figure, plus `the consumer counter is 0/33 SAFE_COMPATIBLE with 1 risk-accepted family (openssh)` |
| `README.md` achievements `SAFE_COMPATIBLE` row | `1 / 33` — openssh graduated | `0 / 33` — no proven closure; 1 risk-accepted (`openssh`) is not a graduation |
| `README.md` memory-safety `Not discharged` / `SAFE_COMPATIBLE` rows | `remains 1/33` / `1 / 33` graduated | `remains 0/33` / `0 / 33` with 1 risk-accepted |
| `README.md` L7 prose | `the Safe-33 cohort is 33/33` | `33/33 at L7-functional` with the 6-measured / 27-carried split and the committed consumer figure |
| `forensics/STATUS.md` phase24 coverage finding | `33/33 at L7-functional` with the identity mixture only | adds `the cohort's committed consumer figure is 0/33 SAFE_COMPATIBLE with 1 risk-accepted family (openssh) … ETP0-CLM-032 SUPERSEDED` |
| `forensics/STATUS.md` downstream table | `current (mixed identity) … 33/33` | `current (mixed identity; L7-functional, not SAFE_COMPATIBLE) … 33/33 …`, with the committed consumer paragraph above the table |
| `forensics/memory-safety/campaign/safe-c33/RESEARCH_REVIEW.md` | `the current atlas records 33/33 at L7-functional` | same figure, plus the 6/27 split and the committed consumer figure |

The `1/33` dated 2026-11-17 note in `README.md` is retained and a dated
2026-11-23/recorded-2026-11-25 superseding paragraph says the counter was
reconciled to `0/33` with 1 risk-accepted family and `ETP0-CLM-032` is
`SUPERSEDED`. The old value stays visible.

### Historical occurrences left unchanged

`forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md` (dated status),
`CLOSURE.md`'s superseded 2026-10-22 note, `atlas-refresh/REPORT.md` (frozen
2026-10-17 receipt), `PROGRESS.md`'s 2026-10-20 sequencing, the
`ASSURANCE_PLAYBOOK.md` "as of 2026-10-20" line,
`docs/PHASE-24-DOWNSTREAM-1000-SEAL.md`'s 2026-11-10 re-measurement, and the
`forensics/STATUS.md` "previous rendering (historical, superseded)" row are
history and were not rewritten.

### Tool changes

- `forensics/tools/render_docs.py`
  - `safe_compatible_clause()` now names the risk-accepted family when
    `safe_compatible` is 0, from `CAMPAIGN-STATUS.json` `consumers`.
  - new `consumer_counter_text()` puts the committed consumer counter beside the
    Safe-33 `L7-functional` row.
  - README was regenerated from `Evidence.blocks()` for the README blocks only;
    the frozen `STATUS-2026-10-20.md` block was not rewritten.
- `forensics/tools/render_status.py`
  - `_runtime_functional()` now reads `consumers.safe_compatible`,
    `risk_accepted` and `risk_accepted_families` from `CAMPAIGN-STATUS.json`.
  - `_consumer_figure_clause()` states the committed consumer figure in the
    phase24 finding sentence and above the downstream table; the table row names
    its metric.
- New control `forensics/tools/tests/test_render_docs.py` (5 tests): the README
  generated blocks must match `Evidence.blocks()`; the counter must equal
  `consumers.safe_compatible / consumers.families_total`; the zero branch must
  name the risk-accepted family and must not invent one; the positive branch
  must report the graduation.

No current-status tool emits a hard-coded `33/33` as current state.
`render_status.py` keeps one literal `33/33` only inside the row labelled
"previous rendering (historical, superseded)"; `etp_t1_seed.py` keeps a literal
in the historical traceability node title `REL-L7-ATLAS-33-33`. Both are history
by design and were not changed.

### Disposition

**Repaired at `f5d9515cf` as a currency/summary finding.** Every current-status
occurrence now states the committed consumer figure beside the functional
figure, and the stale generated `1/33` was regenerated from the claim record.
The checker gap remains: `docs_consistency.py` does not read `STATUS.md` or
README, and `render_docs.py --check` reports the intentional
`STATUS-2026-10-20.md` drift. The 27 carried-forward families remain
un-remeasured, which is an evidence item, not a summary claim.

## 3. Gates and tests (observed)

| command | output |
|---|---|
| `python3 forensics/tools/spec_guard.py check` | `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions` (exit 0) |
| `python3 forensics/tools/docs_consistency.py` | `ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired` (exit 0; one documented Phase-7 exemption) |
| `python3 forensics/tools/earned_trust.py check` | `ok: every article is enforced or declares none, every citation resolves, and the release mapping is complete` (exit 0) |
| `python3 forensics/tools/etp_claims.py validate` | `{"claims":35,…,"refusal_count":0,…,"valid":true}` (exit 0) |
| `python3 forensics/tools/etp_claims.py conjoin` | `SUPERSEDED`, 33 blocked, 37 open obligations |
| `python3 -m unittest forensics.tools.tests.test_render_docs` | 5 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_archival` | 59 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_frc_registers` | 37 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_earned_trust` | 28 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_spec_guard` | 17 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_scheduling` | 36 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_etp_claims` | 95 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_package_external` | 64 tests, OK |
| `python3 -m unittest forensics.tools.tests.test_corrections` | **51 tests, 1 failure** — `Determinism.test_two_runs_are_byte_identical_and_match_committed`: `evidence/a19/EVENTS.json` |
| `python3 forensics/tools/render_docs.py --check` | exit 1; only `DRIFT: …/STATUS-2026-10-20.md: status-current-evidence` (intentionally frozen) |

The `test_corrections` failure is the frozen-population consequence below, not
a regression in the controls: the builder now emits a different
`evidence/a19/EVENTS.json` because that record digests
`evidence/etp7/RECEIPT.md`. It is left red rather than repaired by a re-freeze.

## 4. Frozen population

No `evidence/**/*.json` file was edited (`git diff --name-only` reports none).

`evidence/a19/EVENTS.json` is now **stale relative to its inputs**:
`sourceIdentity.inputs[10]` (`evidence/etp7/RECEIPT.md`) records
`b7b6edef…`; the live receipt is `bbac152d…`, and the builder
(`evidence/a19/build_evidence.py`) would emit `bbac152d…` together with a new
`logEnvelope.payload` and `logEnvelope.signatures[0].sig`. The next batch must
regenerate it as a re-freeze. A11 `evidence/a11/SCAN.json` and A16
`evidence/a16/INVENTORY.json` both record `evidence/a19/EVENTS.json` at its
current committed digest `7df3ca27…`; their entries still match the committed
bytes and **will move to the regenerated digest** when that re-freeze happens.
Membership does not change. This note is the heads-up the re-freeze needs; no
re-freeze was performed here.

## 5. Non-claims

- No gate run is recorded at `f5d9515cf`; §10 is `NOT_RUN`.
- The identity mixture is disclosed, not removed: 27 families remain carried
  forward from `26ba36ff…` and 6 measured at `1c03ec0a…`; no workload was
  re-run.
- `SAFE_COMPATIBLE` remains 0/33; `openssh` is risk-accepted, not graduated.
- The two missing mechanical checks (a transcript-to-candidate rule and a
  rendered-cohort rule) are not implemented; they remain named gaps.
