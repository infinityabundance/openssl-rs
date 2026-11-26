# B8 receipt — the enforcement that refuses, and the two integrations it may not make

## 1. Identity of this batch

| field | value |
|---|---|
| item | B8 (`docs/ETP-ADDENDUM-B.md` §B.30): integrate the admitted profile into `AGENTS.md`, release gates, ETP claim schemas, CI and public non-claims; prevent a silent regression |
| status | **`PARTIAL`** — the gate item, schema field, non-claims, controls and documents are delivered and the item refuses through the real gate; the `AGENTS.md` and CI applications are pending, the §10 mapping was refused and reverted, and the required schema edit invalidates two frozen populations whose records this batch may not write |
| branch | `staging` |
| HEAD at the start | `69cccd242` (`b7: check eight transparency invariants in a model that can fail`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 41 3 0 1 4` (available **4** GiB); `Swap: 45 45 0` |
| `free -g` before the whole-suite gate | `Mem: 45 42 3 0 1 3` (available **3** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, `HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944` (6 GiB), repository bind-mounted at `/work`; **reused, not restarted** |
| interpreter | CPython 3.11.2 in the court |
| heavy commands | one at a time; no Rust build |

Available memory was below the 24 GiB floor `AGENTS.md` §6.1 sets before a
build. No build was needed or attempted: every gate is Python. The derived cap
`min(8g, available − 16g)` is below the 2 GiB floor, so **no new court was
started**; the existing 6 GiB court was reused and every command ran inside it.
`docker/` was not modified and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/continuous_enforcement.py` | 1,016 | the enforcement: eight stable refusal codes plus `CE_OK`/`CE_REFUSED_USAGE`, the registry/publication/claims/schema/non-claims/wiring checks, ten controls, and the `check`/`controls` CLI |
| `forensics/tools/release_gate.py` | +166 | item 10 `check_transparency`, wired in `evaluate()` after item 9; items 1–9 unchanged; five self-test cases added |
| `evidence/etp/claim.schema.json` | +102 | `$defs/transparency` (closed state and profile enums, two SHA-256 digests, RFC 3339 timestamp), the optional claim property, `authority.kind: public-transparency-log`, and the conditional requirement |
| `forensics/tools/tests/test_continuous_enforcement.py` | 467 | 43 controls: one per refusal code, the publication claim refused, the honest `NOT_ADMITTED` claim accepted, the closed enum, the missing-field case, the regression control, determinism, CLI exits, document synchronisation |
| `forensics/tools/tests/test_release_gate.py` | +71 | five `TransparencyRow` tests for the gate adapter |
| `docs/CONTINUOUS-ENFORCEMENT.md` | 183 | the normative document: problem, gate item, codes, schema field, non-claims, pending applications, regression rule, refusal table, non-claims, `NOT_RUN` |
| `docs/TRANSPARENCY-NON-CLAIMS.md` | 79 | the public non-claims with the record that shows each and the §B.29 clause |
| `forensics/etp8/agents-patch.diff` | 56 | the additive `AGENTS.md` §24, `PENDING_MAINTAINER_APPLICATION` |
| `forensics/etp8/ci-transparency-job.patch` | 40 | the CI job, `PENDING_CREDENTIAL` |
| `forensics/etp8/release-gates-section10-attempt.diff` | 15 | the §10 rows that `earned_trust.py` refused; reverted, kept as the attempt |
| `evidence/b8/build_evidence.py` | 351 | the deterministic producer of the four records |
| `evidence/b8/ENFORCEMENT.json` | 173 | gate item, codes, wiring, before/after counts |
| `evidence/b8/SCHEMA.json` | 51 | field, enum, population (0) and the vacuity note |
| `evidence/b8/PENDING.json` | 35 | the three applications, their state, reason and digest |
| `evidence/b8/CONTROLS.json` | 89 | ten `controlOnly` rows, one per code plus two positives |
| `docs/ETP-TODO.md` | 1 row | the B8 row changed from `TODO` to `PARTIAL` at base `69cccd242`; no other row touched |
| `evidence/b8/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `ENFORCEMENT.json` | `cab362b047280bfce2db1bf9b85cff2a4289bf249b496bf3c7709baeb13f5697` |
| `SCHEMA.json` | `c855d7b9781a92d4a24b491f2d4c97d26e7701efbfe2fb4dff9cd2e7ded989d8` |
| `PENDING.json` | `e8a7baf84cfa0d6232791c71bdb1c234a339467ee1ff1f5a85dd15eb263cfedf` |
| `CONTROLS.json` | `4c858ab1867cfc14e5394daecd092f9247035e81c23575cfb96eb1fd253878db` |
| `agents-patch.diff` | `ae74dcc1b73847447f26af7ab0a03da386a64c0ca36981fd3742126cf5b722eb` |
| `ci-transparency-job.patch` | `885fa58044022741c03a72d7b9629c43a20176cb2a46fca39ac8a8af898888e5` |
| `release-gates-section10-attempt.diff` | `792b252e1bb896592219e1c98ad36c59e25545bec2aade93c6122babb414b17b` |

## 3. The gate before and after

**Before** (`python3 forensics/tools/release_gate.py --json` at `69cccd242` with
item 10 absent): `REFUSED`, **35** rows.

| rule | count |
|---|---:|
| `RG_CLAIM_UNCERTIFIABLE_EVIDENCE` | 19 |
| `RG_CLAIM_HISTORICAL_EVIDENCE` | 11 |
| `RG_INSTRUMENT` | 1 |
| `RG_PACKAGE_MISSING` | 1 |
| `RG_AUTHORISATION_REFUSED` | 1 |
| `RG_THRESHOLD_UNMET` | 1 |
| `RG_POLICY_DENIED` | 1 |

The B8 task statement expected **34**. The observed **35** is recorded, not
smoothed: item 4 refuses `valgrind-ctgrind` with `rc=127` because this venue has
no `valgrind`. That is an environmental refusal, not a defect in the record.

**After** (item 10 present, the documents and records committed to the working
tree): `REFUSED`, **35** rows, the same seven rules, and item 10 records:

```
release-gate: transparency enforcement: 35 claim(s) checked, 0 carry a transparency field, no refusal
```

So the new item is **not** the 35th refusal: it passes and adds **0**. The
task's "new item as the 35th" would require item 10 itself to refuse; it does
not, because the records it checks are present and consistent. The control that
matters is that removing the non-claims document makes item 10 refuse
(`CE_REFUSED_NONCLAIMS_ABSENT`), and the self-test observes exactly that. The
`ENFORCEMENT.json` `after` total is therefore derived as `35 + 0`; the record
says so rather than claiming a second full observation it did not make.

## 4. The schema field and its population

`$defs/transparency`:

```json
{
  "state": "NOT_ADMITTED" | "ADMITTED" | "PUBLISHED",
  "profile": "public-good-rekor-v2",
  "statementDigest": "<sha256>",
  "bundleDigest": "<sha256>",
  "publishedAt": "<RFC 3339 UTC instant>"
}
```

`additionalProperties: false`; both enums are closed; there is no free-text
field. `ADMITTED` requires `profile`, `statementDigest` and `bundleDigest`;
`PUBLISHED` also requires `publishedAt`. A claim whose `authority.kind` is
`public-transparency-log` must carry the field.

**Population: 0 of 35 claims.** No committed claim was rewritten. The schema's
absence requirement therefore has no subject, and `SCHEMA.json` records
`absenceCheck: "VACUOUS"` and `claimsRewritten: 0` rather than reporting the
check as coverage. `etp_claims.py validate` still accepts **35/35 with 0
refusals**, which is the two-direction control that the schema extension did not
change any claim's verdict.

## 5. Controls

`evidence/b8/CONTROLS.json`: **10 `controlOnly` rows, 10 fired, 10 codes
covered**, including the two positives.

| control | wrong behaviour | code observed |
|---|---|---|
| `profile-absent` | the B0 registry path does not exist | `CE_REFUSED_PROFILE_ABSENT` |
| `registry-stale` | `v2.4.2` is replaced by `v9.9.9`, which no clause names | `CE_REFUSED_REGISTRY_STALE` |
| `publication-claim` | a claim asserts `PUBLISHED` while B4 says `published: 0` | `CE_REFUSED_PUBLICATION_CLAIM` |
| `profile-not-admitted` | a claim asserts `ADMITTED` while B4 says `admittedService: false` | `CE_REFUSED_PROFILE_NOT_ADMITTED` |
| `schema-field-absent` | `state: MAYBE` and an undefined `note` field | `CE_REFUSED_SCHEMA_FIELD_ABSENT` |
| `unbound-claim` | an `ADMITTED` claim names neither digest | `CE_REFUSED_UNBOUND_CLAIM` |
| `nonclaims-absent` | the non-claims document path does not exist | `CE_REFUSED_NONCLAIMS_ABSENT` |
| `enforcement-regression` | `def check_transparency(` is renamed, so item 10 has disappeared | `CE_REFUSED_ENFORCEMENT_REGRESSION` |
| `not-admitted-honest` | a positive: `NOT_ADMITTED` adds no refusal | `CE_OK` |
| `usage` | `--not-a-flag` is a usage error | `CE_REFUSED_USAGE` |

The gate self-test adds five cases through the real adapter: the publication
claim refused, the honest `NOT_ADMITTED` positive, a missing registry, a missing
non-claims document and an enforcement regression. `release_gate.py
--self-test` reports **34 cases, ok**.

## 6. Defects found

### 6.1 The task's before-count was one low (recorded, not smoothed)

The observed before-count is 35, not 34, because item 4 refuses
`valgrind-ctgrind` with `rc=127` in this venue. The receipt and
`ENFORCEMENT.json` record 35 and the cause. Old: the expectation "34". New: the
observed 35 with its environment. The record was not edited to match the
expectation.

### 6.2 The schema edit invalidates two frozen populations (recorded, not repaired)

`evidence/a11/SCAN.json` and `evidence/a16/INVENTORY.json` freeze an explicit
population that includes `evidence/etp/claim.schema.json` with a declared
digest (`da2534f6…`), which is exactly the bytes at `HEAD`. The required schema
extension changes those bytes to `3064ccbf…`, so nine pre-existing tests refuse:
eight report `PH_REFUSED_POPULATION_DRIFT` and the ninth fails a direct
population-list digest comparison with the same value.

```
test_harden.ScanTests.test_the_frozen_record_reproduces_at_head
test_harden.CommandLine.test_the_frozen_scan_reports_growth_at_the_frozen_count
test_harden.Evidence.test_the_producer_is_deterministic_and_matches_the_committed_bytes
test_sigstore_bundle.DeterminismAndRecords.test_the_producer_is_deterministic_in_process
test_sigstore_bundle.DeterminismAndRecords.test_two_runs_are_byte_identical_and_match_committed
test_sigstore_bundle.FrozenPopulation.test_the_frozen_population_reproduces_at_this_tree
test_sigstore_bundle.FrozenPopulation.test_the_frozen_population_is_the_candidate_population
test_sigstore_bundle.CommandLine.test_inventory_prints_zero_and_not_run
test_sigstore_bundle.FrozenPopulation.test_the_inventory_command_reports_growth_separately
```

This batch may not write another item's evidence, and a freeze must be bound to a
committed candidate: the schema change is uncommitted, so binding a new digest
to `69cccd242` would be false. The drift is therefore **recorded and retained**
for the orchestrator's commit, not repaired here. The check was not relaxed and
the two records were not edited. This is the reason the whole-suite gate below
is red, and the reason the item is `PARTIAL`.

### 6.3 The first claim check compared `profile` to the digest pattern (repaired here)

The first `check_claims` iterated `(profile, statementDigest, bundleDigest)`
and fed every value to the SHA-256 pattern; a valid `profile` would have been
refused as an unbound claim. Old: one loop with a `name != "profile"` guard that
also checked the profile against the digest pattern. New: the profile is checked
for a non-empty string, the two digests against `$defs/sha256.pattern`. The
defect was found before any record was built; `test_unbound_claim_refused` pins
the corrected behaviour.

### 6.4 Two test-only mistakes (repaired here)

The first test read `population["carrying"]`, a key the tool does not emit (the
tool emits `claimsWithTransparency`), and the document test looked for
`single-edit regression` on a line the markdown wrapped. Both were test defects,
not shipped behaviour; the tests now use the emitted key and a whitespace-
normalised document.

### 6.5 No defect in another item's substantive records

No claim, receipt, atlas or ledger other than the A11/A16 frozen populations
described in §6.2 was found wrong or was modified. The §10 edit is the only
other record-level refusal, and it is §6.6.

### 6.6 The §10 mapping was refused (recorded and reverted)

Four rows for gate items 7, 8, 9 and 10 were added to `docs/RELEASE_GATES.md`
§10, each with "articles it evidences: none". `docs_consistency.py` refused:

```
[docs-consistency] FAIL: 1 earned-trust constitution problem(s)
  STALE: docs/RELEASE_GATES.md: ET_GATE_ITEM_DRIFT the gate table lists ['gate-1', 'gate-10', 'gate-2', 'gate-2b', 'gate-3', 'gate-4', 'gate-5', 'gate-6', 'gate-7', 'gate-8', 'gate-9'] but the record registers ['gate-1', 'gate-2', 'gate-2b', 'gate-3', 'gate-4', 'gate-5', 'gate-6']
```

Registering the items requires editing `evidence/etp-t14/ARTICLES.json`, another
item's constitution record and outside this item's write scope. The edit was
reverted with `git checkout -- docs/RELEASE_GATES.md`; the attempted diff is
kept at `forensics/etp8/release-gates-section10-attempt.diff` and the state is
`PENDING_MAINTAINER_APPLICATION` in `PENDING.json`. The checker was not
weakened.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before the work `Mem: 45 41 3 0 1 4` (available **4** GiB); before the suite `Mem: 45 42 3 0 1 3` (available **3** GiB); `Swap: 45 45 0` |
| 1. court and cap | `docker inspect openssl-rs-court` | `mem=6442450944 memswap=6442450944 status=running` (6 GiB), `/work` bind-mounted; reused, no new court, no build; only one container, `/proc/pressure/io` all `avg10=0.00` |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2482 tests in 486.617s`; **`FAILED (failures=6, errors=3)`**, 0 skipped; the 2,434 pre-existing tests are present and none is ignored; the 48 B8 tests pass. All nine failures concern the changed `evidence/etp/claim.schema.json` digest (§6.2) |
| 2. focused B8 tests | `python3 forensics/tools/tests/test_continuous_enforcement.py` | `Ran 43 tests in 0.328s`; `OK` |
| 2. focused gate tests | `python3 forensics/tools/tests/test_release_gate.py` | `Ran 34 tests in 0.365s`; `OK` |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (after the §10 revert) |
| 3. §10 attempt | same, with the four rows added | `ET_GATE_ITEM_DRIFT`; `DOCS_EXIT=1`; reverted; then exit 0 |
| 4. JSON well-formedness | `python3 -m json.tool` on every created or edited JSON | `ok evidence/etp/claim.schema.json`, `ok evidence/b8/ENFORCEMENT.json`, `ok evidence/b8/SCHEMA.json`, `ok evidence/b8/PENDING.json`, `ok evidence/b8/CONTROLS.json` |
| 5. producer, twice | `python3 evidence/b8/build_evidence.py --out …` twice, then `diff -r` | `BYTE_IDENTICAL`; run 2: `code=CE_OK b8: gateItems=11 codes=9 claims=35 withTransparency=0 before=35 after=35 controls=10 codesCovered=10 coversEveryCode=true pending=3` |
| 5. producer check | `python3 evidence/b8/build_evidence.py --check` | `code=CE_OK b8: check ok files=4`; `CHECK_EXIT=0` |
| 6. gate before | `python3 forensics/tools/release_gate.py --json` at `69cccd242` | `verdict REFUSED refusals 35`; the seven rules in §3 |
| 6. gate after | same, item 10 present | `verdict REFUSED refusals 35`; item 10 records `35 claim(s) checked, 0 carry a transparency field, no refusal` |
| 6. gate self-test | `python3 forensics/tools/release_gate.py --self-test` | `release-gate self-test: ok (34 cases)`; the five transparency cases are `ok` |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `M evidence/etp/claim.schema.json`; `M forensics/tools/release_gate.py`; `M forensics/tools/tests/test_release_gate.py`; `?? docs/CONTINUOUS-ENFORCEMENT.md`; `?? docs/TRANSPARENCY-NON-CLAIMS.md`; `?? evidence/b8/`; `?? forensics/etp8/`; `?? forensics/tools/continuous_enforcement.py`; `?? forensics/tools/tests/test_continuous_enforcement.py` — nothing else |

## 8. Obligations retained

* **The A11/A16 frozen populations must be re-frozen** at the commit that
  carries the schema extension. The drift is nine refused tests, recorded in
  §6.2; repairing it here would write another item's evidence and bind a record
  to an uncommitted candidate.
* **Gate items 7–10 are not registered in the earned-trust record.** The §10
  rows are a pending application; `evidence/etp-t14/ARTICLES.json` still
  registers gate-1..gate-6.
* **`AGENTS.md` is not updated.** The additive §24 is a patch,
  `PENDING_MAINTAINER_APPLICATION`.
* **The CI job is not applied.** The patch is `PENDING_CREDENTIAL`; the tool
  runs in the release gate and the tools suite, not on every push.
* **The schema's absence check is vacuous.** 0 of 35 claims carry the field; no
  claim was rewritten. This is recorded, not reported as coverage.
* **The enforcement-regression rule is a single-edit tripwire.** A coordinated
  removal of the gate, the record, this document and the non-claims can still
  pass.
* **A passing item 10 is not a transparency result.** It establishes that no
  claim outruns B4 and that the machinery is wired, nothing about a service.
* **The controls are control-only.** No real adversarial service was used.

## 9. `NOT_RUN`

* An admitted public transparency log, its key, client and inclusion proofs.
* A witness cosignature admitted from an independent operator.
* A trusted RFC 3161 timestamp.
* A published release, its archival record and release reconciliation.
* An independent party's reproduction or authenticated review.
* An applied `AGENTS.md` section or CI job citing item 10.
* The IETF/transparency-community conformance of the profile.
* `BOUNDARY`, `SEAL` and the Rust suite: no Rust source was modified, so no
  `cargo` command ran.

## 10. Forward-freeze member and worktree

The A17 forward-freeze member `b8-receipt` (`evidence/b8/RECEIPT.md`, predicate
"a receipt records the enforced integration and its non-claims") is
**satisfied**: this receipt names the gate item and its codes, the before/after
counts, the schema field and its zero population, the non-claims, the controls,
the §10 refusal, the two pending applications, the retained obligations and the
`NOT_RUN` list. The freeze itself was not closed, and A20's
`A17.forward-freeze-closed` obligation is unaffected.

**Why `PARTIAL`:** the enforcement is delivered and refuses; but the `AGENTS.md`
and CI applications are pending, the §10 mapping is a documented pending
obligation, the schema absence check is vacuous, and the required schema edit
leaves nine pre-existing frozen-population tests refusing until their records
are re-frozen at the commit. None of those is a `PASS`.

This subagent did not commit and did not push.

## 11. Correction (2026-11-25): regenerated at the rewritten HEAD

**Cause.** The history was rewritten for author identity, so the declared base
`69cccd242` no longer names a commit reachable from any ref; and this tree has
moved since the record was written — `AGENTS.md` gained §24 (the memory-incident
stop-work rule), so `forensics/etp8/agents-patch.diff` no longer applies. The
record's `appliesToWorkingTree` flag said `true`; a run at this tree says `false`.

**Old and new.**

| field | old | new |
|---|---|---|
| `baseCommit` / `refusalCounts.before.observedAt` | `69cccd242` | `2ed2cd79f` |
| `agents-continuous-enforcement.appliesToWorkingTree` | `true` | **`false`** |
| `ci-transparency-job.appliesToWorkingTree` | `true` | `true` |
| `release-gates-section10.appliesToWorkingTree` | `true` | `true` |
| gate items / codes / claims / before / after / controls | 11 / 9 / 35 / 35 / 35 / 10 | unchanged |

| file | old sha256 | new sha256 |
|---|---|---|
| `ENFORCEMENT.json` | `cab362b047280bfce2db1bf9b85cff2a4289bf249b496bf3c7709baeb13f5697` | `a57026329b3171dfadfb194829f3d8706f3a72197544924b5d099705912152f4` |
| `SCHEMA.json` | `c855d7b9781a92d4a24b491f2d4c97d26e7701efbfe2fb4dff9cd2e7ded989d8` | `01b0513426b71b981c809cb39ec1e4683d51ca1573171f2dfc292268ba7fc1ec` |
| `PENDING.json` | `e8a7baf84cfa0d6232791c71bdb1c234a339467ee1ff1f5a85dd15eb263cfedf` | `ee07aa60d10b69a16fceac2f8322128e8d480f6b2d1df52e91736fa5ffa7b88b` |

**What the `false` means.** The flag is the actual `git apply --check` result at
this tree, not an intention. Neither patch was applied. The application is
therefore *not* pending merely because this batch may not edit `AGENTS.md`; it is
pending **and currently non-applying**, which its maintainer must know before
attempting it. The record's own reasons are unchanged and no state is upgraded.

**Failing tests fixed.** At `b26552e21` the committed `PENDING.json` said
`appliesToWorkingTree: true` while a fresh run at this tree said `false`, so
`test_continuous_enforcement.Determinism.test_the_producer_is_byte_identical_and_reproduces_the_records`
and `test_continuous_enforcement.Determinism.test_the_producer_check_exits_zero`
failed. Both pass now; two fresh runs are byte-identical to the committed records
and `build_evidence.py --check` reports `CE_OK`.

**Retained.** The `PARTIAL` state stands: the §10 mapping is still a documented
pending obligation, the schema absence check is still vacuous, and the two
applications are still unapplied. The before/after refusal counts are historical
observations of the gate with item 10 absent; only the commit id they name moved.

## 12. Correction (2026-11-26): the record followed the gate to item 11

**Cause.** `forensics/tools/release_gate.py` gained item 11 (branch audit,
`check_branch_audit`, PFP-34) at `cebb10fae`, after the record was last
regenerated at `0054ee1e9`. The pinned `digests.gate` was the bytes of
`release_gate.py` at `0054ee1e9` (`cc9d0dd2…`); the current file is
`b162b583…`. The record's `gateItems` also enumerated the eleven items that
existed then, so it asserted the gate's item set while omitting item 11. The two
`ProducerAndRecords` determinism tests failed (41/43) on exactly that pinned
digest. The gate at the pinned digest already had items 1–10; the only item
added since is 11, not 7–11.

**What the record is for.** It states that item 10 exists, is wired after item 9,
and refuses; that every gate item in its baseline still has its function and is
called from `evaluate()`; that the transparency codes are unchanged; and that
item 10 adds zero refusals at the base. The first three remain true. The item
enumeration was incomplete, which is a false claim about the gate, not merely a
stale digest, so item 11 was added to the baseline rather than the claim being
dropped.

**Old and new (superseded values preserved).**

| field | old | new |
|---|---|---|
| `gateItems` | 11 (`1,2,2b,3,4,5,6,7,8,9,10`) | **12** (adds `11` branch audit / `check_branch_audit`) |
| `digests.gate` | `cc9d0dd24ac6ccd16ad8be4d557c8cb3c6f2248cf3cc67c7c176bd659db7127b` | `b162d583dcea592134009b1ef2464942ca3cefa87bbdb0131d860e26db1ef7da` |
| `digests.tool` | `d64063271d798cd261c2b586e7f905abff19c478d4577f85e4b284aa99a5871a` | `026495781c1f2da3c540221e2aa6e47f6804f28367df117f27639e47a98bd0a7` |
| `digests.document` | `de0218489b8fda951724be5e3050d0df877256623d06b4441e465d962e83a482` | `626a1059d320fba50a2df70580bea6449d971cc8cd996760d0531d6063af3d76` |
| `digests.schema` / `digests.nonClaims` | `3064ccbf…` / `7c8f1caf…` | unchanged |
| `baseCommit`, `gateItem`, `refusalCodes`, `refusalCounts`, `wiring` | — | unchanged |

| file | old sha256 | new sha256 |
|---|---|---|
| `ENFORCEMENT.json` | `a57026329b3171dfadfb194829f3d8706f3a72197544924b5d099705912152f4` | `add8b0b6bad41c0e75dd2ba4f21720d01d9c5d431f7a5d937947f87e9fcbdf11` |
| `SCHEMA.json` | `01b0513426b71b981c809cb39ec1e4683d51ca1573171f2dfc292268ba7fc1ec` | unchanged |
| `PENDING.json` | `63581cd161831246836e2e3da3464d0a88551bc7bf8e6ea23a33174e2f60c5f5` | unchanged |
| `CONTROLS.json` | `4c858ab1867cfc14e5394daecd092f9247035e81c23575cfb96eb1fd253878db` | unchanged |

The tool and document digests move because `continuous_enforcement.py` gained
the item-11 baseline row and `docs/CONTINUOUS-ENFORCEMENT.md` §2 and §6 now name
items 1–11. No digest is hard-coded in `build_evidence.py`: every one is derived
by `_sha` at generation time, so re-running the producer is the only step a gate
change requires; no producer path or digest fix was needed. The previous §11
PENDING hash `ee07aa60…` was itself superseded at `919360368`; the current value
`63581cd1…` is recorded here.

**Scope of the refusal counts.** `refusalCounts.before` (35 at `2ed2cd79f`) and
`refusalCounts.after` (35 = before + item 10's 0 measured findings) are B8's
historical, item-10-scoped observations and are unchanged. They are **not** a
count of the current gate: with item 11 present the gate observed here reports
**36** refusals — the same eight rows plus `RG_AUDIT_IDENTITY_MISMATCH` 1
(`RG_CLAIM_UNCERTIFIABLE_EVIDENCE` 19, `RG_CLAIM_HISTORICAL_EVIDENCE` 11,
`RG_AUTHORISATION_REFUSED`, `RG_INSTRUMENT`, `RG_PACKAGE_MISSING`,
`RG_POLICY_DENIED`, `RG_THRESHOLD_UNMET`, `RG_AUDIT_IDENTITY_MISMATCH` each 1).

**Finding not repaired here (false, not merely stale).** `PENDING.json`'s
`release-gates-section10` entry still says the §10 rows were refused because
`evidence/etp-t14/ARTICLES.json` registers `gate-1..gate-6` only. That is now
false: at `cebb10fae` `docs/RELEASE_GATES.md` §10 gained `gate-7..gate-11` and
`ARTICLES.json` registers `gate-1..gate-11`; `earned_trust.py check` and
`docs_consistency.py` both accept the mapping, and the attempt diff no longer
applies. The application is therefore superseded, not pending. `docs/ETP-TODO.md`
row B8 repeats the same now-false statement. Both are recorded here as open
rather than regenerated: changing a pending state and another item's ledger row
is outside this enforcement-record correction, and the producer's `state`,
`reason` and `checkerOutput` for that entry are pinned observations, not derived
ones. The §8 and §11 statements that the §10 mapping is pending are superseded
by this section.

**Retained.** `AGENTS.md` was not opened or changed; the two applications remain
unapplied; the schema absence check remains vacuous; the enforcement-regression
rule remains a single-edit tripwire.

**Tests.** `test_continuous_enforcement` 43/43, `test_release_gate` 34/34,
`test_etp_claims` 95/95; `spec_guard.py check`, `docs_consistency.py`,
`earned_trust.py check` clean; the gate itself REFUSED with 36 rows as above.
