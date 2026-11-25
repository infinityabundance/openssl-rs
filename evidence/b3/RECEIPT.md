# B3 receipt — a campaign may close with failures recorded, not with failures absent

## 1. Identity of this batch

| field | value |
|---|---|
| item | B3 (`docs/ETP-ADDENDUM-B.md` §B.13–B.14, §B.30): campaign opening, amendments, one terminator, omission-sensitive closure and reconciliation |
| status | **`PARTIAL`** — the records, rules, controls and both real campaigns are implemented and gated; the openings are not DSSE-authenticated preregistrations and there is no independent closer |
| branch | `staging` |
| HEAD at the start | `1155843e6` (`b2: nine times, one imprint verifier, and no trusted clock`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 35 6 0 4 10` (available **10** GiB); `Swap: 45 45 0` |
| `free -g` after the suite | `Mem: 45 36 6 0 3 9` (available **9** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944`), repository bind-mounted at `/work`; **reused, not restarted** |
| interpreter | CPython 3.11.2 in the court |
| heavy commands | one at a time; no Rust build |

Available memory was 10 GiB before the work and 9 GiB after the suite, below
the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed or
attempted: every gate is Python. The derived cap `min(8g, available − 16g)` is
negative, so **no new court was started**; the existing 6 GiB court was reused
and every command ran inside it. `docker/` was not modified and no command was
retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/campaign.py` | 1,704 | opening, amendment, announcement and terminator validation, the 17 `AC_REFUSED_*` codes, the five states, reconciliation against an independent plan, 22 controls and the CLI |
| `forensics/tools/tests/test_campaign.py` | 872 | 69 controls: one per refusal code, the omission rule, SKIP/NOT_RUN in a success summary, retroactivity, order, abandonment, plan narrowing, the real campaigns, `CA_`/`AC_` disjointness, determinism, CLI exit codes, document synchronisation |
| `docs/CAMPAIGN-ACCOUNTABILITY.md` | 378 | the normative document: the problem, the opening/amendment/terminator contracts, the exact omission rule, reconciliation, the two real campaigns, the controls, the full refusal table, non-claims, `NOT_RUN`, the enforcement map |
| `evidence/b3/build_evidence.py` | 532 | the deterministic producer of the three records; `--check` recomputes and compares bytes |
| `evidence/b3/CAMPAIGNS.json` | produced | both campaigns with opening, amendments, closure history, terminator (or none), outcomes and state |
| `evidence/b3/RECONCILIATION.json` | produced | each campaign against its independent plan: produced/missing/omitted sets, narrowing, live-view flag |
| `evidence/b3/CONTROLS.json` | produced | 22 `control-only` fixtures, one per refusal code (three codes have two inputs) plus two positive controls, `coversEveryCode: true` |
| `docs/ETP-TODO.md` | 1 row | the B3 row changed from `TODO` to `PARTIAL`; no other row touched |
| `evidence/b3/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `CAMPAIGNS.json` | `540ffddadbde9a4b36409707ac2f82c46f76771922d0511b8956c0e65a4ffe2e` |
| `RECONCILIATION.json` | `c11893c3799534167bc2fc7227b27202124fe853e55eb48248ca78b1f269b26b` |
| `CONTROLS.json` | `6cd1efb5ae5f0c08dbd83364545026a7aa6982689b5f12f1a5a2c5cbb03493dd` |

## 3. The two real campaigns

### 3.1 `etp-programme` — `OPEN`

| field | value |
|---|---|
| opening | the queue in `docs/ETP-TODO.md` at `731b066e2`, the A17 forward freeze's candidate; `openedAt` `2026-11-24T00:20:00Z` = `FREEZE-forward.json#/frozenAt` |
| plan | **86** queue rows, all required (T1–T32, O1–O12, A0–A27, B0–B8, C1–C5) |
| amendments | **16** — one per commit after the base that changed a queue row (A17, A18, A19, A20, A21, A22 twice, A23, A24, A25 twice, A26, A27, B0, B1, B2). `adds`/`removes`/`supersedes` are derived from the queue text; `at`, `by` and `reason` are the commit's date, author and subject |
| terminator | **none** |
| outcomes | none (there is no closure) |
| state | **`OPEN`** |

The reopening is not presented as a closure: `closure` and `abandonment` are
both `null`, `campaign.py status` prints `code=AC_OPEN`, and the record's `note`
says the programme is not closed. The reconciliation against the A17 forward
freeze reports **15 produced, 5 missing** (`b4-receipt`–`b8-receipt`),
**0 omitted**, **not narrowed**, `liveView: true`. That is a live observation at
the base, not a closure of `FREEZE-forward.json`; the freeze remains `OPEN`.

### 3.2 `a22-adversarial-qualification` — `CLOSED_CLEAN`

| field | value |
|---|---|
| opening | `2026-11-24T09:47:33-05:00`, the A22 item's recorded start commit `6e64e644c`; **reconstructed** from `EXPERIMENTS.json`, not an authenticated preregistration |
| plan | **8** checks, E1–E8, all required |
| amendments | **0** (the plan did not change; the repair changed observations) |
| closure history | **1** earlier closure at `d3050312f`: 6 `PASS` / 1 `FAIL` (E5 `DEFECT`) / 1 `SKIP` (E6 `PARTIAL`), `claimsSuccess: false`, `codes=AQ_DEFECT_FOUND` |
| terminator | closure at `2026-11-24T11:20:19-05:00` (`7c2b5f25f`), from `RESULTS.json` re-measured at `e4029e0d5` |
| outcomes | **8 `PASS`, 0 `FAIL`, 0 `SKIP`, 0 `NOT_RUN`** |
| state | **`CLOSED_CLEAN`** |

The old `DEFECT` and `PARTIAL` are **preserved**: the earlier closure is in
`closureHistory`, and every final outcome carries its earlier result in its
`history`. `test_the_earlier_defect_and_partial_are_preserved` asserts E5
`FAIL → PASS` and E6 `SKIP → PASS`; `test_neither_real_campaign_invented_an_outcome`
re-derives every final result from `evidence/a22/RESULTS.json`.

Reconciliation against the eight experiment ids from `EXPERIMENTS.json`:
**8 produced, 0 missing, 0 omitted, not narrowed**, `liveView: false`.

## 4. Controls

`CONTROLS.json`: **22 `control-only` fixtures, 22/22 fired, `coversEveryCode:
true`**, plus two positive controls. One code
(`AC_REFUSED_NO_TERMINATOR`, `AC_REFUSED_ORDER`, `AC_REFUSED_MANIFEST_INVALID`)
has two controls because two different wrong inputs reach it.

| control | code observed | required by the item |
|---|---|---|
| `omitted-check` | `AC_REFUSED_OMITTED_CHECK` | a closure that omits a failed check |
| `failure-omitted` | `AC_REFUSED_FAILURE_OMITTED` | success while a `FAIL` is recorded |
| `skip-as-pass` | `AC_REFUSED_SKIP_AS_PASS` | a `SKIP` called a pass |
| `not-run-as-pass` | `AC_REFUSED_NOT_RUN_AS_PASS` | a `NOT_RUN` counted as a pass |
| `retroactive-amendment` | `AC_REFUSED_RETROACTIVE_AMENDMENT` | a retroactive amendment |
| `double-terminator` | `AC_REFUSED_DOUBLE_TERMINATOR` | two terminators |
| `unplanned-outcome` | `AC_REFUSED_UNPLANNED_OUTCOME` | an unplanned outcome |
| `duplicate-outcome` | `AC_REFUSED_DUPLICATE_OUTCOME` | a duplicate outcome |
| `abandonment-silent` | `AC_REFUSED_ABANDONMENT_SILENT` | a silent abandonment |
| `order-terminator`, `amendment-after-terminator` | `AC_REFUSED_ORDER` | an out-of-order terminator |
| `plan-narrowed` | `AC_REFUSED_PLAN_NARROWED` | a narrowed plan |
| `no-opening`, `double-opening`, `no-terminator`, `claimed-closed-without-terminator`, `unbound-amendment`, `count-mismatch`, `manifest-invalid`, `unknown-result` | their codes | the remaining vocabulary |
| `positive-closed-with-failures` | none (`CLOSED_WITH_FAILURES`) | a recorded failure is accepted |
| `positive-closed-clean` | none (`CLOSED_CLEAN`) | the decision procedure |

The `AC_` vocabulary is disjoint from A5's `CA_`;
`test_the_two_modules_do_not_share_a_code` asserts that neither module emits the
other's prefix and that A5 still exposes at least ten `CA_` codes, so the test
cannot pass vacuously.

## 5. Defects found

**No defect in an existing record was found or contradicted.** The producer read
`evidence/a17/FREEZE-forward.json`, `evidence/a17/STATUS.json`,
`docs/ETP-TODO.md` at `731b066e2`, `evidence/a22/{EXPERIMENTS,RESULTS}.json`, the
A22 receipt §11 and the git history of `docs/ETP-TODO.md`. `RESULTS.json` records
8 qualified at `e4029e0d5`; the receipt §11 records the earlier 6/1/1 with the
old digests; the two agree, and both are preserved. No existing file was edited
and no check was relaxed.

**Development defects in this item's own machinery**, preserved because a
refusal that fires for the wrong reason is the defect this item exists to catch:

1. **`OPEN` and `AC_REFUSED_NO_TERMINATOR` collided on the first design.** A
   campaign with no terminator was both the programme's honest state and a
   refusal. Old: `validate()` refused every unterminated campaign, which would
   have made the only real open campaign invalid. New: an opening with no
   terminator is a valid `OPEN` record; `AC_REFUSED_NO_TERMINATOR` fires when
   the caller requires a finished record (`require_terminator=True`) or when the
   record *claims* a terminal state without one. Both paths are controlled.
2. **The first out-of-order control observed `AC_REFUSED_UNBOUND_AMENDMENT`.**
   The fixture amendment was dated after the closure but bound to nothing, so
   the binding rule fired first. Old: the control did not exercise order. New:
   the fixture supersedes `C1`, and the order rule fires as intended. The
   precedence is now stated: binding, then order, then retroactivity.
3. **The first queue parser accepted table headers as check ids.** `| item |`
   and `| id |` satisfied a permissive "starts with a letter" test, so the
   programme plan would have carried phantom checks. Old: 88 rows including
   `item`/`id`. New: a queue id must match `^[A-Z]{1,4}[0-9]+[a-z]?$`; the plan
   is 86 rows and the reconciliation's omitted set is empty for the right
   reason.

A22's refresh is not a defect in this item: its receipt §11 already records the
old verdicts and digests, and B3 preserves them in `closureHistory` and in each
outcome's `history`. Nothing in A22's files was edited.

## 6. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before: `Mem: 45 35 6 0 4 10` (available **10** GiB), `Swap: 45 45 0`; after: `Mem: 45 36 6 0 3 9` (available **9** GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect openssl-rs-court` | `HostConfig.Memory` and `MemorySwap` both `6442450944` (6 GiB), `Up 44 hours`, `/work` bind-mounted; reused, no new court, no build |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2207 tests in 453.590s`; `OK`; `closure discipline self-test: 7 control groups passed`. The **2,138 pre-existing tests are present** (2,138 + 69 = 2,207), none removed, none ignored |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on each created JSON | `json.tool ok evidence/b3/CAMPAIGNS.json`; `json.tool ok evidence/b3/RECONCILIATION.json`; `json.tool ok evidence/b3/CONTROLS.json` |
| 5. producer, twice | `python3 evidence/b3/build_evidence.py --out /tmp/b3a` and `--out /tmp/b3b` | both exit 0; `identical CAMPAIGNS.json`; `identical RECONCILIATION.json`; `identical CONTROLS.json` — run 1, run 2 and the committed bytes are **byte-identical** |
| 5. producer output | the same run | `code=AC_OK b3: base=1155843e6 campaigns=2`; `b3: campaign=etp-programme state=OPEN planned=86 amendments=16 pass=0 fail=0 skip=0 notRun=0`; `b3: campaign=a22-adversarial-qualification state=CLOSED_CLEAN planned=8 amendments=0 pass=8 fail=0 skip=0 notRun=0`; `b3: reconcile=etp-programme narrowed=false produced=15 missing=5 omitted=0`; `b3: reconcile=a22-adversarial-qualification narrowed=false produced=8 missing=0 omitted=0`; `b3: controls=22 coversEveryCode=true` |
| 5. producer check | `python3 evidence/b3/build_evidence.py --check` | `code=AC_OK b3: check ok records=3`; exit 0 |
| 6. CLI status | `python3 forensics/tools/campaign.py status` | `campaign=etp-programme state=OPEN code=AC_OPEN planned=86 required=86 amendments=16`; `campaign=a22-adversarial-qualification state=CLOSED_CLEAN code=AC_CLOSED_CLEAN planned=8 required=8 amendments=0 accounted=8 pass=8 fail=0 skip=0 notRun=0`; `STATUS_EXIT=0`. **No refusal code fires.** |
| 6. CLI reconcile, programme | `campaign.py reconcile --campaign … --plan evidence/a17/FREEZE-forward.json` | `code=AC_OK campaign=etp-programme state=OPEN narrowed=false produced=15 missing=5 omitted=0`; `missing=b4-receipt,b5-receipt,b6-receipt,b7-receipt,b8-receipt`; exit 0 |
| 6. CLI reconcile, A22 | `campaign.py reconcile --campaign … --plan <eight experiment ids>` | `code=AC_OK campaign=a22-adversarial-qualification state=CLOSED_CLEAN narrowed=false produced=8 missing=0 omitted=0`; exit 0 |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/CAMPAIGN-ACCOUNTABILITY.md`; `?? evidence/b3/`; `?? forensics/tools/campaign.py`; `?? forensics/tools/tests/test_campaign.py` — nothing else |

The full discovery ran on the final tree, after the code, document and
queue-row edits; only this receipt's gate notes were written afterwards, and
that text changes no code path or test. No test was removed, skipped, ignored or
weakened.

## 7. Obligations retained

* **An opening is not authenticated.** The campaign records are canonical JSON;
  they are not DSSE envelopes, carry no transparency-log inclusion, and have no
  timestamp. A signature over an opening would prove byte integrity, not that
  the plan was chosen honestly.
* **The producer is the validator.** The same module produces and checks the
  records. An independent closer did not run (`AGENTS.md` §15).
* **A plan is only as good as its opening.** Reconciliation detects omission
  against an independent plan; it does not establish that either plan contained
  every check that mattered.
* **`PASS` is a recorded result.** It is not a safety, compatibility or
  cryptographic finding, and a clean closure is not a success claim about the
  subject.
* **The programme campaign is `OPEN`.** It has no terminator, no closure and no
  outcomes; its reconciliation is a live observation, not a closure of the A17
  freeze.
* **A22's opening is reconstructed.** The plan text is from `EXPERIMENTS.json`
  and the opening instant from the item's recorded start commit; it is an
  accountable summary of A22's records, not a preregistration.
* **The recorded times are declared literals.** The producer reads no clock, so
  the ordering checks detect an inconsistent declared order, not wall-clock
  order.

## 8. `NOT_RUN`

* A DSSE-authenticated opening, a transparency-log inclusion and a trusted
  timestamp: **none exists** here (B1/B4/B5 are the relevant items).
* An independent closer or reviewer: **none ran**.
* Closure of the A17 forward freeze: it remains `OPEN` with no reconciliation;
  B3 reports a live produced/missing view and does not write
  `evidence/a17/RECONCILIATION-*`.
* BOUNDARY, SEAL and the Rust suite: not run; no Rust source was modified, so no
  `cargo` command and no Rust result is claimed.
* A real external campaign: both campaigns are reconstructed from records in
  this tree; no external operator's campaign was admitted.

## 9. Forward-freeze member and worktree

The A17 forward freeze member `b3-receipt` (`evidence/b3/RECEIPT.md`, predicate
"a receipt records the campaign opening, amendments and omission-sensitive
closure") is **satisfied**: this receipt and `CAMPAIGNS.json` record one open
campaign with 16 amendments and one closed campaign with 8 `PASS`, and the
closure rule is enforced by 17 refusal codes and 22 controls. The member now
appears in the reconciliation's `produced` set; the freeze itself was not
closed.

Worktree after this batch: `M docs/ETP-TODO.md`; `?? docs/CAMPAIGN-ACCOUNTABILITY.md`;
`?? evidence/b3/`; `?? forensics/tools/campaign.py`;
`?? forensics/tools/tests/test_campaign.py`. Nothing else. This subagent did not
commit and did not push.

## 10. Correction (2026-11-24, found by B5): the reconciliation is frozen at a declared commit

**Found by B5.** B5 ran the whole tools suite and reported `Ran 2308 tests` /
`FAILED (failures=2)`, both in `test_campaign.Determinism`:

* `test_the_committed_records_equal_a_fresh_run` — the fresh run listed
  `b4-receipt` and `b5-receipt` as missing where the committed record did not,
  so `RECONCILIATION.json` differed;
* `test_the_producer_check_mode_accepts_the_committed_bytes` —
  `code=AC_REFUSED_MANIFEST_INVALID` / `b3: stale record(s): RECONCILIATION.json`.

**Cause.** The old `reconcile()` resolved every declared path against the
**working tree** and the producer passed `live=True` for the programme campaign.
The record therefore held a live set captured at production time while claiming
`asOf: 1155843e6`: it listed `b4-receipt` as missing although
`evidence/b4/RECEIPT.md` is tracked. Once B4 and B5 landed, the set changed and
the committed bytes stopped reproducing. This is the fifth instance of a
recorded live measurement (A7's live `HEAD`, A11's and A16's live globs, A17's
live count, now B3's live set). The record had a hidden live input, which §0
forbids; the defect was the binding, not the counts.

**Old record.** `RECONCILIATION.json` sha256
`c11893c3799534167bc2fc7227b27202124fe853e55eb48248ca78b1f269b26b`: top-level
`asOf` and `baseCommit` both `1155843e6`, `liveView: true` for the programme
record, **15 produced / 5 missing**. The 15th produced member, `b3-receipt`, was
present only because the working tree already contained this receipt, which the
commit `1155843e6` does not.

**New contract.**

1. A record is bound to a **declared commit**. `reconcile(..., as_of=...,
   tree=...)` resolves each declared **path** from `tree`, which the producer
   obtains with `git ls-tree -r --name-only <asOfCommit>` (a plan member with no
   path is still read from the campaign's recorded outcomes); the working tree is
   not an input. `asOfCommit` is recorded as the resolved full commit id.
2. The declared commit is an explicit input. `build_evidence.py --as-of <commit>`
   changes it; without the flag the producer reuses the commit already recorded
   (`asOfCommit`, or the old `asOf` on the first run), else `1155843e6`. A later
   evidence commit therefore cannot move the record.
3. A live view is a **separate command**: `campaign.py reconcile --live` reports
   the working-tree set, prints `state=LIVE`, and refuses `--out`; it writes
   nothing. A reconcile with neither `--as-of` nor `--live` is a usage error, so
   a live-looking record cannot be produced by accident.

**New fields.** Top level: `asOfCommit` (full commit id) replaces `asOf`, and
`resolvedFrom: "git ls-tree -r --name-only"` names the mechanism. Each record:
`asOfCommit`, `liveView: false`, and a `record` string that says the view is
frozen -- naming the commit tree for a path-based plan and the recorded outcomes
for an outcome-based one -- and that absence of a later member is not a finding
that it is missing.

**New record.** `RECONCILIATION.json` sha256
`547f3403d63662e5030e54d8de8aa5eeff70e29ae0a68743096f3b1a9c632821`:
**14 produced / 6 missing** at `asOfCommit`
`1155843e6fca64704183f6b7d71b2df5b60652ff` — A18–A27 receipts, B0's two members,
B1 and B2. The six missing are `b3-receipt`–`b8-receipt`. `evidence/b3/RECEIPT.md`
was committed at `dc5855733`, `evidence/b4/RECEIPT.md` at `24ac742f5`, and
`evidence/b5/RECEIPT.md` at `28ae5ff59`; they are absent from the record because
it is frozen at `1155843e6`, **not** because they are missing. The programme
campaign remains `OPEN` with no terminator, the A17 forward freeze remains
`OPEN`, and the record is not a closure of it. `reconcile --live` on the current
working tree reports 17 produced / 3 missing (`b6`–`b8`) and `state=LIVE`.

**Growth control.** `test_the_committed_record_is_unchanged_when_a_later_member_lands`
mirrors the declared members into a temporary directory, appends a synthetic
`zz-later` member to both the plan and the mirror, and asserts that the frozen
report still reproduces the committed record and lists `zz-later` as missing,
while the live view produces it; `RECONCILIATION.json` is byte-unchanged after
the run. `test_a_later_commit_tree_reports_members_the_record_does_not` uses a
later commit's real tree: `evidence/b4/RECEIPT.md` is in `HEAD`'s tree and not in
`1155843e6`'s, and the later view produces `b4-receipt` where the record does
not. `test_a_later_as_of_moves_the_temporary_view_not_the_record` runs the
producer with `--as-of HEAD` into a temporary directory and confirms the
committed bytes do not move.

**Document correction.** `docs/CAMPAIGN-ACCOUNTABILITY.md` §6, §7.1 and
`NOT_RUN` described produced/missing as a live observation with
`liveView: true`. Those sentences now state that the record is frozen at
`asOfCommit`, that a later member is absent because the record is frozen rather
than missing, and that the live view is a separate, unwritten command. The
enforcement map gains the `ReconciliationFreeze` row.

**Preserved.** No `AC_REFUSED_*` code, state, refusal, control or campaign
outcome was changed or relaxed; only the binding moved. `CONTROLS.json` is
byte-identical, which is the check that no control was weakened.
`CAMPAIGNS.json` changed only in `tool.sha256`, because `campaign.py` changed.
The programme campaign is still `OPEN` and the A22 closure still records
8 `PASS` with its earlier 6/1/1 in `closureHistory`.

**Gates re-run for this correction** (all in the reused 6 GiB
`openssl-rs-court`, one command at a time; host `free -g` reported available
**7 GiB** and swap `45/45`, so no build ran):

| gate | command | result |
|---|---|---|
| unit controls | `python3 -m unittest forensics/tools/tests/test_campaign.py` | `Ran 79 tests`; `OK` (69 before, 10 added) |
| whole discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2318 tests in 458.492s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 2,308 parent tests are present (2,308 + 10 = 2,318), none removed, none ignored |
| producer, twice | `build_evidence.py --out /tmp/b3a` and `--out /tmp/b3b --as-of <full>` | both exit 0; `code=AC_OK b3: base=1155843e6 asOfCommit=1155843e6fca64704183f6b7d71b2df5b60652ff (from default)`; `identical CAMPAIGNS.json`; `identical RECONCILIATION.json`; `identical CONTROLS.json`; each also `committed-identical` |
| producer check | `build_evidence.py --check` | `code=AC_OK b3: check ok records=3` |
| frozen vs live | `campaign.py reconcile … --as-of <full>` / `… --live` | frozen: `state=OPEN view=frozen asOf=1155843e6… produced=14 missing=6 omitted=0`, `missing=b3-receipt,…`; live: `state=LIVE campaignState=OPEN view=working-tree produced=17 missing=3`, `missing=b6-receipt,b7-receipt,b8-receipt`; neither flag: `code=AC_USAGE`, exit 2 |
| growth control | mirrored tree plus a synthetic `zz-later` member | `committed record unchanged: True`; `frozen … produced=14 missing=7 zz in missing=True`; `live … produced=21 missing=0 zz in produced=True liveView=True` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; exit 0 |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; exit 0 |
| JSON well-formedness | `python3 -m json.tool` on each record | `json.tool ok` for `CAMPAIGNS.json`, `RECONCILIATION.json`, `CONTROLS.json` |

**Digests.**

| file | old sha256 | new sha256 |
|---|---|---|
| `RECONCILIATION.json` | `c11893c3799534167bc2fc7227b27202124fe853e55eb48248ca78b1f269b26b` | `547f3403d63662e5030e54d8de8aa5eeff70e29ae0a68743096f3b1a9c632821` |
| `CAMPAIGNS.json` | `540ffddadbde9a4b36409707ac2f82c46f76771922d0511b8956c0e65a4ffe2e` | `e6d3dd5dffbd73367e96313253932d688894ad949ade21cf86bb21da330d2fd8` |
| `CONTROLS.json` | `6cd1efb5ae5f0c08dbd83364545026a7aa6982689b5f12f1a5a2c5cbb03493dd` | `6cd1efb5ae5f0c08dbd83364545026a7aa6982689b5f12f1a5a2c5cbb03493dd` (unchanged) |

**Retained.** The correction establishes that the record is reproducible from its
declared commit; it does not authenticate that commit, close the A17 freeze, or
make the opening a preregistration. `PARTIAL` is unchanged.

## 11. Correction (2026-11-25): the record is regenerated against the rewritten history

**Cause.** The history was rewritten for author identity: every commit id from
Phase 5.5 onward changed, and each rewritten commit's **author** is now
`infinityabundance <rdebeer.infinityabundance@gmail.com>` where it had been
`openssl-rs <dev@openssl-rs.invalid>`. This record's amendment list is *derived*
from those commits (author, author date, subject), so the hand edit at
`b26552e21` that replaced sixteen `by` values was superseded by regeneration:
a producer run reproduced `openssl-rs <dev@openssl-rs.invalid>`, which is not the
history that now exists.

**Old and new.**

| field | old | new |
|---|---|---|
| `baseCommit` / `baseCommitLong` | `1155843e6` / `1155843e6fca64704183f6b7d71b2df5b60652ff` | `5b2b7a73e` / `5b2b7a73e7dc9c265d704f844756d3bec542eb38` |
| `RECONCILIATION.json#/asOfCommit` | `1155843e6fca64704183f6b7d71b2df5b60652ff` | `5b2b7a73e7dc9c265d704f844756d3bec542eb38` |
| programme `source.base` (the A17 freeze candidate) | `731b066e261ebc64cf8acb909df18d23b9b11883` | `4885151952a3342cab57311290051a65e42c0659` |
| A22 `source.base`, first record, re-record | `6e64e644c`, `d3050312f`, `7c2b5f25f` | `cb40caf0c`, `b3a7c079a`, `94e7b5f6a` |
| A22 repair commit (`A22_MEASURED_AT`) | `e4029e0d5` | `372a6644f` |
| sixteen amendment `reason` commit hashes | pre-rewrite ids | the rewritten ids |
| sixteen amendment `at` values | 2026-11-24 … | unchanged (author dates) |

| file | old sha256 | new sha256 |
|---|---|---|
| `CAMPAIGNS.json` | `385c920c25ddfb4c4d1fcd7d1593e627780cd5f63c8da2c640bf1d3c20a433d2` | `544ba83f4d00f7677907020b51ec34521808fff8f6f0a9f3dec775667c7d2b92` |
| `RECONCILIATION.json` | `547f3403d63662e5030e54d8de8aa5eeff70e29ae0a68743096f3b1a9c632821` | `a44cb3921ce6a884a0e94679925685413d83a3bed55b6069c11aab5e602ed933` |
| `CONTROLS.json` | `6cd1efb5ae5f0c08dbd83364545026a7aa6982689b5f12f1a5a2c5cbb03493dd` | unchanged |

**What changed in the producer.** All commit constants moved to the rewritten
ids, and the two prose references inside the producer (`731b066e2`, `e4029e0d5`,
`commit 6e64e644c`) moved with them. `commit_time` now reads the **author date**
(`%aI`) rather than the committer date: the rewrite reset every committer date to
2026-11-25T02:30:21, so `%cI` would have replaced every amendment's recorded time
with the rewrite instant. The author dates are preserved and are exactly the
values the record already carried. Nothing about a campaign's state, plan,
outcomes or counts changed: both campaigns validate to `OPEN` and
`CLOSED_CLEAN`, with 16 amendments, 86 planned rows and 8/0/0/0.

**Failing tests fixed.** At `b26552e21` a fresh run of the committed producer did
not equal the committed bytes: it wrote `by: openssl-rs <dev@openssl-rs.invalid>`
where the hand-edited record said `infinityabundance <…>`. That made
`test_campaign.Determinism.test_the_committed_records_equal_a_fresh_run` and
`test_campaign.Determinism.test_the_producer_check_mode_accepts_the_committed_bytes`
fail. Both pass now, and two fresh runs are byte-identical to the committed
records.

**Retained.** The reconciliation is still not a closure of the A17 forward freeze,
which remains `OPEN`; `produced=14 / missing=6` is unchanged. A17's own records
still name the pre-rewrite id `731b066e2` for the same freeze: A17 regenerates
byte-identically and is outside this batch's write scope, so the two ids are the
same tree under two commit objects. That is recorded as a residual, not masked.

## 12. Correction (2026-11-25): re-bind the A22 closure evidence after C13

**Cause.** A22's records were regenerated at `2476a6ceafb4` (C13) inside A22's
declared venue. The A22 closure's `outcomes[*].evidence` binds the digest of
`evidence/a22/RESULTS.json`, so the eight bindings moved from the pre-C13 record
to the current one. The record was re-derived by `evidence/b3/build_evidence.py`
at C14 with its default flags (the declared base and `asOfCommit` are unchanged,
because the producer's own contract says a later evidence commit does not move
the base the record is *about*), not hand-edited.

**Old and new.**

| field | old | new |
|---|---|---|
| `campaigns[a22].closure.outcomes[0..7].evidence` digest | `976ecee77d13e5ab11ae78426c0cff3835a5de4bc25d2dcbbc2a035ca768ddde` | `db49003319376aa633aea9898fb9599097ae6f496ec5f6ff661cb547dfba7a1c` |
| `CAMPAIGNS.json` | `544ba83f4d00f7677907020b51ec34521808fff8f6f0a9f3dec775667c7d2b92` | `763ec8471daa48e72e1058ae410397eb7798064bc8329e838dc80373df877fba` |
| `RECONCILIATION.json` | `a44cb3921ce6a884a0e94679925685413d83a3bed55b6069c11aab5e602ed933` | byte-identical |
| `CONTROLS.json` | `6cd1efb5ae5f0c08dbd83364545026a7aa6982689b5f12f1a5a2c5cbb03493dd` | byte-identical |

**Outcome unchanged.** Both campaigns validate to the states they claimed:
`etp-programme` stays `OPEN` with 86 planned rows and 16 amendments; the A22
campaign stays `CLOSED_CLEAN` with `planned=8`, `pass=8`, `fail=0`, `skip=0`,
`notRun=0`. The reconciliations are unchanged (`produced=14 / missing=6` for the
programme, `produced=8 / missing=0` for A22); neither narrows or omits its plan.
Only the eight digest bindings moved. The earlier closure (`6 qualified / 1 defect
/ 1 partial`) and the first-record digest `4509870…` remain preserved in
`closureHistory` and in each outcome's `history`, exactly as before.

**History.** The pre-C13 A22 digest `976ecee7…` is recorded above rather than
erased; the record's per-outcome `history` continues to preserve the earlier
observation. Nothing about a campaign's plan, state or counts changed.

**Gates.** `python3 evidence/b3/build_evidence.py` reproduces the committed bytes
and prints `campaign=a22-adversarial-qualification state=CLOSED_CLEAN planned=8
pass=8`; `--check` reports `AC_OK`; `test_campaign` is 79/79 OK.
