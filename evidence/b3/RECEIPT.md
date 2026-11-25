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
