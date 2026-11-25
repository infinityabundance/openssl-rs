# B5 receipt — a monitor is not a witness

## 1. Identity of this batch

| field | value |
|---|---|
| item | B5 (`docs/ETP-ADDENDUM-B.md` §B.7, §B.11–§B.12, §B.30): persistent checkpoint state, consistency verification and monitoring, independent witnesses admitted when available, split-view controls |
| status | **`PARTIAL`** — the monitoring half is implemented, controlled and ran offline against the B1 fixture's real checkpoint sequence; **witness admission is `NOT_RUN`** (0 witnesses, 0 quorum, 0 independent domains) |
| branch | `staging` |
| HEAD at the start | `24ac742f5` (`b4: classify before publishing, and publish nothing yet`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 37 4 0 4 8` (available **8** GiB); `Swap: 45 45 0` |
| `free -g` before the last suite | `Mem: 45 38 4 0 4 7` (available **7** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, `HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944` (6 GiB), repository bind-mounted at `/work`; **reused, not restarted** |
| interpreter | CPython 3.11.2 in the court |
| heavy commands | one at a time; no Rust build |

Available memory was below the 24 GiB floor `AGENTS.md` §6.1 sets before a
build. No build was needed or attempted: every gate is Python. The derived cap
`min(8g, available − 16g)` is negative, below the 2 GiB floor, so **no new court
was started**; the existing 6 GiB court was reused and every command ran inside
it. `docker/` was not modified and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/monitor.py` | 1,219 | the store, observation, status/audit, witness admission and the `observe`/`status`/`monitor`/`witness` CLI; 15 `MN_REFUSED_*` codes plus `MN_OK` |
| `forensics/tools/tests/test_monitor.py` | 846 | 52 controls: one per refusal code, the fixture sequence, each corrupted sequence, each accepting canary, store tamper, witness aliasing, the empty set refused for admission but not observation, determinism, CLI exit codes, document synchronisation |
| `docs/TRANSPARENCY-MONITORING.md` | 344 | the normative document: what monitoring can and cannot establish, the store and its tamper evidence, the rules and their order, the witness contract, the real run, the controls, the refusal table, non-claims, `NOT_RUN` |
| `evidence/b5/build_evidence.py` | 1,289 | the deterministic producer of the three records and the store; `--check` recomputes and compares bytes |
| `evidence/b5/MONITOR.json` | 251 | the accepted sequence, final head, store identity, the five corrupted controls with canaries, witness inventory |
| `evidence/b5/WITNESSES.json` | 72 | the empty inventory, the three checks that establish 0 witnesses / 0 quorum / 0 domains, the required quorum and the aliasing rule |
| `evidence/b5/CONTROLS.json` | 371 | 16 `controlOnly` rows, one per refusal code plus a positive |
| `evidence/b5/store/monitor-store.jsonl` | 3 | the append-only checkpoint store (one record per observation) |
| `docs/ETP-TODO.md` | 1 row | the B5 row changed from `TODO` to `PARTIAL`; no other row touched |
| `evidence/b5/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `MONITOR.json` | `45608b109ac36a339d7fdc2a86eb0b45eb61192128257fc57f6f0fc57a92683d` |
| `WITNESSES.json` | `10147872b9ca4f27457b997243b3e1491699e05e530afa5dfd810f1444134416` |
| `CONTROLS.json` | `a4195494e4dd6e25c1dd24d09c1f39ccce39a969ffca93a224901731b81d5564` |
| `store/monitor-store.jsonl` | `08db31ac2292c11fb93cd4d5169a8823461dac9564a12b5e82900c91b4ae7c5b` |

## 3. The monitored sequence and its controls

### 3.1 The store

`evidence/b5/store/monitor-store.jsonl` is one JSON record per line, in
observation order. Each record carries the six required fields — `origin`,
`treeSize`, `rootHash`, `signature`, `observedAt`, `source` — plus `noteSha256`
(the exact signed note), `seq`, `prev` and `digest`. `digest` is SHA-256 over
the canonical JSON of every other field; `prev` is the previous digest (64 zeros
for the first). Editing a field, dropping a record, reordering two or splicing
one in changes a digest or a link and is `MN_REFUSED_STORE_TAMPERED`. A
self-consistent rewrite is still refused by the semantic audit (non-decreasing
size, one root per size, one origin, non-decreasing observation time).

### 3.2 The real run

The B1 fixture `FIXTURE-1`'s real checkpoint sequence was observed in order:

| observation | instant | size | proof used | result |
|---:|---|---:|---|---|
| 1 | `2026-11-24T00:00:01Z` | 2 | none (first) | `MN_OK` |
| 2 | `2026-11-24T00:00:02Z` | 5 | `consistency-2-5.json` (2 elements) | `MN_OK`, consistency verified |
| 3 | `2026-11-24T00:00:03Z` | 6 | `consistency-5-6.json` (3 elements) | `MN_OK`, consistency verified |

Final head: origin `FIXTURE-1`, size **6**, root
`e9a8ad0126e834c0ec34fed464572772d3f3c2d3501198239a1a5554324c540f`. Status:
**3 observations**, accepted size 6, chain verified. The store is 1,665 bytes,
3 records, digest `08db31ac…7c5b`.

The checkpoint body, the note signature and the RFC 6962 consistency proof are
reused from `forensics/tools/tlog.py`; the note format, hashing and recursion
are not reimplemented. The signer is A10's test-only HMAC-SHA256 key, not a log
key.

### 3.3 The corrupted sequence

Built in memory from the real fixture bytes. Each refuses with its code, and
each carries an accepting canary with the named check disabled:

| control | code observed | canary |
|---|---|---|
| size-2 checkpoint after the size-6 head | `MN_REFUSED_ROLLBACK` | accepted with the rollback comparison disabled |
| same size, alternative signed root | `MN_REFUSED_SPLIT_VIEW` | accepted with the split-view comparison disabled |
| checkpoint from `OTHER-LOG` | `MN_REFUSED_ORIGIN` | accepted with the origin comparison disabled |
| backdated size-6 replay | `MN_REFUSED_BACKDATED` | accepted with the backdating comparison disabled |
| flipped byte in the store's chained digest | `MN_REFUSED_STORE_TAMPERED` | read and reported with the store check disabled |

`CONTROLS.json` adds `MN_REFUSED_SIGNATURE` (forged signature),
`MN_REFUSED_INCONSISTENT` (corrupted 2→6 proof), `MN_REFUSED_CHECKPOINT` (signed
size-0 head with a non-empty root), the four witness refusals, `MN_REFUSED_IO`
and `MN_REFUSED_USAGE`, plus a positive row. 16 rows, 13 accepting canaries.
Three cannot accept and say why: an empty witness set (the next refusal is the
quorum), an unreadable path, and a malformed invocation. A malformed checkpoint
body is additionally exercised as an *attribution* canary: disabling signature,
origin and root-validity still refuses `MN_REFUSED_CHECKPOINT`, because the
parse is what makes every other check possible.

### 3.4 Witness inventory

**0 witnesses, 0 quorum, 0 independent domains.** Each is established by a named
check:

* **0 witnesses** — every signed note in `evidence/b1/fixture` carries exactly
  one signature line, none a cosignature (`tlog.parse_signed_checkpoint`); the
  B1 fixture is labelled `no-witness`; `WITNESSES.json#/witnessSet` is empty.
* **0 quorum** — the required quorum is k=3 of n=4 on the §B.11 model;
  `thresholds.available_domain_count` over the empty witness domain inventory is
  0, so no quorum is reachable; `monitor.py witness` refuses before counting.
* **0 independent domains** — `thresholds.distinct_domains` over zero witness
  approvals returns count 0; `evidence/a15/DOMAINS.json` records
  `externalDomains: []`.

`monitor.py witness` exits 1 with `MN_REFUSED_NO_WITNESS`. Witness admission is
`NOT_RUN`, not met. The aliasing rule is delegated to A15
(`thresholds.distinct_domains`): two labels sharing one establishment record are
one domain, and one operator under two labels is one domain; a collapsed set is
`MN_REFUSED_WITNESS_ALIASED`. Signature and expiry are witness-specific checks
that A15 documents it does not perform.

## 4. Controls

`evidence/b5/CONTROLS.json`: **16 `controlOnly` rows, 16 fired, one per refusal
code plus a positive**. 13 carry an accepting canary; `no-witness`, `usage` and
`io` carry a stated non-acceptance. Every witness fixture is synthetic and
generated under `evidence/b5/control-only/`; no witness admission is claimed.

## 5. Defects found

**One defect in an existing record, not repaired.** `evidence/b3/RECONCILIATION.json`
is **stale at `24ac742f5`**, before any B5 file existed. It is a live view
(`asOf: 1155843e6`) that lists `b4-receipt` as missing, while
`evidence/b4/RECEIPT.md` is tracked at HEAD. Cause: B4 wrote its receipt *after*
its own suite run (B4 receipt §6 says "only this receipt was written
afterwards"), so the suite never saw the member. Proven on a pristine
`git worktree` at HEAD, with no B5 file present:

```
code=AC_REFUSED_MANIFEST_INVALID
b3: stale record(s): RECONCILIATION.json
BASE_B3_CHECK_EXIT=1
```

Old (committed `missing`): `[b4-receipt, b5-receipt, b6-receipt, b7-receipt,
b8-receipt]`. New (live at base): `[b5-receipt … b8-receipt]`, produced gains
`b4-receipt`. With this item's receipt the live `missing` is
`[b6-receipt, b7-receipt, b8-receipt]`, produced gains `b5-receipt`. **Not
repaired:** `evidence/b3/` is outside this item's write scope, and the check was
not relaxed. This is the same class A19 recorded for A17 and left to its owner.
The orchestrator should regenerate B3's reconciliation (preserving the old
record) or assign it to B3's owner.

**No other defect in an existing record was found.** `docs_consistency.py` and
`spec_guard.py check` accept the edited queue row; no existing JSON was edited.

**Development defects in this item's own machinery**, preserved because a
control that passes for the wrong reason is the defect this item exists to
catch:

1. **The first sequence paired the wrong proof.** The size-5 observation was
   given the `5 → 6` proof instead of `2 → 5`; it was refused
   `MN_REFUSED_INCONSISTENT`. Old: proof matched to the wrong transition. New:
   each growth names its own proof (`2 → 5`, `5 → 6`), asserted by
   `test_each_growth_records_a_verified_consistency_proof`.
2. **The checkpoint control's first design had no possible canary.** A
   malformed body cannot be accepted by disabling a check, so the control was
   changed to a signed size-0 head with a non-empty root — a real checkpoint
   whose root-validity check can be disabled — and the malformed body is kept as
   an attribution-only test. Old: no acceptance existed; new: an accepting
   canary plus a separate attribution case.
3. **The witness CLI passed the signed note to the body parser.** `witness` read
   `checkpoint-6.note` and refused `MN_REFUSED_CHECKPOINT`, because admission
   parses a *body*. Old: the whole note; new: `checkpoint_body()` extracts the
   exact body and a malformed note still refuses `MN_REFUSED_CHECKPOINT`.
4. **A malformed quorum was masked by the absence check.** `k=0` with an empty
   set reported `MN_REFUSED_NO_WITNESS` instead of a usage error. Old: absence
   first; new: the quorum is validated before the absence check.
5. **One operator could be counted twice.** A15's `distinct_domains` groups by
   establishment record, so one operator declaring two establishment records was
   two groups. Old: the count could reach k with one operator; new: A15's own
   duplicate-identity rule is applied, and the set is
   `MN_REFUSED_WITNESS_ALIASED`. This is a *tightening* of the count, not a
   relaxation of a check.
6. **The `monitor` human line printed `size=None`.** The size lives under
   `head` for the audit result; the printer read only a top-level field. Old:
   `size=None`; new: `size=6`.

## 6. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before: `Mem: 45 37 4 0 4 8` (available **8** GiB), `Swap: 45 45 0`; before the last suite: `Mem: 45 38 4 0 4 7` (available **7** GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect openssl-rs-court` | `mem=6442450944 memswap=6442450944 status=running` (6 GiB), `/work` bind-mounted; reused, no new court, no build |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2308 tests in 454.918s`; `FAILED (failures=2)`. The **2,256 pre-existing tests are present** (2,256 + 52 = 2,308), none removed, none ignored. The two failures are the same pre-existing B3 staleness in §5, not a B5 test |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on every created JSON | `json.tool MONITOR.json ok`, `json.tool WITNESSES.json ok`, `json.tool CONTROLS.json ok`; the store is JSON Lines and each line parsed: `json.tool-per-line monitor-store.jsonl ok: 3 records` |
| 5. producer, twice | `python3 evidence/b5/build_evidence.py` twice, then `diff` of every produced file's SHA-256 | `BYTE-IDENTICAL-RUNS`; run 2: `code=MN_OK b5: base=24ac742f5 observations=3 sizes=[2, 5, 6] head=e9a8ad01…4c540f storeSha256=08db31ac…7c5b witnesses=0/3 witnessOutcome=NOT_RUN`; `code=MN_OK b5: controls=16 onePerRefusalCode=True acceptingCanaries=13 nonAccepting=no-witness,usage,io` |
| 5. producer check | `python3 evidence/b5/build_evidence.py --check` | `code=MN_OK b5: check ok records=4 storeSha256=08db31ac…7c5b` |
| 6. status | `python3 forensics/tools/monitor.py status` | `code=MN_OK outcome=MONITORED observations=3 origin=FIXTURE-1 size=6 root=e9a8ad01…4c540f`; `STATUS_EXIT=0` |
| 6. monitor | `python3 forensics/tools/monitor.py monitor` | `code=MN_OK outcome=MONITORED observations=3 origin=FIXTURE-1 size=6 root=e9a8ad01…4c540f`; `monitor: sizes=[2, 5, 6] transitions=2 chain=verified`; `MONITOR_EXIT=0` |
| 6. witness | `python3 forensics/tools/monitor.py witness` | `code=MN_REFUSED_NO_WITNESS message=no witness set exists; witness admission is NOT_RUN, not met`; `WITNESS_EXIT=1`. Codes fired by the real run: `MN_OK` (status, monitor) and `MN_REFUSED_NO_WITNESS` (witness) |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/TRANSPARENCY-MONITORING.md`; `?? evidence/b5/`; `?? forensics/tools/monitor.py`; `?? forensics/tools/tests/test_monitor.py` — nothing else |

The full discovery ran on the final code, document and record tree; only this
receipt was written afterwards. B5's 52 controls pass. The two failures are the
B3 record staleness proved above and are unrelated to this item.

## 7. Obligations retained

* **Monitoring is not honesty.** It establishes that a sequence of heads is
  internally consistent and append-only, not that the log serves that sequence
  to anyone else.
* **No other view.** `MN_REFUSED_SPLIT_VIEW` is local evidence of equivocation;
  a view that never reaches this monitor is undetectable.
* **The monitor's observation time is its own record**, not a signing time, an
  integrated time or a trusted timestamp. An unzoned instant is refused rather
  than guessed.
* **The consistency proof is verified at observation and not stored.** The
  monitor cannot re-verify a transition after the fact; `monitor` re-checks the
  recorded invariants, not the proof bytes.
* **The store digest is not a signature.** It shows the bytes are the ones
  written, not who wrote them; a rewritten chain is caught only by the semantic
  audit.
* **Witnesses are absent.** A recorded k=3 quorum is not a met quorum, and
  operating several services under one maintainer would not be several
  witnesses.
* **The fixture is not a service.** The signer is A10's test-only key; no log
  key, no admission, no inclusion of a public log.
* **A15 supplies the count, not the cryptography.** Signature verification and
  key expiry are this module's checks; A15 documents that it does not verify
  signatures.
* **The producer is the validator.** The same module produces and checks the
  records; no independent reviewer ran.
* **The suite's two failures are a pre-existing record defect**, recorded with
  its proof and not repaired within this item's write scope.

## 8. `NOT_RUN`

* **Witness admission**: no witness service, witness key or independent operator
  domain exists. `WITNESSES.json` records `outcome: NOT_RUN`.
* **A public log, a second view or another monitor's transcript**: no log and no
  network.
* **An independently operated monitor or an independent reviewer.**
* **Detection of equivocation never served to this monitor.**
* **A trusted timestamp for any observation** (§B.9; B2 records no authority).
* **Repair of `evidence/b3/RECONCILIATION.json`**: outside this item's write
  scope; the owner must regenerate it with the old record preserved.
* Independent review, `BOUNDARY`, `SEAL` and the Rust suite (no Rust source was
  modified, so no `cargo` command ran).
* **Closure of the A17 forward freeze**: this item satisfies its `b5-receipt`
  member only; the freeze stays `OPEN`.

## 9. Forward-freeze member and worktree

The A17 forward-freeze member `b5-receipt` (`evidence/b5/RECEIPT.md`, predicate
"a receipt records checkpoints, consistency, monitoring and witnesses") is
**satisfied**: this receipt and the three records name the accepted sequence, the
final head, the corrupted controls and the empty witness inventory. The freeze
itself was not closed, and A20's `A17.forward-freeze-closed` obligation is
unaffected.

Worktree after this batch: `M docs/ETP-TODO.md`;
`?? docs/TRANSPARENCY-MONITORING.md`; `?? evidence/b5/`;
`?? forensics/tools/monitor.py`; `?? forensics/tools/tests/test_monitor.py`.
Nothing else. This subagent did not commit and did not push.

**Why `PARTIAL`:** the monitoring half is implemented, controlled and ran; the
witness half does not exist in this venue, so no independent witness was
admitted and no witness-dependent property is established.
