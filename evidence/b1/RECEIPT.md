# B1 receipt — a fixture is not an admitted service, and the verifier is real

## 1. Identity of this batch

| field | value |
|---|---|
| item | B1 (`docs/ETP-ADDENDUM-B.md` §B.30; section F of `docs/ETP-TODO.md`), split **B1a / B1b** |
| status | **`PARTIAL`** — B1a `NOT_RUN`, B1b verified against `FIXTURE-1` |
| branch | `staging` |
| HEAD at the start | `54fb5085b` (`b0: a pinned version is not an admitted service`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 32 12 0 1 13` (available **13** GiB); `Swap: 45 45 0` |
| `free -g` after the suite | `Mem: 45 33 8 0 4 12` (available **12** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `HostConfig.MemorySwap` both `6442450944`; cgroup `memory.max` `6442450944`), CPU quota **8 cores** (`cpu.max = 800000 100000`), repository at `/work`; **reused, not restarted** |
| interpreter in the court | CPython **3.11.2** (the host's 3.14 was not used for a gate) |
| heavy commands | one at a time; no Rust build |

Available memory was **13 GiB**, below the 24 GiB floor `AGENTS.md` §6.1 sets
before a build. No build was needed or attempted: every gate is Python, the
derived cap `min(8g, available − 16g)` is below the 2 GiB floor, and **no new
court was started**. The existing 6 GiB court was reused and every gate ran
inside it. The `docker/` launcher was not modified. Peak court memory was not
separately instrumented; the run completed without an OOM or a cgroup-kill
record, and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/tlog.py` | 1,813 | the offline verifier: RFC 6962 §2.1 hashing, inclusion and consistency proofs, the §B.3.2 checkpoint body and note signature, the `tlog-tiles` entry-bundle/hash-tile reader and writer; CLI `prove`, `verify-inclusion`, `verify-consistency`, `checkpoint`, exit 0/1/2, the code always printed; **15 stable refusal codes** plus `TL_REFUSED_USAGE` and `TL_OK` |
| `forensics/tools/tests/test_tlog.py` | 889 | 61 controls: hand-computed hashing vectors, every index for sizes 1–33, tile boundaries, both proof directions, one trigger per refusal code, the real fixture, determinism, CLI exit codes, document synchronisation |
| `docs/LOCAL-TRANSPARENCY.md` | 489 | the normative document: the admitted-service requirement, the fixture identity, the hashing/proof/checkpoint/tile rules, the controls and canaries, the full refusal table, what the fixture establishes and does not, `NOT_RUN` |
| `evidence/b1/build_evidence.py` | 1,577 | the deterministic producer: builds the fixture, signs the checkpoints, runs every offline control and its canary, writes four records and 11 fixture files |
| `evidence/b1/PREFLIGHT.json` | 148 | **B1a**: checks, absences, prerequisites, planned commands, `status: NOT_RUN` |
| `evidence/b1/FIXTURE.json` | 191 | **B1b**: `FIXTURE-1`, six leaves, roots, checkpoints, signatures, tile digests, `admittedService: false` |
| `evidence/b1/PUBLICATION.json` | 103 | the one published statement: binding, leaf index/hash, proof, checkpoint, consistency, `hashedrekordPath: NOT_RUN` |
| `evidence/b1/CONTROLS.json` | 441 | 36 §B.24 rows: 21 run offline with canaries, 15 `NOT_RUN` with their clauses |
| `evidence/b1/fixture/` | 11 files | the actual tile tree, three signed checkpoints and four proof files |
| `docs/ETP-TODO.md` | 1 row | the B1 row changed from `TODO` to `PARTIAL`; no other row touched |
| `evidence/b1/RECEIPT.md` | this file | the receipt |

The fixture tree is:

```
fixture/checkpoint-2.note  checkpoint-5.note  checkpoint-6.note
fixture/consistency-2-5.json  consistency-2-6.json  consistency-5-6.json
fixture/inclusion-3-at-6.json
fixture/tile/entries/000.p/6
fixture/tile/0/000.p/6  tile/1/000.p/3  tile/2/000.p/1
```

The producer is the only writer; `--check` recomputes all four records and all 11
fixture files and compares the bytes.

## 3. B1a — the admitted-service slice is `NOT_RUN`

B1a asks for a pinned POSIX-backed `rekor-tiles` v2 instance and a submission
through the supported `hashedrekord` path. The preflight records:

* **binary absent** — `rekor-server`, `rekor-cli`, `rekor-tiles` all absent
  (`command -v`); no client, no `cosign`, no `sigstore`;
* **no endpoint** — no Rekor endpoint or log key outside `docs/`;
* **no network** — nothing fetched, installed or started;
* **no TSA** — `tsget` absent; `/usr/bin/openssl` is not a timestamp authority;
* **no POSIX asset digest** — §B.3.2 records only the `linux/amd64`
  `rekor-server-aws` asset of v2.4.2 (`sha256:3af252cd…61e8a6`), not the POSIX
  build this project uses; B1 must record the digest of the exact asset it
  installs and may not reuse the AWS digest;
* **SCF-1** — the `signing_config` inspected 2026-10-22 advertised a **v1**
  endpoint, so a recent client does not imply a v2 service and a local slice
  cannot inherit an endpoint (`evidence/b0/SERVICE-CONFIGURATION.json`).

The prerequisites B0 lists are carried as `UNMET`: `TA-B1` (a pinned server
binary matching a recorded digest, the POSIX backend and a log key), the
POSIX-digest gap, authenticated service metadata (§B.10), the `hashedrekord`
representation and its exact DSSE-derived digest (§B.5, §B.3.3 T3), `TA-B2`
(RFC 3161) and `TA-B5` (a witness quorum).

The commands that would run once a pinned instance exists are recorded in
`PREFLIGHT.json#/plannedCommands`; **none was executed and none is evidence**.
They include the exact, executable-now verification commands
(`tlog.py checkpoint …`, `tlog.py verify-inclusion …`) and the service/client
commands whose flags are deliberately left as placeholders: §B.5 requires the API
version and flags to be read from the admitted binary, not from documentation, so
this receipt does not invent them.

## 4. B1b — the verification half, against `FIXTURE-1`

**The fixture.** Six leaves: the exact bytes of the four frozen A9 statements
(`a1-sarif`, `a5-admission`, `a7-delta`, `a8-shard-000`) and two synthetic leaves
generated from the fixed seed `openssl-rs/b1/fixture-1/seed/v1`, labelled
`test-only` and not evidence. Tree size 6, root
`e9a8ad0126e834c0ec34fed464572772d3f3c2d3501198239a1a5554324c540f`. Checkpoints
at sizes 2, 5 and 6; every signature is HMAC-SHA256 under A10's fixed public test
key (name `FIXTURE-1 test-only hmac-sha256`), which is **not a log key**.

**The publication.** `evidence/a9/STATEMENTS/a8-shard-000.json` (714 bytes,
SHA-256 `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582`) at
leaf index **3**, leaf hash
`d634ef880585fd724608819941c9717ddaf3b5081508649df21b86771fdd13ad`, with a
3-element inclusion proof. The subject digest
`b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed` is recomputed
from the 8,699,144-byte SARIF subject by A9's reader. The exact A10 envelope is
verified over its PAE and recorded, but **no `hashedrekord` entry exists**.

**Results.**

| check | result |
|---|---|
| tiles reproduce the signed root (and entry bundles agree with level-0 hashes) | pass |
| inclusion of index 3 in size 6 | pass, 3 elements, `TL_OK` |
| checkpoint size 6 signature, origin, size, root | pass, `TL_OK` |
| consistency 2 → 5 → 6 | pass, both links |
| independent consistency 2 → 6 (`m` a power of two) | pass |
| statement → leaf binding (exact bytes) | pass |
| statement → subject binding (A9 re-hash) | pass |
| refusal codes on valid data | none |

## 5. Controls

`CONTROLS.json` records **36 rows: 21 run offline, 15 `NOT_RUN`**, with **21/21
fired and 21/21 canaries accepted**. Each run row carries the refusal message and
a canary that disables the named check: `scope: verifier` means the whole call is
accepted; `scope: check` means the named check returns without refusal (a
malformed proof cannot become a valid proof merely by disabling its own check,
and the row states the next independent refusal).

| item | control | refusal | canary |
|---:|---|---|---|
| 1 | tampered Merkle leaf | `TL_REFUSED_PROOF` | verifier, `root` disabled |
| 2 | index 6 in size 6 | `TL_REFUSED_INDEX` | check, `index` disabled |
| 2 | proof for index 3 claimed at index 2 | `TL_REFUSED_PROOF` | verifier, `root` disabled |
| 3 | sibling order swapped | `TL_REFUSED_PROOF` | verifier, `root` disabled |
| 4 | truncated proof | `TL_REFUSED_PROOF` | verifier, `proof`+`root` disabled |
| 5 | excess proof element | `TL_REFUSED_PROOF` | verifier, `proof`+`root` disabled |
| 6 | signed wrong checkpoint root | `TL_REFUSED_ROOT` | verifier, `root` disabled |
| 7 | signed size 7 over 6 leaves | `TL_REFUSED_SIZE` | check, `size` disabled; next refusal `TL_REFUSED_TILE` |
| 8 | checkpoint signed with another key | `TL_REFUSED_CHECKPOINT_SIGNATURE` | verifier, `signature` disabled |
| 9 | checkpoint from `OTHER-LOG` | `TL_REFUSED_ORIGIN` | verifier, `origin` disabled |
| 10 | checkpoint from `FIXTURE-1-shard-002` | `TL_REFUSED_ORIGIN` | verifier, `origin` disabled |
| 12 | valid leaf for an unrelated statement | `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` | verifier, `absent-leaf`+`root` disabled |
| 14 | 100-byte hash tile | `TL_REFUSED_TILE` | check, `tile` disabled |
| 15 | reordered entry bundle, head re-signed | `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` | check, the reordered log's own leaf is valid |
| 16 | partial tile declares width 3, carries 4 | `TL_REFUSED_TILE` | check, declared width disabled |
| 17 | corrupted hash tile | `TL_REFUSED_ROOT` | verifier, `root` disabled |
| 18 | size-2 checkpoint replayed after size 6 | `TL_REFUSED_ROLLBACK` | verifier, `rollback` disabled |
| 19 | same-size conflicting checkpoints | `TL_REFUSED_SPLIT_VIEW` | verifier, `split-view` disabled |
| 20 | invalid 5 → 6 consistency proof | `TL_REFUSED_CONSISTENCY` | verifier, `consistency` disabled |
| — | duplicate leaf append | `TL_REFUSED_DUPLICATE_LEAF` | check, `duplicate` disabled |
| — | subject digest not the subject bytes | `TL_REFUSED_BINDING` | check, `binding` disabled |

`NOT_RUN`: item **11** (the admitted client's DSSE PAE/`hashedrekord` digest
derivation, §B.5 / §B.3.3 T3), item **13** (the admitted service's version
negotiation, §B.5 / §B.10), and items **21–33** (witness state, credentials and
correlation; timestamp imprints, authorities and backdating; campaign omission;
archive, revocation and trust-root rotation; interrupted publication, service
unavailability and retry ambiguity). Each row names the clause and the missing
capability.

## 6. Defects found

**Existing records: none contradicted.** The B1b producer re-read the four A9
statements with A9's decoder (canonical bytes, subject files re-hashed), the A10
envelope (payload equals the statement, signature verifies over the PAE), the B0
registry and the B0 service configuration. Nothing disagreed. The **one existing
gap is B0's, reported rather than repaired**: the only recorded digest is the
v2.4.2 **AWS** server asset, not the POSIX build. B1 owns recording the POSIX
digest at admission; this item does not invent one and does not edit
`evidence/b0/`. SCF-1 is an existing finding, not a defect, and was not
re-observed (no network).

**Development defects in this item's own machinery**, preserved because a control
that passes for the wrong reason is the defect this item exists to catch:

1. `_index_segments` first encoded `1234067` as `x1/x234/067` because the leading
   group was not zero-padded. The test caught it; every group is now padded to
   three digits. The expectation was not changed — the addendum's own example is
   `x001/x234/067`.
2. `TiledLog._subproof` passed `start + k` where the span count `k` was required,
   producing a `[4, 10)` read from a size-8 tree. The boundary test caught it; the
   left sibling is now `_tree_hash(start, k, size)`.
3. `TileStore` first demanded a tile re-cut to the requested size (`.p/2` when the
   store held `.p/6`), so verifying an earlier checkpoint against a wider mirror
   failed. `_read_prefix` now accepts a wider tile's prefix; a tile that cannot
   supply the needed prefix is still `TL_REFUSED_TILE`. The check was not
   weakened, and the 2/5/6 chain now verifies from the size-6 store.
4. The subject-binding canary first mutated only the subject digest, which A9's
   structural record binding refused even with subject files skipped, so the
   canary was refused. The mutation now also changes the predicate's record
   digest consistently, leaving the subject file as the only disagreement. The
   production binding check was not relaxed.
5. The corrupted-mirror control first flipped a level-0 hash byte, but root
   reconstruction for size 6 reads level-1/2 tiles, so the root did not change and
   the entry/hash cross-check raised `TL_REFUSED_TILE`, not `TL_REFUSED_ROOT`. The
   control now corrupts the highest stored hash tile that root reconstruction
   reads, and the refusal is `TL_REFUSED_ROOT` as claimed.
6. The document test searched for `no official` in the raw text while the
   document broke the phrase across a line. The document was reworded; the test
   was not weakened. Separately, `no independent witness` was not present until
   §11 said it explicitly; the document was corrected.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container (CPython 3.11.2),
one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before: `Mem: 45 32 12 0 1 13` (available **13** GiB), `Swap: 45 45 0`; after: `Mem: 45 33 8 0 4 12` (available **12** GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect`; cgroup | `Mem=6442450944 MemSwap=6442450944 CPU=8000000000`; `memory.max 6442450944`; `cpu.max 800000 100000`; reused, not restarted |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2067 tests in 439.702s`; `OK`; `closure discipline self-test: 7 control groups passed`. The **2,006 pre-existing tests are present** (2,006 + 61 new = 2,067), none removed, none ignored, no skips reported |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on the four records | `PREFLIGHT.json_JSON_OK`; `FIXTURE.json_JSON_OK`; `PUBLICATION.json_JSON_OK`; `CONTROLS.json_JSON_OK` |
| 5. producer, twice | `python3 evidence/b1/build_evidence.py` twice | each: `b1: identity=FIXTURE-1 admittedService=false leaves=6 publishedIndex=3 root=e9a8ad01…4c540f`; `b1: controls=36 runOffline=21 notRun=15 fired=21 canariesAccepted=21`; `b1: codes=NONE`. A `sha256sum` manifest before, after run 1 and after run 2: `diff` clean twice, **BYTE-IDENTICAL**. `--check`: `b1: check ok records=4 fixtureFiles=11 identity=FIXTURE-1 admittedService=false`; `CHECK_EXIT=0` |
| 6. CLI prove | `tlog.py prove --log evidence/b1/fixture --index 3 --size 6` | `code=TL_OK index=3 size=6 root=e9a8ad01…4c540f`; `leafHash=d634ef88…fdd13ad`; `proof=f5b84960…c8255,4f91d957…cb2d8,9cd027e6…33be2`; `PROVE_EXIT=0` |
| 6. CLI inclusion | `tlog.py verify-inclusion … --checkpoint checkpoint-6.note --origin FIXTURE-1 --test-only-key` | `key=test-only A10 HMAC-SHA256 … notATrustRoot=true`; `checkpoint origin=FIXTURE-1 size=6 … signature=verified`; `code=TL_OK index=3 size=6 … proof=verified binding=verified`; `INC_EXIT=0` |
| 6. CLI consistency 2→6 | `tlog.py verify-consistency … checkpoint-2/checkpoint-6 …` | `checkpoint1 size=2 … signature=verified`; `checkpoint2 size=6 … consistency=verified`; `code=TL_OK m=2 n=6 …`; `CONS26_EXIT=0` |
| 6. CLI consistency 5→6 | same with `checkpoint-5/checkpoint-6` | `checkpoint1 size=5 … signature=verified`; `checkpoint2 size=6 … consistency=verified`; `code=TL_OK m=5 n=6 …`; `CONS56_EXIT=0` |
| 6. corruptions | ten CLI cases (tampered leaf, tampered proof, unrelated leaf, wrong origin, rollback, split view, bad consistency, wrong root, forged signature, unsigned) | every case `EXIT=1`; codes: `TL_REFUSED_INCLUSION_OF_ABSENT_LEAF` (tampered/unrelated leaf), `TL_REFUSED_PROOF`, `TL_REFUSED_ORIGIN`, `TL_REFUSED_ROLLBACK`, `TL_REFUSED_SPLIT_VIEW`, `TL_REFUSED_CONSISTENCY`, `TL_REFUSED_ROOT`, `TL_REFUSED_CHECKPOINT_SIGNATURE` (forged and unsigned) |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/LOCAL-TRANSPARENCY.md`; `?? evidence/b1/`; `?? forensics/tools/tests/test_tlog.py`; `?? forensics/tools/tlog.py` — nothing else |

The 2,006 baseline is the B0 figure; this item adds 61 tests and removes none.
The full discovery ran after the final code and document fixes (including the
index encoding, the consistency span, the wider-tile prefix, the binding canary,
the corrupted-mirror target and the document wording). Only this receipt was
written afterwards; it changes no code and no test.

## 8. Obligations retained

* **A fixture is not a service.** `FIXTURE-1` is not `rekor-tiles`, has no HTTP
  API, no `hashedrekord` entry, no integrated time and no operator.
* **The test key is not a log key.** Every checkpoint signature is A10's fixed
  public HMAC key; it proves the note bytes are unchanged, not that an independent
  operator signed them. `SELF_ISSUED` is not a pass.
* **No witness exists.** No cosignature, quorum, independent operator or
  split-view test against real infrastructure. Items 21–23 stay `NOT_RUN`.
* **No trusted signing time.** No RFC 3161 token; items 24–26 stay `NOT_RUN`; B2
  owns this.
* **No `hashedrekord` binding was demonstrated.** The envelope and its PAE digest
  are recorded, but the admitted client's derivation and the `hashedrekord`
  entry are B1a.
* **Offline refusals are not a Rekor conformance result.** The verifier refuses
  the corruptions it was given; it does not establish that `rekor-tiles` behaves
  as the fixture does, and it earns no credit for a defect class outside its
  scope.
* **The synthetic leaves are not evidence.** They exist to make the tree shape
  non-perfect and are labelled in every record.
* **The forward freeze remains `OPEN`.** Producing `b1-receipt` satisfies its
  predicate; it does not close the freeze.

## 9. `NOT_RUN`

* Every item in B1a: download, install, execute or configure `rekor-tiles`, a
  Rekor client, `cosign`, a Sigstore client, a witness or a TSA; any network
  request or `signing_config` re-inspection; any log key, production checkpoint
  signature or cosignature; any `hashedrekord` submission or Rekor log entry.
* §B.24 items 11 and 13, and 21–33.
* Any RFC 3161 request or token verification (B2).
* Any witness admission, quorum evaluation or real split-view test (B5).
* Independent review, BOUNDARY and SEAL evidence, and the Rust suite (`src/` was
  not modified).

## 10. The forward-freeze member

`evidence/a17/FREEZE-forward.json` declares exactly one B1 member:

* `b1-receipt` — `path: evidence/b1/RECEIPT.md`, predicate "a receipt records the
  frozen statement, inclusion and checkpoint evidence".

This file exists at that exact path and records the frozen statement (SHA-256,
leaf index 3, leaf hash), its inclusion proof and the checkpoint/consistency
evidence, with the B1a half explicitly `NOT_RUN`. The freeze names **only a
receipt** for B1, so the detailed records are placed under `evidence/b1/`
(`PREFLIGHT.json`, `FIXTURE.json`, `PUBLICATION.json`, `CONTROLS.json`, the
fixture tree and the producer) and are named here. The member predicate is
satisfied; the freeze itself remains `OPEN` and is closed only at A17's own
record.
