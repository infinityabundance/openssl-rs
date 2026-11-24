# A8 receipt — a local code-scanning export with no GitHub dependency

## 1. Identity of this batch

| field | value |
|---|---|
| item | A8 (GitHub code-scanning export without a GitHub dependency: full local artefacts authoritative; a shard manifest when an export limit applies) |
| branch | `staging` |
| HEAD at the start | `9f79f5066` (`a7: an absent finding is resolved only when nothing else explains it`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 18 22 0 4 26` (total 45, used 18, free 22, available **26** GiB); `Swap: 45 27 18` |
| derived court cap | `min(8g, 26 − 16) = 8g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/` or another item's tool/evidence modified |

The derived cap was 8 GiB and the running container's cap is 6 GiB, below it;
the container was reused rather than restarted, exactly as A7 did, because one
court already holds the memory budget. Every gate is Python-only.

One venue fact affected the gates and is stated rather than hidden: a plain
`docker exec` into the reused court has `PATH` without `/usr/local/cargo/bin`
and `/opt/opam/4.14.2/bin`, so `rustc` and `binsec` are not found and twelve
pre-existing instrument/binary tests fail with `binsec: command not found` or a
missing runtime. Running the same suite with those two directories on `PATH`
reduces the failures to the one record defect of §6. Nothing in this batch
compiles, links or invokes either tool.

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/CODE-SCANNING-EXPORT.md` | 335 lines | normative document: the problem; the no-dependency rule; the sharding rule and the 5,000 limit; the shard contract; the manifest contract; the 13 verification conditions; all 17 refusal codes with the wrong conclusion each prevents; the real export and figures; the controls; non-claims; `NOT_RUN` |
| `forensics/tools/code_scanning_export.py` | 2,272 lines | the export: `plan`, `emit`, `manifest`, `verify`, the 17 stable codes, the parent validation, the structural no-dependency check, the output-directory refusal, the synthetic control document, the 17 controls, the plan/controls documents and the `plan`/`emit`/`verify` command line |
| `forensics/tools/tests/test_code_scanning_export.py` | 502 lines | 28 controls: the 5,000 boundary in both directions, union completeness and uniqueness on the real population, order preservation, tool/rule/artifact retention and index relabelling, plan and byte determinism, committed evidence matching a fresh build, one control per refusal code, CLI exit codes with printed codes, the structural no-network/no-credential rule, and document synchronisation |
| `evidence/a8/build_evidence.py` | 208 lines | deterministic producer of the four evidence files; reads every count from the parent through the tool and asserts the design expectations |
| `evidence/a8/PLAN.json` | 180,059 bytes | the real one-shard plan (the full 0–4244 index list) and the labelled synthetic 12,001-result plan (three full index lists) proving the 5,000 boundary |
| `evidence/a8/MANIFEST.json` | 4,607 bytes | parent path/bytes/SHA-256, six per-run candidates and their token, the shard entry, the union check, the exporter identity, non-claims |
| `evidence/a8/SHARD-000.sarif` | 8,699,144 bytes | the real emitted shard, a genuine SARIF 2.1.0 log |
| `evidence/a8/CONTROLS.json` | 7,666 bytes | 17 controls, one per code, and the code table |
| `evidence/a8/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A8 row only; no other row was touched. No
existing record was edited; the one defect found is preserved with its old and
new values in §6 and left for its owner.

## 3. The rule

> An upload is a lossy, third-party step. A shard is a subset, not a census.
> Only the manifest states the whole population, and a shard set is an export
> only when the union of its exact identities is the parent population once
> each, in the parent's order.

The export is a local transformation: no API client, no network call, no token,
no upload. `plan` cuts the input order at 5,000 results, so the plan is
reproducible and independent of result content. `emit` copies every contributing
run with `tool` complete except the restricted `rules` table, artifacts
restricted to the referenced URIs, and every `ruleIndex` and artifact index
relabelled. `manifest` binds the exact parent bytes and the shard bytes and
records the union it derives. `verify` refuses 13 kinds of mismatch with 17
stable codes.

## 4. The real export and figures

The parent is `evidence/a1/SARIF.json`: 13,651,450 bytes, SHA-256
`5c0cfee62512deb08cc12f95624be64865d3e544473bae80d9aca0ab36ce7852`, 6 runs,
4,245 results (17, 4, 211, 3,953, 51, 9 per run), 4,245 distinct `a1Exact/v1`
identities, six distinct per-run candidates (mixed, token
`dea0f4228962fc342930e0a45dc50d3b12a9962cef0c4510bc47be89db7a5b92`).

| quantity | measured |
|---|---|
| shards | 1 (`SHARD-000.sarif`, indices 0–4244, runs 0–5) |
| shard bytes / SHA-256 | 8,699,144 / `b16d376ae0b2fa5483650f8019eada15102fcae580b0a46419b13e7ee98450ed` |
| parent / union / distinct results | 4,245 / 4,245 / 4,245 |
| missing / extra / duplicate | 0 / 0 / 0 |
| `equalsParent` | true |
| union identity digest | `1c3b64ca5e1f694f1950f199281d7e61b95e3258128985c470c54f5e21ad5777` (same as the parent) |
| rules per shard run | 4, 2, 6, 5, 5, 2 |
| artifacts per shard run | 1, 1, 9, 616, 31, 2 (run 4's parent lists 32; one is referenced by no result) |
| synthetic boundary plan | 12,001 results → 3 shards: 0–4999 (5,000), 5000–9999 (5,000), 10000–12000 (2,001) |
| refusal codes / controls | 17 / 17 |
| new `unittest` controls | 28 |

A second **real** shard cannot be produced from the tracked 4,245-result
population. The 5,000 boundary is proven by the labelled synthetic plan, and
`build_evidence.py` refuses to write a plan whose boundaries are not input-order
cuts or whose tail does not hold the remainder.

## 5. Controls and measured figures

`evidence/a8/CONTROLS.json` records one control per code; each mutates a copy in
memory or a temporary directory and asserts its named code fires.

| control | code |
|---|---|
| `oversize-shard` | `EX_REFUSED_OVERSIZE_SHARD` |
| `shard-as-census` | `EX_REFUSED_SHARD_AS_CENSUS` |
| `manifest-absent` | `EX_REFUSED_MANIFEST_ABSENT` |
| `manifest-shard-missing` | `EX_REFUSED_MANIFEST_SHARD_MISSING` |
| `union-incomplete` | `EX_REFUSED_UNION_INCOMPLETE` |
| `union-duplicate` | `EX_REFUSED_UNION_DUPLICATE` |
| `order-changed` | `EX_REFUSED_ORDER_CHANGED` |
| `digest-mismatch` | `EX_REFUSED_DIGEST_MISMATCH` |
| `tool-dropped` | `EX_REFUSED_TOOL_DROPPED` |
| `rule-dropped` | `EX_REFUSED_RULE_DROPPED` |
| `artifact-dropped` | `EX_REFUSED_ARTIFACT_DROPPED` |
| `candidate-unrecorded` | `EX_REFUSED_CANDIDATE_UNRECORDED` |
| `absolute-path` | `EX_REFUSED_ABSOLUTE_PATH` |
| `unsupported-version` | `EX_REFUSED_UNSUPPORTED_VERSION` |
| `parent-shape` | `EX_REFUSED_PARENT_SHAPE` |
| `network-or-credential` | `EX_REFUSED_NETWORK_OR_CREDENTIAL` (synthetic source fires; the real module is clean) |
| `output-not-empty` | `EX_REFUSED_OUTPUT_NOT_EMPTY` |

The boundary is controlled in both directions: 5,000 results are one accepted
shard and 5,001 are refused, by
`test_exactly_five_thousand_results_are_accepted` and
`test_five_thousand_and_one_results_are_refused`. The structural no-dependency
rule is enforced by `test_the_module_imports_no_network_client`,
`test_the_module_reads_no_credential` and
`test_a_network_import_is_refused_structurally`, not by prose.

## 6. Defect found in an existing record

**`evidence/a7/BASELINES.json` binds the live worktree HEAD, so the record is
invalidated by the commit that lands it.**

| | value |
|---|---|
| committed `sourceIdentity.commit` | `1efd02cbd1401c4cffb854b906c021915df94386` (A7's start HEAD) |
| fresh build at the recorded parent `9f79f5066` | `9f79f5066a10e0801196bd8e0bec796ac7a13554` (the commit that landed A7) |
| differing fields | `commit` only; `branch` is `staging` and `asOf` is `2026-11-24` on both sides |
| failing test | `test_baseline.ProducerTests.test_the_committed_records_match_a_fresh_build` (`AssertionError: … : BASELINES.json`) |

The producer's `source_identity` reads `git rev-parse HEAD` and the branch; the
committed bytes were generated before the A7 commit, so the record can only be
reproduced at `1efd02cbd` and cannot be reproduced at the commit that contains
it. This is pre-existing and independent of A8: it is not caused by an A8 file,
and `source_identity` reads no A8 path. Verified in the court:

```
{'commit': '9f79f5066a10e0801196bd8e0bec796ac7a13554', 'branch': 'staging', 'asOf': '2026-11-24'}
{'asOf': '2026-11-24', 'branch': 'staging', 'commit': '1efd02cbd1401c4cffb854b906c021915df94386'}
```

**History preserved.** The record was **not edited**: `evidence/a7/BASELINES.json`
still holds `1efd02cbd…`, both values are recorded here, and the failing test is
named. Repair is outside this item's write scope (A7 owns its producer and
evidence). The consistent options for its owner are to regenerate the record at
the landing commit as an evidence-only commit that names the frozen source `S`
(AGENTS §22), or to stop recording a live-HEAD field in a reproducible producer;
this receipt does not choose for A7 and does not relax the check.

No other existing record was contradicted by a gate.

## 7. Gates actually run

All commands ran inside the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 18 22 0 4 26` (available 26 GiB); `Swap: 45 27 18` |
| new controls | `python3 -m unittest forensics.tools.tests.test_code_scanning_export` | `Ran 28 tests in 2.800s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 939 tests in 179.414s`; `FAILED (failures=1)`: the pre-existing `test_baseline` record defect of §6. **911 pre-existing + 28 new = 939**; no test removed, none newly ignored or skipped; the 28 A8 tests pass and no A8 test fails |
| same suite, default `docker exec` PATH | as above without `/usr/local/cargo/bin` and `/opt/opam/4.14.2/bin` | `FAILED (failures=12, errors=1)`: `binsec: command not found` (`IQ_VERSION_COMMAND`) and a missing rust runtime; a venue fact, not an A8 result, cleared by the documented `PATH` rather than by a weakened check |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (one named Phase-7 exemption printed) |
| JSON well-formedness | `python3 -m json.tool` on `PLAN.json`, `MANIFEST.json`, `CONTROLS.json` | exit 0 each |
| shard well-formedness | `python3 -m json.tool evidence/a8/SHARD-000.sarif` | exit 0 |
| producer, two runs | `python3 evidence/a8/build_evidence.py --out /tmp/a8a` and `--out /tmp/a8b` | `results=4245 runs=6 limit=5000 shards=1`; `shard 0: results=4245 bytes=8699144 sha256=b16d376a… first=0 last=4244`; `candidate token=dea0f422… mixed=True runs=6 distinct=6`; `union={… 'equalsParent': True, …}`; `synthetic: results=12001 shards=3 boundaries=0-4999,5000-9999,10000-12000`; `controls=17 codes=17` |
| producer byte-identity | `cmp /tmp/a8a/<name> /tmp/a8b/<name>` and against `evidence/a8/<name>` | `byte-identical` and `matches committed` for all four files |
| plan CLI | `python3 forensics/tools/code_scanning_export.py plan` | `plan: results=4245 runs=6 limit=5000 shards=1`; `shard 0: results=4245 first=0 last=4244 runs=[0, 1, 2, 3, 4, 5]`; exit 0 |
| verify CLI | `python3 forensics/tools/code_scanning_export.py verify evidence/a8` | `verify: ok shards=1 results=4245 union=complete duplicates=0 order=preserved tool=preserved rules=preserved artifacts=preserved candidate=dea0f422…`; exit 0 |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/CODE-SCANNING-EXPORT.md`, `?? evidence/a8/`, `?? forensics/tools/code_scanning_export.py`, `?? forensics/tools/tests/test_code_scanning_export.py` |

## 8. Obligations retained

* **One real shard.** The tracked population is 4,245 results. The export
  mechanism supports more, but no second real shard exists to test the
  multi-shard path against real data; the multi-shard path is exercised by the
  synthetic 6- and 12,001-result control populations.
* **GitHub's ingestion is unobservable.** The 5,000-result limit is a reported
  service limit, not a locally verifiable property. The export refuses an
  over-limit shard; it cannot prove what the service would do with one.
* **The file-size ceiling is not modelled.** The real shard is 8,699,144 bytes
  and no size check exists. A service with a lower ceiling could reject it, and
  this export would not know.
* **The copied `run.properties.a1.projection`** describes the parent run, not
  the shard's result list. It is copied because A1 owns the block, and the
  manifest records the limit; a consumer must read `properties.shard.resultCount`
  and the manifest's `union`, not that field, for the shard.
* **A3/A1 identity dependence.** The union check uses `a1Exact/v1` and the
  collision refinement of A1 §6.4. If A1's identity model changes, the export's
  union digest changes with it; that is identity binding, not instability.
* **No independent reviewer.** A8 is a tool with its own controls. The author is
  not an independent adjudicator of it, and no safety or correctness claim
  inherits from it.
* **The default-`PATH` court failures.** The reused court needs its toolchain
  directories on `PATH` for the pre-existing instrument tests. That is a venue
  configuration task, not an A8 repair, and it is recorded rather than hidden.

## 9. `NOT_RUN`

* **BOUNDARY.** No caller/dependency-closure audit of the export module, no
  Miri/ASan/equivalent (the item is Python only), and no negative-control canary
  outside the tool's own 17 refusal controls.
* **SEAL.** No full forensic regeneration, no downstream consumer replay, no
  release-candidate or schema validation.
* **Upload.** No upload, API call or token was used, by design; the structural
  check is the enforcement.
* **JSON-Schema validation** of the shard against the OASIS SARIF schema; only
  the structural checks named in §6 of the document ran.
* **A real acceptance test** by GitHub or any other code-scanning service.
* **A second real shard** (see §8).
* **An independent consumer replay** of `SHARD-000.sarif`.
* **CI wiring** of the new test module: the suite discovers it, but no CI profile
  was changed by this batch (`docker/` and CI are out of scope here).

## 10. Non-claims

A shard is not a census. An upload is not an admission. GitHub's ingestion,
truncation, deduplication and indexing are not evidence this project controls.
`EMITTED` is not `UPLOADED`. An exact identity is an identity of a record, not
of a defect, and presence, `level`, `ruleId` or a fingerprint establishes no
truth, severity or priority. The manifest states the export's population, not
the code base's. The plan is a local partition, not a prediction of what any
service will keep.
