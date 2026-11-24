# A11 receipt — one strict reader for received evidence, and the differential

## 1. Identity of this batch

| field | value |
|---|---|
| item | A11 (parser hardening: duplicate keys, encodings, non-finite numbers, integer range, number form, depth, size, trailing data, surrogates, control characters, non-text keys) |
| branch | `staging` |
| HEAD at the start | `f1c1a535d` (`a10: sign and verify the bytes that were received`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 22 18 0 5 23` (total 45, used 22, free 18, available **23** GiB); `Swap: 45 27 18` |
| derived court cap | `min(8g, 23 − 16) = 7g`, above the 2 GiB floor |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000`, Python 3.11.2 |
| heavy commands | one at a time; no Rust build; no `src/`, `docker/`, `AGENTS.md` or another item's tool/evidence modified |

The derived cap was 7 GiB and the running container's cap is 6 GiB, below it. The
container was reused rather than restarted, as A7–A10 did: one court holds the
memory budget, and restarting it would not lower the cap. Every reported gate is
Python-only and ran in that court. `free -g` after the work read
`Mem: 45 22 17 0 6 22` (available 22 GiB).

## 2. What was delivered

| path | lines / bytes | role |
|---|---:|---|
| `docs/PARSER-HARDENING.md` | 310 lines | normative document: the problem; the strict contract per rule and why each is refused; the differential and the duplicate-key demonstration; the scan population and result; all 13 refusal codes; the 13 controls; the boundary with the Rust and C parsers; non-claims; `NOT_RUN`; reproduction |
| `forensics/tools/harden.py` | 1,115 lines | `loads` (strict reader), `loads_permissive` (the named reference, used only by the differential), `differential`, `differential_pair`, `tracked_files`, `scan`, the 13 codes and the `parse`/`differential`/`scan` command line |
| `forensics/tools/tests/test_harden.py` | 522 lines | 64 controls: one per code; the duplicate-key and number-form differentials; the size, depth and integer boundaries at the limit and one past; BOM, trailing data, lone surrogate, control character, non-text key; `SKIPPED_SIZE`; symlink refusal; determinism; CLI exit codes with printed codes; document synchronisation |
| `evidence/a11/build_evidence.py` | 421 lines | deterministic producer of the scan, the differential and the controls; reads every digest from bytes; asserts the decisive collapse and every control code |
| `evidence/a11/SCAN.json` | 2,774 lines / 78,949 bytes | the bounded scan: the glob, the parameters, 386 population rows |
| `evidence/a11/DIFFERENTIAL.json` | 680 lines / 25,869 bytes | nine recorded cases, including the decisive duplicate-key pair |
| `evidence/a11/CONTROLS.json` | 408 lines / 16,475 bytes | 13 controls over the 13 codes, with the wrong conclusion each prevents |
| `evidence/a11/RECEIPT.md` | this file | the receipt |

`docs/ETP-TODO.md` replaced the A11 row only; no other row was touched and its
line count is unchanged (339). `spec_guard.py check` still reports the pinned
token set for that file with no drift.

## 3. The rule

> A received evidence record is read by one strict reader whose refusals are
> named, or it is not read. A construct whose meaning depends on the reader is
> refused, not normalised.

The item's premise is that a permissive parser does not only crash: it returns a
value while having read a different document. A duplicate key is last-wins; a
BOM is stripped or treated as content; trailing data is ignored; an integer is
unbounded in one reader and a double in another; `NaN` is accepted although it is
not JSON. The strict reader makes each of those a named refusal.

## 4. The strict contract and the differential

`loads(data, *, max_bytes, max_depth, integer_bits)` accepts bytes, decodes them
as UTF-8 strictly, refuses a BOM, bounds size before decoding and depth while
parsing, refuses a duplicate key at any depth, accepts only the six JSON value
kinds, refuses non-finite literals, bounds integer magnitude, refuses
non-canonical integer forms, refuses trailing data, refuses a lone surrogate and
a raw control character, and requires text keys. The defaults are 4 MiB,
depth 64 and 64 integer bits; they are recorded in `SCAN.json`.

`loads_permissive` is the explicitly named reference and is used only by the
differential. It decodes with `utf-8-sig`, uses
`json.JSONDecoder(strict=False).raw_decode` so a BOM, raw control characters and
trailing bytes are tolerated, installs no duplicate-key hook, and keeps the
default `parse_constant`, so `NaN`/`Infinity` are accepted. It is never used to
admit an evidence record.

`differential(data)` records the strict result, the permissive result, whether a
duplicate key collapsed, every number whose type or value moved, and which reader
accepted the input. `differential_pair(first, second)` reports
`samePermissiveValue`.

**The decisive case.** Two distinct byte strings, distinct digests, one object
under the permissive reader:

| input | bytes | SHA-256 | strict | permissive |
|---|---:|---|---|---|
| `{"a":1,"a":2}` | 13 | `1c53ee0df7b12fd4d65b976120c7fa6b847dc41dffd7f0331c3237a1ceab1756` | `PH_REFUSED_DUPLICATE_KEY` | `{"a":2}` |
| `{"a":2}` | 7 | `7e8059f495589fcd981232cc11d00b00da3802c01d688fa1cf1f6bed6e5bb33c` | accepted | `{"a":2}` |

The producer asserts `samePermissiveValue` and the first code; a control that
does not fire is a producer failure, not a warning.

| case | first SHA-256 | second SHA-256 | strict first | strict second |
|---|---|---|---|---|
| `duplicateKey` | `1c53ee0d…` | `7e8059f4…` | `PH_REFUSED_DUPLICATE_KEY` | accepted |
| `numberForm` (`-0` / `0`) | `d54829e5…` | `f3013f93…` | `PH_REFUSED_NUMBER_FORM` | accepted |
| `integerVsFloat` (`1` / `1.0`) | `2bfd14f4…` | `3b6b06ec…` | accepted | accepted |
| `nonFinite` (`NaN` / `0`) | `df38c437…` | `f3013f93…` | `PH_REFUSED_NONFINITE` | accepted |
| `bom` | `e3170108…` | `015abd7f…` | `PH_REFUSED_BOM` | accepted |
| `trailingData` | `dad3c0d0…` | `015abd7f…` | `PH_REFUSED_TRAILING_DATA` | accepted |
| `depth` (64 / 65) | `36127fd4…` | `de4118ef…` | accepted | `PH_REFUSED_DEPTH` |

The `-0`/`0` pair is a second collapse: an integer reader returns `0` for both,
so the sign is gone. `1`/`1.0` is the type move: equal under `==`, different
types. The non-finite variants also record `Infinity`, `-Infinity` and `1e400`,
which the permissive reader accepts as non-finite doubles.

## 5. The scan population and result

The population is tracked JSON evidence: glob `evidence/*.json`, matched with
`fnmatch.fnmatchcase` over `git ls-files`. `evidence/a11/` is excluded so the
record cannot depend on its own bytes; that exclusion is named in `SCAN.json`.

| quantity | measured |
|---|---:|
| tracked files matched | **386** |
| examined (at or below 4 MiB) | **211** |
| `STRICT_OK` | **211** |
| `SKIPPED_SIZE` (reported, not omitted) | **175** |
| other skips | 0 |
| refusals | **0** |

No tracked evidence record is refused at this bound. The 175 skipped files are
the large ones; the population is about 2.15 GB and the largest single file is
15,629,485 bytes. They are reported with their size and are not read, because
reading them in a pure-Python parser is the denial-of-service surface the bound
exists for. `SCAN.json` has one row per population member with path, size,
result, and the SHA-256 of every examined file.

## 6. The controls

`evidence/a11/CONTROLS.json` records **13 controls over the 13 codes**, exactly
one per code. The producer reads each code from the tool and fails if a control
fires a different code or if a code has no control.

| control | code |
|---|---|
| `encoding` | `PH_REFUSED_ENCODING` |
| `bom` | `PH_REFUSED_BOM` |
| `duplicate-key` | `PH_REFUSED_DUPLICATE_KEY` |
| `depth` | `PH_REFUSED_DEPTH` |
| `size` | `PH_REFUSED_SIZE` |
| `nonfinite` | `PH_REFUSED_NONFINITE` |
| `trailing-data` | `PH_REFUSED_TRAILING_DATA` |
| `integer-range` | `PH_REFUSED_INTEGER_RANGE` |
| `number-form` | `PH_REFUSED_NUMBER_FORM` |
| `lone-surrogate` | `PH_REFUSED_LONE_SURROGATE` |
| `control-character` | `PH_REFUSED_CONTROL_CHARACTER` |
| `key-not-text` | `PH_REFUSED_KEY_NOT_TEXT` |
| `syntax` | `PH_REFUSED_SYNTAX` |

| quantity | measured |
|---|---:|
| refusal codes | 13 |
| controls | 13 (one per code) |
| new `unittest` controls | 64 |
| whole tools suite | 1,111 (1,047 before this item) |

## 7. Defects found

**No existing tracked record was defective and no existing record was edited.**
The scan examined 211 records and refused none. `docs_consistency.py` and
`spec_guard.py check` were clean before and after the A11 row; no anchored claim
was disturbed and the pinned token set for `docs/ETP-TODO.md` did not drift.

Two defects were found in this item's own new files and are preserved here with
the old and the new form. Neither was a silent pass: both failed loudly before a
record was written.

| file | old form | new form | found by |
|---|---|---|---|
| `evidence/a11/build_evidence.py` | the producer read `cases["trailing"]` while the case was registered as `cases["trailingData"]`, so the build stopped with `KeyError: 'trailing'` | the producer reads `cases["trailingData"]` | the producer's own assertion run |
| `forensics/tools/harden.py` | `argparse` printed its own usage error for an unknown subcommand and no stable code, so `test_usage_errors_exit_two_and_print_a_code` failed | `_ArgumentParser.error` prints `harden: code=PH_USAGE …` and exits 2 | the control in `forensics/tools/tests/test_harden.py` |

**Measured and not a finding.** Three float literals in the examined population
are written with trailing zeros (`0.000760`, `2463.90`, `7011.20`). The strict
reader accepts them: their value and type do not change when the spelling is
shortened, and `PH_REFUSED_NUMBER_FORM` applies to integer literals and to
invalid number shapes, not to a float's trailing-zero spelling. This is a stated
scope decision, not an omission; no tracked record is refused for it.

## 8. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` | `Mem: 45 22 18 0 5 23` (available 23 GiB); `Swap: 45 27 18` |
| new controls | `python3 -m unittest forensics.tools.tests.test_harden` | `Ran 64 tests in 4.201s`; `OK` |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1111 tests in 211.037s`; `OK` (**1,047 before + 64 new = 1,111, 0 failures, 0 errors, 0 skipped**; no test removed, none newly ignored) |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on `SCAN.json`, `DIFFERENTIAL.json`, `CONTROLS.json` | `ok` for all three, exit 0 each |
| producer, two runs | `python3 evidence/a11/build_evidence.py --out /tmp/a11a --source-commit f1c1a535d` and the same to `/tmp/a11b` | `a11: files=386 examined=211 strictOk=211 skippedSize=175 refused=0 codes=13 controls=13 commit=f1c1a535d` twice |
| producer byte-identity | `cmp` of `/tmp/a11a/<name>`, `/tmp/a11b/<name>` and `evidence/a11/<name>` | `identical` for `SCAN.json`, `DIFFERENTIAL.json` and `CONTROLS.json` |
| the scan | `python3 forensics/tools/harden.py scan 'evidence/*.json'` | `scan: code=PH_OK glob=evidence/*.json files=386 examined=211 strictOk=211 skippedSize=175 refused=0`; exit 0 |
| worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`, `?? docs/PARSER-HARDENING.md`, `?? evidence/a11/`, `?? forensics/tools/harden.py`, `?? forensics/tools/tests/test_harden.py` |

**Reproducibility.** The producer reads the tracked population, the tool's bytes
and every control from the working tree; nothing is typed. `--source-commit` is
supplied; without it the recorded `BASE_COMMIT` is reused, never a live `HEAD`.
Two runs are byte-identical and the committed files match a fresh build,
enforced by `test_the_producer_is_deterministic_and_matches_the_committed_bytes`
and `test_the_source_identity_is_supplied_not_read_live`.

## 9. Obligations retained

* **No Rust or C parser hardening.** `src/` was not modified, the Rust suite was
  not run, and no claim about the C or Rust parser follows from a clean scan of
  Python-read evidence.
* **A bounded population.** 175 of 386 tracked evidence files were skipped by
  the 4 MiB bound. They are declared and counted, not examined; their contents
  are unknown at this bound.
* **One permissive reference.** The differential compares the strict reader with
  one named standard-library configuration. It does not enumerate every JSON
  reader, and it does not establish how another implementation would behave.
* **Float spellings are not canonicalised.** `2463.90` and `2463.9` parse to the
  same value and neither is refused. That is a value-preserving spelling
  difference with no type or value change; it is not a collapse.
* **No second implementation.** The strict reader has one implementation and one
  set of controls. An independent reader would be BOUNDARY evidence.
* **No independent review.** The author of the tool, document and controls is
  not an independent adjudicator of the code-to-conclusion mapping.
* **The differential is two readers, not a specification of JSON.** It shows
  where one named permissive configuration changes meaning; it does not prove
  that the strict rules are the only sound ones.

## 10. `NOT_RUN`

* **The Rust parsers under `src/` and the Rust suite.** Not modified, not run.
* **The C parser and the OpenSSL authority.** No C code was read or changed.
* **Records above the 4 MiB scan bound.** Skipped by size and reported.
* **A second implementation of the strict reader.** No independent reader exists.
* **Every other JSON reader.** The differential names one permissive reference.
* **JSON Schema validation.** No validator is in the standard library; the
  structural checks and the controls ran instead.
* **Independent review, BOUNDARY and SEAL.** No caller/dependency-closure audit,
  no independent reviewer, no full forensic regeneration or downstream replay.
* **Any cryptographic property.** A reader contract is not a cryptographic
  result and no constant-time claim is made.

## 11. Boundary with A9, A10 and the rest

A9 owns what a statement means; A10 owns the DSSE envelope, the PAE and
verification over received bytes, and it already refuses a duplicate key and
trailing bytes **in the envelope**. This item generalises the strict reading rule
to every JSON evidence record and provides the measured differential; it does
not change `dsse.py`, `intoto.py` or any item's records. A clean scan says these
bytes are read by this reader; it does not say the records are true, current or
complete, and it does not upgrade any other item's claim.

## 12. Correction (2026-11-24): the population is frozen, not a live glob

**A13 found this defect.** Running the whole tools suite at `6b33f1caa`/`cfb27c6eb`
produced `Ran 1202 tests` / `FAILED (failures=3)`, all three in `test_harden`:

| test | failure |
|---|---|
| `test_the_recorded_scan_covers_the_population` | `AssertionError: 386 != 389` |
| `test_scan_prints_the_code_and_the_counts` | `AssertionError: 'files=386' not found in 'scan: … files=389 examined=214 …'` |
| `test_the_producer_is_deterministic_and_matches_the_committed_bytes` | the producer regenerated 389 rows where the committed bytes said 386 |

**The old counts** were 386 files / 211 examined / 211 `STRICT_OK` / 175
`SKIPPED_SIZE`, and they were correct when measured. The old `SCAN.json`
(`sha256 9cc6680f1845b3589034f71f2ff5751338fa23efd041fed53d43c2a806e5376e`)
stored the population as the live glob `evidence/*.json` over `git ls-files`
plus a fixed `files: 386`. Every item that added a JSON record under `evidence/`
changed the glob's answer while the record still claimed 386, so the record was
valid only at the commit that produced it. This is Article 22's defect class: a
record bound to a moving measurement.

**The new contract.** The population is an explicit frozen member list of
`{path, sha256, bytes}` entries, declared at the candidate (`f1c1a535d`). A
rebuild reads that list, re-hashes each member, reproduces the per-file results
and the count, and never consults a live glob. A removed or changed member is
refused with `PH_REFUSED_POPULATION_DRIFT` (a record-verification code kept out
of the reader's 13 input refusals and their one-per-code controls, which are
unchanged). Growth is reported, not absorbed: a glob match that is not a member
is reported `NEW_SINCE_RECORD` with its path and digest, counted separately, and
the frozen count is unchanged. A live scan is still available (`scan --live`)
but its result is labelled `population: LIVE` and `verify_record` refuses to
compare it to a frozen record.

**The new frozen population** is the same 386 members, now bound by digest; its
count is **386 files / 211 examined / 211 `STRICT_OK` / 175 `SKIPPED_SIZE` / 0
refused**. The 175 skipped members now carry a digest too (`bytes` was the only
binding before); hashing streams in 1 MiB chunks and never parses a member above
the bound. The new `SCAN.json` is
`sha256 0307db34a7cbb3e253462b4b0a3ead946b3d698a6a65e8f78ec02da163cb5b5a`
(`schema openssl-rs/a11/scan/2`). At the correction commit the live glob matches
393 files, so verification reports the 7 records A12 and A13 landed
(`evidence/a12/{CONTROLS,TRUST-ROOTS,VERIFICATION}.json` and
`evidence/a13/{ARTEFACT,CLASSIFICATION,CONTROLS,SIGNATURE}.json`) as
`NEW_SINCE_RECORD`; the frozen count stays 386, and `SCAN.json` does not absorb
them, so it remains byte-stable as later items land.

**What changed.** `forensics/tools/harden.py` gained `freeze_population`,
`scan_frozen_population`, `population_growth`, `verify_record`, `hash_file` and
the `scan --live` / `scan --frozen RECORD` modes; `evidence/a11/build_evidence.py`
now seeds the frozen member list from the record (never from a live glob) and
emits `schema …/scan/2`; `forensics/tools/tests/test_harden.py` gained five
controls (frozen coverage, reproduction at `HEAD`, the growth control on a
temporary mirror, the changed/removed refusal, and the LIVE label) and was not
relaxed; `docs/PARSER-HARDENING.md` §4 states the frozen-population contract. The
reader, its 13 codes, the 13 controls, `DIFFERENTIAL.json` and the differential
cases were not changed in substance (only the recorded tool digest moved).

**Not established here.** This correction re-binds the population; it does not
examine the 175 above-bound members, and it does not upgrade the item to
`SAFETY_DISCHARGED` or any consumer to `SAFE_COMPATIBLE`. The `A11` row in
`docs/ETP-TODO.md` still quotes the live 386 figure; that file is outside this
correction's write scope and is recorded as a follow-up, not silently edited.
