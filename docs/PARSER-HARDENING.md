# Parser hardening: one strict reader for received evidence

This document is the normative description of A11. The implementation is
`forensics/tools/harden.py`; the controls are
`forensics/tools/tests/test_harden.py`; the recorded evidence is
`evidence/a11/{SCAN,DIFFERENTIAL,CONTROLS}.json`, produced deterministically by
`evidence/a11/build_evidence.py`. The receipt is `evidence/a11/RECEIPT.md`.

Every record this project admits is parsed by something, and a permissive parser
does not only crash: it returns a value while having read a different document.
This document fixes the reading contract, shows where the permissive reader
would have changed the meaning, and records the population the strict reader was
run over.

## 1. The problem

The failure is a silent change of meaning, not only an exception. Five permissive
habits do the damage, and each is observable in a standard-library reader:

* **A duplicate key is last-wins.** `{"a":1,"a":2}` and `{"a":2}` are different
  byte strings; `json.loads` returns the same object `{"a": 2}` for both. A
  record that was read as the second document cannot be distinguished from the
  first.
* **`NaN` and `Infinity` are accepted although they are not JSON.** The
  standard decoder returns `float("nan")` and `float("inf")` for them.
* **A BOM and trailing data are accepted by some readers.** A `utf-8-sig`
  reader strips the BOM; a reader that decodes the first value and ignores the
  remainder accepts `{"a":1}{"b":2}` as `{"a": 1}`.
* **An integer is exact in one reader and a double in another.** Above
  `2**53` an IEEE-754 round-trip changes the value; an unbounded integer reader
  does not. The same bytes are two different numbers.
* **A number's spelling carries a type.** `1` is an integer and `1.0` is a
  float; `-0` loses its sign when read as an integer; a deeply nested or very
  large input turns the parser into a denial-of-service surface.

The rule is singular:

> A received evidence record is read by one strict reader whose refusals are
> named, or it is not read. A construct whose meaning depends on the reader is
> refused, not normalised.

## 2. The strict contract

`loads(data, *, max_bytes, max_depth, integer_bits)` accepts `bytes` and returns
the parsed value or raises `Refusal` with a stable code. The three bounds are
parameters, not properties of JSON: a consumer that needs IEEE-754 exactness
passes `integer_bits=53`, and a larger record passes a larger `max_bytes`. The
defaults are `max_bytes = 4,194,304` (4 MiB), `max_depth = 64` and
`integer_bits = 64`; they are recorded in `evidence/a11/SCAN.json` so the bound
and the population travel together.

| rule | contract | code that enforces it |
|---|---|---|
| encoding | the bytes decode as UTF-8 strictly; no fallback encoding, no `latin-1` rescue | `PH_REFUSED_ENCODING` |
| byte-order mark | a UTF-8, UTF-16 or UTF-32 BOM at the start is refused, not stripped | `PH_REFUSED_BOM` |
| duplicate key | a key repeated in any object at any depth is refused; the later value never replaces the earlier one | `PH_REFUSED_DUPLICATE_KEY` |
| depth | the number of nested containers is at most `max_depth`; one deeper is refused | `PH_REFUSED_DEPTH` |
| size | an input longer than `max_bytes` is refused before decoding | `PH_REFUSED_SIZE` |
| non-finite | `NaN`, `Infinity`, `-Infinity`, and a finite literal that overflows to infinity in a double are refused | `PH_REFUSED_NONFINITE` |
| trailing data | only whitespace may follow the top-level value; anything else is refused | `PH_REFUSED_TRAILING_DATA` |
| integer range | an integer's magnitude must be below `2**integer_bits`; the sign is separate | `PH_REFUSED_INTEGER_RANGE` |
| number form | an integer is `0` or `-?[1-9][0-9]*`; a leading `+`, a leading zero, `-0`, `1.` and `.5` are refused | `PH_REFUSED_NUMBER_FORM` |
| lone surrogate | a `\u` escape that encodes an unpaired high or low surrogate is refused; a paired surrogate is decoded | `PH_REFUSED_LONE_SURROGATE` |
| control character | a raw character below U+0020 in a string is refused; it must be escaped | `PH_REFUSED_CONTROL_CHARACTER` |
| key not text | an object member name must be a JSON string | `PH_REFUSED_KEY_NOT_TEXT` |
| syntax | an empty, truncated or malformed document is refused | `PH_REFUSED_SYNTAX` |

**Why each is refused.**

* Encoding: two decodings of one byte string make a digest over the bytes and a
  digest over the text disagree, so the record read is not the record hashed.
* BOM: a reader that strips it and a reader that treats it as content disagree
  about the first key; a reader that half-detects UTF-16 produces a different
  document.
* Duplicate key: two documents become one value, which is the item's central
  defect (§3).
* Depth and size: the reader's behaviour must not depend on the interpreter's
  recursion limit or on how much memory the process happens to have.
* Non-finite: `NaN` is not JSON, and `1e400` is a finite literal whose value
  becomes infinite; either way the number read is not the number written.
* Trailing data: a second document appended to a record must not be ignored
  while the first is read and reported.
* Integer range: a value above `2**53` is not exact in a double; an unbounded
  integer reader and a double reader return different numbers for one spelling.
* Number form: one value must have one accepted spelling; otherwise a rewrite
  from `-0` to `0` is invisible and a leading zero is a second spelling.
* Lone surrogate: a Python `str` can hold an unpaired surrogate that cannot be
  emitted to UTF-8 without failing or being replaced.
* Control character: an unescaped newline or NUL changes string content under a
  reader that normalises it.
* Key not text: a coerced key is a key the document did not write.
* Syntax: an empty or partial document is not an empty or partial value.

The reader preserves the integer/float distinction. It does not canonicalise a
float's spelling: `2463.90` and `2463.9` parse to the same float and neither is
refused, because no value or type changes. Three such spellings occur in the
examined population and none of them is a refusal. This is a deliberate scope
decision for `PH_REFUSED_NUMBER_FORM`, which applies to integer literals and to
invalid number shapes.

## 3. The differential

`loads_permissive(data)` is the explicitly named reference: it decodes with
`utf-8-sig`, uses `json.JSONDecoder(strict=False).raw_decode` so a BOM, raw
control characters and trailing bytes are tolerated, installs no duplicate-key
hook, and keeps the default `parse_constant`, so `NaN`/`Infinity` are accepted.
It is used only by `differential` and never to admit an evidence record.

`differential(data)` parses one input with both readers and records the strict
result, the permissive result, whether the permissive reader collapsed a
duplicate key, every number whose type or value moved, and which reader accepted
the input. `differential_pair(first, second)` runs that comparison on two byte
strings and reports `samePermissiveValue`: distinct inputs the permissive reader
maps to one value.

**The decisive case.** These two distinct byte strings have distinct digests and
the permissive reader returns one object for both:

| input | bytes | SHA-256 | strict | permissive |
|---|---:|---|---|---|
| `{"a":1,"a":2}` | 13 | `1c53ee0df7b12fd4d65b976120c7fa6b847dc41dffd7f0331c3237a1ceab1756` | `PH_REFUSED_DUPLICATE_KEY` | `{"a":2}` |
| `{"a":2}` | 7 | `7e8059f495589fcd981232cc11d00b00da3802c01d688fa1cf1f6bed6e5bb33c` | accepted | `{"a":2}` |

`samePermissiveValue` and `samePermissiveCanonical` are both `true`. A reader
that reports the second object cannot say which document it read; the strict
reader refuses the first and names why. This is recorded as
`cases.duplicateKey` in `evidence/a11/DIFFERENTIAL.json`; enforced by
`test_the_duplicate_key_pair_collapses_under_the_permissive_reader` and by the
producer's `samePermissiveValue` assertion.

| case | first SHA-256 | second SHA-256 | strict first | strict second | permissive |
|---|---|---|---|---|---|
| `duplicateKey` | `1c53ee0d…` | `7e8059f4…` | `PH_REFUSED_DUPLICATE_KEY` | accepted | one value |
| `numberForm` (`{"n":-0}` / `{"n":0}`) | `d54829e5…` | `f3013f93…` | `PH_REFUSED_NUMBER_FORM` | accepted | one value |
| `integerVsFloat` (`1` / `1.0`) | `2bfd14f4…` | `3b6b06ec…` | accepted | accepted | equal under `==`, types differ |
| `nonFinite` (`NaN` / `0`) | `df38c437…` | `f3013f93…` | `PH_REFUSED_NONFINITE` | accepted | `NaN` accepted |
| `bom` | `e3170108…` | `015abd7f…` | `PH_REFUSED_BOM` | accepted | BOM stripped |
| `trailingData` | `dad3c0d0…` | `015abd7f…` | `PH_REFUSED_TRAILING_DATA` | accepted | second value ignored |
| `depth` (64 / 65) | `36127fd4…` | `de4118ef…` | accepted | `PH_REFUSED_DEPTH` | both accepted |

The `-0` pair is the number-form collapse: an integer reader returns `0` for
both `-0` and `0`, so the sign is gone. The `integerVsFloat` pair is the type
move: `1` and `1.0` are equal under `==` but are different types, and the
permissive reader has no single value for both. The non-finite group also
records `Infinity`, `-Infinity` and `1e400`, which the permissive reader accepts
as non-finite doubles. Enforced by
`test_the_number_form_pair_collapses_negative_zero`,
`test_an_integer_and_a_float_are_different_types`,
`test_non_finite_is_accepted_only_by_the_permissive_reader` and
`test_bom_trailing_data_and_depth_differ`.

**What the differential does not show.** It compares one strict reader with one
named permissive configuration. It does not enumerate every JSON reader, and it
does not prove that no other permissive reader behaves differently. It shows
that a named, standard-library-based reader changes meaning on these inputs and
that the strict reader refuses them.

## 4. The scan population and its result

The scan population was discovered over **tracked JSON evidence** at the
declared candidate: the glob is `evidence/*.json`, matched with
`fnmatch.fnmatchcase` against `git ls-files`, so `*` matches across `/` and the
pattern covers the subtree. The records this item emits (`evidence/a11/`) are
excluded, so the scan cannot depend on its own bytes; the exclusion is named in
`evidence/a11/SCAN.json`.

The population is **frozen as an explicit member list**, not stored as a glob
count. `evidence/a11/SCAN.json` records `{path, sha256, bytes}` for every member
declared at the candidate; rebuilding it re-hashes each member and reproduces
the per-file results and the count. A member whose bytes changed, or that no
longer exists, is refused with `PH_REFUSED_POPULATION_DRIFT` — a
record-verification code, distinct from the reader's 13 input refusals. Growth is
reported, not absorbed: a file that matches the glob now but is not a member is
reported `NEW_SINCE_RECORD` with its digest, counted separately, and the frozen
count is unchanged. A live scan remains available as `harden.py scan --live`, but
its result says `population: LIVE` and is not comparable to a frozen record.

| quantity | measured |
|---|---:|
| frozen population members | **506** |
| examined (at or below 4 MiB) | **331** |
| `STRICT_OK` | **331** |
| `SKIPPED_SIZE` (reported, not omitted) | **175** |
| other skips | 0 |
| refusals | **0** |

Every examined record parses `STRICT_OK`; no tracked evidence record is refused
at this bound. The 175 skipped files are the large records (the population is
about 2.16 GB, 2,157,829,177 bytes; the largest single file is 15,629,485 bytes).
They are reported
`SKIPPED_SIZE` with their size and are not parsed, because reading them into a
pure-Python parser would be the denial-of-service surface this item exists to
bound; they are streamed in 1 MiB chunks only to bind their digest.
`evidence/a11/SCAN.json` records one row per frozen member with its path, size,
`STRICT_OK` or `SKIPPED_SIZE`, and the SHA-256 of every member.

The count is the member list's length at the declaration
(`a99ddf9677229487e5cf4051031e886444a189b7`, C32); it moves only through an explicit
re-freeze (`build_evidence.py --freeze-population CANDIDATE`), never because
another item landed. That declaration supersedes `9ed7a58b423e4ec7df072f5a6f1634682420d238`
and **grows the population from 519 to 529**: C31 added ten JSON records under
`evidence/performance-frontier/campaigns/PFP-2/` and
`claims/PFP-2.{claim,raw-manifest}.json`, so the count is 529, 354 examined, 354
`STRICT_OK`, 175 `SKIPPED_SIZE`, 0 refused, and the byte total is 2,157,829,177.
The growth is explicit (the re-freeze took C32's path set), not absorbed from a
live glob. Four members' content had moved since the `9ed7a58b4` declaration (the
three A16 records and `performance-frontier/admission/ARMS.json`), so the
candidate and those digests were re-bound. The `9ed7a58b4` declaration had itself
superseded `3ee456d4f8e6e0a62cb96e4c0a31ea0f0ec50db5` with the population grown
from 513 to 519 (six PFP-0-refreeze records added at C28, four moved), and the
`3ee456d4` declaration had itself superseded `1dac1c6e6187fc79e3c9902cfbcc67819a6ba0db` with the population
grown from 506 to 513 (26 moved, seven FRC/performance-frontier records added),
and the `1dac1c6e`
declaration had itself superseded `26e98445fc031066446a3190e329dca41d0da5d8` with
membership unchanged (seven members moved), `26e98445` had superseded
`902b4660ab1807f08a4f8f796db79ad4322b90d4` with 22 members re-bound after the
C8–C11 repairs, and `902b4660` had superseded
`e94c7fdf127d2f2290f7f7c248924a4d6755add6` with membership unchanged (only five
members' content moved then). The earlier freezes stay auditable in
`evidence/a11/RECEIPT.md` §13 and in the git history; the receipt is not edited
by a re-freeze because A19 hashes it as a source input. The population is complete over tracked
evidence JSON:
other items' records — including A16's three records — are members, and A16
breaks the resulting digest cycle from its side by declaring exactly
`evidence/a11/{SCAN,DIFFERENTIAL,CONTROLS}.json` excluded and reporting them
`NEW_SINCE_RECORD`.

The scan does not follow a symlink and does not read outside the repository
root; such a path is reported `SKIPPED_SYMLINK` or `SKIPPED_OUTSIDE`. Enforced by
`test_a_file_over_the_bound_is_reported_not_omitted`,
`test_a_symlink_is_not_followed` and `test_the_recorded_scan_covers_the_population`.

## 5. The refusal table

Every code is stable and is cited verbatim by the tool, the tests, this document
and the evidence. The third column is the wrong conclusion the code prevents.

| code | condition | prevents |
|---|---|---|
| `PH_REFUSED_ENCODING` | the bytes are not valid UTF-8 | that a fallback encoding turns the hashed bytes into a different string |
| `PH_REFUSED_BOM` | a UTF-8, UTF-16 or UTF-32 BOM starts the input | that a stripped BOM and a BOM read as content are both "the document" |
| `PH_REFUSED_DUPLICATE_KEY` | an object repeats a key at any depth | that two distinct documents collapse to one value |
| `PH_REFUSED_DEPTH` | containers nest deeper than `max_depth` | that the result depends on the interpreter's recursion limit |
| `PH_REFUSED_SIZE` | the input exceeds `max_bytes` | that an unbounded input is read before admissibility is decided |
| `PH_REFUSED_NONFINITE` | a `NaN`/`Infinity` literal, or a literal that overflows to infinity | that a value that is not JSON, or a changed finite value, is read as a number |
| `PH_REFUSED_TRAILING_DATA` | non-whitespace follows the top-level value | that a second document is ignored while the first is reported |
| `PH_REFUSED_INTEGER_RANGE` | an integer's magnitude does not fit `integer_bits` | that an exact integer becomes a rounded double |
| `PH_REFUSED_NUMBER_FORM` | `+1`, `01`, `-0`, `1.`, `.5`, or a malformed number | that one value has several accepted spellings |
| `PH_REFUSED_LONE_SURROGATE` | an unpaired surrogate escape | that an unemittable string is read as text |
| `PH_REFUSED_CONTROL_CHARACTER` | a raw character below U+0020 in a string | that an unescaped newline or NUL changes string content |
| `PH_REFUSED_KEY_NOT_TEXT` | an object member name is not a string | that a coerced non-text key is read as a key |
| `PH_REFUSED_SYNTAX` | the input is not JSON | that an empty or partial document is read as a value |

## 6. The controls

`evidence/a11/CONTROLS.json` records **13 controls over the 13 codes**, exactly
one per code. Each control is a byte string, its hex and SHA-256, the bounds it
was read under, the strict result and the permissive result. The producer reads
each code from the tool and fails if a control fires a different code or if a
code has no control. Enforced by `test_controls_cover_every_code_and_fire`.

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

A control proves that a refusal fires for the substituted form. It does not
prove that form occurs in the tree, and it does not test a second implementation.
The boundary controls are also at their exact limits: the size and depth
boundaries accept the value at the limit and refuse one past it, enforced by
`test_size_at_the_limit_and_one_past`, `test_depth_at_the_limit_and_one_past`
and `test_integer_bits_at_the_limit_and_one_past`.

## 7. The boundary

This item hardens **a reader for evidence files**. It does not harden the Rust
parsers in `src/`, which have their own tests, and it does not claim that the C
or Rust parser is safe. The Python reader here is used to read JSON evidence
records; the modules that interpret those records are separate, and their
contracts are not changed by this reader.

* The reader does not decide what a record means; it decides whether the bytes
  are a JSON document this project will read at all.
* The scan is bounded and its bindings are reported. A record above the bound is
  `SKIPPED_SIZE`, which is a declared omission, not an examination.
* The permissive reference is not a second implementation of the strict reader.
  It is a named configuration of the standard library used to make the
  differential's comparison explicit.
* The Rust and C parsers are outside this item. No claim about them follows from
  a clean scan of Python-read evidence.

## 8. Non-claims

* A `STRICT_OK` result is not a claim that the record's contents are true,
  current or complete. It is a claim about the reading of its bytes.
* The scan is not a census of the tree. It is a bounded scan of a named
  population; the 175 files above the bound were not examined.
* The differential does not prove that every other JSON reader behaves as the
  permissive reference. It names one permissive configuration and shows where it
  changes meaning.
* The controls do not prove that a construct occurs in any tracked record. They
  prove the refusal fires for the control.
* A refusal code is a reading decision, not a repair. This item does not rewrite
  a refused record.
* The absence of a refusal in the examined population is not a proof that no
  tracked record can be refused at another bound.
* The document, the tool, the tests and the evidence are not an independent
  review.

## 9. `NOT_RUN`

* **The Rust parsers in `src/`.** Not modified and not hardened here; the Rust
  suite was not run.
* **The C parser and the OpenSSL authority.** No C code was read or changed.
* **Records above the 4 MiB scan bound.** Skipped by size and reported; not
  parsed.
* **A second implementation of the strict reader.** The differential compares
  the strict reader with one named permissive configuration, not with an
  independent reader.
* **Every JSON reader.** The differential does not enumerate the ecosystem.
* **Independent review and BOUNDARY evidence.** The author of the tool,
  document and controls is not an independent adjudicator.
* **SEAL.** No full forensic regeneration, downstream replay or release-candidate
  assurance.
* **A cryptographic property.** This is a reader contract, not a cryptographic
  result.

## 10. Reproducing the evidence

```
python3 evidence/a11/build_evidence.py --source-commit a99ddf9677229487e5cf4051031e886444a189b7
python3 evidence/a11/build_evidence.py --freeze-population a99ddf9677229487e5cf4051031e886444a189b7
python3 forensics/tools/harden.py scan --frozen evidence/a11/SCAN.json
python3 forensics/tools/harden.py scan 'evidence/*.json'
python3 forensics/tools/harden.py parse evidence/a11/CONTROLS.json
python3 -m unittest forensics.tools.tests.test_harden
```

The producer reads the tracked population, the tool's bytes and every control
from the working tree; it writes `SCAN.json`, `DIFFERENTIAL.json` and
`CONTROLS.json` with sorted keys. Two runs are byte-identical and the committed
files match a fresh build, enforced by
`test_the_producer_is_deterministic_and_matches_the_committed_bytes`. The source
identity is supplied (`--source-commit`), never read from a live `HEAD`,
enforced by `test_the_source_identity_is_supplied_not_read_live`.
