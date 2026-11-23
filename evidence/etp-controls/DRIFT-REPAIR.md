# Control-suite drift repair (ETP-T3 / ETP-T4)

**Source candidate:** `246e30580f909c047eeb04a93a06f9bd05dc65f3` (`staging`).
**Evidence commit:** `UNKNOWN` at write time; settled by
`git log -1 --format=%H -- evidence/etp-controls/DRIFT-REPAIR.md`.
**Starting worktree:** one untracked path outside this repair,
`forensics/tools/preservation.py`; every tracked file clean.
**Venue:** court container `openssl-rs-court` (`openssl-rs-court-tools:1`),
`available` 21 GiB, derived cap `min(8g, 21g - 16g) = 5g` (2g floor met).
No Rust build was run because `available < 24 GiB`.

The suite reproduced three failures before the repair:

| test | refusal | classification |
|------|---------|----------------|
| `test_committed_registry_passes` | `SP_KNOWN_FAILURE_DRIFT: docs/ETP-TODO.md: tokens added ['OPENSSL_clear_free', 'guard_ffi'], removed []` | stale record |
| `test_check_output_is_deterministic` | same refusal, same cause | stale record |
| `test_committed_inventory_and_axioms_validate` | `ET4_SOURCE_DRIFT: inventory records b38e0f42…, tree is ef8678c5…` | real source change, stale inventory |

## 1. ETP-T3: stale known-nonconformance token set

The spec guard does not compare a commit or a document digest. For each entry in
`known_failures` it recomputes `scan(read_text(path), lexicon)` and compares the
resulting token set with the recorded `tokens` array
(`forensics/tools/spec_guard.py:392-418`). The recorded entry for
`docs/ETP-TODO.md` held 87 tokens and did not contain `OPENSSL_clear_free` or
`guard_ffi`; the current text produces 89.

The document did change after the record was written:

| token | location in `docs/ETP-TODO.md` | where it entered the document |
|-------|-------------------------------|-------------------------------|
| `guard_ffi` | line 120 (ETP-T2 row), line 124 (ETP-T6 row) | ETP-T6 commits `a4cf2601a`, `5750ac150` |
| `OPENSSL_clear_free` | line 125 (ETP-T7 row) | ETP-T7 commit `bf8c64371` |

Both are genuinely internal, so the finding is correct rather than a lexicon
false positive:

* `guard_ffi` is `pub fn guard_ffi` at `src/ffi/mod.rs:74`; it is not an exported
  C symbol, `#[no_mangle]` item or `extern "C"` declaration.
* `OPENSSL_clear_free` is a `pub(crate) unsafe fn` at `src/cms/cms_asn1.rs:820`
  spelled after the authority macro; it is internal, not an ABI observable.

The document remains a known nonconformance: it still names 89 internal
identifiers. The sanctioned repair is therefore to regenerate the recorded token
set, not to exempt a token, delete a check or change a threshold. The guard, its
levels, its thresholds and its six controls are unchanged.

## 2. ETP-T4: real source change, stale inventory

`unsafe_obligations.validate` compares the inventory's
`identity.source_tree_sha256` with a live hash of every `src/**/*.rs` file
(`forensics/tools/unsafe_obligations.py:1738-1763`). It also compares
`identity.scanner_sha256` with the live tool; that comparison matched, so the
scanner was not the cause.

The recorded digest is the exact source tree at the recorded commit, not a
malformed record. Reconstructing `src/` from the named commit and hashing it the
same way gives:

| identity | source tree SHA-256 | files | lines |
|----------|---------------------|-------|-------|
| `07b776d688fdd1dcc4e315661894c30e623aed9e` (recorded) | `b38e0f426c967da4e5433217b6e03b3042bf8773a0cea1dee0d778c637651a7d` | 883 | 910,498 |
| `246e30580f909c047eeb04a93a06f9bd05dc65f3` (current) | `ef8678c53feb9ec59e8cc61c6a0b636ae59aeb01b6dbe482ebc463932ae2ed1d` | 884 | 915,237 |

Seven commits after the record changed the tree:

```
M src/bn/blinding.rs
A src/rsa/ext_kdk_model.rs
M src/rsa/mod.rs
M src/rsa/object.rs
M src/rsa/ossl.rs
M src/runtime/secret.rs
M src/runtime/stack.rs
```

(`ecd01a20f`, `5d38094cc`, `5750ac150`, `c28ac7bb9`, `4cafcd0ea`, `0cd5dbf73`,
`0eddfe839`). This is a real source change that the inventory had not absorbed,
not only a stale record. The inventory, axiom register and vacuity record were
regenerated at the current tree; `unsafe_obligations.py validate` reports
`0 problems`.

| quantity | recorded at `07b776d68` | regenerated at `246e30580` |
|----------|------------------------|----------------------------|
| sites | 62,178 | 62,297 |
| operations | 767 | 767 |
| `raw_dereference` | 7,402 | 7,430 |
| `ffi_call` | 5,114 | 5,129 |
| `delegated_unsafe_contract` | 36,607 | 36,676 |
| `ownership_adoption` | 2,561 | 2,564 |
| `abi_export` | 6,113 | 6,113 |
| tautological assertions | 0 | 0 |
| ignored tests | 54 | 54 |

The source change also produces two genuinely new distinct vacuity findings,
both test-only `unsafe fn` helpers in `src/rsa/ossl.rs` that cite a caller
obligation without a stateable contract:

* `default_rng_bytes` — `CALLER_OBLIGATION_UNESTABLISHED`
* `scripted_bytes` — `CALLER_OBLIGATION_UNESTABLISHED`

They are recorded in `evidence/etp-t4/VACUITY.json`; they do not make the
validator refuse, and no `src/` change is made by this repair.

### Recorder defect corrected

`build_inventory` hard-coded `identity.commit` to
`07b776d688fdd1dcc4e315661894c30e623aed9e`, `branch` to `staging`, and a fixed
`worktree_state` string. Regenerating the inventory would therefore have
recorded a source tree from HEAD under a commit that cannot produce it. The
identity fields are now read from git (`rev-parse HEAD`, `rev-parse
--abbrev-ref HEAD`, and `status --porcelain -- src`), and `UNRECORDED` is
written when git is unavailable. This changes the scanner digest from
`7b17d4c2b49b8584a0bf7dbfaf98fe84d359e82256a5d01b208675dd1592f3c0` to
`443634a38f50d2563e1abdb2352ae0c8171ad03a06b05e058cf637392e5bf6ad`; the
regenerated inventory records the new digest and the validator binds it.

The T1 seeder had two related stale literals: a hard-coded
`62,178 site rows and 767 operation rows` detail, and `etp_t4.candidate` fixed
to the old analysis commit. Both now derive from the inventory being projected.
Re-seeding `evidence/etp-t1/TRACEABILITY.json` over the regenerated records
produces `361 nodes, 475 edges, 43 orphans`, with `0 undeclared, 0 stale`; the
ETP-T4 files remain declared class-8 orphans at `07b776d68`, where they do not
exist, exactly as before. The hazard-register cross-check is unaffected because
its register digest, hazard nodes and edges are unchanged.

## 3. Regenerated versus recorded as a finding

| record | treatment | current SHA-256 |
|--------|-----------|-----------------|
| `evidence/etp-t3/SPECIFICATIONS.json` | regenerated token set, 87 to 89; no other field changed | `baad775c94c4e4630ab5ef2c296ea0a3d57c1308a3525bab6f9a323ade45bd62` |
| `evidence/etp-t4/SAFETY-SITES.json` | regenerated at the current tree | `7fb1ef96b7b7b36b9d49ae7283743b51ec9db6170bbde74074a6af0a8856e7da` |
| `evidence/etp-t4/AXIOMS.json` | regenerated with the same scan | `edbf1a01a4e30c93ae1513d5b1f96a0d475ecbf1656428928720911bd73e4ee0` |
| `evidence/etp-t4/VACUITY.json` | regenerated; two new test-only rows recorded | `3f62923f032d5571bb80931ea9ff440b1d83aff3f9403eb5dce8708b9e0893b1` |
| `evidence/etp-t1/TRACEABILITY.json` | re-seeded T4 projection only | `d5920c800ad113722d0645b27af0f27e1caee9b2ac596379aa41871be7909e26` |

No check, threshold, refusal code, test or suppression was removed, relaxed or
turned into an expected failure. No new exemption was added. The two new
internal identifiers remain recorded as a known nonconformance, and the two new
T4 rows remain recorded as `CALLER_OBLIGATION_UNESTABLISHED`.

## 4. Previous identities preserved as history

The superseded records are verbatim copies under
`evidence/etp-controls/history/`, described by its `README.md`:

| superseded file | SHA-256 |
|-----------------|---------|
| `SPECIFICATIONS-superseded-07b776d68.json` | `5588e62c314d5e97d0b2516cf7ec55ca1b86b50280fd91340e21fe40cd602456` |
| `SAFETY-SITES-superseded-07b776d68.json` | `09df1355e79fabde6098bfcd3b0d3f6e9d72bd631b2deb08148d33d3963b2f04` |
| `AXIOMS-superseded-07b776d68.json` | `697e885e66ad45b3dd931a0088cdbc68118dfa17e868cc7a7c75f149493036ae` |
| `VACUITY-superseded-07b776d68.json` | `6db78f8fd860b0109cf6c5cf905a4c6c597c4fb5b46fc0fe8931045bdbd196c6` |
| `TRACEABILITY-superseded-t4-07b776d68.json` | `2fc3298fbe142db81acc51048364f78d8902c82a9598739dde132c3457a1a650` |

The superseded `SPECIFICATIONS.json` records the 87-token belief; the superseded
inventory records source tree `b38e0f42…`; the superseded graph records the old
ETP-T4 projection under graph identity
`21bea318819a56f641b3aa2f25027216b97a1c4d`. None of these files was edited in
place.

## 5. Verification

**Suite.** The same command was run before and after:
`python3 -m unittest discover -s forensics/tools/tests`.

| run | tests | failures | result |
|-----|-------|----------|--------|
| before | 451 | 3 | `FAILED (failures=3)` |
| after | 451 | 0 | `OK` |

The qualified test identifiers were extracted from verbose runs and sorted.
`diff` of the before and after lists is empty: 451 identifiers before, 451
after, 0 removed, 0 added, 0 duplicates. No test was skipped, removed or marked
as an expected failure.

**Guard self-tests.**

* `python3 forensics/tools/spec_guard.py check` → exit 0, `10 registered
  specification(s), 5 recorded known nonconformance(s), 6 level(s); 0
  unclassified, 0 unjustified exemptions`.
* `python3 forensics/tools/spec_guard.py self-test` → `6 controls behaved as
  recorded`.
* `python3 forensics/tools/spec_guard.py inventory` → `5/15
  specification-bearing documents name an internal identifier` (exit 1 by
  design; the measured population still names internals).
* `python3 forensics/tools/unsafe_obligations.py validate` → `0 problems`.

**Mutating controls.** In addition to the committed controls, a temporary
control script (not tracked) mutated each repair's input:

| guard | mutation | observed refusal |
|-------|----------|------------------|
| spec guard | remove `guard_ffi` from the recorded `docs/ETP-TODO.md` token set | `SP_KNOWN_FAILURE_DRIFT: docs/ETP-TODO.md: tokens added ['guard_ffi'], removed []` |
| T4 inventory | replace `identity.source_tree_sha256` with 64 zeroes | `ET4_SOURCE_DRIFT: inventory records 0000…0000, tree is ef8678c5…` |
| T4 vault | clear the controls of discharge `DISC-OWNEDSTR-OB2` | `ET4_DISCHARGE_WITHOUT_CONTROL: DISC-OWNEDSTR-OB2` |

The committed negative controls were also run directly and passed:
`test_known_failure_drift_is_refused`,
`test_stale_known_failure_is_refused`,
`test_discharge_without_control_is_refused`,
`test_control_that_cannot_fail_is_refused`,
`test_vacuous_precondition_reported_satisfied_is_refused`,
`test_caller_obligation_without_witness_is_refused`,
`test_tautological_assertion_is_refused`,
`test_inverted_assertion_is_reported_as_a_failure` (9 tests, `OK`).

## 6. Residuals and worktree observations

* No suite failure remains. No `src/` or `docker/` change was made.
* `evidence/etp-t1/TRACEABILITY.json` keeps its graph identity
  `21bea318819a56f641b3aa2f25027216b97a1c4d` and `evidence_commit: UNKNOWN`;
  only its ETP-T4 projection was re-seeded. The projection now names candidate
  `246e30580f909c047eeb04a93a06f9bd05dc65f3`, and the ETP-T4 files remain
  declared class-8 orphans bound to `07b776d68`, where they do not exist.
* The scanner and seeder changes are evidence-deriving tool changes. They must
  travel in the same evidence commit as the regenerated records; the inventory
  carries the scanner digest, so the tool identity is bound to the rows.
* The two new `CALLER_OBLIGATION_UNESTABLISHED` rows are test-only helpers. They
  are recorded, not repaired; no `src/` change is in scope for this repair.
* Unrelated untracked paths were present at the end and are untouched:
  `forensics/tools/preservation.py` (present at the start) and
  `evidence/etp-t13/` (appeared during the session; not created by any command
  in this repair). Neither is part of this change.
