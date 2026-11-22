# ETP-T4 receipt — unsafe-site obligations, axioms and vacuity refusal

**Item:** ETP-T4 of `docs/ETP-TODO.md`.
**Candidate:** `staging` at `07b776d688fdd1dcc4e315661894c30e623aed9e`.
**Worktree at the start:** clean; the files below were untracked until the
evidence commit.

This item classifies and refuses. It does **not** fix any site in `src/`, and it
does not claim that any site is sound.

## 1. Identity

| field | value |
|---|---|
| HEAD | `07b776d688fdd1dcc4e315661894c30e623aed9e` |
| branch | `staging` |
| worktree | clean at the start; no source or `docker/` change |
| source files / lines | 883 / 910,498 |
| source-tree SHA-256 | `b38e0f426c967da4e5433217b6e03b3042bf8773a0cea1dee0d778c637651a7d` |
| scanner SHA-256 | recorded in `SAFETY-SITES.json` `identity.scanner_sha256` |
| court | `openssl-rs-court-tools:1`, cgroup cap 6 GiB, Python 3.11.2 |

The tree digest is the SHA-256 of the sorted `(path, sha256(file))` pairs under
`src/`. The validator re-derives it and refuses a mismatch.

## 2. The inventory

`evidence/etp-t4/SAFETY-SITES.json` (schema
`openssl-rs/etp/unsafe-sites/1`, encoding `indexed-v1`) holds 62,178 unsafe
constructs (`unsafe` blocks 47,992; `unsafe fn` 7,713; `unsafe impl` 341;
`unsafe trait` 10; `unsafe extern` 9; exports with raw work 6,113), 767 named
raw-operation rows, 29,158 distinct contract texts, 1,983 suppression
occurrences and 548 `#[cfg(test)]` modules.

The population is lexical, not compiler-derived. The compiler census at
`17e45eec1` counted 68,250 unsafe contexts including macro expansions; the
source has changed by 10,124 insertions and 858 deletions since, and the census
was not regenerated. The inventory describes the source as written; the
difference is stated in `docs/UNSAFE-OBLIGATIONS.md` and is not presented as a
completeness result.

### 2.1 Obligation classes

| class | sites |
|---|---:|
| `ownership_adoption` | 2,561 |
| `borrowed_view_formation` | 1,899 |
| `raw_dereference` | 7,402 |
| `ffi_call` | 5,114 |
| `callback_reentrancy_edge` | 1,441 |
| `cpu_intrinsic` | 18 |
| `layout_repr_assumption` | 97 |
| `uninitialised_to_initialised` | 293 |
| `concurrency_publication` | 633 |
| `abi_export` | 6,113 |
| `delegated_unsafe_contract` | 36,607 |

`delegated_unsafe_contract` is the added eleventh class: an unsafe call whose
body does no raw work itself. Folding it into `ffi_call` or `raw_dereference`
would misdescribe the obligation.

### 2.2 Impact

Primary impact: `memory_unsafety` 62,160 and `cryptographic_wrong_result` 18
(the CPU intrinsics). Reachable impact set: `memory_unsafety` 62,178,
`secret_disclosure` 10,256, `compatibility_divergence` 11,324,
`availability` 2,074, `cryptographic_wrong_result` 18. Impact names what an
unmet obligation can reach; it is not a severity score or an observed defect.

### 2.3 Contract

| state | sites |
|---|---:|
| `absent` | 1,029 |
| `restatement` | 57,118 |
| `argument` | 4,031 |

Restatement branches: `property_assertion_without_support` 48,126,
`too_short` 8,992, `no_comment` 1,029. Argument branches:
`support_marker` 3,106, `reference_marker` 925.

The heuristic is lexical: a support marker (cause, checked property,
witness/reference) makes an argument; a bare operation phrase, a property
assertion with no support, or fewer than four words makes a restatement. Its
limits are stated in the inventory and in `docs/UNSAFE-OBLIGATIONS.md` section
3. `test_restatement_inversion_control` demonstrates both directions. A
restatement is not a discharge.

### 2.4 Boundary and coverage

Boundary: `UNCONFINED` 51,586; `module` 2,473; `owner_type` 1,838;
`constructor` 168; `abi_export` 6,113. `UNCONFINED` means no named owner,
export, constructor or boundary module confines the obligation; it is not a
claim that the site is unsound.

Coverage: `none` 54,000; `argument` only 3,592; `test` 4,513; named instrument
73. Only 4,586 sites sit in a test module or a named instrument. No ASan,
dudect or differential-court result is attributed to a site, because no tracked
record binds those instruments to site identities at this candidate.

## 3. Axioms and admitted results

`evidence/etp-t4/AXIOMS.json` registers 37 premises: 8 `CHECKED`, 24 `PARTIAL`,
5 `UNCHECKED` (`AX-ALLOC-METADATA`, `AX-CPU-VARIABLE-LATENCY`, `AX-LIBC-ABI`,
`AX-OS-SYSCALL`, `AX-SUPPRESSION-SCOPE`). Each entry states what it is used for,
what would falsify it and what checks it; a `CHECKED` axiom is not universally
true.

The code-generation axioms are bound to rustc 1.98.1, its LLVM,
`x86_64-unknown-linux-gnu`, release `opt-level = 3`, `codegen-units = 16`,
`lto = false`, `overflow-checks = true`, `panic = unwind`.

Suppressions: 1,983 `allow`/`expect` attributes. The safety-adjacent ones are
five `clippy::undocumented_unsafe_blocks` (`src/provider/cipher_gcm.rs:2496`,
`src/runtime/obj.rs:2627`, `src/runtime/secure.rs:899`,
`src/runtime/thread.rs:1112`, `src/store/store_lib.rs:2509`) and five
`clippy::not_unsafe_ptr_arg_deref` (`src/asn1/fre.rs:446` and four sites in
`src/asn1/i2d.rs`). They are recorded, not adjudicated.

## 4. Vacuity refusals and their controls

| refusal | observation |
|---|---|
| `ET4_DISCHARGE_WITHOUT_CONTROL` | the one registered discharge (`OwnedStr`, OB-2) names controls and `control_could_fail: true`; the controls make the detector fire on an empty list and on `false` |
| `ET4_VACUOUS_REPORTED_SATISFIED` | 472 vacuous preconditions are reported as vacuous; 0 is reported satisfied; the control forges the flag and the validator refuses it |
| `ET4_CALLER_OBLIGATION_UNESTABLISHED` | 34 unsafe functions cite a caller obligation and state no contract; the control forges a "SATISFIED" finding with no witness and the validator refuses it |
| `ET4_ASSERTION_CANNOT_FAIL` | 0 tautological assertions found; the control inserts one and the validator refuses it; the inverted-assertion control runs `assertEqual(2 + 2, 5)` and requires a non-zero exit |

Caller-obligation findings: 2,914. Of those, 261 are `VACUOUS_PRECONDITION`
with no production caller, 211 are a safe function delegating an unsafe
precondition to its callers, 34 are an unsafe function with no contract, 322 are
a production caller that cites a contract (not proof), 2,069 are external C ABI
contracts and 17 are implementer obligations.

The 211 safe-function findings are the sharpest class: a safe caller cannot
establish an unsafe precondition, so the stated precondition is not reachable
through the safe API. The finding is structural; a comment may describe an
internal invariant the function actually maintains. The 261 no-caller findings
include test-only unsafe functions; they are vacuous in production, not
satisfied. There are 0 tautological assertions and 54 `#[ignore]` tests.

## 5. T1 projection

`forensics/tools/etp_t1_seed.py` adds 15 nodes and 45 edges:
`IMP-UNSAFE-SURFACE`, `ART-UNSAFE-SITES`, `EV-ETP-T4-SITES`,
`EV-ETP-T4-AXIOMS`, and eleven `OBL-T4-<CLASS>` obligations. Each obligation
carries its class-level `unsafe_site_inventory`.

`forensics/tools/traceability.py` gains orphan class 12,
`unsafe_site_without_contract_or_control`. Every class still has sites with
neither a validity argument nor a control, so all eleven classes are class-12
orphans. Three class-8 orphans declare that the inventory and axiom files do not
exist at the candidate commit; they settle when a later commit binds the
evidence to itself.

| graph | before | after |
|---|---:|---:|
| nodes | 342 | 357 |
| edges | 423 | 468 |
| declared orphans | 24 | 38 |
| orphan classes | 1, 3, 6, 8, 11 | 1, 3, 6, 8, 11, 12 |

The graph is bound to `S = 21bea3188` for its existing nodes; the eleven
obligation nodes are also bound to `S`, and the four ETP-T4
implementation/artefact/evidence nodes are bound to `T4 = 07b776d68`. No edge
is drawn across an identity that would claim the inventory is fresh at `S`.

## 6. Most consequential findings

**Site.** `src/bn/recp.rs:252`, `unsafe fn free_recp`: class
`ownership_adoption`, impact `memory_unsafety | secret_disclosure`, contract
`absent`, coverage `none`, boundary `UNCONFINED`. The block inside it at line
256 delegates "the caller's contract" to a caller, and the function states no
`# Safety`. A missed precondition frees a caller-owned `RecpCtx`, or drops it
twice, on a secret-bearing BN path. `src/ssl/adv_alloc.rs:287` (`hook_free`) has
the same shape. Neither is a confirmed defect; both lack a contract and a
control.

**Axiom.** `AX-CPU-VARIABLE-LATENCY` has no check and is why a branch-free
instruction stream is not a constant-time result: operand-dependent latency and
memory access remain even with no branch. The safety-side companion is
`AX-ALLOC-METADATA`: allocator metadata is outside every owner's extent and
`mem::forget`/abort bypass `Drop`, so no owner's cleanup guarantee is universal.

## 7. Gates run

Court, Python 3.11.2, one command at a time, `available` 27 GiB at the start:

| command | result |
|---|---|
| `python3 forensics/tools/unsafe_obligations.py all` | 62,178 sites, 767 operations |
| `python3 -m json.tool evidence/etp-t4/SAFETY-SITES.json` | exit 0 |
| `python3 -m json.tool evidence/etp-t4/AXIOMS.json` | exit 0 |
| `python3 forensics/tools/unsafe_obligations.py validate` | 0 problems |
| `python3 forensics/tools/etp_t1_seed.py` | 357 nodes, 468 edges, 38 orphans |
| `python3 forensics/tools/traceability.py validate` | 0 undeclared, 0 stale |
| `python3 forensics/tools/tests/test_unsafe_obligations.py` | 18 tests, 0 failures |
| `python3 forensics/tools/tests/test_traceability.py` | 26 tests, 0 failures |

Not run: `cargo fmt`, `cargo clippy`, `cargo test --lib`. This item changes no
Rust source; those gates are `NOT_RUN` and are not claimed.

## 8. Files

| path | change |
|---|---|
| `docs/UNSAFE-OBLIGATIONS.md` | new normative classification |
| `docs/UNSAFE.md` | link to the classification; policy unchanged |
| `docs/REQUIREMENTS-TRACEABILITY.md` | class 12 and the ETP-T4 projection |
| `evidence/etp-t4/SAFETY-SITES.json` | new inventory |
| `evidence/etp-t4/AXIOMS.json` | new axiom register |
| `evidence/etp-t4/VACUITY.json` | new vacuity register |
| `forensics/tools/unsafe_obligations.py` | new scanner/validator |
| `forensics/tools/tests/test_unsafe_obligations.py` | new 18-test control suite |
| `forensics/tools/traceability.py` | orphan class 12 |
| `forensics/tools/etp_t1_seed.py` | T4 nodes, edges and orphans |
| `forensics/tools/tests/test_traceability.py` | class-12 controls and updated counts |
| `evidence/etp-t1/TRACEABILITY.json` | regenerated at 357 / 468 / 38 |
| `docs/ETP-TODO.md` | ETP-T4 row |

No change to `src/` or `docker/`.

## 9. Non-claims

- A row is a lexical classification, not a proof; an unsafe site is not by
  itself a defect.
- A `SAFETY` comment is the author's statement, not an established
  precondition; a restatement is not a validity argument.
- No site is `SAFETY_DISCHARGED` by this item; no family is `SAFE_COMPATIBLE`.
  The cohort remains 0/33.
- The scanner is heuristic; its operation class is not a compiler fact and its
  restatement judgement is not semantic.
- Impact is a reachability class, not a severity score.
- The suppression register records attributes; it does not adjudicate them.
- The class-8 orphans are pending evidence identities, not missing evidence:
  the files are in the working tree and are bound at the commit that adds them.
- Running `cargo test --lib` without the court is not permitted; no Rust result
  is claimed here.
