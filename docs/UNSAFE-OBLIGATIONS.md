# Unsafe obligations (ETP-T4)

Status: **normative for the ETP-T4 classification**.
Candidate: `staging` at `07b776d688fdd1dcc4e315661894c30e623aed9e`.
Inventory: `evidence/etp-t4/SAFETY-SITES.json`.
Axioms: `evidence/etp-t4/AXIOMS.json`.
Vacuity: `evidence/etp-t4/VACUITY.json`.
Scanner and validator: `forensics/tools/unsafe_obligations.py`.
Controls: `forensics/tools/tests/test_unsafe_obligations.py`.
Receipt: `evidence/etp-t4/RECEIPT.md`.

`docs/UNSAFE.md` remains the policy statement: when `unsafe` is permitted, how
the footprint is measured, and what panic containment and the Miri/ASan surfaces
do and do not establish. This document is the classification layer: every
unsafe construct with its obligation class, the impact if the obligation is
unmet, the source-stated contract, the boundary it sits inside, and the control
or argument that bears on it. The two documents are kept separate because
`docs/UNSAFE.md` is a constitution with a stable shape, while the inventory is a
candidate-bound measurement that changes with every source edit. Merging them
would make a generated table look like policy.

The inventory is **heuristic**. It is a comment/string-aware lexical scan, not a
compiler-derived census and not a HIR/MIR walk. `unsafe_footprint.code_only` is
reused for the code view, so the two tools cannot disagree about what text is
code. The compiler's own census (`artifacts/phase25/source-census.json`) counted
68,250 unsafe contexts including macro expansions at `17e45eec1`; the source
tree has changed by 10,124 lines since, and the census was not regenerated for
this item. The lexical scan therefore describes the source as written. Its
population is 62,178 constructs, close to the 62,895 `unsafe` keyword
occurrences `unsafe_footprint` measures, and lower than the compiler census
because macro-expanded contexts are not source text.

## 1. Identity and reproduction

| field | value |
|---|---|
| candidate commit | `07b776d688fdd1dcc4e315661894c30e623aed9e` |
| worktree at scan | `src` unchanged; the ETP-T4 evidence files untracked until the evidence commit |
| source files | 883 |
| source lines | 910,498 |
| source-tree digest | `b38e0f426c967da4e5433217b6e03b3042bf8773a0cea1dee0d778c637651a7d` |
| scanner | `forensics/tools/unsafe_obligations.py` |
| site granularity | one row per lexical `unsafe` block, `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern` block and `#[no_mangle]`/`#[export_name]` export with raw work; operation rows for `transmute`, `from_raw_parts`, `set_len`, `assume_init`, `static mut`, atomic publication and CPU intrinsics |

The source digest is the SHA-256 of the sorted `(path, sha256(file))` pairs
under `src/`. `python3 forensics/tools/unsafe_obligations.py validate` refuses a
file whose recorded digest differs from the tree, or whose scanner digest
differs from the tool. A source edit after the scan is therefore a refusal, not
a silent rebinding.

## 2. Obligation classes

Ten classes are the item's list. The eleventh, `delegated_unsafe_contract`, is
added because an unsafe call whose body does no raw work of its own delegates
the callee's contract to the caller; folding it into `ffi_call` or
`raw_dereference` would misdescribe it. The class is a deterministic function of
the construct kind, its symbol and tokens in its body. It is a classification,
not a compiler fact.

| class | sites | what the obligation is |
|---|---:|---|
| `ownership_adoption` | 2,561 | a raw pointer becomes an owner, or an owner becomes a raw pointer; provenance, extent, alignment, initialisation and the release mechanism must be established |
| `borrowed_view_formation` | 1,899 | a raw range becomes a borrowed slice/reference; lifetime, extent, alignment and alias exclusivity must be established |
| `raw_dereference` | 7,402 | a raw pointer is read or written; non-null, live, aligned, initialised, in-bounds and provenance |
| `ffi_call` | 5,114 | a call crosses the C ABI; the callee's documented contract, the argument pointers and the unwind boundary |
| `callback_reentrancy_edge` | 1,441 | application code runs inside the library; reentrancy, borrowed lifetimes and rollback |
| `cpu_intrinsic` | 18 | an intrinsic or inline-asm operation; target features, operand shape and the emitted instruction |
| `layout_repr_assumption` | 97 | a `repr`, union, transmute or offset assumption; field order, size, alignment and validity |
| `uninitialised_to_initialised` | 293 | `MaybeUninit`/`assume_init`/`set_len`; the transition from allocated storage to a valid value |
| `concurrency_publication` | 633 | atomics, `static mut`, `Send`/`Sync`; ordering, publication and teardown |
| `abi_export` | 6,113 | an exported symbol whose body does raw work; the C contract, the layout and the panic boundary |
| `delegated_unsafe_contract` | 36,607 | an unsafe call that performs no raw work itself; the callee's contract is the caller's obligation |

Impact is recorded as a primary class and a full set. The primary is the first
entry in the class mapping; the set is what the unmet obligation can reach.
`memory_unsafety` is reachable from every class. `secret_disclosure` is
reachable from 10,256 sites, `compatibility_divergence` from 11,324,
`availability` from 2,074 and `cryptographic_wrong_result` from the 18 CPU
intrinsics.

| impact | primary | any |
|---|---:|---:|
| `memory_unsafety` | 62,160 | 62,178 |
| `secret_disclosure` | 0 | 10,256 |
| `cryptographic_wrong_result` | 18 | 18 |
| `availability` | 0 | 2,074 |
| `compatibility_divergence` | 0 | 11,324 |

The impact class names what the obligation can reach; it is not an observation
that a defect exists, and it is not a severity score.

## 3. The contract, and what counts as an argument

The contract is the contiguous `SAFETY:` comment or `# Safety` doc section
immediately above the construct. A block inside an `unsafe fn` inherits the
function's `# Safety` text only when the block states none of its own. The row
records the contract state, the branch the heuristic took, and a digest of the
normalised text; the full text is in the inventory's `contracts` table.

| state | sites | meaning |
|---|---:|---|
| `absent` | 1,029 | no `SAFETY:` text or `# Safety` section was found |
| `restatement` | 57,118 | the text names the operation or asserts a property without a support relation |
| `argument` | 4,031 | the text contains a support relation: a cause, a checked property or a witness/reference |

The restatement branches are: `property_assertion_without_support` 48,126,
`too_short` 8,992, and `no_comment` 1,029. The argument branches are
`support_marker` 3,106 and `reference_marker` 925.

**The heuristic.** A contract is an argument when its normalised text contains a
support marker (`because`, `since`, `checked`, `verified`, `guaranteed`,
`established`, `invariant`, `catalogue`, `within bounds`, `points to`,
`same allocation`, `line N`, `docs/`, `§`, and the rest of the list in
`evidence/etp-t4/SAFETY-SITES.json` `heuristic.restatement.argument_markers`),
or a reference marker (`see`, `witness`, `control`, `test`, `miri`, `asan`).
It is a restatement when it contains neither, or when it is shorter than four
words, or when it matches a bare-operation phrase such as "calls an unsafe
function", "the pointer is valid" or "only used internally".

**Limits.** The heuristic is lexical, not semantic. A true argument written
without a listed marker is classified as a restatement. A restatement that
names a marker word is classified as an argument. The classification says what
the text contains; it does not say that the argument is true, sufficient or
applicable. The control
`test_restatement_inversion_control` demonstrates the sensitivity in both
directions: adding a support clause moves the text to `argument`, and removing
it moves the text back. The number of restatements is therefore an upper bound
on the documentation gap for this heuristic, not a count of false contracts.

A restatement is **not** a discharge. `SAFETY: the pointer is valid` restates
the obligation; it does not say why the pointer is valid at that point.

## 4. Boundaries

The boundary is the narrowest named abstraction the site sits inside, by a
deterministic rule: an owner type (`OwnedBlock`, `OwnedBuf`, `OwnedStr`,
`OwnedRaw`, `OwnedCtx`, `SecretBuf`, `CtxDestroy`, `ManuallyDrop`) when one
encloses the site; an exported symbol; an audited constructor; a known boundary
module; otherwise `UNCONFINED`.

| boundary | sites |
|---|---:|
| `UNCONFINED` | 51,586 |
| `module` | 2,473 |
| `owner_type` | 1,838 |
| `constructor` | 168 |
| `abi_export` | 6,113 |

`UNCONFINED` is not a claim that the site is unsound. It is the inventory's
answer to "which auditable abstraction confines this obligation": none named by
the rule. The 83% figure is consistent with `docs/UNSAFE.md` section 2, which
already records that 90% of the unsafe keyword footprint is in the core
parser/algorithm modules rather than a narrow FFI shim.

## 5. Coverage

Coverage names what bears on the site: a test module, a named instrument, a
source argument, or nothing. An argument is not a control.

| coverage | sites |
|---|---:|
| `none` | 54,000 |
| `argument` only | 3,592 |
| `test` module | 4,513 |
| instrument (`miri-tcb-suite`, `provenance-court`) | 73 |

Only 4,586 sites sit inside a test module or a named instrument. The instrument
mapping is deliberately narrow: `src/runtime/miri_tcb.rs`, functions named
`miri_*`, and the two provenance-sensitive files the provenance court guards.
No ASan, dudect or differential-court result is attributed to a site, because no
tracked record binds those instruments to site identities at this candidate.

## 6. Named raw operations

| operation | rows |
|---|---:|
| `transmute` | 61 |
| `from_raw_parts` | 306 |
| `set_len` | 3 |
| `assume_init` | 60 |
| `static mut` | 45 |
| atomic publication | 237 |
| CPU intrinsic | 22 |
| `MaybeUninit` | 33 |

Each operation row names its enclosing site. An operation outside every unsafe
construct would be its own row; the seven raw-operation kinds that can occur
outside a construct are recorded that way. The operation kind is a
classification on a source span, not a compiler fact.

## 7. Vacuity

Four refusals are implemented. Each has a control that makes it fire.

| refusal | what it refuses | control |
|---|---|---|
| `ET4_DISCHARGE_WITHOUT_CONTROL` | a discharge with no control that could fail | `test_discharge_without_control_is_refused`, `test_control_that_cannot_fail_is_refused` |
| `ET4_VACUOUS_REPORTED_SATISFIED` | an unreachable precondition reported as satisfied | `test_vacuous_precondition_reported_satisfied_is_refused` |
| `ET4_CALLER_OBLIGATION_UNESTABLISHED` | a caller obligation with no witness | `test_caller_obligation_without_witness_is_refused` |
| `ET4_ASSERTION_CANNOT_FAIL` | a tautological assertion | `test_tautological_assertion_is_refused`, `test_inverted_assertion_is_reported_as_a_failure` |

The discharge register contains one record: the `SAFETY_DISCHARGED` verdict
scoped to `OwnedStr` in
`forensics/memory-safety/campaign/safe-c33/OB2-CHECKS.md`. Its own controls are
named (the transition model's three negative controls, nine tests and focused
ASan runs), and `control_could_fail` is true. The register does not adjudicate
their sufficiency. The detector refuses an empty control list or
`control_could_fail: false`; the controls above demonstrate both.

The inventory finds 2,914 caller-obligation findings:

| finding | count |
|---|---:|
| `VACUOUS_PRECONDITION`, no production caller | 261 |
| `VACUOUS_PRECONDITION`, safe function delegates an unsafe precondition | 211 |
| `CALLER_OBLIGATION_UNESTABLISHED`, unsafe fn states no contract | 34 |
| `CITED_BY_CALLER`, a production caller cites a contract (not proof) | 322 |
| `EXTERNAL_CALLER_CONTRACT`, the C ABI caller owns the obligation | 2,069 |
| `IMPLEMENTER_OBLIGATION`, an unsafe impl/trait obligation | 17 |

The 211 safe-function findings are the sharpest vacuity class: a safe function's
`SAFETY` comment cites a caller obligation, and a safe caller has no way to
establish an unsafe precondition. The finding is structural, not a defect
report; the comment may describe an internal invariant that the function
actually maintains. The 261 no-production-caller findings include unsafe
functions used only by tests; they are vacuous in production, not satisfied.

The scanner also searches test modules for tautological assertions and records
ignored tests. It finds **0** tautological assertions and **54** `#[ignore]`
tests. The zero is a lexical result, not a proof that every assertion can fail;
the inverted-assertion control runs the test runner on `assertEqual(2 + 2, 5)`
and requires a non-zero exit, so the harness itself is not vacuous.

## 8. Axioms and admitted results

`evidence/etp-t4/AXIOMS.json` registers 37 premises: 8 `CHECKED`, 24 `PARTIAL`
and 5 `UNCHECKED`. Each states what it is used for, what would falsify it, and
what checks it. The five with no check are:

| axiom | why nothing checks it |
|---|---|
| `AX-ALLOC-METADATA` | allocator metadata and `mem::forget`/abort are outside the owner's extent and outside every instrument in the tree |
| `AX-CPU-VARIABLE-LATENCY` | no per-instruction latency model exists for the target CPU |
| `AX-LIBC-ABI` | libc signatures and errno are assumed, not probed |
| `AX-OS-SYSCALL` | kernel behaviour for randomness, threads, memory and time is assumed |
| `AX-SUPPRESSION-SCOPE` | the register records suppressions; it does not establish what each suppression hides |

The code-generation axioms are `CHECKED` only for the exact bindings in
`docs/CODE-GENERATION-ASSURANCE.md`: rustc 1.98.1, its LLVM,
`x86_64-unknown-linux-gnu`, release `opt-level = 3`, `codegen-units = 16`,
`lto = false`, `overflow-checks = true`, `panic = unwind`. A change to any of
them invalidates the claim; `AX-CPU-VARIABLE-LATENCY` then means that even the
checked branch audit is not a constant-time proof.

The suppression register records 1,983 `allow`/`expect` attributes. The largest
groups are `dead_code` (703), `non_snake_case` (460),
`clippy::too_many_arguments` (240), `non_upper_case_globals` (174) and
`clippy::panic` (77). Five sites allow `clippy::undocumented_unsafe_blocks`:
`src/provider/cipher_gcm.rs:2496`, `src/runtime/obj.rs:2627`,
`src/runtime/secure.rs:899`, `src/runtime/thread.rs:1112` and
`src/store/store_lib.rs:2509`. Five allow `clippy::not_unsafe_ptr_arg_deref`:
`src/asn1/fre.rs:446` and four sites in `src/asn1/i2d.rs`. Those ten are
safety-adjacent suppressions and are the first candidates for review; recording
them is not a finding that they are wrong. The register also records 548
`#[cfg(test)]` modules, so test-only code is identifiable and is not counted as
a production control.

## 9. Projection into the T1 graph

`forensics/tools/etp_t1_seed.py` adds 15 nodes and 45 edges:

- `IMP-UNSAFE-SURFACE` (implementation, `src/lib.rs` at `07b776d68`);
- `ART-UNSAFE-SITES` (artefact, the inventory digest);
- `EV-ETP-T4-SITES` and `EV-ETP-T4-AXIOMS` (evidence);
- eleven `OBL-T4-<CLASS>` obligation nodes, one per obligation class.

Each obligation node carries `unsafe_site_inventory`: the class, its site count,
the contract-state counts, the controlled count and
`sites_without_contract_or_control`. It is raised by `IMP-UNSAFE-SURFACE`,
evidenced by `EV-ETP-T4-SITES`, and constrains `REL-OPENSSH-B85C` and
`REL-L7-ATLAS-33-33`.

`forensics/tools/traceability.py` gains orphan class 12,
`unsafe_site_without_contract_or_control`. Every class still has sites with
neither a validity argument nor a control, so all eleven classes are class-12
orphans. Three class-8 orphans declare that `evidence/etp-t4/SAFETY-SITES.json`
and `evidence/etp-t4/AXIOMS.json` do not exist at `T4`; they settle when a
later commit binds the evidence to itself. A class with no
uncovered site would not be an orphan; the class-12 rule refuses a forged zero
because the graph's own register is reconciled against what the checker
discovers.

| graph | before ETP-T4 | after ETP-T4 |
|---|---:|---:|
| nodes | 342 | 357 |
| edges | 423 | 468 |
| declared orphans | 24 | 38 |
| orphan classes | 1, 3, 6, 8, 11 | 1, 3, 6, 8, 11, 12 |

The T1 controls still pass (`forensics/tools/tests/test_traceability.py`,
26 tests). Two controls are new: a removed class-12 declaration is refused, and a
forged zero `sites_without_contract_or_control` is refused because the
declaration no longer reproduces.

## 10. The most consequential findings

**The most consequential site** is `src/bn/recp.rs:252`, `unsafe fn free_recp`.
It is classified `ownership_adoption`, its impact set is
`memory_unsafety | secret_disclosure`, its contract state is `absent`, its
coverage is `none`, and its boundary is `UNCONFINED`. The block inside it at
line 256 says "the caller's contract", so the obligation is delegated to a
caller; the function itself states no `# Safety`. A missed precondition frees a
`RecpCtx` that the caller still owns, or drops one twice, on a secret-bearing
BN path. The second candidate is the same shape in
`src/ssl/adv_alloc.rs:287` (`hook_free`). Neither is a confirmed defect; both
are sites where the inventory finds no contract and no control.

**The most consequential axiom** is `AX-CPU-VARIABLE-LATENCY`. Nothing checks
it, and it is the reason a branch-free instruction stream is not a
constant-time result: division and memory accesses can depend on operands
without any branch, and the CPU's own latency is outside every instrument in the
tree. The safety-side companion is `AX-ALLOC-METADATA`: allocator metadata is
outside every owner's extent, and `mem::forget`/abort bypass `Drop`, so no
owner's cleanup guarantee is universal.

## 11. Non-claims

- A row records a lexical classification, not a proof. An unsafe site is not by
  itself a defect, and a `SAFETY` comment is not an established precondition.
- The scanner is heuristic. Its limits are stated in section 3 and in the
  inventory's `heuristic.restatement.limits`; its operation class is not a
  compiler fact.
- The inventory does not modify `src/`, does not fix any site, and does not
  establish memory safety, constant-time behaviour or cryptographic correctness.
- A class with no uncovered site would not be a discharge. The obligation nodes
  are `OPEN`; `SAFE_COMPATIBLE` remains 0/33 and no mechanism is
  `SAFETY_DISCHARGED` by this item.
- Impact names what an unmet obligation can reach; it is not a severity score or
  an observed defect.
- The suppression register records attributes; it does not adjudicate them.
- The class-8 orphans are pending evidence identities, not missing evidence: the
  files are present in the working tree and are bound to the candidate at the
  commit that adds them.

## 12. Reproduction

All Python runs use the court:

```
cd /home/user/openssl-rs
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec sh -c '
    cd /work
    python3 forensics/tools/unsafe_obligations.py all
    python3 -m json.tool evidence/etp-t4/SAFETY-SITES.json >/dev/null
    python3 -m json.tool evidence/etp-t4/AXIOMS.json >/dev/null
    python3 forensics/tools/unsafe_obligations.py validate
    python3 forensics/tools/etp_t1_seed.py
    python3 forensics/tools/traceability.py validate
    python3 forensics/tools/tests/test_unsafe_obligations.py
    python3 forensics/tools/tests/test_traceability.py
  '
```

`unsafe_obligations.py show <site-id>` prints one decoded row. The inventory is
stored in an indexed columnar form (`encoding: indexed-v1`); `decode_sites` in
the tool and the `show` mode are the readers, and the tables are part of the
same JSON document so no external index is needed.
