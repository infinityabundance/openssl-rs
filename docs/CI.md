# CI and the regression gate

`.github/workflows/ci.yml` runs on **every push to every branch** and on every
pull request. The rule it enforces is cumulative:

> **A commit may not undo an earlier commit's evidence.**

A green "build + unit tests" check does not enforce that. If a commit deletes an
implementation, weakens a probe, or reopens an obligation, nothing *fails* — there
is simply less evidence than before. So the gate is not a test suite; it is a
comparison against a committed baseline.

## The FAST tier (every push)

`ci.yml` runs on every push to every branch and on every pull request. The FAST
items from `AGENTS.md` section 6 are mapped to jobs as follows. There is no
single job because the Rust and Python gates need different toolchains, and no
step is optional: a missing prerequisite fails the job.

| tier item | job | exact command |
|---|---|---|
| formatting | `lint` | `cargo fmt --all -- --check` |
| lints / `SAFETY:` contracts | `lint` | `cargo clippy --all-targets -- -D warnings` (the crate denies `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks` and `missing_safety_doc`) |
| library tests, tier thread count | `static` | `cargo test --lib -- --test-threads=4`, after the authoritative serial run |
| claim algebra | `assurance` | `python3 forensics/tools/etp_claims.py validate`; the conjunction is recorded, not release-gating |
| interop receipts | `assurance` | `python3 courts/phase18/interop/check_receipts.py` |
| documentation consistency | `assurance` | `python3 forensics/tools/docs_consistency.py` and `--self-test` |
| benchmark reconstruction | `assurance` | `python3 forensics/tools/tests/test_analyse_bench_api.py` |
| claim-algebra controls | `assurance` | `python3 forensics/tools/tests/test_etp_claims.py` |
| release-gate self-test | `assurance` | `python3 forensics/tools/release_gate.py --self-test` |
| structural (lint attributes only) | `assurance` | the inline `Cargo.toml` / `src/lib.rs` assertion |

The conjunction is printed on every push and is expected to read
`CONTRADICTED` while the ETP-T15 contradictions are open. That is a recorded
fact, not a green signal, and the `assurance` job does not fail on it: the
**release gate** refuses it, which is where a positive verdict would be
misleading.

### What the FAST tier does not run, and why

- **The instrument register (`instrument_qualify.py validate`/`check`).** The
  register is venue-bound: every version probe and executable control must run
  in the qualified toolkit (`openssl-rs-court-tools:1`). On a bare runner both
  commands fail closed with `IQ_VERSION_COMMAND` (for example `binsec: command
  not found`), so a workflow claiming to run them there would be false. The
  check runs in the release gate, which is executed in the court. Closing the CI
  half needs the tools image provisioned for CI — infrastructure work, named as
  a gap rather than approximated.
- **The full section 6 structural guards.** `cargo clippy` is the authority for
  a `SAFETY:` contract on every unsafe op, and the inline assertion keeps the
  enabling lint attributes from being weakened. There is no FAST-frequency
  standalone tool for the allocator seam, `#[repr(C)]` layouts or exported
  symbols: the authoritative checks are the seal-tier `ownership_audit.py`,
  `prototype_court.py` and the Phase-2 ABI courts, which need the authority and
  a built artefact. Their absence from FAST is recorded here, not implied to be
  covered.
- **The release gate itself.** It refuses the current tree by design (see
  `docs/RELEASE_GATES.md`), so running it as a push gate would make every push
  red without adding information. It is a release step and its output is
  retained.

## The regression guard

`forensics/tools/regression_guard.py` reads the derived evidence and the committed
baseline (`forensics/regression-baseline.json`) and fails on any movement in the
wrong direction:

| signal | direction | why it is a regression |
|---|---|---|
| implemented symbols per library | non-decreasing | dropping one is a lost implementation |
| open obligations per ledger | non-increasing | a newly unbuilt symbol is lost ground |
| court verdict | `pass` must stay `pass` | a passing court is the strongest claim held |
| observations per court | non-decreasing | a weakened probe silently loses coverage |
| phase state | non-decreasing | `complete` may not become `in-progress` |

A **deferred** count is recorded and reported but is not directional: a symbol may
legitimately move from *open* to *deferred* when the stratum owning its dependency
is identified. The guard prints such movement so it is visible rather than silent.

The observation-count rule is the one that is easy to miss and worth the most: a
probe that is narrowed to avoid a difficult case still passes, and without this
rule the loss would be invisible.

`--update` rewrites the baseline. That is a deliberate, reviewable act: the diff of
`forensics/regression-baseline.json` is the statement "the evidence moved, and here
is where", and it is reviewed like any other change.

Every figure in this section is in `forensics/regression-baseline.json`, which is
**authoritative and generated**, and this document types none of them. It used to: the
sentence below carried an implemented-symbol count, an open-obligation count, a court count
and an observation count. A hand-written number that a generator can move cannot keep up —
and this one is worse than the seals' case (D205), because the regression guard **rewrites the
baseline at the end of every run**, so a typed snapshot is stale by construction rather than
merely late. Read the file.

## The jobs

### `lint` — a required gate

`cargo fmt --all -- --check` and `cargo clippy --all-targets -- -D warnings`.
Clippy carried `continue-on-error: true`
while the Phase 4 BIO and CONF modules did not satisfy it (201 diagnostics, all of the
form "`unsafe` function's docs are missing a `# Safety` section" or "`unsafe` block
missing a safety comment"). The debt was paid, the line was removed, and it is now a
hard gate. Suppressing the lint with an `allow` was rejected along the way and stays
rejected: the `docs/UNSAFE.md` policy is real, and an `allow` with no written reason is
exactly what this project treats as a defect.

### `assurance` — the Python FAST gates

Runs the claim algebra, the interop receipt checker, documentation consistency,
the benchmark-reconstruction analyser's controls, the claim algebra's controls,
the release gate's self-test, and the lint-attribute structural assertion. All
read committed evidence; none builds the authority. See the table above for the
exact commands and the list of checks this job deliberately does not run.

### `static` — no authority required

Formatting, build, unit tests, the forbidden-dependency gate, a check that the
crate still declares no dependencies, **evidence determinism**, **evidence
portability**, and the regression guard over the committed court results.

**Regenerate the derived evidence before pushing, not just before merging.** Evidence
determinism regenerates every derived artefact and requires the committed bytes back, so
a commit whose code moved the implemented surface while its `implemented-surface.json`
still recorded the previous count fails this gate — correctly, and on the first push.
That happened on the Phase 5.3 staging branch: the `phase5-asn1` commit `b1149f7` failed
only this step, while the court job beside it passed.

The generators are cheap and need no authority, so the rule for a staging commit is the
same as for a merge: run `forensics/tools/implemented_surface.py`, the
`phase*_obligations.py` ledgers, `ownership_audit.py`, `prototype_court.py`,
`phase_state.py`, `render_seal_census.py` and `render_status.py` (or just
`evidence_determinism.py`, which runs them in dependency order), then commit what they
wrote. The phase generators are **discovered** from
`forensics/tools/phase<N>_obligations.py`, so a new stratum does not have to be
remembered here. What a staging commit may legitimately leave stale
is the *court* evidence, because running the courts is the expensive part and an
uncourted transcript is honestly labelled by the ledger — not the derived counts, which
the gate can settle in seconds.

**The single pre-commit command is `forensics/tools/regen_all.sh`**, run inside the
court container (it needs the admitted authority and a built crate, exactly as the
`courts` job has before its own re-derivation step):

```bash
bash docker/openssl-rs-court.sh exec bash forensics/tools/regen_all.sh
```

It regenerates the authority-derived prerequisite atlases first — the four files the
`courts` job's "Re-derive the prerequisite atlases" step compares with `git diff
--exit-code`, which is the step that fails when a source change moves
`transcription-edges.json` — and then every other derived artefact in dependency order
through `evidence_determinism.py --keep`, which is also this job's determinism gate.
Running it before committing is what makes that freshness check pass.

`render_docs.py` is **not** in `regen_all.sh` and was previously in neither that script nor
the CI job, so the `README.md` / `STATUS-2026-10-20.md` generated blocks could drift while
every byte-compared artefact was clean. Follow the regeneration with:

```bash
python3 forensics/tools/render_docs.py --write
python3 forensics/tools/render_docs.py --check
```

Evidence determinism is the load-bearing step: every generated artefact is
regenerated by `forensics/tools/evidence_determinism.py` and compared against the
committed copy — `symbol-ownership.json`, `implemented-surface.json`,
`ownership-audit.json`, `prototype-court.json`, every `phase<N>-obligations.json`,
`phase-state.json`, `phase-state.md`, `docs/SEAL-CENSUS.md` and `STATUS.md`. If a
committed artefact is stale relative to its generator, every claim built on it is
unverifiable, so staleness is a hard failure rather than a warning. The list is
authoritative in the tool's `COMPARED` table, not here; this paragraph said "the two
obligation ledgers" until D79, and then named three until D97. Seals cite
`docs/SEAL-CENSUS.md` rather than restating its arithmetic, because a seal's prose does
not regenerate and a census typed into prose goes stale in the document that is
supposed to be the record.

The comparison is *not* a plain `git diff`, and the reason matters. Two fields
record the **build product** rather than a committed input:

| field | why it is a build product |
|---|---|
| `inputs[name=crate-archive\|extra-object].sha256` | a Rust static archive is not byte-reproducible across build environments |
| `internal_symbols.compiler_emitted_count` | most of the archive's symbols are LLVM-internalised anonymous data (`anon.<hash>.<n>.llvm.<hash>`) whose names change per build |

Those two are normalised, and the tool **prints exactly which of them it
normalised** so the exception is visible rather than silent. Everything else —
every count, every symbol name, every phase state, every obligation — is compared
exactly. The `internal_symbols.c_style` subset (the 508 plain C identifiers a
consumer's own symbols could collide with, recorded as `internal_symbols.c_style`
in `forensics/atlas/implemented-surface.json`) *is* compared exactly; only the
compiler-emitted population is not, which is why it is recorded as a count and not
as names.

Symbol tables are read by `forensics/tools/elf_symbols.py`, not by `nm`. A host's
`nm` reads Rust's LLVM bitcode through a plugin whose availability varies, so the
same archive yielded 39 C-identifier internals in the court and 260 on the CI
runner. The native `.symtab` is the thing the shell must reason about and it is a
function of the archive alone. See `docs/DECISIONS.md` D30 and D33.

### Evidence portability

Determinism cannot catch a generator that depends on the host's binutils: on any
one machine both sides use whatever `nm` that machine has and agree. So
`check_evidence_portability.py` stubs `nm`, `objdump`, `readelf`, `ar` and `file`
out of `PATH`, re-runs the whole generator chain, and requires every artefact in
that tool's `COMPARED` set to be byte-identical anyway.

The gate then tests itself, along both axes on which it can fail: it runs a seeded
generator that *does* call `nm`, and a seeded generator that *does* edit an
evidence field, and fails unless both are reported. A check that cannot detect the
defect class it claims to cover is not evidence.

Comparison reuses `evidence_determinism.artefact_differences`, so the fields that
tool declares as build products are excluded here too. That is not a weakening:
the question this gate asks is whether the *evidence* changes when the host tools
vanish, and a build-product field is by definition not evidence. It is also what
lets the gate run on a CI runner, whose look of the crate archive legitimately
differs from the court's — the exact difference that made the first version of
this gate fail on the runner.

### `courts` — the authority-backed behavioural gate

Builds the court image, starts the container with its resource caps, verifies it
has no `openssl` CLI, then acquires and builds the pinned authority **inside the
container** (hash-checked against `forensics/authorities/AUTHORITIES.json`), and
re-runs every court from scratch:

1. `build_phase2.sh` — builds the crate, re-derives the implemented surface,
   regenerates the ABI shell, links `libcrypto.so.3`, `libssl.so.3`, both static
   archives, the provider module and the CLI, and runs all **11 ABI courts**
   (symbol type/binding/version, layout, dynamic contract, link, load, constants,
   the four-way header×library matrix, binary substitution, install layout and
   contamination).
2. the active strata's court scripts, in numeric order, **discovered** by
   `run_courts.py` from `forensics/phase-state.json` rather than named here: today
   `phase3_courts.py` through `phase7_courts.py`, the runtime differential courts of
   strata 3-7 (the core runtime; BIO, CONF and the compression API; BN/ASN.1/PEM; the
   library context, provider core and DSO; and the EVP framework). D94 records why
   the list is derived: it was a workflow step list nobody owned, and Phase 5's
   courts were never re-run by any green CI job while their committed `COURTS.json`
   was read as evidence.
3. `regression_guard.py` — run again over the **freshly derived** results.

Step 3 is what makes the gate behavioural rather than a claim about a file: the
committed numbers are not trusted, they are reproduced. If a court passes on a
developer's machine and fails in CI, CI is right and the commit is not.

## What this gate does not prove

- It does not prove parity. A court that passes means the candidate matched the
  authority for the observations that probe makes, and nothing else
  (`docs/PARITY_MODEL.md`).
- It does not run the FRF courts or produce new FRF receipts and claims. Those
  remain separate, explicitly invoked steps.
- It covers one platform (Linux x86-64) and one build profile. A green CI run says
  nothing about any other.
- It does not gate publishing. Publishing is a deliberate, manual act; this gate
  exists so that every pushed commit is at least not a step backwards. The
  release decision is `forensics/tools/release_gate.py`, documented in
  `docs/RELEASE_GATES.md`; CI does not run it, and no tag or `cargo publish`
  path invokes it automatically. That is a named gap: a release can still be
  published without a green gate, and the change that closes it is a
  tag-triggered workflow in the qualified venue plus protection on the tag.

## Container start-up

The `courts` job starts the court container on the runner itself, so the resource
caps have to fit the runner. GitHub's `ubuntu-latest` has 4 CPUs, and docker
rejects a `--cpus` above the machine's count
(`range of CPUs is from 0.01 to 4.00, as there are only 4 CPUs available`), which
made the job fail at `Start court container` rather than in a court. The cap is
therefore clamped to `nproc` when the machine is smaller than the requested 8, and
the clamp is announced. See `docs/DECISIONS.md` D31.

## Unapplied workflow patch (ETP-7)

The `assurance` job described above is tracked as
`forensics/etp7/ci-assurance-job.patch` and is **not** present in
`.github/workflows/ci.yml`: the credential that pushed it is an OAuth app without
the `workflow` scope, and GitHub refuses a workflow update from such a token.
Apply the patch with a credential that has that scope, then run the workflow once
and record the first execution. Until then the Python assurance gates on this page
run only when invoked by hand.
