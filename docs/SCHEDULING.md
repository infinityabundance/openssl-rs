# Scheduling as an executable policy — tiers, required evidence, reuse and exhaustion

*ETP-T11. Normative description of `forensics/tools/scheduling.py`, the rule
table it executes, and the records in `evidence/etp-t11/`.*

`AGENTS.md` describes five verification levels. A level table that is only read
is a preference: an author calls a change "BATCH" because that is what the author
believes, and a requirement that was not run is recorded as context rather than
as a gap. This document describes the tool that derives the level from the
change set, the fixed evidence each level requires, the identity a recorded
result must carry before it can be reused, and the state a resource-exhausted
run occupies.

Three separations are load-bearing and are not collapsed anywhere below:

| question | answer is derived from | answer is never |
|---|---|---|
| which tier does this change require? | the changed paths and their classes | the author's preference |
| which requirements does that tier have? | a fixed, named set per tier | the evidence that happens to exist |
| is a requirement satisfied? | a cached result bound to a complete identity | a prose receipt, a passing exit code, or an empty gap |

---

## 1. Tier decision

### 1.1 The rule table

Every changed path is classified by exactly one rule, in table order. `rules`
prints this table and the controls exercise every row, so the table below and
the executed policy are the same object rather than two descriptions.

| rule | class | minimum tier | why |
|---|---|---|---|
| `SC_RULE_EXPORTED_ABI` | `exported_abi` | `SEAL` | `artifacts/phase2/libcrypto.ld` defines the exported-symbol ABI every consumer links against; a consumer measurement is only meaningful against the exact artefact it was taken from |
| `SC_RULE_GRADUATION_CLAIM` | `graduation_claim` | `SEAL` | a change to `evidence/etp/claims.json` that adds or removes a `SAFE_COMPATIBLE` assertion changes a consumer family's graduation state |
| `SC_RULE_SHARED_MECHANISM` | `shared_mechanism` | `BOUNDARY` | a reusable ownership or unsafe abstraction, or the FFI layer, or the `OPENSSL_sk_*` stack: the contract changed, not only the code |
| `SC_RULE_INSTRUMENT` | `instrument` | `BOUNDARY` | `evidence/etp3/`: the instrument register and the harnesses it names; results produced with an instrument are bound to its identity |
| `SC_RULE_INDEPENDENCE` | `independence` | `BOUNDARY` | `evidence/etp-t6/`: a change can invalidate an independence claim that is not otherwise observable |
| `SC_RULE_VENUE` | `venue` | `BOUNDARY` | the court image, launcher and entrypoint that supplied the environment of every measurement |
| `SC_RULE_BUILD_INPUT` | `build` | `BATCH` | `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml`, `libcrypto.ld`: a build input shapes the binary |
| `SC_RULE_TOOL` | `tool` | `BATCH` | a tool that derives or checks evidence; its own tests and the evidence it produced are invalidated |
| `SC_RULE_SOURCE` | `source` | `BATCH` | crate source changes the artefact |
| `SC_RULE_UNCLASSIFIED` | `other` | `BATCH` | an unclassified path is treated as an input, never as documentation |
| `SC_RULE_EVIDENCE_ONLY` | `evidence` | `FAST` | a receipt or atlas that no candidate build reads; it does not invalidate a candidate |
| `SC_RULE_DOCS` | `docs` | `FAST` | documentation |

The declared shared mechanisms are the audited ownership constructors of
`AGENTS.md` §1 plus `src/runtime/stack.rs` and the `src/ffi/` prefix. A control
asserts that every declared path exists in the repository, so a stale
declaration cannot silently schedule nothing.

### 1.2 The decision procedure

1. Each changed path (status `A`, `M` or `D`) is matched against the table in
   order; the first match is its rule.
2. The change set's tier is the **maximum** over the paths. One `BOUNDARY` path
   makes a change set `BOUNDARY` however many documents accompany it. The
   reported rule and reason are those of the lexicographically first path at the
   maximum tier, so the output is deterministic.
3. The `by_class` groups carry a count and up to 40 paths; `omitted` carries the
   remainder. Counts are never hidden, only path lists are bounded.
4. An empty change set is refused (`SC_EMPTY_CHANGE_SET`). It cannot be
   distinguished from a wrong range, and "no change" is not a tier.

Content-dependent rules:

* A `SAFE_COMPATIBLE` line added or removed by the diff of
  `evidence/etp/claims.json` is a graduation change. A claim-document edit that
  does not touch such a line is an evidence edit and stays at `FAST`.
* An added, deleted or unreadable claim document is conservatively a graduation
  change (`SEAL`), because the assertion cannot be compared.
* A path list supplied without a repository (`--paths`, `--paths-file`) cannot
  compare the claim document, so `evidence/etp/claims.json` is conservatively
  `SEAL` in that mode.

`EXTERNAL` is in the tier vocabulary and its requirements are printed, but no
change class infers it. Handing a candidate to an external reproducer is a
declared act; a diff cannot perform it. A control asserts that no path class
reaches `EXTERNAL`.

---

## 2. Required evidence per tier

Requirements **accumulate**: the checks of every lower tier are required as
well. A `BOUNDARY` change that never ran `fmt` is not a `BOUNDARY` change with a
smaller requirement; it is an incomplete one. `require --tier T` prints the
cumulative set with the tier that introduced each check.

The sets are uniform across change classes on purpose. A Python-tool change is
still scheduled at `BATCH` and still lists `FAST_FMT`; a documentation-only
change is still scheduled at `FAST`. Per-class exemptions would be a mechanism
for a change to exempt itself, which is the failure mode this policy exists to
remove. The cost is over-strictness, and over-strictness is recorded as such in
§7.

| tier | check | requirement |
|---|---|---|
| `FAST` | `FAST_FMT` | `cargo fmt --all -- --check` |
| `FAST` | `FAST_CLIPPY` | a clippy check of the touched targets |
| `FAST` | `FAST_FOCUSED_TESTS` | name-filtered tests for the changed units |
| `FAST` | `FAST_STRUCTURAL_GUARDS` | allocator seam at the authority's size/file/line, `#[repr(C)]` layouts, exported symbols, unsafe lint attributes, and a `SAFETY` contract for every new unsafe operation |
| `BATCH` | `BATCH_SUITE_SERIAL` | the full library suite, serially |
| `BATCH` | `BATCH_SUITE_PARALLEL` | the full library suite with `--test-threads=4` |
| `BATCH` | `BATCH_CLIPPY` | `cargo clippy --all-targets -- -D warnings` |
| `BATCH` | `BATCH_AFFECTED_PROBES` | the affected adversarial probes |
| `BATCH` | `BATCH_AFFECTED_COURTS` | the affected compatibility courts |
| `BATCH` | `BATCH_RECEIPT` | a compact receipt committed with the batch |
| `BOUNDARY` | `BOUNDARY_INDEPENDENT_AUDIT` | an independent caller and dependency-closure audit |
| `BOUNDARY` | `BOUNDARY_MODEL_CONTROLS` | targeted model controls (Miri/Loom/mutation) on the changed boundary |
| `BOUNDARY` | `BOUNDARY_SANITIZER_CONTROLS` | targeted sanitizer controls (ASan/TSan) on the changed boundary |
| `BOUNDARY` | `BOUNDARY_AUTHORITY_DIFFERENTIAL` | an authority differential for every changed semantic |
| `BOUNDARY` | `BOUNDARY_NEGATIVE_CONTROL` | a negative control showing the instrument fires |
| `BOUNDARY` | `BOUNDARY_REVIEWER_INDEPENDENCE` | a reviewer that is not the author |
| `SEAL` | `SEAL_DEPENDENCY_CLOSURE` | the full applicable dependency closure |
| `SEAL` | `SEAL_PROBE_SUITE` | the complete probe suite |
| `SEAL` | `SEAL_FORENSIC_REGENERATION` | full forensic regeneration |
| `SEAL` | `SEAL_HELD_OUT_COMPAT` | held-out and broad compatibility and cryptographic assurance against the exact candidate |
| `SEAL` | `SEAL_INDEPENDENT_REVIEW` | independent review of the claim and its evidence |
| `SEAL` | `SEAL_REPRODUCIBILITY` | a reproducible rebuild from the frozen source candidate |
| `EXTERNAL` | `EXTERNAL_REPRODUCTION` | reproduction by an independent venue from the published bundle |
| `EXTERNAL` | `EXTERNAL_BUNDLE` | the published source, binary and identity bundle |
| `EXTERNAL` | `EXTERNAL_VENUE_IDENTITY` | the external venue's identity and toolchain recorded |

Check identifiers are stable. A recorded result is cached under its check
identifier, so renaming a check invalidates the cache by design.

---

## 3. States, aggregation and exit codes

Each required check resolves to exactly one state:

| state | meaning |
|---|---|
| `SATISFIED` | a `PASS` cache entry exists at the exact complete identity the declaration states |
| `NOT_RUN` | no record exists for this requirement |
| `FAILED` | a declaration records a failure, or the cached result is `FAILED` |
| `REFUSED` | a declaration exists but cannot be admitted: incomplete identity, no cached result, a control entry, a `BLOCKED` claim without a bound, an unreadable cache entry, or an unknown status |
| `BLOCKED` | a run hit a memory, time or disk bound; the bound and the observed value are carried in the row |

A **declared `SATISFIED` is admitted only from a cache entry**. A prose receipt,
a quoted test count and a passing exit code are not results: they name an
identity that a later change can invalidate, and nothing in the record binds
them to the candidate. A declaration with an incomplete identity resolves to
`REFUSED`, not to `NOT_RUN` and never to `SATISFIED`: the record exists, and it
cannot be read.

Aggregation is worst-of:

```
BLOCKED > REFUSED > FAILED > NOT_RUN > SATISFIED
```

`BLOCKED` outranks everything so that a resource-exhausted run is never
summarised as a deferral. `REFUSED` outranks `FAILED` because a record that
cannot be read is not evidence of failure either. Every aggregate carries the
per-check states, the counts of all five states, the `blocked` rows with their
bounds, and the `not_satisfied` list. A `BLOCKED` row therefore appears in every
aggregate that contains it.

Exit codes are part of the contract:

| code | meaning |
|---|---|
| `0` | a proven success: `cache-get` hit with `PASS`, or every required check `SATISFIED` |
| `1` | an aggregate that is `NOT_RUN`, `FAILED` or `REFUSED` |
| `2` | a refusal: malformed input, unresolvable commit, incomplete or unbound identity, inadmissible cache entry |
| `3` | `cache-get` miss |
| `4` | `BLOCKED` |
| `5` | `cache-get` hit with `FAILED` |

Only `0` means satisfied. The commands that print a listing (`tier`, `rules`,
`require` without an evaluated change set) exit `0` because they assert nothing
about a candidate.

---

## 4. Applicability identity and content-addressed caching

A result is reused only at its **full applicability identity**:

```json
{
  "source":     {"commit": "<40 hex>", "tree": "<40 hex>"},
  "tool":       {"paths": [{"path": "...", "sha256": "<64 hex>"}],
                 "digest": "<sha256 of the canonical path list>"},
  "instrument": {"name": "...", "config": {...}},
  "target":     {"profile": "...", "triple": "...", "features": [...]},
  "population": {"items": ["..."], "digest": "<sha256 of the sorted items>"}
}
```

`identity_digest` is the SHA-256 of the canonical JSON of those five fields.
The store is `evidence/etp-t11/CACHE.json`; an entry carries its identity, its
identity digest, the result, the resource observation, the evidence paths and a
provenance of `run` or `control`.

Rules, each with a control:

1. **Reuse on identical identity.** All five fields equal → hit.
2. **Recompute on any changed field.** A changed source commit, tool digest,
   instrument configuration, target/profile or population is a different
   subject and yields a miss. The population is compared as a set of
   identifiers, so a changed set is a miss and a duplicate identifier is
   refused.
3. **An incomplete identity never reuses.** A missing field, an empty profile,
   an empty population, an unknown field, or a declared digest that does not
   match its contents is refused before any lookup. An unknown field is refused
   rather than ignored, because an ignored field would silently not be part of
   the identity.
4. **A cached entry is re-validated on read.** A hand-edited identity, a
   mismatched `identity_digest`, a result without a complete resource
   observation, or a `PASS` whose observed value exceeds a bound is refused
   rather than reused.
5. **A conflicting result is refused.** Overwriting one check's result at one
   identity with a different result is a refusal, not an update. A recomputation
   happens under a new identity.
6. **A control entry is not evidence.** A `provenance: control` entry can be
   read and its behaviour controlled, but a declaration that points at one
   resolves to `REFUSED`.
7. **The identity builder refuses drift.** `identity --tool-path` reads the tool
   bytes from the named commit and refuses when the working tree differs, so an
   identity cannot describe a tool other than the one that runs.

The store is written sorted on `(check, identity_digest)` and contains no
timestamp, so the same inputs produce byte-identical output.

---

## 5. Resource exhaustion

Every recorded result carries a bound and an observed value for three resource
classes:

```json
{"memory_mib": {"bound": 6144, "observed": 41},
 "time_s":    {"bound": 900,  "observed": 12.5},
 "disk_mib":  {"bound": 4096, "observed": 3}}
```

* `PASS` and `FAILED` require all three classes and `observed <= bound` for
  each. A recorded `PASS` after exceeding a bound is refused
  (`SC_RESULT_EXCEEDS_BOUND`).
* `BLOCKED` requires at least one class with `observed > bound`; the exhausted
  classes are stored in the entry. A `BLOCKED` claim without a bound and an
  observed value is refused (`SC_BLOCKED_WITHOUT_BOUND`), never recorded as a
  deferral.
* A `BLOCKED` aggregate exits `4`, carries the bound and the observed value, and
  is visible in the aggregate even when every other required check is
  `SATISFIED`.
* A declaration with status `BLOCKED` and no bound resolves to `REFUSED`, not to
  `NOT_RUN` — the run is not silently deferred.

The bounds used for a court run are derived, not assumed. `available` is read
from `free -g` before the command; the cap is `min(8 GiB, available - 16 GiB)`
with a 2 GiB floor, and a run whose floor is not met does not start. For the
controls in this item `available` was 22 GiB, so the derived cap was 6 GiB, and
the cache controls were generated inside the court at that cap.

---

## 6. The policy applied to real change sets

`evidence/etp-t11/TIERS.json` is generated by `report` over
`evidence/etp-t11/CHANGE-SETS.json`; it is not hand-written. `RUNS.json` declares
the evidence each change set actually records, and the policy admits or refuses
each declaration.

| change set | change | required tier | recorded aggregate |
|---|---|---|---|
| `cs-docs-performance` | `c9a0fdd58`, three documents | `FAST` | `NOT_RUN` — 4 of 4 requirements have no record |
| `cs-tool-freshness` | `87d0868ef`, freshness tool + controls | `BATCH` | `REFUSED` — 2 declarations, 8 requirements with no record |
| `cs-etp-t10` | `6ab177626`, closure/claim tools + controls | `BATCH` | `REFUSED` — 2 declarations, 8 requirements with no record |
| `cs-source-callback` | `0eddfe839`, RSA + the shared stack | `BOUNDARY` | `REFUSED` — 6 declarations, 10 requirements with no record |
| `cs-source-ffi-atomicity` | `5750ac150`, BN blinding + the shared stack | `BOUNDARY` | `REFUSED` — 8 declarations, 8 requirements with no record |
| `cs-abi-shell` | `5cf48dd4c`, including `libcrypto.ld` | `SEAL` | `REFUSED` — 1 declaration, 21 requirements with no record |

Across the six change sets: 78 requirements, 0 `SATISFIED`, 59 `NOT_RUN`,
19 `REFUSED`, 0 `FAILED`, 0 `BLOCKED`.

The result is the finding rather than a defect in the report. Every recorded
claim is prose. The strongest record in the set — `haz-16` — quotes both
full-suite modes verbatim (`2430 passed; 0 failed; 54 ignored` at
`--test-threads=1` and `=4`) and still carries no tool digest, instrument
configuration, target profile or exact test population, and names the change
set's base commit rather than the candidate that carries the change. It cannot
be admitted, and the policy says so instead of reading the exit code as the
result.

Both source change sets touch `src/runtime/stack.rs`, the `OPENSSL_sk_*` stack
that nearly every public collection uses, so neither is a `BATCH` change. The
`haz-15` record states its own `BOUNDARY` gaps: no sanitizer, Miri or Loom run,
no test-only canary, no re-run differential. Those are recorded as `NOT_RUN` in
`RUNS.json` with the receipt section that says so.

The exported-symbol script makes `5cf48dd4c` a `SEAL` change. Its only recorded
evidence is six Phase-2 ABI courts, which is one `BOUNDARY` differential and
none of the `SEAL` obligations.

---

## 7. What this does not establish

* The tool does not run the checks it names. A `SATISFIED` aggregate means that
  a `PASS` result is bound to the exact identity claimed — not that the result
  is correct, that the population was adequate for the check, or that the
  instrument measured what it says.
* An exact population is a bound population, not a sufficient one. A cached
  `PASS` over one test at an exact identity is reused perfectly well; whether
  that one test supports `FAST_FOCUSED_TESTS` for the change is a judgement the
  identity does not encode.
* Refusing a prose receipt says the record is not admissible. It does not say
  the record is false. Several of the refused receipts describe work that was
  performed; the point is that the description is not bindable, so a later
  change cannot tell whether it still applies.
* The identity is not an equivalence relation: two identities that differ only
  by a comment in a tool are different subjects here, by design. The tool does
  not decide that two different identities are equivalent, and holds no model of
  which differences are immaterial.
* `EXTERNAL` is never derived. The tool prints its requirements; it does not
  perform or verify external reproduction, and none is claimed.
* A `SATISFIED` aggregate is not a graduation. `SAFE_COMPATIBLE` still requires
  every mechanism in the dependency closure to be `SAFETY_DISCHARGED` under
  `AGENTS.md` §7; this policy schedules the evidence for that question, it does
  not answer it.
* The requirement sets are cumulative and uniform, which over-states the
  requirement for changes that cannot affect a class (a documentation change
  lists `FAST_FMT`). No exemption mechanism is provided, because an exemption is
  a way for a change to schedule itself.
* `TIERS.json` is a statement about the six change sets named in
  `CHANGE-SETS.json` at the commits named there. It is not a statement about
  `HEAD`, and it inherits the paths-only limitation for anything the classifier
  treats as `other`.
