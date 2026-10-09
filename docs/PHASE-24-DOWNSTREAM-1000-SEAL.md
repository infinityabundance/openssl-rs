# Phase 24 — the downstream-1000 stratum: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's obligation ledger is empty of open rows —
`forensics/phase24-obligations.json` reads `open_in_this_stratum: 0`, all nineteen contract units
`implemented` — every earlier stratum is `complete`, and this document is the last required evidence
`PHASE24_MODULES` names, so `forensics/phase-state.json` reports phase 24 **`complete`** with an
empty blocking reason. That derived state is the phase-exit predicate (D421, D529): a ledger's own
`complete` is *not* it. `seal_sha256` is derived too: this document is named in
`forensics/tools/atlas_common.py`'s `SEAL_DOCS` table at `24`, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here.

**This seal compiles the downstream-1000 claim over the finished measurement the fourteen
instruments of 24.1 through 24.14 landed, and the claim it licenses is the bounded one §5 states —
nothing stronger.** Its nineteen courts are instruments that read committed evidence; each passes,
and a pass is a statement about the instrument plus the measurement it made, not about a universal
property. The **four non-claims** are named in §6: **a selected population is not a random sample**,
**1000/1000 is not a security proof**, **a build is not a functional proof**, and **direct and
transitive consumers are different evidence** — and they are recorded as findings, so a passing
seal is never "the downstream ecosystem is safe". `docs/NON_CLAIMS.md`, `docs/PARITY_MODEL.md`,
`docs/ABI_POLICY.md`, `docs/AUTHORITY_POLICY.md` and `docs/REPRODUCIBILITY.md` are the authorities
on what may be said. 24.16's **biggest-mover shared-blocker analysis** reads the finished measurement
and is its own bounded instrument: `docs/PHASE-24-BIGGEST-MOVERS.md` names which blocker moves the
most families, and §13.5 records the correction that lands it. 24.17's **biggest-mover remediation**
acts on that analysis: `forensics/downstream/blocker-remediation.json` records the exact repair each
largest mover received, preserves the 24.16 partition as its `before`, re-derives the re-measured
`after` from the committed planes and computes the movement, and §13.6 records the correction that
lands it. 24.18's **recipe-admission campaign** attacks the breadth mover directly:
`forensics/downstream/recipe-campaign.json` records the attempted families, the admitted recipes,
the counts and the measured movement, and §13.7 records the correction that lands it.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`), named as the
  authority by `artifacts/phase24/COURTS.json`. Build profile
  `linux-x86_64-default-shared-legacy-notests`, platform `linux-x86_64`. The frozen candidate is the
  content-addressed **install** `de196adb…` (`forensics/downstream/candidate-freeze.json`), never
  live HEAD (the plan's §4.10 correction).
- Court results: `artifacts/phase24/COURTS.json` — nineteen courts, `all_pass` true, `summary`
  `pass` 19 of 19, `pending_courts` empty. **No court is FRF-declarable**: each carries
  `frf_declarable` `false` with its exclusion reason, because each reads committed evidence and
  stages no `artifacts/phase24/probes/<probe>.{authority,candidate}` pair (D13, D201). The per-court
  table is §2.
- Obligation ledger: `forensics/phase24-obligations.json` — `owned` 18, `implemented` 18,
  `deferred_to_later_phase` 0, `open_in_this_stratum` 0; its unit is `downstream 1000 contract`, a
  non-export unit, and its `atlas_owned` count is 0. `provider_rows_owned` 0, `deferrals_received` 0
  and `unit_deferrals_received` 0: it receives and hands forward nothing.
- Court coverage: `forensics/atlas/court-coverage.json` records **no phase-24 row**, and that is
  the join's own definition rather than an omission: `court_coverage.py` skips a ledger whose unit
  is in `atlas_common.NON_EXPORT_UNITS` (D485), so a stratum with no export universe has no row and
  no unmatched export.
- Derived state: `forensics/phase-state.json`, phase 24, `complete` with empty blocking. It owns
  **no exported symbol**, so its `atlas_owned` count is 0 and it registers no provider row.
- Deciding records: `docs/DECISIONS.md` — **D548** is the activation and **D549** through **D553**
  are its five load-bearing choices (the frozen population, the Docker-only guard, the family as the
  counted unit, the baseline-normalized `DROP_IN_PASS`, and the separate hostility/holdout); **D485**
  is the non-export-unit marker Phases 16 through 24 share; **D13**/**D201** are the FRF-declarable
  rule; **D97** is the cite-the-court-records rule; **D421**/**D529** are the phase-exit predicate.
  `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` is the plan this seal closes, and §12 records the
  corrections this seal makes. For every count in this document, read `docs/SEAL-CENSUS.md`,
  generated by `forensics/tools/render_seal_census.py`; this seal cites the court records rather
  than restating their arithmetic (D97).

## 1. What this stratum is, and what it is not

Phase 24 is the stratum `docs/RELEASE_GATES.md` §1 names "Downstream-1000 replacement atlas and
empirical drop-in corpus". Like Phases 16 through 23 it owns **no exported symbol**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 24` yields nothing, and
`forensics/atlas/provider-algorithms.json` assigns it no registration row. Its unit is the
**downstream 1000 contract** — nineteen contract units, each measured by the court that lands with
it — and it hands nothing forward and receives nothing: it adds no library surface, takes no unit or
symbol deferral from an earlier stratum, and activates no provider.

What it owes is the **atlas itself**: a content-addressed, reproducible, machine-queryable
measurement of whether `openssl-rs` survives how a **precommitted, multi-source-selected population
of 1,000 real OpenSSL downstream project families** depends on OpenSSL. Its vocabulary is fixed in
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` §0: a **family** (the counted unit, never a package
alias), a **specimen** (one pristine source tree, separate from its family), a **variant** (one
build configuration and patch set), a **ranking source** (a frozen multi-source evidence row that
ranked candidates **before** any candidate result existed), a **run** (one execution at one level
under one subject), the **execution level** ladder L0 through L8 with an
**authority-applicable baseline**, a **residual** classified from the closed vocabulary, and a
**drop-in verdict** that is never a boolean of its own. Every one of the nineteen units is in
`artifacts/phase24/COURTS.json` and passes.

**A passing downstream court is an instrument, not a property.** Each unit records its measurement
beside the property it names, and where the evidence falls short the property is carried by
`property_status` and `findings`, never asserted. **This stratum is never a single boolean**: the
result is a **ladder**, never one percentage (the brief's §52), so a rate cannot hide where the
population actually stands.

**Direct and transitive consumers are never summed.** Every counted family carries an
`openssl_linkage` (`direct` or `transitive`), and the reconciliation computes one rate per class;
the two are never added into a single figure (the brief's §30, the plan's §3.6).

## 2. The nineteen courts and their evidence

Every figure below is read from `artifacts/phase24/COURTS.json` and the plane it names, not typed. A
passing court is an **instrument**: it ran and its control was honest; the property it names is
carried by the row's `findings`.

| # | court | subject | verdict |
|---|---|---|---|
| 24.1 | `RT-RANKING-SOURCES` | the frozen multi-source ranking evidence, content-addressed before any candidate result | `pass` |
| 24.2 | `RT-CANDIDATE-UNIVERSE` | the package identities and the deduplicated project families they collapse to | `pass` |
| 24.3 | `RT-AUTHORITY-CENSUS` | the authority-side baseline census, one pristine-source run per cohort member | `pass` |
| 24.4 | `RT-FAMILY-FREEZE` | the frozen P1000 and reserve, selected from the frozen ranking evidence | `pass` |
| 24.5 | `RT-HOLDOUT-PARTITION` | the precommitted development/holdout split, fixed before the candidate ran | `pass` |
| 24.6 | `RT-BUILD-LINK-ATLAS` | the build/link atlas, one run per specimen per subject | `pass` |
| 24.7 | `RT-RUNTIME-FUNCTIONAL-ATLAS` | the load/run/behave runs down to the functional level | `pass` |
| 24.8 | `RT-FAILURE-MINIMIZATION` | the classified, preserved, minimized failures plane | `pass` |
| 24.9 | `RT-HIGH-VALUE-TIER` | the deepest families by the committed usage fingerprints | `pass` |
| 24.10 | `RT-HOSTILITY-AUGMENTATION` | the separate hostility-augmentation corpus | `pass` |
| 24.11 | `RT-CANDIDATE-FREEZE` | the frozen candidate identity and the once-run holdout | `pass` |
| 24.12 | `RT-P1000-RUN` | the final full P1000 run at the frozen candidate | `pass` |
| 24.13 | `RT-ATLAS-RECONCILIATION` | the reconciled atlas, one accounted view of every plane | `pass` |
| 24.14 | `RT-FRF-CLOSURE` | the FRF/Gemel chain closure, and why it is vacuous | `pass` |
| 24.15 | `DOWNSTREAM-1000-SEAL` | the closure of the atlas as the stratum's claim | `pass` |
| 24.16 | `RT-BLOCKER-LEVERAGE` | the biggest-mover shared-blocker analysis over the finished measurement | `pass` |
| 24.17 | `RT-BLOCKER-REMEDIATION` | the biggest-mover remediation: the exact repairs, the preserved before, the re-measured after and the movement | `pass` |
| 24.18 | `RT-RECIPE-CAMPAIGN` | the recipe-admission campaign: the attempts, the admitted recipes, the counts and the measured movement | `pass` |
| 24.19 | `RT-CLOSE-BATCH` | the close-candidate reclamation: the 24.18 linkage misses, the dead-URL pins and the fresh draw, the admitted recipes, the classification findings and the measured movement | `pass` |

Each court reads the artefact that carries its subject and maintains no list of its own, so it
cannot disagree with the evidence it summarises (the plan's §3.5). Each derives controlled mutations
beside the real evidence and requires the instrument to detect the gap it injects; a control that
cannot fail is not evidence (§3.2). The per-court result counts are in `artifacts/phase24/COURTS.json`
and are not restated here (D97).

## 3. The closure of the atlas, and the instrument-versus-property split

**A passing court is an instrument; the property it names is carried by `property_status` and
`findings`.** `RT-ATLAS-RECONCILIATION` is the unit where the two diverge on this tree: it passes as
an instrument while its property reads `NOT_CLAIMED` with findings — the `NOT_APPLICABLE` share, the
thin measured surface and the non-empty residual set — so **a passing `RT-ATLAS-RECONCILIATION` must
never be read as "the population drops in"**.

**The reconciled atlas is the stratum's claim, and `DOWNSTREAM-1000-SEAL` closes it.** 24.13
reconciles every committed Phase-24 plane — the frozen P1000 and holdout, the build/link and
runtime/functional atlases, the failures plane, the high-value tier, the hostility corpus, the
candidate freeze, the full P1000 run and the usage fingerprints — into one accounted view: every
counted family has exactly one re-derived `drop_in_verdict`, every residual is classified, every
failure is preserved and minimized, and the rates are computed over the frozen population rather
than typed. 24.15's `DOWNSTREAM-1000-SEAL` checks that the committed reconciliation, the final
run, the candidate freeze and the FRF closure agree with one another and with the seal document;
that the declared contract is the plan's nineteen units; that the bound §4 states is present rather
than hidden; and that the four non-claims §6 records are carried as findings. **A passing
`DOWNSTREAM-1000-SEAL` is an instrument, not "the downstream ecosystem is safe":** it establishes
that the atlas closed, not that any unmeasured consumer is compatible.

**Mean instrument, measured claim.** Every figure this seal states is measured over the frozen
population and committed in a content-addressed artefact; the claim this seal licenses is bounded to
those figures (§5), and the four non-claims (§6) are the boundary the measured claim never crosses
(§7). The word **measured** is used throughout for what an instrument drove; **claimed** is reserved
for the bounded statement of §5.

**The seal court reads no derived state of its own stratum.** `DOWNSTREAM-1000-SEAL` reads the
committed reconciliation, the full P1000 run, the candidate freeze and the FRF closure, and the seal
document — but **not** `forensics/phase-state.json`, **not** `forensics/phase24-obligations.json`
and **not** `artifacts/phase24/COURTS.json`. Those are exactly what this court's own pass moves, and
an instrument that read its own effect would flip with that effect rather than with the evidence it
measures. This is the Phase-20 defect (§12) anticipated rather than repeated.

## 4. The bound on the measurement — the honest reading of 967/1000 NOT_APPLICABLE

The bound is stated plainly rather than hidden, and it is the load-bearing boundary of every figure
below:

- **The venue admits an authoritative, pinned, pristine source recipe for only 35 of the 1,000 counted families.**
  The other 965 have no such recipe, and the atlas refuses to manufacture a source URL for them
  (the plan's §3.4). A family with no recipe is recorded `acquire-failure`/`unavailable` and is
  **venue-limited**, never a pass and never a fail of that family. 24.17 admits a bounded batch of
  eight such families and repairs the recipe-backed blockers the venue can run (the plan's §4.13);
  24.18's **recipe-admission campaign** attempts 69 recipe-less counted families and admits ten
  further venue-buildable recipes, each really built and linked against both subjects (the plan's
  §4.14); and 24.19's **close-candidate reclamation** attempts 63 further counted families -- the
  24.18 linkage misses, its dead-URL pins re-pinned to working official URLs, and a fresh
  deterministic draw -- and admits five more, each really built and linked against both subjects,
  while recording three families that build in the venue but link no OpenSSL subject as classification
  findings rather than forcing them to link (the plan's §4.15). The recipe-backed count moves from 20
  to 30 at 24.18 and to 35 at 24.19.
- **The ladder is `PASS 33 / PARTIAL 0 / FAIL 0 / UNKNOWN 0 / NOT_APPLICABLE 967`.** Of the thirty-five
  recipe-backed families, thirty-three reach an authority-applicable baseline at L4 or above, so the
  drop-in question is posed for those thirty-three: **the candidate reaches its authority-applicable baseline for all 33 measurable families**.
  All thirty-three are `DROP_IN_PASS`; `DROP_IN_FAIL` is 0 and `DROP_IN_UNKNOWN` is 0. The **pass
  level** behind each pass is not uniform: `drop-in-pass` is a baseline-normalized verdict count, not
  an execution rung, so some passes have no admitted runtime workload behind them, and §5 states that
  split rather than leaving the ladder to be misread as a nested funnel.
- **A `NOT_APPLICABLE` family is neither a pass nor a fail.** The 967 `DROP_IN_NOT_APPLICABLE`
  verdicts are the honest consequence of the admitted recipe coverage, not a measurement of those
  families: this venue did not pose the drop-in question for them, so it records that it did not
  rather than counting an unposed question as a pass. The raw family count (1,000) is visible beside
  the measurable count (33) precisely so the 967 cannot be read as agreement.
- **The measured surface is thin against the known universe:** 600/6499 exported symbols, 42/81
  public headers and 39/152 API families. The atlas speaks for a slice of the authority's public
  surface, and it says so.
- **candidate-specific downstream patches: 0.** No counted family required a candidate-specific
  downstream patch, so every `DROP_IN_PASS` rests on the same pristine source, a succeeded
  authority baseline, the authority-applicable level, proven linkage and zero patches (the plan's
  §3.2). A patch-requiring family would be `DROP_IN_FAIL`, not a pass.

A family this venue cannot pose the drop-in question for is an honest non-applicability, never an
`UNKNOWN`; `DROP_IN_UNKNOWN` is 0 by the schema, not by omission (the plan's §3.5).

## 5. The claim, and its bound

This stratum makes the downstream-1000 measurement of `docs/RELEASE_GATES.md` §1 mechanical over a
frozen, precommitted population of real OpenSSL downstream project families, and compiles exactly
the drop-in ladder the plan requires it to make baseline-normalized:

> **the downstream-1000 atlas over the frozen P1000 population, the `linux-x86_64` platform and the
> admitted candidate install `de196adb…`, bounded to the venue's admitted pristine-source recipe
> coverage: a content-addressed, reproducible, machine-queryable measurement of how a
> precommitted, multi-source-selected population of **1,000** real OpenSSL downstream project
> families depends on OpenSSL, in which only the **35** recipe-backed families have a posed drop-in
> question, the ladder is `PASS 33 / PARTIAL 0 / FAIL 0 / UNKNOWN 0 / NOT_APPLICABLE 967`, the
> candidate reaches its authority-applicable baseline for all 33 measurable families, every verdict
> is baseline-normalized against the admitted authority, every residual is classified from the
> closed vocabulary with `unknown` 0, every failure is preserved and minimized, the measured surface
> is 600/6499 exported symbols, 42/81 public headers and 39/152 API families, the candidate-specific
> downstream patch count is 0, and every rate is computed over the frozen population rather than
> typed — and is explicitly bounded by the four non-claims of §6, by the coverage boundary §4
> records (the 965 recipe-less families read `NOT_APPLICABLE`, which is neither a pass nor a fail),
> and by the measured / inferred / known-divergence / not-tested / not-claimed separation of §7.**

Not: "proof that any consumer is safe"; not "the ecosystem drops in"; not "1000/1000"; and not a
claim wider than the population, the venue, the measured surface and the candidate named. A
`NOT_APPLICABLE` family is neither a pass nor a fail, and the atlas makes no statement about an
unmeasured consumer.

**The pass-level bound.** The ladder is not a nested funnel: `drop-in-pass` is the baseline-normalized verdict count rather than an execution rung, so it is not required to be non-increasing with the rungs above it, and the figure does not hide where the passes sit — thus of the 33 drop-in passes, 25 are at L4-linked with no admitted runtime workload for those families and 8 reach L5 or above. A pass at `L4-linked` is a link-level pass: the candidate reached exactly the level the authority itself reached and the venue admits no runtime or functional workload for that family, so only the eight families that reach `L5` or above have a runtime level behind their pass. This is the material caveat §4 states, and it is generated — `docs/SEAL-CENSUS.md` and `docs/PHASE-24-BIGGEST-MOVERS.md` derive the same split from the final run's verdict rows, and the `DOWNSTREAM-1000-SEAL` court requires this sentence of the seal.

## 6. The four non-claims

The stratum never exceeds these, and the seal records them as findings. Spelled out lowercased so
the markers are exact: a selected population is not a random sample; 1000/1000 is not a security
proof; a build is not a functional proof; direct and transitive consumers are different evidence.

* **A selected population is not a random sample.** The 1,000 families are *selected* from frozen
  ranking evidence, so their drop-in rates are a measurement of that population and do not
  generalise to all downstream software; no population-wide confidence interval or test statistic is
  computed (the brief's §53, the plan's §4.6).
* **1000/1000 is not a security proof.** A full pass is not a guarantee that any consumer is safe,
  and it makes no statement about an unmeasured consumer; the two hostility-corpus candidate
  failures (§9) are the concrete record that a candidate failure in the surface the counted
  population does not drive is possible and is preserved rather than hidden.
* **A build is not a functional proof.** Reaching `L3-built` or `L4-linked` is not behaving; only
  the functional levels (`L6-runtime`, `L7-functional`) are behavioural evidence, and a pass at a
  lower level is not a pass at a higher one.
* **Direct and transitive consumers are different evidence.** A project that only links a library
  transitively is a different measurement from one that calls the API directly, and the two are
  never summed into one rate (the plan's §3.6).

## 7. The measured / inferred / known-divergence / not-tested / not-claimed separation

The stratum keeps five kinds of statement apart (the brief's §69), and this is the line that keeps
the claim honest:

* **measured** — what an instrument drove and observed: the imported surface of the counted
  consumers, 600/6499 exported symbols, 42/81 public headers and 39/152 API families, and the thirty-three
  measurable families' baselines and verdicts. This is execution and import evidence.
* **inferred** — the Phase-22 reachability closure (35,432 reachable entities over 7 roots), which
  is inference from the committed reference graph and is **never** execution; it is reported beside
  the direct surface and never added to it (the brief's §34).
* **known-divergence** — a difference the committed evidence names rather than erases: the two
  hostility-corpus candidate failures of §9. A known divergence is a
  preserved record, not a silently closed gap and not a P1000 rate.
* **not-tested** — the 967 `NOT_APPLICABLE` families and any behaviour no instrument drove; an
  unposed question is recorded unposed, never a pass (the plan's §3.5).
* **not-claimed** — the four non-claims of §6 and the properties no instrument measures (a security
  proof, a functional proof from a build, a population-wide rate from a selected population).

## 8. FRF and Gemel: the chain entry, and why it is vacuous

**This stratum owns no FRF-declarable court, so it begins no FRF chain and needs no Gemel
checkpoint.** All nineteen courts read committed evidence and stage no
`artifacts/phase24/probes/<probe>.{authority,candidate}` pair, so each carries `frf_declarable:
false` with its exclusion reason in `artifacts/phase24/COURTS.json`. `forensics/tools/phase_state.py`'s
`frf_gemel_blocking_reason` derives its requirement from that inventory, never from the registry it
checks, and its documented rule is that *"a stratum whose own court inventory declares no
FRF-declarable court has begun no chain and is **not blocked here**."* Confirmed on this tree:
`frf_gemel_blocking_reason(24) == ""`. This is the same scoping under which Phase 20 — the custodian
seal — Phase 21 — the maintenance delta — Phase 22 — the other non-declarable meta-stratum — and
Phase 23 — the multitrack authority — sealed without a chain entry.

No `.frf` object and no Gemel change or checkpoint was created for Phase 24, because the mechanism
requires none. What stands in the place of a declarable court is recorded in
`forensics/atlas/phase24/frf-closure.json` and re-checked by `RT-FRF-CLOSURE`:

* the **`RT-FRF-CLOSURE` harness challenge** — each of the **13** Phase-24 planes' own pure checker
  is driven over its committed artefact and over the controlled mutations its own sensitivity
  control seeds, and the classifier is proved not a rubber stamp (a registered challenge whose
  observed result is mutated in memory is reported `NOT_DETECTED`): 13 `DETECTED`, 0 `NOT_DETECTED`,
  0 `NOT_DRIVEN`; and
* the **committed Gemel checkpoint projection** — `forensics/GEMEL_TRAJECTORY.md`'s `current:`
  checkpoint `checkpoint.4b913a19e54b61b2f21bf0ed78a152424a79e6dbd291684b2b5f4dc0d713d35d` — over
  **70** checkpoints, which is the boundary a later session resumes from.

The store is **re-created at a release, not at a stratum seal**: the stratum records the chain
status and the release re-creates the store. This seal records the division rather than moving it.

## 9. The honest failure and divergence record

Every discovered failure is preserved and classified rather than discarded, and the record is
scoped so a hostility result is never read as a P1000 rate (the plan's §3.7):

* **The counted P1000 leftover set is 3,928 preserved records**, classified from the failure
  taxonomy: 3,880 `acquire-failure`/`unavailable` (no admitted pristine-source recipe — the venue
  limitation §4 names), 4 `configure-failure`/`unbuildable`, 4 `link-failure`/`unlinked`, and 40
  `out-of-scope` venue-limited dispositions. **0 are candidate-specific**, so **0 required a
  minimized reproducer** — there is no candidate defect to minimize — and **0 were fixed** because a
  discovered-and-minimized failure is a preserved record, not a fix.
* **The two hostility-corpus candidate failures are named and scoped out of every P1000 rate.**
  `run:hostility:static:candidate` failed at `L3-built` (`link-failure`: the static probe's link
  against the Rust archive did not complete), and
  `run:hostility:tls:candidate-candidate->authority-tls1.2` failed at `L6-runtime`
  (`runtime-failure`: the **TLS-1.2 cross-implementation** handshake/workload did not complete).
  Both are preserved in `forensics/downstream/hostility-corpus.json` with `scoped:not-a-p1000-rate`
  evidence and are **excluded from every P1000 rate**: the separate hostility corpus is not the
  counted population.
* **The isync subject divergence this seal previously recorded was resolved by 24.17 and is now a
  pass.** Before 24.17's link-environment repair, `family:isync`'s authority baseline stopped at
  `L1-admitted-source` while the candidate reached `L5-loaded`, so the drop-in question was not
  posed and the verdict was `DROP_IN_NOT_APPLICABLE`/`out-of-scope`. 24.17's `-Wl,-rpath-link`
  repair (§13.6) resolved it: isync now reaches `L7-functional` under both subjects and its verdict
  is `DROP_IN_PASS`. **No counted family now records a subject divergence**, so the `PARTIAL` in the
  ladder is 0.
* **11,172 residuals remain unresolved and 11,373 in total**, every one classified from the closed
  vocabulary with `unknown` **0** and `unclassified` **0**; the residual set is accounted for but
  not empty.

## 10. The final tables (§70 / §51 / §52)

Every figure is machine-derived from the landing artefacts (`forensics/downstream/reconciliation.json`,
`forensics/downstream/p1000-run.json`, `forensics/downstream/candidate-freeze.json`), not typed.

**The population and the ladder (the brief's §52):**

| quantity | value |
|---|---|
| P1000 counted families | 1000 |
| recipe-backed families | 35 |
| measurable families | 33 |
| not-applicable families | 967 |
| `L2-configured` / `L3-built` / `L4-linked` | 33 / 33 / 33 |
| `L5-loaded` / `L6-runtime` / `L7-functional` | 8 / 8 / 8 |
| ladder | `PASS 33 / PARTIAL 0 / FAIL 0 / UNKNOWN 0 / NOT_APPLICABLE 967` |

**The verdict histogram (the brief's §51):**

| verdict | count |
|---|---|
| `DROP_IN_PASS` | 33 |
| `DROP_IN_PARTIAL` | 0 |
| `DROP_IN_FAIL` | 0 |
| `DROP_IN_UNKNOWN` | 0 |
| `DROP_IN_NOT_APPLICABLE` | 967 |

**The coverage against the known universe (the brief's §35):**

| surface | measured | known universe |
|---|---|---|
| exported symbols | 600 | 6499 |
| public headers | 42 | 81 |
| API families | 39 | 152 |

**The usage clusters (the brief's §36, §37):** 3 usage clusters over 6 fingerprinted consumers, 3
distinct stressors (curl/haproxy; monit/pure-ftpd/redis; openssh), 6 marginal consumers — so the
counted families are not read as that many independent stressors.

**The defects and the instruments (the brief's §70):**

| quantity | value |
|---|---|
| candidate-specific defects discovered / minimized / fixed | 0 / 0 / 0 |
| counted leftover records preserved (0 minimized) | 3928 |
| resident hostility failures (preserved, scoped out of every P1000 rate) | 2 |
| permanent courts added (the nineteen contract-unit instruments) | 19 |
| candidate-specific downstream patches | 0 |

**The first-run results and the final result:**

| result | value |
|---|---|
| development first run: 6 measurable families and 6 reaching the baseline | measurable |
| holdout first run: 1 measurable family and 1 DROP_IN_PASS | out-of-sample |
| final result | `PASS 33 / PARTIAL 0 / FAIL 0 / UNKNOWN 0 / NOT_APPLICABLE 967` over 1,000 counted families (33 measurable) |

**The Phase-22 projection (the brief's §34):** 600 directly-referenced symbols (measured
execution/import evidence) beside 35,432 graph-reachable inferred entities (inference, never
execution), never summed.

## 11. The bound roots (§67)

The atlas is content-addressed end to end, and the seal records the roots a reader can recompute
from the artefacts rather than from this document. Each is read or derived from the landing
artefacts, not typed; the root of the P1000 selection is the freeze's own, the atlas root is the
reconciliation body's, the consumer-receipt and residual roots are content hashes over the full
P1000 run's per-consumer receipts and the reconciliation's classified residuals, the coverage root
is the measured surface hash, and the candidate identity is the frozen install's:

| bound root | value |
|---|---|
| P1000 selection root | `f2a0454fe4dca98556da2e958b6e70cebaf76becbebba69b2abd752e63deba4e` |
| atlas root (reconciliation body) | `327ab08b20ad5cbacc95e7c668bd03eafe7c06fa0514fd3a28c03207b97adbe9` |
| consumer-receipt root | `05f2975423e902123d913ece3b7e9c40b7c8d0bdab171a9653a9b11a3cdf97a6` |
| residual root | `670b3ba9cb6b4995e15414904d53bbeab52dfb7daaa9f25ec29786fca8b48ab1` |
| coverage root (measured surface) | `c18b7a4f90919ac4c69ff0bacf8f97e03c1f77cd3f8f050878c4c590f785d68c` |
| candidate identity | `ba530a8830e30729db33cfd734e94abfe53f431c92260e00fcbd34efc4840f97` |

The FRF/Gemel chain boundary is the checkpoint projection §8 records:
`checkpoint.4b913a19e54b61b2f21bf0ed78a152424a79e6dbd291684b2b5f4dc0d713d35d`.

## 12. What this atlas does not establish

It is not a security proof, and it makes no claim about an unmeasured consumer; it is a **selected**
population and its rates are rates for that population, not for all downstream software. A
`DROP_IN_PASS` is a statement that one pristine variant of one specimen reached its
authority-applicable baseline with proven linkage and zero patches — not that the consumer is
correct, secure, or compatible in any configuration this venue did not build. The 967
`NOT_APPLICABLE` families are recorded unposed, not passed. The measured surface is a thin slice of
the authority's public surface no instrument drove past the levels it records. And the two
hostility-corpus candidate failures are preserved beside the counted result precisely because the
counted population did not drive the surfaces they exercise.

## 13. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction merged into the prose it corrects cannot be checked against what it replaced.

1. **`forensics/tools/atlas_common.py`'s `SEAL_DOCS` already carried `24:
   docs/PHASE-24-DOWNSTREAM-1000-SEAL.md`** from 24.0, so no table change was needed here; the seal
   is recorded and `seal_sha256` is recomputed by `render_seal_census.py` and `phase_state.py` at
   the next regeneration.
2. **`DOWNSTREAM-1000-SEAL` was registered and `PENDING_COURTS` emptied, closing the
   `downstream-1000-seal` unit.** `forensics/tools/phase24_courts.py` previously declared the court
   `pending` with the subphase that lands it; 24.15 registers it, the registry is complete at
   **15/15** at the seal, and `forensics/phase24-obligations.json`'s `open_in_this_stratum` falls
   from 1 to 0. (24.16 re-opens the stratum with a sixteenth unit and closes it again; §13.5 records
   that — this seal's own 15/15 is the state at 24.15.)
   The ledger's `downstream-1000-seal` closure text — *the `DOWNSTREAM-1000-SEAL` court passes* —
   was already correct and is now satisfied rather than asserted.
3. **The Phase-20-style defect was checked, and no court's finding flips with the seal document.**
   The Phase-20 defect was a court that read the seal's presence and changed its finding when the
   seal landed. On this tree the fifteen existing Phase-24 courts read **no** seal document and
   **no** derived state of their stratum, and the new `DOWNSTREAM-1000-SEAL` court deliberately
   reads neither `forensics/phase-state.json` nor `forensics/phase24-obligations.json` nor
   `artifacts/phase24/COURTS.json`: it checks the seal document's *shape* and the committed planes,
   so its verdict cannot flip with its own pass. The audit found nothing to fix, and the constraint
   is recorded as a design rule in §3 rather than left implicit.
4. **`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` §4.11 records 24.14's FRF/Gemel closure as
   vacuous by `phase_state.py`'s own scoping.** The plan's §2 wording — the chain closure *"where
   the stratum stages a declarable court"* — is a conditional this stratum's no-probe shape
   resolves to the vacuity: the stratum owns no probe, so no Phase-24 court is declared in
   `gen_frf_courts.py` and no `artifacts/phase24/probes/<probe>.{authority,candidate}` pair is
   staged. What stands in its place is the `RT-FRF-CLOSURE` harness challenge plus the committed
   Gemel checkpoint projection (§8), and the §2 row is not rewritten into a declarable one.
5. **24.16 lands the biggest-mover shared-blocker analysis, a sixteenth contract unit, and this
   seal cites it.** The plan's §2 gains the 24.16 row and §1's count moves to sixteen; the ledger's
   `COURT_UNITS` gains `blocker-leverage` with the closure *the `RT-BLOCKER-LEVERAGE` court passes*;
   and the court re-derives the partition, the ranking, the counts, the funnel and the recipe queue
   from the committed planes and requires `docs/PHASE-24-BIGGEST-MOVERS.md`, the `README.md`
   `downstream-blockers` block and the `Biggest movers (generated)` section of `docs/SEAL-CENSUS.md`
   to reproduce and to cross-link. It is an **instrument**, not a repair: it names which blocker
   moves the most families so 24.17 can act, and its recipe queue is a **heuristic** ranking of
   buildability rather than a measurement of it. `REQUIRED MARKER`: this seal carries
   `docs/PHASE-24-BIGGEST-MOVERS.md` so the seal court refuses a seal that has lost the link to the
   analysis, and the census's `Biggest movers (generated)` marker is likewise required. The stratum
   re-opens with a sixteenth open unit while the new court is unregistered and closes again when it
   passes (`forensics/phase24-obligations.json` reads `open_in_this_stratum: 0`, `owned` 16,
   `implemented` 16).
6. **24.17 lands the biggest-mover remediation, a seventeenth contract unit, and this seal cites it
   and its measured movement.** The plan's §2 gains the 24.17 row and §1's count moves to seventeen;
   the ledger's `COURT_UNITS` gains `blocker-remediation` with the closure *the
   `RT-BLOCKER-REMEDIATION` court passes*; and the court re-derives the whole before/after record
   from the committed planes and the preserved pre-remediation baseline
   `forensics/downstream/blocker-remediation-baseline.json`. The record
   `forensics/downstream/blocker-remediation.json` names the exact recipe/flag/fixture each repair
   applied, preserves the 24.16 blocker partition as its `before`, re-derives the re-measured `after`
   from the committed planes, and computes the **movement** — so what was repaired and what the
   planes then measured is a measurement rather than a claim. It fixes the recipe-backed blockers the
   fixed venue can run (kmod's `--disable-manpages`, openvpn's 2.5 pin without libnl/libcap-ng,
   isync's `-Wl,-rpath-link`), adds the two missing deterministic local fixtures (an authenticated
   explicit-TLS FTPS login for pure-ftpd; a local IMAP4rev1-over-TLS peer for isync), admits a
   bounded, deterministic batch of recipe-less families whose pinned tarball ships a build entry
   point the venue can execute, and records what it cannot repair as `still-blocked` with the exact
   missing tool (`libssh` needs `cmake`; `lighttpd` needs autotools/cmake/meson). It is an
   **instrument**: a build/link is not a functional proof, and a still-blocked class is a measurement
   of the fixed venue rather than of the project. `REQUIRED MARKER`: this seal carries
   `forensics/downstream/blocker-remediation.json` so the seal court refuses a seal that has lost the
   link to the measured remediation. The stratum re-opens with a seventeenth open unit while the new
   court is unregistered and closes again when it passes (`forensics/phase24-obligations.json` reads
   `open_in_this_stratum: 0`, `owned` 17, `implemented` 17).
7. **24.18 lands the recipe-admission campaign, an eighteenth contract unit, and this seal cites it
   and its measured movement.** The plan's §2 gains the 24.18 row and §1's count moves to eighteen;
   the ledger's `COURT_UNITS` gains `recipe-campaign` with the closure *the `RT-RECIPE-CAMPAIGN`
   court passes*; and the court re-derives the whole record from the committed planes and the
   preserved pre-campaign baseline `forensics/downstream/recipe-campaign-baseline.json`. The record
   `forensics/downstream/recipe-campaign.json` selects a candidate list from the committed evidence
   by a stated, reproducible priority rule, finds each candidate's official release tarball, pins its
   URL and SHA-256, classifies its build system **empirically**, and admits only the venue-buildable
   ones into the shared recipe catalogue under the identical-build-intent rule. Every attempt
   (admitted or not) is recorded with its outcome, its failure class and its reason: the measured
   batch attempts **69** recipe-less counted families and admits **10** (each really built and linked
   against both subjects), moving the frozen P1000's measurable, candidate-linked and `DROP_IN_PASS`
   counts from **18 to 28** and its `no-admitted-recipe` count from **980 to 970**. It is an
   **instrument**, not a repair of the properties: the campaign's yield is a property of this venue
   and this batch, not of the whole 970, and a build/link is not a functional proof. `REQUIRED
   MARKER`: this seal carries `forensics/downstream/recipe-campaign.json` so the seal court refuses a
   seal that has lost the link to the measured campaign. The stratum re-opens with an eighteenth open
   unit while the new court is unregistered and closes again when it passes
   (`forensics/phase24-obligations.json` reads `open_in_this_stratum: 0`, `owned` 18,
   `implemented` 18).
8. **24.19 lands the close-candidate reclamation, a nineteenth contract unit, and this seal cites it
   and its measured movement.** The plan's §2 gains the 24.19 row and §1's count moves to nineteen;
   the ledger's `COURT_UNITS` gains `close-batch` with the closure *the `RT-CLOSE-BATCH` court
   passes*; and the court re-derives the whole record from the committed planes and the preserved
   pre-batch baseline `forensics/downstream/close-batch-baseline.json` and its authored attempt record
   `forensics/downstream/close-batch-attempts.json`. The record
   `forensics/downstream/close-batch.json` targets the 24.18 linkage misses, its dead-URL pins and a
   fresh deterministic draw; it fixes the argv where the flags failed to enable a project's TLS
   support, pins a correct official release URL where the pin had died, and admits only the recipes
   actually configured, built and **linked against both subjects** under the identical-build-intent
   rule. A family that builds in the venue but links no OpenSSL subject is recorded as a
   **classification finding**, never forced to link a library it does not use, and every attempt --
   admitted or not -- is recorded with its outcome and reason. The measured batch attempts **63**
   counted families and admits **5** (`rsync 3.3.0`, `ssmtp 2.64`, `squid 6.12`, `keepalived 2.3.1`,
   `libretls 3.8.1`, each really built and linked against both subjects) with **3** classification
   findings (`nghttp2`, `gensio`, `vsftpd`), moving the frozen P1000's measurable, candidate-linked
   and `DROP_IN_PASS` counts from **28 to 33** and its `no-admitted-recipe` count from **970 to 965**.
   It is an **instrument**, not a repair of the properties: the batch's yield is a property of this
   venue and this batch, not of the whole set, and a build/link is not a functional proof. `REQUIRED
   MARKER`: this seal carries `forensics/downstream/close-batch.json` so the seal court refuses a seal
   that has lost the link to the measured batch. The stratum re-opens with a nineteenth open unit
   while the new court is unregistered and closes again when it passes
   (`forensics/phase24-obligations.json` reads `open_in_this_stratum: 0`, `owned` 19,
   `implemented` 19).

SPDX-License-Identifier: Apache-2.0
