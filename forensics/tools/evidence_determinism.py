#!/usr/bin/env python3
"""openssl-rs — is the committed evidence what the generators actually produce?

Why this is not a plain `git diff`
---------------------------------
Most derived artefacts are a pure function of committed inputs and must be
byte-identical when regenerated. A few *fields* are not, because they record the
**build product** — the compiler's output — rather than a committed input:

  * `inputs[name=crate-archive|extra-object].sha256` in
    `forensics/atlas/implemented-surface.json`. A Rust static archive is not
    guaranteed byte-reproducible across build environments.
  * `internal_symbols.compiler_emitted_count` in the same artefact. Which global
    symbols a toolchain emits is a property of that toolchain: most of the
    archive's symbol population is LLVM-internalised anonymous data named
    `anon.<hash>.<n>.llvm.<hash>`, and those hashes change from build to build.
    The *names* are not recorded at all for this reason; the stable C-identifier
    subset is (`internal_symbols.c_style`) and **is** compared exactly.
  * `body_hash` is computed over the evidence subset of `body`, so the build
    product cannot propagate into it, and the obligation ledgers bind that
    digest rather than the artefact's file digest.

So this tool compares the committed artefacts against freshly generated ones
after **normalising exactly those declared fields**, and it reports which fields
it normalised and why. Everything else — every count, every symbol name, every
phase state, every obligation — is compared exactly.

What it catches
---------------
A committed artefact that has drifted from its generator: a ledger whose counts no
longer match the implemented surface, a `STATUS.md` that was edited by hand, a
phase state that was not re-derived after the evidence changed. Those are the ways
a claim silently becomes unverifiable.

Usage
-----
    python3 forensics/tools/evidence_determinism.py          # regenerate and check
    python3 forensics/tools/evidence_determinism.py --keep   # leave outputs written

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel  # noqa: E402

# The generators, in dependency order: each may consume the previous artefact.
# `implemented_surface.py` needs a built archive, so the build is a precondition
# and the caller runs it first.
#
# The per-stratum obligation generators are **discovered**, not listed. Listing them
# meant every new stratum had to remember to add its generator here as well as to the
# court runner, the ownership audit and the regression guard -- four registries for
# one fact, which is the failure mode `run_courts.py` removed for the courts and
# D94 records in full. The glob is checked in both directions below: a
# `phase<N>_obligations.py` with no ledger, and a ledger with no generator, are both
# failures rather than silent omissions.
#
# `ownership_audit.py` sits **after** the obligation generators, not before them: it
# reconciles the ledgers and records each one's sha256 as an input, so running it
# first makes it record the *previous* generation's hashes. That mistake is invisible
# to this tool, because `inputs[].sha256` for a path that is itself compared is
# normalised away (COMPARED_INPUT_PATHS below) -- the ledger's content is compared
# directly, so a wrong recorded hash changes nothing this check can see. It was found
# by running the audit alone, after the ledgers, and watching the recorded hashes
# move. Measured on the Phase 5.3 landing.
GENERATORS_BEFORE_LEDGERS = [
    "forensics/tools/symbol_ownership.py",
    "forensics/tools/implemented_surface.py",
    # Phase 6.7b: the character-class table, derived from the authority's own
    # `crypto/ctype.c`. It is listed so that a stale committed copy is a failure
    # rather than a silent divergence: the whole point of generating it was to stop
    # 128 masks being recalled, and a generator nothing re-runs would reintroduce
    # exactly that.
    "forensics/tools/gen_ctype_table.py",
    # The error-coordinate plane (D135, closing D109's open half). It reads the
    # authority's source tree too, so it carries the same two-tier check: re-derive when
    # the tree is present, and check `src/runtime/err_sites.rs` against the committed
    # `err-raise-sites.json` when it is not. `check_evidence_portability.py` tests
    # `ed.GENERATORS` as one set, so listing it here is also what puts it in that gate's
    # exercised set -- which was the other half of what D109 left open, and the reason
    # doing only one of the two would have replaced one silent gap with two.
    "forensics/tools/gen_err_raise_sites.py",
    "forensics/tools/gen_bn_primes.py",
    # Phase 8.5's named-group constants (D332). It is listed here so a stale committed copy
    # is a failure and not a silent divergence: the whole point of reading 13,536 bytes of
    # limb data back from the authority instead of transcribing them is defeated by a
    # generator nothing re-runs. It has two tiers like the two above -- re-derive with the
    # authority present, rebuild-and-compare from the committed pair without it -- and it
    # additionally checks `src/bn/dh.rs`'s accessor table against `bn_dh.c`'s own
    # `make_dh_bn` inventory in **both** tiers, so a hand edit to that table fails on a
    # runner with no authority too.
    "forensics/tools/gen_bn_dh.py",
    # Phase 8.7's built-in curve parameters (D334). Listed here so a stale committed copy is a
    # failure and not a silent divergence: the whole point of reading 14,542 bytes of curve
    # constants back from the authority instead of transcribing them is defeated by a generator
    # nothing re-runs. It has the same two tiers as the three above -- re-derive with the
    # authority present, rebuild-and-compare from the committed pair without it -- and it
    # additionally checks `src/ec/support.rs`'s two name tables against `crypto/evp/ec_support.c`
    # in **both** tiers, so a hand edit to that module fails on a runner with no authority too.
    "forensics/tools/gen_ec_curves.py",
    # The provider algorithm-row census (D237). It reads the authority's provider tables and
    # the crate's two provider modules, and nothing else, so it has no position dependence
    # beyond being after the crate's sources are final; it is listed here so a stale
    # committed copy is a failure rather than a silent divergence. The whole point of the
    # census is that `DES3-WRAP` was invisible, so a generator nothing re-runs would
    # reintroduce exactly that.
    "forensics/tools/gen_provider_algorithms.py",
    # Phase 18.1's hostile TLS corpus. It reads no authority -- the corpus is authored state, not
    # authority-derived -- but it is listed here so a stale committed fixture is a failure and not
    # a silent divergence: the whole point of a *fixed* corpus is that the bytes the court drove
    # are the bytes the generator derives, and a corpus nothing re-runs would drift from the
    # ledger row that names it. It writes one file per entry plus the manifest; the manifest is
    # compared below, and `RT-HOSTILE-TLS` itself re-verifies every entry byte for byte, so a hand
    # edit to a fixture fails the court rather than changing what it drove.
    "forensics/tools/gen_hostile_tls_corpus.py",
    # Phase 18.2's hostile X.509 / malformed-input corpus. Like 18.1's it reads no authority --
    # the corpus is authored state over four committed Phase 17 fixtures -- but it is listed
    # here so a stale committed fixture is a failure and not a silent divergence: the whole
    # point of a *fixed* corpus is that the bytes the court drove are the bytes the generator
    # derives. It writes one file per entry plus the manifest; the manifest is compared below,
    # and `RT-HOSTILE-X509` itself re-verifies every entry byte for byte, so a hand edit to a
    # fixture fails the court rather than changing what it drove.
    "forensics/tools/gen_hostile_x509_corpus.py",
    # Phase 18.6's measured unsafe / FFI footprint. It reads only the crate's own
    # `src/**/*.rs`, so it has no position dependence beyond being after the sources are final;
    # it is listed here so a stale committed footprint is a failure and not a silent divergence.
    # The whole point of the table is that the memory-safety claim is a measurement rather than
    # an assertion, which a generator nothing re-runs would defeat. `render_status.py` renders it
    # into `forensics/STATUS.md`, so it must run before that renderer, and the register court in
    # `phase18_courts.py` re-scans against the authored bounds at court time.
    "forensics/tools/unsafe_footprint.py",
    # Phase 23.1's release catalogue and lineage (D535). It reads the committed archaeology
    # snapshot `forensics/multitrack/release-archaeology.json` and nothing else, so it has no
    # position dependence beyond being after the sources are final; it is listed here so a stale
    # committed catalogue is a failure rather than a silent divergence. The whole point of
    # deriving the catalogue from the snapshot rather than typing it is that the lineage is a
    # fact a reader can recompute, which a generator nothing re-runs would defeat. The court
    # `RT-RELEASE-CATALOG` reads the two artefacts it writes.
    "forensics/tools/authority_catalog.py",
    # Phase 23.3's parameterized archaeology atlas (D538). It is a pure function of committed
    # inputs -- the default-authority alias, the admitted/historical registries and the committed
    # source manifests -- so a stale receipt or plane census is a failure rather than a silent
    # divergence. The RT-ATLAS-PARAMETERIZATION court reads the two artefacts it writes and
    # re-derives every census through the same generator.
    "forensics/tools/atlas_authority.py",
    # Phase 23.5's entity lineage (D538's second identity plane). It is a pure function of the
    # committed per-authority atlases -- the declaration and public-symbol planes -- so a stale
    # committed plane is a failure rather than a silent divergence. The RT-ENTITY-LINEAGE court
    # reads the artefact it writes and re-derives every relation through the same identity shapes.
    "forensics/tools/entity_lineage.py",
    # Phase 23.6's delta engine. It is a pure function of the committed atlases and the entity
    # lineage -- the semantic compatibility delta over the canonical release-graph edges -- so a
    # stale committed edge delta is a failure rather than a silent divergence, and no pairwise
    # combination beyond the canonical edges is written. The RT-DELTA-ENGINE court reads the
    # artefacts it writes and re-derives every row through the same engine.
    "forensics/tools/authority_delta.py",
    # Phase 23.7's ABI/history façades. In the court container it is a pure function of the
    # committed measurement `forensics/multitrack/abi-facades.json`: it re-checks each layout's
    # provenance against the committed source manifest and regenerates
    # `src/compat/layout_generated.rs`, the repr(C) façades and their compile-time assertions, so
    # a cargo-visible generated file cannot drift from the measurement. (`--measure` runs only in
    # the historical venue and writes the measurement itself; the court never needs a compiler.)
    "forensics/tools/gen_abi_facades.py",
    # Phase 23.8's semantic multitrack courts. Its default run is a pure function of the committed
    # artefact's own preserved raw transcripts: it re-derives every normalized observation through
    # the same adapter and re-classifies every difference against the committed 23.6 delta engine,
    # so a stale committed plane is a failure rather than a silent divergence. (`--measure` compiles
    # and runs the probe against both authorities and runs only in the court venue; the court and
    # this re-derivation need neither a compiler nor an authority prefix.)
    "forensics/tools/gen_semantic_courts.py",
    # Phase 23.9's directional, dimension-specific compatibility views. It is a pure function of the
    # committed authorities' own evidence -- the authority-node registry, the production atlas, the
    # historical build receipts and census, the source manifest and the committed Phase-2
    # distribution shell -- so a stale committed plane is a failure rather than a silent divergence.
    # The RT-COMPATIBILITY-VIEWS court re-derives the whole plane through the same generator and
    # refuses a view relayed from another authority.
    "forensics/tools/compat_views.py",
    # Phase 23.12's directional, dimension-specific compatibility edges. It is a pure function of
    # the committed edge deltas, the entity lineage, the compatibility views and the Phase-2 ABI
    # courts, so a stale committed plane -- or a verdict that was typed rather than derived -- is a
    # failure rather than a silent divergence. The RT-COMPATIBILITY-EDGES court re-derives the whole
    # plane through the same generator and refuses a side whose evidence is inherited from the other.
    "forensics/tools/compat_edges.py",
    # Phase 23.13's negative and positive obligations. It is a pure function of the committed
    # censuses, ABI/history façades, edge deltas and symbols planes, so a stale committed plane --
    # or an obligation whose state was typed rather than read from its evidence -- is a failure
    # rather than a silent divergence. The RT-NEGATIVE-OBLIGATIONS court re-derives the whole plane
    # through the same generator and re-reads each record's named evidence through `adjudicate`.
    "forensics/tools/negative_obligations.py",
    # Phase 23.11's downstream multitrack court. Its default run is a pure function of the committed
    # artefact's own preserved raw outputs: it re-derives every consumer record from the raw build
    # and run bytes through the same code, so a stale committed record -- or a hand-typed outcome --
    # is a failure rather than a silent divergence. (`--measure` builds and runs the consumers
    # against the authority prefixes and runs only in the historical and forensic venues, one venue
    # per set of trials; the court and this re-derivation need neither a compiler nor a prefix.) It
    # sits **before** `historical_population.py`, which reads its `downstream-evidenced` rung, so a
    # plan change propagates in one pass rather than leaving the population stale.
    "forensics/tools/downstream_multitrack.py",
    # Phase 23.10's historical population. It is a pure function of the committed catalogue, the
    # authority-node registry, the acquisition and build receipts, the committed atlases, the
    # compatibility views, the semantic pair and the downstream-multitrack plane, so a stale
    # committed record -- or a hand-typed status -- is a failure rather than a silent divergence.
    # The RT-HISTORICAL-POPULATION court re-derives the whole record through the same generator and
    # refuses a typed status.
    "forensics/tools/historical_population.py",
    # Phase 23.15's support-status ladder (D545). It reuses 23.10's derivation -- it calls the
    # historical-population generator and re-expresses each record as the schema-validated
    # `support_status` row the plan names, adding the per-rung evidence and the reason for each rung
    # not attained, so the status has one derivation rather than two. The RT-SUPPORT-STATUS court
    # re-derives the whole plane through the same generator, reconciles every row with its population
    # record, and checks each attained rung is backed by the artefact that establishes it.
    "forensics/tools/support_status.py",
    # Phase 24.4's P1000 + reserve freeze. It is a pure function of committed non-ledger inputs --
    # the committed 24.2 families, the frozen 24.1 ranking evidence, and the committed 24.3
    # consensus signal it imports -- so a stale committed freeze, or a population re-selected by
    # something other than the recorded rule, is a failure rather than a silent divergence. It sits
    # **before** the ledgers because it reads no ledger; the RT-FAMILY-FREEZE court re-derives the
    # whole population through the same rule and refuses a family typed into the 1,000.
    "forensics/tools/downstream_freeze.py",
    # Phase 24.5's precommitted holdout partition. It is a pure function of committed non-ledger
    # inputs -- the committed 24.4 frozen P1000 and the committed 24.2 families -- so a stale
    # committed partition, or one re-divided by something other than the recorded rule, is a failure
    # rather than a silent divergence. It sits **after** the freeze (it reads family-freeze.json) and
    # **before** the ledgers because it reads no ledger; the RT-HOLDOUT-PARTITION court re-derives the
    # whole split through the same rule and refuses a holdout chosen after a candidate failure.
    "forensics/tools/downstream_holdout.py",
    # Phase 24.8's failure discovery/minimization plane. Unlike 24.6's and 24.7's atlases below it
    # executes nothing: it is a **pure function of committed inputs** -- the committed 24.6 build/link
    # atlas, the committed 24.7 runtime/functional atlas and the committed 24.4 frozen P1000 -- so a
    # stale committed failures plane, or a leftover re-classified by something other than the record's
    # authority row, is a failure rather than a silent divergence. It is exactly the pure aggregate the
    # 24.6/24.7 comments below anticipated ("a later subphase that derives a pure aggregate from it is
    # what belongs in this list"). It sits **after** the atlases it reads and **before** the ledgers
    # because it reads no ledger; the RT-FAILURE-MINIMIZATION court re-derives the whole plane through
    # the same functions and refuses a candidate-specific label the authority baseline does not justify.
    "forensics/tools/downstream_failures.py",
    # Phase 24.13's atlas reconciliation. Like 24.8's failures plane it executes nothing: it is a
    # **pure function of committed inputs** -- every committed Phase-24 plane (the frozen P1000 and
    # holdout, the build/link and runtime/functional atlases, the failures plane, the high-value tier,
    # the hostility corpus, the candidate freeze, the full P1000 run, the usage fingerprints) plus the
    # committed Phase-22 known-universe and reachability atlases it reads for coverage and the
    # direct/inferred projection -- so a stale committed reconciliation, or a rate/residual/failure
    # re-typed rather than re-derived, is a failure rather than a silent divergence. It is exactly the
    # pure aggregate the 24.6/24.7 comments below name ("the reconciliation") and the 24.8 comment
    # named as the pattern; the RT-ATLAS-RECONCILIATION court re-derives the whole accounted view
    # through the same functions and refuses a counted family with no verdict, an unknown residual, a
    # dropped failure or a hostility result mixed into the P1000 rate.
    "forensics/tools/downstream_reconciliation.py",
    # Phase 24.16's biggest-mover shared-blocker analysis. Like 24.8's and 24.13's planes it
    # executes nothing: it is a **pure function of the committed Phase-24 planes** (the frozen P1000,
    # the families, the build/link and runtime/functional atlases, the failures plane, the final
    # P1000 run and the reconciliation), so a stale committed analysis -- or a blocker, a count, a
    # funnel figure or a recipe-queue entry typed rather than re-derived -- is a failure rather than a
    # silent divergence. It reads no ledger; the RT-BLOCKER-LEVERAGE court re-derives the whole
    # partition, the ranking, the counts, the funnel and the queue through the same functions and
    # refuses a family the partition omits or double-counts. It must run **after** the planes above it
    # in this block, which it reads.
    "forensics/tools/downstream_blockers.py",
    # Phase 24.17's biggest-mover remediation record. Like 24.16's analysis it executes nothing: it
    # is a **pure function of the committed Phase-24 planes** (the committed analysis, the build/link
    # and runtime/functional atlases, the final P1000 run, the frozen P1000) plus the preserved
    # pre-remediation baseline `forensics/downstream/blocker-remediation-baseline.json`, so a stale
    # committed record -- or a movement figure that disagrees with the planes -- is a failure rather
    # than a silent divergence. It reads no ledger; the RT-BLOCKER-REMEDIATION court re-derives the
    # whole record through the same functions and refuses a claimed fix with no measured movement or
    # a still-blocked class marked resolved. It must run **after** the analysis above it, which it
    # reads.
    "forensics/tools/downstream_remediation.py",
    # Phase 24.18's recipe-admission campaign record. Like 24.17's record it executes nothing: it is
    # a **pure function of the committed Phase-24 planes** (the committed analysis, the build/link
    # and runtime/functional atlases, the final P1000 run and the frozen P1000) plus the preserved
    # pre-campaign baseline `forensics/downstream/recipe-campaign-baseline.json` and its own authored
    # attempt record, so a stale committed record -- or a movement figure that disagrees with the
    # planes, or an admitted recipe the atlas does not show linked -- is a failure rather than a
    # silent divergence. It reads no ledger; the RT-RECIPE-CAMPAIGN court re-derives the whole record
    # through the same functions and refuses a recipe that was not really built. The recipes it admits
    # are built by `downstream_build_link.py`, which imports its catalogue. It must run **after** the
    # analysis above it, which it reads.
    "forensics/tools/downstream_recipe_campaign.py",
    # Phase 24.19's close-candidate reclamation batch. Like 24.18's campaign it executes nothing: it
    # is a **pure function of the committed Phase-24 planes** (the committed analysis, the build/link
    # and runtime/functional atlases, the final P1000 run and the frozen P1000) plus the preserved
    # pre-batch baseline `forensics/downstream/close-batch-baseline.json` and its own authored attempt
    # record `forensics/downstream/close-batch-attempts.json`, so a stale committed record -- or a
    # movement figure that disagrees with the planes, an admitted recipe the atlas does not show
    # linked, or a classification finding that was not really built -- is a failure rather than a
    # silent divergence. It reads no ledger; the RT-CLOSE-BATCH court re-derives the whole record
    # through the same functions. The recipes it admits are built by `downstream_build_link.py`, which
    # imports its catalogue. It must run **after** the campaign above it, which it reads.
    "forensics/tools/downstream_close_batch.py",
    # Phase 24.6's **build/link atlas is deliberately not here, and not in `COMPARED`.** It is
    # produced by measurement -- real builds of real downstream releases inside the court container --
    # so the level each build reaches and the ELF it links are a function of the court's toolchain and
    # of the network, not of committed inputs; regenerating it needs a compiler and a prefix that a
    # CI runner (which runs this tool host-side) does not have, and the Docker-only guard refuses a
    # host invocation of the tool before it builds anything. This is the same precedent as the
    # Phase-17 measured corpus under `courts/phase17/downstream/*/result.json`: the raw measurement is
    # the court's business (`RT-BUILD-LINK-ATLAS` re-runs only its pure checks over the committed
    # artefact), not a byte-compared artefact here. If a later subphase derives a pure aggregate from
    # it, that aggregate is what belongs in this list.
    #
    # Phase 24.7's **runtime/functional atlas follows the same precedent, for the same reason and one
    # more.** It is measurement -- real builds and real local workloads inside the court container --
    # so the level a run reaches and its normalised transcript are a function of the court's toolchain
    # and of the network, not of committed inputs; a CI runner has no compiler, no prefix and no
    # loopback peer for the workloads, and the Docker-only guard refuses a host invocation before it
    # builds or launches anything. It also carries a per-run transcript digest that is a measurement,
    # not a derivation. The raw measurement is the court's business (`RT-RUNTIME-FUNCTIONAL-ATLAS`
    # re-runs only its pure checks over the committed artefact), exactly as the Phase-17 measured
    # corpus and 24.6's atlas are. A later subphase that derives a pure aggregate from it (the
    # failure minimisation, the reconciliation) is what belongs in this list.
    #
    # Phase 24.9's high-value deep tier and **Phase 24.10's hostility-augmentation corpus follow the
    # same precedent, for the same reason.** Both are measurement: the tier re-runs the Phase-17
    # build harnesses for Git and CPython, and the hostility corpus compiles a bounded set of rare-
    # surface probes (custom BIO, legacy ENGINE, provider config, the error queue, layout,
    # fork/reinit, threading, dlopen, PKCS#12, CMS, cross-implementation TLS, static) against each
    # subject and runs them locally, so the level a run reaches and its normalised transcript are a
    # function of the court's toolchain and of the network, not of committed inputs. A CI runner has
    # no compiler, no install prefix and no loopback TLS peer, and the Docker-only guard refuses a
    # host invocation before either builds anything. Neither artefact is listed here; their courts
    # (`RT-HIGH-VALUE-TIER`, `RT-HOSTILITY-AUGMENTATION`) re-run only their pure selection/checks
    # over the committed artefacts. 24.10 is a **separate** corpus, but that changes nothing about
    # how it is regenerated: it is still measurement, and a later subphase that derives a pure
    # aggregate from it is what would belong in this list.
    #
    # Phase 24.11's candidate freeze follows the same precedent, for the same reason and one more. It
    # re-runs the precommitted holdout against the frozen candidate using the exact 24.6/24.7
    # recipe/workload machinery, so the level a run reaches, its normalised transcript and the
    # candidate install's digests at the moment of the run are a measurement. It also carries an
    # **immutable first_run** that a re-run must never overwrite (a rerun is appended, not folded in),
    # so regenerating it is a deliberate act, not a byte-compare. It is therefore not listed here; the
    # `RT-CANDIDATE-FREEZE` court re-runs only its pure checks -- the identity re-derivation from the
    # committed install, the precommitted-set check, the first_run immutability (every rerun attests
    # the recorded first_run), the verdict re-derivation and the fix-source check -- over the
    # committed artefact.
    #
    # Phase 24.12's final P1000 run follows the same precedent, for the same reason: it re-runs the
    # whole frozen population under both subjects against the frozen candidate using the exact
    # 24.6/24.7 recipe/workload machinery, so the level a run reaches and its normalised transcript
    # are a measurement, not a function of committed inputs -- a CI runner has no compiler, no install
    # prefix and no network, and the Docker-only guard refuses a host invocation before it builds
    # anything. It is therefore not listed here and not in `COMPARED`; the `RT-P1000-RUN` court
    # re-runs only its pure checks -- the identity re-derivation from the committed install and its
    # equality with the 24.11 freeze, the one-verdict-per-counted-family re-derivation, the section-20
    # PASS refusal, the UNKNOWN-is-zero check, the ladder and the counts -- over the committed
    # artefact.
    #
    # Phase 25.1's **compiler-backed source census follows the same precedent, for the same reason.**
    # `forensics/tools/ms_census.py` produces `artifacts/phase25/source-census.json` by measurement --
    # one clippy run with the built-in `unsafe_code` lint (plus the three named documentation lints)
    # and a pinned-nightly `-Zunpretty=expanded` -- so its unsafe contexts, compiler-derived sites
    # and LOC projection are a function of the court's exact toolchain and of the network, not of
    # committed inputs. A CI runner has no compiler and no pinned nightly, and the Docker-only guard
    # refuses a host invocation of `ms_census.py` before it runs anything. It is therefore not listed
    # here and not in `COMPARED`; the `MS-SOURCE-CENSUS` court re-runs only its pure checks
    # (`ms_census.census_findings` and `ms_census.census_sensitivity_control`) over the committed
    # artefact. If a later subphase derives a pure aggregate from the census, that aggregate is what
    # belongs in this list.
    #
    # **Phase 25.2's non-Rust trusted computing base (`forensics/tools/ms_non_rust_tcb.py` ->
    # `artifacts/phase25/non-rust-tcb.json`) follows the same precedent, for the same reason.** It
    # inventories the first-party C the crate compiles by compiling every adapter under
    # `-std=c11 -Wall -Wextra -Werror` and running `nm` for the object's symbol sets, and it scans
    # `src` for the extern blocks and the `core::arch` intrinsics -- so its rows are a function of the
    # court's exact C toolchain and its read of the crate, not of committed inputs, and it also
    # carries the 25.1 census's FFI site ids as a cross-reference. A CI runner has no C compiler and
    # no `nm`, and the Docker-only guard refuses a host invocation of `ms_non_rust_tcb.py` before it
    # runs anything. It is therefore not listed here and not in `COMPARED`; the `MS-NON-RUST-TCB`
    # court re-runs only its pure checks (`ms_non_rust_tcb.non_rust_findings` and
    # `ms_non_rust_tcb.non_rust_sensitivity_control`) over the committed artefact and the on-disk file
    # universe. If a later subphase derives a pure aggregate from this inventory, that aggregate is
    # what belongs in this list.
    #
    # **Phase 25.3's safety obligations (`forensics/tools/ms_obligations.py` ->
    # `artifacts/phase25/safety-obligations.json`) are a pure function of committed inputs, so they
    # belong here and are byte-compared.** The plane binds every compiler-derived unsafe site of the
    # 25.1 census to a grouped contract whose per-dimension obligations follow from the operation-kind
    # -> dimension rule recorded in the plane and the source-stated contract the census indexed; it
    # runs no compiler and reads no source tree, so `forensics/memory-safety/container.json` lists it
    # `metadata_only` and the Docker-only guard admits it on any host. A stale committed plane -- or a
    # typed count, a dropped site, or a discharge no source-stated contract can establish -- is a
    # failure rather than a silent divergence, and the `MS-SAFETY-OBLIGATIONS` court re-runs the same
    # pure checks over the committed artefact and the census it is derived from.
    "forensics/tools/ms_obligations.py",
    # **Phase 25.4's ownership/allocation/callback planes (`forensics/tools/ms_ownership_planes.py` ->
    # `artifacts/phase25/ownership-planes.json`) are a pure function of committed inputs too, so they
    # belong here and are byte-compared.** The plane classifies the compiler-derived sites of the
    # 25.1 census, the FFI boundaries of the 25.2 TCB and the committed source text (the allocation
    # families, the set/get/up_ref conventions, the callback registrations, the unsafe Send/Sync
    # impls, the globals and the exported bodies) against tables recorded in the plane. It compiles
    # nothing -- no compiler, no tool, no probe -- so `forensics/memory-safety/container.json` lists
    # it `metadata_only` and the Docker-only guard admits it on any host, exactly as `ms_obligations`
    # is. A stale committed plane -- or a typed count, a dropped record, a hidden UNKNOWN panic class
    # or an unmatched FREES edge with no finding -- is a failure rather than a silent divergence, and
    # the `MS-OWNERSHIP-PLANES` court re-runs the same pure checks over the committed artefact, the
    # census, the TCB and the source it classifies.
    "forensics/tools/ms_ownership_planes.py",
    # **Phase 25.5's Phase-22 reachability crosswalk (`forensics/tools/ms_phase22_crosswalk.py` ->
    # `artifacts/phase25/phase22-crosswalk.json`) is a pure function of committed inputs too, so it
    # belongs here and is byte-compared.** It maps every compiler-derived unsafe site of the 25.1
    # census to the OpenSSL public compatibility roots that can reach it, reading the committed
    # Phase-22 reachability atlas (`compatibility-closure.json`), its entity plane
    # (`reconciliation.json`) and the module -> authority-unit correspondence
    # (`transcription-edges.json`, `internal-symbols.json`, `export-defining-units.json`). It
    # compiles nothing -- no compiler, no tool, no probe -- so `forensics/memory-safety/container.json`
    # lists it `metadata_only` and the Docker-only guard admits it on any host, exactly as
    # `ms_ownership_planes` is. A stale committed crosswalk -- or a dropped site, a site mapped to a
    # root the atlas does not reach, an inverse view that disagrees with the site map, an unresolved
    # site defaulted to a root or a re-derived graph -- is a failure rather than a silent divergence,
    # and the `MS-PHASE22-CROSSWALK` court re-runs the same pure checks over the committed artefact,
    # the census and the committed Phase-22 atlas.
    "forensics/tools/ms_phase22_crosswalk.py",
    # **Phase 25.6's Phase-24 downstream crosswalk (`forensics/tools/ms_phase24_crosswalk.py` ->
    # `artifacts/phase25/phase24-crosswalk.json`) is a pure function of committed inputs too, so it
    # belongs here and is byte-compared.** It maps every compiler-derived unsafe site of the 25.1
    # census to the Phase-24 measured consumers that reach it, reading the committed 25.5 crosswalk
    # for the site -> authority-unit resolution, the Phase-22 entity plane for the name index, and
    # the committed Phase-24 downstream measurement (`usage-fingerprints.json`, `reconciliation.json`,
    # `runtime-functional-atlas.json`, `build-link-atlas.json`, `p1000-run.json`,
    # `family-freeze.json`) for the imports, the runtime levels, the clusters and the counted
    # population. It compiles nothing -- no compiler, no tool, no probe -- so
    # `forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard
    # admits it on any host, exactly as `ms_phase22_crosswalk` is. A stale committed crosswalk -- or
    # a typed consumer, a dropped site, a runtime-observed site with no runtime row, an inverse view
    # that disagrees with the forward map or a partial join with no residual -- is a failure rather
    # than a silent divergence, and the `MS-PHASE24-CROSSWALK` court re-runs the same pure checks
    # over the committed artefact, the census and the committed Phase-24 measurement.
    "forensics/tools/ms_phase24_crosswalk.py",
    # **Phase 25.7's exposure/data-flow classification (`forensics/tools/ms_exposure.py` ->
    # `artifacts/phase25/exposure.json`) is a pure function of committed inputs too, so it belongs
    # here and is byte-compared.** It gives every compiler-derived unsafe site of the 25.1 census
    # exactly one class from the closed exposure vocabulary, reading the committed 25.5 crosswalk
    # for the authority unit and public roots, the committed 25.6 crosswalk for the downstream
    # state, the committed 25.4 ownership planes for the manual allocation sites, and the census's
    # own file/module context; the attacker-input routes and the buffer-operation census follow from
    # the same committed parser identities. It compiles nothing -- no compiler, no tool, no probe --
    # so `forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard
    # admits it on any host, exactly as `ms_phase24_crosswalk` is. A stale committed classification
    # A stale committed classification
    # -- or a dropped site, a remote class with no justification, an attacker route with no path, an
    # inverse view that disagrees, a boundary plan marked executed, a typed count or an
    # unknown-reachability site assigned the non-exposed tier S0 (an unknown is tier SU) -- is a
    # failure
    # rather than a silent divergence, and the `MS-EXPOSURE-CLASSIFICATION` court re-runs the same
    # pure checks over the committed artefact and the committed planes it is derived from.
    "forensics/tools/ms_exposure.py",
    # **Phase 25.8's unsafe reduction (`forensics/tools/ms_reduction.py` ->
    # `artifacts/phase25/unsafe-reduction.json`) is a pure function of committed inputs too, so it
    # belongs here and is byte-compared.** It is a pure derivation because this venue applies **no**
    # reduction: the worklist is a local-replacement feasibility census, not an impossibility result
    # -- none of the reachable operations screened against the ten local-substitution patterns was
    # locally replaceable without changing the public surface or behaviour (each candidate
    # replacement would change a signature or the foreign ABI, turn a documented precondition the
    # authority states into a defined panic, or remove no site at all), which is not a claim that the
    # rest of the core is irreducible -- so the census is unchanged and the tool runs no compiler. It
    # reads the committed 25.1 census, the committed 25.7 exposure
    # classification and the committed source spans the census names; `forensics/memory-safety/
    # container.json` lists it `metadata_only` and the Docker-only guard admits it on any host,
    # exactly as `ms_exposure` is. Had a reduction been applied, re-running the compiler census would
    # have been required and the tool would have followed the `ms_census.py` measurement precedent
    # instead of this list. A stale committed worklist -- or a dropped candidate class, a typed count,
    # an applied reduction with no test evidence, a weakened lint or a frozen census that disagrees
    # with the live census -- is a failure rather than a silent divergence, and the
    # `MS-UNSAFE-REDUCTION` court re-runs the same pure checks over the committed artefact, the census
    # and the exposure classification.
    "forensics/tools/ms_reduction.py",
]
GENERATORS_AFTER_LEDGERS = [
    # The court coverage atlas (D199). It consumes the ledgers and the staged court
    # results, and `phase_state.py` consumes *it*, so it sits first in this block. It
    # is listed here so a stale committed copy is a failure and not a silent
    # divergence -- the whole point of the atlas is that the coverage claim is a fact a
    # reader can recompute.
    "forensics/tools/court_coverage.py",
    "forensics/tools/ownership_audit.py",
    "forensics/tools/prototype_court.py",
    # The provider dispatch plane (D180). It reads only the atlas's `macros.json` and
    # `typedefs.json` and the crate's sources, so it has no position dependence beyond
    # being after the surface it does not consume; it is listed here so that a stale
    # committed copy is a failure rather than a silent divergence.
    "forensics/tools/dispatch_court.py",
    # The divergence register's machine-readable form. It is listed so that a stale committed
    # copy is a failure and not a silent divergence: `phase_state.py` refuses to derive any
    # state without it, and the whole point of the file is that a triggered obligation cannot
    # be outrun by a derived `complete`, so a generator nothing re-runs would reintroduce
    # exactly that. It sits before `phase_state.py`, which consumes *it*.
    "forensics/tools/divergence_obligations.py",
    # Phase 23.14's security lineage. It is a pure function of the committed source snapshot, the
    # release catalogue, the default-authority alias, the divergence register and the negative
    # obligations plane, so a stale committed plane -- or a typed disposition, a hand-listed fix or
    # a re-adopted vulnerable behaviour -- is a failure rather than a silent divergence. It records
    # the divergence register's own hash as evidence, so it must run **after**
    # `divergence_obligations.py` (the court's content-addressing check reads the recorded hash back
    # against that file); it also supplies the `security_backport` lineage edges `authority_catalog.py`
    # merges, which stays a one-run lag exactly as the ledgers' own inputs do. The RT-SECURITY-LINEAGE
    # court re-derives the whole plane through the same generator and re-reads every cited evidence
    # path.
    "forensics/tools/security_lineage.py",
    # Phase 23.16's assembled compatibility matrix (D546). It is a pure function of the five
    # committed planes -- the compatibility views, the directional edges, the negative obligations,
    # the security lineage and the support-status ladder -- so a stale matrix, or a verdict that was
    # typed rather than joined, is a failure rather than a silent divergence. It reads the security
    # lineage, which this block generates just above, so it sits after it; it needs no authority and
    # no compiler. The RT-COMPATIBILITY-MATRIX court re-derives the whole matrix through the same
    # generator, re-reads every source record a cell references, and refuses a cell that contradicts
    # the plane it joins.
    "forensics/tools/compat_matrix.py",
    "forensics/tools/phase_state.py",
    # The prerequisite gate reads the phase states to decide whether a stratum has
    # sealed, so it sits after `phase_state.py` rather than beside it. It needs no
    # authority: the one authority-derived artefact it consumes is
    # `transcription-edges.json`, which `gen_prerequisite_atlas.py` generates in the
    # court job and which is committed for exactly this reason (D123).
    "forensics/tools/prerequisite_gate.py",
    # The plan-versus-crate reconciliation (D134). It sits beside the gate and for the same
    # reason: it reads `phase-state.json` to decide which strata are claiming, so it must run
    # after `phase_state.py`. The pair is deliberately adjacent in this list, because the two
    # answer the two halves of one question -- the gate asks whether every name the crate
    # *references* has an owner, and this asks whether every unit the plan *promises* is
    # reached -- and D132 was the case that fell between them.
    "forensics/tools/plan_reconciliation.py",
    # Phase 24.16's biggest-mover report generator. It is a pure function of the committed analysis
    # `forensics/downstream/shared-blockers.json` -- it renders `docs/PHASE-24-BIGGEST-MOVERS.md` and
    # the marker-bounded `downstream-blockers` block in `README.md` -- so a hand-edited summary, a
    # dropped marker or a report line that no longer matches the analysis is a failure rather than a
    # silent divergence. It executes nothing and reads no ledger; the RT-BLOCKER-LEVERAGE court
    # re-renders both from the committed analysis and requires them to reproduce and cross-link. It
    # sits before `render_seal_census.py`, which cites its section, and after the analysis it reads.
    "forensics/tools/render_biggest_movers.py",
    "forensics/tools/render_seal_census.py",
    "forensics/tools/render_status.py",
    # The Phase 8 remainder projection (docs/PHASE-8-REMAINING.md). It reads the Phase 8
    # obligation ledger the block above just wrote, so it sits after the ledgers rather
    # than before them, and it is listed here so a stale committed copy is a failure
    # rather than a silent divergence -- the document exists to answer a planning
    # question about what is left of the stratum, and a copy nothing re-runs would drift
    # from the ledger it projects.
    "forensics/tools/phase8_remaining.py",
    # The Phase 17 downstream corpus and its generated prose. Both are pure functions of the
    # measured records under `courts/phase17/downstream/<program>/result.json`, which the driver
    # `courts/phase17/downstream/run_all.sh` writes; listing them here is what makes a stale
    # committed corpus or `EVIDENCE.md` a failure rather than a silent divergence. They need no
    # authority and no container.
    "courts/phase17/downstream/lib/build_corpus.py",
    "forensics/tools/gen_downstream_evidence.py",
    # Phase 24.14's FRF/Gemel closure. It executes nothing -- it drives each Phase-24 plane's own
    # pure `*_findings`/`*_sensitivity_control` over the committed artefact, records the per-mutation
    # delta, and derives the FRF chain staging and the Gemel checkpoint projection from the committed
    # `gen_frf_courts.py` registry and the committed `forensics/GEMEL_TRAJECTORY.md`. It sits after
    # the ledgers because it reads the Phase-24 planes (several of them regenerated in the
    # before-ledgers block) and none of them reads it; the RT-FRF-CLOSURE court re-runs the same pure
    # functions over the committed artefact.
    "forensics/tools/phase24_frf.py",
]


def phase_ledgers() -> list[tuple[str, str]]:
    """`(generator, artefact)` for every stratum's obligation ledger on disk."""
    out: list[tuple[str, str]] = []
    for path in sorted((REPO_ROOT / "forensics" / "tools").glob("phase*_obligations.py")):
        m = re.fullmatch(r"phase(\d+)_obligations\.py", path.name)
        if m is None:
            continue
        out.append((rel(path), f"forensics/phase{m.group(1)}-obligations.json"))
    if not out:
        raise SystemExit(
            "[evidence-determinism] no forensics/tools/phase<N>_obligations.py found, "
            "which cannot be right"
        )
    return out


LEDGERS = phase_ledgers()
GENERATORS = (
    GENERATORS_BEFORE_LEDGERS
    + [g for g, _a in LEDGERS]
    + GENERATORS_AFTER_LEDGERS
)

# The hand-written-document consistency gate (`forensics/tools/docs_consistency.py`,
# docs/DECISIONS.md D203). It writes no artefact and compares no artefact: it asserts that
# the prose in the audited documents does not contradict the generated evidence, which is
# the one staleness `evidence_determinism.py` cannot see because the prose is not a
# generator's output. It is a separate registry rather than an entry in `GENERATORS` for a
# reason: a generator whose output nothing compares would be a silent no-op here, whereas
# this tool's whole job is to fail. It is listed at all so that `check_evidence_portability.py`
# exercises it under the binutils stubs through the same mechanism as the generators -- a
# gate that needed the host's `nm` would not be evidence either.
CHECKS = [
    "forensics/tools/docs_consistency.py",
]

# Derived artefacts that are compared. Anything not listed is not this tool's
# business (court transcripts, staged probe binaries and the ABI shell are
# produced by the court venue, not by these generators).
COMPARED = [
    "forensics/atlas/symbol-ownership.json",
    "forensics/atlas/implemented-surface.json",
    "forensics/atlas/court-coverage.json",
    "forensics/atlas/ownership-audit.json",
    "forensics/atlas/prototype-court.json",
    "forensics/atlas/dispatch-court.json",
    "forensics/atlas/unsafe-footprint.json",
    "forensics/atlas/ctype-table.json",
    "forensics/atlas/err-raise-sites.json",
    "forensics/atlas/bn-primes.json",
    "forensics/atlas/prerequisite-gate.json",
    "forensics/atlas/plan-reconciliation.json",
    *[a for _g, a in LEDGERS],
    "forensics/divergence-obligations.json",
    "forensics/phase-state.json",
    "forensics/phase-state.md",
    "docs/SEAL-CENSUS.md",
    "docs/PHASE-8-REMAINING.md",
    "forensics/STATUS.md",
    # Not a JSON artefact and not written by a generator that reads the atlas: it is
    # emitted by `gen_ctype_table.py` above, so it is compared in the same pass. It
    # is listed here rather than in the atlas because a `cargo`-visible source file
    # being stale is the failure this catches.
    "src/runtime/ctype_table.rs",
    # The same argument for the error-coordinate plane, and the one D109 left open: a
    # `cargo`-visible file generated from the authority was in neither this list nor the
    # generator list, so it could drift from the atlas without anything noticing.
    "src/runtime/err_sites.rs",
    # Phase 8.5's named-group constants (D332), for the same reason as the two above and
    # `src/bn/dh_data.rs`, for the same reason as the two above and
    # with one extra property the other generated `.rs` files do not need: this file's
    # renderer is **`rustfmt`-stable**, so `pipeline.sh` may run it before `cargo fmt`
    # without the formatter moving a byte. That is what lets it be compared here at all,
    # and why the two Phase 8 table generators below are deliberately not.
    "src/bn/dh_data.rs",
    # Phase 8.7's built-in curve parameters (D334), the same argument again: a `cargo`-visible
    # file generated from the authority, whose renderer is `rustfmt`-stable, so a formatter pass
    # cannot move it. It is 75 `EC_CURVE_DATA` structures and `curve_list[]`'s eighty-two rows.
    "src/ec/curve_data.rs",
    # The Phase 17 downstream corpus and the prose generated from it. The records themselves are
    # measurement, not generator output, so they are the court's business (RT-DOWNSTREAM-CORPUS);
    # the aggregate and the EVIDENCE.md/README.md built from them are compared here so prose
    # cannot drift from the recorded measurement.
    "forensics/atlas/downstream-corpus.json",
    "courts/phase17/downstream/README.md",
    *[f"courts/phase17/downstream/{p}/EVIDENCE.md"
      for p in ("curl", "git", "haproxy", "nginx", "openssh", "python")],
    # Phase 18.1's hostile TLS corpus manifest: the entries and their per-entry sha256, which the
    # court's `RT-HOSTILE-TLS` row records as the corpus's provenance. The `.bin` fixtures
    # themselves are binary and are re-derived by the generator above and re-verified by the
    # court, so the compared artefact is the manifest that pins them.
    "courts/phase18/fixtures/hostile-tls/MANIFEST.json",
    # Phase 18.2's hostile X.509 / malformed-input corpus manifest: the entries, their per-entry
    # sha256 and the provenance of the four fixed Phase 17 base objects the corpus mutates. The
    # `.bin` fixtures are re-derived by the generator above and re-verified by the court, so the
    # compared artefact is the manifest that pins them.
    "courts/phase18/fixtures/hostile-x509/MANIFEST.json",
    # Phase 23.1's release catalogue and its typed lineage: pure functions of the committed
    # `forensics/multitrack/release-archaeology.json`, so a stale committed copy is a failure and
    # not a silent divergence -- the whole point of deriving the catalogue rather than typing it
    # is defeated by a generator nothing re-runs.
    "forensics/release-catalog.json",
    "forensics/authority-lineage.json",
    # Phase 23.3's parameterization receipt and the historical authorities' plane censuses: pure
    # functions of the committed default-authority alias and the committed source manifests, so a
    # stale copy is a failure and not a silent divergence.
    "forensics/atlas/parameterization-receipt.json",
    *[rel(p) for p in sorted((REPO_ROOT / "forensics" / "atlas").glob(
        "openssl-*-historical/plane-census.json"))],
    # Phase 23.5's entity lineage: what became of each public entity across the covered release
    # pair, a pure function of the committed declaration and symbol planes, so a stale copy is a
    # failure and not a silent divergence.
    "forensics/multitrack/entity-lineage.json",
    # Phase 23.6's canonical edge deltas: the semantic compatibility delta over the release-graph
    # edges, a pure function of the committed atlases and the entity lineage. Every committed edge
    # delta is compared -- the artefact set is the canonical edges, never their pairwise product --
    # so a stale copy is a failure and not a silent divergence.
    *[rel(p) for p in sorted((REPO_ROOT / "forensics" / "deltas").glob("*.json"))],
    # Phase 23.7's generated repr(C) façades and their compile-time layout assertions. A
    # cargo-visible generated file regenerated from the committed measurement, so a hand edit or a
    # measurement drift is a failure rather than a silent divergence. The measurement itself
    # (`forensics/multitrack/abi-facades.json`) is a historical-venue measurement, compared by the
    # RT-ABI-HISTORY-FACADES court against its provenance rather than regenerated here.
    "src/compat/layout_generated.rs",
    # Phase 23.8's normalized oracle-to-oracle observations and the raw transcripts they were
    # re-derived from. A pure function of those preserved raw bytes and the committed 23.6 delta, so
    # a hand edit to a normalized reading or a classification is a failure rather than a silent
    # divergence -- which is exactly the erasure the court's sensitivity control injects.
    "forensics/multitrack/semantic-courts.json",
    # Phase 23.9's compatibility views: a pure function of each authority's own committed evidence,
    # so a stale committed plane -- or a view relayed from another authority -- is a failure rather
    # than a silent divergence.
    "forensics/multitrack/compatibility-views.json",
    # Phase 23.12's compatibility edges: a pure function of the committed edge delta, the entity
    # lineage, the compatibility views and the Phase-2 ABI courts, so a stale plane -- or an edge
    # whose verdict is not established by its evidence -- is a failure rather than a silent
    # divergence.
    "forensics/multitrack/compatibility-edges.json",
    # Phase 23.13's negative and positive obligations: a pure function of the committed censuses,
    # ABI/history façades, edge deltas and symbols planes, so a stale plane -- or an obligation
    # whose state was not read from its evidence -- is a failure rather than a silent divergence.
    "forensics/multitrack/negative-obligations.json",
    # Phase 23.14's security lineage: a pure function of the frozen source snapshot, the release
    # catalogue, the default-authority alias, the divergence register and the negative obligations
    # plane, so a stale plane -- or a typed disposition, a hand-listed fix or a re-adopted
    # vulnerable behaviour -- is a failure rather than a silent divergence. The source snapshot
    # itself (`forensics/multitrack/security-source.json`) is an acquisition, not a derivation, so
    # it is the input this plane binds rather than an artefact compared here.
    "forensics/multitrack/security-lineage.json",
    # Phase 23.10's historical population: a pure function of the committed catalogue, authority
    # nodes, receipts, atlases, compatibility views and semantic pair, so a stale record or a typed
    # status is a failure rather than a silent divergence.
    "forensics/multitrack/historical-population.json",
    # Phase 23.15's support-status ladder: a pure function of the 23.10 population, so a stale row, a
    # typed status or a row that disagrees with its population record is a failure rather than a
    # silent divergence.
    "forensics/multitrack/support-status.json",
    # Phase 23.16's assembled compatibility matrix: a pure function of the five committed planes, so a
    # stale cell, a typed verdict or a cell that contradicts the plane it joins is a failure rather
    # than a silent divergence. Every cell references its source records rather than restating them,
    # so the matrix cannot drift from the planes it joins.
    "forensics/multitrack/compatibility-matrix.json",
    # Phase 23.11's downstream multitrack court: a pure function of the committed artefact's own
    # preserved raw outputs, so a stale record or a hand-typed outcome is a failure rather than a
    # silent divergence. The raw build/run outputs are carried inside the artefact, which is why the
    # re-derivation needs no compiler, no network and no authority prefix.
    "forensics/multitrack/downstream-multitrack.json",
    # Phase 24.4's frozen P1000 + reserve: a pure function of the committed 24.2 families and the
    # frozen 24.1 ranking evidence, so a stale population, or one re-selected by something other than
    # the recorded rule, is a failure rather than a silent divergence. It carries no candidate result
    # (the freeze precedes every candidate run), which is why re-deriving it needs no compiler and no
    # candidate.
    "forensics/downstream/family-freeze.json",
    # Phase 24.16's biggest-mover shared-blocker analysis: a pure function of the committed Phase-24
    # planes, so a stale analysis -- or a blocker, a count, the funnel or the recipe queue typed
    # rather than re-derived -- is a failure rather than a silent divergence. It reads no ledger.
    "forensics/downstream/shared-blockers.json",
    # Phase 24.17's preserved pre-remediation baseline and the before/after record derived from it:
    # the baseline is the 24.16 partition captured once, and the record re-derives the re-measured
    # `after` from the planes, so a stale record -- or a movement figure typed rather than subtracted
    # -- is a failure rather than a silent divergence.
    "forensics/downstream/blocker-remediation-baseline.json",
    "forensics/downstream/blocker-remediation.json",
    # Phase 24.18's preserved pre-campaign baseline and the admission record derived from it: the
    # baseline is the 24.17-state blocker summary captured once, and the record re-derives the
    # re-measured `after` from the planes, so a stale record -- or a movement figure typed rather than
    # subtracted -- is a failure rather than a silent divergence.
    "forensics/downstream/recipe-campaign-baseline.json",
    "forensics/downstream/recipe-campaign.json",
    # Phase 24.19's preserved pre-batch baseline and the close-candidate reclamation record derived
    # from it: the baseline is the 24.18-state blocker summary captured once, and the record re-derives
    # the re-measured `after` from the planes, so a stale record -- or a movement figure typed rather
    # than subtracted -- is a failure rather than a silent divergence.
    "forensics/downstream/close-batch-baseline.json",
    "forensics/downstream/close-batch.json",
    # The detailed report 24.16 renders from `shared-blockers.json`, byte-compared so its prose
    # cannot drift from the analysis it cites. The marker-bounded `downstream-blockers` block of
    # `README.md` is compared in the same pass.
    "docs/PHASE-24-BIGGEST-MOVERS.md",
    "README.md",
    # Phase 24.5's precommitted development/holdout partition: a pure function of the committed 24.4
    # frozen P1000 (and the committed 24.2 families it re-checks), so a stale split, or one
    # re-divided by something other than the recorded rule, is a failure rather than a silent
    # divergence. It carries no candidate result (the split is fixed before any candidate run), which
    # is why re-deriving it needs no compiler and no candidate.
    "forensics/downstream/holdout.json",
    # Phase 24.8's classified, preserved, minimized failures: a pure function of the committed 24.6
    # build/link atlas, the 24.7 runtime/functional atlas and the 24.4 frozen P1000, so a stale plane,
    # a fabricated record, a candidate-specific label the authority baseline does not justify or an
    # unclassified leftover is a failure rather than a silent divergence. The minimized fixtures it
    # references are re-hashed from disk by the RT-FAILURE-MINIMIZATION court, so a fixture drifting
    # from its record fails the court rather than passing here.
    "forensics/downstream/failures.json",
    # Phase 24.13's reconciliation of the atlas: a pure function of every committed Phase-24 plane
    # (and the Phase-22 denominators), so a stale accounted view -- or a rate, a residual
    # classification or a failure summary that was typed rather than re-derived -- is a failure rather
    # than a silent divergence. It carries no measurement (it executes nothing and reads nothing that
    # moves), which is why re-deriving it needs no compiler, no prefix and no network.
    "forensics/downstream/reconciliation.json",
    # Phase 24.14's FRF/Gemel closure: the per-plane FRF challenges, the FRF chain staging and the
    # Gemel checkpoint projection. A pure function of the committed Phase-24 planes, the committed
    # `gen_frf_courts.py` registry and the committed `forensics/GEMEL_TRAJECTORY.md`, so a stale
    # challenge delta, a chain record that no longer matches the registry, or a Gemel current
    # checkpoint that moved is a failure rather than a silent divergence. It executes no probe and
    # opens no store.
    "forensics/atlas/phase24/frf-closure.json",
    # Phase 25.3's safety obligations: a pure function of the committed 25.1 census and 25.2 non-Rust
    # TCB and the operation-kind -> dimension rule the plane records, so a stale plane -- or a typed
    # count, a dropped site, or a `discharged` obligation no source-stated contract can establish --
    # is a failure rather than a silent divergence. It executes nothing and reads no source tree, so
    # re-deriving it needs no compiler and no authority.
    "artifacts/phase25/safety-obligations.json",
    # Phase 25.4's ownership/allocation/callback planes: a pure function of the committed 25.1
    # census, the committed 25.2 non-Rust TCB and the committed source text it classifies against the
    # tables the plane records, so a stale plane -- or a typed count, a dropped record, a hidden
    # UNKNOWN panic class or an unmatched `FREES` edge with no finding -- is a failure rather than a
    # silent divergence. It compiles nothing and reads no authority, so re-deriving it needs no
    # compiler and no candidate.
    "artifacts/phase25/ownership-planes.json",
    # Phase 25.5's Phase-22 reachability crosswalk: a pure function of the committed 25.1 census and
    # the committed Phase-22 reachability atlas (its closure, its entity plane and the module ->
    # authority-unit correspondence), so a stale crosswalk -- or a dropped site, a site mapped to a
    # root the atlas does not reach, an inverse view that disagrees with the site map, an unresolved
    # site defaulted to a root or a re-derived graph -- is a failure rather than a silent divergence.
    # It executes nothing and reads no compiler output, so re-deriving it needs no compiler and no
    # candidate.
    "artifacts/phase25/phase22-crosswalk.json",
    # Phase 25.6's Phase-24 downstream crosswalk: a pure function of the committed 25.1 census, the
    # committed 25.5 crosswalk and the committed Phase-24 downstream measurement (the usage
    # fingerprints, the reconciliation clusters, the runtime and build/link atlases, the drop-in run
    # and the family freeze), so a stale crosswalk -- or a typed consumer, a dropped site, a
    # runtime-observed site with no runtime row, an inverse view that disagrees with the forward map
    # or a partial join with no residual -- is a failure rather than a silent divergence. It executes
    # nothing and reads no compiler output, so re-deriving it needs no compiler and no candidate.
    "artifacts/phase25/phase24-crosswalk.json",
    # Phase 25.7's exposure/data-flow classification: a pure function of the committed 25.1 census,
    # the committed 25.5 crosswalk, the committed 25.6 crosswalk and the committed 25.4 ownership
    # planes. A dropped site, a remote class with no justification, an attacker route with no path,
    # an inverse view that disagrees, a boundary plan marked executed or a typed count is a failure
    # rather than a silent divergence. It executes nothing and reads no compiler output, so
    # re-deriving it needs no compiler and no candidate.
    "artifacts/phase25/exposure.json",
    # Phase 25.8's unsafe reduction: a pure function of the committed 25.1 census, the committed 25.7
    # exposure classification and the committed source spans the census names. It applies no
    # worklist reduction -- the worklist is a local-replacement feasibility census, not an
    # impossibility result: no reachable operation screened against the ten local-substitution
    # patterns was locally replaceable without changing the public surface or behaviour, which is not
    # a claim that the rest of the core is irreducible -- so the census is unchanged and it runs no
    # compiler. A dropped candidate
    # class, a typed count, an applied reduction with no test evidence, a weakened lint, a reduced
    # site still present or a frozen census that disagrees with the live census is a failure rather
    # than a silent divergence. It executes nothing and reads no compiler output, so re-deriving it
    # needs no compiler and no candidate.
    "artifacts/phase25/unsafe-reduction.json",
]

# ---------------------------------------------------------------------------
# The declared build-product surface. Nothing outside this set is normalised.
# ---------------------------------------------------------------------------

NORMALISED_DIGEST = "<build-product-digest-normalised>"
NORMALISED_COUNT = "<build-product-count-normalised>"

# `inputs[]` entries whose `sha256` is a build product, by entry name.
BUILD_PRODUCT_INPUT_NAMES = frozenset({"crate-archive", "extra-object"})

# A compared artefact may itself be an input of another compared artefact --
# `ownership-audit.json` records the hash of `implemented-surface.json`, which it
# reads. That recorded hash cannot be compared exactly on any machine whose
# toolchain produces a different crate archive, because the *artefact* being
# hashed contains the declared build-product fields. Measured: the CI runner's
# `ownership-audit.json` input hash for `implemented-surface.json` differed while
# `implemented-surface.json` itself compared equal modulo normalisation.
#
# The binding is redundant rather than lost: the inner artefact is compared
# directly, so a substantive change to it fails on its own account before the
# outer artefact's input hash is even reached. What is blanked is a hash that
# could only ever match modulo a normalisation the inner artefact already
# declares.
COMPARED_INPUT_PATHS = frozenset(COMPARED)

# `body.internal_symbols.<field>` values that are build products, by field name.
BUILD_PRODUCT_SYMBOL_FIELDS = ("compiler_emitted_count",)

# How many differences to print before truncating. Enough to diagnose, bounded
# so a wholesale drift does not produce an unreadable wall of text.
MAX_REPORTED_DIFFERENCES = 12


def normalise(doc: object, fired: set[str]) -> object:
    """Blank the declared build-product fields, recursively.

    Returns a copy, so the caller's document is untouched. A JSON string is
    returned unchanged (used for the Markdown artefacts). `fired` accumulates the
    names of the normalisations that actually applied, so the exception is
    reported rather than silent.
    """
    if isinstance(doc, str):
        return doc
    if isinstance(doc, list):
        return [normalise(x, fired) for x in doc]
    if not isinstance(doc, dict):
        return doc
    out: dict = {}
    for k, v in doc.items():
        if k == "inputs" and isinstance(v, list):
            new_inputs = []
            for entry in v:
                if isinstance(entry, dict) and entry.get("name") in BUILD_PRODUCT_INPUT_NAMES:
                    fired.add(f"inputs[name={entry.get('name')}].sha256")
                    entry = {**entry, "sha256": NORMALISED_DIGEST}
                elif isinstance(entry, dict) and entry.get("path") in COMPARED_INPUT_PATHS:
                    fired.add(f"inputs[path={entry.get('path')}].sha256")
                    entry = {**entry, "sha256": NORMALISED_DIGEST}
                new_inputs.append(normalise(entry, fired))
            out[k] = new_inputs
        elif k == "internal_symbols" and isinstance(v, dict):
            sub = dict(v)
            for field in BUILD_PRODUCT_SYMBOL_FIELDS:
                if field in sub:
                    fired.add(f"internal_symbols.{field}")
                    sub[field] = NORMALISED_COUNT
            out[k] = normalise(sub, fired)
        else:
            out[k] = normalise(v, fired)
    return out


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def differences(a: object, b: object, path: str = "",
                found: list[str] | None = None) -> list[str]:
    """Every structural difference, as readable `path: detail` strings.

    Reporting *all* of them, not just the first, is deliberate: a gate that names
    only the first divergence costs its reader a regeneration cycle per hidden
    one.
    """
    if found is None:
        found = []
    if len(found) >= MAX_REPORTED_DIFFERENCES:
        return found
    if type(a) is not type(b):
        found.append(f"{path or '<root>'}: {type(a).__name__} vs {type(b).__name__}")
        return found
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                found.append(f"{path}.{k}: only in regenerated")
            elif k not in b:
                found.append(f"{path}.{k}: only in committed")
            else:
                differences(a[k], b[k], f"{path}.{k}", found)
            if len(found) >= MAX_REPORTED_DIFFERENCES:
                break
        return found
    if isinstance(a, list):
        if len(a) != len(b):
            found.append(f"{path}: {len(a)} entries vs {len(b)}")
            only_a = [x for x in a if x not in b][:3]
            only_b = [x for x in b if x not in a][:3]
            if only_a:
                found.append(f"{path}: only in committed, e.g. {only_a}")
            if only_b:
                found.append(f"{path}: only in regenerated, e.g. {only_b}")
            return found
        for i, (x, y) in enumerate(zip(a, b)):
            differences(x, y, f"{path}[{i}]", found)
            if len(found) >= MAX_REPORTED_DIFFERENCES:
                break
        return found
    if a != b:
        ra, rb = repr(a), repr(b)
        if len(ra) > 80:
            ra = ra[:77] + "..."
        if len(rb) > 80:
            rb = rb[:77] + "..."
        found.append(f"{path}: committed {ra} vs regenerated {rb}")
    return found


def artefact_differences(relpath: str, committed_text: str, now_text: str,
                         fired: set[str]) -> list[str]:
    """Differences between a committed and a regenerated artefact, normalised.

    Shared with `check_evidence_portability.py` so that the normalisation policy is
    applied *symmetrically*: a field declared as a build product is not evidence in
    either tool, and every field that **is** evidence must be identical in both. A
    second, drifting comparison policy would be a place for a claim to hide.
    """
    if not relpath.endswith(".json"):
        if committed_text == now_text:
            return []
        return [f"{relpath}: content differs (first line: "
                f"{now_text.splitlines()[:1]})"]
    a = normalise(json.loads(committed_text), fired)
    b = normalise(json.loads(now_text), fired)
    return [f"{relpath}: {d}" for d in differences(a, b)]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the regenerated artefact in place (default: restore)")
    args = ap.parse_args(argv)

    # Snapshot the committed artefacts, then regenerate.
    committed: dict[str, object] = {}
    for relpath in COMPARED:
        p = REPO_ROOT / relpath
        if not p.is_file():
            raise SystemExit(f"[evidence-determinism] missing artefact: {relpath}")
        committed[relpath] = p.read_text(encoding="utf-8")

    for gen in GENERATORS:
        res = subprocess.run([sys.executable, gen], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise SystemExit(
                f"[evidence-determinism] {gen} failed with {res.returncode}:\n"
                f"{res.stdout}\n{res.stderr}")

    # The prose checks run against the freshly regenerated evidence, so a document that
    # contradicts the *current* generator output fails here rather than one release later.
    for check in CHECKS:
        res = subprocess.run([sys.executable, check], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise SystemExit(
                f"[evidence-determinism] {check} failed with {res.returncode}:\n"
                f"{res.stdout}\n{res.stderr}")

    problems: list[str] = []
    fired: set[str] = set()
    for relpath in COMPARED:
        now = (REPO_ROOT / relpath).read_text(encoding="utf-8")
        problems += artefact_differences(relpath, committed[relpath], now, fired)

        if not args.keep:
            (REPO_ROOT / relpath).write_text(committed[relpath], encoding="utf-8")

    if fired:
        print("[evidence-determinism] normalised declared build-product fields: "
              + ", ".join(sorted(fired)))
        print("  a Rust static archive is not byte-reproducible across build "
              "environments, and the archive's compiler-emitted symbol population "
              "is a property of the toolchain;")
        print("  every other field is compared exactly "
              "(docs/DECISIONS.md D30, D33).")

    if problems:
        print(f"[evidence-determinism] FAIL: {len(problems)} stale artefact(s)")
        for p in problems:
            print(f"  STALE: {p}")
        print("  Regenerate and commit: the generators are the source of truth.")
        return 1

    print(f"[evidence-determinism] ok: {len(COMPARED)} artefact(s) reproduce "
          f"from their generators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
