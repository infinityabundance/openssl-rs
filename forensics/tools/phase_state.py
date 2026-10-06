#!/usr/bin/env python3
"""openssl-rs — derive phase states from evidence.

Phase status must never be typed, least of all inside a renderer. This tool
computes each stratum's state from artefacts that either exist or do not, and
emits:

    forensics/phase-state.json
    forensics/phase-state.md

The transition rule is executable policy, not prose:

    a phase may be `complete` only if every earlier phase is `complete`

so a tidy-looking later phase cannot claim completion while an earlier one is
open. That is exactly the situation Phase 2 is in: its work and exit criteria are
met, but it stays `in-progress` because Phase 1's FRF sensitivity gap is recorded
rather than papered over.

Each phase row carries: the state, the evidence that decided it, the number of
open blocking residuals, and the seal identity when one exists.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    NON_EXPORT_UNITS,
    SEAL_DOCS,
    content_hash,
    envelope,
    rel,
    sha256_file,
    write_json,
    write_text,
    REPO_ROOT,
)
# The register's own derivation, so the sensitivity control below judges a reconstructed row by the
# real rule rather than by a boolean typed into the test. `divergence_obligations` imports only
# `atlas_common`, so this is not a cycle.
from divergence_obligations import derive_blocking  # noqa: E402
# The FRF declaration registry (D58). `phase_state.py` reads it rather than `artifacts/phase<N>/
# COURTS.json` because the two sets differ exactly where this rule must: a reference-basis court
# (`RT-RUNTIME-REF` and its siblings) has a `COURTS.json` row and a staged probe pair but no table
# row, so it is not declarable and must not be required to carry a chain. `docs_consistency.py`
# imports the same table for the manifest counts, so there is one registry.
import gen_frf_courts  # noqa: E402

OUT = REPO_ROOT / "forensics" / "phase-state.json"

# The court coverage atlas (docs/DECISIONS.md D199). A stratum that claims `complete` must
# have every one of its implemented exports in one of the atlas's three sets, or the claim
# "implemented and observed by a differential court" is not machine-checked. The atlas is
# generated before this tool in `court/pipeline.sh`, and it derives the completed strata
# from the ledgers rather than from this file, so there is no cycle.
COVERAGE = "forensics/atlas/court-coverage.json"

# The provider-algorithm census (docs/DECISIONS.md D237). A stratum owns **two** universes: the
# exports it must publish, and the provider *algorithm registration rows* it must publish. The
# second is invisible to every ELF census -- `deflt_ciphers[]` and its siblings are arrays whose
# members no `libcrypto.num` entry names -- so until this rule it participated in no completion
# decision at all. That left the hole the structural review found: a stratum could reach
# `open_in_this_stratum == 0`, every court passing, zero unmatched exports and a seal, while
# publishing two hundred fewer provider rows than the authority, with only the atlas saying so.
# The rule below is generic over `STRATUM_EVIDENCE` rather than special to the stratum that
# happens to be in progress, and it reads the same atlas the census writes.
PROVIDER_ALGORITHMS = "forensics/atlas/provider-algorithms.json"

# The provider-row court-coverage atlas (docs/DECISIONS.md D245): the join that says a row the
# census calls `implemented` is also *observed*. Generated before this tool, from the same census
# and the court probes.
PROVIDER_COVERAGE = "forensics/atlas/provider-court-coverage.json"

# The generated security-divergence register (docs/SECURITY_DIVERGENCE_POLICY.md, made
# machine-readable). `docs/SECURITY_DIVERGENCE_POLICY.md` is the one obligation register in this
# project that was **prose**: its entries carry a `**Trigger:**` -- the condition under which the
# divergence must be revisited or removed -- and nothing machine-checked it, so a stratum could
# derive `complete` while an obligation it owned had had its trigger fire and was still owed.
# `forensics/tools/divergence_obligations.py` now renders each trigger-bearing entry as a row whose
# trigger state is **derived**, not typed: a `trigger_basis: predicate` row reads generated evidence
# through a named predicate, and a `trigger_basis: manual` row's `trigger_satisfied` is `null` and
# blocks while `open` until an `adjudication` records why it has not fired. `divergence_blocking_reason`
# below is the executable half, and it reads the row's derived `blocking` so the rule and the
# artefact cannot disagree. Generated before this tool by the pipeline; if the JSON is absent this
# tool fails closed rather than skipping the rule, because a check that can be silently skipped is
# not a check (see `divergence_blocking_reason`).
DIVERGENCE_OBLIGATIONS = "forensics/divergence-obligations.json"

# The FRF chain rule (docs/RELEASE_GATES.md section 2 items 6, 8 and 10, and
# docs/DECISIONS.md D200/D413/D424/D475). A stratum that has staged FRF courts must carry the
# whole chain those items name: a declaration for every staged court, a receipt and two
# adjudicated challenges for every declaration, one compiled `sensitivity-backed` claim with no
# blockers that covers the receipts, and a Gemel checkpoint whose summary names the stratum and
# the chain. This is generic over `STRATUM_EVIDENCE` for the same reason the coverage and
# provider joins are (D199/D237): the requirement is a property of a stratum's own evidence, not
# of the stratum that happens to be landing, so a later stratum inherits it by existing rather
# than by a reviewer remembering to copy a check.
#
# Every fact is read from the artefact that carries it -- `.frf/` for the FRF objects,
# `artifacts/phase<N>/COURTS.json` and `forensics/frf/courts/` for the declarations, and the
# Git-tracked projection `forensics/GEMEL_TRAJECTORY.md` for the checkpoint summaries, because
# the Gemel binary is not in the court container this runs in. The projection is what makes the
# checkpoint half checkable here; `forensics/tools/render_gemel_trajectory.sh` prints each
# checkpoint's own `gemel show` summary into it for exactly this reason.
FRF_DECLARATIONS = "forensics/frf/courts"
FRF_RECEIPTS = ".frf/receipts"
FRF_CHALLENGES = ".frf/challenges"
FRF_CLAIMS = ".frf/claims"
GEMEL_TRAJECTORY = "forensics/GEMEL_TRAJECTORY.md"

# The authored court-coverage rows, whose `reference_probes` set is the independent record of
# which courts are reference bases rather than differential transcript courts. It is *not*
# `gen_frf_courts.py`, which is the registry the FRF predicate checks.
FRF_COVERAGE_ROWS = "forensics/atlas/court-coverage-rows.json"

# The two axes every runtime court declares (`observables` stdout and exit in its manifest) and
# whose challenge records FRF carries as these `operator` values. A court is not sensitivity-clean
# unless both have been seen to fire on their own axis and to spare the other (D13, D201); one
# axis alone is a green run, not a sensitivity control.
FRF_CHALLENGE_OPERATORS = ("stdout-first-line", "exit-class")

# **The checkpoint clause is waived for the strata whose chains predate the phrase it reads, and
# for nothing else.** Measured in the tree on 2026-10-02 against `forensics/GEMEL_TRAJECTORY.md`:
# the phrase `FRF chain` first appears in a checkpoint summary in `K45` (Phase 8's, "the stratum
# joins the FRF chain with fifteen declarations"); `K48` (Phase 9), `K49` (Phase 10) and `K50`
# (Phase 11) carry it, and no earlier checkpoint does. Strata 3-7 landed or advanced their chains
# before that phrasing, so their closing checkpoints name the stratum but not the chain. The
# waiver is the *checkpoint clause alone*: every other clause below is still measured for a
# grandfathered stratum, so a stratum that loses its declarations, a receipt, a challenge or its
# claim blocks on that loss rather than hiding behind the exemption. The row for each phase is
# the measured reason, not a bare number.
FRF_CHAIN_CHECKPOINT_EXEMPT: dict[int, str] = {
    3: "no checkpoint summary names Phase 3 and the chain; the phrase is used from K45 (Phase 8) onward",
    4: "K7/K8 close the stratum but predate the `FRF chain` phrase (used from K45, Phase 8's, onward)",
    5: "K26 closes the stratum but predates the `FRF chain` phrase (used from K45, Phase 8's, onward)",
    6: "K43 closes the stratum but predates the `FRF chain` phrase (used from K45, Phase 8's, onward)",
    7: "K44 closes the stratum but predates the `FRF chain` phrase (used from K45, Phase 8's, onward)",
}

# The conservation strata, in dependency order (docs/RELEASE_GATES.md §1).
STRATA: list[tuple[int, str, str]] = [
    (0, "constitution", "Constitution, authorities, claim algebra"),
    (1, "archaeology", "Complete archaeology / API / ABI atlas"),
    (2, "distribution-shell", "Distribution / ABI shell"),
    (3, "core-runtime", "Core runtime: allocation, threads, ERR, refcounts, ex_data, stacks, objects"),
    (4, "bio-conf-objects", "BIO + CONF + object database"),
    (5, "bn-asn1-der-pem", "BN + ASN.1 + DER/PEM"),
    (6, "libctx-provider", "OSSL_LIB_CTX + provider core"),
    (7, "evp", "EVP framework"),
    (8, "algorithms", "Native cryptographic primitives"),
    (9, "rand-drbg", "RAND / DRBG + entropy"),
    (10, "key-formats", "Key formats + PKCS + STORE"),
    (11, "x509", "X.509 + verification"),
    (12, "protocol-families", "CMS / OCSP / CMP / CT / TS and remaining libcrypto families"),
    (13, "legacy", "Legacy / deprecated compatibility"),
    (14, "tls-dtls", "TLS / DTLS (libssl)"),
    (15, "quic-ech", "QUIC / ECH and modern SSL surface"),
    (16, "cli-config", "CLI / config / filesystem contract"),
    (17, "downstream", "Downstream replacement court"),
    (18, "hostile-hardening", "Hostile fuzz / security / side-channel hardening"),
    (19, "performance", "Performance / CPU dispatch"),
    (20, "custodian-seal", "3.6.4 custodian seal"),
    (21, "maintenance-delta", "Maintenance delta machinery"),
    (22, "whole-program-atlas",
     "Authority exhaustiveness and the whole-program compatibility atlas"),
    (23, "multitrack-authority",
     "Multitrack authority compatibility and OpenSSL lineage"),
]

# The dependency the strata are ordered by (D138). It is a DAG, not "the previous number".
#
# The historical chain is `requires[n] == (n - 1,)`: a stratum may not be complete while the one
# before it is not. Phase 22 is why that is no longer the whole rule. Its evidence is the
# whole-program archaeology every *later* implementation stratum leans on -- the verification
# engine most of all -- so it must exist before Phase 11 finishes even though it is numbered 22.
# The edge is therefore declared rather than inferred from the number:
#
#     0 -> 1 -> ... -> 10 -> 22 -> 11 -> 12 -> ... -> 21
#
# Phase numbers stay as historical names; the dependency is represented by the dependency. The
# plan is `docs/PHASE-22-SUBPHASES.md` section 8.
REQUIRES: dict[int, tuple[int, ...]] = {
    **{p: (p - 1,) for p, _n, _s in STRATA if 1 <= p <= 21},
    22: (10,),
    11: (10, 22),
    # Phase 23 (D532) is dependency-ordered after the authority archaeology and the
    # maintenance-delta machinery, not after the highest number. It is admitted once Phase 21 is
    # complete; because 21 -> 20 -> ... -> 12 -> 11 -> (10, 22), that one edge transitively
    # requires Phase 22 as well. No existing phase is renumbered
    # (docs/PHASE-23-MULTITRACK-SUBPHASES.md section 0).
    23: (21,),
}

CONSTITUTION_DOCS = [
    "docs/CUSTODIAN_CONTRACT.md", "docs/PARITY_MODEL.md", "docs/AUTHORITY_POLICY.md",
    "docs/SECURITY_DIVERGENCE_POLICY.md", "docs/OWNERSHIP_MODEL.md", "docs/ABI_POLICY.md",
    "docs/PROVIDER_MODEL.md", "docs/FIPS_CLAIMS.md", "docs/CONCURRENCY_MODEL.md",
    "docs/RELEASE_GATES.md", "docs/NON_CLAIMS.md", "docs/REPRODUCIBILITY.md",
    "docs/UNSAFE.md",
]


def exists(relpath: str) -> bool:
    return (REPO_ROOT / relpath).exists()


def read_json(relpath: str) -> dict | None:
    p = REPO_ROOT / relpath
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def evidence_for(phase: int) -> tuple[list[str], list[str], str]:
    """Return (evidence present, evidence absent, blocking reason)."""
    present: list[str] = []
    absent: list[str] = []
    blocking = ""

    if phase == 0:
        for d in CONSTITUTION_DOCS:
            (present if exists(d) else absent).append(d)
        if absent:
            blocking = "the constitution is incomplete"
        return present, absent, blocking

    if phase == 1:
        for d in ("docs/PHASE-1-ARCHAEOLOGY-SEAL.md", "forensics/atlas/phase1-completeness.json"):
            (present if exists(d) else absent).append(d)
        comp = read_json("forensics/atlas/phase1-completeness.json")
        if comp:
            unknowns = comp["body"]["open_unknown_count"]
            if unknowns:
                blocking = (f"{unknowns} open unknown(s) recorded in the Phase 1 "
                            f"completeness inventory; the FRF sensitivity gap for the "
                            f"two non-fixture-driven courts (docs/DECISIONS.md D13) is "
                            f"one of them")
        return present, absent, blocking

    if phase == 2:
        for d in ("docs/PHASE-2-DISTRIBUTION-SEAL.md",
                  "forensics/tools/build_phase2.sh",
                  "artifacts/phase2/COURTS.json"):
            (present if exists(d) else absent).append(d)
        courts = read_json("artifacts/phase2/COURTS.json")
        if courts:
            failed = [c["court"] for c in courts["body"]["courts"]
                      if c["verdict"] != "pass"]
            if failed:
                blocking = f"courts not passing: {failed}"
        return present, absent, blocking

    # Phase 22 is an atlas stratum: its evidence is the plan, the residual ledger its closure
    # produces, the atlas courts and the seal -- not an export universe, an ownership projection or
    # a provider row. It is the one stratum whose `open` count is a count of *unclassified
    # surfaces* rather than of unbuilt exports, and `docs/PHASE-22-SUBPHASES.md` section 7 is what
    # its seal requires.
    if phase == 22:
        for d in PHASE22_MODULES:
            (present if exists(d) else absent).append(d)
        ledger = read_json(PHASE22_LEDGER)
        if ledger:
            present.append(PHASE22_LEDGER)
            open_count = ledger["body"]["counts"]["open_in_this_stratum"]
            if open_count:
                # **The two quantities this stratum blocks on are different things** and the state
                # line must not conflate them. Until 22.14's closure exists there are no
                # `UNKNOWN` residuals to count -- what is open is *instruments not yet built* --
                # and calling them "residuals" overstates the atlas and understates the work. Once
                # the closure artefact exists the residual count is read from it and reported
                # beside the plane count, which is the pair a reader needs.
                blocking = (
                    f"{open_count} compatibility plane(s) remain unimplemented "
                    f"(docs/PHASE-22-SUBPHASES.md sections 5 and 7)"
                )
                closure = read_json(PHASE22_CLOSURE)
                if closure:
                    unknown = closure["body"]["counts"].get("unknown_intersecting_roots", 0)
                    blocking += (f"; the closure graph records {unknown} UNKNOWN residual(s) "
                                 f"intersecting a declared compatibility root")
                if ledger["body"].get("note"):
                    blocking += f". {ledger['body']['note']}"
        else:
            absent.append(PHASE22_LEDGER)
        courts = read_json(PHASE22_COURTS)
        if courts:
            present.append(PHASE22_COURTS)
            failed = [c["court"] for c in courts["body"]["courts"] if c["verdict"] != "pass"]
            if failed:
                blocking = f"Phase 22 courts not passing: {failed}"
        else:
            blocking = blocking or f"no Phase 22 courts yet ({PHASE22_COURTS} absent)"
        (present if exists(PHASE22_SEAL) else absent).append(PHASE22_SEAL)
        return present, absent, blocking

    # Strata 3 and later are one rule, not five.
    #
    # Until Phase 7 the same thirty lines appeared once per stratum, differing only in the
    # phase number and two path constants. That is the failure mode this project keeps
    # removing: adding a stratum meant remembering to add a sixth copy, and a stratum whose
    # copy was forgotten would have been derived `not-started` while its modules existed --
    # which is precisely the understatement the Phase 4, 5 and 6 comments each record having
    # happened once. The rule is now one function over `STRATUM_EVIDENCE`, so a new stratum is
    # a table row and cannot be half-added, and the only per-stratum choice left is the two
    # paths its plan owns.
    ev = STRATUM_EVIDENCE.get(phase)
    if ev is None:
        return present, absent, "not started"

    for d in ev.modules:
        (present if exists(d) else absent).append(d)
    ledger = read_json(ev.ledger)
    if ledger:
        present.append(ev.ledger)
        open_count = ledger["body"]["counts"]["open_in_this_stratum"]
        if open_count:
            blocking = (
                f"{open_count} open obligation(s) of this stratum recorded in "
                f"{ev.ledger}; a stratum cannot be complete while any export it owns is "
                f"neither implemented nor handed to a later phase"
                + (f". {ev.ledger_note}" if ev.ledger_note else "")
            )
    else:
        absent.append(ev.ledger)
    courts = read_json(ev.courts)
    if courts:
        present.append(ev.courts)
        failed = [c["court"] for c in courts["body"]["courts"] if c["verdict"] != "pass"]
        if failed:
            blocking = f"Phase {phase} courts not passing: {failed}"
    else:
        # A missing court file is a blocker once the modules exist, not evidence that the
        # stratum has not begun. This was Phase 3's rule and is now every stratum's: the
        # alternative -- listing the courts as absent -- reports `not-started` and
        # understates a stratum whose modules have landed, which is the mistake the Phase 4,
        # 5 and 6 comments each record being made once by hand.
        blocking = blocking or f"no Phase {phase} courts yet ({ev.courts} absent)"

    # Coverage (D199). **This is the join the Phase-7 seal leaned on without checking**:
    # `open == 0` and `every court passes` do not imply that every implemented export has
    # a court. The atlas performs that join; a `complete` stratum must appear in it with no
    # unmatched export, or the state it would otherwise reach is not one the evidence
    # supports. The atlas covers every stratum that has begun -- phases 3-8 -- so this rule
    # holds for each of them rather than being scoped to Phase 7, and Phase 8 is subject to it
    # while it is being written rather than only on the day it seals (docs/DECISIONS.md D236).
    coverage = read_json(COVERAGE)
    if coverage:
        present.append(COVERAGE)
        # **A stratum whose ledger's unit is not an export universe is outside this join by
        # the join's own definition.** `court_coverage.py` skips a non-export ledger
        # (`atlas_common.NON_EXPORT_UNITS`) because it has no symbol set to partition, so it
        # has no row here -- and, owning no export, no unmatched export either. Phase 16's
        # `cli-config contract` is the case; Phase 22 is scoped out earlier by its own
        # evidence branch. Demanding a row here would demand one the join cannot produce
        # (D199/D236, D485).
        unit = (ledger or {}).get("body", {}).get("unit")
        if unit not in NON_EXPORT_UNITS:
            row = next((s for s in coverage["body"]["strata"] if s["phase"] == phase), None)
            if row is None:
                blocking = blocking or (
                    f"phase {phase} has no row in {COVERAGE}; the court coverage join has not "
                    f"been performed for it")
            elif row["counts"]["unmatched"]:
                blocking = blocking or (
                    f"{row['counts']['unmatched']} implemented export(s) of this stratum are "
                    f"in no court coverage set ({COVERAGE})")
    else:
        absent.append(COVERAGE)

    # Provider registration rows (D237). The census in `PROVIDER_ALGORITHMS` records every row of
    # every admitted provider's tables with an `owning_phase` and an `implementation_state`
    # (`implemented` / `unimplemented`), and a stratum may not be complete while any row it owns is
    # unlanded. "Handed on" is not a state a row can carry: it is the census's `projection`, which
    # counts the unlanded rows the plan gives a *later* stratum, and handing work to a later stratum
    # is a decision this project allows -- silently *not* publishing a row is what it does not.
    #
    # **This rule reads no stratum-relative value** (D295). Until D295 the census stored
    # `state = "open" if owning_phase == 8 else "deferred"`, which meant this rule's answer for
    # phase 8 depended on phase 8 happening to be the stratum that was active; activating phase 9
    # would have made eleven of phase 8's rows read as `deferred` and let the stratum complete with
    # them unpublished. The projection cannot move under a different active stratum.
    providers = read_json(PROVIDER_ALGORITHMS)
    if providers:
        present.append(PROVIDER_ALGORITHMS)
        owned = [r for r in providers["body"]["rows"] if r["owning_phase"] == phase]
        open_rows = [r for r in owned if r["implementation_state"] == "unimplemented"]
        if open_rows:
            names = sorted({r["algorithm_names"] for r in open_rows})
            shown = ", ".join(names[:6]) + ("..." if len(names) > 6 else "")
            blocking = blocking or (
                f"{len(open_rows)} provider registration row(s) of this stratum are neither "
                f"implemented nor handed to a later phase ({PROVIDER_ALGORITHMS}): {shown}")
    else:
        absent.append(PROVIDER_ALGORITHMS)

    # Provider-row court coverage (D245). The same join D199 performs for exports, one universe
    # down: `implemented` is a statement about a candidate table, and it is not a statement that
    # any observation touches the row. A stratum may not be complete while any row it owns is
    # implemented and named by no probe.
    pcov = read_json(PROVIDER_COVERAGE)
    if pcov:
        present.append(PROVIDER_COVERAGE)
        unmatched = pcov["body"]["unmatched"]
        if unmatched:
            names = sorted(
                r["algorithm_names"] for r in pcov["body"]["rows"]
                if r["coverage"] == "unmatched"
            )
            shown = ", ".join(names[:6]) + ("..." if len(names) > 6 else "")
            blocking = blocking or (
                f"{unmatched} implemented provider row(s) are named by no probe "
                f"({PROVIDER_COVERAGE}): {shown}")
    else:
        absent.append(PROVIDER_COVERAGE)
    return present, absent, blocking

    return present, absent, "not started"




# Phase 3 evidence: the core-runtime modules, the differential courts that
# exercise them, and the seal that records what they establish.
PHASE3_COURTS = "artifacts/phase3/COURTS.json"
# Every symbol in the Phase 3 projection is either implemented, handed to a later
# phase with a stated reason, or recorded `open`. The ledger reads its universe from
# the global ownership atlas and fails closed if any export it assigns this stratum
# is unaccounted for, so the ledger -- not this file -- decides whether anything is
# outstanding. `open_in_this_stratum > 0` keeps the phase `in-progress`.
PHASE3_OBLIGATIONS = "forensics/phase3-obligations.json"
PHASE3_MODULES = [
    "docs/PHASE-3-CORE-RUNTIME-SEAL.md",
    "src/runtime/mod.rs",
    "src/runtime/mem.rs",
    "src/runtime/err.rs",
    "src/runtime/err_strings.rs",
    "src/runtime/err_sites.rs",
    "src/runtime/err_loaders.rs",
    "src/runtime/err_variadic.c",
    "src/runtime/stack.rs",
    "src/runtime/ex_data.rs",
    "src/runtime/lhash.rs",
    "src/runtime/secure.rs",
    "src/runtime/thread.rs",
    "src/runtime/init.rs",
    "src/runtime/obj.rs",
    "src/runtime/obj_table.rs",
    # `crypto/o_str.c` and `crypto/o_dir.c`, admitted to this stratum after the
    # seal when the ownership audit found their thirteen exports unclaimed by any
    # family; see docs/DECISIONS.md D51.
    "src/runtime/str.rs",
    "src/runtime/dir.rs",
    "src/runtime/dir_posix.c",
    # `crypto/o_time.c`, the three calendar primitives the ASN.1 time family in
    # Phase 5 stands on. The file is this stratum's by placement and by its own
    # header comment; it was in no `FAMILIES` prefix list, so neither this list nor
    # the ledger mentioned it until D97.
    "src/runtime/time.rs",
    # The D97 reconciliation's own finding, then its work. `trace.rs`, `err_state.rs`
    # and `uid.rs` are the modules of the three export families that no ledger and
    # no evidence list mentioned until 6.0 read the ownership atlas against them.
    "src/runtime/trace.rs",
    "src/runtime/err_state.rs",
    "src/runtime/uid.rs",
    # `ossl_safe_getenv`, used by the CONF reader's default-path logic; internal,
    # so it claims no export, but it is core-runtime surface.
    "src/runtime/getenv.rs",
    "forensics/tools/phase3_courts.py",
    "forensics/tools/phase3_obligations.py",
    "courts/phase3/rt_mem_probe.c",
    "courts/phase3/rt_exdata_probe.c",
    "courts/phase3/rt_err_probe.c",
    "courts/phase3/rt_err_strings_cases.h",
    "courts/phase3/rt_stack_probe.c",
    "courts/phase3/rt_thread_probe.c",
    "courts/phase3/rt_secure_probe.c",
    "courts/phase3/rt_lhash_probe.c",
    "courts/phase3/rt_runtime_ext_probe.c",
    # The reference-basis probe the court coverage atlas (D199) added for the runtime
    # exports no behavioural court drives. It references, it does not call.
    "courts/phase3/rt_coverage_ref_probe.c",
]
# Whether anything in the Phase 3 families is unaccounted for is decided by the
# ledger (`phase3_obligations.py` fails closed), not by a string here.


# Phase 4 evidence: the BIO/CONF/buffer modules, the differential courts that
# exercise them, and the seal that records what they establish. The obligation
# ledger is what decides whether anything in the phase's families is
# unaccounted for: `phase4_obligations.py` separates hand-offs to later strata
# from open work, and `open_in_this_stratum > 0` keeps the phase `in-progress`.
PHASE4_COURTS = "artifacts/phase4/COURTS.json"
PHASE4_OBLIGATIONS = "forensics/phase4-obligations.json"
PHASE4_MODULES = [
    "docs/PHASE-4-BIO-CONF-SEAL.md",
    # The BIO infrastructure: methods, chains, the I/O library, callbacks, retry
    # state, addresses and the print family.
    "src/runtime/bio/mod.rs",
    "src/runtime/bio/iolib.rs",
    "src/runtime/bio/method.rs",
    "src/runtime/bio/sys.rs",
    "src/runtime/bio/print.rs",
    "src/runtime/bio/dump.rs",
    "src/runtime/bio/retry.rs",
    "src/runtime/bio/bio_cb.rs",
    "src/runtime/bio/addr.rs",
    "src/runtime/bio/addr_info.rs",
    "src/runtime/bio/legacy_host.rs",
    "src/runtime/bio/comp.rs",
    "src/runtime/bio/print_engine.rs",
    # The individual BIO methods.
    "src/runtime/bio/bss_mem.rs",
    "src/runtime/bio/bss_null.rs",
    "src/runtime/bio/bss_sock.rs",
    "src/runtime/bio/bss_fd.rs",
    "src/runtime/bio/bss_file.rs",
    "src/runtime/bio/bss_conn.rs",
    "src/runtime/bio/bss_acpt.rs",
    "src/runtime/bio/bss_dgram.rs",
    "src/runtime/bio/bss_dgram_pair.rs",
    "src/runtime/bio/bss_bio.rs",
    "src/runtime/bio/bss_log.rs",
    "src/runtime/bio/bio_sock2.rs",
    "src/runtime/bio/bf_null.rs",
    "src/runtime/bio/bf_buff.rs",
    "src/runtime/bio/bf_lbuf.rs",
    "src/runtime/bio/bf_readbuff.rs",
    "src/runtime/bio/bf_prefix.rs",
    "src/runtime/bio/bio_va.c",
    "src/runtime/bio/bio_variadic.c",
    # The buffer object and the CONF reader.
    "src/runtime/buffer.rs",
    "src/runtime/conf/mod.rs",
    "src/runtime/conf/types.rs",
    "src/runtime/conf/api.rs",
    "src/runtime/conf/def.rs",
    "src/runtime/conf/lib.rs",
    "src/runtime/conf/modparse.rs",
    "src/runtime/conf/init_settings.rs",
    # The D97 reconciliation's own finding, then 6.3's work. `conf_ssl.rs` and
    # `sap.rs` are the two CONF translation units whose exports no ledger and no
    # evidence list mentioned until 6.0 read the ownership atlas against them.
    "src/runtime/conf/conf_ssl.rs",
    "src/runtime/conf/sap.rs",
    # The differential courts, and the discovery probes `docs/DECISIONS.md` and
    # `docs/SECURITY_DIVERGENCE_POLICY.md` cite as the origin of recorded
    # measurements. Both kinds are evidence: a decision that names a probe is only
    # checkable while the probe exists.
    "courts/phase4/rt_bio_probe.c",
    "courts/phase4/rt_err_bio_probe.c",
    "courts/phase4/rt_bio_addr_probe.c",
    "courts/phase4/rt_bio_resolve_probe.c",
    "courts/phase4/rt_bio_sock_probe.c",
    "courts/phase4/rt_bio_comp_probe.c",
    "courts/phase4/rt_bio_debug_probe.c",
    "courts/phase4/rt_bio_print_probe.c",
    "courts/phase4/rt_bio_file_probe.c",
    "courts/phase4/rt_bio_filter_probe.c",
    "courts/phase4/rt_bio_pair_probe.c",
    "courts/phase4/rt_bio_dgram_pair_probe.c",
    "courts/phase4/rt_bio_dgram_probe.c",
    "courts/phase4/rt_bio_conn_probe.c",
    "courts/phase4/rt_obj_stream_probe.c",
    "courts/phase4/rt_conf_probe.c",
    "courts/phase4/rt_comp_probe.c",
    "courts/phase4/discover_bio_addr.c",
    "courts/phase4/discover_bio_addr2.c",
    "courts/phase4/discover_bio_lookup.c",
    "courts/phase4/discover_bio_lookup_hints.c",
    "courts/phase4/discover_bio_legacy_host.c",
    "courts/phase4/bio_addr_null_calls.c",
    # The discovery probe D97's `COMP_*` finding is recorded against: the profile's
    # `no-zlib`/`no-zstd`/`no-brotli` guards, the six NULL factories and the
    # `COMP_CTX_get_type(NULL)` fault are all read off its transcript. A decision that
    # names a probe is only checkable while the probe exists.
    "courts/phase4/discover_comp.c",
    "forensics/tools/phase4_courts.py",
    "forensics/tools/phase4_obligations.py",
    # The reference-basis probe the court coverage atlas (D199) added.
    "courts/phase4/rt_coverage_ref_probe.c",
]


# Phase 5 evidence: the arithmetic and encoding substrate, the differential courts
# that exercise it, and the seal that records what they establish. As with Phase 4,
# the obligation ledger decides whether anything in the phase's families is
# unaccounted for: `phase5_obligations.py` separates hand-offs to later strata from
# open work, and `open_in_this_stratum > 0` keeps the phase `in-progress`.
PHASE5_COURTS = "artifacts/phase5/COURTS.json"
PHASE5_OBLIGATIONS = "forensics/phase5-obligations.json"
PHASE5_MODULES = [
    "docs/PHASE-5-BN-ASN1-PEM-SEAL.md",
    # The limb primitives and the opaque `BIGNUM` object, then the `BN_*` entry
    # points over them.
    "src/bn/mod.rs",
    "src/bn/limbs.rs",
    "src/bn/bignum.rs",
    "src/bn/arith.rs",
    "src/bn/ctx.rs",
    # The differential court and the runner that compiles it against both
    # distributions.
    "courts/phase5/rt_bn_probe.c",
    "forensics/tools/phase5_courts.py",
    "forensics/tools/phase5_obligations.py",
    # The reference-basis probe the court coverage atlas (D199) added.
    "courts/phase5/rt_coverage_ref_probe.c",
]

# Phase 6 evidence: the parameter surface and the provider core, the differential
# court that exercises it, and the ledger that decides the stratum's arithmetic.
#
# `docs/PHASE-6-PROVIDER-SEAL.md` **is** listed now, in the commit that writes it: with the
# last open obligation closed the stratum can report `complete`, and a `complete` stratum
# without a seal would be a completion claim nobody can audit. That is the rule phases 3, 4
# and 5 already follow, and this line is where Phase 6 joins them.
PHASE6_COURTS = "artifacts/phase6/COURTS.json"
PHASE6_OBLIGATIONS = "forensics/phase6-obligations.json"
PHASE6_MODULES = [
    "src/params/mod.rs",
    "src/params/dup.rs",
    "src/params/from_text.rs",
    "src/params/build.rs",
    "courts/phase6/rt_param_probe.c",
    # 6.6: the context and its slot table, the core BIO, the namemap and the thread slot.
    "src/context/mod.rs",
    "src/context/dispatch.rs",
    "src/context/core_bio.rs",
    "src/context/namemap.rs",
    "src/context/thread_data.rs",
    "courts/phase6/rt_libctx_probe.c",
    "courts/phase6/rt_bio_core_probe.c",
    # 6.7: the property engine, whose court is the slot table because it exports nothing.
    "src/property/mod.rs",
    "src/property/globals.rs",
    "src/property/defn_cache.rs",
    "src/property/list.rs",
    "src/property/parse.rs",
    "src/property/query.rs",
    "src/property/strings.rs",
    # 6.8: the provider object, its registry, its activation and the child callbacks.
    "src/provider/mod.rs",
    "src/provider/init.rs",
    "src/provider/activate.rs",
    "src/provider/stores.rs",
    "src/provider/core_dispatch.rs",
    # 6.8d: `crypto/provider_conf.c`, the `providers` configuration module, whose court is
    # RT-PROVIDER -- the same court the registry calls home, because the module is reached
    # only through a configuration file and every observation of it goes through the
    # provider surface it configures.
    "src/provider/conf.rs",
    # 6.8e: `crypto/provider_child.c`, the child provider and the parent callbacks, plus the
    # three accessors `provider_core.c` keeps beside the object. Its observations are split:
    # `RT-LIBCTX` reaches them through `OSSL_LIB_CTX_new_child`, and `RT-PROVIDER` through the
    # registry the parent-side registration walks.
    "src/provider/child.rs",
    # 6.10 closure: the seal. A stratum may only report `complete` with its seal in place --
    # that is the rule phases 3, 4 and 5 already follow, and adding it here is what makes
    # Phase 6's completion claim auditable rather than merely reported.
    "docs/PHASE-6-PROVIDER-SEAL.md",
    "courts/phase6/rt_provider_probe.c",
    # 6.12: the provider **core** hosting a third-party provider. This is the only probe that
    # compiles an `OSSL_provider_init` into itself, so it is the only one that can see the
    # provider-facing dispatch table at all -- and it is what closes the two
    # `D-CHILD-REGISTER-PROPS-1`/`D-CHILD-PROPS-CB-1` entries from "no court has observed
    # either half" to measured.
    "courts/phase6/rt_provider_3p_probe.c",
    # 6.9: the DSO layer, reassigned from Phase 2 by D95 because Phase 2's definition is
    # distribution structure and the dynamic-loader abstraction is semantic.
    "src/dso/mod.rs",
    "src/dso/dlfcn.rs",
    "courts/phase6/rt_dso_probe.c",
    # 6.6e-ii and all three units of 6.10a: the thread-event table, the per-context
    # thread-local family, the sparse array underneath it, and RCU. RCU exports nothing and
    # has no C-visible entry point, so its evidence is its transcription and its unit tests
    # rather than a court -- recorded as D-RCU-4 rather than glossed.
    "src/runtime/thread_events.rs",
    "src/runtime/threads_common.rs",
    "src/runtime/sparse_array.rs",
    "src/runtime/rcu.rs",
    "courts/phase6/rt_threaddata_probe.c",
    # 6.7b: the character-class table, generated from the authority's own `crypto/ctype.c`.
    "src/runtime/ctype.rs",
    "src/runtime/ctype_table.rs",
    # 6.8c: the compiled-in directory defaults.
    "src/runtime/defaults.rs",
    # 6.6c: the self-test indicator object.
    "src/selftest/mod.rs",
    "src/selftest/indicator.rs",
    "courts/phase6/rt_selftest_probe.c",
    # 6.10b/6.10c/6.10d: the CONF module registry and the automatic configuration
    # loader. The court is `RT-CONF-MOD`, which is also what reaches the RCU layer,
    # since `conf_mod.c` is its only consumer in this build.
    "src/runtime/confmod/mod.rs",
    "src/runtime/confmod/asn1.rs",
    "src/runtime/conf/sap.rs",
    "courts/phase6/rt_conf_mod_probe.c",
    "forensics/tools/phase6_courts.py",
    "forensics/tools/phase6_obligations.py",
    # The reference-basis probe the court coverage atlas (D199) added.
    "courts/phase6/rt_coverage_ref_probe.c",
]


class StratumEvidence:
    """One stratum's evidence: what its plan claims, and where its ledger and courts are.

    Deliberately data. The rule that reads it is a single function, so a stratum that is
    added to the phase registry without a row here is derived `not-started` however much
    evidence it carries -- which is why `main` fails when a phase the registry lists at 3 or
    later has no row, and prints which ones.
    """

    __slots__ = ("modules", "ledger", "courts", "ledger_note")

    def __init__(self, modules, ledger, courts, ledger_note=""):
        self.modules = modules
        self.ledger = ledger
        self.courts = courts
        self.ledger_note = ledger_note


# Phase 7's evidence: the EVP framework's modules, its ledger and its courts. Its plan is
# `docs/PHASE-7-SUBPHASES.md`, and 7.0 landed the ledger while the stratum itself is still
# entirely open, which is the honest starting state and is what that plan's §2 records.
PHASE7_COURTS = "artifacts/phase7/COURTS.json"
PHASE7_OBLIGATIONS = "forensics/phase7-obligations.json"
PHASE7_MODULES = [
    "docs/PHASE-7-SUBPHASES.md",
    # 7.1 -- the fetch core: `crypto/core_algorithm.c`'s walk, transcribed.
    "src/evp/mod.rs",
    "src/evp/algorithm.rs",
    # 7.1/7.2 -- the method store and the fetch surface above it. `src/property/store.rs` is
    # `crypto/property/property.c`'s remainder, which is a `crypto/property/` file belonging to
    # this stratum because the earliest caller of the object it defines is `evp_fetch.c`
    # (D141); `src/runtime/rdtsc.rs` is `crypto/x86_64cpuid.pl`'s `OPENSSL_rdtsc`, whose first
    # caller here is the store's stochastic flush.
    "src/evp/fetch.rs",
    "src/evp/method_store.rs",
    "src/property/store.rs",
    "src/runtime/rdtsc.rs",
    # 7.3 -- the symmetric method objects and their legacy wrappers.
    "src/evp/cipher.rs",
    "src/evp/digest.rs",
    "src/evp/mac.rs",
    "src/evp/kdf.rs",
    "src/evp/rand.rs",
    "src/evp/skeymgmt.rs",
    # **`src/evp/legacy_cipher.rs` and `src/evp/legacy_digest.rs` were listed here and never came
    # into being**, which made `absent` non-empty and held this stratum `in-progress`. They were the
    # destinations 7.3g's ledger labels the legacy `EVP_CIPHER`/`EVP_MD` statics with, and 7.3g handed
    # **every** one of them to Phase 13 with its primitive unit named, so no file was written and
    # none should be: creating empty modules to satisfy an evidence list is the failure mode
    # `docs/NON_CLAIMS.md` is about. The label stays in `phase7_obligations.py`'s `MODULE_PREFIXES`,
    # where it is documented as a label rather than a claim about a file (D193's `p_legacy.rs`
    # reading, and D194 for the `PKCS5_` half of the `pem_bridge.rs` label); the evidence list is
    # what had the wrong shape, and D196 removes the two entries.
    "src/evp/legacy_evp.rs",
    # 7.4 -- the EVP_PKEY layer and the ASN.1 glue declared in `evp.h`.
    "src/evp/pkey.rs",
    "src/evp/pkey_ctx.rs",
    "src/evp/pkey_asn1.rs",
    "src/evp/pbe.rs",
    # `ctrl_params_translate.c`'s work is in `pkey_ctx.rs`, which is where the ctrl plane landed
    # (D188); `src/evp/params_translate.rs` was listed here as the expected module for that unit and
    # was never created. D196 removes it, for the reason the two above are removed.
    "src/evp/signature.rs",
    "src/evp/asymcipher.rs",
    "src/evp/kem.rs",
    "src/evp/exchange.rs",
    "src/evp/keymgmt.rs",
    # 7.5 -- the BIO, encoding and PEM bridges.
    "src/evp/bio_enc.rs",
    "src/evp/encode.rs",
    "src/evp/p_legacy.rs",
    "src/evp/pem_bridge.rs",
    # 7.6 -- the MAC, KDF and HPKE header surfaces.
    "src/mac/mod.rs",
    "src/mac/hmac.rs",
    "src/mac/cmac.rs",
    "src/hpke/mod.rs",
    # 7.7 -- the seal. A stratum may only report `complete` with its seal in place, which is the rule
    # phases 3, 4, 5 and 6 already follow and which is the reason this line is added in the commit
    # that writes the document rather than after it.
    "docs/PHASE-7-EVP-SEAL.md",
    "forensics/tools/phase7_courts.py",
    "forensics/tools/phase7_obligations.py",
    "courts/phase7/rt_fetch_probe.c",
    # The reference-basis probe the court coverage atlas (D199) added for the EVP exports
    # no behavioural court drives. It references, it does not call.
    "courts/phase7/rt_coverage_ref_probe.c",
    "courts/phase7/rt_evp_introspect_probe.c",
    "courts/phase7/rt_evp_class_probe.c",
    "courts/phase7/rt_evp_pkey_ops_probe.c",
]


# Phase 8's evidence: the native cryptographic primitives -- the digests, the symmetric
# ciphers and their modes, and the four asymmetric key types with the ASN.1 method objects
# that name them. Its plan is `docs/PHASE-8-SUBPHASES.md`, and 8.0 landed the ledger while the
# stratum itself is entirely open, which is the honest starting state and is what that plan's
# §2 records. The modules are added by the subphase that lands them, in the same commit, so
# that this list is a statement about the tree rather than about the plan.
PHASE8_COURTS = "artifacts/phase8/COURTS.json"
PHASE8_OBLIGATIONS = "forensics/phase8-obligations.json"
PHASE8_MODULES = [
    "docs/PHASE-8-SUBPHASES.md",
    "forensics/tools/phase8_courts.py",
    "forensics/tools/phase8_obligations.py",
    # 8.1a adds the second evidence plane: the correctness courts' driver and the
    # candidate-only probe. The committed vector sets under `forensics/vectors/` are that
    # driver's data and are recorded per court by `phase8_courts.py`; naming the code here
    # is what makes the plane's absence a blocking reason rather than a silent one.
    "forensics/tools/correctness_vectors.py",
    "courts/phase8/ct_digest.c",
]


# Phase 9's evidence: the random layer -- `rand.h`'s front, the BN random family behind it, the
# providers' DRBG framework and its three instantiations, and the seed sources those draw on. Its
# plan is `docs/PHASE-9-SUBPHASES.md`, which 9.0 lands with the ledger and the runner. The
# modules are added by the subphase that lands them, in the same commit, so that this list is a
# statement about the tree rather than about the plan -- which is why it does not yet name
# `src/rand/` or any of the three DRBG modules: none of them exists.
#
# **The court file is present and empty, and its own claim says so** (docs/DECISIONS.md D294).
# `run_courts.py` requires a stratum that has committed a courts file to have a runner that
# reproduces it, so the runner lands with the file; `Phase 9`'s evidence until 9.1 is the ledger,
# and `phase-state.json` reports the stratum `in-progress` rather than `complete` because the
# ledger's `open_in_this_stratum` is ninety-three.
PHASE9_COURTS = "artifacts/phase9/COURTS.json"
PHASE9_OBLIGATIONS = "forensics/phase9-obligations.json"
PHASE9_MODULES = [
    "docs/PHASE-9-SUBPHASES.md",
    "forensics/tools/phase9_courts.py",
    "forensics/tools/phase9_obligations.py",
    # 9.2's first unit, and the only part of this stratum that can land before the front it is
    # called from: `crypto/rand/rand_pool.c` has no platform dependency, so it compiles and its
    # ten unit tests run while nothing in the crate calls it. It carries no export, so it adds no
    # row to the ledger and no edge to the court-coverage atlas -- which is why naming it here is
    # the only place its landing is visible to the evidence machinery at all.
    "src/rand/mod.rs",
    "src/rand/pool.rs",
    # 9.5's platform layer. It landed before the arm that calls it because it is the part with an
    # ABI to get wrong and no dependency of its own: ten unit tests exercise each binding against
    # the running kernel, including the `struct stat` offsets and the `__NR_getrandom` value, which
    # are exactly the two a transcription can get wrong without any caller noticing.
    "src/rand/sys.rs",
    # 9.5's seeding arm itself: `rand_unix.c`, the unit D298 moved out of
    # `crypto/rand/rand_pool.c`. It is the only part of this stratum that reaches the kernel for
    # entropy, so its four tests are the only place `ossl_pool_acquire_entropy` is called at all.
    "src/rand/unix.rs",
    # 9.3's provider-side prerequisites: the four seed up-calls `drbg.c` reaches through the
    # provider context, and `provider_util.c`'s two MAC-context functions `drbg_hmac.c` calls.
    # Both are internal and neither has a caller until the DRBG rows land, which is why they are
    # named here -- nothing else in the evidence machinery sees them.
    "src/provider/seeding.rs",
    "src/provider/util.rs",
    # 9.7 -- the seal. A stratum may only report `complete` with its seal in place, which is the
    # rule phases 3 through 8 already follow and which is the reason this line is added in the
    # commit that writes the document rather than after it. Without it phase 9 could reach
    # `complete` with no seal at all, and `phase_state.py`'s own claim -- "a stratum may only
    # report `complete` with its seal in place" -- would be false for exactly one stratum.
    "docs/PHASE-9-RAND-DRBG-SEAL.md",
]

# Phase 10's evidence: the key-format layer -- the `OSSL_ENCODER`/`OSSL_DECODER` codec
# framework and the provider rows that publish its codecs, PKCS#12, and `OSSL_STORE` -- plus the
# PKCS#8/PVK and `d2i_*`/`i2d_*` helpers earlier strata handed forward. Its plan is
# `docs/PHASE-10-SUBPHASES.md`, which 10.0 lands with the ledger. The modules are added by the
# subphase that lands them, in the same commit, so that this list is a statement about the tree
# rather than about the plan -- which is why it names no `src/store/` module and no PKCS#12
# submodule: the stratum has landed none of them.
#
# **Unlike every earlier activation, this stratum does not start with a whole working set open.**
# `forensics/phase10-obligations.json` reports eighty-seven of its atlas-owned exports already
# `implemented` -- all seventy-nine `encoder.h`/`decoder.h` exports and eight `pkcs12.h` ones,
# landed by Phase 8's 8.8 chain (D362-D367) -- so `phase-state.json` reports the stratum
# `in-progress` rather than `not-started` because its ledger has an open count, not because it
# has a plan alone. `docs/PHASE-10-SUBPHASES.md` section 4 records the measurement and the
# precondition it places on the coverage join.
PHASE10_COURTS = "artifacts/phase10/COURTS.json"
PHASE10_OBLIGATIONS = "forensics/phase10-obligations.json"
PHASE10_MODULES = [
    "docs/PHASE-10-SUBPHASES.md",
    "forensics/tools/phase10_obligations.py",
    # 10.7 -- the seal. A stratum may only report `complete` with its seal in place, which is the
    # rule phases 3 through 9 already follow and which is the reason this line is added in the
    # commit that writes the document rather than after it. Without it phase 10 could reach
    # `complete` with no seal at all, and `phase_state.py`'s own claim -- "a stratum may only
    # report `complete` with its seal in place" -- would be false for exactly one stratum.
    "docs/PHASE-10-KEYFORMATS-SEAL.md",
]


# Phase 11's evidence: the X.509 stratum -- the certificate, request, CRL and attribute-
# certificate object graphs and their verification machinery (`X509`, `X509_REQ`, `X509_CRL`,
# `X509_ACERT`, `X509_STORE`, `X509_VERIFY_PARAM`, `X509_POLICY_*`, the `X509V3_EXT_*` engine
# and the `PEM_*_X509*` container readers and writers). Its plan is
# `docs/PHASE-11-SUBPHASES.md`, which 11.0 lands with the ledger. The modules are added by
# the subphase that lands them, in the same commit, so that this list is a statement about the
# tree rather than about the plan -- which is why it names no `src/x509/` module beyond the ones
# Phase 10's pulled-forward subphases already landed: the stratum has landed none of its own.
#
# **Like Phase 10, this stratum does not start with a whole working set open.**
# `forensics/phase11-obligations.json` reports a working set of 1,467 exports and an `open` count
# smaller than it, because Phase 8's 8.8 chain, Phase 10's pulled-forward X.509 subphases
# (10.8-10.14, D442-D451) and two Phase 5 hand-offs landed part of the set before activation, so
# `phase-state.json` reports the stratum `in-progress` because its ledger has an open count, not
# because it has a plan alone. **That split moves as the stratum lands its own units**, so the
# note below does not restate its counts: the ledger's `counts` is the live record and
# `forensics/atlas/implemented-surface.json` is the authority behind it. It owns **no provider
# registration row**. `docs/PHASE-11-SUBPHASES.md` section 4 records the activation measurement
# and the precondition it places on the coverage join.
PHASE11_COURTS = "artifacts/phase11/COURTS.json"
PHASE11_OBLIGATIONS = "forensics/phase11-obligations.json"
PHASE11_MODULES = [
    "docs/PHASE-11-SUBPHASES.md",
    "forensics/tools/phase11_obligations.py",
]

# Phase 12's evidence: the CMS/OCSP/CMP/CT/TS stratum -- the signed and encrypted container
# formats and the certificate-status and protocol machinery built over Phase 11's X.509 objects
# (`CMS`, `PKCS7`, `OCSP`, `CMP` with `CRMF`, `TS`, `CT`, the S/MIME bridge) and the remaining
# `libcrypto` families the earlier strata left (`SRP`, `ESS`, the HTTP client). Its plan is
# `docs/PHASE-12-SUBPHASES.md`, which 12.0 lands with the ledger. The modules are added by the
# subphase that lands them, in the same commit, so that this list is a statement about the tree
# rather than about the plan -- which is why it names no `src/cms/` module: the stratum has landed
# none of its own.
#
# **Like Phases 10 and 11, this stratum does not start with a whole working set open.**
# `forensics/phase12-obligations.json` reports a working set of 1,033 exports and an `open` count
# smaller than it, because the whole `ocsp_asn.c` item group, the CT `ct_*` units, `pk7_asn1.c`
# with `pk7_lib.c` and `http_lib.c`'s `OSSL_parse_url` landed before activation as substrate the
# earlier strata needed, so `phase-state.json` reports the stratum `in-progress` because its ledger
# has an open count, not because it has a plan alone. **That split moves as the stratum lands its
# own units**, so the note below does not restate its counts: the ledger's `counts` is the live
# record and `forensics/atlas/implemented-surface.json` is the authority behind it. It owns **no
# provider registration row**. `docs/PHASE-12-SUBPHASES.md` section 4 records the activation
# measurement and the precondition it places on the coverage join.
PHASE12_COURTS = "artifacts/phase12/COURTS.json"
PHASE12_OBLIGATIONS = "forensics/phase12-obligations.json"
PHASE12_MODULES = [
    "docs/PHASE-12-SUBPHASES.md",
    "forensics/tools/phase12_obligations.py",
]

# Phase 13's evidence: the legacy/deprecated-compatibility stratum -- the `ENGINE` framework, the
# `UI` dialog framework, the `TXT_DB` text database the `ca` app reads, and the deprecated
# METHOD-era surface the earlier strata hand it rather than transcribe. Its plan is
# `docs/PHASE-13-SUBPHASES.md`, which 13.0 lands with the ledger. The modules are added by the
# subphase that lands them, in the same commit, so that this list is a statement about the tree
# rather than about the plan -- which is why it names no `src/engine/` module: the stratum has
# landed none of its own.
#
# **This stratum's working set is more than its atlas-owned universe.** The atlas assigns it 189
# `engine.h`/`ui.h`/`txt_db.h` exports, and it receives 188 more as recorded hand-offs from
# phases 3, 7 and 12; `forensics/phase13-obligations.json` reports a working set of 377 and an
# `open` count smaller than it, because 123 atlas-owned exports and the four Phase 7 -> 13
# `PEM_read[_bio]_PrivateKey` hand-offs are already implemented, so `phase-state.json` reports the
# stratum `in-progress` because its ledger has an open count, not because it has a plan alone.
# **That split moves as the stratum lands its own units**, so the note below does not restate its
# counts: the ledger's `counts` is the live record and `forensics/atlas/implemented-surface.json`
# is the authority behind it. It owns **no provider registration row**: the 39 legacy digest and
# cipher rows `forensics/atlas/provider-algorithms.json` records for `providers/legacyprov.c` are
# the loadable module the candidate ships as a scaffold `ossl-modules/legacy.so`, which this
# stratum's subphases deliberately do not activate, so `provider-algorithm-plans.json` hands them
# to the distribution stratum (Phase 16). `docs/PHASE-13-SUBPHASES.md` section 4 records the
# activation measurement and the precondition it places on the coverage join.
PHASE13_COURTS = "artifacts/phase13/COURTS.json"
PHASE13_OBLIGATIONS = "forensics/phase13-obligations.json"
PHASE13_MODULES = [
    "docs/PHASE-13-SUBPHASES.md",
    "forensics/tools/phase13_obligations.py",
]

# Phase 14's evidence: the TLS/DTLS stratum -- the whole of `libssl`: the `SSL_CTX`/`SSL` object
# model, the `TLS_*`/`DTLS_*` method and version tables, the record layer, the handshake state
# machine, the BIO pair, the session and certificate plumbing and the DTLS and QUIC bridges. Its
# plan is `docs/PHASE-14-SUBPHASES.md`, which 14.0 lands with the ledger. The modules are added by
# the subphase that lands them, in the same commit, so that this list is a statement about the tree
# rather than about the plan -- which is why it names no `src/ssl/` module: the stratum has landed
# none of its own.
#
# **This stratum's working set is exactly its atlas-owned universe, and it inherits nothing.**
# The atlas assigns it 600 `ssl.h`/`tls1.h`/`srtp.h`/`sslerr_legacy.h` exports, no earlier stratum's
# ledger records an `owning_phase == 14` hand-off, and `forensics/phase14-obligations.json` reports
# `received_by_handoff: 0`. **Unlike every earlier activation, not one of the 600 is implemented at
# activation**: libssl is the candidate distribution's second namespace, its exports are present
# only as the Phase 2 ABI scaffold, and `forensics/atlas/implemented-surface.json` records
# `implemented: 0` for libssl, so `phase-state.json` reports the stratum `in-progress` with an
# `open` count equal to its whole working set, not because it has a plan alone. **That split moves
# as the stratum lands its own units**, so the note below does not restate its counts: the ledger's
# `counts` is the live record and `forensics/atlas/implemented-surface.json` is the authority behind
# it. It owns **no provider registration row**: libssl is not a provider and this stratum activates
# none. `docs/PHASE-14-SUBPHASES.md` section 4 records the activation measurement and the
# precondition it places on the runner.
PHASE14_COURTS = "artifacts/phase14/COURTS.json"
PHASE14_OBLIGATIONS = "forensics/phase14-obligations.json"
PHASE14_MODULES = [
    "docs/PHASE-14-SUBPHASES.md",
    "forensics/tools/phase14_obligations.py",
]

# Phase 15 is the QUIC/ECH stratum: the three `quic.h` exports Phase 14 left it. Its evidence is
# its plan and its ledger generator; the ledger's universe is the ownership atlas's
# `owner_phase == 15` rows -- exactly three -- plus every row an earlier stratum's ledger records
# as handed to it, of which there are none, so `forensics/phase15-obligations.json` reports
# `received_by_handoff: 0`. It begins on Phase 14's landed libssl substrate: the three `quic.h`
# names are the only `libssl` exports that stratum did not own, so at activation they are open and
# the split moves as 15.1 lands them. It owns **no provider registration row**: QUIC is not a
# provider and this stratum activates none. The two authority units `forensics/prerequisites.json`
# defers to this stratum (`ssl/statem/statem_clnt.c`, `ssl/statem/statem_srvr.c`) are unit
# deferrals for the prerequisite gate, not export hand-offs. `docs/PHASE-15-SUBPHASES.md` section 4
# records the activation measurement and the precondition it places on the runner.
PHASE15_COURTS = "artifacts/phase15/COURTS.json"
PHASE15_OBLIGATIONS = "forensics/phase15-obligations.json"
PHASE15_MODULES = [
    "docs/PHASE-15-SUBPHASES.md",
    "forensics/tools/phase15_obligations.py",
]

# Phase 16 is the CLI / config / filesystem contract stratum, and **it owns no exported symbol**:
# reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 16` yields no record, so
# its ledger's unit is not a symbol. `forensics/phase16-obligations.json` records its unit as
# `cli-config contract` (in `atlas_common.NON_EXPORT_UNITS`, so the export-partitioning tools
# skip it, as they skip Phase 22's `compatibility plane`), and its working set is instead the 39
# legacy provider registration rows `forensics/atlas/provider-algorithms.json` assigns it, the
# prerequisite deferrals `forensics/prerequisites.json` records with `owner_phase: 16`, and the
# three CLI / config / filesystem contract units. 16.1 published all 39 provider rows, and
# 16.2/16.3 retired the dynamic-ENGINE loader and the two `OPENSSLDIR`/install-context deferrals.
# The stratum registers no
# coverage-reference probe, because it owns no symbol to take an address of, so its runner's
# registry is empty at activation and the remaining behavioural courts are `pending` with the
# subphase that lands each. `docs/PHASE-16-SUBPHASES.md` section 4 records the activation
# measurement and the precondition it places on the runner.
PHASE16_COURTS = "artifacts/phase16/COURTS.json"
PHASE16_OBLIGATIONS = "forensics/phase16-obligations.json"
PHASE16_MODULES = [
    "docs/PHASE-16-SUBPHASES.md",
    "forensics/tools/phase16_obligations.py",
]

# Phase 17 is the downstream replacement court stratum, and **it owns no exported symbol**: reading
# `forensics/atlas/symbol-ownership.json` for `owner_phase == 17` yields no record, so its ledger's
# unit is not a symbol. `forensics/phase17-obligations.json` records its unit as `downstream
# replacement contract` (in `atlas_common.NON_EXPORT_UNITS`, so the export-partitioning tools skip
# it, as they skip Phase 16's `cli-config contract` and Phase 22's `compatibility plane`), and its
# working set is the 52 `apps/<name>.c` unit deferrals `forensics/prerequisites.json` records with
# `owner_phase: 17` (D530) plus four downstream replacement contract units. It owns no provider
# registration row -- it activates no provider -- and no symbol deferral. It registers no
# coverage-reference probe, because it owns no symbol to take an address of, so its runner's registry
# is empty at activation and its four behavioural courts are `pending` with the subphase that lands
# each. The ledger measures its contract-unit states from the courts registry, so the runner does not
# bind the ledger (the edge runs ledger -> courts, the reverse of Phase 16's).
# `docs/PHASE-17-SUBPHASES.md` section 4 records the activation measurement and the precondition it
# places on the runner.
PHASE17_COURTS = "artifacts/phase17/COURTS.json"
PHASE17_OBLIGATIONS = "forensics/phase17-obligations.json"
PHASE17_MODULES = [
    "docs/PHASE-17-SUBPHASES.md",
    "forensics/tools/phase17_obligations.py",
]

# Phase 18 is the hostile fuzz / security / side-channel hardening stratum, and **it owns no
# exported symbol**: reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 18`
# yields no record, so its ledger's unit is not a symbol. `forensics/phase18-obligations.json`
# records its unit as `hostile hardening contract` (in `atlas_common.NON_EXPORT_UNITS`, so the
# export-partitioning tools skip it, as they skip Phase 16's `cli-config contract` and Phase 17's
# `downstream replacement contract`), and its working set is five contract units -- a hostile TLS
# corpus, a hostile X.509 / malformed-input corpus, the constant-time secret-independence checks,
# the memory-safety / resource-exhaustion hardening and the hostile-boundary register. Unlike
# Phases 16 and 17 it hands nothing forward and receives nothing: it owns no provider registration
# row, no symbol deferral and no prerequisite unit, because it hardens the implementation Phases 3
# through 15 completed rather than adding library surface. It registers no coverage-reference
# probe, because it owns no symbol to take an address of, so its runner's registry is empty at
# activation and its five courts are `pending` with the subphase that lands each. The ledger
# measures its contract-unit states from the courts registry, so the runner does not bind the
# ledger (the edge runs ledger -> courts, the reverse of Phase 16's).
# `docs/PHASE-18-SUBPHASES.md` section 4 records the activation measurement and the precondition it
# places on the runner.
PHASE18_COURTS = "artifacts/phase18/COURTS.json"
PHASE18_OBLIGATIONS = "forensics/phase18-obligations.json"
PHASE18_MODULES = [
    "docs/PHASE-18-SUBPHASES.md",
    "forensics/tools/phase18_obligations.py",
]

# Phase 19 is the performance / CPU dispatch stratum, and **it owns no exported symbol**: reading
# `forensics/atlas/symbol-ownership.json` for `owner_phase == 19` yields no record, so its ledger's
# unit is not a symbol. `forensics/phase19-obligations.json` records its unit as `performance
# dispatch contract` (in `atlas_common.NON_EXPORT_UNITS`, so the export-partitioning tools skip it,
# as they skip Phase 16's `cli-config contract`, Phase 17's `downstream replacement contract` and
# Phase 18's `hostile hardening contract`), and its working set is five contract units -- the
# CPU-capability dispatch audit, the EVP / cipher dispatch comparison, the deterministic work
# court, the instrument-sensitivity court and the performance-boundary register. Like Phase 18 it
# hands nothing forward and receives nothing: it owns no provider registration row, no symbol
# deferral and no prerequisite unit, because it measures the implementation the strata before it
# completed rather than adding library surface. It registers no coverage-reference probe, because
# it owns no symbol to take an address of, so its runner's registry is empty at activation and its
# five courts are `pending` with the subphase that lands each. The ledger measures its
# contract-unit states from the courts registry, so the runner does not bind the ledger (the edge
# runs ledger -> courts, the reverse of Phase 16's). `docs/PHASE-19-SUBPHASES.md` section 4 records
# the activation measurement and the precondition it places on the runner.
PHASE19_COURTS = "artifacts/phase19/COURTS.json"
PHASE19_OBLIGATIONS = "forensics/phase19-obligations.json"
PHASE19_MODULES = [
    "docs/PHASE-19-SUBPHASES.md",
    "forensics/tools/phase19_obligations.py",
]

# Phase 20 is the 3.6.4 custodian seal stratum, and **it owns no exported symbol**: reading
# `forensics/atlas/symbol-ownership.json` for `owner_phase == 20` yields no record, so its ledger's
# unit is not a symbol. `forensics/phase20-obligations.json` records its unit as `custodian seal
# contract` (in `atlas_common.NON_EXPORT_UNITS`, so the export-partitioning tools skip it, as they
# skip Phase 16's `cli-config contract`, Phase 17's `downstream replacement contract`, Phase 18's
# `hostile hardening contract` and Phase 19's `performance dispatch contract`), and its working set
# is five contract units -- the maturity derivation, the receipt closure, the residual disposition,
# the substitution witness and the custodian-boundary register. Like Phases 18 and 19 it hands
# nothing forward and receives nothing: it owns no provider registration row, no symbol deferral
# and no prerequisite unit, because it compiles the custodian claim over the implementation the
# strata before it completed rather than adding library surface. It registers no coverage-reference
# probe, because it owns no symbol to take an address of, so its runner's registry is empty at
# activation and its five courts are `pending` with the subphase that lands each. The ledger
# measures its contract-unit states from the courts registry, so the runner does not bind the
# ledger (the edge runs ledger -> courts, the reverse of Phase 16's). A passing court is an
# *instrument*: the property it names may still carry findings, and the stratum makes no claim
# stronger than `docs/CUSTODIAN_CONTRACT.md` section 6's -- no FIPS validation, no universal parity
# from finite evidence and no claim that memory safety is established. `docs/PHASE-20-SUBPHASES.md`
# section 4 records the activation measurement and the precondition it places on the runner.
PHASE20_COURTS = "artifacts/phase20/COURTS.json"
PHASE20_OBLIGATIONS = "forensics/phase20-obligations.json"
PHASE20_MODULES = [
    "docs/PHASE-20-SUBPHASES.md",
    "forensics/tools/phase20_obligations.py",
    # Phase 20 owns no FRF-declarable court -- its five custodian courts stage no probe and validate
    # committed evidence -- so the FRF/Gemel chain rule is correctly vacuous for it and cannot be the
    # stratum's closing evidence. Its seal document is, exactly as it is for Phases 3 through 7: the
    # stratum stays `in-progress` until 20.6 writes this file, so a passing register at 20.5 cannot
    # be read as the finished custodian seal.
    "docs/PHASE-20-CUSTODIAN-SEAL.md",
]

# Phase 21 is the maintenance delta machinery stratum, and **it owns no exported symbol**: reading
# `forensics/atlas/symbol-ownership.json` for `owner_phase == 21` yields no record, so its ledger's
# unit is not a symbol. `forensics/phase21-obligations.json` records its unit as `maintenance delta
# contract` (in `atlas_common.NON_EXPORT_UNITS`, so the export-partitioning tools skip it, as they
# skip Phase 16's `cli-config contract`, Phase 17's `downstream replacement contract`, Phase 18's
# `hostile hardening contract`, Phase 19's `performance dispatch contract` and Phase 20's `custodian
# seal contract`), and its working set is five contract units -- the authority admission, the atlas
# delta, the delta disposition, the affected-court selection and the maintenance-boundary register.
# Like Phases 18 through 20 it hands nothing forward and receives nothing: it owns no provider
# registration row, no symbol deferral and no prerequisite unit, because it computes the delta
# between two authorities that are already admitted rather than adding library surface. It registers
# no coverage-reference probe, because it owns no symbol to take an address of, so its runner's
# registry is empty at activation and its five courts are `pending` with the subphase that lands
# each. The ledger measures its contract-unit states from the courts registry, so the runner does not
# bind the ledger (the edge runs ledger -> courts, the reverse of Phase 16's). A passing court is an
# *instrument*: the property it names may still carry findings, and the stratum makes no
# version-universality claim -- OpenSSL 4.x is a new compatibility profile and a 3.x receipt is never
# silently reinterpreted as evidence for 4, only the exercised delta is claimed, and unknown stays
# unknown. `docs/PHASE-21-SUBPHASES.md` section 4 records the activation measurement and the
# precondition it places on the runner.
PHASE21_COURTS = "artifacts/phase21/COURTS.json"
PHASE21_OBLIGATIONS = "forensics/phase21-obligations.json"
PHASE21_MODULES = [
    "docs/PHASE-21-SUBPHASES.md",
    "forensics/tools/phase21_obligations.py",
    # Phase 21 owns no FRF-declarable court -- its five delta courts stage no probe and read
    # committed evidence -- so the FRF/Gemel chain rule is correctly vacuous for it and cannot be the
    # stratum's closing evidence. Its seal document is, exactly as it is for Phases 3 through 7 and
    # for Phase 20: the stratum stays `in-progress` until 21.6 writes this file, so a passing
    # register at 21.5 cannot be read as the finished maintenance delta machinery.
    "docs/PHASE-21-MAINTENANCE-SEAL.md",
]

# Phase 22 is an *atlas* stratum, not an export stratum, so its evidence is not the same shape as
# every other stratum's: no export universe, no ownership projection and no provider row. What it
# owes instead is the plan, the residual ledger its closure produces, the atlas's own courts and
# the seal. `docs/PHASE-22-SUBPHASES.md` sections 7 and 8 are the rule and the claim.
PHASE22_MODULES = [
    "docs/PHASE-22-SUBPHASES.md",
]
PHASE22_LEDGER = "forensics/phase22-obligations.json"
PHASE22_COURTS = "artifacts/phase22/COURTS.json"
PHASE22_CLOSURE = "forensics/atlas/phase22/compatibility-closure.json"
PHASE22_SEAL = "docs/PHASE-22-ATLAS-SEAL.md"

# Phase 23 is the multitrack authority stratum, and **it owns no exported symbol**: reading
# `forensics/atlas/symbol-ownership.json` for `owner_phase == 23` yields no record, so its ledger's
# unit is not a symbol. `forensics/phase23-obligations.json` records its unit as `multitrack
# authority contract` (in `atlas_common.NON_EXPORT_UNITS`, so the export-partitioning tools skip it,
# as they skip Phase 16's `cli-config contract` through Phase 21's `maintenance delta contract`), and
# its working set is seventeen contract units -- one per subphase 23.1 through 23.17: the release-node
# catalogue, the authority-node registry, the parameterized atlases, the lineage edges, the entity
# lineage, the delta engine, the ABI/history façades, the semantic multitrack courts, the
# compatibility views, the historical population, the downstream multitrack court, the directional
# compatibility edges, the negative obligations, the security lineage, the support-status ladder, the
# compatibility matrix and the multitrack seal.
# Like Phases 18 through 21 it hands nothing forward and receives nothing: it owns no provider
# registration row, no symbol deferral and no prerequisite unit, because it emits compatibility
# *views* over releases and authorities that are already admitted rather than adding library surface.
# It registers no coverage-reference probe, because it owns no symbol to take an address of, so its
# runner's registry was empty at activation (23.0); each later subphase registers its court in the
# commit that lands it, and a court still unregistered is `pending` with the subphase that lands it.
# The ledger measures its contract-unit states from the courts registry, so the runner
# does not bind the ledger (the edge runs ledger -> courts, the reverse of Phase 16's). A passing
# court is an *instrument*: the property it names may still carry findings. The stratum makes no
# one-boolean compatibility claim -- compatibility is directional and dimension-specific, receipt
# inheritance across versions is forbidden, and a historical vulnerability is observed but never
# reintroduced. `docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 0 records the activation measurement
# and the precondition it places on the runner.
PHASE23_COURTS = "artifacts/phase23/COURTS.json"
PHASE23_OBLIGATIONS = "forensics/phase23-obligations.json"
PHASE23_MODULES = [
    "docs/PHASE-23-MULTITRACK-SUBPHASES.md",
    "forensics/tools/phase23_obligations.py",
    # The schemas the later subphases populate. They are authored evidence from 23.0, and the
    # runner binds them as an input, so the stratum's record types are a file the evidence
    # points at rather than prose this module would have to restate.
    "forensics/tools/multitrack_schemas.py",
    # Phase 23 owns no FRF-declarable court -- its seventeen courts stage no probe and read committed
    # evidence, exactly as Phase 21's delta courts do -- so the FRF/Gemel chain rule is correctly
    # vacuous for it and cannot be the stratum's closing evidence. Its seal document is, exactly as
    # it is for Phases 3 through 7 and for Phases 20 and 21: the stratum stays `in-progress` until
    # 23.17 writes this file, so a passing matrix at 23.16 cannot be read as the finished multitrack
    # authority.
    "docs/PHASE-23-MULTITRACK-SEAL.md",
]


STRATUM_EVIDENCE: dict[int, StratumEvidence] = {
    3: StratumEvidence(PHASE3_MODULES, PHASE3_OBLIGATIONS, PHASE3_COURTS,
                       ledger_note=(
                           "The ledger reads its universe from the ownership atlas, so "
                           "this is no longer a question of which prefixes its families "
                           "happened to list (docs/DECISIONS.md D97)"
                       )),
    4: StratumEvidence(PHASE4_MODULES, PHASE4_OBLIGATIONS, PHASE4_COURTS),
    5: StratumEvidence(PHASE5_MODULES, PHASE5_OBLIGATIONS, PHASE5_COURTS),
    6: StratumEvidence(PHASE6_MODULES, PHASE6_OBLIGATIONS, PHASE6_COURTS),
    7: StratumEvidence(PHASE7_MODULES, PHASE7_OBLIGATIONS, PHASE7_COURTS),
    8: StratumEvidence(PHASE8_MODULES, PHASE8_OBLIGATIONS, PHASE8_COURTS),
    9: StratumEvidence(PHASE9_MODULES, PHASE9_OBLIGATIONS, PHASE9_COURTS,
                       ledger_note=(
                           "Twenty-five of the exports it owns are its own header's and the "
                           "remainder arrive as recorded hand-offs from phases 4, 5, 7 and 8, "
                           "so the stratum's work lives in earlier strata's modules "
                           "(docs/DECISIONS.md D294). Courts have landed since this note was "
                           "first written; the registered set and its observation counts are "
                           "`artifacts/phase9/COURTS.json` and the ledger's own `courts` block, "
                           "and this note defers to them rather than restating counts that move."
                       )),
    10: StratumEvidence(PHASE10_MODULES, PHASE10_OBLIGATIONS, PHASE10_COURTS,
                        ledger_note=(
                            "Two hundred and seventy-two of the exports it owns are its own "
                            "four headers' (`pkcs12.h`, `store.h`, `decoder.h`, `encoder.h`) and "
                            "the twenty-six remainder arrive as recorded hand-offs from phases "
                            "5 and 7. Eighty-seven of the working set are already implemented, "
                            "landed by Phase 8's 8.8 chain rather than by this stratum, so the "
                            "ledger's `open` count is not the whole working set "
                            "(docs/PHASE-10-SUBPHASES.md section 4)"
                        )),
    11: StratumEvidence(PHASE11_MODULES, PHASE11_OBLIGATIONS, PHASE11_COURTS,
                        ledger_note=(
                            "One thousand four hundred and fifty-five of the exports it owns "
                            "are its own five headers' (`x509.h`, `x509v3.h`, `x509_vfy.h`, "
                            "`x509_acert.h`, `pem.h`) and the twelve remainder arrive as "
                            "recorded hand-offs from phases 5 and 7. The ledger does not start "
                            "with that whole working set open: exports Phase 8's 8.8 chain and "
                            "Phase 10's pulled-forward X.509 subphases landed, and two Phase 5 "
                            "hand-offs, are reported as `implemented` at activation, so its "
                            "`open` count is not the whole working set. That split moves as "
                            "this stratum lands its own units, so this note does not restate "
                            "its counts; the ledger's `counts` and `forensics/atlas/"
                            "implemented-surface.json` are the live record. The stratum owns "
                            "no provider registration row (docs/PHASE-11-SUBPHASES.md "
                            "sections 1 and 4)"
                        )),
    12: StratumEvidence(PHASE12_MODULES, PHASE12_OBLIGATIONS, PHASE12_COURTS,
                        ledger_note=(
                            "One thousand and twenty-four of the exports it owns are its own "
                            "twelve headers' (`ts.h`, `ocsp.h`, `cmp.h`, `cms.h`, `pkcs7.h`, "
                            "`crmf.h`, `ct.h`, `ess.h`, `srp.h`, `http.h`, `cmp_util.h`, "
                            "`pem.h`) and the nine remainder arrive as recorded hand-offs from "
                            "phases 5 and 11. The ledger does not start with that whole working "
                            "set open: the `ocsp_asn.c` item group, the CT `ct_*` units, "
                            "`pk7_asn1.c`/`pk7_lib.c` and `http_lib.c`'s `OSSL_parse_url` are "
                            "reported as `implemented` at activation, so its `open` count is "
                            "not the whole working set. That split moves as this stratum lands "
                            "its own units, so this note does not restate its counts; the "
                            "ledger's `counts` and `forensics/atlas/implemented-surface.json` "
                            "are the live record. The stratum owns no provider registration "
                            "row (docs/PHASE-12-SUBPHASES.md sections 1 and 4)"
                        )),
    13: StratumEvidence(PHASE13_MODULES, PHASE13_OBLIGATIONS, PHASE13_COURTS,
                        ledger_note=(
                            "One hundred and eighty-nine of the exports it owns are its own "
                            "three headers' (`engine.h`, `ui.h`, `txt_db.h`) and the one "
                            "hundred and eighty-eight remainder arrive as recorded hand-offs "
                            "from phases 3, 7 and 12 -- the deprecated METHOD-era EVP statics "
                            "and PEM readers, the ASYNC framework, and the three Phase 12 rows "
                            "`TS_CONF_set_crypto_device`, `TS_CONF_set_default_engine` and "
                            "`SRP_VBASE_init`. The ledger does not start with that whole working "
                            "set open: 123 atlas-owned exports and the four Phase 7 -> 13 "
                            "`PEM_read[_bio]_PrivateKey` spellings are reported as `implemented` "
                            "at activation, so its `open` count is not the whole working set. "
                            "That split moves as this stratum lands its own units, so this note "
                            "does not restate its counts; the ledger's `counts` and "
                            "`forensics/atlas/implemented-surface.json` are the live record. The "
                            "stratum owns no provider registration row: the 39 legacy digest and "
                            "cipher rows of `providers/legacyprov.c` are the loadable module the "
                            "candidate ships as a scaffold `ossl-modules/legacy.so`, handed to the "
                            "distribution stratum (Phase 16) because this stratum's subphases do "
                            "not activate it (docs/PHASE-13-SUBPHASES.md sections 1 and 4)"
                        )),
    14: StratumEvidence(PHASE14_MODULES, PHASE14_OBLIGATIONS, PHASE14_COURTS,
                        ledger_note=(
                            "All six hundred of the exports it owns are its own four headers' "
                            "(`ssl.h` 582, `tls1.h` 13, `srtp.h` 4, `sslerr_legacy.h` 1) and no "
                            "earlier stratum's ledger records a hand-off to it, so its working "
                            "set is exactly the atlas projection -- the first stratum that "
                            "inherits nothing. **Unlike every earlier activation, not one of the "
                            "six hundred is implemented at activation**: libssl is the candidate "
                            "distribution's second namespace and its exports are present only "
                            "as the Phase 2 ABI scaffold, so its `open` count is its whole "
                            "working set. That split moves as this stratum lands its own units, "
                            "so this note does not restate its counts; the ledger's `counts` and "
                            "`forensics/atlas/implemented-surface.json` are the live record. The "
                            "stratum owns no provider registration row: libssl is not a provider "
                            "and this stratum activates none (docs/PHASE-14-SUBPHASES.md "
                            "sections 1 and 4)"
                        )),
    15: StratumEvidence(PHASE15_MODULES, PHASE15_OBLIGATIONS, PHASE15_COURTS,
                        ledger_note=(
                            "All three of the exports it owns are its own header's "
                            "(`quic.h`), and no earlier stratum's ledger records a hand-off to "
                            "it, so its working set is exactly the atlas projection: "
                            "`OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and "
                            "`OSSL_QUIC_server_method`. Its plan and seal record that the QUIC "
                            "object and the TLS message layer are not this unit's, and the two "
                            "authority units `forensics/prerequisites.json` defers to it "
                            "(`ssl/statem/statem_clnt.c`, `ssl/statem/statem_srvr.c`) are unit "
                            "deferrals for the prerequisite gate, not export hand-offs. That "
                            "split moves as this stratum lands its own units, so this note "
                            "does not restate its counts; the ledger's `counts` and "
                            "`forensics/atlas/implemented-surface.json` are the live record. "
                            "The stratum owns no provider registration row: QUIC is not a "
                            "provider and this stratum activates none "
                            "(docs/PHASE-15-SUBPHASES.md sections 1 and 4)"
                        )),
    16: StratumEvidence(PHASE16_MODULES, PHASE16_OBLIGATIONS, PHASE16_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase16-obligations.json` publishes "
                            "`unit: cli-config contract` and its `implemented`/`open` *export* "
                            "lists are empty by measurement, while `open_in_this_stratum` "
                            "counts the 39 legacy provider registration rows it owns, the "
                            "prerequisite deferrals and the three CLI/config/filesystem contract "
                            "units. The provider-row rule below no longer holds it open: "
                            "16.1's three slices published all 39 `providers/legacyprov.c` rows "
                            "(`provider_rows_open` 0), and 16.2/16.3 retired the dynamic-ENGINE "
                            "loader and the two `OPENSSLDIR`/install-context deferrals, so the "
                            "CLI capture defect, the two message-layer units and the CLI contract "
                            "unit are what remains. Its "
                            "`artifacts/phase16/COURTS.json` "
                            "registered no court at activation because it owns no symbol for a "
                            "differential probe to observe; 16.1/16.2/16.3 registered "
                            "`RT-LEGACY-MODULE`, `RT-ENGINE-DYN` and `RT-DEFAULTS`, and the "
                            "remaining three are "
                            "`pending` with the subphases that land them. "
                            "`docs/PHASE-16-SUBPHASES.md` sections 1 and 4 record the "
                            "measurement (docs/DECISIONS.md D485, D525, D528)"
                        )),
    17: StratumEvidence(PHASE17_MODULES, PHASE17_OBLIGATIONS, PHASE17_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase17-obligations.json` publishes "
                            "`unit: downstream replacement contract` and its `implemented`/`open` "
                            "*export* lists are empty by measurement, while `open_in_this_stratum` "
                            "counts the 52 `apps/<name>.c` unit deferrals it owns (D530) and the "
                            "five downstream replacement contract units (`command-bodies`, "
                            "`tls13-interop`, `cross-dso-state`, `downstream-consumer` and the "
                            "machine-owned `downstream-corpus`). It owns no provider registration "
                            "row -- it activates no provider -- and no symbol deferral. Its "
                            "sealed `artifacts/phase17/COURTS.json` registers **six** courts: the "
                            "five differential courts `RT-CLI-BODIES`, `RT-TLS13-INTEROP`, "
                            "`RT-TLS13-INTEROP-MATRIX`, `RT-CROSS-DSO-STATE` and "
                            "`RT-DOWNSTREAM-CONSUMER`, and the data-validation "
                            "`RT-DOWNSTREAM-CORPUS`, whose row is marked `frf_declarable: false` "
                            "because it consumes the recorded downstream records and stages no "
                            "probe pair, so the FRF chain requires the five declarable ones. "
                            "The corpus is the seal's mechanical dependency: `phase_state.py` "
                            "blocks the stratum on any non-`pass` court in "
                            "`artifacts/phase17/COURTS.json`, so a program whose `functional` is "
                            "false, a missing required field or a recorded `candidate` that is "
                            "not the current `Cargo.toml` version fails the stratum rather than "
                            "the corpus alone. The ledger's contract-unit states are measured "
                            "from the courts registry, so the runner does not bind the ledger "
                            "and the edge runs ledger -> courts, the reverse of Phase 16's. "
                            "`docs/PHASE-17-SUBPHASES.md` and "
                            "`docs/PHASE-17-DOWNSTREAM-SEAL.md` record the measurement and the "
                            "chain (docs/DECISIONS.md D530)"
                        )),
    18: StratumEvidence(PHASE18_MODULES, PHASE18_OBLIGATIONS, PHASE18_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase18-obligations.json` publishes "
                            "`unit: hostile hardening contract` and its `implemented`/`open` "
                            "*export* lists are empty by measurement, while "
                            "`open_in_this_stratum` counts the five contract units "
                            "(`hostile-tls`, `hostile-x509`, `constant-time`, "
                            "`memory-hardening` and `hostile-boundary-register`). It owns no "
                            "provider registration row, no symbol deferral and no prerequisite "
                            "unit: it activates no provider and adds no library surface, because "
                            "it hardens the implementation Phases 3 through 15 completed. Its "
                            "`artifacts/phase18/COURTS.json` landed `RT-HOSTILE-TLS` in 18.1 -- "
                            "the fixed malformed-input corpus driven through the record layer and "
                            "the TLS 1.3 flight with crash/OOM/timeout detection and an "
                            "authority-linked differential control -- and `RT-HOSTILE-X509` in "
                            "18.2 -- the fixed malformed-input corpus driven through the X.509, "
                            "ASN.1 and PEM readers with the same detection and an "
                            "authority-linked differential control -- and `CT-PRIMITIVES` in "
                            "18.3, the candidate-only secret-independence screen over the "
                            "primitive-bearing paths (BN, RSA, EC, the AEADs and the TLS key "
                            "schedule) whose section-3.2 sensitivity control a deliberately "
                            "branch-on-secret tag comparison is caught by; that probe records the "
                            "reduced engine's BN square-and-multiply core as separating its two "
                            "secret classes (`bn-modexp`, `bn-inverse`) as **findings** rather "
                            "than failing, because `src/bn/exp.rs` documents that timing "
                            "profile, and the court's pass is the instrument's proven "
                            "sensitivity plus a bounded screen at its stated resolution, not a "
                            "claim that the paths are constant-time. `RT-MEM-HARDENING` landed "
                            "in 18.4: the fixed-buffer boundary court drives "
                            "`SSL3_RT_MAX_PLAIN_LENGTH` (16384) on the record write path -- the "
                            "previous greater-than-16-KiB overflow's concrete case, now "
                            "fragmented and round-tripped at, below and above the capacity -- "
                            "the `TLS13_HS_BUF_LEN` (16384) handshake-reassembly buffer and the "
                            "`Ssl::rec_body` (17000) store at, below and above each capacity, "
                            "each case in its own forked child against both sides, with an "
                            "explicit injected-failure control that lowers `RLIMIT_DATA` and "
                            "observes the allocation fail and be handled "
                            "(`ERR_R_MALLOC_FAILURE`, a NULL `d2i_X509`). A buffer that is "
                            "merely unsafe to use -- `tls13_encrypt_record`'s inner buffer, "
                            "which the fragmenting caller bounds but whose own contract does "
                            "not -- is recorded, not silently fixed. `HOSTILE-BOUNDARY-REGISTER` "
                            "landed in 18.5: the authored register "
                            "`artifacts/phase18/hostile-boundary-register.json` records, per "
                            "surface, whether it is `hardened` (a change landed), `measured` (a "
                            "passing court covers it) or `not-claimed` (explicitly outside this "
                            "stratum), and the register court re-reads the live courts registry "
                            "and fails the stratum if a recorded classification, capacity or "
                            "count has drifted from what the courts show. So all five contract "
                            "units are `implemented` and `open_in_this_stratum` has moved from "
                            "one to zero. The 18.6 seal `docs/PHASE-18-HARDENING-SEAL.md` lands "
                            "with the FRF chain the release gates require: its three declarable "
                            "courts (`rt-hostile-tls`, `rt-hostile-x509`, `rt-mem-hardening`) are "
                            "declared in `gen_frf_courts.py`, each carries a receipt and two "
                            "adjudicated challenges, and one `sensitivity-backed` claim "
                            "`ce672949dc8d06ea18b1969c829e7c6314cd8bc2d431975be3cfbfcc72db2e2a` "
                            "binds authority `openssl-rt-3.6.4-r2` to candidate `openssl-rs "
                            "0.0.22` (`e4f60d8b`) with zero blockers -- `CT-PRIMITIVES` is "
                            "candidate-only and `HOSTILE-BOUNDARY-REGISTER` validates data, so "
                            "neither is declarable (D13, D201). The ledger's contract-unit "
                            "states are measured from the courts registry, so the runner does "
                            "not bind the ledger and the edge runs ledger -> courts, the reverse "
                            "of Phase 16's. `docs/PHASE-18-SUBPHASES.md` sections 1, 3 and 4 and "
                            "`docs/PHASE-18-HARDENING-SEAL.md` record the measurement and the "
                            "chain"
                        )),
    19: StratumEvidence(PHASE19_MODULES, PHASE19_OBLIGATIONS, PHASE19_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase19-obligations.json` publishes "
                            "`unit: performance dispatch contract` and its `implemented`/`open` "
                            "*export* lists are empty by measurement, while "
                            "`open_in_this_stratum` counts the five contract units "
                            "(`cpu-capability`, `evp-dispatch`, `performance-work`, "
                            "`performance-sensitivity` and `performance-boundary-register`). It "
                            "owns no provider registration row, no symbol deferral and no "
                            "prerequisite unit: it activates no provider and adds no library "
                            "surface, because it measures the implementation the strata before "
                            "it completed. Its `artifacts/phase19/COURTS.json` landed "
                            "`RT-CPU-CAPABILITY` in 19.1 -- the CPU-capability surface "
                            "(`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`) "
                            "driven under fixed and faulted CPUID facades against the authority, "
                            "with an authority-linked differential control -- and `RT-EVP-DISPATCH` "
                            "in 19.2 -- the selection surface (the legacy constructor, the provider "
                            "fetch, the legacy name lookup and the cipher/digest context) driven "
                            "over the same fixed capability sets, where masking the AES-NI bit "
                            "moves the authority's `AES-*-CBC-HMAC-*` selection and the candidate's "
                            "does not -- and `RT-PERFORMANCE-WORK` in 19.3 -- the deterministic "
                            "work vector over a fixed primitive set (AES-128/256-CBC/GCM, "
                            "ChaCha20-Poly1305, SHA-256, a P-256 scalar multiplication and an "
                            "RSA-1024 private decrypt), measured by a counting `CRYPTO` allocator "
                            "the stratum introduces plus the method-derived block/output/tag "
                            "sizes, with the EC and RSA paths recording a divergent-work `finding` "
                            "and the symmetric/digest paths agreeing -- and `RT-PERFORMANCE-SENSITIVITY` "
                            "in 19.4 -- the candidate-only instrument-sensitivity control, where a "
                            "deliberately slowed `control-extra-pass` variant of `aes-128-cbc` (an "
                            "injected extra full pass over the primitive in the harness, never product "
                            "code) is caught on the counting allocator the stratum introduces while the "
                            "reference arm matches the authority's recorded vector, so the instrument "
                            "is proven able to tell a slow path from a fast one -- and "
                            "`PERFORMANCE-BOUNDARY-REGISTER` in 19.5 -- the performance-boundary "
                            "register, which reads the authored "
                            "`artifacts/phase19/performance-boundary-register.json` against the four "
                            "probe-court records and fails the stratum if a measured row's court no "
                            "longer covers its surface, a not-measured or not-claimed row a passing "
                            "court now covers, or a stated count/evidence value has moved, recording "
                            "what is measured, what is not (the ENGINE path, the three capability "
                            "names the candidate does not implement) and the explicit non-claims "
                            "(no benchmark-parity claim, no assembly-versus-Rust equivalence claim) "
                            "-- so all five contract units are `implemented` and "
                            "`open_in_this_stratum` is zero. Nothing here is a throughput or parity "
                            "claim: there is no benchmark-parity claim and no "
                            "assembly-versus-Rust equivalence claim, and no verdict is ever "
                            "taken from wall-clock time alone. The ledger records two axes "
                            "separately -- "
                            "`measurement_state` says the instrument completed and "
                            "`property_status`/`findings` say what is claimed -- so a passing "
                            "`RT-PERFORMANCE-WORK` is an instrument plus bounded "
                            "deterministic-work comparison and must never be read as "
                            "'performance parity achieved'. The ledger's contract-unit states "
                            "are measured from the courts registry, so the runner does not bind "
                            "the ledger and the edge runs ledger -> courts, the reverse of "
                            "Phase 16's. The 19.6 seal `docs/PHASE-19-PERFORMANCE-SEAL.md` lands "
                            "with the FRF chain the release gates require: its three declarable "
                            "courts (`rt-cpu-capability`, `rt-evp-dispatch`, "
                            "`rt-performance-work`) are declared in `gen_frf_courts.py`, each "
                            "carries a receipt and two adjudicated challenges, and one "
                            "`sensitivity-backed` claim "
                            "`63f910ced5baf43c6dc30b2da63996fb3fb0e1b1334e8d89be2f5ad23c528af8` binds "
                            "authority `openssl-rt-3.6.4-r2` to candidate `openssl-rs 0.0.23` "
                            "(`e4f60d8b`) with zero blockers -- `RT-PERFORMANCE-SENSITIVITY` is "
                            "candidate-only (its row carries `frf_declarable` false) and "
                            "`PERFORMANCE-BOUNDARY-REGISTER` validates data, so neither is "
                            "declarable (D13, D201). `docs/PHASE-19-SUBPHASES.md` sections 1 and 4 "
                            "and `docs/PHASE-19-PERFORMANCE-SEAL.md` record the measurement and "
                            "the chain"
                        )),
    20: StratumEvidence(PHASE20_MODULES, PHASE20_OBLIGATIONS, PHASE20_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase20-obligations.json` publishes "
                            "`unit: custodian seal contract` and its `implemented`/`open` "
                            "*export* lists are empty by measurement, while "
                            "`open_in_this_stratum` counts the five contract units "
                            "(`custodian-maturity`, `receipt-closure`, `custodian-residuals`, "
                            "`substitution-witness` and `custodian-boundary-register`). It "
                            "owns no provider registration row, no symbol deferral and no "
                            "prerequisite unit: it activates no provider and adds no library "
                            "surface, because it compiles the custodian claim over the "
                            "implementation the strata before it completed. Its "
                            "`artifacts/phase20/COURTS.json` lands its five courts with the "
                            "subphases that build their instruments: 20.1's "
                            "`RT-CUSTODIAN-MATURITY` is registered and passing -- it derives the "
                            "L0-L9 maturity ladder from committed evidence and records the L9 gap "
                            "as a finding, so its property reads NOT_CLAIMED -- and 20.2's "
                            "`RT-RECEIPT-CLOSURE` is registered and passing: it joins every "
                            "obligation the in-scope strata recorded `implemented` or closed to "
                            "the FRF receipt that proves it and requires the covering "
                            "`sensitivity-backed` claim in the FRF store to carry zero blockers, "
                            "recording zero findings because the closure is complete -- and 20.3's "
                            "`RT-CUSTODIAN-RESIDUALS` is registered and passing: it dispositions "
                            "every residual the earlier strata and the FRF store record, requiring a "
                            "disposition for each and no `UNKNOWN` residual to intersect the claimed "
                            "production profile. On the current tree there are 334 `UNKNOWN` "
                            "residual records -- the 167 POD_NAME_NOT_IN_ATLAS names the pod-contract "
                            "plane carries, re-projected by two registers (the Phase-22 cross-plane "
                            "census and the checkpoint's named `UNKNOWN` sets) -- and the closure "
                            "records that zero of them intersect a declared compatibility root, so the "
                            "residual court records zero findings too -- and 20.4's "
                            "`RT-SUBSTITUTION-WITNESS` is registered and passing: it records the "
                            "ABI-substitution witness chain (the Phase-2 ABI-SUBSTITUTION, ABI-LOAD "
                            "and ABI-LINK courts) and the machine-owned downstream corpus witness "
                            "chain (the six Phase-17 programs curl, git, haproxy, nginx, openssh and "
                            "python), re-establishing the corpus as current and functional rather "
                            "than assuming it and recording, per witness, the binary it was built "
                            "against, the run that exercised it and the observation it produced. The "
                            "Phase-17 driver has no cheap verify/currency mode, so the court "
                            "re-derives currency (candidate 0.0.24) and functional status from the "
                            "machine-owned records rather than re-running the harnesses, and "
                            "records zero findings -- and 20.5's `CUSTODIAN-BOUNDARY-REGISTER` is "
                            "registered and passing: it binds the authored register "
                            "artifacts/phase20/custodian-boundary-register.json, recording, per "
                            "surface, whether it is `claimed` (a passing court covers it) or "
                            "`bounded` (explicitly outside this stratum). It re-reads the four "
                            "custodian courts' records and the constitution/limitations artefacts "
                            "-- `docs/NON_CLAIMS.md`, `docs/FIPS_CLAIMS.md`, `docs/UNSAFE.md` and the "
                            "unsafe-footprint growth ceiling -- and fails the stratum if a recorded "
                            "boundary has drifted from its evidence, carrying the three "
                            "load-bearing non-claims as bounded rows: no FIPS validation, no "
                            "universal parity from finite evidence, and memory safety measured "
                            "rather than established. So all five contract units are `implemented` "
                            "and `open_in_this_stratum` is zero. 20.6's seal "
                            "docs/PHASE-20-CUSTODIAN-SEAL.md is the stratum's closure: it owns no "
                            "FRF-declarable court, so the FRF/Gemel chain rule is correctly vacuous "
                            "for it and its seal document is the required evidence, which has landed "
                            "-- exactly as for Phases 3 through 7. A passing court is an **instrument**, not a "
                            "property claim: the property it names may still carry findings, so "
                            "`measurement_state` says the instrument completed while "
                            "`property_status`/`findings` say what is claimed. The stratum "
                            "makes no claim stronger than `docs/CUSTODIAN_CONTRACT.md` section "
                            "6's -- in particular no FIPS validation, no universal parity from "
                            "finite evidence and no claim that memory safety is established "
                            "(`docs/NON_CLAIMS.md`) -- and a passing `RT-CUSTODIAN-MATURITY` "
                            "must never be read as 'L9 custodian seal achieved'. The ledger's "
                            "contract-unit states are measured from the courts registry, so "
                            "the runner does not bind the ledger and the edge runs ledger -> "
                            "courts, the reverse of Phase 16's. `docs/PHASE-20-SUBPHASES.md` "
                            "sections 1 and 4 record the measurement"
                        )),
    21: StratumEvidence(PHASE21_MODULES, PHASE21_OBLIGATIONS, PHASE21_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase21-obligations.json` publishes "
                            "`unit: maintenance delta contract` and its `implemented`/`open` "
                            "*export* lists are empty by measurement, while "
                            "`open_in_this_stratum` counts the five contract units "
                            "(`authority-admission`, `atlas-delta`, `delta-disposition`, "
                            "`affected-court-selection` and `maintenance-boundary-register`). It "
                            "owns no provider registration row, no symbol deferral and no "
                            "prerequisite unit: it activates no provider and adds no library "
                            "surface, because it computes the delta between two authorities that "
                            "are already admitted. Its `artifacts/phase21/COURTS.json` registers "
                            "all five courts, and all pass: `RT-AUTHORITY-ADMISSION` (21.1) records "
                            "the delta's input pair, `RT-ATLAS-DELTA` (21.2) recomputes the added / "
                            "removed / changed delta across the atlas planes the procedure names -- "
                            "the exports plane measured, the provider registration-row and "
                            "prerequisite-unit planes named `not-measured` with their reasons rather "
                            "than counted motionless -- `RT-DELTA-DISPOSITION` (21.3) dispositions "
                            "every delta row against the candidate's own installed surface, a "
                            "measured row `implemented` only when that surface carries it, a "
                            "`not-measured` plane or axis `boundary`, and a `removed`/`changed` row "
                            "the candidate carries a finding rather than a disposition -- "
                            "`RT-AFFECTED-COURT-SELECTION` (21.4) derives, mechanically from the "
                            "dispositioned delta and the coverage atlas's export -> court edge, "
                            "which courts each moving row reaches, re-deriving exactly those courts "
                            "-- and 21.5's `MAINTENANCE-BOUNDARY-REGISTER` is registered and "
                            "passing: it binds the authored register "
                            "artifacts/phase21/maintenance-boundary-register.json, recording, per "
                            "surface, whether it is `claimed` (a passing court covers it) or "
                            "`bounded` (explicitly outside this stratum). It re-reads the four "
                            "delta courts' records and the constitution/limitations artefacts -- "
                            "`docs/RELEASE_GATES.md` section 8, `docs/NON_CLAIMS.md`, "
                            "`docs/PARITY_MODEL.md` section 1, `docs/SECURITY_DIVERGENCE_POLICY.md` "
                            "and the two planes RT-ATLAS-DELTA recorded `not-measured` -- and fails "
                            "the stratum if a recorded boundary has drifted from its evidence, "
                            "carrying the load-bearing non-claims as bounded rows: OpenSSL 4.x is "
                            "a new compatibility profile and a 3.x receipt is never silently "
                            "reinterpreted as evidence for 4, only the exercised delta is claimed, "
                            "unknown stays unknown, the provider registration-row and "
                            "prerequisite-unit planes are bounded rather than motionless with what "
                            "would make each measurable, and a 3.6.3 behaviour that corresponds to "
                            "an upstream security fix is not reintroduced. So all five contract "
                            "units are `implemented` and `open_in_this_stratum` is zero. "
                            "21.6's seal docs/PHASE-21-MAINTENANCE-SEAL.md is the stratum's "
                            "closure: it owns no FRF-declarable court, so the FRF/Gemel chain "
                            "rule is correctly vacuous for it and its seal document is the "
                            "required evidence, which has landed -- exactly as for Phases 3 "
                            "through 7. "
                            "A passing court is an "
                            "**instrument**, not a "
                            "property claim: the property it names may still carry findings, so "
                            "`measurement_state` says the instrument completed while "
                            "`property_status`/`findings` say what is claimed. The stratum "
                            "makes no version-universality claim: OpenSSL 4.x is a new "
                            "compatibility profile and a 3.x receipt is never silently "
                            "reinterpreted as evidence for 4 (`docs/RELEASE_GATES.md` section 8, "
                            "`docs/NON_CLAIMS.md` section 3), only the exercised delta is claimed, "
                            "and unknown stays unknown (`docs/PARITY_MODEL.md` section 1); a "
                            "3.6.3 behaviour that corresponds to an upstream security fix is not "
                            "reintroduced (`docs/SECURITY_DIVERGENCE_POLICY.md` section 1). The "
                            "ledger's contract-unit states are measured from the courts "
                            "registry, so the runner does not bind the ledger and the edge runs "
                            "ledger -> courts, the reverse of Phase 16's. "
                            "`docs/PHASE-21-SUBPHASES.md` sections 1 and 4 record the measurement"
                        )),
    # Phase 22's evidence is read by `evidence_for`'s own phase-22 branch rather than this row's
    # ledger shape, but the row must exist: `main` refuses a stratum with evidence on disk and no
    # row, and `docs/PHASE-22-SUBPHASES.md` is evidence from the day 22.0 lands it.
    22: StratumEvidence(PHASE22_MODULES, PHASE22_LEDGER, PHASE22_COURTS,
                        ledger_note=(
                            "This stratum's `open` count is a count of unclassified surfaces, "
                            "not of unbuilt exports; the closure and its disposition model are "
                            "docs/PHASE-22-SUBPHASES.md sections 3, 4 and 7"
                        )),
    23: StratumEvidence(PHASE23_MODULES, PHASE23_OBLIGATIONS, PHASE23_COURTS,
                        ledger_note=(
                            "This stratum owns **no exported symbol**, so its ledger's unit is "
                            "not a symbol: `forensics/phase23-obligations.json` publishes "
                            "`unit: multitrack authority contract` and its `implemented`/`open` "
                            "*export* lists are empty by measurement, while "
                            "`open_in_this_stratum` counts the seventeen contract units "
                            "(`release-nodes`, `authority-nodes`, `atlas-parameterization`, "
                            "`lineage-edges`, `entity-lineage`, `delta-engine`, "
                            "`abi-history-facades`, `semantic-courts`, `compatibility-views`, "
                            "`historical-population`, `downstream-multitrack`, "
                            "`directional-compatibility-edges`, `negative-obligations`, "
                            "`security-lineage`, `support-status`, `compatibility-matrix` and "
                            "`multitrack-seal`). It owns no provider registration row, no symbol "
                            "deferral and no prerequisite unit: it activates no provider and adds "
                            "no library surface, because it emits compatibility views over "
                            "releases and authorities that are already admitted. Its courts stage "
                            "no probe, because it owns no symbol for a differential probe to "
                            "observe: `RT-RELEASE-CATALOG` (23.1, the release catalogue and its "
                            "lineage), `RT-AUTHORITY-NODES` (23.2, the authority-node registry), "
                            "`RT-ATLAS-PARAMETERIZATION` (23.3, the parameterized atlases and the "
                            "byte-identical proof), `RT-LINEAGE-EDGES` (23.4, the typed, "
                            "directed lineage edges), `RT-ENTITY-LINEAGE` (23.5, the entity "
                            "lineage -- what became of each public entity across the covered "
                            "release pair), `RT-DELTA-ENGINE` (23.6, the semantic "
                            "compatibility delta over the canonical release-graph edges), "
                            "`RT-ABI-HISTORY-FACADES` (23.7, the compatibility-policy layer and "
                            "the historical ABI/history façades, with the historical "
                            "public-layout and prototype adapters), `RT-SEMANTIC-COURTS` "
                            "(23.8, the oracle-to-oracle and candidate-to-authority semantic "
                            "courts over a shared normalized observation vocabulary), "
                            "`RT-COMPATIBILITY-VIEWS` (23.9, the directional, dimension-specific "
                            "compatibility views whose distribution/ABI shell surface is derived "
                            "from each authority's own evidence), `RT-HISTORICAL-POPULATION` "
                            "(23.10, the historical population -- one support status per "
                            "catalogue node, with honest unavailability) and `RT-DOWNSTREAM-MULTITRACK` "
                            "(23.11, the unmodified downstream consumer per major compatibility "
                            "epoch) "
                            "are registered, and the remaining six courts are "
                            "`pending` with the subphases that land them. A "
                            "passing court is an **instrument**, not a property claim: the "
                            "property it names may still carry findings, so `measurement_state` "
                            "says the instrument completed while `property_status`/`findings` say "
                            "what is claimed. The stratum makes no one-boolean compatibility "
                            "claim: compatibility is **directional and dimension-specific** "
                            "(docs/PARITY_MODEL.md sections 3 and 4), a cross-version receipt is "
                            "never inherited, an authority is named explicitly and singularly "
                            "rather than selected by a Cargo feature, and a historical "
                            "vulnerability is observed but never reintroduced "
                            "(docs/SECURITY_DIVERGENCE_POLICY.md section 1). The stratum records "
                            "six explicit non-claims: historical API compatibility is not "
                            "security approval; reproducing an old algorithm is not recommending "
                            "it; OpenSSL compatibility is not FIPS validation "
                            "(docs/FIPS_CLAIMS.md); one platform/profile is not every "
                            "platform/profile; an archaeological source node is not runtime "
                            "parity; and upstream's ABI promise is not candidate evidence. The "
                            "ledger's "
                            "contract-unit states are measured from the courts registry, so the "
                            "runner does not bind the ledger and the edge runs ledger -> courts, "
                            "the reverse of Phase 16's. `docs/PHASE-23-MULTITRACK-SUBPHASES.md` "
                            "sections 0 and 4 and docs/DECISIONS.md D537 through D543 record the "
                            "measurement"
                        )),
}


def seal_identity(doc: str) -> str | None:
    p = REPO_ROOT / doc
    return sha256_file(p) if p.exists() else None


def deferred_rows(phase: int) -> list[str]:
    """The recorded, phase-scoped hand-offs for a stratum.

    A deferral is not a claim of parity: it names the phase that owns the
    subsystem a symbol needs. Phase 3 has one such list, produced by
    `phase3_obligations.py`, which refuses to run if any export in the Phase 3
    families is neither implemented nor listed there.
    """
    if phase != 3:
        return []
    doc = read_json(PHASE3_OBLIGATIONS)
    if not doc:
        return []
    return [
        f"{row['symbol']} -> phase {row['owning_phase']} ({row['reason']})"
        for row in doc["body"]["deferred"]
    ]


def provider_rows_for(phase: int) -> dict | None:
    """The stratum's provider registration rows, counted by the census's own `implementation_state`.

    Machine-readable rather than prose, and on every stratum's row rather than only the one in
    progress, because the *count* is what makes the obligation auditable a year from now: a
    reader can see that phase 8 owns so many rows of which so many are implemented, and the
    regression guard can watch those numbers instead of watching the state alone. `None` when the
    atlas is absent, which `evidence_for` already reports as absent evidence rather than as a zero.

    The `handed_on` count beside them is the census's projection for the same stratum: the unlanded
    rows the plan gives a *later* phase (D295).
    """
    doc = read_json(PROVIDER_ALGORITHMS)
    if not doc:
        return None
    owned = [r for r in doc["body"]["rows"] if r["owning_phase"] == phase]
    if not owned:
        return None
    by_state: dict[str, int] = {}
    for row in owned:
        by_state[row["implementation_state"]] = by_state.get(row["implementation_state"], 0) + 1
    handed_on = doc["body"].get("projection", {}).get("handed_on", {}).get(str(phase))
    return {
        "owned": len(owned),
        **{k: by_state[k] for k in sorted(by_state)},
        "handed_on": handed_on if handed_on is not None else 0,
    }


def evaluate_manual_adjudication(row: dict, states: dict[int, str] | None) -> tuple[bool | None, str]:
    """Re-evaluate a manual row's machine fact against the derived states.

    A manual `open` row's `adjudication` may rest on a machine fact: `adjudication_phase` names the
    stratum whose derived state it cites and `adjudication_requires` the state it needs. When the
    row names no fact (`adjudication_requires` empty) this returns `None`, and the row's rendered
    `blocking` decides. When it does, it returns whether the cited stratum's *freshly derived*
    state still equals the required one, plus an observation naming both -- which is the precise
    blocking reason when it no longer does.

    `states` is `None` while `derive_state_rows` is still computing the states; the fact is then
    undecided rather than guessed, and the fixed-point pass re-evaluates it once the states exist.
    """
    requires = row.get("adjudication_requires", "")
    if not requires or states is None:
        return None, ""
    cited = int(row.get("adjudication_phase", -1))
    actual = states.get(cited)
    return (
        actual == requires,
        f"its adjudication rests on phase {cited} being `{requires}`, and the machine state "
        f"derives `{actual}`",
    )


def divergence_blocking_reason(
    phase: int, doc: dict | None = None, states: dict[int, str] | None = None
) -> str:
    """The reason a blocking divergence obligation holds this stratum open.

    `docs/SECURITY_DIVERGENCE_POLICY.md`'s entries carry a `**Trigger:**`: the condition under
    which the divergence must be revisited or removed. Review named the absence of any
    machine-check on those triggers the branch's most interesting weakness -- a stratum could
    derive `complete` while an obligation it owned had had its trigger fire and was still owed,
    because the register was prose and nothing read it. `divergence_obligations.py` renders the
    trigger-bearing entries as rows, so the rule can be executable:

        a row blocks its `current_owner` when its derived `blocking` is true, which the register
        sets for an `open` obligation whose trigger has materially fired (`trigger_satisfied`),
        which is a `manual` row with no `adjudication`, or whose manual `adjudication` rests on a
        machine fact (`adjudication_phase`/`adjudication_requires`) that no longer holds

    and this function reads that derived state scoped by the row's own `current_owner` equality,
    so the artefact and the rule cannot disagree about *which* stratum a row blocks. Deriving the
    trigger state is the point: the hand-typed `trigger_satisfied` this replaces is what let
    `D-DECODER-ABSENT-1` read `false` while its trigger had fired.

    **The manual machine fact is re-evaluated here, every run.** The generator runs before
    `phase-state.json` and cannot read a fresh state, so a manual adjudication that cites one is a
    human sentence until this function re-evaluates its `(adjudication_phase,
    adjudication_requires)` against the states derived in this run; the moment the cited state is
    anything else, the row blocks its owner instead of reading open-but-nonblocking forever. This
    is the general bug `D-EVP-CIPHER-LEGACY-NID-1` exposed.

    `doc` exists so `--self-test` can hand in a reconstructed artefact; it defaults to reading the
    committed file. `states` exists for the same reason; it is `None` during `derive_state_rows`'
    first pass (the fact is undecided then) and the derived map in the fixed-point pass.

    **Fail-closed when the artefact is absent.** The register is what makes the rule checkable,
    so a missing `divergence-obligations.json` is a fatal, not an empty result: returning "" would
    let the whole rule be skipped by deleting one file, which is the hole this closes. The message
    names the generator to run, the way the pipeline runs it.
    """
    if doc is None:
        doc = read_json(DIVERGENCE_OBLIGATIONS)
    if doc is None:
        print(
            f"[phase-state] fatal: {DIVERGENCE_OBLIGATIONS} is absent or unreadable, so the "
            f"divergence-trigger rule cannot run and no stratum's state can be trusted; run "
            f"`python3 forensics/tools/divergence_obligations.py` to write it.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    owed: list[tuple[dict, str]] = []
    for row in doc["body"]["rows"]:
        if row["current_owner"] != phase or row.get("disposition") != "open":
            continue
        evaluated = dict(row)
        holds, observation = evaluate_manual_adjudication(row, states)
        if holds is not None:
            evaluated["adjudication_predicate_satisfied"] = holds
        # The register's derivation, not the rendered `blocking`: the same function the generator
        # used, so a reconstructed row (and a machine fact) is judged by the real rule.
        if derive_blocking(evaluated):
            owed.append((row, observation))
    if not owed:
        return ""
    ids = ", ".join(row["id"] for row, _obs in owed)
    reasons = [obs for _row, obs in owed if obs]
    reason = (
        f"{len(owed)} blocking divergence obligation(s) of this stratum -- an `open` row whose "
        f"trigger has fired, an `open` `manual` row with no adjudication, or an `open` `manual` "
        f"row whose machine-checked adjudication no longer holds "
        f"({DIVERGENCE_OBLIGATIONS}): {ids}"
    )
    if reasons:
        reason += "; " + "; ".join(reasons)
    return reason


def _frf_declaration(court: str) -> str:
    """The generated declaration an FRF court id owns."""
    return f"{FRF_DECLARATIONS}/{court}/manifest.yaml"


def _frf_declared_candidate(court: str) -> tuple[str | None, str | None]:
    """`(version_or_commit, artifact_sha256)` the current declaration binds for `court`.

    A compiled claim records a candidate identity as `candidate.version_or_commit` plus
    `candidate.identity_hash`, and `identity_hash` is FRF's hash of the candidate reference
    object the declaration names (`candidate.path`). Reading both from the declaration is what
    lets clause 4 require the *compiled* claim to carry the *current* candidate identity rather
    than merely covering the receipts: the object hash is over the reference file itself, which is
    exactly what FRF stores content-addressed and what the claim records, so the two are
    comparable without opening the FRF store (which this container cannot do).

    `(None, None)` when the declaration or the reference it names is absent, so the clause cannot
    manufacture a match it did not measure.
    """
    path = REPO_ROOT / _frf_declaration(court)
    if not path.is_file():
        return None, None
    version = cpath = None
    in_candidate = False
    for line in path.read_text().splitlines():
        if re.match(r"^  candidate:\s*$", line):
            in_candidate = True
            continue
        if not in_candidate:
            continue
        m = re.match(r'^    version_or_commit:\s*"?([^"]+?)"?\s*$', line)
        if m:
            version = m.group(1)
            continue
        m = re.match(r"^    path:\s*(\S+)\s*$", line)
        if m:
            cpath = m.group(1)
            continue
        if line and not line.startswith("    "):
            in_candidate = False
    artifact = None
    if cpath:
        ref = REPO_ROOT / cpath
        if ref.is_file():
            artifact = sha256_file(ref)
    return version, artifact


def _reference_probes() -> frozenset[str]:
    """The authored `reference_probes` set from the court-coverage rows.

    Court-coverage data (those courts contribute basis `referenced`, not `called`, D199),
    authored rather than derived from `gen_frf_courts.py`. It is the independent record of which
    courts take addresses rather than diffing a transcript.
    """
    doc = read_json(FRF_COVERAGE_ROWS)
    if doc is None:
        return frozenset()
    return frozenset(doc.get("reference_probes", []))


def _frf_court_inventory(phase: int) -> list[tuple[str, str, bool, str | None]]:
    """Every court the stratum itself ran, classified for FRF declarability.

    `(frf court id, probe stem, declarable, exclusion reason)`, read from
    `artifacts/phase<N>/COURTS.json` -- **the stratum's own record of the courts it ran**, not the
    FRF declaration registry. That is the whole point: `gen_frf_courts.py` is the thing
    `frf_gemel_blocking_reason` checks, so deriving the *requirement* from it would let a stratum
    that forgot to register a court define its own completeness -- `_frf_declared_courts` would
    answer the empty set and the rule would return `""`. The requirement therefore comes from an
    independent inventory and the registry must satisfy it.

    A court's own `frf_declarable`/`frf_exclusion` fields are authoritative when a runner emits
    them. When they are absent -- every inventory written before those fields existed -- the two
    documented exclusion rules apply: a court named in the authored `reference_probes` set takes
    addresses rather than diffing a transcript, and a `CT-` court is vector-driven and compiled
    against the candidate alone (D13, D201). Every exclusion carries a reason, so none is silent.
    """
    doc = read_json(f"artifacts/phase{phase}/COURTS.json")
    if doc is None:
        return []
    refs = _reference_probes()
    out: list[tuple[str, str, bool, str | None]] = []
    for row in doc.get("body", {}).get("courts", []):
        name = row["court"]
        court_id = "openssl-rs-" + name.lower()
        probe = Path(row.get("probe", "")).stem
        declarable = row.get("frf_declarable")
        exclusion = row.get("frf_exclusion")
        if declarable is None:
            if name in refs:
                declarable = False
                exclusion = ("reference-basis probe: takes addresses, prints non-NULL, no "
                             "transcript to diff (authored `reference_probes`)")
            elif name.startswith("CT-"):
                declarable = False
                exclusion = ("vector-driven correctness court, compiled against the candidate "
                             "alone (D13, D201)")
            else:
                declarable = True
                exclusion = None
        out.append((court_id, probe, bool(declarable), exclusion))
    return out


def _frf_declared_courts(phase: int) -> list[tuple[str, str]]:
    """`(court id, probe)` for every court `gen_frf_courts.py` declares at `phase`.

    The registry (D58), not `artifacts/phase<N>/COURTS.json`, is the set of *declarable* courts. A
    reference-basis court -- `RT-RUNTIME-REF`, `RT-BIO-CONF-REF`, `RT-PROVIDER-REF` and the other
    `-REF` names -- has a `COURTS.json` row and stages a probe pair for the court venue, but it has
    no row in this table because its probe takes addresses and there is no authority transcript to
    diff; a vector-driven `CT-*` court is compiled against the candidate alone (D13, D201). Neither
    can carry a declaration, so neither is required to. Phase 11's `RT-X509-REF` *is* in the table
    because its probe is fixture-driven and diffs a real transcript, which is why this rule requires
    a chain for it and not for its predecessors.
    """
    return [
        ("openssl-rs-" + name, probe)
        for name, p, probe, _desc in gen_frf_courts.COURTS
        if p == phase
    ]


def _frf_receipt_index() -> dict[str, set[str]]:
    """Receipt stems by FRF court id, read from each receipt's own `court.id`."""
    out: dict[str, set[str]] = {}
    directory = REPO_ROOT / FRF_RECEIPTS
    if not directory.is_dir():
        return out
    for p in sorted(directory.glob("*.json")):
        try:
            doc = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        cid = (doc.get("court") or {}).get("id")
        if cid:
            out.setdefault(cid, set()).add(p.stem)
    return out


def _frf_challenge_index() -> dict[str, list[dict]]:
    """Challenge records by the FRF court id each names."""
    out: dict[str, list[dict]] = {}
    directory = REPO_ROOT / FRF_CHALLENGES
    if not directory.is_dir():
        return out
    for p in sorted(directory.glob("*.json")):
        try:
            doc = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        cid = doc.get("court")
        if cid:
            out.setdefault(cid, []).append(doc)
    return out


def _frf_claim_docs() -> list[dict]:
    """Every compiled claim in the FRF store."""
    out: list[dict] = []
    directory = REPO_ROOT / FRF_CLAIMS
    if not directory.is_dir():
        return out
    for p in sorted(directory.glob("*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def _gemel_checkpoint_summaries() -> list[tuple[str, str]]:
    """The `(name, summary)` of every checkpoint in the Git-tracked projection.

    `render_gemel_trajectory.sh` writes each checkpoint as

        * `K50` -- `checkpoint.<sha>`
          - <its own `gemel show` summary>

    so the summary is read from the same file a reader consults rather than from the untracked
    store, which this container cannot open.
    """
    path = REPO_ROOT / GEMEL_TRAJECTORY
    if not path.exists():
        return []
    out: list[tuple[str, str]] = []
    for line in path.read_text().splitlines():
        m = re.match(r"^\* `(K\d+)` — `checkpoint\.[0-9a-f]+`$", line)
        if m:
            out.append((m.group(1), ""))
        elif out and line.startswith("  - "):
            name, summary = out[-1]
            out[-1] = (name, f"{summary} {line[4:]}".strip())
    return out


def frf_gemel_blocking_reason(phase: int, claims: list[dict] | None = None) -> str:
    """The reason a stratum's FRF/Gemel chain entry is incomplete, or "" when it is complete.

    `docs/RELEASE_GATES.md` section 2 items 6, 8 and 10 are the same three items every stratum
    since Phase 7 left open to its chain entry, and D200/D413/D424/D475 repaired them the same
    way each time. Until this rule the repair was asserted in a seal and in a Gemel change
    summary, and nothing derived a stratum's state from it -- so a stratum could derive
    `complete` with a declared court that had no receipt, a receipt with no sensitivity
    evidence, or a claim no checkpoint reached, exactly as it could derive `complete` with an
    unmatched export before D199. The rule is executable here, and it is OR-ed into the state
    *before* the state is computed, like the divergence rule, so the effect is the state rather
    than a reason printed beside a `complete`.

    The five clauses, every one read from disk:

      1. every court the stratum's own `artifacts/phase<N>/COURTS.json` marks FRF-declarable is
         declared in `gen_frf_courts.py`, staging its probe pair;
      2. every declarable court has a receipt (`receipt-run-<court>-*` in `.frf/receipts`);
      3. every declarable court has two adjudicated challenges -- `saw_defect` and
         `specificity_clean` both true -- covering both operators;
      4. one `sensitivity-backed` claim with no blockers covers a receipt of every declarable
         court (the claim's `requires`, matched to the receipts' own `court.id`) **and records the
         current candidate identity** -- `candidate.version_or_commit == CANDIDATE_VERSION` and,
         when the claim carries the artifact hash, `candidate.identity_hash` equal to the hash of
         the candidate reference the declarations name. Without the identity clause a release
         could move the candidate to `0.0.18` while every compiled claim still recorded `0.0.17`,
         and the phase would derive `complete` on a claim about the previous release; and
      5. a Gemel checkpoint in the projection names the stratum and the chain (with the measured
         exemption `FRF_CHAIN_CHECKPOINT_EXEMPT` for the strata whose checkpoints predate the
         phrase).

    A stratum whose own court inventory declares no FRF-declarable court has begun no chain and is
    not blocked here; Phase 22 is an atlas stratum with no export courts and is out of scope for the
    same reason every other export-shaped rule scopes it out.
    """
    if phase not in STRATUM_EVIDENCE or phase == 22:
        return ""

    # **The requirement is the stratum's own court inventory, and the registry must satisfy it.**
    inventory = _frf_court_inventory(phase)
    required = [(court, probe) for court, probe, declarable, _excl in inventory if declarable]
    declared = dict(_frf_declared_courts(phase))

    problems: list[str] = []

    # A court the inventory marks declarable but the registry does not declare is a finding, so a
    # forgotten registry row can no longer make the requirement vanish. The containment is
    # one-way: the registry may carry *extra* courts, e.g. a reference basis whose probe happens
    # to diff a real transcript (Phase 11's `RT-X509-REF`), which is evidence rather than a fault.
    missing_registry = [court for court, _probe in required if court not in declared]
    if missing_registry:
        problems.append(
            f"{len(missing_registry)} court(s) that artifacts/phase{phase}/COURTS.json marks "
            f"FRF-declarable have no row in the gen_frf_courts.py registry: "
            + ", ".join(missing_registry)
        )
    if not required and not problems:
        return ""

    undeclared = [
        court for court, probe in required
        if not (
            exists(_frf_declaration(court))
            and exists(f"artifacts/phase{phase}/probes/{probe}.authority")
            and exists(f"artifacts/phase{phase}/probes/{probe}.candidate")
        )
    ]
    if undeclared:
        problems.append(
            f"{len(undeclared)} of {len(required)} required court(s) have no FRF declaration "
            f"staging their artifacts/phase{phase}/probes/<probe>.{{authority,candidate}} pair "
            f"({FRF_DECLARATIONS}/openssl-rs-<court>/manifest.yaml): "
            + ", ".join(undeclared)
        )

    receipts = _frf_receipt_index()
    challenges = _frf_challenge_index()

    no_receipt = [court for court, _probe in required if not receipts.get(court)]
    if no_receipt:
        problems.append(
            f"{len(no_receipt)} required court(s) have no receipt in {FRF_RECEIPTS}: "
            + ", ".join(no_receipt)
        )

    unadjudicated: list[str] = []
    for court, _probe in required:
        adjudicated = [
            c for c in challenges.get(court, [])
            if c.get("saw_defect") and c.get("specificity_clean")
        ]
        operators = {c.get("operator") for c in adjudicated}
        if len(adjudicated) < 2 or not set(FRF_CHALLENGE_OPERATORS).issubset(operators):
            unadjudicated.append(court)
    if unadjudicated:
        problems.append(
            f"{len(unadjudicated)} required court(s) lack two adjudicated challenges "
            f"(`saw_defect` and `specificity_clean` true) covering both operators "
            f"{FRF_CHALLENGE_OPERATORS} in {FRF_CHALLENGES}: " + ", ".join(unadjudicated)
        )

    # **The claim must bind the current release identity, not merely cover the receipts.** A
    # `sensitivity-backed` claim is a claim about ONE candidate artifact; FRF records the artifact
    # hash and the `version_or_commit` of the release it was compiled at. Covering the receipts is
    # necessary but not sufficient: the claim's `requires` name content-addressed receipt ids, and
    # the material kind of a claim is "this candidate is what the authority does", so a claim
    # compiled at `0.0.17` over receipts whose declared candidate was `0.0.17` is not evidence
    # about the `0.0.18` release even though every receipt still exists. The two coexist silently
    # because nothing compared the claim's recorded identity to the current one -- which is what
    # this clause does.
    current_version = gen_frf_courts.CANDIDATE_VERSION
    current_artifact = None
    if required:
        _v, current_artifact = _frf_declared_candidate(required[0][0])
    claim_docs = _frf_claim_docs() if claims is None else claims

    covering: list[dict] = []
    for claim in claim_docs:
        if claim.get("policy") != "sensitivity-backed" or claim.get("blockers"):
            continue
        premises = set(claim.get("requires") or ())
        if all(receipts.get(court, set()) & premises for court, _probe in required):
            covering.append(claim)

    stale: list[str] = []
    covered = False
    for claim in covering:
        candidate = claim.get("candidate") or {}
        recorded_version = candidate.get("version_or_commit")
        recorded_artifact = candidate.get("identity_hash")
        if recorded_version != current_version or (
            current_artifact is not None
            and recorded_artifact is not None
            and recorded_artifact != current_artifact
        ):
            stale.append(
                f"{claim.get('id')} records candidate "
                f"version_or_commit={recorded_version!r}, identity_hash={recorded_artifact!r}"
            )
            continue
        covered = True
        break
    if not covered:
        if covering:
            identity = f"version_or_commit={current_version!r}"
            if current_artifact is not None:
                identity += f", identity_hash={current_artifact!r}"
            problems.append(
                f"{len(covering)} `sensitivity-backed` claim(s) with zero blockers in "
                f"{FRF_CLAIMS} cover every one of the {len(required)} required court(s) but none "
                f"records the current candidate identity ({identity}): " + "; ".join(stale)
            )
        else:
            problems.append(
                f"no `sensitivity-backed` claim with zero blockers in {FRF_CLAIMS} covers a "
                f"receipt of every one of the {len(required)} required court(s)"
            )

    if phase not in FRF_CHAIN_CHECKPOINT_EXEMPT and not any(
        f"Phase {phase}" in summary and "FRF chain" in summary
        for _, summary in _gemel_checkpoint_summaries()
    ):
        problems.append(
            f"no checkpoint in {GEMEL_TRAJECTORY} names Phase {phase} and the FRF chain"
        )

    if not problems:
        return ""
    return f"Phase {phase}'s FRF chain entry is incomplete: " + "; ".join(problems)


def _frf_owner_is_in_scope(row: dict) -> bool:
    """Whether the FRF/Gemel rule can fire for `row`'s stratum.

    In `STRATUM_EVIDENCE`, not Phase 22, and the stratum's own `artifacts/phase<N>/COURTS.json`
    declares at least one FRF-declarable court. Reads the inventory, never the registry the rule
    checks, for the reason `_frf_court_inventory` records.
    """
    return (
        row["phase"] != 22
        and row["phase"] in STRATUM_EVIDENCE
        and any(declarable for _c, _p, declarable, _e in _frf_court_inventory(row["phase"]))
    )


def derive_state_rows() -> list[dict]:
    """Compute every stratum's row from evidence, exactly as `main` writes it.

    Factored out of `main` so `self_test` can ask *which* strata derive `complete` without writing
    the artefacts and reconstruct its stale row against one. The divergence rule
    (`divergence_blocking_reason`) is applied here, **before** the state is computed from
    `blocking`, so a blocking row's effect is the state rather than a reason printed beside a
    `complete`.
    """
    rows = []
    for phase, name, stratum in STRATA:
        present, absent, blocking = evidence_for(phase)
        # The divergence rule (`divergence_blocking_reason`). An obligation this stratum owns whose
        # register row blocks it is a blocking reason exactly as an open ledger row is, and it is
        # applied here, **before** the state is computed from `blocking`, so the effect is the state
        # rather than a reason printed beside a `complete`.
        blocking = blocking or divergence_blocking_reason(phase)
        # The FRF/Gemel chain rule (`frf_gemel_blocking_reason`, docs/RELEASE_GATES.md section 2
        # items 6, 8 and 10). A stratum that has staged FRF courts must carry the whole chain the
        # release gates name, and it is applied here for the same reason the divergence rule is:
        # before the state is computed from `blocking`, so the effect is the state rather than a
        # reason printed beside a `complete`.
        blocking = blocking or frf_gemel_blocking_reason(phase)
        # **A stratum with any evidence is under way, and `absent` does not say otherwise.**
        #
        # This used to read `elif absent: state = "not-started"`, which meant a stratum whose
        # plan and ledger had landed but whose modules had not was reported as never started.
        # The Phase 4, 5 and 6 notes each record that mistake being made once by hand for the
        # *court* item and being fixed for that item alone; the same reasoning applies to every
        # other piece of evidence, so it is applied once here instead. What is missing is
        # reported in `blocking` and listed in `evidence_absent`, so the state is not weaker
        # for the change -- it is `in-progress`, which is what a stratum with a ledger is.
        if not present:
            state = "not-started"
        elif absent:
            state = "in-progress"
            blocking = blocking or (
                f"{len(absent)} required evidence file(s) absent, the first being "
                f"{absent[0]}"
            )
        elif blocking:
            state = "in-progress"
        else:
            state = "complete"

        seal_doc = SEAL_DOCS.get(phase)
        rows.append({
            "phase": phase, "name": name, "stratum": stratum, "state": state,
            "evidence_present": present, "evidence_absent": absent,
            "blocking": blocking,
            "seal_sha256": seal_identity(seal_doc) if seal_doc else None,
            "deferred": deferred_rows(phase),
            "provider_rows": provider_rows_for(phase),
        })

    # The dependency invariant (`REQUIRES`, D138, and `docs/PHASE-22-SUBPHASES.md` section 8). A
    # stratum may be `complete` only when every stratum it *requires* is complete. Two things make
    # this a separate pass rather than the running "earlier phase" check it used to be: the edges
    # are declared rather than inferred from the number, and one of them -- `requires[11] = (10,
    # 22)` -- points *forward* in the registry, so a single list-order pass would read Phase 22's
    # state before it had one. The pass therefore runs to a fixed point.
    by_phase = {r["phase"]: r for r in rows}
    changed = True
    while changed:
        changed = False
        for row in rows:
            if row["state"] != "complete":
                continue
            incomplete = [d for d in REQUIRES.get(row["phase"], ())
                          if by_phase[d]["state"] != "complete"]
            if incomplete:
                row["state"] = "in-progress"
                row["blocking"] = (
                    "blocked by the dependency invariant: phase "
                    + ", ".join(str(d) for d in incomplete) + " is not complete")
                changed = True
        # The manual-adjudication clause of the divergence rule, re-evaluated against the states
        # as they now stand (Fix 2; the general bug `D-EVP-CIPHER-LEGACY-NID-1` exposed). A manual
        # `open` row whose `adjudication` cites a machine phase-state fact is only checkable once
        # the states exist, so the first pass left it undecided; this is where a stale fact blocks
        # the owner. The clause sits **inside** the fixed point so a stratum it forces
        # `in-progress` propagates through `REQUIRES` on the next iteration.
        states_now = {r["phase"]: r["state"] for r in rows}
        for row in rows:
            if row["state"] != "complete":
                continue
            reason = divergence_blocking_reason(row["phase"], states=states_now)
            if reason:
                row["state"] = "in-progress"
                row["blocking"] = reason
                changed = True
    return rows


# The id the sensitivity control stamps on the row it reconstructs. It cannot collide with a real
# register id, and the control requires the rule's reason to name it.
SELF_TEST_STALE_ID = "SELF-TEST-STALE-ROW"
# The id the second control stamps on the stale-*adjudication* row it reconstructs.
SELF_TEST_STALE_ADJ_ID = "SELF-TEST-STALE-ADJUDICATION"
# The id the fourth control stamps on the stale-*candidate-identity* claim it reconstructs.
SELF_TEST_STALE_CANDIDATE_ID = "SELF-TEST-STALE-CANDIDATE-CLAIM"


def self_test() -> int:
    """Reconstruct the stale row the typed trigger state could not see, and require the rule to fire.

    The register's most important input used to be a hand-typed `trigger_satisfied`, and
    `D-DECODER-ABSENT-1` is the proof it failed: its trigger had fired (Phase 10's provider
    decoders existed, `RT-CODEC` courted them, and the Phase 10 seal named the row a retirement
    candidate) while the row still read `false`, so Phase 10 derived `complete` with a fired
    trigger. The fix derives the trigger state, and this control reconstructs the shape the defect
    had -- an `open`, `manual`, unadjudicated row whose `current_owner` is a stratum that derives
    `complete` -- and requires `divergence_blocking_reason` to name it. It refuses to pass
    otherwise, because a check that has never been seen to fire is not evidence.
    """
    rows = derive_state_rows()
    complete = [r for r in rows if r["state"] == "complete"]
    if not complete:
        print(
            "[phase-state] SELF-TEST FAILED: no stratum derives `complete`, so the stale row "
            "cannot be reconstructed against one",
            file=sys.stderr,
        )
        return 1
    owner = complete[-1]  # the highest-numbered stratum that derived `complete`

    doc = read_json(DIVERGENCE_OBLIGATIONS)
    if doc is None:
        print(
            f"[phase-state] SELF-TEST FAILED: {DIVERGENCE_OBLIGATIONS} is absent or unreadable, "
            f"so the rule the control exercises cannot run; run "
            f"`python3 forensics/tools/divergence_obligations.py` to write it.",
            file=sys.stderr,
        )
        return 1
    reconstructed = copy.deepcopy(doc)
    stale = {
        "id": SELF_TEST_STALE_ID,
        "current_owner": owner["phase"],
        "trigger_basis": "manual",
        "trigger_predicate": "",
        "trigger_satisfied": None,
        "adjudication": "",
        "disposition": "open",
    }
    # The register's own derivation, not a typed boolean: the control is evidence only if it is the
    # `manual`/`open`/unadjudicated shape that makes `blocking` true.
    stale["blocking"] = derive_blocking(stale)
    reconstructed["body"]["rows"].append(stale)

    reason = divergence_blocking_reason(owner["phase"], doc=reconstructed)
    print(
        f"[phase-state] self-test: reconstructed a stale row ({stale['trigger_basis']}, "
        f"{stale['disposition']}, unadjudicated, `blocking` derived {stale['blocking']}) owned by "
        f"phase {owner['phase']} ({owner['name']}), which derives `complete`:")
    print(f"  {reason or '(no reason: the rule did not fire)'}")
    if not reason or SELF_TEST_STALE_ID not in reason:
        print(
            "[phase-state] SELF-TEST FAILED: the divergence rule did not refuse an open, manual, "
            "unadjudicated row owned by a complete stratum",
            file=sys.stderr,
        )
        return 1
    print(
        "[phase-state] self-test ok: the stale row (manual, open, unadjudicated) is caught "
        "without a human"
    )

    # ---- second control: the FRF requirement cannot be defined by its own registry ----
    # The requirement is read from the stratum's own `artifacts/phase<N>/COURTS.json` (`D524`);
    # `gen_frf_courts.py` is the registry the rule *checks*. Emptying the registry for a stratum
    # that derives `complete` must therefore **block** it -- every required court has no registry
    # row -- rather than make its requirement vanish. The old shape derived the requirement from
    # the registry (`_frf_declared_courts`) and returned `""` when it was empty, so a forgotten
    # registry row was indistinguishable from nothing being owed. This control reconstructs that
    # shape and refuses to pass unless the rule fires.
    # The divergence control above can use any complete stratum -- phase 22 works, since an
    # atlas stratum owns divergence rows. This control cannot: the FRF rule is scoped out of
    # phase 22 and of any stratum whose own court inventory declares no FRF-declarable court, so
    # emptying such a registry is *correctly* no reason. The control therefore needs a complete
    # stratum whose own `artifacts/phase<N>/COURTS.json` actually declares FRF-declarable courts
    # -- discovered from that inventory, never from the registry it is about to empty.
    frf_owner_row = next(
        (row for row in reversed(complete)
         if _frf_owner_is_in_scope(row)),
        None,
    )
    frf_owner_derives_complete = frf_owner_row is not None
    if frf_owner_row is None:
        # The FRF rule fires for any stratum whose own court inventory declares a declarable
        # court, whatever its derived state; the fallback keeps this control runnable while a
        # release's claims are stale and no FRF-bearing stratum derives `complete` (which is
        # exactly the state Part A's identity clause produces before the claims are recompiled).
        frf_owner_row = next((row for row in reversed(rows) if _frf_owner_is_in_scope(row)), None)
    if frf_owner_row is None:
        print(
            "[phase-state] SELF-TEST FAILED: no stratum declares an FRF-declarable court in its "
            "own court inventory, so the registry-independence control cannot run",
            file=sys.stderr,
        )
        return 1
    frf_owner = frf_owner_row["phase"]
    frf_owner_state = (
        "which derives `complete`" if frf_owner_derives_complete
        else "whose claims currently record a stale candidate identity"
    )
    saved_courts = gen_frf_courts.COURTS
    try:
        gen_frf_courts.COURTS = [row for row in saved_courts if row[1] != frf_owner]
        frf_reason = frf_gemel_blocking_reason(frf_owner)
    finally:
        gen_frf_courts.COURTS = saved_courts
    print(
        f"[phase-state] self-test: emptied the gen_frf_courts.py registry for phase {frf_owner} "
        f"({frf_owner_row['name']}), {frf_owner_state}:"
    )
    print(f"  {frf_reason or '(no reason: the requirement vanished with its registry)'}")
    if not frf_reason or "gen_frf_courts.py registry" not in frf_reason:
        print(
            "[phase-state] SELF-TEST FAILED: emptying the FRF registry for a complete stratum did "
            "not refuse it; the requirement is still defined by the registry it checks",
            file=sys.stderr,
        )
        return 1
    print(
        "[phase-state] self-test ok: emptying the FRF registry refuses the stratum through its "
        "own court inventory, so a forgotten registry row cannot define completion"
    )

    # ---- fourth control: a covering claim whose candidate identity is stale must fail closed ----
    # Clause 4 used to require only that a claim cover the receipts; it never required the claim's
    # *candidate identity* to equal the current one, so a release could move the candidate to
    # `0.0.18` while every compiled claim still recorded `0.0.17`, and the phase derived `complete`
    # on a claim about the previous release. The control reconstructs a covering claim whose
    # `candidate.version_or_commit` is deliberately stale and requires the rule to name it. It
    # refuses to pass otherwise, because a check that has never been seen to fire is not evidence.
    owner_required = [court for court, _p, declarable, _e
                      in _frf_court_inventory(frf_owner) if declarable]
    owner_receipts = _frf_receipt_index()
    covering_claim = next(
        (claim for claim in _frf_claim_docs()
         if claim.get("policy") == "sensitivity-backed" and not claim.get("blockers")
         and all(owner_receipts.get(court, set()) & set(claim.get("requires") or ())
                 for court in owner_required)),
        None,
    )
    if covering_claim is None:
        print(
            f"[phase-state] SELF-TEST FAILED: no `sensitivity-backed` claim with zero blockers "
            f"covers every required court of phase {frf_owner}, so the stale-candidate-identity "
            f"control cannot be reconstructed against it",
            file=sys.stderr,
        )
        return 1
    stale_claim = copy.deepcopy(covering_claim)
    stale_claim["id"] = SELF_TEST_STALE_CANDIDATE_ID
    stale_claim["candidate"] = dict(
        stale_claim.get("candidate") or {},
        version_or_commit="0.0.0-stale-self-test",
    )
    stale_candidate_reason = frf_gemel_blocking_reason(frf_owner, claims=[stale_claim])
    print(
        f"[phase-state] self-test: reconstructed a covering `sensitivity-backed` claim "
        f"({SELF_TEST_STALE_CANDIDATE_ID}, copied from {covering_claim.get('id')}) for phase "
        f"{frf_owner} ({frf_owner_row['name']}) with a stale candidate identity "
        f"(version_or_commit was {covering_claim.get('candidate', {}).get('version_or_commit')!r}, "
        f"stamped {stale_claim['candidate']['version_or_commit']!r}; current is "
        f"{gen_frf_courts.CANDIDATE_VERSION!r}):"
    )
    print(f"  {stale_candidate_reason or '(no reason: the rule did not fire)'}")
    if (
        not stale_candidate_reason
        or SELF_TEST_STALE_CANDIDATE_ID not in stale_candidate_reason
        or "candidate identity" not in stale_candidate_reason
    ):
        print(
            "[phase-state] SELF-TEST FAILED: a covering claim whose recorded candidate identity "
            "is stale did not block",
            file=sys.stderr,
        )
        return 1
    print(
        "[phase-state] self-test ok: a covering claim that records a stale candidate identity "
        "is refused, so a released product cannot derive `complete` on a claim about the "
        "previous release"
    )

    # ---- third control: a stale manual adjudication must fail closed ----
    # Fix 2's general bug, which `D-EVP-CIPHER-LEGACY-NID-1` exposed: `divergence_obligations.py`
    # treated `manual` + nonempty `adjudication` as non-blocking, so an adjudication that rested on
    # a machine fact ("Phase N is not-started") kept the row open-but-nonblocking after the fact
    # changed. The control reconstructs exactly that shape -- an `open`, `manual` row with a
    # nonempty `adjudication` whose `adjudication_requires` the owner no longer satisfies -- against
    # a stratum that derives `complete`, and requires the rule to block it. It refuses to pass
    # otherwise, because a check that has never been seen to fire is not evidence.
    stale_adj = {
        "id": SELF_TEST_STALE_ADJ_ID,
        "current_owner": owner["phase"],
        "trigger_basis": "manual",
        "trigger_predicate": "",
        "trigger_satisfied": None,
        "adjudication": (
            f"the cited phase is `not-started`, so the trigger is adjudicated as not fired"
        ),
        # The machine fact the adjudication cites: the owner's own state, which the control knows
        # derives `complete` and the row requires to be `not-started`.
        "adjudication_phase": owner["phase"],
        "adjudication_requires": "not-started",
        "disposition": "open",
    }
    reconstructed_adj = copy.deepcopy(doc)
    reconstructed_adj["body"]["rows"].append(stale_adj)
    states = {r["phase"]: r["state"] for r in rows}
    adj_reason = divergence_blocking_reason(
        owner["phase"], doc=reconstructed_adj, states=states
    )
    print(
        f"[phase-state] self-test: reconstructed a stale manual adjudication ({stale_adj['id']})"
        f" owned by phase {owner['phase']} ({owner['name']}), which derives `complete`, resting on "
        f"`adjudication_phase` {owner['phase']} being `not-started`:"
    )
    print(f"  {adj_reason or '(no reason: the rule did not fire)'}")
    if not adj_reason or SELF_TEST_STALE_ADJ_ID not in adj_reason:
        print(
            "[phase-state] SELF-TEST FAILED: a manual, open row whose nonempty adjudication rests "
            "on a machine fact the owner no longer satisfies did not block",
            file=sys.stderr,
        )
        return 1
    print(
        "[phase-state] self-test ok: a stale manual adjudication is re-evaluated against the "
        "derived states and blocks its owner"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="reconstruct a stale divergence row and require the rule to refuse it",
    )
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()

    # Every stratum that has *any* of the three artefacts a stratum's evidence is built from
    # must have a row, or it would be derived `not-started` however much of that evidence is
    # on disk. The check reads the filesystem rather than `STRATA`, because reading the
    # registry would make it tautological: every phase is in the registry from the day it is
    # planned, including the fifteen nothing has been written for. A phase is *started* when a
    # plan, a ledger or a court file exists, and that is a fact about the tree.
    #
    # This is the one place a stratum's existence is discovered rather than declared, and it
    # runs on every invocation rather than being asserted in prose.
    started_without_a_row = [
        phase for phase, _n, _s in STRATA
        if phase >= 3
        and phase not in STRATUM_EVIDENCE
        and (
            exists(f"docs/PHASE-{phase}-SUBPHASES.md")
            or exists(f"forensics/phase{phase}-obligations.json")
            or exists(f"artifacts/phase{phase}/COURTS.json")
        )
    ]
    if started_without_a_row:
        print(
            f"[phase-state] fatal: {started_without_a_row} have evidence on disk but no "
            f"STRATUM_EVIDENCE row, so they would be derived `not-started` despite it. "
            f"Add the row rather than the state: `forensics/STATUS.md` is generated and "
            f"docs/DECISIONS.md D138 is why.",
            file=sys.stderr,
        )
        return 1

    rows = derive_state_rows()

    body = {
        "rule": "a phase may be complete only if every phase it requires is complete "
                "(forensics/tools/phase_state.py REQUIRES; docs/PHASE-22-SUBPHASES.md section 8)",
        "derived_from": "artefact existence and their content, never typed status",
        "phases": rows,
        "summary": {
            "complete": sum(1 for r in rows if r["state"] == "complete"),
            "in_progress": sum(1 for r in rows if r["state"] == "in-progress"),
            "not_started": sum(1 for r in rows if r["state"] == "not-started"),
        },
    }
    doc = envelope("phase-state", "forensics/tools/phase_state.py", [], body)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)

    L = ["# Phase state (derived)", "",
         "Generated by `forensics/tools/phase_state.py` from artefact existence",
         "and content. **No phase state is ever typed.** The transition rule is",
         "enforced here:", "",
         f"> {body['rule']}", "",
         "| phase | stratum | state | blocking |", "|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['phase']} | {r['stratum']} | `{r['state']}` | {r['blocking']} |")
    L.append("")
    for r in rows:
        if not r["deferred"]:
            continue
        L += [f"Deferred out of phase {r['phase']} (recorded hand-offs, not parity",
              "claims):", ""]
        for entry in r["deferred"]:
            L.append(f"* {entry}")
        L.append("")
    write_text(REPO_ROOT / "forensics" / "phase-state.md", "\n".join(L))

    print(f"[phase-state] {body['summary']}")
    for r in rows:
        if r["state"] != "not-started":
            print(f"  phase {r['phase']} ({r['name']}): {r['state']}"
                  + (f" -- {r['blocking']}" if r["blocking"] else ""))
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
