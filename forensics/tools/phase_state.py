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

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    SEAL_DOCS,
    content_hash,
    envelope,
    rel,
    sha256_file,
    write_json,
    write_text,
    REPO_ROOT,
)

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
# `forensics/tools/divergence_obligations.py` now renders each trigger-bearing entry as a row with
# `trigger_satisfied`, `disposition` and `current_owner`, and `divergence_blocking_reason` below is
# the executable half. Generated before this tool by the pipeline; if the JSON is absent this tool
# fails closed rather than skipping the rule, because a check that can be silently skipped is not a
# check (see `divergence_blocking_reason`).
DIVERGENCE_OBLIGATIONS = "forensics/divergence-obligations.json"

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
]

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


def divergence_blocking_reason(phase: int) -> str:
    """The reason a triggered, still-open divergence obligation holds a stratum open.

    `docs/SECURITY_DIVERGENCE_POLICY.md`'s entries carry a `**Trigger:**`: the condition under
    which the divergence must be revisited or removed. Review named the absence of any
    machine-check on those triggers the branch's most interesting weakness -- a stratum could
    derive `complete` while an obligation it owned had had its trigger fire and was still owed,
    because the register was prose and nothing read it. `divergence_obligations.py` renders the
    trigger-bearing entries as rows, so the rule can be executable:

        a row blocks its `current_owner` when `trigger_satisfied` and `disposition == "open"`

    and this function applies it to one stratum. The test is the row's own `current_owner`
    equality rather than the derived `blocking` field, so the artefact and the rule cannot
    disagree about *which* stratum a row blocks.

    **Fail-closed when the artefact is absent.** The register is what makes the rule checkable,
    so a missing `divergence-obligations.json` is a fatal, not an empty result: returning "" would
    let the whole rule be skipped by deleting one file, which is the hole this closes. The message
    names the generator to run, the way the pipeline runs it.
    """
    doc = read_json(DIVERGENCE_OBLIGATIONS)
    if doc is None:
        print(
            f"[phase-state] fatal: {DIVERGENCE_OBLIGATIONS} is absent or unreadable, so the "
            f"divergence-trigger rule cannot run and no stratum's state can be trusted; run "
            f"`python3 forensics/tools/divergence_obligations.py` to write it.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    owed = [
        row for row in doc["body"]["rows"]
        if row["current_owner"] == phase
        and row["trigger_satisfied"]
        and row["disposition"] == "open"
    ]
    if not owed:
        return ""
    ids = ", ".join(row["id"] for row in owed)
    return (
        f"{len(owed)} triggered, open divergence obligation(s) of this stratum, whose trigger has "
        f"fired and which are still owed ({DIVERGENCE_OBLIGATIONS}): {ids}"
    )


def main() -> int:
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

    rows = []
    earlier_incomplete: int | None = None
    for phase, name, stratum in STRATA:
        present, absent, blocking = evidence_for(phase)
        # The divergence-trigger rule (`divergence_blocking_reason`). A triggered, still-open
        # obligation this stratum owns is a blocking reason exactly as an open ledger row is, and
        # it is applied here, **before** the state is computed from `blocking`, so the effect is
        # the state rather than a reason printed beside a `complete`.
        blocking = blocking or divergence_blocking_reason(phase)
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

        # Executable policy: a later stratum may not be complete while an earlier
        # one is not.
        if state == "complete" and earlier_incomplete is not None:
            state = "in-progress"
            blocking = (f"blocked by the dependency-order invariant: phase "
                        f"{earlier_incomplete} is not complete")
        elif state != "complete" and earlier_incomplete is None:
            earlier_incomplete = phase

        seal_doc = SEAL_DOCS.get(phase)
        rows.append({
            "phase": phase, "name": name, "stratum": stratum, "state": state,
            "evidence_present": present, "evidence_absent": absent,
            "blocking": blocking,
            "seal_sha256": seal_identity(seal_doc) if seal_doc else None,
            "deferred": deferred_rows(phase),
            "provider_rows": provider_rows_for(phase),
        })

    body = {
        "rule": "a phase may be complete only if every earlier phase is complete",
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
    sys.exit(main())
