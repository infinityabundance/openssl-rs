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
    content_hash,
    envelope,
    rel,
    sha256_file,
    write_json,
    write_text,
    REPO_ROOT,
)

OUT = REPO_ROOT / "forensics" / "phase-state.json"

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

    if phase == 3:
        for d in PHASE3_MODULES:
            (present if exists(d) else absent).append(d)
        courts = read_json(PHASE3_COURTS)
        if courts:
            present.append(PHASE3_COURTS)
            failed = [c["court"] for c in courts["body"]["courts"]
                      if c["verdict"] != "pass"]
            if failed:
                blocking = f"Phase 3 courts not passing: {failed}"
        else:
            absent.append(PHASE3_COURTS)
        ledger = read_json(PHASE3_OBLIGATIONS)
        if ledger:
            present.append(PHASE3_OBLIGATIONS)
        else:
            absent.append(PHASE3_OBLIGATIONS)
        return present, absent, blocking

    if phase == 4:
        for d in PHASE4_MODULES:
            (present if exists(d) else absent).append(d)
        ledger = read_json(PHASE4_OBLIGATIONS)
        if ledger:
            present.append(PHASE4_OBLIGATIONS)
            body4 = ledger["body"]
            open_count = body4["counts"]["open_in_this_stratum"]
            if open_count:
                blocking = (
                    f"{open_count} open obligation(s) of this stratum recorded in "
                    f"{PHASE4_OBLIGATIONS}; a stratum cannot be complete while any "
                    f"export it owns is neither implemented nor handed to a later "
                    f"phase"
                )
        else:
            absent.append(PHASE4_OBLIGATIONS)
        courts = read_json(PHASE4_COURTS)
        if courts:
            present.append(PHASE4_COURTS)
            failed = [c["court"] for c in courts["body"]["courts"]
                      if c["verdict"] != "pass"]
            if failed:
                blocking = f"Phase 4 courts not passing: {failed}"
        else:
            # Missing courts are a blocker, not evidence of a phase that has not
            # begun: the modules exist, so the stratum is under way and the gap is
            # what must be closed. Listing it as absent would report `not-started`
            # and understate the recorded work.
            blocking = blocking or f"no Phase 4 courts yet ({PHASE4_COURTS} absent)"
        return present, absent, blocking

    return present, absent, "not started"


# Phase 3 evidence: the core-runtime modules, the differential courts that
# exercise them, and the seal that records what they establish.
PHASE3_COURTS = "artifacts/phase3/COURTS.json"
# Every symbol in the Phase 3 families is either implemented or deferred to a
# later phase with a stated reason. `phase3_obligations.py` fails closed if any
# export in those families is neither, so the ledger -- not this file -- decides
# whether anything is unaccounted for.
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
    "courts/phase4/discover_bio_addr.c",
    "courts/phase4/discover_bio_addr2.c",
    "courts/phase4/discover_bio_lookup.c",
    "courts/phase4/discover_bio_lookup_hints.c",
    "courts/phase4/discover_bio_legacy_host.c",
    "courts/phase4/bio_addr_null_calls.c",
    "forensics/tools/phase4_courts.py",
    "forensics/tools/phase4_obligations.py",
]


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


def main() -> int:
    rows = []
    earlier_incomplete: int | None = None
    for phase, name, stratum in STRATA:
        present, absent, blocking = evidence_for(phase)
        has_evidence = bool(present)
        if not has_evidence:
            state = "not-started"
        elif absent:
            state = "not-started"
            blocking = blocking or "required evidence missing"
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

        seals = {
            "phase1": seal_identity("docs/PHASE-1-ARCHAEOLOGY-SEAL.md"),
            "phase2": seal_identity("docs/PHASE-2-DISTRIBUTION-SEAL.md"),
        }
        rows.append({
            "phase": phase, "name": name, "stratum": stratum, "state": state,
            "evidence_present": present, "evidence_absent": absent,
            "blocking": blocking, "seal_sha256": seals.get(f"phase{phase}"),
            "deferred": deferred_rows(phase),
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
