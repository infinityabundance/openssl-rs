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
        if not absent:
            blocking = PHASE3_OUTSTANDING
        return present, absent, blocking

    return present, absent, "not started"


# Phase 3 evidence: the core-runtime modules and the courts that exercise them.
PHASE3_MODULES = [
    "src/runtime/mod.rs",
    "src/runtime/mem.rs",
    "src/runtime/err.rs",
    "src/runtime/stack.rs",
]
PHASE3_OUTSTANDING = (
    "the runtime substrate is under construction: implemented so far are memory, "
    "the ERR queue and the stack. Outstanding: ex_data, lhash, the OBJ/NID "
    "database, secure memory, CRYPTO_THREAD_*, initialisation/cleanup, and the "
    "remaining reference-counting surface."
)


def seal_identity(doc: str) -> str | None:
    p = REPO_ROOT / doc
    return sha256_file(p) if p.exists() else None


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
