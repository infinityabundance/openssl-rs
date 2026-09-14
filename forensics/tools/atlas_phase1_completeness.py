#!/usr/bin/env python3
"""openssl-rs — Phase 1 completeness: prove every expected plane is represented.

The Phase 1 exit rule requires that every expected archaeology plane is either
**represented** or **deliberately deferred with a reason**. Without a checked
inventory that is an assertion; with one, it is a fact.

    forensics/atlas/phase1-completeness.json
    forensics/atlas/phase1-completeness.md

Three classifications, and nothing may be silently absent:

    complete   the artefact exists and is content-addressed
    deferred   not Phase 1 work, with the phase that owns it named
    open       known and unresolved, with a reason (never omitted)

An artefact listed as `complete` must actually exist: the check reads it. A
`deferred` row must name the owning phase. An `open` row is the honest inventory
of what Phase 1 does *not* know, and is part of the seal rather than a blemish on
it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    PRODUCTION_AUTHORITY,
    content_hash,
    envelope,
    rel,
    sha256_file,
    write_json,
    write_text,
    REPO_ROOT,
)

# (plane, artefact path relative to the authority atlas dir, description)
COMPLETE_PLANES: list[tuple[str, str, str]] = [
    ("authority-registry", "../../authorities/AUTHORITIES.json",
     "admitted authorities with verified archive hashes and source-tree root hashes"),
    ("build-records", "../BUILD_RECORDS.json",
     "configure argv, toolchain, platform and produced artifacts per authority"),
    ("symbols-libcrypto", "symbols-libcrypto.json",
     "four-plane reconciliation: .num vs generated .ld vs DSO exports vs ELF version nodes"),
    ("symbols-libssl", "symbols-libssl.json",
     "the same reconciliation for libssl"),
    ("symbol-versions", "symbol-versions.json",
     "version definition nodes and the ABS version markers in .dynsym"),
    ("declarations", "functions.json",
     "public function declarations from the Clang AST, with header and line"),
    ("typedefs", "typedefs.json", "public typedefs"),
    ("structs", "structs.json", "public struct and union definitions (complete and opaque)"),
    ("enums", "enums.json", "named enums and their constants"),
    ("variables", "variables.json", "exported data objects (extern declarations)"),
    ("macros", "macros.json", "macro inventory attributed to defining headers"),
    ("header-graph", "header-graph.json", "include topology and per-header macro definitions"),
    ("abi-layout", "abi-layout.json",
     "measured sizeof/alignof/offsetof from probes compiled against installed headers"),
    ("ownership-obligations", "ownership-obligations.json",
     "get0/get1/set0/set1/up_ref/free/dup/constructor obligations (declaration-derived)"),
    ("provider-inventory", "provider-inventory.json",
     "providers and the full algorithm-class inventory, from the authority's own binary"),
    ("cli-commands", "cli-commands.json", "every command with its option list"),
    ("configs", "configs.json", "configuration file inventory"),
    ("corpus-inventory", "corpus-inventory.json",
     "per-file content-addressed census of the upstream test/fuzz/provider corpora"),
    ("surface-reconciliation", "surface-reconciliation.json",
     "cross-plane agreement and classified residuals"),
    ("coverage", "coverage.json", "inventory census"),
    ("parity-obligations", "parity-obligations.json",
     "one generated obligation per externally relevant contract item"),
    ("rendered-atlas", "ATLAS.md", "Markdown projection of every atlas document"),
]

# Planes that are deliberately NOT Phase 1 work, with the owning phase.
DEFERRED_PLANES: list[tuple[str, str, str]] = [
    ("abi-cross-compile-matrix", "2",
     "the four oracle/candidate header x DSO combinations; Phase 2 has landed "
     "ABI-LINK and ABI-LAYOUT, the remaining combinations are Phase 2 work"),
    ("binary-substitution-skeleton", "2",
     "build once against OpenSSL, run against candidate DSOs; Phase 2"),
    ("static-archives-provider-modules-cli", "2",
     "libcrypto.a/libssl.a, legacy.so, the `openssl` executable and a real install layout"),
    ("ownership-behavioural-probes", "3",
     "canary-allocator and refcount probes in an oracle process; requires the core runtime"),
    ("enum-constant-values", "2",
     "enum constant integers are captured in the declaration atlas as AST values, "
     "but a compiled constant-value court belongs with the ABI shell"),
    ("frf-receipts-for-the-atlas", "1-closure",
     "FRF receipts covering the archaeology itself, compiled into a phase claim"),
]


def main() -> int:
    outdir = ATLAS / PRODUCTION_AUTHORITY
    rows = []
    missing = []

    for plane, relpath, desc in COMPLETE_PLANES:
        p = (outdir / relpath).resolve()
        if p.exists() and p.is_file():
            rows.append({"plane": plane, "status": "complete", "artifact": rel(p),
                         "description": desc, "sha256": sha256_file(p)})
        else:
            rows.append({"plane": plane, "status": "MISSING", "artifact": rel(p),
                         "description": desc})
            missing.append(plane)

    deferred = [{"plane": p, "status": "deferred", "owning_phase": ph, "reason": r}
                for p, ph, r in DEFERRED_PLANES]

    # Open unknowns: read from the reconciliation where available so the numbers
    # cannot drift from the evidence.
    recon = json.loads((outdir / "surface-reconciliation.json").read_text())["body"]
    fs = recon["function_vs_symbol"]
    unknowns = [
        {
            "unknown": "declared-but-not-in-ABI-inventory symbols",
            "count": fs["declared_not_exported_by_class"].get(
                "declared_but_not_in_abi_inventory", 0),
            "sample": fs.get("declared_not_exported_sample", {}).get(
                "declared_but_not_in_abi_inventory", [])[:11],
            "why": "declared in a public header, not exported by the DSO, and not "
                   "listed in .num. Not a defect and not yet explained; each needs "
                   "a per-symbol disposition.",
        },
        {
            "unknown": "exported symbols with no installed declaration",
            "count": fs["exported_not_declared"],
            "sample": fs["exported_not_declared_sample"][:12],
            "why": "the DSO exports them and no installed header declares them "
                   "(the DSO_* family belongs to dso.h, which the authority does "
                   "not install). A consumer can link these but cannot see a "
                   "declaration; whether the candidate must export them is an "
                   "open contract question.",
        },
        {
            "unknown": "FRF sensitivity coverage for the non-fixture-driven courts",
            "count": 2,
            "sample": ["openssl-cli-list-disabled", "openssl-cli-list-cipher"],
            "why": "docs/DECISIONS.md D13: the challenge mutant cannot locate the "
                   "reference when the court's arguments do not reference "
                   "{fixture}, so axis isolation cannot be demonstrated. Remedy: "
                   "make the courts fixture-driven. Blocks a sensitivity-backed "
                   "claim, not a baseline one.",
        },
        {
            "unknown": "panic payload not surfaced at the FFI boundary",
            "count": 1,
            "sample": ["src/ffi/mod.rs"],
            "why": "docs/DECISIONS.md D16: the payload is dropped because it is not "
                   "ABI-stable. Phase 3 surfaces the condition through the "
                   "thread-local ERR queue, which is what an OpenSSL caller "
                   "expects after a failure.",
        },
    ]

    body = {
        "authority": PRODUCTION_AUTHORITY,
        "complete_count": sum(1 for r in rows if r["status"] == "complete"),
        "missing_count": len(missing),
        "missing": missing,
        "deferred_count": len(deferred),
        "open_unknown_count": len(unknowns),
        "planes": rows,
        "deferred": deferred,
        "open_unknowns": unknowns,
        "note": "Phase 1 is archaeology only: no candidate parity is claimed "
                "anywhere in this inventory, and no obligation is PARITY_VERIFIED.",
    }
    doc = envelope("phase1-completeness", "forensics/tools/atlas_phase1_completeness.py",
                   [], body, authority=PRODUCTION_AUTHORITY)
    doc["body_hash"] = content_hash(body)
    write_json(ATLAS / "phase1-completeness.json", doc)

    L = [
        "# Phase 1 completeness",
        "",
        "Generated by `forensics/tools/atlas_phase1_completeness.py`.",
        "Every expected archaeology plane is either complete, deferred with an",
        "owning phase, or listed as an open unknown. Nothing is silently absent.",
        "",
        f"- complete: **{body['complete_count']}**",
        f"- missing: **{body['missing_count']}**",
        f"- deferred: **{body['deferred_count']}**",
        f"- open unknowns: **{body['open_unknown_count']}**",
        "",
        "## Complete planes",
        "",
        "| plane | artifact |",
        "|---|---|",
    ]
    for r in rows:
        if r["status"] == "complete":
            L.append(f"| `{r['plane']}` | `{r['artifact']}` |")
    L += ["", "## Deferred planes", "", "| plane | owning phase | reason |", "|---|---|---|"]
    for d in deferred:
        L.append(f"| `{d['plane']}` | {d['owning_phase']} | {d['reason']} |")
    L += ["", "## Open unknowns", "", "| unknown | count | why |", "|---|---|---|"]
    for u in unknowns:
        L.append(f"| {u['unknown']} | {u['count']} | {u['why']} |")
    L += ["", "## Non-claims", "",
          "No plane in this inventory carries a candidate parity claim. No",
          "obligation is `PARITY_VERIFIED`. Phase 1 establishes what must be",
          "proved and what remains unknown; it proves nothing about a candidate.",
          ""]
    write_text(ATLAS / "phase1-completeness.md", "\n".join(L))

    print(f"[phase1] complete={body['complete_count']} missing={body['missing_count']} "
          f"deferred={body['deferred_count']} unknowns={body['open_unknown_count']}")
    if missing:
        print(f"  MISSING PLANES: {missing}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
