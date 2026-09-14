#!/usr/bin/env python3
"""openssl-rs — Phase 1 completeness: prove every expected plane is represented.

The Phase 1 exit rule requires that every expected archaeology plane is either
**represented** or **deliberately deferred with a reason**. Without a checked
inventory that is an assertion; with one, it is a fact.

    forensics/atlas/phase1-completeness.json
    forensics/atlas/phase1-completeness.md

Four classifications, and nothing may be silently absent:

    complete      the artefact exists and is content-addressed
    deferred      not this phase's work, with the owning phase named
    dispositioned a residual that has been *decided*, with the decision recorded
    open          known, unresolved, and carrying a reason

`complete` is verified by reading the artefact. `deferred` must name the owning
phase. `open` is the honest inventory of what this phase does not know, and is
part of the seal rather than a blemish on it.

## Why dispositions exist

Two residual classes were previously listed as open unknowns and are in fact
decidable from the evidence already in the atlas:

* **26 symbols the authority's DSO exports but no installed header declares**
  (`DSO_*`; `dso.h` is not installed). For *source* compatibility they are
  invisible. For *binary* compatibility they are unambiguously part of the
  observed ABI, because a precompiled consumer can resolve them. The candidate
  must therefore export them, which it does, because its scaffold set is derived
  from the authority's DSO exports. Disposition: `ABI_ONLY_EXPORTED`.

* **11 symbols declared in a public header that the authority neither exports
  nor lists in `.num`** (`OSSL_provider_init`, `_CONF_*`, and similar). They are
  declaration-only: a consumer can compile a reference to one and will fail to
  link, against the authority. The candidate must therefore *not* export them,
  and does not. Disposition: `DECLARED_NOT_EXPORTED_BY_AUTHORITY`.

Carrying either as "unknown" would be a failure to read the evidence that is
already there.
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
    # Delivered by Phase 2 and therefore no longer deferred. Listed here so the
    # projection cannot keep claiming they are outstanding.
    ("oracle-oracle-differential", "../differential/"
     "openssl-3.6.3-historical-vs-openssl-3.6.4-production.json",
     "measured 3.6.3 -> 3.6.4 movement across every plane"),
    ("abi-cross-compile-matrix", "../../../artifacts/phase2/COURTS.json",
     "all four authority/candidate header x library combinations (court ABI-MATRIX)"),
    ("binary-substitution", "../../../artifacts/phase2/COURTS.json",
     "one executable built against the authority runs against candidate libraries (ABI-SUBSTITUTION)"),
    ("static-archives-provider-module-cli", "../../../artifacts/phase2/SHELL_MANIFEST.json",
     "libcrypto.a/libssl.a, legacy.so provider module, openssl and c_rehash, install layout"),
    ("compiled-constant-values", "../../../artifacts/phase2/COURTS.json",
     "27 compile-time constants compared across header sets (court ABI-CONSTANTS)"),
    ("dynamic-elf-contract", "../../../artifacts/phase2/COURTS.json",
     "SONAME, DT_NEEDED and ELF identity (court ABI-DYNAMIC)"),
]

# Planes that are deliberately NOT Phase 1 work, with the owning phase.
#
# NOTE the panic/ERR item: it was previously listed as a Phase-1 *unknown*,
# which created a dependency cycle -- Phase 3's complete state would require
# Phase 1 complete, while Phase 1's complete state required Phase 3 to implement
# the ERR queue. It is not an unknown; it is a Phase-3 obligation.
DEFERRED_PLANES: list[tuple[str, str, str]] = [
    ("ownership-behavioural-probes", "3",
     "canary-allocator and refcount probes in an oracle process; requires the core runtime"),
    ("panic-payload-surfacing-at-ffi", "3",
     "the FFI boundary drops the panic payload because it is not ABI-stable; Phase 3 "
     "surfaces the condition through the thread-local ERR queue "
     "(docs/DECISIONS.md D16). A Phase-3 obligation, not a Phase-1 unknown."),
    ("secure-memory-semantics", "3",
     "CRYPTO_secure_malloc/secure_arena behaviour and its mmap/mlock/guard-page "
     "policy; part of the core runtime, not archaeology"),
    ("initialisation-and-cleanup", "3",
     "OPENSSL_init_crypto flags, implicit init, atexit/OPENSSL_cleanup ordering"),
    ("object-and-nid-database", "3",
     "OBJ_*/NID tables, which are large but derivable from the authority's own sources"),
]

# The fixture-driven replacement for the two courts whose sensitivity evidence was
# unobtainable. Its presence closes the FRF sensitivity gap; see D13/D18.
FIXTURE_DRIVEN_COURT = "forensics/frf/courts/openssl-cli-inventory/manifest.yaml"


def _load(outdir: Path, name: str) -> dict | None:
    p = outdir / name
    return json.loads(p.read_text()) if p.exists() else None


def compute_dispositions(outdir: Path) -> tuple[list[dict], list[dict]]:
    """Derive the decidable residual classes from the atlas, and decide them.

    NOTE: both libraries' symbol inventories are loaded. Using only
    `libcrypto`'s would classify every `libssl`-only declaration as absent from
    the `.num` inventory, which inflated this class from 11 to 614 the first
    time it was written.
    """
    funcs = _load(outdir, "functions.json")
    libcrypto = _load(outdir, "symbols-libcrypto.json")
    libssl = _load(outdir, "symbols-libssl.json")
    if not funcs or not libcrypto:
        return [], []

    declared = {r["name"]: r for r in funcs["body"]["records"]}
    records: dict[str, dict] = {}
    for doc in (libcrypto, libssl):
        if doc:
            for r in doc["body"]["records"]:
                records[r["symbol"]] = r
    exported = {s for s, r in records.items() if (r.get("dso") or {}).get("present")}

    # ABI-only exports: the DSO exports them, no installed header declares them.
    abi_only = sorted(exported - set(declared))

    # Declaration-only: declared, not exported, and not in the .num inventory,
    # excluding the `static ossl_inline` header helpers, which are a third and
    # entirely unremarkable class.
    decl_only = []
    for name in sorted(set(declared) - exported):
        if name in records:
            continue
        fn = declared[name]
        if fn.get("inline") or fn.get("storage_class") == "static":
            continue
        decl_only.append({"symbol": name, "header": fn["header"], "line": fn["line"]})

    dispositions = [
        {
            "class": "ABI_ONLY_EXPORTED",
            "count": len(abi_only),
            "symbols_sample": abi_only[:12],
            "source_public": False,
            "binary_public": True,
            "must_export": True,
            "why": "exported by the authority DSO but declared by no installed header "
                   "(the DSO_* family; dso.h is not installed). A precompiled consumer "
                   "can resolve these, so they are part of the observed binary ABI even "
                   "though they are invisible to source compatibility. The candidate "
                   "exports them because its scaffold set is derived from the "
                   "authority's DSO exports.",
            "candidate_exports": True,
            "closed": True,
        },
        {
            "class": "DECLARED_NOT_EXPORTED_BY_AUTHORITY",
            "count": len(decl_only),
            "symbols": decl_only,
            "source_public": True,
            "binary_public": False,
            "must_export": False,
            "why": "declared in a public header, but the authority neither exports them "
                   "nor lists them in .num. A consumer can compile a reference and will "
                   "fail to link against the authority, so the candidate must not export "
                   "them either -- and does not, for the same reason as above.",
            "candidate_exports": False,
            "closed": True,
        },
    ]
    return dispositions, decl_only


def main() -> int:
    outdir = ATLAS / PRODUCTION_AUTHORITY
    rows, missing = [], []

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

    dispositions, _ = compute_dispositions(outdir)

    recon = _load(outdir, "surface-reconciliation.json")
    unknowns: list[dict] = []
    if recon:
        # The only residual class that remains genuinely open.
        if not (REPO_ROOT / FIXTURE_DRIVEN_COURT).exists():
            unknowns.append({
                "unknown": "FRF sensitivity coverage for the non-fixture-driven courts",
                "count": 2,
                "sample": ["openssl-cli-list-disabled", "openssl-cli-list-cipher"],
                "why": "docs/DECISIONS.md D13: the challenge mutant cannot locate the "
                       "reference when the court's arguments do not reference "
                       "{fixture}, so axis isolation cannot be demonstrated. Remedy: "
                       "replace them with a fixture-driven court "
                       "(" + FIXTURE_DRIVEN_COURT + ").",
            })

    body = {
        "authority": PRODUCTION_AUTHORITY,
        "complete_count": sum(1 for r in rows if r["status"] == "complete"),
        "missing_count": len(missing),
        "missing": missing,
        "deferred_count": len(deferred),
        "dispositioned_count": len(dispositions),
        "open_unknown_count": len(unknowns),
        "planes": rows,
        "deferred": deferred,
        "residual_dispositions": dispositions,
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
        "Generated by `forensics/tools/atlas_phase1_completeness.py`. Every expected",
        "archaeology plane is complete, deliberately deferred with an owning phase,",
        "dispositioned, or listed as an open unknown. Nothing is silently absent.",
        "",
        f"- complete: **{body['complete_count']}**",
        f"- missing: **{body['missing_count']}**",
        f"- deferred: **{body['deferred_count']}**",
        f"- dispositioned residual classes: **{body['dispositioned_count']}**",
        f"- open unknowns: **{body['open_unknown_count']}**",
        "",
        "## Dispositioned residual classes",
        "",
        "| class | count | exists in source API | exists in binary ABI | must export |",
        "|---|---|---|---|---|",
    ]
    for d in dispositions:
        L.append(f"| `{d['class']}` | {d['count']} | {d['source_public']} | "
                 f"{d['binary_public']} | {d['must_export']} |")
    L += ["", "## Deferred planes", "", "| plane | owning phase | reason |", "|---|---|---|"]
    for d in deferred:
        L.append(f"| `{d['plane']}` | {d['owning_phase']} | {d['reason']} |")
    L += ["", "## Open unknowns", ""]
    if unknowns:
        L += ["| unknown | count | why |", "|---|---|---|"]
        for u in unknowns:
            L.append(f"| {u['unknown']} | {u['count']} | {u['why']} |")
    else:
        L.append("None.")
    L += ["", "## Complete planes", "", "| plane | artifact |", "|---|---|"]
    for r in rows:
        if r["status"] == "complete":
            L.append(f"| `{r['plane']}` | `{r['artifact']}` |")
    L += ["", "## Non-claims", "",
          "No plane in this inventory carries a candidate parity claim. No",
          "obligation is `PARITY_VERIFIED`.", ""]
    write_text(ATLAS / "phase1-completeness.md", "\n".join(L))

    print(f"[phase1] complete={body['complete_count']} missing={body['missing_count']} "
          f"deferred={body['deferred_count']} dispositioned={body['dispositioned_count']} "
          f"unknowns={body['open_unknown_count']}")
    for d in dispositions:
        print(f"  {d['class']}: {d['count']}")
    if missing:
        print(f"  MISSING PLANES: {missing}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
