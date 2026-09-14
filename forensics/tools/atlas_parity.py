#!/usr/bin/env python3
"""openssl-rs — atlas generator: reconciliation, coverage and parity obligations.

This is where the Phase 1 atlas becomes *claims machinery*. It consumes the
per-authority atlas produced by the other generators and emits:

    surface-reconciliation.json   cross-plane agreement and classified residuals
    coverage.json                 inventory census and plane coverage
    parity-obligations.json       one obligation per externally relevant item
    PARITY_MATRIX.md              presentation projection of the above

Reconciliation planes
---------------------
The obligation cross-check required by `docs/PARITY_MODEL.md` §4:

    .num inventory  vs  generated version script  vs  DSO exports
    declared functions  vs  exported symbols  vs  provider/CLI inventory

Every disagreement is emitted with a classification. A disagreement that cannot
be classified remains an explicit residual; it is never dropped.

Obligation states
-----------------
Nothing is implemented yet, so every obligation is `DISCOVERED` (or
`ARCHAEOLOGICAL` where the atlas carries a full provenance-bearing record). The
point of generating them now is that the *inventory of what must be proved* is
neither hand-typed nor quietly incomplete. `docs/PARITY_MODEL.md` §1 defines the
states; this generator only ever emits the honest early ones.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    all_authority_ids,
    authority_atlas_dir,
    content_hash,
    envelope,
    resolve_authority,
    write_json,
    write_text,
)

# Dimensions that must be proved before an obligation may be promoted. The set
# is per kind: a `#define` has no ownership dimension; a `get0` accessor always
# does. Applicability is itself evidence (docs/PARITY_MODEL.md §2).
DIMENSIONS_BY_KIND = {
    "symbol": ["ABI", "SEMANTIC", "OWNERSHIP", "ERROR", "STATE", "CONCURRENCY"],
    "function": ["ABI", "SEMANTIC", "OWNERSHIP", "ERROR", "STATE", "CONCURRENCY"],
    "variable": ["ABI", "SEMANTIC"],
    "typedef": ["SOURCE", "ABI"],
    "struct": ["SOURCE", "ABI"],
    "enum": ["SOURCE", "ABI"],
    "macro": ["SOURCE"],
    "header": ["SOURCE"],
    "provider_algorithm": ["PROVIDER", "SEMANTIC"],
    "disabled_feature": ["BUILD"],
    "cli_command": ["SEMANTIC", "CLI"],
    "cli_option": ["CLI"],
}


def _load(outdir: Path, name: str) -> dict | None:
    p = outdir / name
    if not p.exists():
        return None
    import json
    return json.loads(p.read_text())


def build(authority_id: str) -> tuple[dict, dict, dict]:
    auth = resolve_authority(authority_id)
    outdir = authority_atlas_dir(authority_id)
    print(f"[parity] {auth.id}")

    symbols = {}
    for lib in ("libcrypto", "libssl"):
        d = _load(outdir, f"symbols-{lib}.json")
        if d:
            symbols[lib] = d
    functions = _load(outdir, "functions.json")
    typedefs = _load(outdir, "typedefs.json")
    structs = _load(outdir, "structs.json")
    enums = _load(outdir, "enums.json")
    variables = _load(outdir, "variables.json")
    macros = _load(outdir, "macros.json")
    headers = _load(outdir, "header-graph.json")
    providers = _load(outdir, "provider-inventory.json")
    cli = _load(outdir, "cli-commands.json")
    configs = _load(outdir, "configs.json")
    corpus = _load(outdir, "corpus-inventory.json")

    # --- symbol reconciliation ------------------------------------------------
    symbol_records = {}
    for lib, doc in symbols.items():
        for rec in doc["body"]["records"]:
            symbol_records[rec["symbol"]] = (lib, rec)

    # --- declared vs exported reconciliation ----------------------------------
    declared_functions = {r["name"] for r in (functions or {}).get("body", {}).get("records", [])}
    # NOTE: `exported` is the set of symbols the *built DSO* actually defines, not
    # the set declared in `.num`. Conflating the two would misreport every
    # declared-but-not-built symbol as exported.
    exported = {
        name for name, (_lib, rec) in symbol_records.items()
        if rec.get("dso", {}).get("present")
    }

    classification = Counter()
    declared_not_exported: dict[str, list[str]] = {}
    fn_records = {r["name"]: r for r in (functions or {}).get("body", {}).get("records", [])}
    for name in sorted(declared_functions - exported):
        lib_rec = symbol_records.get(name)
        if lib_rec is not None:
            cls = lib_rec[1]["reconciliation"]
        else:
            fn = fn_records.get(name, {})
            if fn.get("inline") or fn.get("storage_class") == "static":
                # Header-only `static ossl_inline` helpers. They are declared in
                # public headers but are not part of the exported ABI, so their
                # absence from the DSO is correct, not a defect.
                cls = "static_inline_header_helper"
            else:
                cls = "declared_but_not_in_abi_inventory"
        classification[cls] += 1
        declared_not_exported.setdefault(cls, []).append(name)

    exported_not_declared = sorted(exported - declared_functions)

    reconciliation_body = {
        "planes": {
            "num_declared_symbols": sum(len(d["body"]["records"]) for d in symbols.values()),
            "version_script_symbols": sum(
                d["body"]["counts"]["version_script_symbols"] for d in symbols.values()
            ),
            "dso_exported_symbols": sum(
                d["body"]["counts"]["dso_exported_symbols"] for d in symbols.values()
            ),
            "declared_functions": len(declared_functions),
            "declared_macros": (macros or {}).get("body", {}).get("count", 0),
            "declared_headers": (headers or {}).get("body", {}).get("header_count", 0),
        },
        "symbol_hard_residuals": {
            "libcrypto": symbols.get("libcrypto", {}).get("body", {}).get("residuals", {}),
            "libssl": symbols.get("libssl", {}).get("body", {}).get("residuals", {}),
        },
        "function_vs_symbol": {
            "declared_and_exported": len(declared_functions & exported),
            "declared_not_exported": len(declared_functions - exported),
            "declared_not_exported_by_class": {k: classification[k] for k in sorted(classification)},
            "declared_not_exported_sample": {
                k: v[:10] for k, v in sorted(declared_not_exported.items())
            },
            "exported_not_declared": len(exported_not_declared),
            "exported_not_declared_sample": exported_not_declared[:25],
            "exported_not_declared_note": (
                "Symbols the built DSO exports that no *installed* public header "
                "declares. Verified for authority 3.6.4: the DSO_* family belongs "
                "to dso.h, which the authority does not install, so an application "
                "can link these but cannot see a declaration."
            ),
        },
        "explained_absences": {
            lib: {
                k: len(v) for k, v in symbols[lib]["body"]["explained_absences"].items()
            } for lib in symbols
        },
    }

    # --- coverage -------------------------------------------------------------
    coverage_body = {
        "authority": auth.id,
        "version": auth.version,
        "counts": {
            "headers": (headers or {}).get("body", {}).get("header_count", 0),
            "macros": (macros or {}).get("body", {}).get("count", 0),
            "functions_declared": (functions or {}).get("body", {}).get("count", 0),
            "typedefs": (typedefs or {}).get("body", {}).get("count", 0),
            "structs_unions": (structs or {}).get("body", {}).get("count", 0),
            "enums_named": (enums or {}).get("body", {}).get("count", 0),
            "variables": (variables or {}).get("body", {}).get("count", 0),
            "symbols_exported": reconciliation_body["planes"]["dso_exported_symbols"],
            "cli_commands": (cli or {}).get("body", {}).get("command_count", 0),
            "config_files": (configs or {}).get("body", {}).get("config_file_count", 0),
        },
        "provider_algorithm_classes": {
            k: v.get("count", 0)
            for k, v in (providers or {}).get("body", {}).get("algorithm_classes", {}).items()
        },
        "corpora": {
            k: v.get("file_count")
            for k, v in (corpus or {}).get("body", {}).items()
            if isinstance(v, dict) and "file_count" in v
        },
    }

    # --- obligations ----------------------------------------------------------
    obligations = []

    def add(kind: str, name: str, evidence: dict, *, status: str = "DISCOVERED") -> None:
        obligations.append({
            "id": f"{auth.id}:{kind}:{name}",
            "authority": auth.id,
            "kind": kind,
            "name": name,
            "status": status,
            "required_dimensions": DIMENSIONS_BY_KIND.get(kind, ["SEMANTIC"]),
            "dimension_results": {d: "UNKNOWN" for d in DIMENSIONS_BY_KIND.get(kind, [])},
            "evidence": evidence,
        })

    for name, (lib, rec) in sorted(symbol_records.items()):
        add("symbol", name, {
            "library": lib,
            "num_version": rec["num"]["version"],
            "num_conditions": rec["num"]["conditions"],
            "num_status": rec["num"]["status"],
            "dso": rec.get("dso", {}),
            "reconciliation": rec["reconciliation"],
        }, status="ARCHAEOLOGICAL" if rec["reconciliation"] == "agree" else "DISCOVERED")

    for rec in (functions or {}).get("body", {}).get("records", []):
        add("function", rec["name"], {
            "header": rec["header"], "line": rec["line"], "type": rec["type"],
            "deprecated": rec["deprecated"], "variadic": rec["variadic"],
        }, status="ARCHAEOLOGICAL")

    for rec in (typedefs or {}).get("body", {}).get("records", []):
        add("typedef", rec["name"], {"header": rec["header"], "underlying_type": rec["underlying_type"]})
    for rec in (structs or {}).get("body", {}).get("records", []):
        add("struct", f"{rec['tag']} {rec['name']}", {
            "header": rec["header"], "complete": rec["complete"], "field_count": len(rec["fields"])})
    for rec in (enums or {}).get("body", {}).get("records", []):
        add("enum", rec["name"], {"header": rec["header"], "constants": len(rec["constants"])})
    for rec in (variables or {}).get("body", {}).get("records", []):
        add("variable", rec["name"], {"header": rec["header"], "type": rec["type"]})
    for rec in (macros or {}).get("body", {}).get("records", []):
        add("macro", rec["name"], {"defined_in": rec["defined_in"], "kind": rec["kind"]})
    for name in (headers or {}).get("body", {}).get("headers", []):
        add("header", name, {"includes": (headers or {}).get("body", {}).get("edges", {}).get(name, [])})

    for cls, info in (providers or {}).get("body", {}).get("algorithm_classes", {}).items():
        entries = info.get("entries", [])
        if cls in ("disabled", "engines"):
            # These selectors list plain tokens (feature names / engine names),
            # not algorithm records. They are still contract-relevant: `disabled`
            # is the authority's own statement of what was compiled out, and it
            # explains absences elsewhere in the atlas.
            for entry in entries:
                if isinstance(entry, str) and entry:
                    add("disabled_feature", f"{cls}:{entry}", {"class": cls})
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name"):
                add("provider_algorithm", f"{cls}:{entry['name']}",
                    {"class": cls, "provider": entry.get("provider")})
    for cmd in (cli or {}).get("body", {}).get("commands", []):
        add("cli_command", cmd["name"], {"option_count": cmd["option_count"]})

    obligations.sort(key=lambda o: o["id"])
    by_kind = Counter(o["kind"] for o in obligations)
    by_status = Counter(o["status"] for o in obligations)
    print(f"  obligations: {len(obligations)}")
    for k in sorted(by_kind):
        print(f"    {k}: {by_kind[k]}")
    print(f"  reconciliation: declared_not_exported={len(declared_functions - exported)} "
          f"({dict(classification)}), exported_not_declared={len(exported_not_declared)}")

    parity_body = {
        "authority": auth.id,
        "obligation_count": len(obligations),
        "by_kind": {k: by_kind[k] for k in sorted(by_kind)},
        "by_status": {k: by_status[k] for k in sorted(by_status)},
        "promotion_rule": (
            "PARITY_VERIFIED only when every required dimension passes; "
            "UNKNOWN is distinct from FAIL (docs/PARITY_MODEL.md §1-2)"
        ),
        "obligations": obligations,
    }

    inputs_doc = envelope("surface-reconciliation", "forensics/tools/atlas_parity.py", [],
                          reconciliation_body, authority=auth.id)
    inputs_doc["body_hash"] = content_hash(reconciliation_body)
    coverage_doc = envelope("coverage", "forensics/tools/atlas_parity.py", [],
                            coverage_body, authority=auth.id)
    coverage_doc["body_hash"] = content_hash(coverage_body)
    parity_doc = envelope("parity-obligations", "forensics/tools/atlas_parity.py", [],
                          parity_body, authority=auth.id)
    parity_doc["body_hash"] = content_hash(parity_body)
    return inputs_doc, coverage_doc, parity_doc


def render_markdown(coverage: dict, parity: dict, recon: dict) -> str:
    c = coverage["body"]["counts"]
    p = parity["body"]
    r = recon["body"]
    lines = [
        "# Parity Matrix (generated)",
        "",
        "Generated by `forensics/tools/atlas_parity.py`. **Do not edit by hand.**",
        "This file is a presentation projection of machine-readable evidence; the",
        "JSON beside it is authoritative (`docs/PARITY_MODEL.md` §6).",
        "",
        f"- Authority: `{coverage['authority']}` (OpenSSL {coverage['body']['version']})",
        f"- Build profile: `linux-x86_64-default-shared-legacy-notests`",
        f"- Obligations: **{p['obligation_count']}**",
        "",
        "## Inventory census",
        "",
        "| surface | count |",
        "|---|---|",
    ]
    for k in sorted(c):
        lines.append(f"| {k.replace('_', ' ')} | {c[k]} |")
    lines += [
        "",
        "## Obligations by kind",
        "",
        "| kind | obligations |",
        "|---|---|",
    ]
    for k in sorted(p["by_kind"]):
        lines.append(f"| {k} | {p['by_kind'][k]} |")
    lines += [
        "",
        "## Obligations by state",
        "",
        "| state | obligations |",
        "|---|---|",
    ]
    for k in sorted(p["by_status"]):
        lines.append(f"| {k} | {p['by_status'][k]} |")
    fs = r["function_vs_symbol"]
    lines += [
        "",
        "## Symbol reconciliation (hard residuals must be zero)",
        "",
        "| plane | count |",
        "|---|---|",
        f"| .num declared symbols | {r['planes']['num_declared_symbols']} |",
        f"| generated version-script symbols | {r['planes']['version_script_symbols']} |",
        f"| DSO exported symbols | {r['planes']['dso_exported_symbols']} |",
        f"| declared and exported | {fs['declared_and_exported']} |",
        f"| declared not exported | {fs['declared_not_exported']} |",
        f"| exported not declared | {fs['exported_not_declared']} |",
        "",
        "### Declared-not-exported, by explanation",
        "",
        "| class | count |",
        "|---|---|",
    ]
    for k in sorted(fs["declared_not_exported_by_class"]):
        lines.append(f"| {k} | {fs['declared_not_exported_by_class'][k]} |")
    lines += [
        "",
        "## Hard residuals",
        "",
        "| location | residual | count |",
        "|---|---|---|",
    ]
    for lib in sorted(r["symbol_hard_residuals"]):
        for k, v in r["symbol_hard_residuals"][lib].items():
            lines.append(f"| {lib} | {k} | {len(v) if isinstance(v, list) else v} |")
    lines += [
        "",
        "> **Non-claims.** No cryptographic-security claim arises from OpenSSL parity;",
        "> behavioural FIPS parity is not FIPS validation; no completion percentage here",
        "> is a compatibility percentage. See `docs/NON_CLAIMS.md`.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Reconcile the atlas into parity obligations.")
    ap.add_argument("--authority", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)
    ids = all_authority_ids() if args.all else args.authority
    if not ids:
        ap.error("specify --all or --authority")

    for aid in ids:
        recon, coverage, parity = build(aid)
        outdir = authority_atlas_dir(aid)
        write_json(outdir / "surface-reconciliation.json", recon)
        write_json(outdir / "coverage.json", coverage)
        write_json(outdir / "parity-obligations.json", parity)
        write_text(outdir / "PARITY_MATRIX.md", render_markdown(coverage, parity, recon))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
