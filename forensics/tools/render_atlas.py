#!/usr/bin/env python3
"""openssl-rs — render Markdown projections of the machine-readable atlas.

`docs/PARITY_MODEL.md` §6: the machine-readable atlas is authoritative and
Markdown is *presentation*. This generator therefore derives every Markdown
document from the JSON, and never the other way round.

Generic by design: for each atlas document it prints the envelope provenance and
a table of the document's integral summary fields. A few documents additionally
get a purpose-specific projection (symbol reconciliation, parity matrix, ABI
layout) because a flat key dump would hide the thing that matters there.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    all_authority_ids,
    authority_atlas_dir,
    rel,
    resolve_authority,
    write_text,
)

# Documents whose summary is best read as prose rather than a key table.
CUSTOM = {
    "symbols-libcrypto", "symbols-libssl", "symbol-versions",
    "surface-reconciliation", "coverage", "parity-obligations",
    "abi-layout", "ownership-obligations", "corpus-inventory",
    "provider-inventory", "cli-commands",
}


def int_table(body: dict, indent: str = "") -> list[str]:
    """Rows for the integral leaf fields of a body, one level deep."""
    rows = []
    for k in sorted(body):
        v = body[k]
        if isinstance(v, int):
            rows.append(f"{indent}| `{k}` | {v} |")
        elif isinstance(v, dict) and v and all(isinstance(x, int) for x in v.values()):
            for k2 in sorted(v):
                rows.append(f"{indent}| `{k}.{k2}` | {v[k2]} |")
    return rows


def render_symbols(doc: dict) -> list[str]:
    b = doc["body"]
    c = b["counts"]
    L = [
        f"Library: `{b['library']}` ({b['soname']})",
        "",
        "| plane | count |",
        "|---|---|",
    ]
    for k in sorted(c):
        L.append(f"| `{k}` | {c[k]} |")
    L += ["", "Hard residuals (a non-zero value is a defect, not a note):", ""]
    L += ["| residual | count |", "|---|---|"]
    for k in sorted(b["residuals"]):
        v = b["residuals"][k]
        L.append(f"| `{k}` | {len(v) if isinstance(v, list) else v} |")
    L += ["", "Explained absences (absence with a reason):", ""]
    L += ["| class | count |", "|---|---|"]
    for k in sorted(b["explained_absences"]):
        L.append(f"| `{k}` | {len(b['explained_absences'][k])} |")
    return L


def render_parity(doc: dict) -> list[str]:
    b = doc["body"]
    L = [
        f"Total obligations: **{b['obligation_count']}**",
        "",
        f"Promotion rule: {b['promotion_rule']}",
        "",
        "| kind | obligations |",
        "|---|---|",
    ]
    for k in sorted(b["by_kind"]):
        L.append(f"| `{k}` | {b['by_kind'][k]} |")
    L += ["", "| state | obligations |", "|---|---|"]
    for k in sorted(b["by_status"]):
        L.append(f"| `{k}` | {b['by_status'][k]} |")
    return L


def render_reconciliation(doc: dict) -> list[str]:
    b = doc["body"]
    fs = b["function_vs_symbol"]
    L = ["| plane | count |", "|---|---|"]
    for k in sorted(b["planes"]):
        L.append(f"| `{k}` | {b['planes'][k]} |")
    L += ["", "Declared vs built:", "", "| measure | count |", "|---|---|"]
    for k in ("declared_and_exported", "declared_not_exported", "exported_not_declared"):
        L.append(f"| `{k}` | {fs[k]} |")
    L += ["", "Declared-not-exported, by explanation:", "", "| class | count |", "|---|---|"]
    for k in sorted(fs["declared_not_exported_by_class"]):
        L.append(f"| `{k}` | {fs['declared_not_exported_by_class'][k]} |")
    return L


def render_custom(name: str, doc: dict) -> list[str] | None:
    b = doc.get("body", {})
    if name in ("symbols-libcrypto", "symbols-libssl"):
        return render_symbols(doc)
    if name == "parity-obligations":
        return render_parity(doc)
    if name == "surface-reconciliation":
        return render_reconciliation(doc)
    if name == "abi-layout":
        return [
            "| measure | count |", "|---|---|",
            f"| aggregates probed | {b.get('aggregates_probed')} |",
            f"| probes ok | {b.get('aggregates_ok')} |",
            f"| probe failures (residuals) | {b.get('aggregates_failed')} |",
            f"| opaque aggregates | {b.get('opaque_aggregates')} |",
            "",
            "Layout is *measured* by compiling and running a probe against the",
            "authority's own installed headers; a failure is preserved with its",
            "diagnostic rather than dropped.",
        ]
    if name == "corpus-inventory":
        return ["| corpus | files | bytes | root hash |", "|---|---|---|---|"] + [
            f"| `{k}` | {v['file_count']} | {v['total_bytes']} | `{v['root_hash'][:16]}…` |"
            for k, v in sorted(b.items())
            if isinstance(v, dict) and "file_count" in v
        ]
    if name == "provider-inventory":
        rows = ["| class | count |", "|---|---|"]
        rows += [f"| `{k}` | {v.get('count', 0)} |"
                 for k, v in sorted(b.get("algorithm_classes", {}).items())]
        rows += ["", "Loaded providers: " + ", ".join(
            p["name"] for p in b.get("providers", []))]
        return rows
    if name == "cli-commands":
        return [f"Commands: **{b.get('command_count')}**",
                "", "| command | options |", "|---|---|"] + [
            f"| `{c['name']}` | {c['option_count']} |" for c in b.get("commands", [])
        ]
    if name == "ownership-obligations":
        return ["| convention | obligations |", "|---|---|"] + [
            f"| `{k}` | {b['by_kind'][k]} |" for k in sorted(b.get("by_kind", {}))
        ]
    return None


def render_document(path: Path) -> str:
    doc = json.loads(path.read_text())
    name = path.stem
    L = [f"# `{path.name}`", ""]
    L.append(f"- schema: `{doc.get('schema')}`")
    L.append(f"- generator: `{doc.get('generator')}`")
    if doc.get("authority"):
        L.append(f"- authority: `{doc['authority']}`")
    if doc.get("body_hash"):
        L.append(f"- body hash: `{doc['body_hash']}`")
    L.append("")
    inputs = doc.get("inputs") or []
    if inputs:
        L += ["Inputs:", ""]
        for i in inputs:
            sha = f" `{i['sha256'][:16]}…`" if i.get("sha256") else ""
            note = f" — {i['note']}" if i.get("note") else ""
            L.append(f"- `{i.get('name')}`{sha}{note}")
        L.append("")
    custom = render_custom(name, doc)
    if custom is not None:
        L += custom
    else:
        rows = int_table(doc.get("body", {}))
        if rows:
            L += ["| summary field | value |", "|---|---|"] + rows
        else:
            L.append("_No integral summary fields; see the JSON._")
    L.append("")
    return "\n".join(L)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Render Markdown projections of the atlas.")
    ap.add_argument("--authority", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)
    ids = all_authority_ids() if args.all else args.authority
    if not ids:
        ap.error("specify --all or --authority")

    for aid in ids:
        auth = resolve_authority(aid)
        outdir = authority_atlas_dir(aid)
        sections = [f"# Atlas — `{auth.id}` (OpenSSL {auth.version})", ""]
        sections += [
            "Generated by `forensics/tools/render_atlas.py` from the",
            "machine-readable atlas. **Do not edit by hand.** The JSON is",
            "authoritative; this file is presentation (`docs/PARITY_MODEL.md` §6).",
            "",
        ]
        docs = sorted(p for p in outdir.glob("*.json"))
        for p in docs:
            sections.append(render_document(p))
            sections.append("---")
            sections.append("")
        write_text(outdir / "ATLAS.md", "\n".join(sections))
        print(f"[render] {rel(outdir / 'ATLAS.md')} ({len(docs)} documents)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
