#!/usr/bin/env python3
"""openssl-rs — atlas generator: symbol and symbol-version inventories.

Produces, per authority:

    forensics/atlas/<authority>/symbols-libcrypto.json
    forensics/atlas/<authority>/symbols-libssl.json
    forensics/atlas/<authority>/symbol-versions.json

Four evidence planes are reconciled, because a symbol that appears in one plane
but not another is a *residual*, not an inconvenience:

    A. util/libcrypto.num / util/libssl.num
       The upstream linker inventory: the authoritative declaration of what the
       ABI promises, carrying ordinals, version nodes, a STATUS (EXIST/NOEXIST),
       an optional platform scope, and build conditions (DEPRECATEDIN_3_0, EC,
       CRYPTO_MDEBUG, ...).

    B. <build>/libcrypto.ld / libssl.ld
       The generated GNU ld version script. This is the *build-profile-specific*
       export promise: util/mkdef.pl filters plane A through the configure
       configuration to produce it. The difference A \\ B is exactly the set of
       exclusions this build profile made, so it is the correct way to explain
       an absence instead of guessing from condition strings.

    C. The built DSO dynamic symbol table.
       This is what downstream binaries actually bind against.

    D. The ELF version-definition section (--version-info) and the version
       markers the linker emits into .dynsym as ABSOLUTE OBJECT symbols named
       `OPENSSL_3.x.y`. These markers are NOT API symbols and are excluded from
       plane C; they are recorded separately as the version namespace identity.

Absence is classified, never assumed to be a defect:

    declared_nonexistent   .num says NOEXIST  -> correctly absent
    platform_scoped        .num scopes to VMS -> correctly absent on ELF
    excluded_by_build_profile  present in .num, absent from the generated .ld
                           -> the build configuration excluded it
    unexplained_absent     expected everywhere, yet missing -> HARD residual
    exported_undeclared    exported, but the build's own .ld does not list it
                           -> HARD residual

No wall-clock, path or environment value is written; see atlas_common.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    Authority,
    InputRef,
    all_authority_ids,
    authority_atlas_dir,
    authority_build_dir,
    content_hash,
    envelope,
    parse_num_file,
    parse_version_script,
    read_dynsyms,
    read_version_definition_names,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

# Libraries the distribution contract requires. Keys are linker names; the
# runtime SONAMEs are in the value.
LIBRARIES = {
    "libcrypto": {"num": "util/libcrypto.num", "soname": "libcrypto.so.3"},
    "libssl": {"num": "util/libssl.num", "soname": "libssl.so.3"},
}


def _is_version_marker(name: str, ndx: str) -> bool:
    """True for the ABS `OPENSSL_3.x.y` markers the linker emits into .dynsym."""
    return ndx == "ABS" and name.startswith("OPENSSL_")


def build_library_atlas(auth: Authority, lib: str) -> dict:
    spec = LIBRARIES[lib]
    num_path = auth.source / spec["num"]
    dso_path = auth.dso(lib)
    ld_path = authority_build_dir(auth.id) / f"{lib}.ld"

    num_entries, unparsed = parse_num_file(num_path)
    by_symbol = {e.symbol: e for e in num_entries}
    dupes = [s for s, n in Counter(e.symbol for e in num_entries).items() if n > 1]
    if dupes:
        raise SystemExit(f"FATAL: duplicate symbols in {num_path}: {sorted(dupes)}")

    ld_nodes = parse_version_script(ld_path)
    ld_node_of: dict[str, str] = {}
    for node, syms in ld_nodes.items():
        for s in syms:
            ld_node_of.setdefault(s, node)
    ld_symbols = set(ld_node_of)

    dynsyms = read_dynsyms(dso_path)
    version_markers = sorted(s.name for s in dynsyms if _is_version_marker(s.name, s.ndx))
    exported = {
        s.name: s for s in dynsyms
        if s.defined and s.bind in ("GLOBAL", "WEAK") and s.ndx != "ABS"
    }

    records: list[dict] = []
    explained = {
        "declared_nonexistent": [],
        "platform_scoped": [],
        "excluded_by_build_profile": [],
    }
    residuals = {
        "unexplained_absent": [],
        "exported_undeclared": [],
        "version_mismatch": [],
        "kind_mismatch": [],
    }

    for symbol in sorted(by_symbol):
        e = by_symbol[symbol]
        d = exported.get(symbol)
        rec: dict = {
            "symbol": symbol,
            "num": {
                "ordinal": e.ordinal,
                "version": e.version_node,
                "status": e.status,
                "platform": e.platform,
                "kind": e.kind,
                "conditions": e.conditions,
                "deprecated": e.deprecated,
            },
            "in_version_script": symbol in ld_symbols,
        }
        if d is not None:
            rec["dso"] = {
                "present": True,
                "type": d.stype,
                "bind": d.bind,
                "visibility": d.vis,
                "version": d.version,
                "size": d.size,
            }
            if not rec["in_version_script"]:
                # The build exported something its own version script omitted.
                rec["reconciliation"] = "exported_undeclared"
                residuals["exported_undeclared"].append(symbol)
            else:
                ld_version = ld_node_of.get(symbol)
                if e.version_node != ld_version:
                    rec["reconciliation"] = "version_mismatch"
                    residuals["version_mismatch"].append({
                        "symbol": symbol, "kind": "num_vs_version_script",
                        "num_version": e.version_node, "ld_version": ld_version,
                    })
                elif d.version != ld_version:
                    rec["reconciliation"] = "version_mismatch"
                    residuals["version_mismatch"].append({
                        "symbol": symbol, "kind": "dso_vs_version_script",
                        "dso_version": d.version, "ld_version": ld_version,
                    })
                elif e.kind and not _kind_agrees(e.kind, d.stype):
                    rec["reconciliation"] = "kind_mismatch"
                    residuals["kind_mismatch"].append({
                        "symbol": symbol, "num_kind": e.kind, "dso_type": d.stype,
                    })
                else:
                    rec["reconciliation"] = "agree"
        else:
            rec["dso"] = {"present": False}
            if e.declared_nonexistent:
                rec["reconciliation"] = "declared_nonexistent"
                explained["declared_nonexistent"].append(symbol)
            elif e.platform_scoped_away:
                rec["reconciliation"] = "platform_scoped"
                explained["platform_scoped"].append(symbol)
            elif symbol not in ld_symbols:
                rec["reconciliation"] = "excluded_by_build_profile"
                explained["excluded_by_build_profile"].append(symbol)
            else:
                rec["reconciliation"] = "unexplained_absent"
                residuals["unexplained_absent"].append(symbol)
        records.append(rec)

    # Symbols the build exported that the .num inventory never declares.
    dso_only = []
    for s in sorted(set(exported) - set(by_symbol)):
        d = exported[s]
        dso_only.append({
            "symbol": s,
            "type": d.stype,
            "bind": d.bind,
            "visibility": d.vis,
            "version": d.version,
            "size": d.size,
            "in_version_script": s in ld_symbols,
        })
    residuals["dso_only_unlisted"] = [r["symbol"] for r in dso_only if not r["in_version_script"]]

    # Version-script symbols that .num never declares (aliases, linker helpers).
    ld_only = sorted(ld_symbols - set(by_symbol))

    agree = sum(1 for r in records if r["reconciliation"] == "agree")
    counts = {
        "num_entries": len(records),
        "num_unparsed_lines": len(unparsed),
        "num_ordinal_max": max((e.ordinal for e in num_entries), default=0),
        "num_status_nonexist": sum(1 for e in num_entries if e.declared_nonexistent),
        "num_platform_scoped": sum(1 for e in num_entries if e.platform_scoped_away),
        "num_deprecated": sum(1 for e in num_entries if e.deprecated),
        "version_script_symbols": len(ld_symbols),
        "version_script_nodes": len(ld_nodes),
        "dso_exported_symbols": len(exported),
        "dso_version_markers": len(version_markers),
        "reconciled_agree": agree,
        "explained_absent": sum(len(v) for v in explained.values()),
        "unexplained_absent": len(residuals["unexplained_absent"]),
        "exported_undeclared": len(residuals["exported_undeclared"]),
        "version_mismatch": len(residuals["version_mismatch"]),
        "kind_mismatch": len(residuals["kind_mismatch"]),
        "dso_only": len(dso_only),
        "dso_only_unlisted": len(residuals["dso_only_unlisted"]),
        "version_script_only": len(ld_only),
    }

    body = {
        "library": lib,
        "soname": spec["soname"],
        "planes": {
            "num": {
                "path": rel(num_path),
                "sha256": sha256_file(num_path),
                "unparsed_lines": unparsed,
            },
            "version_script": {
                "path": rel(ld_path),
                "sha256": sha256_file(ld_path),
                "node_symbol_counts": {n: len(s) for n, s in sorted(ld_nodes.items())},
            },
            "dso": {
                "path": rel(dso_path),
                "sha256": sha256_file(dso_path),
                "size_bytes": dso_path.stat().st_size,
            },
        },
        "version_definition_markers": version_markers,
        "records": records,
        "dso_only": dso_only,
        "version_script_only": ld_only,
        "explained_absences": explained,
        "residuals": residuals,
        "counts": counts,
    }
    doc = envelope(
        "symbols", "forensics/tools/atlas_symbols.py",
        [InputRef("num_inventory", num_path),
         InputRef("version_script", ld_path),
         InputRef("dso", dso_path)],
        body, authority=auth.id,
    )
    doc["body_hash"] = content_hash(body)
    return doc


def _kind_agrees(num_kind: str, dso_type: str) -> bool:
    if num_kind == "FUNCTION":
        return dso_type in ("FUNC", "IFUNC")
    if num_kind == "VARIABLE":
        return dso_type == "OBJECT"
    return True


def build_version_atlas(auth: Authority, lib_atlases: dict[str, dict]) -> dict:
    """Version namespaces per DSO, plus per-version symbol counts.

    The per-version counts are derived from the DSO bindings (plane C) so they
    describe what a downstream binary would actually resolve to.
    """
    libs = {}
    for lib, atlas in sorted(lib_atlases.items()):
        dso_path = auth.dso(lib)
        defs = read_version_definition_names(dso_path)
        per_version: dict[str, int] = defaultdict(int)
        for rec in atlas["body"]["records"]:
            d = rec.get("dso", {})
            if d.get("present"):
                per_version[d.get("version") or "(unversioned)"] += 1
        for node in atlas["body"]["version_definition_markers"]:
            per_version.setdefault(node, 0)
        libs[lib] = {
            "soname": LIBRARIES[lib]["soname"],
            "path": rel(dso_path),
            "sha256": sha256_file(dso_path),
            "version_definitions": defs,
            "version_markers_in_dynsym": atlas["body"]["version_definition_markers"],
            "symbol_count_by_version": dict(sorted(per_version.items())),
        }
    body = {"libraries": libs}
    doc = envelope(
        "symbol-versions", "forensics/tools/atlas_symbols.py",
        [InputRef("libcrypto_dso", auth.dso("libcrypto")),
         InputRef("libssl_dso", auth.dso("libssl"))],
        body, authority=auth.id,
    )
    doc["body_hash"] = content_hash(body)
    return doc


def generate(authority_id: str) -> dict[str, str]:
    auth = resolve_authority(authority_id)
    outdir = authority_atlas_dir(authority_id)
    print(f"[symbols] {auth.id} ({auth.version})")
    outputs: dict[str, str] = {}
    lib_atlases = {}
    for lib in sorted(LIBRARIES):
        atlas = build_library_atlas(auth, lib)
        lib_atlases[lib] = atlas
        path = outdir / f"symbols-{lib}.json"
        outputs[path.name] = write_json(path, atlas)
        c = atlas["body"]["counts"]
        print(f"  {lib}: num={c['num_entries']} ld={c['version_script_symbols']} "
              f"dso={c['dso_exported_symbols']} agree={c['reconciled_agree']} "
              f"explained_absent={c['explained_absent']}")
        print(f"       unexplained_absent={c['unexplained_absent']} "
              f"exported_undeclared={c['exported_undeclared']} "
              f"ver_mismatch={c['version_mismatch']} kind_mismatch={c['kind_mismatch']} "
              f"dso_only_unlisted={c['dso_only_unlisted']} ld_only={c['version_script_only']}")
    ver = build_version_atlas(auth, lib_atlases)
    path = outdir / "symbol-versions.json"
    outputs[path.name] = write_json(path, ver)
    print(f"  version nodes libcrypto: "
          f"{ver['body']['libraries']['libcrypto']['version_definitions']}")
    return outputs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate symbol atlas.")
    ap.add_argument("--authority", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)

    ids = all_authority_ids() if args.all else args.authority
    if not ids:
        ap.error("specify --all or --authority")

    for aid in ids:
        generate(aid)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
