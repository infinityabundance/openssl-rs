#!/usr/bin/env python3
"""openssl-rs — atlas generator: the oracle-vs-oracle differential atlas.

Two separately generated inventories are not a trajectory. This generator
computes the actual *movement* between the admitted historical authority
(OpenSSL 3.6.3) and the production authority (OpenSSL 3.6.4) across every
archaeology plane, and records it as one artifact:

    forensics/atlas/differential/openssl-3.6.3-vs-3.6.4.json
    forensics/atlas/differential/openssl-3.6.3-vs-3.6.4.md

This is the atlas-side counterpart of the FRF oracle-vs-oracle courts
(`forensics/frf/`): the courts observe *behaviour* on fixtures, this observes the
*contract surface*. Together they answer "what actually changed upstream?"
before any candidate exists — which is what `docs/SECURITY_DIVERGENCE_POLICY.md`
§1 requires, so that later effort is not spent reproducing a 3.6.3 quirk that
upstream itself removed.

Direction matters and is fixed: **from** the historical authority **to** the
production authority. `added` therefore means "present in 3.6.4, absent in
3.6.3".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    HISTORICAL_AUTHORITY,
    PRODUCTION_AUTHORITY,
    InputRef,
    content_hash,
    envelope,
    rel,
    sha256_file,
    write_json,
    write_text,
)

OUTDIR = ATLAS / "differential"

# (plane, atlas file) pairs whose *record key* allows a set comparison.
SET_PLANES = [
    ("functions", "functions.json", lambda r: r["name"]),
    ("typedefs", "typedefs.json", lambda r: r["name"]),
    ("structs", "structs.json", lambda r: f"{r['tag']} {r['name']}"),
    ("enums", "enums.json", lambda r: r["name"]),
    ("variables", "variables.json", lambda r: r["name"]),
    ("macros", "macros.json", lambda r: r["name"]),
]


def load(authority_id: str, name: str) -> dict | None:
    p = ATLAS / authority_id / name
    if not p.exists():
        return None
    return json.loads(p.read_text())


def diff_sets(old: dict[str, dict], new: dict[str, dict]) -> dict:
    o, n = set(old), set(new)
    return {
        "common": len(o & n),
        "added_in_to": sorted(n - o),
        "removed_in_to": sorted(o - n),
        "added_count": len(n - o),
        "removed_count": len(o - n),
    }


def plane_symbols(from_id: str, to_id: str) -> dict:
    out = {}
    for lib in ("libcrypto", "libssl"):
        a = load(from_id, f"symbols-{lib}.json")
        b = load(to_id, f"symbols-{lib}.json")
        if not a or not b:
            continue
        oa = {r["symbol"]: r for r in a["body"]["records"]}
        ob = {r["symbol"]: r for r in b["body"]["records"]}
        d = diff_sets(oa, ob)
        ver_changed = []
        kind_changed = []
        for s in sorted(set(oa) & set(ob)):
            va = (oa[s].get("dso") or {}).get("version")
            vb = (ob[s].get("dso") or {}).get("version")
            if va != vb:
                ver_changed.append({"symbol": s, "from": va, "to": vb})
        out[lib] = {**d, "version_changed": ver_changed,
                    "version_changed_count": len(ver_changed),
                    "kind_changed": kind_changed}
    return out


def plane_abi_layout(from_id: str, to_id: str) -> dict:
    a = load(from_id, "abi-layout.json")
    b = load(to_id, "abi-layout.json")
    if not a or not b:
        return {}
    oa = {r["aggregate"]: r for r in a["body"]["records"] if r.get("probe_status") == "ok"}
    ob = {r["aggregate"]: r for r in b["body"]["records"] if r.get("probe_status") == "ok"}
    d = diff_sets(oa, ob)
    changed = []
    for agg in sorted(set(oa) & set(ob)):
        ra, rb = oa[agg], ob[agg]
        if ra["sizeof"] != rb["sizeof"] or ra["alignof"] != rb["alignof"]:
            changed.append({"aggregate": agg, "from_sizeof": ra["sizeof"],
                            "to_sizeof": rb["sizeof"]})
            continue
        if ra["field_offsetof"] != rb["field_offsetof"]:
            changed.append({"aggregate": agg, "note": "field offsets differ"})
    out = {**d, "layout_changed": changed, "layout_changed_count": len(changed),
           "opaque_from": a["body"]["opaque_aggregates"],
           "opaque_to": b["body"]["opaque_aggregates"]}
    return out


def plane_providers(from_id: str, to_id: str) -> dict:
    a = load(from_id, "provider-inventory.json")
    b = load(to_id, "provider-inventory.json")
    if not a or not b:
        return {}
    out = {}
    ca = a["body"]["algorithm_classes"]
    cb = b["body"]["algorithm_classes"]
    for cls in sorted(set(ca) | set(cb)):
        ea = {e["name"] for e in ca.get(cls, {}).get("entries", []) if isinstance(e, dict)}
        eb = {e["name"] for e in cb.get(cls, {}).get("entries", []) if isinstance(e, dict)}
        if cls == "disabled":
            ea = {e for e in ca.get(cls, {}).get("entries", []) if isinstance(e, str)}
            eb = {e for e in cb.get(cls, {}).get("entries", []) if isinstance(e, str)}
        if ea != eb:
            out[cls] = {"added": sorted(eb - ea), "removed": sorted(ea - eb)}
    return out


def plane_cli(from_id: str, to_id: str) -> dict:
    a = load(from_id, "cli-commands.json")
    b = load(to_id, "cli-commands.json")
    if not a or not b:
        return {}
    ca = {c["name"]: c for c in a["body"]["commands"]}
    cb = {c["name"]: c for c in b["body"]["commands"]}
    d = diff_sets(ca, cb)
    opt_changes = {}
    for name in sorted(set(ca) & set(cb)):
        oa = {o["name"] for o in ca[name]["options"]}
        ob = {o["name"] for o in cb[name]["options"]}
        if oa != ob:
            opt_changes[name] = {"added": sorted(ob - oa), "removed": sorted(oa - ob)}
    return {**d, "option_changes": opt_changes,
            "option_changes_count": len(opt_changes),
            "from_count": a["body"]["command_count"],
            "to_count": b["body"]["command_count"]}


def plane_corpus(from_id: str, to_id: str) -> dict:
    a = load(from_id, "corpus-inventory.json")
    b = load(to_id, "corpus-inventory.json")
    if not a or not b:
        return {}
    out = {}
    for k in sorted(set(a["body"]) | set(b["body"])):
        va, vb = a["body"].get(k), b["body"].get(k)
        if not isinstance(va, dict) or not isinstance(vb, dict) or "files" not in va:
            continue
        fa = {f["path"] for f in va["files"]}
        fb = {f["path"] for f in vb["files"]}
        out[k] = {
            "added_count": len(fb - fa), "removed_count": len(fa - fb),
            "from_root_hash": va["root_hash"], "to_root_hash": vb["root_hash"],
            "identical": va["root_hash"] == vb["root_hash"],
        }
    return out


def plane_headers(from_id: str, to_id: str) -> dict:
    a = load(from_id, "header-graph.json")
    b = load(to_id, "header-graph.json")
    if not a or not b:
        return {}
    ha = set(a["body"]["headers"])
    hb = set(b["body"]["headers"])
    edge_changes = {}
    ea, eb = a["body"]["edges"], b["body"]["edges"]
    for h in sorted(ha & hb):
        if sorted(ea.get(h, [])) != sorted(eb.get(h, [])):
            edge_changes[h] = {"added": sorted(set(eb.get(h, [])) - set(ea.get(h, []))),
                               "removed": sorted(set(ea.get(h, [])) - set(eb.get(h, [])))}
    return {"added_headers": sorted(hb - ha), "removed_headers": sorted(ha - hb),
            "edge_changes": edge_changes, "edge_changes_count": len(edge_changes)}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate the differential atlas.")
    ap.add_argument("--from", dest="from_id", default=HISTORICAL_AUTHORITY)
    ap.add_argument("--to", dest="to_id", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    from_id, to_id = args.from_id, args.to_id
    print(f"[differential] {from_id} -> {to_id}")

    planes: dict[str, dict] = {}
    for plane, fname, keyfn in SET_PLANES:
        a = load(from_id, fname)
        b = load(to_id, fname)
        if not a or not b:
            continue
        planes[plane] = diff_sets(
            {keyfn(r): r for r in a["body"]["records"]},
            {keyfn(r): r for r in b["body"]["records"]},
        )
    planes["symbols"] = plane_symbols(from_id, to_id)
    planes["abi_layout"] = plane_abi_layout(from_id, to_id)
    planes["provider_algorithms"] = plane_providers(from_id, to_id)
    planes["cli"] = plane_cli(from_id, to_id)
    planes["corpus"] = plane_corpus(from_id, to_id)
    planes["headers"] = plane_headers(from_id, to_id)

    # Movement summary: what did the release actually change, on this surface?
    symbol_movement = sum(
        v.get("added_count", 0) + v.get("removed_count", 0) + v.get("version_changed_count", 0)
        for v in (planes.get("symbols") or {}).values()
    )
    declared_movement = sum(
        p.get("added_count", 0) + p.get("removed_count", 0)
        for k, p in planes.items() if k in {p_[0] for p_ in SET_PLANES}
    )
    layout_movement = planes.get("abi_layout", {}).get("layout_changed_count", 0)
    provider_movement = sum(
        len(v.get("added", [])) + len(v.get("removed", []))
        for v in (planes.get("provider_algorithms") or {}).values()
    )
    cli_movement = planes.get("cli", {}).get("added_count", 0) + \
        planes.get("cli", {}).get("removed_count", 0) + \
        planes.get("cli", {}).get("option_changes_count", 0)

    body = {
        "from_authority": from_id,
        "to_authority": to_id,
        "direction": "added means present in 'to', absent in 'from'",
        "planes": planes,
        "movement": {
            "symbol_movement": symbol_movement,
            "declared_declaration_movement": declared_movement,
            "abi_layout_movement": layout_movement,
            "provider_algorithm_movement": provider_movement,
            "cli_movement": cli_movement,
            "total": symbol_movement + declared_movement + layout_movement
                     + provider_movement + cli_movement,
        },
        "interpretation": (
            "A narrow trajectory is the useful kind of negative result: it means a "
            "later divergence reported by a consumer can be localised quickly, and it "
            "corroborates (or contradicts) the FRF oracle-vs-oracle courts, which "
            "observe behaviour rather than surface."
        ),
    }
    OUTDIR.mkdir(parents=True, exist_ok=True)
    doc = envelope("differential", "forensics/tools/atlas_differential.py",
                   [InputRef("from_authority", note=from_id),
                    InputRef("to_authority", note=to_id)],
                   body)
    doc["body_hash"] = content_hash(body)
    write_json(OUTDIR / f"{from_id}-vs-{to_id}.json", doc)

    # Markdown projection
    L = [
        f"# Differential atlas — `{from_id}` → `{to_id}`",
        "",
        "Generated by `forensics/tools/atlas_differential.py`. `added` means present",
        "in the **to** authority and absent in the **from** authority.",
        "",
        "## Movement",
        "",
        "| plane | movement |",
        "|---|---|",
    ]
    for k in sorted(body["movement"]):
        L.append(f"| `{k}` | {body['movement'][k]} |")
    L += ["", "## Symbol planes", "", "| library | added | removed | version changed |", "|---|---|---|---|"]
    for lib, v in sorted((planes.get("symbols") or {}).items()):
        L.append(f"| `{lib}` | {v['added_count']} | {v['removed_count']} | {v['version_changed_count']} |")
    for plane in ("functions", "typedefs", "structs", "enums", "variables", "macros"):
        v = planes.get(plane)
        if v:
            L += ["", f"`{plane}`: common {v['common']}, "
                      f"added {v['added_count']}, removed {v['removed_count']}"]
            if v["added_count"] == 0 and v["removed_count"] == 0:
                L[-1] += " — **identical across the two authorities**"
    L += ["", "## Other planes", ""]
    L.append(f"- abi layout changed aggregates: "
             f"{planes.get('abi_layout', {}).get('layout_changed_count', 0)}")
    L.append(f"- provider algorithm classes with changes: "
             f"{len(planes.get('provider_algorithms') or {})}")
    L.append(f"- cli option changes: {planes.get('cli', {}).get('option_changes_count', 0)}")
    for k, v in sorted((planes.get("corpus") or {}).items()):
        L.append(f"- corpus `{k}`: identical={v['identical']}, "
                 f"added={v['added_count']}, removed={v['removed_count']}")
    L.append("")
    write_text(OUTDIR / f"{from_id}-vs-{to_id}.md", "\n".join(L))

    print(f"  movement: {body['movement']}")
    for plane in ("functions", "typedefs", "structs", "enums", "variables", "macros"):
        v = planes.get(plane)
        if v:
            print(f"  {plane}: common={v['common']} added={v['added_count']} removed={v['removed_count']}")
    print(f"  -> {rel(OUTDIR / f'{from_id}-vs-{to_id}.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
