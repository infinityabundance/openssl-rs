#!/usr/bin/env python3
"""openssl-rs — query the OpenSSL release catalogue and its lineage, deterministically.

23.1 lands the release catalogue (`forensics/release-catalog.json`) and the typed lineage
(`forensics/authority-lineage.json`). This is the **query tool** over them: it reads the two
committed artefacts and answers release-graph questions in a machine-readable form (the
authoritative output, `--json`) and a concise human form.

It never sorts versions to answer a question and it never invents an edge. The lineage it reads
is a DAG (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` sections 0 and 4.3): parallel maintained
branches -- the 1.0.2 LTS, 1.1.1 LTS, the 3.x series and the 4.x line -- are typed edges, not a
false linear mainline. Every edge records the **sense it is read in** (`direction`): `forward`
reads from `from_id` to `to_id`, `reverse` reads from `to_id` to `from_id`. The query tool
resolves a canonical parent/child by that sense, so an edge cannot be read backwards silently.

The edge families are carried:

  * the **canonical** lineage (`branch_fork`, `chronological_successor`, `maintenance_successor`),
    which is the parent relation `parents` and `path` read;
  * **`git_ancestry`**, the commit graph's own nearest release ancestor, corroborating the
    canonical relation without replacing it; and
  * **`declared_abi_compatibility`**, upstream's own ABI promise for a declared compatibility
    family -- a **declaration**, marked `declared`, never candidate evidence and never a proof
    that a date-order edge implies ABI compatibility.

`latest-stable` reads the catalogue's alias, which points at a **final** release only: a
pre-release that sorts above the stable release is never returned.

Commands
--------
  list [--channel C] [--mainline] [--auxiliary]   every release node
  show <release>                                   one node, its parents, children and ancestors
  parents <release>                                the canonical parent edge(s)
  path <a> <b>                                     the lineage path between two releases
  edges [--kind K] [--from R] [--to R]             the typed edges, filtered by kind/endpoint
  kinds                                            the edge-kind counts
  latest-stable                                    the stable alias
  unresolved                                       the labels the version model could not decode

`<release>` is a `release_id` (`openssl-4.0.3`) or a `display_version` (`4.0.3`).

Outputs
-------
  (none) — it reads `forensics/release-catalog.json` and `forensics/authority-lineage.json`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel  # noqa: E402

CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"


def load_catalog() -> dict:
    if not CATALOG.is_file():
        raise SystemExit(f"authority-graph: {rel(CATALOG)} is absent; run authority_catalog.py")
    return json.loads(CATALOG.read_text(encoding="utf-8"))["body"]


def load_lineage() -> dict:
    if not LINEAGE.is_file():
        raise SystemExit(f"authority-graph: {rel(LINEAGE)} is absent; run authority_catalog.py")
    return json.loads(LINEAGE.read_text(encoding="utf-8"))["body"]


def canonical_kinds(lineage: dict) -> tuple[str, ...]:
    return tuple(lineage.get("canonical_kinds")
                 or ("branch_fork", "chronological_successor", "maintenance_successor"))


def index_nodes(catalog: dict) -> dict[str, dict]:
    """Every node by its `release_id`, and by its `display_version` where that is unambiguous.

    An auxiliary line can repeat a mainline version (`openssl-0.9.6` and
    `openssl-engine-0.9.6`), so a bare `display_version` resolves to the **mainline** node;
    the auxiliary node is always reachable by its `release_id`.
    """
    index: dict[str, dict] = {}
    for n in catalog["nodes"]:
        index[n["release_id"]] = n
    for n in catalog["nodes"]:
        index.setdefault(n["display_version"], n)
    return index


def resolve(catalog: dict, name: str) -> dict:
    node = index_nodes(catalog).get(name)
    if node is None:
        raise SystemExit(f"authority-graph: no such release {name!r}")
    return node


def _read_pair(edge: dict) -> tuple[str, str]:
    """The edge's endpoints in the sense it is read: `(predecessor/reference, successor/subject)`.

    `direction` is load-bearing: `forward` reads `from_id -> to_id`, `reverse` reads
    `to_id -> from_id`. A reader that ignored it would silently reverse a relationship.
    """
    if edge.get("direction", "forward") == "reverse":
        return edge["to_id"], edge["from_id"]
    return edge["from_id"], edge["to_id"]


def _canonical_edges(catalog: dict, lineage: dict) -> list[dict]:
    kinds = set(canonical_kinds(lineage))
    return [e for e in lineage["edges"] if e["kind"] in kinds]


def parents(catalog: dict, lineage: dict, release_id: str) -> list[dict]:
    return [e for e in _canonical_edges(catalog, lineage) if _read_pair(e)[1] == release_id]


def children(catalog: dict, lineage: dict, release_id: str) -> list[dict]:
    return [e for e in _canonical_edges(catalog, lineage) if _read_pair(e)[0] == release_id]


def git_ancestors(lineage: dict, release_id: str) -> list[dict]:
    return [e for e in lineage["edges"]
            if e["kind"] == "git_ancestry" and _read_pair(e)[1] == release_id]


def selected_edges(lineage: dict, kind: str | None, from_id: str | None,
                   to_id: str | None) -> list[dict]:
    """The edges matching a kind and/or an endpoint, matched in the sense the edge is read."""
    out = []
    for e in lineage["edges"]:
        if kind is not None and e["kind"] != kind:
            continue
        pred, succ = _read_pair(e)
        if from_id is not None and pred != from_id:
            continue
        if to_id is not None and succ != to_id:
            continue
        out.append(e)
    return out


def path_between(catalog: dict, lineage: dict, a: str, b: str) -> dict:
    """The shortest lineage path between two releases, over the canonical edges.

    Traversal follows an edge in either direction and reports, per step, whether it was read
    `forward` (parent -> child) or `reverse`; the answer is therefore a path through the DAG,
    never a claim that either release is compatible with the other.
    """
    edges = _canonical_edges(catalog, lineage)
    adj: dict[str, list[tuple[str, dict, str]]] = {}
    for e in edges:
        pred, succ = _read_pair(e)
        adj.setdefault(pred, []).append((succ, e, "forward"))
        adj.setdefault(succ, []).append((pred, e, "reverse"))
    start, goal = a, b
    if start == goal:
        return {"found": True, "from": a, "to": b, "steps": []}
    seen = {start}
    queue: deque[tuple[str, list[dict]]] = deque([(start, [])])
    while queue:
        current, steps = queue.popleft()
        for nxt, edge, direction in sorted(adj.get(current, []), key=lambda t: t[0]):
            if nxt in seen:
                continue
            pred, succ = _read_pair(edge)
            step = {"from_id": pred, "to_id": succ, "kind": edge["kind"],
                    "read": direction}
            if nxt == goal:
                return {"found": True, "from": start, "to": goal, "steps": steps + [step]}
            seen.add(nxt)
            queue.append((nxt, steps + [step]))
    return {"found": False, "from": start, "to": goal, "steps": []}


def latest_stable(catalog: dict) -> dict:
    target = catalog["aliases"]["latest-stable"]
    node = index_nodes(catalog)[target]
    return {"alias": "latest-stable", "release_id": node["release_id"],
            "display_version": node["display_version"], "release_channel": node["release_channel"],
            "release_date": node["release_date"], "upstream_tag": node["upstream_tag"]}


def filtered_nodes(catalog: dict, channel: str | None, mainline: bool, auxiliary: bool) -> list[dict]:
    out = list(catalog["nodes"])
    if channel:
        out = [n for n in out if n["release_channel"] == channel]
    if mainline and not auxiliary:
        out = [n for n in out if n["mainline_or_auxiliary"] == "mainline"]
    if auxiliary and not mainline:
        out = [n for n in out if n["mainline_or_auxiliary"] == "auxiliary"]
    return out


def _sum_edges(edges: list[dict]) -> list[dict]:
    return [{"from_id": e["from_id"], "to_id": e["to_id"], "kind": e["kind"]} for e in edges]


def _print_human(command: str, payload: dict) -> None:
    if command == "list":
        for n in payload["nodes"]:
            print(f"{n['release_id']:<28} {n['release_channel']:<20} "
                  f"{n['mainline_or_auxiliary']:<9} {n['release_date']}  "
                  f"{n['upstream_tag']}")
        print(f"-- {payload['count']} release node(s)")
    elif command == "show":
        n = payload["node"]
        print(f"{n['release_id']}  ({n['display_version']}, {n['version_scheme']})")
        print(f"  channel={n['release_channel']} {n['mainline_or_auxiliary']} "
              f"{n['public_or_extended']} date={n['release_date']}")
        print(f"  tag={n['upstream_tag']} commit={n['upstream_commit']}")
        print(f"  support={n['declared_support_class']} family={n['declared_compatibility_family']} "
              f"licence={n['licence_epoch']}")
        print(f"  source={n['official_source_artifact']} sha256={n['source_sha256']}")
        print(f"  canonical parents: "
              + (", ".join(f"{e['from_id']}[{e['kind']}]" for e in payload["parents"]) or "-- root"))
        print(f"  children: "
              + (", ".join(e["to_id"] for e in payload["children"]) or "-- none"))
        print(f"  git ancestors: "
              + (", ".join(e["from_id"] for e in payload["git_ancestors"]) or "-- none"))
        print(f"  provenance: {'; '.join(n['metadata_provenance'])}")
    elif command == "parents":
        if not payload["parents"]:
            print(f"{payload['release_id']}: -- root (no canonical parent)")
        for e in payload["parents"]:
            print(f"{payload['release_id']} <- {e['from_id']}  [{e['kind']}]")
    elif command == "path":
        if not payload["found"]:
            print(f"{payload['from']} -> {payload['to']}: no canonical lineage path")
        else:
            hops = " -> ".join([payload["from"]] + [s["to_id"] if s["read"] == "forward"
                                                    else s["from_id"] for s in payload["steps"]])
            print(f"{payload['from']} -> {payload['to']}: {hops}")
            for s in payload["steps"]:
                print(f"    {s['from_id']} -> {s['to_id']} [{s['kind']}] read {s['read']}")
    elif command == "latest-stable":
        print(f"latest-stable = {payload['release_id']} ({payload['release_channel']}, "
              f"{payload['release_date']})")
    elif command == "edges":
        for e in payload["edges"]:
            print(f"{e['edge_id']:<64} [{e['kind']}] "
                  f"{e['from_id']} -> {e['to_id']} ({e['direction']})")
        print(f"-- {payload['count']} edge(s)")
    elif command == "kinds":
        for kind, count in sorted(payload["kinds"].items()):
            print(f"{kind:<28} {count}")
        print(f"-- {payload['total']} edge(s) over {len(payload['kinds'])} kind(s); "
              f"declared={payload['declared']}")
    elif command == "unresolved":
        for r in payload["unresolved"]:
            print(f"{r['tag']:<28} {r['date']}  {r['upstream_label']!r}  -- {r['reason']}")
        print(f"-- {payload['count']} unresolved label(s)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true",
                    help="emit the authoritative machine-readable JSON")
    sub = ap.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--channel", default=None)
    p_list.add_argument("--mainline", action="store_true")
    p_list.add_argument("--auxiliary", action="store_true")

    for name in ("show", "parents"):
        p = sub.add_parser(name)
        p.add_argument("release")

    p_path = sub.add_parser("path")
    p_path.add_argument("a")
    p_path.add_argument("b")

    p_edges = sub.add_parser("edges")
    p_edges.add_argument("--kind", default=None)
    p_edges.add_argument("--from", dest="from_id", default=None)
    p_edges.add_argument("--to", dest="to_id", default=None)

    sub.add_parser("kinds")
    sub.add_parser("latest-stable")
    sub.add_parser("unresolved")
    args = ap.parse_args(argv)

    catalog = load_catalog()
    lineage = load_lineage()
    command = args.command

    if command == "list":
        nodes = filtered_nodes(catalog, args.channel, args.mainline, args.auxiliary)
        nodes = sorted(nodes, key=lambda n: (n["release_date"], n["release_id"]))
        payload = {"command": "list", "count": len(nodes), "nodes": nodes}
    elif command == "show":
        node = resolve(catalog, args.release)
        payload = {"command": "show", "node": node,
                   "parents": _sum_edges(parents(catalog, lineage, node["release_id"])),
                   "children": _sum_edges(children(catalog, lineage, node["release_id"])),
                   "git_ancestors": _sum_edges(git_ancestors(lineage, node["release_id"]))}
    elif command == "parents":
        node = resolve(catalog, args.release)
        payload = {"command": "parents", "release_id": node["release_id"],
                   "parents": _sum_edges(parents(catalog, lineage, node["release_id"]))}
    elif command == "path":
        a_id = resolve(catalog, args.a)["release_id"]
        b_id = resolve(catalog, args.b)["release_id"]
        payload = {"command": "path", **path_between(catalog, lineage, a_id, b_id)}
    elif command == "edges":
        if args.kind is not None and args.kind not in lineage["edge_kinds"]:
            raise SystemExit(f"authority-graph: no such edge kind {args.kind!r}; "
                             f"known: {', '.join(lineage['edge_kinds'])}")
        for name, value in (("--from", args.from_id), ("--to", args.to_id)):
            if value is not None:
                resolve(catalog, value)
        found = selected_edges(lineage, args.kind, args.from_id, args.to_id)
        payload = {"command": "edges", "count": len(found), "kind": args.kind,
                   "edges": found}
    elif command == "kinds":
        kinds = lineage.get("counts", {}).get("kinds", {})
        payload = {"command": "kinds", "kinds": kinds,
                   "total": sum(kinds.values()),
                   "declared": sum(1 for e in lineage["edges"] if e.get("declared") is True),
                   "absent": lineage.get("absent_kinds", {})}
    elif command == "latest-stable":
        payload = {"command": "latest-stable", **latest_stable(catalog)}
    else:
        payload = {"command": "unresolved", "count": len(catalog["unresolved"]),
                   "unresolved": catalog["unresolved"]}

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(command, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
