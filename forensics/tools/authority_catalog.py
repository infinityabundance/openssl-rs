#!/usr/bin/env python3
"""openssl-rs — the OpenSSL release catalogue and its lineage, derived from the archaeology.

Phase 23 is the multitrack authority stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). 23.1 is "the release-node catalogue": one release
node per upstream OpenSSL release from the first real release, OpenSSL 0.9.1c (23 December
1998), forward, plus its pre-releases and historical side branches, and the typed lineage
between them. This module is that generator.

Why the catalogue is derived rather than typed
----------------------------------------------
`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 3.5 fixes the rule: a release node's identity
is read from the source manifest and the upstream lineage, **never typed**. So this generator
reads one committed archaeology snapshot —
`forensics/multitrack/release-archaeology.json` — and derives both artefacts from it:

  * `forensics/release-catalog.json` — the release nodes, each schema-validated against
    `multitrack_schemas.validate_release_node`;
  * `forensics/authority-lineage.json` — the typed lineage edges between them.

The snapshot is the raw fact: every row of the official release timeline
(`https://openssl-library.org/news/timeline/`) with its date, the git tag it names, the commit
that tag peels to (`git ls-remote --tags` and a bare partial clone), and the nearest **release**
ancestor the git graph gives it. The snapshot records the SHA-256 of the timeline HTML it was
extracted from, so a live website change cannot alter a reproduced result: a catalogue is only
reproduced from the snapshot, and the snapshot by construction names the bytes it saw. The
node's own `content_hash` is a function of the committed snapshot alone.

What a node is, and the three refusals
--------------------------------------
A node is a *fact about upstream*: its identity and scheme, its channel (`final`, `alpha`,
`beta`, `development` or `historical_auxiliary`), its date, whether it is `public` or `extended`
and `mainline` or `auxiliary`, its upstream tag and commit, its source artefact and digest, its
declared support class and compatibility family, its licence epoch, its parent edges and the
provenance of its metadata. Three things this generator refuses to do:

  * **it never sorts versions to invent a lineage** (D535). `multitrack_schemas.parse_version`
    establishes chronology and names the scheme; the lineage is typed by the version-series
    structure and, separately, by the git graph read into the snapshot. A version order is not
    a compatibility claim and this file makes none.
  * **it never promotes a pre-release by sorting higher.** `latest-stable` is resolved to a
    `final` node only; a `4.1.0-alpha1` that sorts above `4.0.3` is never the stable alias.
  * **it never turns SSLeay into OpenSSL.** The three SSLeay tags are recorded as **provenance
    ancestry metadata** (the lineage OpenSSL began from), not as release nodes.

A label the version model cannot decode — the FIPS 2.0 module's `2.0`, `2.0-pl1`, `2.0-rcN`,
and the FIPS 1.0 `1.0` — is **not invented into a node**. It is recorded in the catalogue's
`unresolved` list with its reason, and the `RT-RELEASE-CATALOG` court surfaces it rather than
hiding it. Unknown stays unknown (`docs/PARITY_MODEL.md` section 1).

Outputs
-------
  forensics/release-catalog.json
  forensics/authority-lineage.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    REPO_ROOT,
    InputRef,
    canonical_json,
    content_hash,
    envelope,
    rel,
    write_json,
)

import multitrack_schemas as mts  # noqa: E402

SNAPSHOT = REPO_ROOT / "forensics" / "multitrack" / "release-archaeology.json"
OUT_CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
OUT_LINEAGE = REPO_ROOT / "forensics" / "authority-lineage.json"
GENERATOR = "forensics/tools/authority_catalog.py"
AUTHORITIES = REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json"

ROOT_TAG = "OpenSSL_0_9_1c"
STABLE_ALIAS = "latest-stable"

# A series the official release strategy (https://openssl-library.org/policies/releasestrat/)
# designates long-term support. Read from the snapshot's `source.lts_series`, never typed here.

# The mainline series an auxiliary (engine / FIPS module) line forked from, where the git graph
# does not answer it directly. The engine branch forked from 0.9.6; the FIPS 1.0 module from
# 0.9.7; the FIPS 1.2 module from 0.9.8; and the FIPS 2.0 module from 1.0.1.
AUX_FORK_BASE: dict[str, str] = {
    "engine-0.9.6": "0.9.6",
    "fips-1.0": "0.9.7",
    "fips-1.2": "0.9.8",
    "fips-2.0": "1.0.1",
}

# The one place a node's source digest is established rather than stated `unknown`: the two
# admitted authorities' published artifacts, read from AUTHORITIES.json.
KNOWN_ARTIFACT = {
    "openssl-3.6.3": ("openssl-3.6.3.tar.gz", "243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1"),
    "openssl-3.6.4": ("openssl-3.6.4.tar.gz", "9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef"),
}

PRERELEASE_MARKERS = ("alpha", "beta", "rc", "pre")

# The kinds the lineage vocabulary names but the catalogue's evidence cannot yet settle. Each is
# recorded with the reason it is absent, so an omitted relationship is a stated gap rather than a
# silent default (the plan's section 3.6 discipline applied to a missing edge).
ABSENT_EDGE_KINDS: dict[str, str] = {
    "observed_compatibility": (
        "no candidate-to-authority measurement exists at 23.4; the compatibility courts and views "
        "land at 23.9 and 23.12, so no observed relationship is asserted"
    ),
    "security_backport": (
        "the security lineage lands at 23.14; until a vulnerability observation names a fixed-in "
        "release there is no backport to assert, so the kind is absent rather than guessed"
    ),
}

# The lineage body's content hash is taken over these keys, so the direction model and the stated
# absences are content-addressed alongside the edges. The court imports this tuple and re-seals a
# mutated body with it, so a sensitivity control isolates the semantic check.
LINEAGE_HASH_KEYS: tuple[str, ...] = (
    "root", "canonical_kinds", "edges", "edge_kinds", "absent_kinds", "direction_model",
    "date_order_is_not_abi", "declared_abi_family_field",
)


def load_snapshot() -> dict:
    if not SNAPSHOT.is_file():
        raise SystemExit(
            f"authority-catalog: the archaeology snapshot {rel(SNAPSHOT)} is absent, so the "
            f"catalogue has no source; it is not typed by hand"
        )
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def _label(name: str) -> str:
    """The upstream label with the `OpenSSL ` prefix stripped: `fips-2.0.16`, `0.9.1c`, ..."""
    text = name
    if text.startswith("OpenSSL "):
        text = text[len("OpenSSL "):]
    for prefix in ("fips-", "engine-", "FIPS."):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def _is_aux(tag: str) -> bool:
    return (tag.startswith("OpenSSL-engine-") or tag.startswith("OpenSSL-fips-")
            or tag.startswith("OpenSSL_FIPS_"))


def classify(row: dict, source: dict) -> dict:
    """One timeline row as a release node, or an `unresolved` record.

    Returns `{"node": ..., "unresolved": ...}` with exactly one of the two set. The channel is
    read from the upstream label's own markers -- `alpha`, `beta`, `rc` (a development
    pre-release of the FIPS module), `pre` (a development snapshot) or the auxiliary branches --
    and never from a version comparison.
    """
    lts_series = set(source["lts_series"])
    timeline_url = source["timeline_url"]
    tag = row["tag"]
    name = row["name"]
    version = _label(name)
    aux = _is_aux(tag)
    try:
        parsed = mts.parse_version(version)
    except mts.VersionError as exc:
        return {"node": None, "unresolved": {
            "tag": tag, "name": name, "date": row["date"], "upstream_label": version,
            "reason": str(exc),
        }}

    low = version.lower()
    if "alpha" in low:
        channel = "alpha"
    elif "beta" in low:
        channel = "beta"
    elif "rc" in low or "pre" in low:
        channel = "development"
    elif aux:
        channel = "historical_auxiliary"
    else:
        channel = "final"

    series = _series_name(tag, aux, parsed)
    release_id = (f"openssl-engine-{version}" if "engine" in tag
                  else f"openssl-fips-{version}" if aux else f"openssl-{version}")

    if aux:
        support_class, public_or_extended = "unknown", "public"
    elif channel != "final":
        support_class, public_or_extended = "prerelease", "public"
    elif series in lts_series:
        support_class, public_or_extended = "lts", "extended"
    else:
        support_class, public_or_extended = "release", "public"

    if release_id in KNOWN_ARTIFACT:
        artifact, digest = KNOWN_ARTIFACT[release_id]
    else:
        artifact, digest = "unknown", "unknown"

    provenance = [
        f"{timeline_url} ({row['date']})",
        f"git:openssl/openssl refs/tags/{tag} -> {row['commit']}",
        rel(SNAPSHOT),
    ]
    if release_id in KNOWN_ARTIFACT:
        provenance.append(rel(AUTHORITIES))

    node = {
        "release_id": release_id,
        "display_version": version,
        "version_scheme": parsed.scheme,
        "release_channel": channel,
        "release_date": row["date"],
        "public_or_extended": public_or_extended,
        "mainline_or_auxiliary": "auxiliary" if aux else "mainline",
        "upstream_tag": tag,
        "upstream_commit": row["commit"] if row["commit"] != "unknown" else "unknown",
        "official_source_artifact": artifact,
        "source_sha256": digest,
        "declared_support_class": support_class,
        "declared_compatibility_family": f"openssl-{series}",
        "licence_epoch": "Apache-2.0" if parsed.major >= 3 else "OpenSSL",
        "known_parent_edges": [],
        "metadata_provenance": provenance,
    }
    return {"node": node, "unresolved": None}


def _order_key(node: dict) -> tuple:
    """Chronology by the authoritative upstream date, version order as the tie-break.

    The date is the primary key because `multitrack_schemas.Version.order_key` compares a
    pre-release label as a plain string, so `alpha10` would sort before `alpha2`; the release
    date is the fact the timeline carries and it is monotonic within a series. The parsed
    version order breaks a same-day tie.
    """
    v = mts.parse_version(node["display_version"])
    return (node["release_date"], v.order_key(), node["release_id"])


def build_catalog() -> tuple[dict, dict]:
    """The release catalogue body and the raw index the lineage is derived from."""
    snap = load_snapshot()
    source = snap["source"]
    nodes: list[dict] = []
    unresolved: list[dict] = []
    node_by_tag: dict[str, dict] = {}
    for row in snap["timeline"]:
        got = classify(row, source)
        if got["node"] is not None:
            nodes.append(got["node"])
            node_by_tag[row["tag"]] = got["node"]
        else:
            unresolved.append(got["unresolved"])
    nodes.sort(key=lambda n: n["release_id"])
    unresolved.sort(key=lambda r: r["tag"])

    by_series: dict[str, list[dict]] = {}
    for n in nodes:
        series = _series_of(n)
        by_series.setdefault(series, []).append(n)
    for series in by_series:
        by_series[series].sort(key=_order_key)

    edges = build_lineage(nodes, by_series, node_by_tag, snap, source)

    # The alias points at a *final* release only: the newest mainline final by chronology.
    finals = [n for n in nodes
              if n["release_channel"] == "final" and n["mainline_or_auxiliary"] == "mainline"]
    if not finals:
        raise SystemExit("authority-catalog: no mainline final release in the catalogue")
    latest = max(finals, key=_order_key)["release_id"]
    root = min((n for n in nodes if n["mainline_or_auxiliary"] == "mainline"), key=_order_key)
    if root["upstream_tag"] != ROOT_TAG:
        raise SystemExit(
            f"authority-catalog: the mainline root is {root['release_id']}, not "
            f"{ROOT_TAG}; the lineage does not begin where upstream's does"
        )

    channel_counts: dict[str, int] = {}
    for n in nodes:
        channel_counts[n["release_channel"]] = channel_counts.get(n["release_channel"], 0) + 1
    support_counts: dict[str, int] = {}
    for n in nodes:
        support_counts[n["declared_support_class"]] = support_counts.get(
            n["declared_support_class"], 0) + 1

    catalog_body = {
        "root": root["release_id"],
        "aliases": {STABLE_ALIAS: latest},
        "ssleay_ancestry": [
            {"tag": s["tag"], "display": s["name"], "date": s["date"], "commit": s["commit"],
             "note": "SSLeay is OpenSSL's provenance ancestry, recorded as metadata and not as a "
                     "release node"}
            for s in snap["ssleay"]
        ],
        "nodes": nodes,
        "unresolved": unresolved,
        "counts": {
            "nodes": len(nodes),
            "mainline": sum(1 for n in nodes if n["mainline_or_auxiliary"] == "mainline"),
            "auxiliary": sum(1 for n in nodes if n["mainline_or_auxiliary"] == "auxiliary"),
            "channels": {k: channel_counts[k] for k in sorted(channel_counts)},
            "support_classes": {k: support_counts[k] for k in sorted(support_counts)},
            "unresolved": len(unresolved),
            "series": len(by_series),
        },
        "source": dict(snap["source"]),
    }
    catalog_body["content_hash"] = content_hash({
        "root": catalog_body["root"],
        "aliases": catalog_body["aliases"],
        "ssleay_ancestry": catalog_body["ssleay_ancestry"],
        "nodes": catalog_body["nodes"],
        "unresolved": catalog_body["unresolved"],
    })

    present = {e["kind"] for e in edges["edges"]}
    absent = {k: v for k, v in ABSENT_EDGE_KINDS.items() if k not in present}
    unaccounted = sorted(set(mts.LINEAGE_EDGE_KINDS) - present - set(absent))
    if unaccounted:
        raise SystemExit(
            f"authority-catalog: the lineage omits {unaccounted} but records no reason; a kind "
            f"that is neither present nor stated absent is a dropped relationship"
        )

    lineage_body = {
        "root": root["release_id"],
        "canonical_kinds": ["branch_fork", "chronological_successor", "maintenance_successor"],
        "edge_kinds": list(mts.LINEAGE_EDGE_KINDS),
        "absent_kinds": {k: absent[k] for k in sorted(absent)},
        "direction_model": ("forward: the edge is read from `from_id` to `to_id`; reverse: it is "
                            "read from `to_id` to `from_id`"),
        "date_order_is_not_abi": True,
        "declared_abi_family_field": "declared_compatibility_family",
        "edges": edges["edges"],
        "topological_order": edges["topological_order"],
        "counts": {
            "edges": len(edges["edges"]),
            "kinds": edges["kinds"],
            "nodes": len(nodes),
        },
        "dag": edges["dag"],
    }
    lineage_body["content_hash"] = content_hash({k: lineage_body.get(k) for k in LINEAGE_HASH_KEYS})
    return catalog_body, lineage_body


def _series_name(tag: str, aux: bool, v: mts.Version) -> str:
    if aux:
        if "engine" in tag:
            return f"engine-{v.major}.{v.minor}.{v.release}"
        return f"fips-{v.major}.{v.minor}"
    if v.scheme == mts.SCHEME_PRE_3_0:
        return f"{v.major}.{v.minor}.{v.release}"
    return f"{v.major}.{v.minor}"


def _series_of(node: dict) -> str:
    """The maintenance series a node belongs to.

    For the pre-3.0 scheme the series is `MAJOR.MINOR.FIX` (`0.9.6`, `1.0.2`, `1.1.1`); for
    3.0-plus it is `MAJOR.MINOR` (`3.0`, `3.6`). An auxiliary line carries its branch prefix.
    """
    v = mts.parse_version(node["display_version"])
    return _series_name(node["upstream_tag"], node["mainline_or_auxiliary"] == "auxiliary", v)


def _series_key(series: str) -> tuple[int, int, int]:
    nums = [int(x) for x in series.split("-")[-1].split(".")]
    return tuple((nums + [0, 0, 0])[:3])  # type: ignore[return-value]


def _is_aux_series(series: str) -> bool:
    return series.startswith(("engine-", "fips-"))


def _predecessor_series(series: str, by_series: dict[str, list[dict]]) -> str | None:
    """The series a new series forked from, as the lineage names it."""
    if _is_aux_series(series):
        base = AUX_FORK_BASE.get(series)
        return base if base in by_series else None
    key = _series_key(series)
    earlier = [s for s in by_series if not _is_aux_series(s) and _series_key(s) < key]
    return max(earlier, key=_series_key) if earlier else None


def _parallel(pred_series: str, first: dict, by_series: dict[str, list[dict]]) -> bool:
    """Whether the predecessor series was still being released after `first` began."""
    return any(n["release_channel"] == "final" and n["release_date"] > first["release_date"]
               for n in by_series.get(pred_series, []))


def _fork_base(pred_series: str, first: dict, by_series: dict[str, list[dict]]) -> dict | None:
    candidates = [n for n in by_series.get(pred_series, []) if n["release_channel"] == "final"]
    if not candidates:
        return None
    earlier = [n for n in candidates if n["release_date"] <= first["release_date"]]
    return max(earlier, key=_order_key) if earlier else min(candidates, key=_order_key)


def build_lineage(nodes: list[dict], by_series: dict[str, list[dict]],
                  node_by_tag: dict[str, dict], snap: dict, source: dict) -> dict:
    """The typed lineage edges, plus the DAG's topological order.

    A series chains by version order internally: a pre-release to the next pre-release or final
    is a `chronological_successor`, and a final to its successor final is a `maintenance_successor`.
    The first node of a series is a `branch_fork` from the predecessor series' current final.
    Beside that version-structural parent relation, the git graph's own nearest release ancestor
    is recorded as a `git_ancestry` edge, so the two independent facts are both present and
    neither is a compatibility claim.
    """
    edges: list[dict] = []
    seen_ids: set[str] = set()

    def add(kind: str, parent: dict, child: dict, evidence: list[str],
            provenance: list[str] | None = None, **extra: object) -> None:
        edge_id = f"L-{kind}-{parent['release_id']}-{child['release_id']}"
        if edge_id in seen_ids:
            return
        seen_ids.add(edge_id)
        edge = {
            "edge_id": edge_id,
            "kind": kind,
            "from_id": parent["release_id"],
            "to_id": child["release_id"],
            "direction": "forward",
            "evidence": evidence,
            "metadata_provenance": provenance or [rel(SNAPSHOT), source["timeline_url"]],
        }
        edge.update(extra)
        edges.append(edge)

    for series, members in sorted(by_series.items()):
        for i, child in enumerate(members):
            if i > 0:
                parent = members[i - 1]
                kind = ("chronological_successor"
                        if (parent["release_channel"] != "final"
                            or child["release_channel"] != "final")
                        else "maintenance_successor")
                evidence = [
                    f"version-series {series}: {parent['display_version']} precedes "
                    f"{child['display_version']}",
                    f"upstream dates {parent['release_date']} <= {child['release_date']}",
                ]
                if parent.get("upstream_tag") and _git_parent(child, snap) == parent["upstream_tag"]:
                    evidence.append(
                        f"git ancestry confirms {parent['upstream_tag']} -> {child['upstream_tag']}")
                add(kind, parent, child, evidence)
                continue
            pred = _predecessor_series(series, by_series)
            base = _fork_base(pred, child, by_series) if pred else None
            if base is None:
                continue
            if _parallel(pred, child, by_series):
                add("branch_fork", base, child, [
                    f"series {series} runs in parallel with series {pred}",
                    f"fork base {base['release_id']} ({base['release_date']}) is the predecessor "
                    f"series' final current when {child['release_id']} ({child['release_date']}) "
                    f"began, and {pred} kept releasing after it",
                ])
            else:
                add("chronological_successor", base, child, [
                    f"series {series} continues series {pred}",
                    f"{base['release_id']} ({base['release_date']}) is the predecessor series' "
                    f"final before {child['release_id']} ({child['release_date']})",
                ])

    # The independent git fact: the nearest release ancestor the commit graph gives each node.
    for node in sorted(nodes, key=lambda n: n["release_id"]):
        parent_tag = _git_parent(node, snap)
        parent = node_by_tag.get(parent_tag) if parent_tag else None
        if parent is None or parent["release_id"] == node["release_id"]:
            continue
        add("git_ancestry", parent, node, [
            f"git ancestry: {parent_tag} ({parent['upstream_commit']}) is the nearest release "
            f"ancestor of {node['upstream_tag']} ({node['upstream_commit']})",
        ])

    # The declared relationship, kept apart from the date-order chain: upstream's own ABI promise
    # for a declared compatibility family. It is scoped to the family the catalogue records, marked
    # `declared`, and is a **declaration**, never a measurement -- the non-claim "upstream's ABI
    # promise is not candidate evidence" is why it is a separate kind and never backs a view. The
    # declared ABI reference is the family's earliest final; each later final is declared compatible
    # with it in that direction. This is deliberately not the `chronological_successor` chain (D535:
    # a date order is not an ABI proof), which is why the two edge sets are distinct.
    finals_by_family: dict[str, list[dict]] = {}
    for node in nodes:
        if node["release_channel"] != "final" or node["mainline_or_auxiliary"] != "mainline":
            continue
        finals_by_family.setdefault(node["declared_compatibility_family"], []).append(node)
    for family, members in sorted(finals_by_family.items()):
        if len(members) < 2:
            continue
        ordered = sorted(members, key=_order_key)
        base = ordered[0]
        for later in ordered[1:]:
            add("declared_abi_compatibility", base, later, [
                f"upstream's declared compatibility family {family}: {base['release_id']} "
                f"({base['release_date']}) is the declared ABI reference for {later['release_id']}",
                "a declared relationship (upstream's ABI promise), never a candidate measurement",
            ], provenance=[rel(SNAPSHOT), source["timeline_url"], source["release_strategy_url"],
                           "docs/ABI_POLICY.md"], dimension="abi", declared=True)

    # Canonical parents are the version-structural edges; git_ancestry corroborates them.
    incoming: dict[str, list[dict]] = {}
    for e in edges:
        if e["kind"] in ("branch_fork", "chronological_successor", "maintenance_successor"):
            incoming.setdefault(e["to_id"], []).append(e)
    for node in nodes:
        node["known_parent_edges"] = sorted(e["from_id"] for e in incoming.get(
            node["release_id"], []))

    kinds: dict[str, int] = {}
    for e in edges:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1

    order, dag = _topological(nodes, edges)
    return {"edges": edges, "topological_order": order, "kinds": {k: kinds[k] for k in sorted(kinds)},
            "dag": dag}


def _git_parent(node: dict, snap: dict) -> str | None:
    for row in snap["timeline"]:
        if row["tag"] == node["upstream_tag"]:
            return row.get("git_parent_tag")
    return None


def _topological(nodes: list[dict], edges: list[dict]) -> tuple[list[str], dict]:
    """The edges' topological order over the nodes, and whether the graph is a DAG."""
    ids = sorted(n["release_id"] for n in nodes)
    adj: dict[str, list[str]] = {i: [] for i in ids}
    indeg: dict[str, int] = {i: 0 for i in ids}
    for e in edges:
        if e["from_id"] in adj and e["to_id"] in adj:
            adj[e["from_id"]].append(e["to_id"])
            indeg[e["to_id"]] += 1
    queue = sorted(i for i in ids if indeg[i] == 0)
    order: list[str] = []
    while queue:
        x = queue.pop(0)
        order.append(x)
        for y in sorted(adj[x]):
            indeg[y] -= 1
            if indeg[y] == 0:
                queue.append(y)
        queue.sort()
    cyclic = sorted(i for i in ids if i not in set(order))
    return order, {"is_dag": not cyclic, "nodes": len(ids), "cyclic_nodes": cyclic}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)

    catalog_body, lineage_body = build_catalog()

    inputs = [InputRef(name="release-archaeology", path=SNAPSHOT)]
    catalog = envelope(kind="release-catalog", generator=GENERATOR, inputs=inputs,
                       body=catalog_body)
    lineage = envelope(kind="authority-lineage", generator=GENERATOR, inputs=inputs,
                       body=lineage_body)
    write_json(OUT_CATALOG, catalog)
    write_json(OUT_LINEAGE, lineage)

    c = catalog_body["counts"]
    print(f"[authority-catalog] {c['nodes']} release node(s): "
          f"{c['mainline']} mainline + {c['auxiliary']} auxiliary; "
          f"channels {c['channels']}; unresolved {c['unresolved']}")
    print(f"  root={catalog_body['root']}  latest-stable={catalog_body['aliases'][STABLE_ALIAS]}")
    print(f"  lineage: {lineage_body['counts']['edges']} edge(s) "
          f"{lineage_body['counts']['kinds']}; dag={lineage_body['dag']['is_dag']}")
    for r in catalog_body["unresolved"]:
        print(f"  unresolved: {r['tag']} ({r['upstream_label']!r}) -- {r['reason']}")
    print(f"  -> {rel(OUT_CATALOG)}")
    print(f"  -> {rel(OUT_LINEAGE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
